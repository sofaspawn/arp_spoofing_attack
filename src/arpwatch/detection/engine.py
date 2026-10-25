"""ARP Spoofing Detection Engine - Core detection logic with multiple detection rules."""
from __future__ import annotations
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Callable
import time
import threading
import logging

from ..models import (
    ArpPacket, ArpOperation, IpMacBinding, Alert, AlertType, AlertSeverity,
    parse_mac, is_valid_ip, is_valid_mac
)
from ..config import get_config, DetectionConfig

logger = logging.getLogger(__name__)


@dataclass
class DetectionStats:
    """Runtime statistics for the detection engine."""
    packets_processed: int = 0
    alerts_generated: int = 0
    bindings_learned: int = 0
    baseline_complete: bool = False
    baseline_start_time: float = 0
    last_alert_time: float = 0
    alerts_by_type: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    
    def to_dict(self) -> dict:
        return {
            'packets_processed': self.packets_processed,
            'alerts_generated': self.alerts_generated,
            'bindings_learned': self.bindings_learned,
            'baseline_complete': self.baseline_complete,
            'baseline_elapsed': time.time() - self.baseline_start_time if self.baseline_start_time else 0,
            'alerts_by_type': dict(self.alerts_by_type)
        }


class DetectionEngine:
    """Main detection engine implementing all detection rules from the report.
    
    Detection Rules (from report Section 5.3):
    1. Mapping Change: IP bound to different MAC than previously seen
    2. Duplicate Mapping: Single IP associated with multiple MACs in short window
    3. Abnormal ARP Reply Rate: Reply rate significantly exceeds baseline
    4. Gratuitous ARP Flood: Excessive gratuitous ARP announcements
    5. MAC Spoofing: Single MAC claiming multiple IPs
    6. Gateway Impersonation: Attacker claiming gateway IP
    7. Two-Way Spoofing: Both victim and gateway poisoned simultaneously
    """
    
    def __init__(self, config: Optional[DetectionConfig] = None,
                 alert_callback: Optional[Callable[[Alert], None]] = None):
        self.config = config or get_config().detection
        self.alert_callback = alert_callback
        
        # Core state
        self.bindings: Dict[str, IpMacBinding] = {}  # ip -> binding
        self.mac_to_ips: Dict[str, Set[str]] = defaultdict(set)  # mac -> set of ips
        self.reply_history: Dict[str, deque] = defaultdict(deque)  # ip -> timestamps
        self.gratuitous_history: Dict[str, deque] = defaultdict(deque)  # ip -> timestamps
        self.mac_change_history: Dict[str, deque] = defaultdict(deque)  # ip -> (mac, timestamp)
        
        # Baseline learning
        self.baseline_mode = self.config.baseline_learning_enabled
        self.baseline_start = time.time()
        self.baseline_complete = False
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Statistics
        self.stats = DetectionStats()
        self.stats.baseline_start_time = self.baseline_start
        
        # Known gateway
        self.gateway_ip = get_config().network.gateway_ip
        self.gateway_mac = get_config().network.gateway_mac
        
        logger.info("Detection engine initialized")
    
    def process_packet(self, packet: ArpPacket) -> List[Alert]:
        """Process an ARP packet through all detection rules."""
        if not self._validate_packet(packet):
            return []
        
        with self._lock:
            self.stats.packets_processed += 1
            
            # Update baseline status
            self._update_baseline_status()
            
            # Learn/update binding
            self._update_binding(packet)
            
            # Run detection rules
            alerts = []
            
            if self.config.mapping_change_enabled:
                alerts.extend(self._check_mapping_change(packet))
            
            if self.config.duplicate_window_seconds > 0:
                alerts.extend(self._check_duplicate_mapping(packet))
            
            if self.config.rate_limit_enabled:
                alerts.extend(self._check_reply_rate(packet))
            
            if self.config.gratuitous_arp_enabled:
                alerts.extend(self._check_gratuitous_arp(packet))
            
            if self.config.mac_spoofing_enabled:
                alerts.extend(self._check_mac_spoofing(packet))
            
            # Special gateway-specific checks
            alerts.extend(self._check_gateway_impersonation(packet))
            alerts.extend(self._check_two_way_spoofing(packet))
            
            # Process alerts
            for alert in alerts:
                self._process_alert(alert)
            
            return alerts
    
    def _validate_packet(self, packet: ArpPacket) -> bool:
        """Validate packet has required fields."""
        if not packet.sender_ip or not packet.sender_mac:
            return False
        if not is_valid_ip(packet.sender_ip):
            return False
        if not is_valid_mac(packet.sender_mac):
            return False
        if packet.sender_ip == "0.0.0.0":
            return False
        return True
    
    def _update_baseline_status(self):
        """Update baseline learning status."""
        if self.baseline_mode and not self.baseline_complete:
            elapsed = time.time() - self.baseline_start
            if elapsed >= self.config.baseline_duration_seconds:
                self.baseline_complete = True
                self.stats.baseline_complete = True
                logger.info(f"Baseline learning complete after {elapsed:.1f}s. "
                           f"Learned {len(self.bindings)} bindings.")
    
    def _update_binding(self, packet: ArpPacket):
        """Update IP-to-MAC binding table."""
        ip = packet.sender_ip
        mac = packet.sender_mac
        now = packet.timestamp
        
        if ip in self.bindings:
            binding = self.bindings[ip]
            old_mac = binding.mac
            binding.update(now)
            
            # Track MAC changes for this IP
            if old_mac != mac:
                self.mac_change_history[ip].append((old_mac, binding.last_seen))
                # Clean old history
                cutoff = now - self.config.duplicate_window_seconds * 2
                self.mac_change_history[ip] = deque(
                    [(m, t) for m, t in self.mac_change_history[ip] if t > cutoff],
                    maxlen=100
                )
        else:
            # New binding
            is_gateway = (ip == self.gateway_ip)
            binding = IpMacBinding(
                ip=ip, mac=mac, first_seen=now, last_seen=now,
                is_gateway=is_gateway
            )
            self.bindings[ip] = binding
            self.stats.bindings_learned += 1
            logger.debug(f"Learned new binding: {ip} -> {mac} {'(GATEWAY)' if is_gateway else ''}")
        
        # Update reverse mapping
        self.mac_to_ips[mac].add(ip)
    
    def _check_mapping_change(self, packet: ArpPacket) -> List[Alert]:
        """Rule 1: Detect when an IP changes its associated MAC."""
        alerts = []
        ip = packet.sender_ip
        mac = packet.sender_mac
        now = packet.timestamp
        
        if ip in self.bindings:
            binding = self.bindings[ip]
            if binding.mac != mac:
                # Check if this is a duplicate (rapid change back and forth)
                is_duplicate = False
                for old_mac, change_time in self.mac_change_history[ip]:
                    if old_mac == mac and (now - change_time) <= self.config.duplicate_window_seconds:
                        is_duplicate = True
                        break
                
                if is_duplicate:
                    alert = Alert.create(
                        alert_type=AlertType.DUPLICATE_MAPPING,
                        severity=AlertSeverity.CRITICAL,
                        sender_ip=ip,
                        sender_mac=mac,
                        target_ip=packet.target_ip,
                        previous_mac=binding.mac,
                        message=f"Duplicate mapping: {ip} rapidly switching between {binding.mac} and {mac}",
                        duplicate_window=self.config.duplicate_window_seconds,
                        original_mac=binding.mac,
                        new_mac=mac
                    )
                else:
                    severity = AlertSeverity.CRITICAL if binding.is_gateway else AlertSeverity.WARNING
                    alert = Alert.create(
                        alert_type=AlertType.MAPPING_CHANGE,
                        severity=severity,
                        sender_ip=ip,
                        sender_mac=mac,
                        target_ip=packet.target_ip,
                        previous_mac=binding.mac,
                        message=f"Mapping change: {ip} changed from {binding.mac} to {mac}",
                        is_gateway=binding.is_gateway,
                        original_mac=binding.mac,
                        new_mac=mac
                    )
                alerts.append(alert)
        
        return alerts
    
    def _check_duplicate_mapping(self, packet: ArpPacket) -> List[Alert]:
        """Rule 2: Detect multiple MACs for same IP in short window."""
        alerts = []
        ip = packet.sender_ip
        mac = packet.sender_mac
        now = packet.timestamp
        
        # Track all MACs seen for this IP in the window
        window = self.mac_change_history[ip]
        unique_macs = {mac}
        for old_mac, change_time in window:
            if now - change_time <= self.config.duplicate_window_seconds:
                unique_macs.add(old_mac)
        
        if len(unique_macs) > 1:
            # Check if we already alerted for this combination recently
            alert = Alert.create(
                alert_type=AlertType.DUPLICATE_MAPPING,
                severity=AlertSeverity.CRITICAL,
                sender_ip=ip,
                sender_mac=mac,
                target_ip=packet.target_ip,
                previous_mac=None,
                message=f"Multiple MACs for {ip} in {self.config.duplicate_window_seconds}s window: {', '.join(unique_macs)}",
                macs_seen=list(unique_macs),
                window_seconds=self.config.duplicate_window_seconds
            )
            alerts.append(alert)
        
        return alerts
    
    def _check_reply_rate(self, packet: ArpPacket) -> List[Alert]:
        """Rule 3: Detect abnormal ARP reply rate for an IP."""
        alerts = []
        
        if packet.operation != ArpOperation.REPLY:
            return alerts
        
        ip = packet.sender_ip
        now = packet.timestamp
        window = self.reply_history[ip]
        
        # Add current timestamp
        window.append(now)
        
        # Remove old entries outside window
        cutoff = now - self.config.rate_window_seconds
        while window and window[0] < cutoff:
            window.popleft()
        
        # Check rate
        if len(window) > self.config.max_replies_per_window:
            alert = Alert.create(
                alert_type=AlertType.REPLY_RATE_EXCEEDED,
                severity=AlertSeverity.WARNING,
                sender_ip=ip,
                sender_mac=packet.sender_mac,
                target_ip=packet.target_ip,
                previous_mac=None,
                message=f"High ARP reply rate: {len(window)} replies for {ip} in {self.config.rate_window_seconds}s "
                       f"(threshold: {self.config.max_replies_per_window})",
                reply_count=len(window),
                window_seconds=self.config.rate_window_seconds,
                threshold=self.config.max_replies_per_window
            )
            alerts.append(alert)
        
        return alerts
    
    def _check_gratuitous_arp(self, packet: ArpPacket) -> List[Alert]:
        """Rule 4: Detect excessive gratuitous ARP announcements."""
        alerts = []
        
        if not packet.is_gratuitous:
            return alerts
        
        ip = packet.sender_ip
        now = packet.timestamp
        window = self.gratuitous_history[ip]
        
        window.append(now)
        
        # 1-minute window for gratuitous ARP
        cutoff = now - 60.0
        while window and window[0] < cutoff:
            window.popleft()
        
        if len(window) > self.config.gratuitous_threshold:
            alert = Alert.create(
                alert_type=AlertType.GRATUITOUS_ARP_FLOOD,
                severity=AlertSeverity.WARNING,
                sender_ip=ip,
                sender_mac=packet.sender_mac,
                target_ip=packet.target_ip,
                previous_mac=None,
                message=f"Gratuitous ARP flood: {len(window)} gratuitous ARPs for {ip} in 60s "
                       f"(threshold: {self.config.gratuitous_threshold})",
                gratuitous_count=len(window),
                threshold=self.config.gratuitous_threshold
            )
            alerts.append(alert)
        
        return alerts
    
    def _check_mac_spoofing(self, packet: ArpPacket) -> List[Alert]:
        """Rule 5: Detect single MAC claiming multiple IPs."""
        alerts = []
        mac = packet.sender_mac
        ip = packet.sender_ip
        
        ips_for_mac = self.mac_to_ips.get(mac, set())
        if len(ips_for_mac) > self.config.max_ips_per_mac:
            alert = Alert.create(
                alert_type=AlertType.MAC_SPOOFING,
                severity=AlertSeverity.CRITICAL,
                sender_ip=ip,
                sender_mac=mac,
                target_ip=packet.target_ip,
                previous_mac=None,
                message=f"MAC spoofing: {mac} claiming {len(ips_for_mac)} IPs: {', '.join(sorted(ips_for_mac))}",
                ips_claimed=list(ips_for_mac),
                max_allowed=self.config.max_ips_per_mac
            )
            alerts.append(alert)
        
        return alerts
    
    def _check_gateway_impersonation(self, packet: ArpPacket) -> List[Alert]:
        """Rule 6: Detect gateway IP claimed by non-gateway MAC."""
        alerts = []
        
        if packet.sender_ip != self.gateway_ip:
            return alerts
        
        if packet.sender_mac != self.gateway_mac:
            # Check if we have a baseline for gateway
            gateway_binding = self.bindings.get(self.gateway_ip)
            
            if gateway_binding and gateway_binding.mac != packet.sender_mac:
                alert = Alert.create(
                    alert_type=AlertType.GATEWAY_IMPERSONATION,
                    severity=AlertSeverity.CRITICAL,
                    sender_ip=packet.sender_ip,
                    sender_mac=packet.sender_mac,
                    target_ip=packet.target_ip,
                    previous_mac=gateway_binding.mac,
                    message=f"GATEWAY IMPERSONATION: {self.gateway_ip} claimed by {packet.sender_mac} "
                           f"(legitimate: {gateway_binding.mac})",
                    legitimate_mac=gateway_binding.mac,
                    attacker_mac=packet.sender_mac
                )
                alerts.append(alert)
            elif not gateway_binding and self.baseline_complete:
                # No baseline but baseline period complete - suspicious
                alert = Alert.create(
                    alert_type=AlertType.GATEWAY_IMPERSONATION,
                    severity=AlertSeverity.WARNING,
                    sender_ip=packet.sender_ip,
                    sender_mac=packet.sender_mac,
                    target_ip=packet.target_ip,
                    previous_mac=None,
                    message=f"Gateway IP {self.gateway_ip} seen with unknown MAC {packet.sender_mac} "
                           f"(no baseline established)",
                    attacker_mac=packet.sender_mac
                )
                alerts.append(alert)
        
        return alerts
    
    def _check_two_way_spoofing(self, packet: ArpPacket) -> List[Alert]:
        """Rule 7: Detect simultaneous spoofing of victim and gateway (MITM indicator)."""
        alerts = []
        
        # This is a correlation check - we need to see both directions
        # For now, flag when we see gateway IP from attacker MAC AND victim IP from same attacker MAC
        # within a short time window
        
        attacker_mac = packet.sender_mac
        
        # Check if this MAC has recently claimed both gateway and a victim IP
        ips_claimed = self.mac_to_ips.get(attacker_mac, set())
        
        if self.gateway_ip in ips_claimed and len(ips_claimed) > 1:
            # This MAC is claiming gateway IP AND at least one other IP
            victim_ips = [ip for ip in ips_claimed if ip != self.gateway_ip]
            if victim_ips:
                alert = Alert.create(
                    alert_type=AlertType.TWO_WAY_SPOOFING,
                    severity=AlertSeverity.CRITICAL,
                    sender_ip=packet.sender_ip,
                    sender_mac=attacker_mac,
                    target_ip=packet.target_ip,
                    previous_mac=None,
                    message=f"TWO-WAY SPOOFING (MITM): MAC {attacker_mac} claiming gateway "
                           f"({self.gateway_ip}) and victim(s): {', '.join(victim_ips)}",
                    gateway_ip=self.gateway_ip,
                    victim_ips=victim_ips,
                    attacker_mac=attacker_mac
                )
                alerts.append(alert)
        
        return alerts
    
    def _process_alert(self, alert: Alert):
        """Process and dispatch alert."""
        self.stats.alerts_generated += 1
        self.stats.alerts_by_type[alert.alert_type.value] += 1
        self.stats.last_alert_time = alert.timestamp
        
        logger.warning(f"ALERT [{alert.severity.value.upper()}] {alert.alert_type.value}: {alert.message}")
        
        if self.alert_callback:
            try:
                self.alert_callback(alert)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")
    
    def get_binding(self, ip: str) -> Optional[IpMacBinding]:
        """Get current binding for an IP."""
        with self._lock:
            return self.bindings.get(ip)
    
    def get_all_bindings(self) -> Dict[str, IpMacBinding]:
        """Get all current bindings."""
        with self._lock:
            return dict(self.bindings)
    
    def get_stats(self) -> dict:
        """Get detection engine statistics."""
        with self._lock:
            return self.stats.to_dict()
    
    def force_baseline_complete(self):
        """Force baseline completion (for testing)."""
        with self._lock:
            self.baseline_complete = True
            self.stats.baseline_complete = True
    
    def reset(self):
        """Reset detection engine state."""
        with self._lock:
            self.bindings.clear()
            self.mac_to_ips.clear()
            self.reply_history.clear()
            self.gratuitous_history.clear()
            self.mac_change_history.clear()
            self.baseline_mode = self.config.baseline_learning_enabled
            self.baseline_start = time.time()
            self.baseline_complete = False
            self.stats = DetectionStats()
            self.stats.baseline_start_time = self.baseline_start
            logger.info("Detection engine reset")