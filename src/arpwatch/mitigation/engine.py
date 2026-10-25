"""ARP Spoofing Mitigation Module - Automated response to detected attacks.
SAFETY: All mitigation actions require explicit enable and respect dry-run mode."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable
import time
import threading
import logging
import subprocess
import shlex

from ..models import Alert, AlertType, AlertSeverity
from ..config import get_config, MitigationConfig, SafetyConfig

logger = logging.getLogger(__name__)


@dataclass
class MitigationAction:
    """Record of a mitigation action taken."""
    timestamp: float
    alert_id: str
    action_type: str
    target_mac: str
    target_ip: str
    success: bool
    details: str
    dry_run: bool


class MitigationEngine:
    """Automated mitigation for ARP spoofing attacks.
    
    Supported Actions:
    1. Corrective ARP Announcement: Send legitimate ARP replies to restore correct mappings
    2. Firewall Block: Block attacker MAC at host firewall (Linux iptables/nftables)
    3. Network Notification: Log/alert for manual intervention
    
    SAFETY:
    - Disabled by default (config.mitigation.enabled = false)
    - Respects dry-run mode
    - Rate limited
    - Auto-expire firewall rules
    - Comprehensive logging
    """
    
    def __init__(self, config: Optional[MitigationConfig] = None,
                 safety_config: Optional[SafetyConfig] = None,
                 action_callback: Optional[Callable[[MitigationAction], None]] = None):
        self.config = config or get_config().mitigation
        self.safety = safety_config or get_config().safety
        self.action_callback = action_callback
        
        self._enabled = False
        self._lock = threading.RLock()
        
        # Track active mitigations
        self.active_blocks: Dict[str, Dict] = {}  # mac -> {expires, rule_id}
        self.corrective_arp_pending: Dict[str, int] = {}  # ip -> count remaining
        
        # History
        self.action_history: List[MitigationAction] = []
        self.max_history = 1000
        
        # Statistics
        self.stats = {
            'corrective_arp_sent': 0,
            'firewall_blocks_added': 0,
            'firewall_blocks_removed': 0,
            'actions_failed': 0,
            'dry_run_actions': 0
        }
        
        # Check firewall backend
        self._firewall_backend = self._detect_firewall_backend()
        
        logger.info(f"Mitigation engine initialized (backend: {self._firewall_backend}, "
                   f"enabled: {self.config.enabled}, dry_run: {self.safety.dry_run})")
    
    def _detect_firewall_backend(self) -> str:
        """Detect available firewall backend."""
        for cmd in ['nft', 'iptables']:
            try:
                subprocess.run([cmd, '--version'], capture_output=True, check=False)
                return cmd
            except FileNotFoundError:
                continue
        return 'none'
    
    def enable(self):
        """Explicitly enable mitigation (safety requirement)."""
        if not self.config.enabled:
            raise RuntimeError("Mitigation not enabled in configuration. Set mitigation.enabled=true")
        
        if self.safety.dry_run:
            logger.info("Mitigation engine enabled in DRY-RUN mode")
        else:
            logger.warning("Mitigation engine enabled in LIVE mode - actions WILL be executed!")
        
        self._enabled = True
    
    def disable(self):
        """Disable mitigation and clean up."""
        self._enabled = False
        self._cleanup_all_blocks()
        logger.info("Mitigation engine disabled")
    
    def process_alert(self, alert: Alert) -> List[MitigationAction]:
        """Process an alert and take appropriate mitigation actions."""
        if not self._enabled:
            return []
        
        actions = []
        
        # Determine mitigation based on alert type and severity
        if alert.severity == AlertSeverity.CRITICAL:
            # Critical alerts get full mitigation
            if self.config.corrective_arp_enabled:
                actions.extend(self._send_corrective_arp(alert))
            
            if self.config.firewall_block_enabled and alert.alert_type in (
                AlertType.GATEWAY_IMPERSONATION,
                AlertType.TWO_WAY_SPOOFING,
                AlertType.MAC_SPOOFING
            ):
                actions.extend(self._block_attacker_mac(alert))
        
        elif alert.severity == AlertSeverity.WARNING:
            # Warning alerts get corrective ARP only
            if self.config.corrective_arp_enabled:
                actions.extend(self._send_corrective_arp(alert))
        
        # Record actions
        for action in actions:
            self._record_action(action)
        
        return actions
    
    def _send_corrective_arp(self, alert: Alert) -> List[MitigationAction]:
        """Send corrective ARP announcements to restore legitimate mapping."""
        actions = []
        
        # Determine the correct mapping
        correct_mac = alert.previous_mac
        target_ip = alert.sender_ip
        
        if not correct_mac:
            # Try to get from detection engine bindings
            logger.warning(f"No previous MAC for corrective ARP on {target_ip}")
            return actions
        
        # Check rate limiting
        key = f"{target_ip}:{correct_mac}"
        with self._lock:
            pending = self.corrective_arp_pending.get(key, 0)
            if pending > 0:
                logger.debug(f"Corrective ARP already pending for {key}")
                return actions
            
            self.corrective_arp_pending[key] = self.config.corrective_arp_count
        
        # Send corrective ARPs
        for i in range(self.config.corrective_arp_count):
            if self.safety.dry_run:
                action = MitigationAction(
                    timestamp=time.time(),
                    alert_id=alert.alert_id,
                    action_type="corrective_arp",
                    target_mac=correct_mac,
                    target_ip=target_ip,
                    success=True,
                    details=f"DRY-RUN: Would send corrective ARP {i+1}/{self.config.corrective_arp_count} "
                           f"for {target_ip} -> {correct_mac}",
                    dry_run=True
                )
                actions.append(action)
                self.stats['dry_run_actions'] += 1
            else:
                success = self._transmit_corrective_arp(target_ip, correct_mac, alert.target_ip)
                action = MitigationAction(
                    timestamp=time.time(),
                    alert_id=alert.alert_id,
                    action_type="corrective_arp",
                    target_mac=correct_mac,
                    target_ip=target_ip,
                    success=success,
                    details=f"Sent corrective ARP {i+1}/{self.config.corrective_arp_count} "
                           f"for {target_ip} -> {correct_mac}",
                    dry_run=False
                )
                actions.append(action)
                if success:
                    self.stats['corrective_arp_sent'] += 1
                else:
                    self.stats['actions_failed'] += 1
            
            # Wait between ARPs
            if i < self.config.corrective_arp_count - 1:
                time.sleep(self.config.corrective_arp_interval)
        
        # Clear pending
        with self._lock:
            self.corrective_arp_pending.pop(key, None)
        
        return actions
    
    def _transmit_corrective_arp(self, target_ip: str, correct_mac: str, 
                                  destination_ip: str) -> bool:
        """Transmit a corrective ARP announcement."""
        try:
            from scapy.all import ARP, Ether, sendp
            from ..config import get_config
            
            cfg = get_config()
            iface = cfg.network.interface
            
            # Send gratuitous ARP from the legitimate owner
            eth = Ether(src=correct_mac, dst="ff:ff:ff:ff:ff:ff")
            arp = ARP(
                op=2,  # Reply
                psrc=target_ip,
                hwsrc=correct_mac,
                pdst=target_ip,  # Gratuitous
                hwdst="00:00:00:00:00:00"
            )
            
            sendp(eth/arp, iface=iface, verbose=False)
            
            # Also send directed ARP to the poisoned victim
            if destination_ip and destination_ip != "192.168.1.255":
                eth2 = Ether(src=correct_mac, dst="ff:ff:ff:ff:ff:ff")
                arp2 = ARP(
                    op=2,
                    psrc=target_ip,
                    hwsrc=correct_mac,
                    pdst=destination_ip,
                    hwdst="ff:ff:ff:ff:ff:ff"
                )
                sendp(eth2/arp2, iface=iface, verbose=False)
            
            logger.info(f"Sent corrective ARP: {target_ip} -> {correct_mac}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send corrective ARP: {e}")
            return False
    
    def _block_attacker_mac(self, alert: Alert) -> List[MitigationAction]:
        """Block attacker MAC at host firewall."""
        actions = []
        attacker_mac = alert.sender_mac
        
        if not attacker_mac or attacker_mac == "ff:ff:ff:ff:ff:ff":
            return actions
        
        # Check if already blocked
        with self._lock:
            if attacker_mac in self.active_blocks:
                logger.debug(f"MAC {attacker_mac} already blocked")
                return actions
        
        if self.safety.dry_run:
            action = MitigationAction(
                timestamp=time.time(),
                alert_id=alert.alert_id,
                action_type="firewall_block",
                target_mac=attacker_mac,
                target_ip=alert.sender_ip,
                success=True,
                details=f"DRY-RUN: Would block MAC {attacker_mac} for {self.config.firewall_block_duration}s",
                dry_run=True
            )
            actions.append(action)
            self.stats['dry_run_actions'] += 1
            
            # Track for auto-expiry simulation
            with self._lock:
                self.active_blocks[attacker_mac] = {
                    'expires': time.time() + self.config.firewall_block_duration,
                    'rule_id': f'dryrun_{attacker_mac.replace(":", "")}',
                    'alert_id': alert.alert_id
                }
        else:
            success = self._add_firewall_rule(attacker_mac)
            action = MitigationAction(
                timestamp=time.time(),
                alert_id=alert.alert_id,
                action_type="firewall_block",
                target_mac=attacker_mac,
                target_ip=alert.sender_ip,
                success=success,
                details=f"Blocked MAC {attacker_mac} for {self.config.firewall_block_duration}s",
                dry_run=False
            )
            actions.append(action)
            if success:
                self.stats['firewall_blocks_added'] += 1
            else:
                self.stats['actions_failed'] += 1
        
        return actions
    
    def _add_firewall_rule(self, mac: str) -> bool:
        """Add firewall rule to block MAC."""
        try:
            if self._firewall_backend == 'nft':
                return self._add_nft_rule(mac)
            elif self._firewall_backend == 'iptables':
                return self._add_iptables_rule(mac)
            else:
                logger.error("No supported firewall backend available")
                return False
        except Exception as e:
            logger.error(f"Failed to add firewall rule: {e}")
            return False
    
    def _add_nft_rule(self, mac: str) -> bool:
        """Add nftables rule."""
        try:
            # Create table/chain if needed
            subprocess.run(['nft', 'add', 'table', 'inet', 'arpwatch'], 
                          capture_output=True, check=False)
            subprocess.run(['nft', 'add', 'chain', 'inet', 'arpwatch', 'input', 
                           '{ type filter hook input priority 0 ; }'],
                          capture_output=True, check=False)
            
            # Add rule
            rule = f'nft add rule inet arpwatch input ether saddr {mac} drop'
            result = subprocess.run(shlex.split(rule), capture_output=True, check=True)
            
            # Track for cleanup
            with self._lock:
                self.active_blocks[mac] = {
                    'expires': time.time() + self.config.firewall_block_duration,
                    'rule_id': f'nft_{mac.replace(":", "")}',
                    'backend': 'nft'
                }
            
            # Schedule auto-removal
            if self.config.auto_restore_on_timeout:
                threading.Timer(
                    self.config.firewall_block_duration,
                    self._remove_firewall_rule,
                    args=[mac]
                ).start()
            
            logger.info(f"Added nftables block for MAC {mac}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"nftables rule failed: {e.stderr.decode()}")
            return False
    
    def _add_iptables_rule(self, mac: str) -> bool:
        """Add iptables rule."""
        try:
            rule = ['iptables', '-A', 'INPUT', '-m', 'mac', '--mac-source', mac, '-j', 'DROP']
            subprocess.run(rule, capture_output=True, check=True)
            
            with self._lock:
                self.active_blocks[mac] = {
                    'expires': time.time() + self.config.firewall_block_duration,
                    'rule_id': f'iptables_{mac.replace(":", "")}',
                    'backend': 'iptables'
                }
            
            if self.config.auto_restore_on_timeout:
                threading.Timer(
                    self.config.firewall_block_duration,
                    self._remove_firewall_rule,
                    args=[mac]
                ).start()
            
            logger.info(f"Added iptables block for MAC {mac}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"iptables rule failed: {e.stderr.decode()}")
            return False
    
    def _remove_firewall_rule(self, mac: str):
        """Remove firewall rule for MAC."""
        with self._lock:
            block_info = self.active_blocks.pop(mac, None)
        
        if not block_info:
            return
        
        try:
            backend = block_info.get('backend', self._firewall_backend)
            
            if backend == 'nft':
                # nftables: delete by handle would be better, but we'll use a broad delete
                subprocess.run(['nft', 'delete', 'rule', 'inet', 'arpwatch', 'input', 
                               'ether', 'saddr', mac, 'drop'],
                              capture_output=True, check=False)
            elif backend == 'iptables':
                subprocess.run(['iptables', '-D', 'INPUT', '-m', 'mac', 
                               '--mac-source', mac, '-j', 'DROP'],
                              capture_output=True, check=False)
            
            self.stats['firewall_blocks_removed'] += 1
            logger.info(f"Removed firewall block for MAC {mac}")
            
        except Exception as e:
            logger.error(f"Failed to remove firewall rule for {mac}: {e}")
    
    def _cleanup_all_blocks(self):
        """Remove all active firewall blocks."""
        with self._lock:
            macs = list(self.active_blocks.keys())
        
        for mac in macs:
            self._remove_firewall_rule(mac)
    
    def _record_action(self, action: MitigationAction):
        """Record mitigation action in history."""
        with self._lock:
            self.action_history.append(action)
            if len(self.action_history) > self.max_history:
                self.action_history = self.action_history[-self.max_history:]
        
        if self.action_callback:
            try:
                self.action_callback(action)
            except Exception as e:
                logger.error(f"Action callback error: {e}")
    
    def get_stats(self) -> dict:
        """Get mitigation statistics."""
        with self._lock:
            active_count = len(self.active_blocks)
            return {
                **self.stats,
                'enabled': self._enabled,
                'dry_run': self.safety.dry_run,
                'firewall_backend': self._firewall_backend,
                'active_blocks': active_count,
                'pending_corrective_arp': len(self.corrective_arp_pending),
                'history_size': len(self.action_history)
            }
    
    def get_recent_actions(self, limit: int = 50) -> List[MitigationAction]:
        """Get recent mitigation actions."""
        with self._lock:
            return self.action_history[-limit:]
    
    def is_blocked(self, mac: str) -> bool:
        """Check if MAC is currently blocked."""
        with self._lock:
            if mac not in self.active_blocks:
                return False
            # Check expiry
            if time.time() > self.active_blocks[mac]['expires']:
                # Expired, clean up
                del self.active_blocks[mac]
                return False
            return True


def create_mitigation_engine(config: Optional[MitigationConfig] = None,
                            safety_config: Optional[SafetyConfig] = None,
                            action_callback: Optional[Callable[[MitigationAction], None]] = None) -> MitigationEngine:
    """Factory function to create mitigation engine."""
    return MitigationEngine(config, safety_config, action_callback)