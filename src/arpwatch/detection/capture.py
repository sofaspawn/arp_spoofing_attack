"""Packet Capture Module - Interfaces with Scapy for live ARP packet capture."""
from __future__ import annotations
from typing import Optional, Callable, List
import threading
import time
import logging
import queue

from ..models import ArpPacket, ArpOperation
from ..config import get_config

logger = logging.getLogger(__name__)


class PacketCapture:
    """Live ARP packet capture using Scapy.
    
    Features:
    - Runs in background thread
    - BPF filter for ARP only
    - Thread-safe packet queue
    - Graceful start/stop
    - Statistics tracking
    """
    
    def __init__(self, interface: Optional[str] = None,
                 packet_callback: Optional[Callable[[ArpPacket], None]] = None,
                 bpf_filter: str = "arp"):
        self.interface = interface or get_config().network.interface
        self.packet_callback = packet_callback
        self.bpf_filter = bpf_filter
        
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._packet_queue: queue.Queue = queue.Queue(maxsize=10000)
        self._scapy_available = self._check_scapy()
        
        # Statistics
        self.packets_captured = 0
        self.packets_dropped = 0
        self.packets_processed = 0
        self.errors = 0
        self.start_time: Optional[float] = None
        self.last_packet_time: Optional[float] = None
    
    def _check_scapy(self) -> bool:
        try:
            from scapy.all import sniff, ARP
            return True
        except ImportError:
            logger.warning("Scapy not available - packet capture disabled")
            return False
    
    def start(self) -> bool:
        """Start packet capture in background thread."""
        if not self._scapy_available:
            logger.error("Cannot start capture: Scapy not available")
            return False
        
        if self._running:
            logger.warning("Capture already running")
            return True
        
        self._running = True
        self._stop_event.clear()
        self.start_time = time.time()
        self.packets_captured = 0
        self.packets_dropped = 0
        self.packets_processed = 0
        self.errors = 0
        
        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()
        
        logger.info(f"Packet capture started on interface {self.interface} with filter '{self.bpf_filter}'")
        return True
    
    def stop(self):
        """Stop packet capture."""
        if not self._running:
            return
        
        self._running = False
        self._stop_event.set()
        
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)
        
        logger.info(f"Packet capture stopped. Captured: {self.packets_captured}, "
                   f"Processed: {self.packets_processed}, Dropped: {self.packets_dropped}")
    
    def _capture_loop(self):
        """Main capture loop running in background thread."""
        try:
            from scapy.all import sniff, ARP
            
            def packet_handler(pkt):
                if not self._running:
                    return True  # Stop sniffing
                
                if ARP not in pkt:
                    return
                
                self.packets_captured += 1
                self.last_packet_time = time.time()
                
                try:
                    arp_packet = ArpPacket.from_scapy(pkt)
                    
                    # Try to queue for processing
                    try:
                        self._packet_queue.put_nowait(arp_packet)
                    except queue.Full:
                        self.packets_dropped += 1
                        
                except Exception as e:
                    self.errors += 1
                    logger.debug(f"Error parsing ARP packet: {e}")
            
            # Start sniffing
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=packet_handler,
                store=False,
                stop_filter=lambda _: not self._running
            )
            
        except Exception as e:
            logger.error(f"Capture loop error: {e}")
            self.errors += 1
        finally:
            self._running = False
    
    def process_queued_packets(self, max_packets: int = 100) -> List[ArpPacket]:
        """Process queued packets (call from main thread)."""
        packets = []
        for _ in range(min(max_packets, self._packet_queue.qsize())):
            try:
                pkt = self._packet_queue.get_nowait()
                packets.append(pkt)
                self.packets_processed += 1
                
                if self.packet_callback:
                    try:
                        self.packet_callback(pkt)
                    except Exception as e:
                        logger.error(f"Packet callback error: {e}")
                        self.errors += 1
                        
            except queue.Empty:
                break
        return packets
    
    def get_stats(self) -> dict:
        """Get capture statistics."""
        uptime = time.time() - self.start_time if self.start_time else 0
        return {
            'running': self._running,
            'interface': self.interface,
            'filter': self.bpf_filter,
            'packets_captured': self.packets_captured,
            'packets_processed': self.packets_processed,
            'packets_dropped': self.packets_dropped,
            'errors': self.errors,
            'queue_size': self._packet_queue.qsize(),
            'uptime_seconds': uptime,
            'packets_per_second': self.packets_captured / uptime if uptime > 0 else 0,
            'last_packet_ago': time.time() - self.last_packet_time if self.last_packet_time else None
        }
    
    def is_running(self) -> bool:
        return self._running


class OfflinePacketSource:
    """Offline packet source for testing with PCAP files or generated traces."""
    
    def __init__(self, packets: List[ArpPacket], 
                 packet_callback: Optional[Callable[[ArpPacket], None]] = None,
                 replay_speed: float = 1.0):
        self.packets = packets
        self.packet_callback = packet_callback
        self.replay_speed = replay_speed
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._index = 0
        self.packets_sent = 0
    
    def start(self):
        """Start replaying packets."""
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._index = 0
        self.packets_sent = 0
        self._thread = threading.Thread(target=self._replay_loop, daemon=True)
        self._thread.start()
        logger.info(f"Offline packet replay started: {len(self.packets)} packets at {self.replay_speed}x speed")
    
    def stop(self):
        """Stop replay."""
        self._running = False
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        logger.info(f"Offline replay stopped. Sent {self.packets_sent} packets.")
    
    def _replay_loop(self):
        """Replay packets with timing."""
        if not self.packets:
            return
        
        start_time = self.packets[0].timestamp
        real_start = time.time()
        
        for i, pkt in enumerate(self.packets):
            if not self._running or self._stop_event.is_set():
                break
            
            # Calculate when to send this packet
            if i > 0:
                expected_elapsed = (pkt.timestamp - start_time) / self.replay_speed
                real_elapsed = time.time() - real_start
                sleep_time = expected_elapsed - real_elapsed
                if sleep_time > 0:
                    self._stop_event.wait(sleep_time)
            
            if not self._running:
                break
            
            self.packets_sent += 1
            if self.packet_callback:
                try:
                    self.packet_callback(pkt)
                except Exception as e:
                    logger.error(f"Replay callback error: {e}")
        
        self._running = False
        logger.info("Offline replay completed")


def create_test_packets(scenario: str = "mixed") -> List[ArpPacket]:
    """Create test packet traces for offline testing."""
    from ..attack.generator import create_attack_scenario, AttackMode
    from ..models import ArpPacket, ArpOperation
    
    packets = []
    base_time = time.time()
    
    if scenario == "benign":
        # Normal ARP traffic
        packets = [
            ArpPacket(base_time, ArpOperation.REQUEST, "192.168.1.10", "02:00:00:00:00:10", "192.168.1.1", "00:00:00:00:00:00"),
            ArpPacket(base_time + 0.1, ArpOperation.REPLY, "192.168.1.1", "02:00:00:00:00:01", "192.168.1.10", "02:00:00:00:00:10"),
            ArpPacket(base_time + 1.0, ArpOperation.REQUEST, "192.168.1.20", "02:00:00:00:00:20", "192.168.1.1", "00:00:00:00:00:00"),
            ArpPacket(base_time + 1.1, ArpOperation.REPLY, "192.168.1.1", "02:00:00:00:00:01", "192.168.1.20", "02:00:00:00:00:20"),
            ArpPacket(base_time + 5.0, ArpOperation.REPLY, "192.168.1.1", "02:00:00:00:00:01", "192.168.1.10", "02:00:00:00:00:10"),  # Refresh
        ]
    
    elif scenario == "gateway_impersonation":
        # Normal then attack
        packets = [
            ArpPacket(base_time, ArpOperation.REPLY, "192.168.1.1", "02:00:00:00:00:01", "192.168.1.10", "02:00:00:00:00:10"),
            ArpPacket(base_time + 1.0, ArpOperation.REPLY, "192.168.1.1", "02:00:00:00:00:01", "192.168.1.20", "02:00:00:00:00:20"),
            # Attack starts
            ArpPacket(base_time + 2.0, ArpOperation.REPLY, "192.168.1.1", "02:00:00:00:00:99", "192.168.1.10", "02:00:00:00:00:10"),
            ArpPacket(base_time + 4.0, ArpOperation.REPLY, "192.168.1.1", "02:00:00:00:00:99", "192.168.1.20", "02:00:00:00:00:20"),
            ArpPacket(base_time + 6.0, ArpOperation.REPLY, "192.168.1.1", "02:00:00:00:00:99", "192.168.1.10", "02:00:00:00:00:10"),
        ]
    
    elif scenario == "mitm_two_way":
        packets = [
            ArpPacket(base_time, ArpOperation.REPLY, "192.168.1.1", "02:00:00:00:00:01", "192.168.1.10", "02:00:00:00:00:10"),
            ArpPacket(base_time + 1.0, ArpOperation.REPLY, "192.168.1.10", "02:00:00:00:00:10", "192.168.1.1", "02:00:00:00:00:01"),
            # Attack - both directions
            ArpPacket(base_time + 2.0, ArpOperation.REPLY, "192.168.1.1", "02:00:00:00:00:99", "192.168.1.10", "02:00:00:00:00:10"),
            ArpPacket(base_time + 2.1, ArpOperation.REPLY, "192.168.1.10", "02:00:00:00:00:99", "192.168.1.1", "02:00:00:00:00:01"),
            ArpPacket(base_time + 4.0, ArpOperation.REPLY, "192.168.1.1", "02:00:00:00:00:99", "192.168.1.10", "02:00:00:00:00:10"),
            ArpPacket(base_time + 4.1, ArpOperation.REPLY, "192.168.1.10", "02:00:00:00:00:99", "192.168.1.1", "02:00:00:00:00:01"),
        ]
    
    elif scenario == "reply_flood":
        packets = [
            ArpPacket(base_time, ArpOperation.REPLY, "192.168.1.1", "02:00:00:00:00:01", "192.168.1.10", "02:00:00:00:00:10"),
        ]
        # Flood of replies
        for i in range(15):
            packets.append(ArpPacket(
                base_time + 1.0 + i * 0.1,
                ArpOperation.REPLY,
                "192.168.1.1", "02:00:00:00:00:01",
                "192.168.1.10", "02:00:00:00:00:10"
            ))
    
    elif scenario == "gratuitous_flood":
        packets = [
            ArpPacket(base_time, ArpOperation.REPLY, "192.168.1.1", "02:00:00:00:00:01", "192.168.1.10", "02:00:00:00:00:10"),
        ]
        for i in range(5):
            packets.append(ArpPacket(
                base_time + 1.0 + i * 0.5,
                ArpOperation.REPLY,
                "192.168.1.1", "02:00:00:00:00:99",
                "192.168.1.1", "02:00:00:00:00:99",
                is_gratuitous=True
            ))
    
    elif scenario == "mac_spoofing":
        packets = [
            ArpPacket(base_time, ArpOperation.REPLY, "192.168.1.1", "02:00:00:00:00:01", "192.168.1.10", "02:00:00:00:00:10"),
            ArpPacket(base_time + 1.0, ArpOperation.REPLY, "192.168.1.2", "02:00:00:00:00:99", "192.168.1.10", "02:00:00:00:00:10"),
            ArpPacket(base_time + 2.0, ArpOperation.REPLY, "192.168.1.3", "02:00:00:00:00:99", "192.168.1.10", "02:00:00:00:00:10"),
            ArpPacket(base_time + 3.0, ArpOperation.REPLY, "192.168.1.4", "02:00:00:00:00:99", "192.168.1.10", "02:00:00:00:00:10"),
            ArpPacket(base_time + 4.0, ArpOperation.REPLY, "192.168.1.5", "02:00:00:00:00:99", "192.168.1.10", "02:00:00:00:00:10"),
        ]
    
    else:  # mixed
        packets = create_test_packets("benign") + create_test_packets("gateway_impersonation")[2:]
    
    return packets


import time  # For create_test_packets