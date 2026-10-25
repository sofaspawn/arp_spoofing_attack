"""Tests for detection engine."""
import unittest
import time
from arpwatch.models import ArpPacket, ArpOperation, AlertType, AlertSeverity
from arpwatch.detection.engine import DetectionEngine
from arpwatch.config import DetectionConfig


class TestDetectionEngine(unittest.TestCase):
    def setUp(self):
        config = DetectionConfig(
            mapping_change_enabled=True,
            duplicate_window_seconds=30.0,
            rate_limit_enabled=True,
            max_replies_per_window=5,
            rate_window_seconds=10.0,
            gratuitous_arp_enabled=True,
            gratuitous_threshold=3,
            mac_spoofing_enabled=True,
            max_ips_per_mac=3,
            baseline_learning_enabled=False,  # Disable for testing
            require_baseline_before_alert=False
        )
        self.engine = DetectionEngine(config=config)
        self.base_time = time.time()
    
    def _create_packet(self, ip, mac, op=ArpOperation.REPLY, target_ip="192.168.1.10", 
                       target_mac="02:00:00:00:00:10", timestamp=None, gratuitous=False):
        return ArpPacket(
            timestamp=timestamp or self.base_time,
            operation=op,
            sender_ip=ip,
            sender_mac=mac,
            target_ip=target_ip,
            target_mac=target_mac,
            is_gratuitous=gratuitous
        )
    
    def test_stable_binding_no_alert(self):
        """Stable IP-MAC binding should not generate alerts."""
        pkt = self._create_packet("192.168.1.1", "02:00:00:00:00:01")
        alerts = self.engine.process_packet(pkt)
        self.assertEqual(len(alerts), 0)
        
        # Repeat same binding
        pkt2 = self._create_packet("192.168.1.1", "02:00:00:00:00:01", timestamp=self.base_time + 1)
        alerts = self.engine.process_packet(pkt2)
        self.assertEqual(len(alerts), 0)
    
    def test_mapping_change_alert(self):
        """IP changing MAC should generate mapping change alert."""
        # Initial binding
        pkt1 = self._create_packet("192.168.1.1", "02:00:00:00:00:01")
        self.engine.process_packet(pkt1)
        
        # Change MAC
        pkt2 = self._create_packet("192.168.1.1", "02:00:00:00:00:99", timestamp=self.base_time + 2)
        alerts = self.engine.process_packet(pkt2)
        
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].alert_type, AlertType.MAPPING_CHANGE)
        self.assertEqual(alerts[0].sender_ip, "192.168.1.1")
        self.assertEqual(alerts[0].previous_mac, "02:00:00:00:00:01")
    
    def test_duplicate_mapping_alert(self):
        """Rapid MAC changes for same IP should generate duplicate mapping alert."""
        # Initial binding
        pkt1 = self._create_packet("192.168.1.1", "02:00:00:00:00:01")
        self.engine.process_packet(pkt1)
        
        # Change to attacker MAC
        pkt2 = self._create_packet("192.168.1.1", "02:00:00:00:00:99", timestamp=self.base_time + 2)
        self.engine.process_packet(pkt2)
        
        # Change back quickly (within duplicate window)
        pkt3 = self._create_packet("192.168.1.1", "02:00:00:00:00:01", timestamp=self.base_time + 5)
        alerts = self.engine.process_packet(pkt3)
        
        # Should get duplicate mapping alert
        dup_alerts = [a for a in alerts if a.alert_type == AlertType.DUPLICATE_MAPPING]
        self.assertEqual(len(dup_alerts), 1)
    
    def test_reply_rate_alert(self):
        """High ARP reply rate should generate rate alert."""
        # Send many replies quickly
        for i in range(8):
            pkt = self._create_packet("192.168.1.1", "02:00:00:00:00:01", 
                                     timestamp=self.base_time + i * 0.5)
            alerts = self.engine.process_packet(pkt)
        
        # Should trigger rate alert after threshold (5)
        rate_alerts = [a for a in alerts if a.alert_type == AlertType.REPLY_RATE_EXCEEDED]
        self.assertGreater(len(rate_alerts), 0)
    
    def test_gratuitous_arp_alert(self):
        """Excessive gratuitous ARPs should generate alert."""
        for i in range(5):
            pkt = self._create_packet("192.168.1.1", "02:00:00:00:00:99",
                                     timestamp=self.base_time + i * 10,
                                     gratuitous=True)
            alerts = self.engine.process_packet(pkt)
        
        # Should trigger gratuitous ARP alert after threshold (3)
        grat_alerts = [a for a in alerts if a.alert_type == AlertType.GRATUITOUS_ARP_FLOOD]
        self.assertGreater(len(grat_alerts), 0)
    
    def test_mac_spoofing_alert(self):
        """Single MAC claiming multiple IPs should generate alert."""
        attacker_mac = "02:00:00:00:00:99"
        
        # Claim 4 different IPs (threshold is 3)
        for i in range(1, 5):
            pkt = self._create_packet(f"192.168.1.{i}", attacker_mac,
                                     timestamp=self.base_time + i)
            alerts = self.engine.process_packet(pkt)
        
        # Should trigger MAC spoofing alert
        mac_alerts = [a for a in alerts if a.alert_type == AlertType.MAC_SPOOFING]
        self.assertGreater(len(mac_alerts), 0)
    
    def test_gateway_impersonation_alert(self):
        """Attacker claiming gateway IP should generate critical alert."""
        # First establish legitimate gateway
        pkt1 = self._create_packet("192.168.1.1", "02:00:00:00:00:01")
        self.engine.process_packet(pkt1)
        
        # Attacker claims gateway IP
        pkt2 = self._create_packet("192.168.1.1", "02:00:00:00:00:99", timestamp=self.base_time + 2)
        alerts = self.engine.process_packet(pkt2)
        
        gateway_alerts = [a for a in alerts if a.alert_type == AlertType.GATEWAY_IMPERSONATION]
        self.assertEqual(len(gateway_alerts), 1)
        self.assertEqual(gateway_alerts[0].severity, AlertSeverity.CRITICAL)
    
    def test_two_way_spoofing_alert(self):
        """Same MAC claiming gateway and victim should generate MITM alert."""
        attacker_mac = "02:00:00:00:00:99"
        
        # Attacker claims gateway IP
        pkt1 = self._create_packet("192.168.1.1", attacker_mac)
        self.engine.process_packet(pkt1)
        
        # Attacker claims victim IP
        pkt2 = self._create_packet("192.168.1.10", attacker_mac, timestamp=self.base_time + 1)
        alerts = self.engine.process_packet(pkt2)
        
        mitm_alerts = [a for a in alerts if a.alert_type == AlertType.TWO_WAY_SPOOFING]
        self.assertEqual(len(mitm_alerts), 1)
        self.assertEqual(mitm_alerts[0].severity, AlertSeverity.CRITICAL)
    
    def test_binding_retrieval(self):
        """Test binding retrieval methods."""
        pkt = self._create_packet("192.168.1.1", "02:00:00:00:00:01")
        self.engine.process_packet(pkt)
        
        binding = self.engine.get_binding("192.168.1.1")
        self.assertIsNotNone(binding)
        self.assertEqual(binding.mac, "02:00:00:00:00:01")
        
        all_bindings = self.engine.get_all_bindings()
        self.assertEqual(len(all_bindings), 1)
    
    def test_stats(self):
        """Test statistics collection."""
        stats = self.engine.get_stats()
        self.assertEqual(stats['packets_processed'], 0)
        self.assertEqual(stats['alerts_generated'], 0)
        
        pkt = self._create_packet("192.168.1.1", "02:00:00:00:00:01")
        self.engine.process_packet(pkt)
        
        stats = self.engine.get_stats()
        self.assertEqual(stats['packets_processed'], 1)
        self.assertEqual(stats['bindings_learned'], 1)


class TestOfflinePacketSource(unittest.TestCase):
    def test_create_test_packets(self):
        from arpwatch.detection.capture import create_test_packets
        
        for scenario in ['benign', 'gateway_impersonation', 'mitm_two_way', 
                        'reply_flood', 'gratuitous_flood', 'mac_spoofing', 'mixed']:
            packets = create_test_packets(scenario)
            self.assertGreater(len(packets), 0)
            for pkt in packets:
                self.assertIsInstance(pkt, ArpPacket)
                self.assertIn(pkt.operation, [ArpOperation.REQUEST, ArpOperation.REPLY])


if __name__ == '__main__':
    unittest.main()