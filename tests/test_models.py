"""Tests for data models."""
import unittest
import time
from arpwatch.models import (
    ArpPacket, ArpOperation, IpMacBinding, Alert, AlertType, AlertSeverity,
    AttackEvent, DetectionMetrics, parse_mac, is_valid_ip, is_valid_mac
)


class TestModels(unittest.TestCase):
    def test_arp_packet_creation(self):
        pkt = ArpPacket(
            timestamp=time.time(),
            operation=ArpOperation.REPLY,
            sender_ip="192.168.1.1",
            sender_mac="02:00:00:00:00:01",
            target_ip="192.168.1.10",
            target_mac="02:00:00:00:00:10"
        )
        self.assertEqual(pkt.operation, ArpOperation.REPLY)
        self.assertEqual(pkt.sender_ip, "192.168.1.1")
        d = pkt.to_dict()
        self.assertIn('timestamp_iso', d)
        self.assertEqual(d['operation'], 'REPLY')
    
    def test_ip_mac_binding(self):
        binding = IpMacBinding(
            ip="192.168.1.1",
            mac="02:00:00:00:00:01",
            first_seen=time.time(),
            last_seen=time.time()
        )
        binding.update(time.time() + 10)
        self.assertEqual(binding.seen_count, 2)
        d = binding.to_dict()
        self.assertIn('first_seen_iso', d)
    
    def test_alert_creation(self):
        alert = Alert.create(
            alert_type=AlertType.MAPPING_CHANGE,
            severity=AlertSeverity.WARNING,
            sender_ip="192.168.1.1",
            sender_mac="02:00:00:00:00:99",
            target_ip="192.168.1.10",
            previous_mac="02:00:00:00:00:01",
            message="Test alert"
        )
        self.assertEqual(alert.alert_type, AlertType.MAPPING_CHANGE)
        self.assertEqual(alert.severity, AlertSeverity.WARNING)
        d = alert.to_dict()
        self.assertEqual(d['alert_type'], 'mapping_change')
    
    def test_detection_metrics(self):
        m = DetectionMetrics(window_start=0, window_end=60)
        m.true_positives = 10
        m.false_positives = 2
        m.true_negatives = 80
        m.false_negatives = 1
        m.total_attacks = 11
        m.total_alerts = 12
        
        self.assertAlmostEqual(m.accuracy, 0.966, places=2)
        self.assertAlmostEqual(m.precision, 0.833, places=2)
        self.assertAlmostEqual(m.recall, 0.909, places=2)
        self.assertAlmostEqual(m.f1_score, 0.869, places=2)
        self.assertAlmostEqual(m.false_positive_rate, 0.024, places=2)
        self.assertAlmostEqual(m.false_negative_rate, 0.091, places=2)
    
    def test_parse_mac(self):
        self.assertEqual(parse_mac("02:00:00:00:00:01"), "02:00:00:00:00:01")
        self.assertEqual(parse_mac("02-00-00-00-00-01"), "02:00:00:00:00:01")
        self.assertEqual(parse_mac("0200.0000.0001"), "02:00:00:00:00:01")
        self.assertEqual(parse_mac("2:0:0:0:0:1"), "02:00:00:00:00:01")
    
    def test_is_valid_ip(self):
        self.assertTrue(is_valid_ip("192.168.1.1"))
        self.assertTrue(is_valid_ip("0.0.0.0"))
        self.assertTrue(is_valid_ip("255.255.255.255"))
        self.assertFalse(is_valid_ip("256.1.1.1"))
        self.assertFalse(is_valid_ip("192.168.1"))
        self.assertFalse(is_valid_ip("not.an.ip"))
    
    def test_is_valid_mac(self):
        self.assertTrue(is_valid_mac("02:00:00:00:00:01"))
        self.assertTrue(is_valid_mac("ff:ff:ff:ff:ff:ff"))
        self.assertFalse(is_valid_mac("02:00:00:00:00"))
        self.assertFalse(is_valid_mac("gg:00:00:00:00:01"))
        self.assertFalse(is_valid_mac("not-a-mac"))


if __name__ == '__main__':
    unittest.main()