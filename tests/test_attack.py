"""Tests for attack generator."""
import unittest
import time
from arpwatch.attack.generator import (
    AttackGenerator, AttackConfig, AttackMode, create_attack_scenario
)
from arpwatch.models import ArpPacket, ArpOperation
from arpwatch.config import SafetyConfig


class TestAttackGenerator(unittest.TestCase):
    def setUp(self):
        self.safety = SafetyConfig(dry_run=True, require_explicit_interface=False)
    
    def test_attack_config_creation(self):
        config = AttackConfig(
            mode=AttackMode.ONE_WAY,
            attacker_mac="02:00:00:00:00:99",
            victim_ip="192.168.1.10",
            gateway_ip="192.168.1.1"
        )
        self.assertEqual(config.mode, AttackMode.ONE_WAY)
        self.assertEqual(config.attacker_mac, "02:00:00:00:00:99")
    
    def test_create_attack_scenarios(self):
        for name in ['gateway_impersonation', 'mitm_two_way', 'reply_flood', 'gratuitous_flood']:
            config = create_attack_scenario(name)
            self.assertIsInstance(config, AttackConfig)
            self.assertEqual(config.mode.value, name.replace('_', '-') if name != 'mitm_two_way' else 'two_way')
    
    def test_attack_generator_dry_run(self):
        config = create_attack_scenario('gateway_impersonation')
        config.duration_seconds = 1.0
        config.interval_seconds = 0.1
        
        generator = AttackGenerator(config=config, safety_config=self.safety)
        generator.enable()
        generator.start()
        
        # Wait for completion
        time.sleep(1.5)
        generator.disable()
        
        stats = generator.get_stats()
        self.assertGreater(stats['packets_sent'], 0)
        self.assertTrue(stats['dry_run'])
    
    def test_one_way_attack_packets(self):
        config = AttackConfig(
            mode=AttackMode.ONE_WAY,
            attacker_mac="02:00:00:00:00:99",
            victim_ip="192.168.1.10",
            victim_mac="02:00:00:00:00:10",
            gateway_ip="192.168.1.1",
            gateway_mac="02:00:00:00:00:01",
            interval_seconds=0.1,
            duration_seconds=0.5,
            packets_per_burst=1
        )
        
        packets_received = []
        def callback(pkt):
            packets_received.append(pkt)
        
        generator = AttackGenerator(config=config, safety_config=self.safety, packet_callback=callback)
        generator.enable()
        generator.start()
        
        time.sleep(0.8)
        generator.disable()
        
        # Should have generated packets
        self.assertGreater(len(packets_received), 0)
        
        # Check packet structure
        for pkt in packets_received:
            self.assertEqual(pkt.sender_ip, "192.168.1.1")  # Gateway IP
            self.assertEqual(pkt.sender_mac, "02:00:00:00:00:99")  # Attacker MAC
            self.assertEqual(pkt.target_ip, "192.168.1.10")  # Victim IP
            self.assertEqual(pkt.operation, ArpOperation.REPLY)
    
    def test_two_way_attack_packets(self):
        config = AttackConfig(
            mode=AttackMode.TWO_WAY,
            attacker_mac="02:00:00:00:00:99",
            victim_ip="192.168.1.10",
            victim_mac="02:00:00:00:00:10",
            gateway_ip="192.168.1.1",
            gateway_mac="02:00:00:00:00:01",
            interval_seconds=0.1,
            duration_seconds=0.5,
            packets_per_burst=1
        )
        
        packets_received = []
        def callback(pkt):
            packets_received.append(pkt)
        
        generator = AttackGenerator(config=config, safety_config=self.safety, packet_callback=callback)
        generator.enable()
        generator.start()
        
        time.sleep(0.8)
        generator.disable()
        
        # Should have generated packets in both directions
        gateway_spoof = [p for p in packets_received if p.sender_ip == "192.168.1.1"]
        victim_spoof = [p for p in packets_received if p.sender_ip == "192.168.1.10"]
        
        self.assertGreater(len(gateway_spoof), 0)
        self.assertGreater(len(victim_spoof), 0)
    
    def test_attack_events_recorded(self):
        config = create_attack_scenario('gateway_impersonation')
        config.duration_seconds = 0.5
        config.interval_seconds = 0.1
        
        generator = AttackGenerator(config=config, safety_config=self.safety)
        generator.enable()
        generator.start()
        
        time.sleep(0.8)
        generator.disable()
        
        events = generator.get_attack_events()
        self.assertGreater(len(events), 0)
        
        for event in events:
            self.assertEqual(event.attacker_mac, "02:00:00:00:00:99")
            self.assertEqual(event.spoofed_ip, "192.168.1.1")
            self.assertEqual(event.spoofed_mac, "02:00:00:00:00:99")


if __name__ == '__main__':
    unittest.main()