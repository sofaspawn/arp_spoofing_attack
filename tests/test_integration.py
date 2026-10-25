"""Integration tests for the complete ARP spoofing detection system."""
import unittest
import time
import json
from arpwatch.config import Config, DetectionConfig
from arpwatch.models import ArpPacket, ArpOperation
from arpwatch.detection.engine import DetectionEngine
from arpwatch.detection.capture import create_test_packets
from arpwatch.evaluation.engine import EvaluationEngine
from arpwatch.attack.generator import create_attack_scenario, AttackGenerator
from arpwatch.config import SafetyConfig


class TestFullSystemIntegration(unittest.TestCase):
    """Test the complete pipeline: attack -> detection -> evaluation."""
    
    def setUp(self):
        self.detection_config = DetectionConfig(
            mapping_change_enabled=True,
            duplicate_window_seconds=30.0,
            rate_limit_enabled=True,
            max_replies_per_window=5,
            rate_window_seconds=10.0,
            gratuitous_arp_enabled=True,
            gratuitous_threshold=3,
            mac_spoofing_enabled=True,
            max_ips_per_mac=3,
            baseline_learning_enabled=False,
            require_baseline_before_alert=False
        )
        self.detection_engine = DetectionEngine(config=self.detection_config)
        self.evaluation_engine = EvaluationEngine()
        self.safety = SafetyConfig(dry_run=True, require_explicit_interface=False)
    
    def test_gateway_impersonation_scenario(self):
        """Test complete gateway impersonation detection."""
        # Create attack scenario
        attack_config = create_attack_scenario('gateway_impersonation')
        attack_config.duration_seconds = 2.0
        attack_config.interval_seconds = 0.2
        
        # Generate attack packets
        generator = AttackGenerator(config=attack_config, safety_config=self.safety)
        packets = []
        def collect(pkt):
            packets.append(pkt)
        generator.packet_callback = collect
        generator.enable()
        generator.start()
        time.sleep(2.5)
        generator.disable()
        
        # Add attack events as ground truth
        for event in generator.get_attack_events():
            self.evaluation_engine.add_ground_truth(event)
        
        # Process packets through detection
        for pkt in packets:
            alerts = self.detection_engine.process_packet(pkt)
            for alert in alerts:
                self.evaluation_engine.add_alert(alert)
        
        # Verify detection
        metrics = self.evaluation_engine.get_overall_metrics()
        self.assertGreater(metrics.true_positives, 0)
        self.assertEqual(metrics.false_negatives, 0)  # Should detect all
        
        # Should have gateway impersonation alerts
        correlations = self.evaluation_engine.get_correlation_details()
        gateway_alerts = [c for c in correlations if c['alert_type'] == 'gateway_impersonation']
        self.assertGreater(len(gateway_alerts), 0)
    
    def test_mitm_two_way_scenario(self):
        """Test MITM two-way spoofing detection."""
        attack_config = create_attack_scenario('mitm_two_way')
        attack_config.duration_seconds = 2.0
        attack_config.interval_seconds = 0.2
        
        generator = AttackGenerator(config=attack_config, safety_config=self.safety)
        packets = []
        generator.packet_callback = lambda p: packets.append(p)
        generator.enable()
        generator.start()
        time.sleep(2.5)
        generator.disable()
        
        for event in generator.get_attack_events():
            self.evaluation_engine.add_ground_truth(event)
        
        for pkt in packets:
            alerts = self.detection_engine.process_packet(pkt)
            for alert in alerts:
                self.evaluation_engine.add_alert(alert)
        
        metrics = self.evaluation_engine.get_overall_metrics()
        self.assertGreater(metrics.true_positives, 0)
        
        # Should detect two-way spoofing
        correlations = self.evaluation_engine.get_correlation_details()
        mitm_alerts = [c for c in correlations if c['alert_type'] == 'two_way_spoofing']
        self.assertGreater(len(mitm_alerts), 0)
    
    def test_reply_flood_scenario(self):
        """Test reply flood detection."""
        attack_config = create_attack_scenario('reply_flood')
        attack_config.duration_seconds = 1.0
        attack_config.interval_seconds = 0.05
        
        generator = AttackGenerator(config=attack_config, safety_config=self.safety)
        packets = []
        generator.packet_callback = lambda p: packets.append(p)
        generator.enable()
        generator.start()
        time.sleep(1.5)
        generator.disable()
        
        for event in generator.get_attack_events():
            self.evaluation_engine.add_ground_truth(event)
        
        for pkt in packets:
            alerts = self.detection_engine.process_packet(pkt)
            for alert in alerts:
                self.evaluation_engine.add_alert(alert)
        
        metrics = self.evaluation_engine.get_overall_metrics()
        # Reply flood uses legitimate MAC, so may not be "attack" in ground truth
        # But should trigger rate alerts
        correlations = self.evaluation_engine.get_correlation_details()
        rate_alerts = [c for c in correlations if c['alert_type'] == 'reply_rate_exceeded']
        self.assertGreater(len(rate_alerts), 0)
    
    def test_benign_traffic_no_false_positives(self):
        """Test that benign traffic doesn't generate false alerts."""
        packets = create_test_packets('benign')
        
        for pkt in packets:
            alerts = self.detection_engine.process_packet(pkt)
            for alert in alerts:
                self.evaluation_engine.add_alert(alert)
        
        metrics = self.evaluation_engine.get_overall_metrics()
        # Benign traffic should not generate alerts (or very few)
        self.assertEqual(metrics.total_alerts, 0)
    
    def test_mixed_scenario(self):
        """Test mixed benign and attack traffic."""
        packets = create_test_packets('mixed')
        
        # Add ground truth for attack portion
        attack_packets = create_test_packets('gateway_impersonation')
        for event in attack_packets[2:]:  # Skip initial benign packets
            if hasattr(event, '_attack_event') and event._attack_event:
                self.evaluation_engine.add_ground_truth(event._attack_event)
        
        for pkt in packets:
            alerts = self.detection_engine.process_packet(pkt)
            for alert in alerts:
                self.evaluation_engine.add_alert(alert)
        
        metrics = self.evaluation_engine.get_overall_metrics()
        self.assertGreater(metrics.true_positives, 0)
    
    def test_detection_stats_tracking(self):
        """Test that detection stats are properly tracked."""
        initial_stats = self.detection_engine.get_stats()
        self.assertEqual(initial_stats['packets_processed'], 0)
        
        packets = create_test_packets('gateway_impersonation')
        for pkt in packets:
            self.detection_engine.process_packet(pkt)
        
        final_stats = self.detection_engine.get_stats()
        self.assertEqual(final_stats['packets_processed'], len(packets))
        self.assertGreater(final_stats['alerts_generated'], 0)
        self.assertGreater(final_stats['bindings_learned'], 0)
        self.assertIn('gateway_impersonation', final_stats['alerts_by_type'])


class TestOfflineSimulation(unittest.TestCase):
    """Test the offline simulation mode."""
    
    def test_simulation_scenarios(self):
        """Test all simulation scenarios produce expected results."""
        from arpwatch.detection.capture import OfflinePacketSource
        from arpwatch.detection.engine import DetectionEngine
        from arpwatch.config import DetectionConfig
        
        config = DetectionConfig(
            baseline_learning_enabled=False,
            require_baseline_before_alert=False
        )
        
        scenarios_expected_alerts = {
            'benign': 0,
            'gateway_impersonation': 1,  # At least 1 gateway impersonation
            'mitm_two_way': 2,  # Gateway impersonation + two-way
            'reply_flood': 1,  # At least 1 rate alert
            'gratuitous_flood': 1,  # At least 1 gratuitous alert
            'mac_spoofing': 1,  # At least 1 MAC spoofing alert
        }
        
        for scenario, min_alerts in scenarios_expected_alerts.items():
            with self.subTest(scenario=scenario):
                engine = DetectionEngine(config=config)
                packets = create_test_packets(scenario)
                
                total_alerts = 0
                for pkt in packets:
                    alerts = engine.process_packet(pkt)
                    total_alerts += len(alerts)
                
                self.assertGreaterEqual(total_alerts, min_alerts, 
                    f"Scenario {scenario} expected at least {min_alerts} alerts, got {total_alerts}")


if __name__ == '__main__':
    unittest.main()