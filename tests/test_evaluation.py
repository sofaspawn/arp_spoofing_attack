"""Tests for evaluation engine."""
import unittest
import time
from arpwatch.evaluation.engine import EvaluationEngine, CorrelationResult
from arpwatch.models import Alert, AlertType, AlertSeverity, AttackEvent


class TestEvaluationEngine(unittest.TestCase):
    def setUp(self):
        self.engine = EvaluationEngine()
        self.base_time = time.time()
    
    def _create_alert(self, alert_type, sender_ip, sender_mac, target_ip="192.168.1.10", 
                      previous_mac=None, timestamp=None):
        return Alert.create(
            alert_type=alert_type,
            severity=AlertSeverity.WARNING,
            sender_ip=sender_ip,
            sender_mac=sender_mac,
            target_ip=target_ip,
            previous_mac=previous_mac,
            message=f"Test {alert_type.value}",
            timestamp=timestamp or self.base_time
        )
    
    def _create_attack_event(self, attack_type, attacker_mac, spoofed_ip, spoofed_mac,
                             target_ip="192.168.1.10", timestamp=None):
        return AttackEvent(
            event_id=f"test_{attack_type}",
            timestamp=timestamp or self.base_time,
            attack_type=attack_type,
            attacker_mac=attacker_mac,
            target_ip=target_ip,
            spoofed_ip=spoofed_ip,
            spoofed_mac=spoofed_mac,
            description=f"Test {attack_type}"
        )
    
    def test_true_positive_correlation(self):
        """Alert matching ground truth should be true positive."""
        # Add ground truth
        event = self._create_attack_event(
            'gateway_impersonation',
            '02:00:00:00:00:99',
            '192.168.1.1',
            '02:00:00:00:00:99'
        )
        self.engine.add_ground_truth(event)
        
        # Add matching alert
        alert = self._create_alert(
            AlertType.GATEWAY_IMPERSONATION,
            '192.168.1.1',
            '02:00:00:00:00:99'
        )
        self.engine.add_alert(alert)
        
        # Check correlation
        correlations = self.engine.get_correlation_details()
        self.assertEqual(len(correlations), 1)
        self.assertTrue(correlations[0]['is_true_positive'])
        self.assertEqual(correlations[0]['matched_attack_type'], 'gateway_impersonation')
    
    def test_false_positive_no_ground_truth(self):
        """Alert without matching ground truth should be false positive."""
        alert = self._create_alert(
            AlertType.MAPPING_CHANGE,
            '192.168.1.5',
            '02:00:00:00:00:99'
        )
        self.engine.add_alert(alert)
        
        correlations = self.engine.get_correlation_details()
        self.assertEqual(len(correlations), 1)
        self.assertFalse(correlations[0]['is_true_positive'])
        self.assertIsNone(correlations[0]['matched_event_id'])
    
    def test_false_negative_missed_attack(self):
        """Ground truth without matching alert should be false negative."""
        event = self._create_attack_event(
            'mitm_two_way',
            '02:00:00:00:00:99',
            '192.168.1.1',
            '02:00:00:00:00:99'
        )
        self.engine.add_ground_truth(event)
        
        # No alert added
        
        metrics = self.engine.get_overall_metrics()
        self.assertEqual(metrics.total_attacks, 1)
        self.assertEqual(metrics.true_positives, 0)
        self.assertEqual(metrics.false_negatives, 1)
    
    def test_metrics_computation(self):
        """Test overall metrics computation."""
        # Add ground truth events
        for i in range(5):
            event = self._create_attack_event(
                'gateway_impersonation',
                '02:00:00:00:00:99',
                '192.168.1.1',
                '02:00:00:00:00:99',
                timestamp=self.base_time + i * 10
            )
            self.engine.add_ground_truth(event)
        
        # Add matching alerts (3 TP)
        for i in range(3):
            alert = self._create_alert(
                AlertType.GATEWAY_IMPERSONATION,
                '192.168.1.1',
                '02:00:00:00:00:99',
                timestamp=self.base_time + i * 10 + 1
            )
            self.engine.add_alert(alert)
        
        # Add non-matching alerts (2 FP)
        for i in range(2):
            alert = self._create_alert(
                AlertType.MAPPING_CHANGE,
                '192.168.1.5',
                '02:00:00:00:00:aa',
                timestamp=self.base_time + i * 10 + 5
            )
            self.engine.add_alert(alert)
        
        metrics = self.engine.get_overall_metrics()
        self.assertEqual(metrics.total_attacks, 5)
        self.assertEqual(metrics.total_alerts, 5)
        self.assertEqual(metrics.true_positives, 3)
        self.assertEqual(metrics.false_positives, 2)
        self.assertEqual(metrics.false_negatives, 2)  # 5 attacks - 3 detected
        
        # Check derived metrics
        self.assertAlmostEqual(metrics.precision, 0.6, places=1)
        self.assertAlmostEqual(metrics.recall, 0.6, places=1)
    
    def test_response_time_calculation(self):
        """Test response time calculation."""
        event = self._create_attack_event(
            'gateway_impersonation',
            '02:00:00:00:00:99',
            '192.168.1.1',
            '02:00:00:00:00:99',
            timestamp=self.base_time
        )
        self.engine.add_ground_truth(event)
        
        # Alert 100ms after attack
        alert = self._create_alert(
            AlertType.GATEWAY_IMPERSONATION,
            '192.168.1.1',
            '02:00:00:00:00:99',
            timestamp=self.base_time + 0.1
        )
        self.engine.add_alert(alert)
        
        correlations = self.engine.get_correlation_details()
        self.assertAlmostEqual(correlations[0]['response_time_ms'], 100, delta=10)
    
    def test_export_results(self):
        """Test results export."""
        event = self._create_attack_event(
            'gateway_impersonation',
            '02:00:00:00:00:99',
            '192.168.1.1',
            '02:00:00:00:00:99'
        )
        self.engine.add_ground_truth(event)
        
        alert = self._create_alert(
            AlertType.GATEWAY_IMPERSONATION,
            '192.168.1.1',
            '02:00:00:00:00:99'
        )
        self.engine.add_alert(alert)
        
        results = self.engine.export_results()
        
        self.assertIn('overall_metrics', results)
        self.assertIn('correlation_details', results)
        self.assertEqual(results['ground_truth_count'], 1)
        self.assertEqual(results['total_alerts'], 1)
    
    def test_reset(self):
        """Test engine reset."""
        event = self._create_attack_event('test', 'aa', '1.1.1.1', 'aa')
        self.engine.add_ground_truth(event)
        
        alert = self._create_alert(AlertType.MAPPING_CHANGE, '1.1.1.1', 'aa')
        self.engine.add_alert(alert)
        
        self.engine.reset()
        
        metrics = self.engine.get_overall_metrics()
        self.assertEqual(metrics.total_attacks, 0)
        self.assertEqual(metrics.total_alerts, 0)


if __name__ == '__main__':
    unittest.main()