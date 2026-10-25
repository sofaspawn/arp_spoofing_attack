"""Focused regression tests for the presentation-critical offline pipeline."""
import unittest
from arpwatch.__main__ import build_trace
from arpwatch.models import ArpOperation
from arpwatch.detection.engine import DetectionEngine
from arpwatch.config import Config, set_config

class DemoPipelineTests(unittest.TestCase):
    def setUp(self):
        cfg=Config.load('configs/default.yaml')
        cfg.network.gateway_ip='192.168.1.1'; cfg.network.gateway_mac='02:00:00:00:00:01'
        cfg.detection.max_replies_per_window=8
        cfg.detection.gratuitous_threshold=3
        set_config(cfg)

    def test_replay_contains_benign_and_labeled_events(self):
        trace=build_trace()
        self.assertGreater(len(trace),15)
        self.assertTrue(any(k=='benign' for _,_,k in trace))
        self.assertTrue(any(k=='gateway_impersonation' for _,_,k in trace))
        self.assertTrue(any(k=='two_way_spoofing' for _,_,k in trace))

    def test_replay_raises_gateway_and_anomaly_alerts(self):
        detector=DetectionEngine()
        alerts=[]
        for _,packet,_ in build_trace(): alerts.extend(detector.process_packet(packet))
        kinds={a.alert_type.value for a in alerts}
        self.assertIn('gateway_impersonation',kinds)
        self.assertIn('mapping_change',kinds)
        self.assertIn('reply_rate_exceeded',kinds)
        self.assertIn('gratuitous_arp_flood',kinds)
        self.assertEqual(detector.get_stats()['packets_processed'],len(build_trace()))

if __name__=='__main__': unittest.main()
