import unittest
from arpwatch.core import ArpDetector, ArpEvent
from arpwatch.scenarios import scenario

class DetectorTests(unittest.TestCase):
    def test_stable_binding_is_not_flagged(self):
        d = ArpDetector()
        self.assertEqual(d.process(ArpEvent(1, "reply", "10.0.0.1", "aa")), [])
        self.assertEqual(d.process(ArpEvent(2, "reply", "10.0.0.1", "aa")), [])
    def test_mapping_change_and_duplicate(self):
        d = ArpDetector()
        d.process(ArpEvent(1, "reply", "10.0.0.1", "aa"))
        alerts = d.process(ArpEvent(2, "reply", "10.0.0.1", "bb"))
        self.assertEqual(alerts[0].rule, "duplicate_mapping")
    def test_rate_threshold(self):
        d = ArpDetector(rate_limit=2)
        results = [d.process(ArpEvent(t, "reply", "10.0.0.1", "aa")) for t in (1, 2, 3)]
        self.assertTrue(any(a.rule == "reply_rate" for a in results[-1]))
    def test_attack_scenarios_raise_alert(self):
        for name in ("gateway-impersonation", "two-way"):
            events, _ = scenario(name)
            d = ArpDetector()
            alerts = [a for e in events for a in d.process(e)]
            self.assertTrue(alerts, name)

if __name__ == "__main__":
    unittest.main()
