"""Deterministic evaluation with explicit labeled events and response latency."""
import json
import time
from pathlib import Path
from ..models import DetectionMetrics

class EvaluationEngine:
    def __init__(self, config=None):
        self.config = config
        self.ground_truth = []
        self.alerts = []
        self.correlations = []

    def add_ground_truth(self, event): self.ground_truth.append(event)

    def add_alert(self, alert):
        self.alerts.append(alert)
        match = next((e for e in self.ground_truth if e.spoofed_ip == alert.sender_ip
                      and e.attacker_mac.lower() == alert.sender_mac.lower()
                      and abs(e.timestamp-alert.timestamp) <= 5), None)
        if match:
            match.detected = True
            latency = max(0.0, (alert.timestamp-match.timestamp)*1000)
            self.correlations.append({'alert_id': alert.alert_id, 'event_id': match.event_id,
                                      'true_positive': True, 'response_time_ms': latency})
        else:
            self.correlations.append({'alert_id': alert.alert_id, 'event_id': None,
                                      'true_positive': False, 'response_time_ms': None})

    def get_overall_metrics(self):
        detected_ids = {c['event_id'] for c in self.correlations if c['true_positive'] and c['event_id']}
        tp = len(detected_ids)
        fp = sum(c['event_id'] is None for c in self.correlations)
        fn = sum(e.event_id not in detected_ids for e in self.ground_truth)
        # Specificity/FPR need a defined number of benign opportunities. Report only
        # labeled replay packet counts where available; never invent true negatives.
        return {'attacks': len(self.ground_truth), 'alerts': len(self.alerts), 'tp': tp, 'fp': fp, 'fn': fn,
                'precision': tp/(tp+fp) if tp+fp else 0.0,
                'recall': tp/(tp+fn) if tp+fn else 0.0,
                'false_negative_rate': fn/(tp+fn) if tp+fn else 0.0,
                'mean_response_ms': (sum(min(c['response_time_ms'] for c in self.correlations if c['true_positive'] and c['event_id']==event_id) for event_id in detected_ids)/tp if tp else 0.0),
                'note': 'Accuracy and false-positive rate require labeled benign/attack decision windows; not estimated here.'}

    def export_results(self, path=None):
        data = {'metrics': self.get_overall_metrics(), 'correlations': self.correlations,
                'ground_truth': [e.to_dict() for e in self.ground_truth],
                'alerts': [a.to_dict() for a in self.alerts]}
        path = path or 'logs/evaluation_results.json'
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(data, indent=2))
        return data

    def print_summary(self):
        m = self.get_overall_metrics()
        print('\nEVALUATION (labeled replay)')
        for k,v in m.items(): print(f'  {k}: {v}')
