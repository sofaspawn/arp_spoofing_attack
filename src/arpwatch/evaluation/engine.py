"""Evaluation Module - Metrics computation and ground truth correlation."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import time
import threading
import json
import logging
from pathlib import Path
from collections import defaultdict

from ..models import Alert, AttackEvent, DetectionMetrics, AlertType, AlertSeverity
from ..config import get_config, EvaluationConfig

logger = logging.getLogger(__name__)


@dataclass
class CorrelationResult:
    """Result of correlating an alert with ground truth."""
    alert: Alert
    matched_event: Optional[AttackEvent]
    is_true_positive: bool
    response_time_ms: float
    match_reason: str


class EvaluationEngine:
    """Evaluation engine for computing detection metrics.
    
    Features:
    - Real-time metric computation
    - Ground truth correlation
    - Time-windowed metrics
    - Detailed event logging
    - Export for analysis
    """
    
    def __init__(self, config: Optional[EvaluationConfig] = None):
        self.config = config or get_config().evaluation
        self._lock = threading.RLock()
        
        # Ground truth events (attack events)
        self.ground_truth: List[AttackEvent] = []
        
        # Alerts generated
        self.alerts: List[Alert] = []
        
        # Correlation results
        self.correlations: List[CorrelationResult] = []
        
        # Metrics history
        self.metrics_history: List[DetectionMetrics] = []
        
        # Current window metrics
        self.current_window_start = time.time()
        self.current_metrics = DetectionMetrics(
            window_start=self.current_window_start,
            window_end=self.current_window_start + self.config.metrics_window_seconds
        )
        
        # Load existing ground truth if file exists
        self._load_ground_truth()
        
        logger.info("Evaluation engine initialized")
    
    def _load_ground_truth(self):
        """Load ground truth events from file."""
        path = Path(self.config.ground_truth_file)
        if path.exists():
            try:
                with open(path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            data = json.loads(line)
                            event = AttackEvent(**data)
                            self.ground_truth.append(event)
                logger.info(f"Loaded {len(self.ground_truth)} ground truth events from {path}")
            except Exception as e:
                logger.error(f"Failed to load ground truth: {e}")
    
    def add_ground_truth(self, event: AttackEvent):
        """Add a ground truth attack event."""
        with self._lock:
            self.ground_truth.append(event)
            if self.config.log_detailed_events:
                self._write_ground_truth(event)
    
    def _write_ground_truth(self, event: AttackEvent):
        """Write ground truth event to file."""
        try:
            path = Path(self.config.ground_truth_file)
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, 'a') as f:
                f.write(json.dumps(event.to_dict()) + '\n')
        except Exception as e:
            logger.error(f"Failed to write ground truth: {e}")
    
    def add_alert(self, alert: Alert):
        """Add an alert and correlate with ground truth."""
        with self._lock:
            self.alerts.append(alert)
            
            # Correlate with ground truth
            correlation = self._correlate_alert(alert)
            self.correlations.append(correlation)
            
            # Update current window metrics
            self._update_metrics(correlation)
    
    def _correlate_alert(self, alert: Alert) -> CorrelationResult:
        """Correlate alert with ground truth events."""
        best_match = None
        best_score = 0
        best_reason = ""
        
        for event in self.ground_truth:
            # Time proximity (within 5 seconds)
            time_diff = abs(alert.timestamp - event.timestamp)
            if time_diff > 5.0:
                continue
            
            # IP/MAC matching
            score = 0
            reasons = []
            
            if alert.sender_ip == event.spoofed_ip:
                score += 3
                reasons.append("IP match")
            
            if alert.sender_mac == event.attacker_mac:
                score += 3
                reasons.append("Attacker MAC match")
            
            if alert.sender_mac == event.spoofed_mac:
                score += 2
                reasons.append("Spoofed MAC match")
            
            if alert.target_ip == event.target_ip:
                score += 1
                reasons.append("Target IP match")
            
            # Alert type relevance
            if alert.alert_type in (AlertType.GATEWAY_IMPERSONATION, AlertType.TWO_WAY_SPOOFING):
                if event.attack_type in ('gateway_impersonation', 'mitm_two_way'):
                    score += 2
                    reasons.append("Type match")
            
            if score > best_score:
                best_score = score
                best_match = event
                best_reason = "; ".join(reasons)
        
        is_tp = best_match is not None and best_score >= 3
        response_time = (alert.timestamp - best_match.timestamp) * 1000 if best_match else 0
        
        return CorrelationResult(
            alert=alert,
            matched_event=best_match,
            is_true_positive=is_tp,
            response_time_ms=response_time,
            match_reason=best_reason or "No matching ground truth event"
        )
    
    def _update_metrics(self, correlation: CorrelationResult):
        """Update current window metrics."""
        now = time.time()
        
        # Check if we need to start a new window
        if now >= self.current_metrics.window_end:
            self._finalize_window()
            self.current_window_start = now
            self.current_metrics = DetectionMetrics(
                window_start=self.current_window_start,
                window_end=now + self.config.metrics_window_seconds
            )
        
        # Update metrics
        if correlation.is_true_positive:
            self.current_metrics.true_positives += 1
            # Update average response time
            n = self.current_metrics.true_positives
            old_avg = self.current_metrics.avg_response_time_ms
            self.current_metrics.avg_response_time_ms = (
                (old_avg * (n - 1) + correlation.response_time_ms) / n
            )
        else:
            self.current_metrics.false_positives += 1
        
        self.current_metrics.total_alerts += 1
    
    def _finalize_window(self):
        """Finalize current window and compute derived metrics."""
        # Count ground truth events in this window
        window_attacks = sum(
            1 for e in self.ground_truth
            if self.current_metrics.window_start <= e.timestamp < self.current_metrics.window_end
        )
        self.current_metrics.total_attacks = window_attacks
        
        # False negatives = attacks not detected
        detected_attacks = set()
        for corr in self.correlations:
            if corr.is_true_positive and corr.matched_event:
                detected_attacks.add(corr.matched_event.event_id)
        
        window_attack_ids = {
            e.event_id for e in self.ground_truth
            if self.current_metrics.window_start <= e.timestamp < self.current_metrics.window_end
        }
        
        self.current_metrics.false_negatives = len(window_attack_ids - detected_attacks)
        
        # True negatives = non-attack periods correctly not alerted
        # Approximation: total possible alerts - actual alerts - false negatives
        # This is a simplification; in practice TN is hard to define for streaming
        self.current_metrics.true_negatives = max(0, 100 - self.current_metrics.total_alerts)  # Placeholder
        
        self.metrics_history.append(self.current_metrics)
        
        # Keep only recent history
        if len(self.metrics_history) > 100:
            self.metrics_history = self.metrics_history[-100:]
        
        logger.info(f"Window metrics: {self.current_metrics.to_dict()}")
    
    def get_current_metrics(self) -> DetectionMetrics:
        """Get current window metrics (including partial window)."""
        with self._lock:
            # Return a copy with current time as window_end
            metrics = DetectionMetrics(
                window_start=self.current_metrics.window_start,
                window_end=time.time(),
                true_positives=self.current_metrics.true_positives,
                false_positives=self.current_metrics.false_positives,
                true_negatives=self.current_metrics.true_negatives,
                false_negatives=self.current_metrics.false_negatives,
                total_attacks=self.current_metrics.total_attacks,
                total_alerts=self.current_metrics.total_alerts,
                avg_response_time_ms=self.current_metrics.avg_response_time_ms
            )
            return metrics
    
    def get_overall_metrics(self) -> DetectionMetrics:
        """Get aggregated metrics across all windows."""
        with self._lock:
            if not self.metrics_history and self.current_metrics.total_alerts == 0:
                return DetectionMetrics(window_start=0, window_end=time.time())
            
            # Aggregate all windows
            total = DetectionMetrics(window_start=0, window_end=time.time())
            for m in self.metrics_history:
                total.true_positives += m.true_positives
                total.false_positives += m.false_positives
                total.true_negatives += m.true_negatives
                total.false_negatives += m.false_negatives
                total.total_attacks += m.total_attacks
                total.total_alerts += m.total_alerts
            
            # Add current partial window
            total.true_positives += self.current_metrics.true_positives
            total.false_positives += self.current_metrics.false_positives
            total.true_negatives += self.current_metrics.true_negatives
            total.false_negatives += self.current_metrics.false_negatives
            total.total_attacks += self.current_metrics.total_attacks
            total.total_alerts += self.current_metrics.total_alerts
            
            # Weighted average response time
            tp_total = total.true_positives
            if tp_total > 0:
                weighted_sum = sum(m.avg_response_time_ms * m.true_positives for m in self.metrics_history)
                weighted_sum += self.current_metrics.avg_response_time_ms * self.current_metrics.true_positives
                total.avg_response_time_ms = weighted_sum / tp_total
            
            return total
    
    def get_correlation_details(self) -> List[dict]:
        """Get detailed correlation results for analysis."""
        with self._lock:
            return [
                {
                    'alert_id': c.alert.alert_id,
                    'alert_type': c.alert.alert_type.value,
                    'alert_severity': c.alert.severity.value,
                    'alert_time': c.alert.timestamp,
                    'matched_event_id': c.matched_event.event_id if c.matched_event else None,
                    'matched_attack_type': c.matched_event.attack_type if c.matched_event else None,
                    'is_true_positive': c.is_true_positive,
                    'response_time_ms': c.response_time_ms,
                    'match_reason': c.match_reason
                }
                for c in self.correlations
            ]
    
    def export_results(self, path: Optional[str] = None) -> dict:
        """Export evaluation results to file."""
        path = path or self.config.results_file
        
        results = {
            'timestamp': time.time(),
            'overall_metrics': self.get_overall_metrics().to_dict(),
            'current_window_metrics': self.get_current_metrics().to_dict(),
            'window_history': [m.to_dict() for m in self.metrics_history],
            'correlation_details': self.get_correlation_details(),
            'ground_truth_count': len(self.ground_truth),
            'total_alerts': len(self.alerts)
        }
        
        try:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            with open(path, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            logger.info(f"Evaluation results exported to {path}")
        except Exception as e:
            logger.error(f"Failed to export results: {e}")
        
        return results
    
    def print_summary(self):
        """Print evaluation summary to console."""
        metrics = self.get_overall_metrics()
        print("\n" + "="*60)
        print("EVALUATION SUMMARY")
        print("="*60)
        print(f"Total Attacks (Ground Truth): {metrics.total_attacks}")
        print(f"Total Alerts Generated:       {metrics.total_alerts}")
        print(f"True Positives:               {metrics.true_positives}")
        print(f"False Positives:              {metrics.false_positives}")
        print(f"False Negatives:              {metrics.false_negatives}")
        print(f"True Negatives:               {metrics.true_negatives}")
        print("-"*60)
        print(f"Accuracy:          {metrics.accuracy:.2%}")
        print(f"Precision:         {metrics.precision:.2%}")
        print(f"Recall:            {metrics.recall:.2%}")
        print(f"F1 Score:          {metrics.f1_score:.2%}")
        print(f"False Positive Rate: {metrics.false_positive_rate:.2%}")
        print(f"False Negative Rate: {metrics.false_negative_rate:.2%}")
        print(f"Avg Response Time: {metrics.avg_response_time_ms:.1f} ms")
        print("="*60)
        
        # Per-alert-type breakdown
        print("\nAlert Type Breakdown:")
        type_counts = defaultdict(int)
        for c in self.correlations:
            type_counts[c.alert.alert_type.value] += 1
        for atype, count in sorted(type_counts.items()):
            tp = sum(1 for c in self.correlations 
                    if c.alert.alert_type.value == atype and c.is_true_positive)
            print(f"  {atype}: {count} alerts ({tp} TP)")
    
    def reset(self):
        """Reset evaluation state."""
        with self._lock:
            self.ground_truth.clear()
            self.alerts.clear()
            self.correlations.clear()
            self.metrics_history.clear()
            self.current_window_start = time.time()
            self.current_metrics = DetectionMetrics(
                window_start=self.current_window_start,
                window_end=self.current_window_start + self.config.metrics_window_seconds
            )
        logger.info("Evaluation engine reset")


def create_evaluation_engine(config: Optional[EvaluationConfig] = None) -> EvaluationEngine:
    """Factory function to create evaluation engine."""
    return EvaluationEngine(config)