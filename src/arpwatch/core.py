"""Rule-based ARP mapping monitor. Uses only the Python standard library."""
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Optional

@dataclass
class ArpEvent:
    timestamp: float
    operation: str
    sender_ip: str
    sender_mac: str
    target_ip: str = ""
    target_mac: str = ""

@dataclass
class Alert:
    timestamp: str
    rule: str
    sender_ip: str
    sender_mac: str
    previous_mac: Optional[str]
    target_ip: str
    message: str

@dataclass
class Binding:
    mac: str
    first_seen: float
    last_seen: float

class ArpDetector:
    def __init__(self, rate_limit: int = 8, rate_window: float = 10.0, duplicate_window: float = 30.0):
        if rate_limit < 1 or rate_window <= 0 or duplicate_window <= 0:
            raise ValueError("thresholds must be positive")
        self.rate_limit, self.rate_window, self.duplicate_window = rate_limit, rate_window, duplicate_window
        self.bindings: dict[str, Binding] = {}
        self.history: dict[str, deque] = defaultdict(deque)

    def process(self, event: ArpEvent) -> list[Alert]:
        ip, mac, ts = event.sender_ip, event.sender_mac.lower(), event.timestamp
        if not ip or not mac or ip == "0.0.0.0":
            return []
        alerts = []
        old = self.bindings.get(ip)
        if old and old.mac != mac:
            duplicate = ts - old.last_seen <= self.duplicate_window
            rule = "duplicate_mapping" if duplicate else "mapping_change"
            alerts.append(Alert(self._time(ts), rule, ip, mac, old.mac, event.target_ip,
                                f"{ip} changed from {old.mac} to {mac}"))
        window = self.history[ip]
        while window and ts - window[0] > self.rate_window:
            window.popleft()
        window.append(ts)
        if event.operation.lower() in ("reply", "2") and len(window) > self.rate_limit:
            alerts.append(Alert(self._time(ts), "reply_rate", ip, mac, old.mac if old else None,
                                event.target_ip, f"{len(window)} ARP replies for {ip} within {self.rate_window:g}s"))
        if old is None:
            self.bindings[ip] = Binding(mac, ts, ts)
        else:
            old.mac, old.last_seen = mac, ts
        return alerts

    @staticmethod
    def _time(ts: float) -> str:
        return datetime.fromtimestamp(ts, timezone.utc).isoformat()

    def snapshot(self):
        return {ip: asdict(binding) for ip, binding in sorted(self.bindings.items())}
