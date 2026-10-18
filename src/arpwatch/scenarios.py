"""Deterministic, offline attack/benign traces; never transmits packets."""
from .core import ArpEvent

def scenario(name: str):
    base = [ArpEvent(1, "reply", "192.168.1.1", "02:00:00:00:00:01", "192.168.1.10")]
    if name == "benign":
        return base + [ArpEvent(5, "reply", "192.168.1.1", "02:00:00:00:00:01", "192.168.1.10"),
                       ArpEvent(8, "request", "192.168.1.10", "02:00:00:00:00:10", "192.168.1.1")], {"spoofed": 0}
    if name == "gateway-impersonation":
        return base + [ArpEvent(2, "reply", "192.168.1.1", "02:00:00:00:00:99", "192.168.1.10")], {"spoofed": 1}
    if name == "two-way":
        return base + [ArpEvent(2, "reply", "192.168.1.1", "02:00:00:00:00:99", "192.168.1.10"),
                       ArpEvent(2.2, "reply", "192.168.1.10", "02:00:00:00:00:99", "192.168.1.1")], {"spoofed": 2}
    if name == "reply-flood":
        return base + [ArpEvent(2 + i * .1, "reply", "192.168.1.1", "02:00:00:00:00:01", "192.168.1.10") for i in range(12)], {"spoofed": 0}
    raise ValueError(f"unknown scenario: {name}")

SCENARIOS = ("benign", "gateway-impersonation", "two-way", "reply-flood")
