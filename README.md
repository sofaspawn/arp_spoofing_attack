# Real-Time ARP Spoofing Detection

A Python educational prototype based on the project report. It provides rule-based ARP monitoring, deterministic offline attack traces, and optional passive live capture. **It does not transmit forged packets, modify ARP caches, or change firewall rules.** Use only on networks you own or are authorized to monitor.

## Requirements
- Python 3.10+
- Optional live capture: Scapy and OS capture privileges (`python -m pip install -r requirements.txt`).

## Run
From the project root:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
PYTHONPATH=src python -m arpwatch simulate gateway-impersonation
PYTHONPATH=src python -m arpwatch simulate two-way
PYTHONPATH=src python -m arpwatch simulate benign
PYTHONPATH=src python -m arpwatch simulate reply-flood
PYTHONPATH=src python -m unittest discover -s tests -v
```

Live passive monitoring (requires Scapy and typically administrator/root capture permissions):

```sh
PYTHONPATH=src sudo -E .venv/bin/python -m arpwatch live
```
Stop with Ctrl-C. It prints newline-delimited JSON alerts and never injects traffic. Use a monitored interface/SPAN-capable lab or a virtual network that actually exposes the traffic; ordinary switched ports may not see unicast traffic between other hosts.

## Detection model and limitations
The first observed sender IP/MAC pair seeds the in-memory baseline. A different MAC is flagged as a mapping change; changes inside the duplicate window (30 seconds) are classified as duplicate mappings. More than 8 ARP replies per sender IP in 10 seconds triggers the rate rule. Thresholds can be adjusted in code; `simulate` accepts `--rate-limit`. Events expose timestamp, claimed sender and target addresses. This is a small host-based heuristic, not cryptographic verification: first-seen poisoning can seed a bad baseline, legitimate failover/DHCP changes can alert, and passive visibility depends on network placement. Bindings are not persisted.

## Architecture
`src/arpwatch/core.py` contains stateful detection; `scenarios.py` provides reproducible offline ground-truth traces; `__main__.py` is the CLI and Scapy passive-capture adapter. `tests/` checks core rules. See `DEMO.md` for the complete presentation sequence and topology.
