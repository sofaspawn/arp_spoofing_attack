# ARP Spoofing Detection System

A comprehensive, educational implementation of real-time ARP spoofing detection and mitigation for local area networks. Based on the BCSE308L Computer Networks project report.

## 🎯 Features

- **Multi-Rule Detection Engine**: 7 detection rules (mapping change, duplicate mapping, reply rate, gratuitous ARP, MAC spoofing, gateway impersonation, two-way spoofing)
- **Attack Generation**: Scapy-based ARP spoofing (one-way, MITM two-way, reply flood, gratuitous flood)
- **Automated Mitigation**: Corrective ARP announcements + host firewall blocking (iptables/nftables)
- **Evaluation Framework**: Ground truth correlation, accuracy/precision/recall/F1, response time measurement
- **Web Dashboard**: Real-time visualization (bindings, alerts, stats, timeline charts)
- **Network Topology**: Packet Tracer compatible topology generator
- **Safety First**: Dry-run mode by default, no packets transmitted without explicit consent

## 📦 Installation

```bash
cd arp_spoofing
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## 🚀 Quick Start

```bash
# Run offline simulation with dashboard
PYTHONPATH=src python -m arpwatch simulate --scenario mixed --dashboard

# Open http://localhost:8080 in browser
```

## 📖 Commands

| Command | Description |
|---------|-------------|
| `simulate` | Offline simulation with test scenarios |
| `live` | Live packet capture (requires root/Scapy) |
| `attack` | Generate attack traffic for testing |
| `evaluate` | Run evaluation on recorded data |
| `dashboard` | Start web dashboard only |
| `topology` | Generate network topology diagrams |

### Simulation Scenarios
- `benign` - Normal ARP traffic
- `gateway_impersonation` - Attacker impersonates gateway
- `mitm_two_way` - Full MITM (victim + gateway poisoned)
- `reply_flood` - High ARP reply rate
- `gratuitous_flood` - Excessive gratuitous ARPs
- `mac_spoofing` - One MAC claiming multiple IPs
- `mixed` - Combination of benign and attacks

## 🏗️ Architecture

```
src/arpwatch/
├── attack/          # Attack packet generation
├── detection/       # Packet capture + detection engine
├── mitigation/      # Corrective ARP + firewall
├── evaluation/      # Metrics + ground truth correlation
├── visualization/   # Web dashboard
├── topology/        # Network topology builder
├── models.py        # Shared data models
├── config.py        # Configuration management
└── __main__.py      # CLI entry point
```

## 🧪 Testing

```bash
# Run all tests
PYTHONPATH=src python -m pytest tests/ -v

# Run specific test module
PYTHONPATH=src python -m pytest tests/test_detection.py -v
```

## 📊 Demo

See [DEMO.md](DEMO.md) for complete professor demo guide with exact commands and talking points.

## ⚠️ Safety & Ethics

- **Default dry-run mode**: No packets transmitted, no firewall changes
- **Explicit enable required**: Must call `.enable()` on attack/mitigation engines
- **Interface restriction**: Requires explicit interface configuration for live mode
- **Rate limiting**: Built-in packet rate limits
- **Educational use only**: Test only on networks you own or have explicit authorization

## 📄 License

Educational project for BCSE308L Computer Networks course.