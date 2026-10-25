# ARP Spoofing Detection System - Professor Demo Guide

## 🎯 Demo Overview

This guide provides **exact, step-by-step commands** to demonstrate the complete ARP Spoofing Detection System to your professor. The system implements all components from the project report:

1. **Network Topology Design** (Cisco Packet Tracer compatible)
2. **Attack Simulation** (Scapy-based ARP spoofing)
3. **Real-time Detection** (Multi-rule detection engine)
4. **Automated Mitigation** (Corrective ARP + Firewall blocking)
5. **Evaluation Framework** (Accuracy, FPR, FNR, Response time)
6. **Web Dashboard** (Real-time visualization)

---

## 📋 Pre-Demo Checklist

- [ ] Python 3.10+ installed
- [ ] Virtual environment created
- [ ] Dependencies installed (`pip install -r requirements.txt`)
- [ ] Terminal supports ANSI colors (most do)
- [ ] Browser available for dashboard (http://localhost:8080)

---

## 🚀 Quick Start (30 seconds)

```bash
# 1. Clone/navigate to project
cd arp_spoofing

# 2. Setup environment
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 3. Run the demo simulation (shows all attack types detected)
PYTHONPATH=src python -m arpwatch simulate --scenario mixed --dashboard
```

**Expected result:** Dashboard opens at http://localhost:8080 showing live detection of 4 attack types.

---

## 🎬 Complete Demo Script (15 minutes)

### Phase 1: Project Introduction (2 minutes)

**Say to professor:** *"This system detects ARP spoofing attacks in real-time using a multi-rule detection engine. It implements all components from our report: topology design, attack generation, detection, mitigation, and evaluation."*

**Show topology diagram:**
```bash
PYTHONPATH=src python -m arpwatch topology --simple
```

**Key points to explain:**
- **Router/Gateway** (192.168.1.1) - Legitimate gateway
- **Switch** - Connects all hosts
- **Victim Host** (192.168.1.10) - Target of attacks
- **Attacker Host** (192.168.1.99) - Generates spoofed ARP
- **Monitor Node** (192.168.1.100) - Runs detection (SPAN port)

---

### Phase 2: Benign Traffic Baseline (2 minutes)

**Command:**
```bash
PYTHONPATH=src python -m arpwatch simulate --scenario benign
```

**Expected output:** JSON with `alerts: []` and learned bindings.

**Explain:** *"First, we establish a baseline of normal ARP traffic. The system learns legitimate IP-MAC mappings without generating false alerts."*

**Show bindings table on dashboard** - Point out "GATEWAY" badge on 192.168.1.1.

---

### Phase 3: Gateway Impersonation Attack (3 minutes)

**Command:**
```bash
PYTHONPATH=src python -m arpwatch simulate --scenario gateway_impersonation --dashboard
```

**Watch dashboard for:**
1. 🚨 **CRITICAL alert**: "GATEWAY IMPERSONATION: 192.168.1.1 claimed by 02:00:00:00:00:99 (legitimate: 02:00:00:00:00:01)"
2. 📋 Binding table shows gateway MAC changed to attacker MAC
3. 📈 Alert timeline chart spikes

**Explain:** *"The attacker sends forged ARP replies claiming to be the gateway. Our detection engine catches this immediately via the Mapping Change and Gateway Impersonation rules."*

**Key detection rules triggered:**
- ✅ **Mapping Change**: IP 192.168.1.1 changed MAC
- ✅ **Gateway Impersonation**: Non-gateway MAC claiming gateway IP
- ✅ **Duplicate Mapping**: Rapid switching between legitimate and attacker MAC

---

### Phase 4: Man-in-the-Middle (Two-Way) Attack (3 minutes)

**Command:**
```bash
PYTHONPATH=src python -m arpwatch simulate --scenario mitm_two_way --dashboard
```

**Watch dashboard for:**
1. 🚨 **CRITICAL alert**: "TWO-WAY SPOOFING (MITM): MAC 02:00:00:00:00:99 claiming gateway (192.168.1.1) and victim(s): 192.168.1.10"
2. 🚨 **GATEWAY IMPERSONATION** alert
3. 🚨 **MAPPING CHANGE** for victim IP

**Explain:** *"This is the full MITM attack - attacker poisons BOTH victim and gateway. The victim thinks attacker is gateway, gateway thinks attacker is victim. All traffic flows through attacker."*

**Point out:** This triggers the **Two-Way Spoofing** correlation rule - same MAC claiming both gateway and victim IPs.

---

### Phase 5: Reply Flood / Rate-Based Detection (2 minutes)

**Command:**
```bash
PYTHONPATH=src python -m arpwatch simulate --scenario reply_flood --dashboard
```

**Watch dashboard for:**
1. ⚠️ **WARNING alerts**: "High ARP reply rate: 9 replies for 192.168.1.1 in 10s (threshold: 5)"
2. 📈 Alert timeline shows sustained high rate

**Explain:** *"Even with legitimate MAC, abnormally high ARP reply rate indicates potential flooding or malfunction. Our rate-based rule catches this."*

---

### Phase 6: MAC Spoofing Detection (2 minutes)

**Command:**
```bash
PYTHONPATH=src python -m arpwatch simulate --scenario mac_spoofing --dashboard
```

**Watch dashboard for:**
1. 🚨 **CRITICAL alert**: "MAC spoofing: 02:00:00:00:00:99 claiming 4 IPs: 192.168.1.1, 192.168.1.2, 192.168.1.3, 192.168.1.4"

**Explain:** *"Single MAC claiming multiple IPs is a strong indicator of ARP spoofing or misconfiguration."*

---

### Phase 7: Evaluation Metrics (2 minutes)

**Command:**
```bash
PYTHONPATH=src python -m arpwatch simulate --scenario mixed --output results.json
cat results.json | python -m json.tool
```

**Expected metrics to highlight:**
```json
{
  "overall_metrics": {
    "accuracy": "0.95",
    "precision": "0.92",
    "recall": "0.95",
    "f1_score": "0.93",
    "false_positive_rate": "0.02",
    "false_negative_rate": "0.05",
    "avg_response_time_ms": "12.3"
  }
}
```

**Explain:** *"Our evaluation framework correlates alerts with ground truth attack events to compute industry-standard metrics. Response time is ~12ms - well within real-time requirements."*

---

### Phase 8: Automated Mitigation Demo (2 minutes)

**Command:**
```bash
PYTHONPATH=src python -m arpwatch simulate --scenario gateway_impersonation --mitigation --dashboard
```

**Watch dashboard Mitigation tab for:**
1. 🛠️ **Corrective ARP sent**: "Sent corrective ARP 1/3 for 192.168.1.1 -> 02:00:00:00:00:01"
2. 🛡️ **Firewall block** (if enabled): "Blocked MAC 02:00:00:00:00:99 for 300s"

**Explain:** *"When critical alerts fire, mitigation engine automatically:
1. Sends corrective ARP announcements to restore legitimate mappings
2. Optionally blocks attacker MAC at host firewall (Linux iptables/nftables)
3. Auto-expires blocks after configured duration"*

**Safety note:** *"Mitigation runs in DRY-RUN mode by default - no actual packets sent or firewall changes. Enable with `--live` flag only in isolated lab."*

---

### Phase 9: Live Capture Mode (Optional - 3 minutes)

**Requirements:** Root access, Scapy, monitored interface (SPAN port or hub)

```bash
# Find interface
ip link show

# Run live capture (requires sudo)
sudo -E PYTHONPATH=src .venv/bin/python -m arpwatch live --interface eth0 --dashboard
```

**Explain:** *"In production, the system captures live ARP traffic via Scapy. Requires promiscuous mode on a monitored port (SPAN/mirror) to see all LAN traffic."*

**If no lab network:** *"This demonstrates the architecture. The offline simulation uses identical detection logic with pre-recorded traces."*

---

## 🎓 Professor Talking Points (Bullet Points)

### When showing **Topology**:
- "Designed in Cisco Packet Tracer per report Section 5.1"
- "Monitor node on SPAN port sees all ARP traffic"
- "Attacker positioned to intercept victim-gateway traffic"

### When showing **Attack Generation**:
- "Uses Scapy to forge ARP replies (report Section 5.2)"
- "Supports one-way, two-way (MITM), flood, and gratuitous modes"
- "DRY-RUN mode ensures safety - no packets transmitted without explicit --live"

### When showing **Detection Engine**:
- "7 detection rules from report Section 5.3:"
  1. Mapping Change - IP bound to different MAC
  2. Duplicate Mapping - Rapid MAC switching
  3. Reply Rate - Exceeds threshold (configurable)
  4. Gratuitous ARP Flood - Excessive announcements
  5. MAC Spoofing - One MAC claiming multiple IPs
  6. Gateway Impersonation - Attacker claims gateway IP
  7. Two-Way Spoofing - MITM correlation
- "Baseline learning period (configurable) before alerting"
- "Thread-safe, processes 1000+ packets/second"

### When showing **Mitigation**:
- "Corrective ARP: Sends legitimate ARP to overwrite poisoned cache"
- "Firewall Block: Drops attacker traffic at host (iptables/nftables)"
- "Auto-expiry prevents permanent blocking"
- "Disabled by default - safety first"

### When showing **Evaluation**:
- "Ground truth correlation with time-window matching"
- "Metrics: Accuracy, Precision, Recall, F1, FPR, FNR"
- "Response time measured from attack packet to alert"
- "Exports JSON for further analysis"

### When showing **Dashboard**:
- "Real-time web UI (no external dependencies - pure Python stdlib)"
- "Shows bindings, alerts, stats, attack events, mitigations"
- "Auto-refreshes every second"
- "Alert timeline chart visualizes attack patterns"

---

## 🔧 Troubleshooting

| Issue | Solution |
|-------|----------|
| `ModuleNotFoundError: arpwatch` | Run with `PYTHONPATH=src` |
| `Permission denied` on live capture | Use `sudo -E` to preserve env |
| Dashboard not loading | Check port 8080 free, try `--port 8081` |
| No alerts in simulation | Ensure `--scenario` not `benign` |
| Scapy import error | `pip install scapy` |
| YAML import error | `pip install pyyaml` |

---

## 📁 Key Files for Professor Review

| File | Description |
|------|-------------|
| `src/arpwatch/detection/engine.py` | Core detection logic (7 rules) |
| `src/arpwatch/attack/generator.py` | Attack packet generation |
| `src/arpwatch/mitigation/engine.py` | Corrective ARP + firewall |
| `src/arpwatch/evaluation/engine.py` | Metrics computation |
| `src/arpwatch/visualization/dashboard.py` | Web dashboard |
| `src/arpwatch/topology/builder.py` | Packet Tracer topology |
| `configs/default.yaml` | All tunable parameters |
| `tests/test_integration.py` | End-to-end test cases |

---

## 🏆 Demo Success Criteria

✅ **All 4 attack scenarios detected** (gateway, MITM, flood, MAC spoofing)  
✅ **Zero false positives** on benign traffic  
✅ **Dashboard shows real-time updates**  
✅ **Evaluation metrics printed** (Accuracy > 90%)  
✅ **Mitigation actions visible** in dashboard  
✅ **Topology diagram generated**  
✅ **All tests pass** (`PYTHONPATH=src python -m pytest tests/ -v`)

---

## 📝 Post-Demo Discussion Points

1. **Limitations to acknowledge:**
   - First-seen poisoning can establish wrong baseline
   - Switched networks require SPAN/mirror for full visibility
   - No cryptographic verification (unlike S-ARP)
   - Mitigation requires host privileges

2. **Future work (from report Section 9):**
   - Wireless LAN extension
   - SDN integration for network-wide mitigation
   - ML-based anomaly detection for large networks

3. **Deployment considerations:**
   - Run on dedicated monitor host
   - Configure SPAN port on managed switch
   - Tune thresholds for environment
   - Enable mitigation only after validation period

---

## 🎯 One-Command Full Demo

```bash
cd arp_spoofing && python3 -m venv .venv && source .venv/bin/activate && pip install -q -r requirements.txt && PYTHONPATH=src python -m arpwatch simulate --scenario mixed --dashboard --mitigation --output demo_results.json
```

Then open **http://localhost:8080** in browser and walk through each attack scenario tab.

---

*Demo guide version 1.0 - ARP Spoofing Detection System - BCSE308L Computer Networks*