# ARP Spoofing Detection Lab — Demo Runbook

This is the complete presentation runbook. One command runs the lab. The built-in demo is an **offline replay**: it generates realistic, labeled ARP events in memory, feeds them through the detection engine, performs dry-run mitigation, updates a browser dashboard, and exports evaluation results. **No packets are transmitted and no firewall changes are made.**

> **Accuracy note:** Do not claim live-capture precision/recall. Metrics are computed from the labeled replay trace. Accuracy and FPR require a denominator of labeled benign windows, which the replay intentionally omits rather than fabricates.

---

## What the project demonstrates

| Feature | Details |
|---|---|
| **Network topology** | Gateway, switch, victim, second host, attacker node, monitor node |
| **Baseline learning** | Normal IP→MAC associations observed before anomalies are injected |
| **Attack scenarios** | Gateway impersonation, two-way MITM poisoning, reply burst, gratuitous ARP flood |
| **Detection signals** | Mapping change, gateway impersonation, two-way MITM signature, reply rate, gratuitous rate, header consistency |
| **Mitigation (dry-run)** | Corrective ARP proposals and firewall-block logs — no real actions taken |
| **Evaluation** | Labeled events, matched alerts, precision / recall / F1, response latency |
| **Dashboard** | Real-time UI — 8 pages covering overview, alerts, bindings, topology, packet feed, attacks, mitigation, and evaluation metrics |

---

## What's new in this version

### New detection signals

| Signal | Description |
|---|---|
| **MITM two-way signature** | Fires when one MAC simultaneously holds both the gateway IP and at least one victim IP — the strongest available MITM indicator |
| **Header consistency check** | Counts frames where the ARP sender hardware address is a broadcast or all-zero address — a low-level spoofing hint |
| **Deduplicated MITM alerts** | The same MITM event is not fired twice within a single packet's processing cycle |

### New dashboard pages (all visible in the left sidebar)

| Page | What you'll see |
|---|---|
| **Overview** | Summary tiles (packets, alerts, bindings, attacks, mitigations, MITM sigs), alert timeline chart, recent alerts, engine stats |
| **Alerts** | Full scrollable alert log with severity, type badge, message, sender IP/MAC, and previous MAC |
| **Bindings** | IP→MAC table with role badges (Gateway / Static / Learned), timestamps, and seen count |
| **Topology** | Live SVG node graph — gateway at top, hosts in a semicircle, attacker nodes shown in red with dashed edges |
| **Packet Feed** | Scrollable live feed of the last 30 ARP frames with timestamp, operation (REQUEST/REPLY), IPs, and MACs |
| **Attack Events** | Ground-truth labeled events from the replay trace |
| **Mitigation** | Engine status panel + action log (all marked DRY-RUN) |
| **Evaluation** | Precision / Recall / F1 bars, confusion matrix tiles, per-type alert breakdown |

---

## Before presentation — one-time setup

```sh
python3 --version    # 3.10+ recommended
python3 -m venv .venv
```

Linux / macOS:
```sh
. .venv/bin/activate
python -m pip install -r requirements.txt
```

Windows PowerShell:
```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

---

## Presentation steps (~5–8 minutes)

### Step 1 — Show the topology (~30 seconds)

```sh
PYTHONPATH=src python -m arpwatch topology --output packet_tracer
```

Windows PowerShell:
```powershell
$env:PYTHONPATH = "src"
python -m arpwatch topology --output packet_tracer
```

This prints an ASCII diagram and writes `packet_tracer/topology.json` and `packet_tracer/topology.mmd`. Open the `.mmd` file in any Mermaid-capable Markdown previewer for a visual graph.

**Say:** *"This is the small LAN from our report: a gateway, a switch, two hosts, and an attacker-role node. The monitor is offline; it replays frames it would have seen through a mirror/SPAN port."*

---

### Step 2 — Start the complete lab (one command)

Linux / macOS:
```sh
PYTHONPATH=src python -m arpwatch demo --hold
```

Windows PowerShell:
```powershell
$env:PYTHONPATH = "src"
python -m arpwatch demo --hold
```

The terminal prints each simulated ARP frame in real time, followed by any alert and dry-run mitigation message. The replay takes ~8 seconds. With `--hold`, the dashboard stays live until **Ctrl+C**.

Optional flags:
| Flag | Effect |
|---|---|
| `--port 8081` | Use a different port if 8080 is occupied |
| `--output logs/my_run.json` | Save evaluation results to a custom path |

---

### Step 3 — Open the dashboard while replay is running

Open in your browser immediately after the URL appears in the terminal:

```
http://127.0.0.1:8080
```

The page auto-refreshes every second. You do not need to reload it.

#### Dashboard walkthrough

**Overview page** (default landing page)
- Six summary tiles at the top — watch "Alerts" and "MITM Sigs" increment in real time.
- **Alert Timeline chart** — each spike corresponds to a burst of attacks (impersonation, reply flood, gratuitous flood).
- **Detection Engine** stat grid — note "MITM signatures" and "Header anomalies" alongside the classic counters.

**Alerts page** (click "Alerts" in the left sidebar)
- Every generated alert is shown with a severity badge (`CRITICAL` / `WARNING`), alert type badge (e.g. `gateway impersonation`), the sender IP/MAC, and previous MAC when available.
- Look for `two_way_spoofing` alerts — those are new. They fire when the attacker MAC (`02:00:00:00:00:99`) simultaneously holds the gateway IP (`192.168.1.1`) and a victim IP.

**Bindings page**
- Shows the live ARP table with role badges. The gateway row should carry a **Gateway** teal badge.
- After the attack, the gateway entry's MAC will have flipped to `02:00:00:00:00:99`.

**Topology page**
- The gateway node appears at the top center (blue circle).
- After the attack begins, the attacker node turns **red** and its connecting edge becomes a dashed red line — a visual MITM indicator.

**Packet Feed page**
- Scrollable chronological feed of the last 30 ARP frames.
- REQUEST packets are highlighted in blue; REPLY packets in green.
- Gratuitous ARPs are labelled `[GRAT]`.

**Attack Events page**
- Lists the three labeled ground-truth events from the replay trace:
  - `gateway_impersonation` × 2 (attacker → victim, attacker → host)
  - `two_way_spoofing` × 1

**Mitigation page**
- Engine status grid: confirms "Dry-run: yes" and "Enabled: yes".
- Action log: all corrective-ARP proposals and (if triggered) firewall-block proposals, each labeled **DRY-RUN**.

**Evaluation page**
- Precision / Recall / F1 progress bars with color coding (green > 60 %, yellow > 30 %, red below).
- Confusion matrix tiles: TP, FP, FN, TN.
- Alert type breakdown sorted by frequency.

**Say:** *"The MITM signature is the most valuable new signal — one MAC claiming both the gateway IP and a victim IP is the exact two-way poisoning pattern described in our report."*

---

### Step 4 — Read the terminal summary and report

When the replay ends, the terminal prints:

```
FINAL RESULTS (labeled attack events only)
{
  "attacks": 3,
  "alerts": N,
  "tp": ...,
  "fp": ...,
  ...
}
Full event report: logs/demo_results.json
Dashboard remains available; press Ctrl-C to stop.
```

Inspect the JSON report:

```sh
python -m json.tool logs/demo_results.json
```

Explain the terms:
| Term | Meaning |
|---|---|
| **TP** | Alert matched a labeled attack event |
| **FP** | Alert did not match any labeled attack event |
| **FN** | Labeled attack event had no matching alert |
| **Precision** | TP / (TP + FP) |
| **Recall** | TP / (TP + FN) |
| **Response time** | Alert timestamp − event timestamp, in milliseconds |

**Say:** *"These numbers are for this deterministic replay only. Real-world precision and recall depend on network diversity, threshold tuning, and representative benign traffic."*

---

### Step 5 — Close cleanly

Press **Ctrl+C** in the demo terminal. The dashboard stops. `logs/demo_results.json` is preserved.

---

## Repeat a clean run / alternate port

```sh
PYTHONPATH=src python -m arpwatch demo --hold --port 8081 --output logs/run2.json
```

Open `http://127.0.0.1:8081`. Each run resets detector state completely.

---

## Automated tests

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
```

---

## Answers to expected questions

**Does this perform a real attack?**
"No. The presentation is a controlled offline replay. No packets leave the machine. The attacker-role MAC is a locally administered example address (`02:00:00:00:00:99`) that only exists inside the detector's in-memory model."

**What is the two-way MITM signature?**
"When one MAC address holds both the gateway IP and at least one other host's IP simultaneously, it is the fingerprint of a man-in-the-middle setup. An attacker must poison in both directions to intercept bidirectional traffic. That is exactly what our new `two_way_spoofing` signal detects."

**Can it detect attacks on a live network?**
"The optional passive capture component (`detection/capture.py`) uses Scapy for live ARP sniffing. It requires root/admin, Scapy installed, an explicitly named interface, and a switch mirror/SPAN port for full visibility. That path is not part of this classroom run."

**Does it actually block the attacker?**
"The mitigation engine records corrective ARP proposals and firewall-block proposals. In dry-run mode nothing is transmitted or changed. Enabling live mitigation on a shared network can disrupt connectivity and is intentionally disabled for this demo."

**What are the limitations?**
"ARP has no authentication. A detector that has not yet seen the legitimate mapping can be fooled by an attacker who sends a forged reply first. Rate and threshold tuning is environment-specific. This lab validates the detection logic on a known trace; it does not claim deployment-grade performance."

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `ModuleNotFoundError: arpwatch` | Confirm CWD is the project root and prefix the command with `PYTHONPATH=src` |
| `No module named yaml` | Activate `.venv` and run `python -m pip install -r requirements.txt` |
| Port already in use | Add `--port 8081` and open `http://127.0.0.1:8081` |
| Browser empty after load | Wait 2 seconds and refresh. Check that the terminal still shows the demo running. |
| Dashboard shows 0 MITM sigs | Replay has not yet reached the attack phase. Wait for `gateway_impersonation` frames in the terminal. |

---

## Alignment with the report

This demo directly implements the topology, attack scenarios, detection rules, dry-run mitigation, and evaluation methodology from the project report. The new MITM two-way signature and header consistency check are the detector improvements described in the "future work" and "detection hardening" sections of the report.
