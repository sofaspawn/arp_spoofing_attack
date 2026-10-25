# ARP Spoofing Detection Lab — Professor Demo

This is the presentation runbook. It is written for someone new to ARP and uses **one command** to run the complete reproducible lab. The built-in presentation is an offline replay: it generates realistic, labeled ARP event data in memory, feeds it through the same detection engine used by the optional passive capture component, performs dry-run mitigation, updates a browser dashboard, and exports evaluation results. It does **not** send packets or change firewall settings.

> **Important accuracy note:** Do not describe the offline replay as a live network attack. Say “controlled offline replay” unless you have separately arranged an authorized, isolated network and intentionally configured live capture. Do not promise accuracy/FPR values: metrics are computed from labeled events, and accuracy/FPR require a denominator of benign decision windows. This demo intentionally reports those as not estimated rather than inventing them.

## What the project demonstrates

- **Topology:** gateway, switch, victim, second host, attacker-role node, and monitoring node.
- **Baseline learning:** normal host and gateway IP-to-MAC observations are seen before the injected anomaly events.
- **Attack-like events:** gateway impersonation and a two-sided poisoning indicator, plus ARP reply burst and gratuitous ARP burst.
- **Detection:** mapping changes, gateway impersonation, reply-rate threshold, and gratuitous ARP rate threshold.
- **Response:** human-readable alert and corrective-ARP action in **dry-run** mode.
- **Evaluation:** labeled attack events, matched alerts, missed events, precision/recall, false-negative rate, and response latency; JSON report saved to disk.
- **Dashboard:** live replay activity, learned IP/MAC bindings, alerts, attack labels, component statistics, and mitigation action log.

## ARP in plain language

- An IP address identifies a host at the network layer. A MAC address identifies its network interface on the local Ethernet/Wi-Fi segment.
- Before a local device can send an Ethernet frame to an IP address, it uses ARP to ask, “Who has this IP? Tell me your MAC.”
- Classic ARP does not authenticate the answer. A forged reply can claim “the gateway IP belongs to my MAC,” which can redirect local traffic.
- A **baseline** is the monitor's record of the expected IP-to-MAC association. A later unexpected MAC for the same IP is suspicious.
- A **gateway** is the router a host uses to reach other networks. A **victim** is a host whose ARP cache may be misled.
- **Two-way poisoning** means forged claims are aimed at both sides of a conversation. It is a condition associated with a man-in-the-middle (MITM) attempt; the offline demo does not intercept or relay traffic.

## Before presentation (one-time setup)

Open a terminal in the repository folder (the folder containing `ARP_Spoofing_Detection_Report.pdf`). Check Python:

```sh
python3 --version
```

Python 3.10 or later is recommended. Create the environment and install the listed dependencies:

```sh
python3 -m venv .venv
```

Linux/macOS:

```sh
. .venv/bin/activate
python -m pip install -r requirements.txt
```

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Dependencies install once. The demo needs no root/admin privileges, Scapy, Packet Tracer, or network access after dependencies are installed. Scapy is only needed for optional passive live capture; the full professor presentation does not need it.

## Presentation: exact steps (about 5–8 minutes)

### Step 1 — Show the topology (about 30 seconds)

Run:

```sh
PYTHONPATH=src python -m arpwatch topology --output packet_tracer
```

On Windows PowerShell, set the import path for that command as:

```powershell
$env:PYTHONPATH = "src"
python -m arpwatch topology --output packet_tracer
```

The command prints a text topology and writes files under `packet_tracer/`. Open `packet_tracer/topology.mmd` in a Mermaid-capable Markdown preview if you want a visual diagram. The generated JSON documents the topology; it is **not** a Cisco `.pkt` file and is not imported directly into Packet Tracer.

**Say:**
- “This is the small LAN from our report: a gateway/router and several end devices share one switch.”
- “The monitor needs visibility of the relevant ARP frames. In a real switched LAN, a monitor may need a mirror/SPAN port; this replay removes that visibility dependency for a reliable classroom demonstration.”
- “The attacker is a modeled role in this offline experiment, not a machine attacking the classroom network.”

### Step 2 — Start the complete lab (one command)

Linux/macOS:

```sh
PYTHONPATH=src python -m arpwatch demo --hold
```

Windows PowerShell (set `PYTHONPATH` once in that terminal):

```powershell
$env:PYTHONPATH = "src"
python -m arpwatch demo --hold
```

Keep this terminal open. The program prints each simulated ARP frame, alert messages, dry-run mitigation messages, and a final metrics summary. It also writes `logs/demo_results.json`. The event replay lasts about seven seconds; after it finishes, the dashboard remains running until you press **Ctrl+C** in that terminal.

If port 8080 is occupied, start with `--port 8081` and open `http://127.0.0.1:8081`.

### Step 3 — Open the dashboard while replay is running

As soon as the terminal prints the dashboard URL, open this in a browser:

```text
http://127.0.0.1:8080
```

The browser refreshes its data periodically. The replay has a short normal-traffic lead-in before suspicious events; the printed terminal event stream and final summary remain available even if you open the page late. The API data is also available at `http://127.0.0.1:8080/api/data`.

**Point to these dashboard areas:**
- **IP-MAC Bindings:** normal learned associations, including gateway `192.168.1.1` with `02:00:00:00:00:01` before spoofed claims arrive.
- **Recent Alerts:** severity, rule name, claimed IP/MAC, and explanation.
- **Detection Statistics:** processed frames, alerts, and learned bindings.
- **Attack Events:** labeled simulated events (ground truth).
- **Mitigation Actions:** corrective response proposals explicitly marked DRY-RUN.
- **Capture statistics:** in this run it identifies the source as offline replay, not a physical interface.

**Say:**
- “The first frames establish the legitimate mapping. The attacker-role MAC is `02:00:00:00:00:99`; it is a locally administered example address in the replay.”
- “When that MAC claims the known gateway IP, the mapping-change and gateway-impersonation checks alert.”
- “Later, the replay tests a claim for the victim IP as well, demonstrating the two-sided MITM indicator.”
- “The reply burst and gratuitous ARP burst exercise independent rate rules. A rate alert is an anomaly signal, not proof of malicious intent.”
- “The response panel records a corrective ARP action as a dry-run proposal. No frame is transmitted and no firewall is changed.”

### Step 4 — Explain results and show the report

When the replay ends, read the **FINAL RESULTS** block in the original terminal. Then open `logs/demo_results.json` in an editor, or use:

```sh
python -m json.tool logs/demo_results.json
```

The report contains labeled ground truth, alerts, correlation results, and calculated metrics. Explain the terms:

- **TP (true positive):** an alert matched a labeled attack event.
- **FP (false positive):** an alert did not match a labeled attack event.
- **FN (false negative):** a labeled event had no matching alert.
- **Precision:** TP divided by all alerts, TP + FP.
- **Recall:** TP divided by all labeled attacks, TP + FN.
- **False-negative rate:** FN divided by TP + FN.
- **Response time:** alert timestamp minus labeled event timestamp, in milliseconds.

**Say:** “These are results for this particular deterministic trace, not a claim of general real-world accuracy. A defensible false-positive rate and accuracy need explicitly labeled benign decision windows and multiple representative trials. The report's proposed metrics are part of our evaluation plan; we avoid fabricating a true-negative count from an arbitrary constant.”

### Step 5 — Close cleanly

Press **Ctrl+C** in the demo terminal. This stops the dashboard. The JSON report remains in `logs/demo_results.json`.

## Optional: repeat a clean run / change dashboard port

The demo resets detector state every time it starts. Run again with:

```sh
PYTHONPATH=src python -m arpwatch demo --hold --port 8081 --output logs/professor_run.json
```

Use `http://127.0.0.1:8081`, and the new results are saved to `logs/professor_run.json`.

## Optional: automated test

From the repository root, after activating the environment:

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
```

Windows PowerShell:

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
```

## Questions the professor may ask

**Does this perform a real attack?**  
“No. The main presentation is a controlled offline replay. The packet model and detector are exercised end-to-end without sending network traffic. This avoids affecting other users and makes the results repeatable.”

**Can it monitor real ARP traffic?**  
“There is an optional Scapy passive capture component in `detection/capture.py`. It requires Scapy, capture permissions, an explicitly selected interface, and network placement with visibility. A switched-port monitor may not receive other hosts' unicast traffic unless the switch is configured to mirror it.”

**Does it automatically fix the network?**  
“The mitigation module records proposed corrective actions in dry-run mode. Live corrective ARP and firewall operations are intentionally not part of the classroom run; enabling them on a shared network could disrupt connectivity.”

**What does ARP spoofing enable?**  
“Poisoned ARP caches can redirect traffic and may enable a man-in-the-middle or denial-of-service condition. This lab detects mapping anomalies; it does not decrypt traffic or demonstrate credential theft.”

**What are the limitations?**  
“ARP is unauthenticated; first-seen baseline poisoning, legitimate host changes, threshold tuning, and incomplete visibility can affect detection. Our synthetic replay validates detector behavior, not deployment performance on a production LAN.”

## If something goes wrong

- **`ModuleNotFoundError: arpwatch`:** confirm current directory is the project root and use the `PYTHONPATH=src` prefix (PowerShell uses `$env:PYTHONPATH = "src"`).
- **`No module named yaml`:** activate `.venv` and run `python -m pip install -r requirements.txt`.
- **Address/port already in use:** use `--port 8081` and open that port's localhost URL.
- **Browser opens but seems empty:** watch the demo terminal for the final results; ensure the run has completed and refresh `/` or `/api/data`.
- **Need to rerun:** Ctrl+C, then run the demo command again. Each process starts a clean in-memory detector.

## Alignment with the report

This demo directly reflects the report's gateway + switch + end-host topology, forged-claim attack scenarios, passive mapping-change/rate detection, alerting, mitigation concept, and labeled evaluation. Cisco Packet Tracer is a separate topology-design aid; the generated JSON is documentation and the replay is the dependable executable experiment. Live traffic, accuracy claims across many trials, and deployment-grade mitigation remain follow-up experimental work—not claims made by this classroom demo.
