# Professor Demo: Real-Time ARP Spoofing Detection

## Safety and presentation goal
This demo shows detection logic using synthetic, deterministic ARP event traces. It does not perform an ARP-poisoning attack. Live mode is passive only. Do not run spoofing tools on a campus, public, or production network. For a live capture demonstration, obtain explicit authorization and use an isolated lab network.

## What to explain
ARP maps an IPv4 address to a link-layer MAC address on a local subnet. Basic ARP has no authentication, so a receiver can be misled by an unsolicited reply claiming a different sender MAC. Our monitor tracks observed sender IP-to-MAC bindings and raises alerts for mapping changes, rapid duplicate associations, and unusually frequent replies. The baseline is learned from the first packet, so trustworthy initialization remains an important limitation.

## Project layout
- `src/arpwatch/core.py`: detector and mapping state.
- `src/arpwatch/scenarios.py`: fixed benign/attack traces and ground truth.
- `src/arpwatch/__main__.py`: CLI, offline runner, optional passive Scapy capture.
- `tests/test_detector.py`: automated rule tests.
- `ARP_Spoofing_Detection_Report.pdf`: original project proposal.

## Exact demo steps
Run these from the repository root in a terminal. Use Python 3.10 or newer.

### 1. Prepare the environment

```sh
python3 --version
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

If network/package installation is unavailable, the offline simulator and tests use only the Python standard library; skip the `pip install` step. On Windows PowerShell activate with `.venv\Scripts\Activate.ps1`; replace `python3` with `py -3` if needed.

### 2. Show the normal baseline

```sh
PYTHONPATH=src python -m arpwatch simulate benign
```

Expected: JSON output with an empty `alerts` list and bindings for the gateway and host. Explain that repeated stable mappings are not treated as suspicious.

### 3. Show gateway impersonation

```sh
PYTHONPATH=src python -m arpwatch simulate gateway-impersonation
```

Expected: an alert with rule `duplicate_mapping`, describing `192.168.1.1` changing from `02:00:00:00:00:01` to `02:00:00:00:00:99`. The output also reports one injected spoofed event as the scenario's ground truth.

### 4. Show the two-way case

```sh
PYTHONPATH=src python -m arpwatch simulate two-way
```

Expected: alerts for the forged gateway mapping and forged victim mapping. Describe this as the conceptual condition an attacker would seek for a man-in-the-middle position; this demo generates no network packets and intercepts no traffic.

### 5. Show the abnormal reply-rate rule

```sh
PYTHONPATH=src python -m arpwatch simulate reply-flood
```

Expected: one or more `reply_rate` alerts once the per-IP reply count exceeds the configured threshold (8) in the 10-second window. This trace is benign-labeled to make the false-positive tradeoff visible: high reply frequency alone is not proof of an attack.

### 6. Run the tests

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
```

Expected: four tests pass. Point out coverage for stable mappings, rapid conflicting mappings, reply-rate threshold, and attack scenario alerts.

### 7. Optional live passive capture (only in an authorized isolated lab)

Have an explicitly authorized test LAN with a monitoring interface that can observe ARP broadcasts; a switched network port generally cannot see all other hosts' unicast traffic. Scapy must be installed. Start:

```sh
PYTHONPATH=src sudo -E .venv/bin/python -m arpwatch live
```

The process prints a startup message and JSON alert lines; press Ctrl-C to stop. The tool only listens. It neither poisons caches nor automatically corrects ARP or blocks a MAC. If capture permission or interface setup is a problem, use the offline demos above; no live network is needed to present the project.

## Evaluation discussion
The built-in traces provide known ground truth and reproducible demonstrations, not statistically meaningful benchmark results. For an evaluation extension, repeat labeled benign and spoofing-like traces, count alerts against labeled events, and report TP/FP/TN/FN; derive accuracy `(TP+TN)/(TP+FP+TN+FN)`, false-positive rate `FP/(FP+TN)`, false-negative rate `FN/(FN+TP)`, and alert response delay from event to alert. The current offline traces have timestamps but are illustrative, and the current CLI does not claim a validated real-world accuracy percentage. In a real experiment, independently verify observed packets with Wireshark and record capture conditions.

## Topology to draw in Packet Tracer / slides
Draw a router (`192.168.1.1`) connected to a LAN switch; connect a legitimate host (`192.168.1.10`), another host, an attacker-role host (`192.168.1.99`), and a monitoring node to the same LAN. Explain that the monitor must receive relevant ARP frames (for example, by being on the same segment or using a properly configured mirror port). The offline simulator models the detector inputs rather than requiring Packet Tracer packet integration.

## Closing and candid limitations
The prototype demonstrates a real-time detection approach and repeatable tests, but does not implement packet injection, automatic mitigation, persistent baselines, or real-world benchmark collection. First-seen poisoning, legitimate MAC changes, and limited switched-network visibility are significant limitations. Automated corrective ARP and firewall blocking are intentionally not included because they can disrupt networks and require platform-specific authorization and recovery procedures.
