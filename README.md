# ARP Spoofing Detection Lab

A reproducible educational prototype based on the BCSE308L project report. Its presentation workflow runs locally using an in-memory labeled ARP trace; it demonstrates the flow from normal mapping learning through suspicious claims, detection, dry-run response, and evaluation, then exposes the run in a browser dashboard.

## Fast presentation

Install Python 3.10+, then from the project root:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
PYTHONPATH=src python -m arpwatch demo --hold
```

Open `http://127.0.0.1:8080`. Press Ctrl-C in the terminal to stop. Detailed, beginner-friendly speaking notes and troubleshooting are in [`demo.md`](demo.md).

## Commands

```sh
PYTHONPATH=src python -m arpwatch topology --output packet_tracer
PYTHONPATH=src python -m arpwatch demo --hold --port 8081 --output logs/presentation.json
PYTHONPATH=src python -m unittest discover -s tests -v
```

On Windows PowerShell first run `$env:PYTHONPATH = "src"` in that terminal, then invoke `python -m arpwatch ...`.

## Architecture

- `src/arpwatch/detection/engine.py`: in-memory IP-to-MAC table and mapping-change, gateway impersonation, reply-rate, gratuitous ARP, and MAC/IP anomaly rules.
- `src/arpwatch/__main__.py`: deterministic event timeline, command-line orchestration, dashboard updates, and results output.
- `src/arpwatch/evaluation/engine.py`: alert-to-labeled-event matching and honest metric reporting.
- `src/arpwatch/mitigation/engine.py`: mitigation action proposals; the demo runs it in dry-run mode.
- `src/arpwatch/visualization/dashboard.py`: localhost-only status/dashboard endpoints.
- `src/arpwatch/detection/capture.py`: optional Scapy passive capture building block; it is not used by the offline demo command.
- `src/arpwatch/topology/builder.py`: topology documentation exported as JSON, Mermaid, and text. JSON is not a Cisco Packet Tracer `.pkt` file.
- `configs/default.yaml`: demo/system thresholds.

## Safety and scientific limits

The built-in demo never injects packets, modifies another host's ARP cache, or changes firewall state. Dry-run mitigation only records proposed action. Do not enable experimental packet injection or firewall changes on a shared network. Optional live passive capture requires Scapy, privileges, explicit authorization, and suitable visibility (often a switch mirror port).

The demonstration uses a small synthetic trace and is not evidence of production detection accuracy. Precision/recall and latency are computed from labeled events. The tool does not invent true-negative counts: defensible accuracy and false-positive rates require a defined labeled set of benign and attack decision windows and repeated trials.
