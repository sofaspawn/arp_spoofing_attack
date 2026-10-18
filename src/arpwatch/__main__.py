import argparse
import json
import sys
from .core import ArpDetector, ArpEvent
from .scenarios import SCENARIOS, scenario

def run_trace(name, detector):
    events, truth = scenario(name)
    alerts = []
    for event in events:
        alerts.extend(detector.process(event))
    return alerts, truth, events

def main():
    parser = argparse.ArgumentParser(description="Safe ARP monitoring and offline evaluation")
    sub = parser.add_subparsers(dest="command", required=True)
    sim = sub.add_parser("simulate", help="run a deterministic offline scenario")
    sim.add_argument("scenario", choices=SCENARIOS, nargs="?", default="gateway-impersonation")
    sim.add_argument("--rate-limit", type=int, default=8)
    sub.add_parser("live", help="passively capture ARP packets (requires Scapy and capture privileges)")
    args = parser.parse_args()
    detector = ArpDetector(rate_limit=getattr(args, "rate_limit", 8))
    if args.command == "simulate":
        alerts, truth, _ = run_trace(args.scenario, detector)
        print(json.dumps({"scenario": args.scenario, "alerts": [a.__dict__ for a in alerts],
                          "bindings": detector.snapshot(), "ground_truth_spoofed_events": truth["spoofed"]}, indent=2))
        return
    try:
        from scapy.all import ARP, sniff
    except ImportError:
        parser.error("live capture requires Scapy: install with `python -m pip install -r requirements.txt`")
    print("Passive ARP capture active. Ctrl-C to stop. No packets are injected or blocked.", file=sys.stderr)
    def observe(packet):
        if ARP not in packet:
            return
        layer = packet[ARP]
        op = "request" if int(layer.op) == 1 else "reply"
        event = ArpEvent(packet.time, op, layer.psrc, layer.hwsrc, layer.pdst, layer.hwdst)
        for alert in detector.process(event):
            print(json.dumps(alert.__dict__), flush=True)
    sniff(filter="arp", prn=observe, store=False)

if __name__ == "__main__":
    main()
