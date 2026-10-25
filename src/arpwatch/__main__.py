"""Presentation-friendly ARP lab. All built-in scenarios are offline and safe."""
import argparse, json, logging, os, sys, time, threading
from pathlib import Path
from arpwatch.config import Config, set_config, DetectionConfig, MitigationConfig, SafetyConfig, VisualizationConfig
from arpwatch.models import ArpPacket, ArpOperation, AttackEvent
from arpwatch.detection.engine import DetectionEngine
from arpwatch.evaluation.engine import EvaluationEngine
from arpwatch.mitigation.engine import MitigationEngine
from arpwatch.visualization.dashboard import WebDashboard
from arpwatch.topology.builder import create_standard_topology

MAC={'gw':'02:00:00:00:00:01','victim':'02:00:00:00:00:10','host':'02:00:00:00:00:20','attacker':'02:00:00:00:00:99'}
GW='192.168.1.1'; V='192.168.1.10'; H='192.168.1.20'; A='192.168.1.99'

def build_trace():
    """Return a timed, labeled sequence. No sockets, Scapy sends, or real network traffic."""
    now=time.time(); trace=[]; labels=[]
    def put(offset, op, ip, mac, tip, tmac, kind='benign', gratuitous=False):
        p=ArpPacket(now+offset, op, ip, mac, tip, tmac, gratuitous)
        trace.append((offset,p,kind))
    # Warm-up / baseline: resolve normal hosts and gateway.
    put(0,ArpOperation.REQUEST,V,MAC['victim'],GW,'00:00:00:00:00:00')
    put(.2,ArpOperation.REPLY,GW,MAC['gw'],V,MAC['victim'])
    put(.5,ArpOperation.REPLY,H,MAC['host'],V,MAC['victim'])
    put(.8,ArpOperation.REPLY,GW,MAC['gw'],H,MAC['host'])
    put(1.3,ArpOperation.REQUEST,A,MAC['attacker'],GW,'00:00:00:00:00:00')
    # Victim remains healthy during baseline; then gateway poisoning.
    put(2.0,ArpOperation.REPLY,GW,MAC['attacker'],V,MAC['victim'],'gateway_impersonation')
    put(2.4,ArpOperation.REPLY,GW,MAC['attacker'],H,MAC['host'],'gateway_impersonation')
    # Two-way MITM poison: attacker claims victim IP back to gateway.
    put(3.0,ArpOperation.REPLY,V,MAC['attacker'],GW,MAC['gw'],'two_way_spoofing')
    # Reply burst; rate rule intentionally produces a warning.
    for n in range(10): put(4+n*.12,ArpOperation.REPLY,GW,MAC['gw'],V,MAC['victim'],'reply_burst')
    # Repeated gratuitous announcement test.
    for n in range(4): put(6+n*.15,ArpOperation.REPLY,GW,MAC['attacker'],GW,MAC['attacker'],'gratuitous_flood',True)
    return sorted(trace,key=lambda row:row[0])

def run_demo(args):
    cfg=Config.load(args.config)
    cfg.network.gateway_ip=GW; cfg.network.gateway_mac=MAC['gw']
    cfg.safety.dry_run=True
    cfg.mitigation.enabled=True
    set_config(cfg)
    Path('logs').mkdir(exist_ok=True)
    alerts=[]; eval_engine=EvaluationEngine()
    dash=WebDashboard(VisualizationConfig(web_port=args.port))
    mit=MitigationEngine(MitigationConfig(enabled=True,corrective_arp_enabled=True,
                            corrective_arp_count=1,corrective_arp_interval=0), SafetyConfig(dry_run=True))
    def on_alert(alert):
        alerts.append(alert); eval_engine.add_alert(alert); dash.add_alert(alert)
        print(f"ALERT [{alert.severity.value.upper()}] {alert.alert_type.value}: {alert.message}",flush=True)
        for action in mit.process_alert(alert):
            dash.add_mitigation_action(action)
            print(f"MITIGATION [DRY RUN] {action.details}",flush=True)
    mit.enable()  # Explicitly enable only in dry-run; no host/network changes are possible.
    detector=DetectionEngine(alert_callback=on_alert)
    trace=build_trace()
    for i,(offset,p,kind) in enumerate(trace):
        if kind in ('gateway_impersonation','two_way_spoofing'):
            ev=AttackEvent(f'E{i:02d}', p.timestamp, kind, MAC['attacker'],p.target_ip,p.sender_ip,p.sender_mac,
                           f"Simulated {kind.replace('_',' ')} event")
            eval_engine.add_ground_truth(ev); dash.add_attack_event(ev)
    dash.start()
    print(f"\nDashboard: http://127.0.0.1:{args.port}",flush=True)
    print("OFFLINE LAB: all ARP frames are simulated; no packets are sent and firewall is untouched.\n",flush=True)
    start=time.monotonic()
    try:
        for offset,p,kind in trace:
            delay=offset-(time.monotonic()-start)
            if delay>0: time.sleep(delay)
            print(f"FRAME {p.operation.name:7s} {p.sender_ip:15s} is-at {p.sender_mac} -> {p.target_ip} [{kind}]",flush=True)
            detector.process_packet(p)
            dash.update_bindings(detector.get_all_bindings())
            dash.update_detection_stats(detector.get_stats())
            dash.update_capture_stats({'running':True,'interface':'offline replay','packets_captured':detector.stats['packets_processed'],
                                       'packets_processed':detector.stats['packets_processed'],'packets_dropped':0,'errors':0,
                                       'packets_per_second':0})
            dash.update_mitigation_stats(mit.get_stats())
    except KeyboardInterrupt: pass
    finally:
        m=eval_engine.get_overall_metrics()
        result=eval_engine.export_results(args.output)
        dash.update_detection_stats(detector.get_stats())
        dash.update_mitigation_stats(mit.get_stats())
        print("\nFINAL RESULTS (labeled attack events only)")
        print(json.dumps(m,indent=2))
        print(f"Full event report: {args.output}")
        print("Dashboard remains available; press Ctrl-C to stop.")
        if args.hold:
            try:
                while True:
                    dash.update_bindings(detector.get_all_bindings())
                    time.sleep(1)
            except KeyboardInterrupt: pass
        dash.stop()

def main():
    parser=argparse.ArgumentParser(description='ARP spoofing defensive lab (safe offline replay)')
    sub=parser.add_subparsers(dest='command',required=True)
    demo=sub.add_parser('demo',help='run complete offline lab with dashboard, detections, mitigation dry-run, and evaluation')
    demo.add_argument('--port',type=int,default=8080)
    demo.add_argument('--output',default='logs/demo_results.json')
    demo.add_argument('--config',default='configs/default.yaml')
    demo.add_argument('--hold',action='store_true',help='keep dashboard open after replay; Ctrl-C exits')
    topo=sub.add_parser('topology',help='export the lab topology as documentation JSON and Mermaid')
    topo.add_argument('--output',default='packet_tracer')
    args=parser.parse_args()
    if args.command=='demo': run_demo(args)
    elif args.command=='topology':
        b=create_standard_topology(); os.makedirs(args.output,exist_ok=True)
        b.save_json(os.path.join(args.output,'topology.json')); b.save_mermaid(os.path.join(args.output,'topology.mmd'))
        print(b.generate_ascii_diagram())

if __name__=='__main__': main()
