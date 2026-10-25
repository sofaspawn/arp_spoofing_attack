#!/usr/bin/env python3
"""ARP Spoofing Detection System - Main CLI Entry Point.

This is the primary command-line interface for the ARP spoofing detection system.
It supports multiple modes of operation:
- live: Live packet capture and detection (requires root/Scapy)
- simulate: Offline simulation with predefined attack scenarios
- attack: Generate attack traffic for testing (dry-run by default)
- evaluate: Run evaluation on recorded data
- dashboard: Start web dashboard
- topology: Generate network topology diagrams
"""
from __future__ import annotations
import argparse
import sys
import os
import time
import json
import signal
import logging
from pathlib import Path
from typing import Optional, List

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from arpwatch.config import Config, get_config, set_config
from arpwatch.models import ArpPacket, ArpOperation
from arpwatch.attack.generator import AttackGenerator, AttackConfig, AttackMode, create_attack_scenario
from arpwatch.detection.engine import DetectionEngine
from arpwatch.detection.capture import PacketCapture, OfflinePacketSource, create_test_packets
from arpwatch.mitigation.engine import MitigationEngine
from arpwatch.evaluation.engine import EvaluationEngine
from arpwatch.visualization.dashboard import WebDashboard
from arpwatch.topology.builder import create_standard_topology, create_simple_topology

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ArpWatchApp:
    """Main application class coordinating all components."""
    
    def __init__(self, config: Config):
        self.config = config
        self.running = False
        
        # Components
        self.detection_engine: Optional[DetectionEngine] = None
        self.capture: Optional[PacketCapture] = None
        self.offline_source: Optional[OfflinePacketSource] = None
        self.attack_generator: Optional[AttackGenerator] = None
        self.mitigation_engine: Optional[MitigationEngine] = None
        self.evaluation_engine: Optional[EvaluationEngine] = None
        self.dashboard: Optional[WebDashboard] = None
        
        # Statistics
        self.start_time: Optional[float] = None
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        self.stop()
        sys.exit(0)
    
    def initialize_components(self, enable_mitigation: bool = False, 
                             enable_dashboard: bool = False,
                             enable_evaluation: bool = True):
        """Initialize all system components."""
        # Detection engine
        self.detection_engine = DetectionEngine(
            alert_callback=self._on_alert
        )
        
        # Evaluation engine
        if enable_evaluation and self.config.evaluation.enabled:
            self.evaluation_engine = EvaluationEngine()
        
        # Mitigation engine
        if enable_mitigation and self.config.mitigation.enabled:
            self.mitigation_engine = MitigationEngine(
                action_callback=self._on_mitigation_action
            )
            self.mitigation_engine.enable()
        
        # Dashboard
        if enable_dashboard and self.config.visualization.enabled:
            self.dashboard = WebDashboard()
            self.dashboard.start()
    
    def _on_alert(self, alert):
        """Handle alert from detection engine."""
        # Log to evaluation
        if self.evaluation_engine:
            self.evaluation_engine.add_alert(alert)
        
        # Trigger mitigation
        if self.mitigation_engine:
            self.mitigation_engine.process_alert(alert)
        
        # Update dashboard
        if self.dashboard:
            self.dashboard.add_alert(alert)
    
    def _on_mitigation_action(self, action):
        """Handle mitigation action."""
        if self.dashboard:
            self.dashboard.add_mitigation_action(action)
    
    def start_live_capture(self):
        """Start live packet capture and detection."""
        logger.info("Starting live capture mode...")
        
        self.capture = PacketCapture(
            interface=self.config.network.interface,
            packet_callback=self._on_packet_captured
        )
        
        if not self.capture.start():
            logger.error("Failed to start packet capture")
            return False
        
        self.running = True
        self.start_time = time.time()
        
        # Main processing loop
        try:
            while self.running:
                # Process queued packets
                packets = self.capture.process_queued_packets(max_packets=100)
                for pkt in packets:
                    self.detection_engine.process_packet(pkt)
                
                # Update dashboard stats
                if self.dashboard:
                    self.dashboard.update_detection_stats(self.detection_engine.get_stats())
                    self.dashboard.update_capture_stats(self.capture.get_stats())
                    if self.mitigation_engine:
                        self.dashboard.update_mitigation_stats(self.mitigation_engine.get_stats())
                
                time.sleep(0.1)
                
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()
        
        return True
    
    def _on_packet_captured(self, packet: ArpPacket):
        """Callback for captured packets (alternative to queue processing)."""
        # This is called from capture thread - use queue instead for thread safety
        pass
    
    def run_simulation(self, scenario: str = "mixed", 
                       replay_speed: float = 1.0,
                       enable_mitigation: bool = False,
                       enable_dashboard: bool = False) -> dict:
        """Run offline simulation with predefined scenario."""
        logger.info(f"Running simulation: {scenario} at {replay_speed}x speed")
        
        # Create test packets
        packets = create_test_packets(scenario)
        logger.info(f"Generated {len(packets)} test packets")
        
        # Initialize components
        self.initialize_components(
            enable_mitigation=enable_mitigation,
            enable_dashboard=enable_dashboard,
            enable_evaluation=True
        )
        
        # Create offline source
        self.offline_source = OfflinePacketSource(
            packets=packets,
            packet_callback=self._on_offline_packet,
            replay_speed=replay_speed
        )
        
        self.running = True
        self.start_time = time.time()
        
        # Start replay
        self.offline_source.start()
        
        # Wait for completion
        while self.running and self.offline_source._running:
            time.sleep(0.5)
            
            # Update dashboard
            if self.dashboard:
                self.dashboard.update_detection_stats(self.detection_engine.get_stats())
                if self.mitigation_engine:
                    self.dashboard.update_mitigation_stats(self.mitigation_engine.get_stats())
        
        # Final evaluation
        results = {}
        if self.evaluation_engine:
            self.evaluation_engine.print_summary()
            results = self.evaluation_engine.export_results()
        
        return results
    
    def _on_offline_packet(self, packet: ArpPacket):
        """Process packet from offline source."""
        alerts = self.detection_engine.process_packet(packet)
        
        # Record attack events as ground truth (for scenarios that have them)
        if hasattr(packet, '_attack_event') and packet._attack_event:
            if self.evaluation_engine:
                self.evaluation_engine.add_ground_truth(packet._attack_event)
    
    def run_attack_scenario(self, scenario_name: str, 
                           duration: Optional[float] = None,
                           interval: Optional[float] = None) -> dict:
        """Run an attack scenario (generates attack traffic)."""
        logger.info(f"Running attack scenario: {scenario_name}")
        
        # Create attack config
        attack_config = create_attack_scenario(scenario_name)
        if duration:
            attack_config.duration_seconds = duration
        if interval:
            attack_config.interval_seconds = interval
        
        # Create attack generator
        self.attack_generator = AttackGenerator(
            config=attack_config,
            safety_config=self.config.safety,
            packet_callback=self._on_attack_packet
        )
        
        # Enable and start
        self.attack_generator.enable()
        self.attack_generator.start()
        
        # Wait for completion
        try:
            while self.attack_generator._running:
                time.sleep(1.0)
                stats = self.attack_generator.get_stats()
                logger.info(f"Attack stats: {stats}")
        except KeyboardInterrupt:
            pass
        finally:
            self.attack_generator.disable()
        
        return self.attack_generator.get_stats()
    
    def _on_attack_packet(self, packet: ArpPacket):
        """Callback for attack packets (can feed into detection for testing)."""
        # In dry-run mode, we can also feed attack packets to detection for testing
        if self.config.safety.dry_run and self.detection_engine:
            self.detection_engine.process_packet(packet)
    
    def start_dashboard_only(self):
        """Start only the web dashboard."""
        logger.info("Starting dashboard only mode...")
        
        self.dashboard = WebDashboard()
        self.dashboard.start()
        
        logger.info(f"Dashboard running at http://localhost:{self.config.visualization.web_port}")
        logger.info("Press Ctrl+C to stop")
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            self.dashboard.stop()
    
    def generate_topology(self, output_dir: str = "packet_tracer", 
                         format: str = "both"):
        """Generate network topology files."""
        logger.info("Generating network topology...")
        
        os.makedirs(output_dir, exist_ok=True)
        
        # Standard topology
        builder = create_standard_topology()
        
        if format in ("json", "both"):
            builder.save_json(os.path.join(output_dir, "topology.json"))
        
        if format in ("mermaid", "both"):
            builder.save_mermaid(os.path.join(output_dir, "topology.mmd"))
        
        # Also save ASCII diagram
        with open(os.path.join(output_dir, "topology.txt"), 'w') as f:
            f.write(builder.generate_ascii_diagram())
        
        logger.info(f"Topology files saved to {output_dir}/")
        
        # Print ASCII diagram to console
        print(builder.generate_ascii_diagram())
    
    def stop(self):
        """Stop all components."""
        self.running = False
        
        if self.capture:
            self.capture.stop()
        if self.offline_source:
            self.offline_source.stop()
        if self.attack_generator:
            self.attack_generator.disable()
        if self.mitigation_engine:
            self.mitigation_engine.disable()
        if self.dashboard:
            self.dashboard.stop()
        
        logger.info("All components stopped")


def setup_logging(level: str = "INFO", json_format: bool = False, log_file: Optional[str] = None):
    """Configure application logging."""
    log_level = getattr(logging, level.upper(), logging.INFO)
    
    handlers = [logging.StreamHandler(sys.stdout)]
    
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_file))
    
    if json_format:
        formatter = logging.Formatter(
            '{"timestamp": "%(asctime)s", "level": "%(levelname)s", '
            '"logger": "%(name)s", "message": "%(message)s"}'
        )
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    for handler in handlers:
        handler.setFormatter(formatter)
    
    logging.basicConfig(level=log_level, handlers=handlers, force=True)


def main():
    parser = argparse.ArgumentParser(
        description="ARP Spoofing Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run live detection (requires root and Scapy)
  sudo python -m arpwatch live --interface eth0
  
  # Run offline simulation
  python -m arpwatch simulate --scenario gateway_impersonation
  
  # Run attack scenario (dry-run by default)
  python -m arpwatch attack --scenario mitm_two_way
  
  # Start web dashboard
  python -m arpwatch dashboard
  
  # Generate topology diagrams
  python -m arpwatch topology --output packet_tracer
        """
    )
    
    parser.add_argument('--config', '-c', help='Configuration file path')
    parser.add_argument('--log-level', default='INFO', 
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'])
    parser.add_argument('--log-file', help='Log file path')
    parser.add_argument('--json-logs', action='store_true', help='JSON format logs')
    parser.add_argument('--dry-run', action='store_true', help='Enable dry-run mode (no packet transmission)')
    parser.add_argument('--interface', '-i', help='Network interface for live capture')
    
    subparsers = parser.add_subparsers(dest='command', required=True, help='Command to run')
    
    # Live capture command
    live_parser = subparsers.add_parser('live', help='Live packet capture and detection')
    live_parser.add_argument('--interface', '-i', help='Network interface')
    live_parser.add_argument('--mitigation', action='store_true', help='Enable mitigation')
    live_parser.add_argument('--dashboard', action='store_true', help='Enable web dashboard')
    live_parser.add_argument('--no-eval', action='store_true', help='Disable evaluation')
    
    # Simulation command
    sim_parser = subparsers.add_parser('simulate', help='Offline simulation with test scenarios')
    sim_parser.add_argument('--scenario', '-s', default='mixed',
                           choices=['benign', 'gateway_impersonation', 'mitm_two_way', 
                                   'reply_flood', 'gratuitous_flood', 'mac_spoofing', 'mixed'],
                           help='Test scenario to run')
    sim_parser.add_argument('--speed', type=float, default=1.0, help='Replay speed multiplier')
    sim_parser.add_argument('--mitigation', action='store_true', help='Enable mitigation')
    sim_parser.add_argument('--dashboard', action='store_true', help='Enable web dashboard')
    sim_parser.add_argument('--output', '-o', help='Output results file')
    
    # Attack command
    attack_parser = subparsers.add_parser('attack', help='Generate attack traffic (for testing)')
    attack_parser.add_argument('--scenario', '-s', required=True,
                              choices=['gateway_impersonation', 'mitm_two_way', 
                                      'reply_flood', 'gratuitous_flood'],
                              help='Attack scenario')
    attack_parser.add_argument('--duration', '-d', type=float, help='Attack duration (seconds)')
    attack_parser.add_argument('--interval', type=float, help='Packet interval (seconds)')
    attack_parser.add_argument('--live', action='store_true', help='Actually transmit packets (requires root)')
    
    # Evaluation command
    eval_parser = subparsers.add_parser('evaluate', help='Run evaluation on recorded data')
    eval_parser.add_argument('--ground-truth', help='Ground truth file')
    eval_parser.add_argument('--alerts', help='Alerts file')
    eval_parser.add_argument('--output', '-o', help='Output results file')
    
    # Dashboard command
    dash_parser = subparsers.add_parser('dashboard', help='Start web dashboard')
    dash_parser.add_argument('--port', '-p', type=int, default=8080, help='Dashboard port')
    
    # Topology command
    topo_parser = subparsers.add_parser('topology', help='Generate network topology diagrams')
    topo_parser.add_argument('--output', '-o', default='packet_tracer', help='Output directory')
    topo_parser.add_argument('--format', '-f', choices=['json', 'mermaid', 'both'], default='both')
    topo_parser.add_argument('--simple', action='store_true', help='Generate simple topology')
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.log_level, args.json_logs, args.log_file)
    
    # Load configuration
    config = Config.load(args.config)
    
    # Apply CLI overrides
    if args.dry_run:
        config.safety.dry_run = True
    if args.interface:
        config.network.interface = args.interface
    if hasattr(args, 'port') and args.port:
        config.visualization.web_port = args.port
    
    set_config(config)
    
    # Print configuration summary
    logger.info(f"Configuration: interface={config.network.interface}, "
               f"dry_run={config.safety.dry_run}, "
               f"mitigation_enabled={config.mitigation.enabled}")
    
    # Create app
    app = ArpWatchApp(config)
    
    # Execute command
    try:
        if args.command == 'live':
            app.initialize_components(
                enable_mitigation=args.mitigation,
                enable_dashboard=args.dashboard,
                enable_evaluation=not args.no_eval
            )
            app.start_live_capture()
            
        elif args.command == 'simulate':
            results = app.run_simulation(
                scenario=args.scenario,
                replay_speed=args.speed,
                enable_mitigation=args.mitigation,
                enable_dashboard=args.dashboard
            )
            
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(results, f, indent=2, default=str)
                logger.info(f"Results saved to {args.output}")
            
        elif args.command == 'attack':
            # Override dry-run if --live specified
            if args.live:
                config.safety.dry_run = False
                set_config(config)
                logger.warning("LIVE MODE: Packets will be transmitted!")
            
            stats = app.run_attack_scenario(
                scenario_name=args.scenario,
                duration=args.duration,
                interval=args.interval
            )
            print(json.dumps(stats, indent=2))
            
        elif args.command == 'dashboard':
            app.start_dashboard_only()
            
        elif args.command == 'topology':
            if args.simple:
                builder = create_simple_topology()
            else:
                builder = create_standard_topology()
            
            os.makedirs(args.output, exist_ok=True)
            
            if args.format in ('json', 'both'):
                builder.save_json(os.path.join(args.output, "topology.json"))
            if args.format in ('mermaid', 'both'):
                builder.save_mermaid(os.path.join(args.output, "topology.mmd"))
            
            with open(os.path.join(args.output, "topology.txt"), 'w') as f:
                f.write(builder.generate_ascii_diagram())
            
            print(builder.generate_ascii_diagram())
            
    except Exception as e:
        logger.error(f"Command failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()