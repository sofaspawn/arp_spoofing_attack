"""Network Topology Builder - Creates Packet Tracer topology files and network diagrams."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Dict, Optional
import json
import logging

logger = logging.getLogger(__name__)


@dataclass
class NetworkNode:
    """Represents a network node in the topology."""
    name: str
    node_type: str  # 'router', 'switch', 'host', 'attacker', 'monitor'
    ip: str = ""
    mac: str = ""
    interfaces: List[Dict] = field(default_factory=list)
    x: float = 0
    y: float = 0


@dataclass
class NetworkLink:
    """Represents a link between two nodes."""
    source: str
    target: str
    source_interface: str = ""
    target_interface: str = ""
    link_type: str = "ethernet"


class TopologyBuilder:
    """Builds network topologies for Cisco Packet Tracer and documentation."""
    
    def __init__(self):
        self.nodes: List[NetworkNode] = []
        self.links: List[NetworkLink] = []
        self._node_counter = 0
    
    def add_router(self, name: str, ip: str, mac: str, x: float = 0, y: float = 0) -> NetworkNode:
        """Add a router (gateway) to the topology."""
        node = NetworkNode(
            name=name,
            node_type='router',
            ip=ip,
            mac=mac,
            x=x, y=y,
            interfaces=[
                {'name': 'GigabitEthernet0/0', 'ip': ip, 'mac': mac, 'connected_to': ''}
            ]
        )
        self.nodes.append(node)
        return node
    
    def add_switch(self, name: str, x: float = 0, y: float = 0, ports: int = 24) -> NetworkNode:
        """Add a switch to the topology."""
        interfaces = []
        for i in range(ports):
            interfaces.append({
                'name': f'FastEthernet0/{i+1}',
                'connected_to': ''
            })
        
        node = NetworkNode(
            name=name,
            node_type='switch',
            x=x, y=y,
            interfaces=interfaces
        )
        self.nodes.append(node)
        return node
    
    def add_host(self, name: str, ip: str, mac: str, gateway: str,
                 x: float = 0, y: float = 0, node_type: str = 'host') -> NetworkNode:
        """Add a host (PC, attacker, monitor) to the topology."""
        node = NetworkNode(
            name=name,
            node_type=node_type,
            ip=ip,
            mac=mac,
            x=x, y=y,
            interfaces=[
                {'name': 'FastEthernet0', 'ip': ip, 'mac': mac, 'gateway': gateway, 'connected_to': ''}
            ]
        )
        self.nodes.append(node)
        return node
    
    def connect(self, source_name: str, target_name: str, 
                source_interface: str = "", target_interface: str = "") -> NetworkLink:
        """Connect two nodes."""
        link = NetworkLink(
            source=source_name,
            target=target_name,
            source_interface=source_interface,
            target_interface=target_interface
        )
        self.links.append(link)
        
        # Update interface connections
        source_node = next((n for n in self.nodes if n.name == source_name), None)
        target_node = next((n for n in self.nodes if n.name == target_name), None)
        
        if source_node:
            for iface in source_node.interfaces:
                if iface['name'] == source_interface or (not source_interface and not iface.get('connected_to')):
                    iface['connected_to'] = target_name
                    break
        
        if target_node:
            for iface in target_node.interfaces:
                if iface['name'] == target_interface or (not target_interface and not iface.get('connected_to')):
                    iface['connected_to'] = source_name
                    break
        
        return link
    
    def generate_packet_tracer_json(self) -> Dict:
        """Generate a JSON representation compatible with Packet Tracer import."""
        # This is a simplified representation - actual .pkt files are binary
        # But we can generate a JSON that documents the topology
        return {
            'version': '1.0',
            'name': 'ARP Spoofing Detection Lab',
            'description': 'Topology for ARP Spoofing Detection demonstration',
            'nodes': [
                {
                    'name': n.name,
                    'type': n.node_type,
                    'ip': n.ip,
                    'mac': n.mac,
                    'position': {'x': n.x, 'y': n.y},
                    'interfaces': n.interfaces
                }
                for n in self.nodes
            ],
            'links': [
                {
                    'source': l.source,
                    'target': l.target,
                    'source_interface': l.source_interface,
                    'target_interface': l.target_interface
                }
                for l in self.links
            ]
        }
    
    def generate_mermaid_diagram(self) -> str:
        """Generate Mermaid diagram for documentation."""
        lines = [
            "graph LR",
            "    subgraph LAN[\"Local Area Network\"]",
            "        direction LR"
        ]
        
        # Add nodes
        for node in self.nodes:
            shape = {
                'router': '((Router))',
                'switch': '[(Switch)]',
                'host': '[Host]',
                'attacker': '[Attacker]',
                'monitor': '[Monitor]'
            }.get(node.node_type, '[Node]')
            
            label = f"{node.name}\\n{node.ip}\\n{node.mac}"
            lines.append(f"        {node.name}{shape}")
        
        lines.append("    end")
        lines.append("")
        
        # Add connections
        for link in self.links:
            lines.append(f"    {link.source} --- {link.target}")
        
        # Add styling
        lines.extend([
            "",
            "    classDef router fill:#1f77b4,color:#fff;",
            "    classDef switch fill:#ff7f0e,color:#fff;",
            "    classDef host fill:#2ca02c,color:#fff;",
            "    classDef attacker fill:#d62728,color:#fff;",
            "    classDef monitor fill:#9467bd,color:#fff;"
        ])
        
        for node in self.nodes:
            lines.append(f"    class {node.name} {node.node_type};")
        
        return "\\n".join(lines)
    
    def generate_ascii_diagram(self) -> str:
        """Generate ASCII topology diagram."""
        # Simple fixed layout for the standard topology
        return """
    ARP Spoofing Detection Lab Topology
    ====================================
    
    [Router/Gateway]                    [Monitor Node]
    192.168.1.1                          192.168.1.100
    02:00:00:00:00:01                    02:00:00:00:00:64
         |                                     |
         |                                     |
         +------------+        +---------------+
                      |        |
                  [Switch - 24 Port]
                      |        |
         +------------+        +---------------+
         |                                     |
    [Victim Host]                         [Attacker Host]
    192.168.1.10                          192.168.1.99
    02:00:00:00:00:10                     02:00:00:00:00:99
    
    Connections:
    - All nodes connected to Switch via Ethernet
    - Monitor port configured for SPAN/mirror (receives all traffic)
    - Attacker positioned to perform ARP spoofing
    - Victim is target of spoofing attacks
    """
    
    def save_json(self, path: str):
        """Save topology as JSON."""
        data = self.generate_packet_tracer_json()
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
        logger.info(f"Topology saved to {path}")
    
    def save_mermaid(self, path: str):
        """Save topology as Mermaid diagram."""
        diagram = self.generate_mermaid_diagram()
        with open(path, 'w') as f:
            f.write(diagram)
        logger.info(f"Mermaid diagram saved to {path}")


def create_standard_topology() -> TopologyBuilder:
    """Create the standard lab topology from the report."""
    builder = TopologyBuilder()
    
    # Router/Gateway
    router = builder.add_router(
        name="Gateway",
        ip="192.168.1.1",
        mac="02:00:00:00:00:01",
        x=100, y=100
    )
    
    # Switch
    switch = builder.add_switch(
        name="LabSwitch",
        x=400, y=100,
        ports=24
    )
    
    # Connect router to switch
    builder.connect("Gateway", "LabSwitch", "GigabitEthernet0/0", "FastEthernet0/1")
    
    # Victim Host
    victim = builder.add_host(
        name="Victim",
        ip="192.168.1.10",
        mac="02:00:00:00:00:10",
        gateway="192.168.1.1",
        x=400, y=250,
        node_type='host'
    )
    builder.connect("Victim", "LabSwitch", "FastEthernet0", "FastEthernet0/2")
    
    # Additional Host
    host2 = builder.add_host(
        name="Host2",
        ip="192.168.1.20",
        mac="02:00:00:00:00:20",
        gateway="192.168.1.1",
        x=400, y=320,
        node_type='host'
    )
    builder.connect("Host2", "LabSwitch", "FastEthernet0", "FastEthernet0/3")
    
    # Attacker Host
    attacker = builder.add_host(
        name="Attacker",
        ip="192.168.1.99",
        mac="02:00:00:00:00:99",
        gateway="192.168.1.1",
        x=400, y=400,
        node_type='attacker'
    )
    builder.connect("Attacker", "LabSwitch", "FastEthernet0", "FastEthernet0/4")
    
    # Monitor Node (with SPAN port)
    monitor = builder.add_host(
        name="Monitor",
        ip="192.168.1.100",
        mac="02:00:00:00:00:64",
        gateway="192.168.1.1",
        x=700, y=100,
        node_type='monitor'
    )
    builder.connect("Monitor", "LabSwitch", "FastEthernet0", "FastEthernet0/24")
    
    return builder


def create_simple_topology() -> TopologyBuilder:
    """Create a minimal topology for quick testing."""
    builder = TopologyBuilder()
    
    builder.add_router("Gateway", "192.168.1.1", "02:00:00:00:00:01", 100, 100)
    builder.add_switch("Switch", 300, 100, 8)
    builder.add_host("Victim", "192.168.1.10", "02:00:00:00:00:10", "192.168.1.1", 300, 200)
    builder.add_host("Attacker", "192.168.1.99", "02:00:00:00:00:99", "192.168.1.1", 300, 280)
    builder.add_host("Monitor", "192.168.1.100", "02:00:00:00:00:64", "192.168.1.1", 500, 100, 'monitor')
    
    builder.connect("Gateway", "Switch", "GigabitEthernet0/0", "FastEthernet0/1")
    builder.connect("Victim", "Switch", "FastEthernet0", "FastEthernet0/2")
    builder.connect("Attacker", "Switch", "FastEthernet0", "FastEthernet0/3")
    builder.connect("Monitor", "Switch", "FastEthernet0", "FastEthernet0/8")
    
    return builder