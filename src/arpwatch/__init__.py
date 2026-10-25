"""ARP Spoofing Detection System - Main Package.

A comprehensive educational system for detecting ARP spoofing attacks
in local area networks, based on the BCSE308L project report.

Modules:
- attack: ARP spoofing attack generation (for testing)
- detection: Real-time ARP packet capture and analysis
- mitigation: Automated response to detected attacks
- evaluation: Metrics computation and ground truth correlation
- visualization: Real-time web dashboard
- topology: Network topology design and documentation
"""

__version__ = "1.0.0"
__author__ = "ARP Spoofing Detection Project Team"
__description__ = "Real-time ARP spoofing detection and mitigation system"

# Main exports
from .config import Config, get_config, set_config
from .models import (
    ArpPacket, ArpOperation, IpMacBinding, Alert, AlertType, AlertSeverity,
    AttackEvent, DetectionMetrics
)

# Submodules
from . import attack
from . import detection
from . import mitigation
from . import evaluation
from . import visualization
from . import topology

__all__ = [
    'Config', 'get_config', 'set_config',
    'ArpPacket', 'ArpOperation', 'IpMacBinding', 'Alert', 'AlertType', 'AlertSeverity',
    'AttackEvent', 'DetectionMetrics',
    'attack', 'detection', 'mitigation', 'evaluation', 'visualization', 'topology'
]