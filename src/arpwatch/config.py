"""Configuration management for ARP Spoofing Detection System."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
import yaml
import os
from pathlib import Path


@dataclass
class NetworkConfig:
    interface: str = "eth0"
    subnet: str = "192.168.1.0/24"
    gateway_ip: str = "192.168.1.1"
    gateway_mac: str = "02:00:00:00:00:01"


@dataclass
class DetectionConfig:
    mapping_change_enabled: bool = True
    duplicate_window_seconds: float = 30.0
    rate_limit_enabled: bool = True
    max_replies_per_window: int = 8
    rate_window_seconds: float = 10.0
    gratuitous_arp_enabled: bool = True
    gratuitous_threshold: int = 3
    mac_spoofing_enabled: bool = True
    max_ips_per_mac: int = 3
    baseline_learning_enabled: bool = True
    baseline_duration_seconds: float = 60.0
    require_baseline_before_alert: bool = True


@dataclass
class MitigationConfig:
    enabled: bool = False
    corrective_arp_enabled: bool = True
    corrective_arp_count: int = 3
    corrective_arp_interval: float = 1.0
    firewall_block_enabled: bool = False
    firewall_block_duration: int = 300
    auto_restore_on_timeout: bool = True


@dataclass
class EvaluationConfig:
    enabled: bool = True
    log_detailed_events: bool = True
    metrics_window_seconds: float = 60.0
    ground_truth_file: str = "logs/ground_truth.jsonl"
    results_file: str = "logs/evaluation_results.json"


@dataclass
class VisualizationConfig:
    enabled: bool = True
    web_port: int = 8080
    update_interval_seconds: float = 1.0
    max_history_points: int = 300


@dataclass
class LoggingConfig:
    level: str = "INFO"
    file: str = "logs/arpwatch.log"
    max_size_mb: int = 10
    backup_count: int = 5
    json_format: bool = True


@dataclass
class SafetyConfig:
    dry_run: bool = True
    require_explicit_interface: bool = True
    allowed_interfaces: list = field(default_factory=list)
    max_packets_per_second: int = 100


@dataclass
class Config:
    network: NetworkConfig = field(default_factory=NetworkConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    mitigation: MitigationConfig = field(default_factory=MitigationConfig)
    evaluation: EvaluationConfig = field(default_factory=EvaluationConfig)
    visualization: VisualizationConfig = field(default_factory=VisualizationConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    safety: SafetyConfig = field(default_factory=SafetyConfig)
    
    @classmethod
    def load(cls, path: Optional[str] = None) -> 'Config':
        """Load configuration from YAML file."""
        config = cls()
        
        if path is None:
            # Try default locations
            for p in [
                "configs/default.yaml",
                "../configs/default.yaml",
                "../../configs/default.yaml",
                "/etc/arpwatch/config.yaml"
            ]:
                if os.path.exists(p):
                    path = p
                    break
        
        if path and os.path.exists(path):
            with open(path, 'r') as f:
                data = yaml.safe_load(f)
            if data:
                config._update_from_dict(data)
        
        # Override with environment variables
        config._apply_env_overrides()
        
        return config
    
    def _update_from_dict(self, data: Dict[str, Any]):
        """Update config from dictionary."""
        if 'network' in data:
            for k, v in data['network'].items():
                if hasattr(self.network, k):
                    setattr(self.network, k, v)
        if 'detection' in data:
            for k, v in data['detection'].items():
                if hasattr(self.detection, k):
                    setattr(self.detection, k, v)
        if 'mitigation' in data:
            for k, v in data['mitigation'].items():
                if hasattr(self.mitigation, k):
                    setattr(self.mitigation, k, v)
        if 'evaluation' in data:
            for k, v in data['evaluation'].items():
                if hasattr(self.evaluation, k):
                    setattr(self.evaluation, k, v)
        if 'visualization' in data:
            for k, v in data['visualization'].items():
                if hasattr(self.visualization, k):
                    setattr(self.visualization, k, v)
        if 'logging' in data:
            for k, v in data['logging'].items():
                if hasattr(self.logging, k):
                    setattr(self.logging, k, v)
        if 'safety' in data:
            for k, v in data['safety'].items():
                if hasattr(self.safety, k):
                    setattr(self.safety, k, v)
    
    def _apply_env_overrides(self):
        """Apply environment variable overrides."""
        env_map = {
            'ARPWATCH_INTERFACE': ('network', 'interface'),
            'ARPWATCH_SUBNET': ('network', 'subnet'),
            'ARPWATCH_GATEWAY_IP': ('network', 'gateway_ip'),
            'ARPWATCH_DRY_RUN': ('safety', 'dry_run'),
            'ARPWATCH_WEB_PORT': ('visualization', 'web_port'),
            'ARPWATCH_LOG_LEVEL': ('logging', 'level'),
        }
        
        for env_var, (section, key) in env_map.items():
            value = os.environ.get(env_var)
            if value is not None:
                section_obj = getattr(self, section)
                # Type conversion
                current = getattr(section_obj, key)
                if isinstance(current, bool):
                    value = value.lower() in ('true', '1', 'yes', 'on')
                elif isinstance(current, int):
                    value = int(value)
                elif isinstance(current, float):
                    value = float(value)
                setattr(section_obj, key, value)
    
    def save(self, path: str):
        """Save current configuration to YAML file."""
        data = {
            'network': self.network.__dict__,
            'detection': self.detection.__dict__,
            'mitigation': self.mitigation.__dict__,
            'evaluation': self.evaluation.__dict__,
            'visualization': self.visualization.__dict__,
            'logging': self.logging.__dict__,
            'safety': self.safety.__dict__,
        }
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)


# Global config instance
_config: Optional[Config] = None


def get_config() -> Config:
    """Get global configuration instance."""
    global _config
    if _config is None:
        _config = Config.load()
    return _config


def set_config(config: Config):
    """Set global configuration instance."""
    global _config
    _config = config