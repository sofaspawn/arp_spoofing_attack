"""Visualization Module - Real-time web dashboard for ARP monitoring."""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any
import time
import threading
import json
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import os

from ..models import Alert, IpMacBinding, ArpPacket
from ..config import get_config, VisualizationConfig

logger = logging.getLogger(__name__)


@dataclass
class DashboardData:
    """Data structure for dashboard state."""
    bindings: Dict[str, Dict] = field(default_factory=dict)
    recent_alerts: List[Dict] = field(default_factory=list)
    stats: Dict = field(default_factory=dict)
    attack_events: List[Dict] = field(default_factory=list)
    mitigation_actions: List[Dict] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)


class DashboardHandler(BaseHTTPRequestHandler):
    """HTTP request handler for dashboard."""
    
    # Class-level reference to dashboard instance
    dashboard: 'WebDashboard' = None
    
    def do_GET(self):
        parsed = urlparse(self.path)
        
        if parsed.path == '/' or parsed.path == '/index.html':
            self.serve_dashboard()
        elif parsed.path == '/api/data':
            self.serve_api_data()
        elif parsed.path == '/api/bindings':
            self.serve_bindings()
        elif parsed.path == '/api/alerts':
            self.serve_alerts()
        elif parsed.path == '/api/stats':
            self.serve_stats()
        elif parsed.path == '/api/attacks':
            self.serve_attacks()
        elif parsed.path == '/api/mitigations':
            self.serve_mitigations()
        elif parsed.path.startswith('/static/'):
            self.serve_static(parsed.path)
        else:
            self.send_error(404)
    
    def serve_dashboard(self):
        """Serve the main dashboard HTML."""
        html = self.dashboard.get_dashboard_html()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())
    
    def serve_api_data(self):
        """Serve complete dashboard data as JSON."""
        data = self.dashboard.get_data()
        self.send_json(data)
    
    def serve_bindings(self):
        """Serve current IP-MAC bindings."""
        self.send_json(self.dashboard.get_bindings())
    
    def serve_alerts(self):
        """Serve recent alerts."""
        self.send_json(self.dashboard.get_alerts())
    
    def serve_stats(self):
        """Serve detection statistics."""
        self.send_json(self.dashboard.get_stats())
    
    def serve_attacks(self):
        """Serve attack events."""
        self.send_json(self.dashboard.get_attacks())
    
    def serve_mitigations(self):
        """Serve mitigation actions."""
        self.send_json(self.dashboard.get_mitigations())
    
    def serve_static(self, path: str):
        """Serve static files."""
        # For simplicity, we embed CSS/JS in HTML
        self.send_error(404)
    
    def send_json(self, data: Any):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data, default=str).encode())
    
    def log_message(self, format, *args):
        # Suppress default log messages
        pass


class WebDashboard:
    """Real-time web dashboard for ARP spoofing detection."""
    
    def __init__(self, config: Optional[VisualizationConfig] = None):
        self.config = config or get_config().visualization
        self.port = self.config.web_port
        
        # Data
        self.bindings: Dict[str, IpMacBinding] = {}
        self.alerts: List[Alert] = []
        self.attack_events: List = []
        self.mitigation_actions: List = []
        self.detection_stats: Dict = {}
        self.capture_stats: Dict = {}
        self.mitigation_stats: Dict = {}
        
        # History for charts
        self.alert_history: List[Dict] = []
        self.packet_rate_history: List[Dict] = []
        self.max_history = self.config.max_history_points
        
        # Server
        self.server: Optional[HTTPServer] = None
        self.server_thread: Optional[threading.Thread] = None
        self._running = False
        self._lock = threading.RLock()
        
        # Set class reference
        DashboardHandler.dashboard = self
        
        logger.info(f"Web dashboard initialized on port {self.port}")
    
    def start(self):
        """Start the web server."""
        if self._running:
            return
        
        try:
            self.server = HTTPServer(('0.0.0.0', self.port), DashboardHandler)
            self.server_thread = threading.Thread(target=self._run_server, daemon=True)
            self.server_thread.start()
            self._running = True
            logger.info(f"Web dashboard started at http://0.0.0.0:{self.port}")
        except Exception as e:
            logger.error(f"Failed to start web dashboard: {e}")
    
    def stop(self):
        """Stop the web server."""
        if not self._running:
            return
        
        self._running = False
        if self.server:
            self.server.shutdown()
        if self.server_thread:
            self.server_thread.join(timeout=2.0)
        logger.info("Web dashboard stopped")
    
    def _run_server(self):
        """Server run loop."""
        try:
            self.server.serve_forever()
        except Exception as e:
            if self._running:
                logger.error(f"Dashboard server error: {e}")
    
    def update_bindings(self, bindings: Dict[str, IpMacBinding]):
        """Update IP-MAC bindings."""
        with self._lock:
            self.bindings = {ip: binding for ip, binding in bindings.items()}
    
    def add_alert(self, alert: Alert):
        """Add an alert to the dashboard."""
        with self._lock:
            self.alerts.insert(0, alert)
            # Keep only recent alerts
            if len(self.alerts) > 100:
                self.alerts = self.alerts[:100]
            
            # Add to history for charts
            self.alert_history.append({
                'timestamp': alert.timestamp,
                'type': alert.alert_type.value,
                'severity': alert.severity.value,
                'ip': alert.sender_ip,
                'mac': alert.sender_mac
            })
            if len(self.alert_history) > self.max_history:
                self.alert_history = self.alert_history[-self.max_history:]
    
    def add_attack_event(self, event):
        """Add an attack event."""
        with self._lock:
            self.attack_events.insert(0, event)
            if len(self.attack_events) > 100:
                self.attack_events = self.attack_events[:100]
    
    def add_mitigation_action(self, action):
        """Add a mitigation action."""
        with self._lock:
            self.mitigation_actions.insert(0, action)
            if len(self.mitigation_actions) > 100:
                self.mitigation_actions = self.mitigation_actions[:100]
    
    def update_detection_stats(self, stats: Dict):
        """Update detection statistics."""
        with self._lock:
            self.detection_stats = stats
    
    def update_capture_stats(self, stats: Dict):
        """Update capture statistics."""
        with self._lock:
            self.capture_stats = stats
    
    def update_mitigation_stats(self, stats: Dict):
        """Update mitigation statistics."""
        with self._lock:
            self.mitigation_stats = stats
    
    def get_data(self) -> Dict:
        """Get all dashboard data."""
        with self._lock:
            return {
                'bindings': {ip: b.to_dict() for ip, b in self.bindings.items()},
                'alerts': [a.to_dict() for a in self.alerts[:20]],
                'stats': {
                    'detection': self.detection_stats,
                    'capture': self.capture_stats,
                    'mitigation': self.mitigation_stats
                },
                'attacks': [a.to_dict() if hasattr(a, 'to_dict') else a for a in self.attack_events[:20]],
                'mitigations': [m.to_dict() if hasattr(m, 'to_dict') else m for m in self.mitigation_actions[:20]],
                'alert_history': self.alert_history[-50:],
                'timestamp': time.time()
            }
    
    def get_bindings(self) -> List[Dict]:
        with self._lock:
            return [b.to_dict() for b in self.bindings.values()]
    
    def get_alerts(self) -> List[Dict]:
        with self._lock:
            return [a.to_dict() for a in self.alerts[:50]]
    
    def get_stats(self) -> Dict:
        with self._lock:
            return {
                'detection': self.detection_stats,
                'capture': self.capture_stats,
                'mitigation': self.mitigation_stats
            }
    
    def get_attacks(self) -> List[Dict]:
        with self._lock:
            return [a.to_dict() if hasattr(a, 'to_dict') else a for a in self.attack_events[:50]]
    
    def get_mitigations(self) -> List[Dict]:
        with self._lock:
            return [m.to_dict() if hasattr(m, 'to_dict') else m for m in self.mitigation_actions[:50]]
    
    def get_dashboard_html(self) -> str:
        """Generate the dashboard HTML."""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ARP Spoofing Detection Dashboard</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #1a1a2e; color: #eee; line-height: 1.6; }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
        header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 1px solid #333; }}
        h1 {{ font-size: 1.8rem; color: #00d9ff; }}
        .status {{ display: flex; gap: 15px; align-items: center; }}
        .status-indicator {{ display: flex; align-items: center; gap: 8px; padding: 8px 16px; border-radius: 20px; font-weight: 600; }}
        .status-running {{ background: #0f3460; color: #00ff88; }}
        .status-stopped {{ background: #333; color: #888; }}
        .status-dot {{ width: 10px; height: 10px; border-radius: 50%; }}
        .dot-green {{ background: #00ff88; box-shadow: 0 0 10px #00ff88; }}
        .dot-red {{ background: #ff4444; box-shadow: 0 0 10px #ff4444; }}
        .dot-gray {{ background: #666; }}
        
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 20px; }}
        .card {{ background: #16213e; border-radius: 12px; padding: 20px; border: 1px solid #0f3460; }}
        .card h2 {{ color: #00d9ff; margin-bottom: 15px; font-size: 1.2rem; display: flex; align-items: center; gap: 10px; }}
        .card h2::before {{ content: ''; width: 4px; height: 20px; background: #00d9ff; border-radius: 2px; }}
        
        .binding-table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
        .binding-table th, .binding-table td {{ padding: 10px; text-align: left; border-bottom: 1px solid #333; }}
        .binding-table th {{ color: #888; font-weight: 500; }}
        .binding-table tr:hover {{ background: #0f3460; }}
        .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.75rem; font-weight: 600; }}
        .badge-gateway {{ background: #00d9ff; color: #1a1a2e; }}
        .badge-critical {{ background: #ff4444; color: white; }}
        .badge-warning {{ background: #ffaa00; color: #1a1a2e; }}
        .badge-info {{ background: #00d9ff; color: #1a1a2e; }}
        .badge-success {{ background: #00ff88; color: #1a1a2e; }}
        
        .alert-item {{ padding: 12px; margin: 8px 0; border-radius: 8px; border-left: 4px solid; animation: slideIn 0.3s; }}
        @keyframes slideIn {{ from {{ opacity: 0; transform: translateX(-20px); }} to {{ opacity: 1; transform: translateX(0); }} }}
        .alert-critical {{ background: #331111; border-color: #ff4444; }}
        .alert-warning {{ background: #332200; border-color: #ffaa00; }}
        .alert-info {{ background: #112233; border-color: #00d9ff; }}
        .alert-header {{ display: flex; justify-content: space-between; margin-bottom: 5px; }}
        .alert-time {{ color: #888; font-size: 0.8rem; }}
        .alert-message {{ font-family: monospace; font-size: 0.85rem; }}
        
        .stat-row {{ display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #333; }}
        .stat-label {{ color: #888; }}
        .stat-value {{ font-weight: 600; color: #00d9ff; }}
        .stat-value.warning {{ color: #ffaa00; }}
        .stat-value.critical {{ color: #ff4444; }}
        .stat-value.success {{ color: #00ff88; }}
        
        .chart-container {{ height: 200px; position: relative; }}
        .chart-canvas {{ width: 100%; height: 100%; }}
        
        .empty-state {{ text-align: center; color: #666; padding: 40px; }}
        
        .tabs {{ display: flex; gap: 5px; margin-bottom: 15px; }}
        .tab {{ padding: 8px 16px; background: #0f3460; border: none; color: #888; cursor: pointer; border-radius: 6px 6px 0 0; }}
        .tab.active {{ background: #16213e; color: #00d9ff; }}
        .tab-content {{ display: none; }}
        .tab-content.active {{ display: block; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ ARP Spoofing Detection Dashboard</h1>
            <div class="status">
                <div class="status-indicator status-running" id="captureStatus">
                    <span class="status-dot dot-gray" id="captureDot"></span>
                    <span id="captureText">Capture: Stopped</span>
                </div>
                <div class="status-indicator status-running" id="detectionStatus">
                    <span class="status-dot dot-gray" id="detectionDot"></span>
                    <span id="detectionText">Detection: Stopped</span>
                </div>
                <div class="status-indicator status-running" id="mitigationStatus">
                    <span class="status-dot dot-gray" id="mitigationDot"></span>
                    <span id="mitigationText">Mitigation: Disabled</span>
                </div>
            </div>
        </header>
        
        <div class="grid">
            <!-- Bindings Card -->
            <div class="card">
                <h2>📋 IP-MAC Bindings</h2>
                <table class="binding-table" id="bindingsTable">
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>MAC Address</th>
                            <th>Status</th>
                            <th>First Seen</th>
                            <th>Last Seen</th>
                            <th>Count</th>
                        </tr>
                    </thead>
                    <tbody id="bindingsBody">
                        <tr><td colspan="6" class="empty-state">Waiting for ARP traffic...</td></tr>
                    </tbody>
                </table>
            </div>
            
            <!-- Alerts Card -->
            <div class="card">
                <h2>🚨 Recent Alerts</h2>
                <div id="alertsContainer">
                    <div class="empty-state">No alerts yet</div>
                </div>
            </div>
            
            <!-- Statistics Card -->
            <div class="card">
                <h2>📊 Detection Statistics</h2>
                <div class="tabs">
                    <button class="tab active" onclick="showTab('detection')">Detection</button>
                    <button class="tab" onclick="showTab('capture')">Capture</button>
                    <button class="tab" onclick="showTab('mitigation')">Mitigation</button>
                </div>
                <div id="detectionTab" class="tab-content active">
                    <div id="detectionStats"></div>
                </div>
                <div id="captureTab" class="tab-content">
                    <div id="captureStats"></div>
                </div>
                <div id="mitigationTab" class="tab-content">
                    <div id="mitigationStats"></div>
                </div>
            </div>
            
            <!-- Attack Events Card -->
            <div class="card">
                <h2>⚔️ Attack Events (Ground Truth)</h2>
                <div id="attacksContainer">
                    <div class="empty-state">No attack events recorded</div>
                </div>
            </div>
            
            <!-- Mitigation Actions Card -->
            <div class="card">
                <h2>🛠️ Mitigation Actions</h2>
                <div id="mitigationsContainer">
                    <div class="empty-state">No mitigation actions taken</div>
                </div>
            </div>
            
            <!-- Alert Timeline Chart -->
            <div class="card" style="grid-column: 1 / -1;">
                <h2>📈 Alert Timeline</h2>
                <canvas id="alertChart" class="chart-canvas"></canvas>
            </div>
        </div>
    </div>
    
    <script>
        // Chart.js minimal implementation
        const Chart = {{
            register: () => {{}},
            Chart: class {{
                constructor(ctx, config) {{
                    this.ctx = ctx;
                    this.config = config;
                    this.draw();
                }}
                draw() {{
                    const ctx = this.ctx;
                    const data = this.config.data;
                    ctx.clearRect(0, 0, ctx.canvas.width, ctx.canvas.height);
                    
                    if (!data.datasets[0]?.data?.length) return;
                    
                    const padding = 40;
                    const w = ctx.canvas.width - padding * 2;
                    const h = ctx.canvas.height - padding * 2;
                    const maxVal = Math.max(...data.datasets[0].data) || 1;
                    
                    // Axes
                    ctx.strokeStyle = '#333';
                    ctx.lineWidth = 1;
                    ctx.beginPath();
                    ctx.moveTo(padding, padding);
                    ctx.lineTo(padding, ctx.canvas.height - padding);
                    ctx.lineTo(ctx.canvas.width - padding, ctx.canvas.height - padding);
                    ctx.stroke();
                    
                    // Data line
                    ctx.strokeStyle = '#00d9ff';
                    ctx.lineWidth = 2;
                    ctx.beginPath();
                    data.datasets[0].data.forEach((val, i) => {{
                        const x = padding + (i / (data.datasets[0].data.length - 1 || 1)) * w;
                        const y = ctx.canvas.height - padding - (val / maxVal) * h;
                        if (i === 0) ctx.moveTo(x, y);
                        else ctx.lineTo(x, y);
                    }});
                    ctx.stroke();
                    
                    // Points
                    ctx.fillStyle = '#00d9ff';
                    data.datasets[0].data.forEach((val, i) => {{
                        const x = padding + (i / (data.datasets[0].data.length - 1 || 1)) * w;
                        const y = ctx.canvas.height - padding - (val / maxVal) * h;
                        ctx.beginPath();
                        ctx.arc(x, y, 4, 0, Math.PI * 2);
                        ctx.fill();
                    }});
                    
                    // Labels
                    ctx.fillStyle = '#888';
                    ctx.font = '10px sans-serif';
                    ctx.textAlign = 'center';
                    data.labels.forEach((label, i) => {{
                        const x = padding + (i / (data.labels.length - 1 || 1)) * w;
                        ctx.fillText(label, x, ctx.canvas.height - padding + 20);
                    }});
                }}
            }}
        }};
        
        let alertChart = null;
        
        function showTab(tabName) {{
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            event.target.classList.add('active');
            document.getElementById(tabName + 'Tab').classList.add('active');
        }}
        
        function formatTime(ts) {{
            if (!ts) return 'N/A';
            const date = new Date(ts * 1000);
            return date.toLocaleTimeString();
        }}
        
        function formatDuration(ts) {{
            if (!ts) return 'N/A';
            const diff = Date.now() / 1000 - ts;
            if (diff < 60) return `${{Math.floor(diff)}}s ago`;
            if (diff < 3600) return `${{Math.floor(diff/60)}}m ago`;
            return `${{Math.floor(diff/3600)}}h ago`;
        }}
        
        function getSeverityClass(severity) {{
            return severity === 'critical' ? 'alert-critical' : 
                   severity === 'warning' ? 'alert-warning' : 'alert-info';
        }}
        
        function getBadgeClass(type) {{
            if (type === 'gateway') return 'badge-gateway';
            if (type.includes('critical')) return 'badge-critical';
            if (type.includes('warning')) return 'badge-warning';
            return 'badge-info';
        }}
        
        async function fetchData() {{
            try {{
                const response = await fetch('/api/data');
                const data = await response.json();
                updateDashboard(data);
            }} catch (e) {{
                console.error('Fetch error:', e);
            }}
        }}
        
        function updateDashboard(data) {{
            // Update status indicators
            updateStatus('capture', data.stats.capture?.running);
            updateStatus('detection', data.stats.detection?.baseline_complete);
            updateStatus('mitigation', data.stats.mitigation?.enabled);
            
            // Update bindings
            updateBindings(data.bindings);
            
            // Update alerts
            updateAlerts(data.alerts);
            
            // Update stats
            updateStats(data.stats);
            
            // Update attacks
            updateAttacks(data.attacks);
            
            // Update mitigations
            updateMitigations(data.mitigations);
            
            // Update chart
            updateChart(data.alert_history);
        }}
        
        function updateStatus(name, running) {{
            const dot = document.getElementById(name + 'Dot');
            const text = document.getElementById(name + 'Text');
            const container = document.getElementById(name + 'Status');
            
            if (running) {{
                dot.className = 'status-dot dot-green';
                text.textContent = name.charAt(0).toUpperCase() + name.slice(1) + ': Running';
                container.className = 'status-indicator status-running';
            }} else {{
                dot.className = 'status-dot dot-red';
                text.textContent = name.charAt(0).toUpperCase() + name.slice(1) + ': Stopped';
                container.className = 'status-indicator status-stopped';
            }}
        }}
        
        function updateBindings(bindings) {{
            const tbody = document.getElementById('bindingsBody');
            if (!bindings || Object.keys(bindings).length === 0) {{
                tbody.innerHTML = '<tr><td colspan="6" class="empty-state">Waiting for ARP traffic...</td></tr>';
                return;
            }}
            
            tbody.innerHTML = Object.entries(bindings).map(([ip, b]) => `
                <tr>
                    <td><code>${{ip}}</code></td>
                    <td><code>${{b.mac}}</code></td>
                    <td><span class="badge ${{b.is_gateway ? 'badge-gateway' : 'badge-success'}}">${{b.is_gateway ? 'GATEWAY' : 'LEARNED'}}</span></td>
                    <td>${{formatTime(b.first_seen)}}</td>
                    <td>${{formatTime(b.last_seen)}} (${{formatDuration(b.last_seen)}})</td>
                    <td>${{b.seen_count}}</td>
                </tr>
            `).join('');
        }}
        
        function updateAlerts(alerts) {{
            const container = document.getElementById('alertsContainer');
            if (!alerts || alerts.length === 0) {{
                container.innerHTML = '<div class="empty-state">No alerts yet</div>';
                return;
            }}
            
            container.innerHTML = alerts.map(a => `
                <div class="alert-item ${{getSeverityClass(a.severity)}}">
                    <div class="alert-header">
                        <span class="badge ${{getBadgeClass(a.alert_type)}}">${{a.alert_type}}</span>
                        <span class="alert-time">${{formatTime(a.timestamp)}} (${{formatDuration(a.timestamp)}})</span>
                    </div>
                    <div class="alert-message">${{a.message}}</div>
                </div>
            `).join('');
        }}
        
        function updateStats(stats) {{
            const det = stats.detection || {};
            const cap = stats.capture || {};
            const mit = stats.mitigation || {};
            
            document.getElementById('detectionStats').innerHTML = `
                <div class="stat-row"><span class="stat-label">Packets Processed</span><span class="stat-value">${{det.packets_processed || 0}}</span></div>
                <div class="stat-row"><span class="stat-label">Alerts Generated</span><span class="stat-value warning">${{det.alerts_generated || 0}}</span></div>
                <div class="stat-row"><span class="stat-label">Bindings Learned</span><span class="stat-value">${{det.bindings_learned || 0}}</span></div>
                <div class="stat-row"><span class="stat-label">Baseline Complete</span><span class="stat-value ${{det.baseline_complete ? 'success' : 'warning'}}">${{det.baseline_complete ? 'Yes' : 'No'}}</span></div>
                <div class="stat-row"><span class="stat-label">Baseline Elapsed</span><span class="stat-value">${{Math.floor(det.baseline_elapsed || 0)}}s</span></div>
            `;
            
            document.getElementById('captureStats').innerHTML = `
                <div class="stat-row"><span class="stat-label">Packets Captured</span><span class="stat-value">${{cap.packets_captured || 0}}</span></div>
                <div class="stat-row"><span class="stat-label">Packets Processed</span><span class="stat-value">${{cap.packets_processed || 0}}</span></div>
                <div class="stat-row"><span class="stat-label">Packets Dropped</span><span class="stat-value warning">${{cap.packets_dropped || 0}}</span></div>
                <div class="stat-row"><span class="stat-label">Errors</span><span class="stat-value critical">${{cap.errors || 0}}</span></div>
                <div class="stat-row"><span class="stat-label">Queue Size</span><span class="stat-value">${{cap.queue_size || 0}}</span></div>
                <div class="stat-row"><span class="stat-label">PPS</span><span class="stat-value">${{cap.packets_per_second?.toFixed(1) || 0}}</span></div>
            `;
            
            document.getElementById('mitigationStats').innerHTML = `
                <div class="stat-row"><span class="stat-label">Enabled</span><span class="stat-value ${{mit.enabled ? 'success' : 'warning'}}">${{mit.enabled ? 'Yes' : 'No'}}</span></div>
                <div class="stat-row"><span class="stat-label">Dry Run</span><span class="stat-value">${{mit.dry_run ? 'Yes' : 'No'}}</span></div>
                <div class="stat-row"><span class="stat-label">Corrective ARPs Sent</span><span class="stat-value">${{mit.corrective_arp_sent || 0}}</span></div>
                <div class="stat-row"><span class="stat-label">Firewall Blocks Added</span><span class="stat-value">${{mit.firewall_blocks_added || 0}}</span></div>
                <div class="stat-row"><span class="stat-label">Firewall Blocks Removed</span><span class="stat-value">${{mit.firewall_blocks_removed || 0}}</span></div>
                <div class="stat-row"><span class="stat-label">Active Blocks</span><span class="stat-value warning">${{mit.active_blocks || 0}}</span></div>
                <div class="stat-row"><span class="stat-label">Failed Actions</span><span class="stat-value critical">${{mit.actions_failed || 0}}</span></div>
            `;
        }}
        
        function updateAttacks(attacks) {{
            const container = document.getElementById('attacksContainer');
            if (!attacks || attacks.length === 0) {{
                container.innerHTML = '<div class="empty-state">No attack events recorded</div>';
                return;
            }}
            
            container.innerHTML = attacks.map(a => `
                <div class="alert-item alert-warning">
                    <div class="alert-header">
                        <span class="badge badge-warning">${{a.attack_type || 'unknown'}}</span>
                        <span class="alert-time">${{formatTime(a.timestamp)}} (${{formatDuration(a.timestamp)}})</span>
                    </div>
                    <div class="alert-message">${{a.description || `Attacker: ${{a.attacker_mac}} -> Target: ${{a.target_ip}}`}}</div>
                </div>
            `).join('');
        }}
        
        function updateMitigations(mitigations) {{
            const container = document.getElementById('mitigationsContainer');
            if (!mitigations || mitigations.length === 0) {{
                container.innerHTML = '<div class="empty-state">No mitigation actions taken</div>';
                return;
            }}
            
            container.innerHTML = mitigations.map(m => `
                <div class="alert-item alert-info">
                    <div class="alert-header">
                        <span class="badge badge-info">${{m.action_type}}</span>
                        <span class="alert-time">${{formatTime(m.timestamp)}} (${{formatDuration(m.timestamp)}})</span>
                    </div>
                    <div class="alert-message">${{m.details}} ${{m.dry_run ? '(DRY-RUN)' : ''}}</div>
                </div>
            `).join('');
        }}
        
        function updateChart(history) {{
            const canvas = document.getElementById('alertChart');
            const ctx = canvas.getContext('2d');
            
            // Resize canvas
            canvas.width = canvas.parentElement.clientWidth;
            canvas.height = 200;
            
            // Aggregate alerts by time buckets (10 second intervals)
            const now = Date.now() / 1000;
            const buckets = 30; // 5 minutes
            const bucketSize = 10; // seconds
            const data = new Array(buckets).fill(0);
            const labels = new Array(buckets).fill('');
            
            for (let i = 0; i < buckets; i++) {{
                const bucketStart = now - (buckets - i) * bucketSize;
                labels[i] = new Date(bucketStart * 1000).toLocaleTimeString([], {{minute: '2-digit', second: '2-digit'}});
            }}
            
            if (history && history.length > 0) {{
                history.forEach(a => {{
                    const idx = Math.floor((a.timestamp - (now - buckets * bucketSize)) / bucketSize);
                    if (idx >= 0 && idx < buckets) {{
                        data[idx]++;
                    }}
                }});
            }}
            
            if (alertChart) {{
                alertChart.config.data.labels = labels;
                alertChart.config.data.datasets[0].data = data;
                alertChart.draw();
            }} else {{
                alertChart = new Chart.Chart(ctx, {{
                    type: 'line',
                    data: {{
                        labels: labels,
                        datasets: [{{
                            label: 'Alerts per 10s',
                            data: data,
                            borderColor: '#00d9ff',
                            fill: false
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        maintainAspectRatio: false
                    }}
                }});
            }}
        }}
        
        // Initial load and periodic updates
        fetchData();
        setInterval(fetchData, 1000);
    </script>
</body>
</html>"""


def create_dashboard(config: Optional[VisualizationConfig] = None) -> WebDashboard:
    """Factory function to create web dashboard."""
    return WebDashboard(config)