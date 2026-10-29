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
    recent_packets: List[Dict] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)


class DashboardHandler(BaseHTTPRequestHandler):
    """HTTP request handler for dashboard."""
    dashboard: 'WebDashboard' = None

    def do_GET(self):
        parsed = urlparse(self.path)
        routes = {
            '/': self.serve_dashboard,
            '/index.html': self.serve_dashboard,
            '/api/data': self.serve_api_data,
            '/api/bindings': lambda: self.send_json(self.dashboard.get_bindings()),
            '/api/alerts': lambda: self.send_json(self.dashboard.get_alerts()),
            '/api/stats': lambda: self.send_json(self.dashboard.get_stats()),
            '/api/attacks': lambda: self.send_json(self.dashboard.get_attacks()),
            '/api/mitigations': lambda: self.send_json(self.dashboard.get_mitigations()),
        }
        handler = routes.get(parsed.path)
        if handler:
            handler()
        else:
            self.send_error(404)

    def serve_dashboard(self):
        html = self.dashboard.get_dashboard_html()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())

    def serve_api_data(self):
        self.send_json(self.dashboard.get_data())

    def send_json(self, data: Any):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data, default=str).encode())

    def log_message(self, format, *args):
        pass


class WebDashboard:
    """Real-time web dashboard for ARP spoofing detection."""

    def __init__(self, config: Optional[VisualizationConfig] = None):
        self.config = config or get_config().visualization
        self.port = self.config.web_port

        self.bindings: Dict[str, IpMacBinding] = {}
        self.alerts: List[Alert] = []
        self.attack_events: List = []
        self.mitigation_actions: List = []
        self.detection_stats: Dict = {}
        self.capture_stats: Dict = {}
        self.mitigation_stats: Dict = {}
        self.recent_packets: List[Dict] = []

        self.alert_history: List[Dict] = []
        self.max_history = self.config.max_history_points

        self.server: Optional[HTTPServer] = None
        self.server_thread: Optional[threading.Thread] = None
        self._running = False
        self._lock = threading.RLock()

        DashboardHandler.dashboard = self
        logger.info(f"Web dashboard initialized on port {self.port}")

    def start(self):
        if self._running:
            return
        try:
            self.server = HTTPServer(('127.0.0.1', self.port), DashboardHandler)
            self.server_thread = threading.Thread(target=self._run_server, daemon=True)
            self.server_thread.start()
            self._running = True
            logger.info(f"Web dashboard started at http://127.0.0.1:{self.port}")
        except Exception as e:
            logger.error(f"Failed to start web dashboard: {e}")

    def stop(self):
        if not self._running:
            return
        self._running = False
        if self.server:
            self.server.shutdown()
        if self.server_thread:
            self.server_thread.join(timeout=2.0)
        logger.info("Web dashboard stopped")

    def _run_server(self):
        try:
            self.server.serve_forever()
        except Exception as e:
            if self._running:
                logger.error(f"Dashboard server error: {e}")

    def update_bindings(self, bindings: Dict[str, IpMacBinding]):
        with self._lock:
            self.bindings = dict(bindings)

    def add_alert(self, alert: Alert):
        with self._lock:
            self.alerts.insert(0, alert)
            if len(self.alerts) > 100:
                self.alerts = self.alerts[:100]
            self.alert_history.append({
                'timestamp': alert.timestamp,
                'type': alert.alert_type.value,
                'severity': alert.severity.value,
                'ip': alert.sender_ip,
                'mac': alert.sender_mac,
            })
            if len(self.alert_history) > self.max_history:
                self.alert_history = self.alert_history[-self.max_history:]

    def add_attack_event(self, event):
        with self._lock:
            self.attack_events.insert(0, event)
            if len(self.attack_events) > 100:
                self.attack_events = self.attack_events[:100]

    def add_mitigation_action(self, action):
        with self._lock:
            self.mitigation_actions.insert(0, action)
            if len(self.mitigation_actions) > 100:
                self.mitigation_actions = self.mitigation_actions[:100]

    def update_detection_stats(self, stats: Dict):
        with self._lock:
            self.detection_stats = stats

    def update_capture_stats(self, stats: Dict):
        with self._lock:
            self.capture_stats = stats

    def update_mitigation_stats(self, stats: Dict):
        with self._lock:
            self.mitigation_stats = stats

    def update_recent_packets(self, packets: List[Dict]):
        with self._lock:
            self.recent_packets = packets[-30:]

    def get_data(self) -> Dict:
        with self._lock:
            return {
                'bindings': {ip: b.to_dict() for ip, b in self.bindings.items()},
                'alerts': [a.to_dict() for a in self.alerts[:20]],
                'stats': {
                    'detection': self.detection_stats,
                    'capture': self.capture_stats,
                    'mitigation': self.mitigation_stats,
                },
                'attacks': [a.to_dict() if hasattr(a, 'to_dict') else a for a in self.attack_events[:20]],
                'mitigations': [m.to_dict() if hasattr(m, 'to_dict') else m for m in self.mitigation_actions[:20]],
                'alert_history': self.alert_history[-60:],
                'recent_packets': list(self.recent_packets),
                'timestamp': time.time(),
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
                'mitigation': self.mitigation_stats,
            }

    def get_attacks(self) -> List[Dict]:
        with self._lock:
            return [a.to_dict() if hasattr(a, 'to_dict') else a for a in self.attack_events[:50]]

    def get_mitigations(self) -> List[Dict]:
        with self._lock:
            return [m.to_dict() if hasattr(m, 'to_dict') else m for m in self.mitigation_actions[:50]]

    def get_dashboard_html(self) -> str:
        return _DASHBOARD_HTML


# ---------------------------------------------------------------------------
# HTML / CSS / JS  (single-file, no CDN dependencies)
# ---------------------------------------------------------------------------

_DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ARPwatch — Detection Dashboard</title>
<style>
/* ── reset & tokens ──────────────────────────────────────────── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --bg0:   #0c0e14;
  --bg1:   #111420;
  --bg2:   #181d2e;
  --bg3:   #1e2438;
  --border: rgba(100,120,200,.15);
  --border2: rgba(100,120,200,.3);

  --accent:  #4f8fff;
  --green:   #3dffa0;
  --yellow:  #ffc84a;
  --red:     #ff4f6b;
  --purple:  #b57fff;
  --teal:    #00d4c8;

  --text:    #d4d8f0;
  --muted:   #5a6180;
  --dim:     #333a55;

  --font-mono: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;
  --font-sans: 'Inter', system-ui, -apple-system, sans-serif;
  --radius:  8px;
  --radius-lg: 12px;
}

@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=JetBrains+Mono:wght@400;500&display=swap');

html, body { height: 100%; }
body {
  font-family: var(--font-sans);
  background: var(--bg0);
  color: var(--text);
  font-size: 13px;
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}

/* ── layout ──────────────────────────────────────────────────── */
.shell {
  display: grid;
  grid-template-rows: 52px 1fr;
  grid-template-columns: 220px 1fr;
  height: 100vh;
  overflow: hidden;
}

/* ── topbar ──────────────────────────────────────────────────── */
.topbar {
  grid-column: 1 / -1;
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 0 20px;
  background: var(--bg1);
  border-bottom: 1px solid var(--border);
  z-index: 20;
}
.topbar-logo {
  display: flex;
  align-items: center;
  gap: 10px;
  font-weight: 600;
  font-size: 14px;
  letter-spacing: .02em;
  color: var(--text);
}
.topbar-logo svg { flex-shrink: 0; }
.topbar-sep { flex: 1; }
.pill {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 10px;
  border-radius: 20px;
  font-size: 11px;
  font-weight: 500;
  background: var(--bg3);
  border: 1px solid var(--border);
  color: var(--muted);
  transition: color .2s, border-color .2s;
}
.pill.on  { color: var(--green);  border-color: rgba(61,255,160,.3); }
.pill.warn{ color: var(--yellow); border-color: rgba(255,200,74,.3); }
.pill.off { color: var(--red);    border-color: rgba(255,79,107,.3); }
.pill-dot {
  width: 6px; height: 6px;
  border-radius: 50%;
  background: currentColor;
}
.pill.on  .pill-dot { box-shadow: 0 0 6px var(--green); }
.pill.warn .pill-dot { box-shadow: 0 0 6px var(--yellow); }
.pill.off  .pill-dot { box-shadow: 0 0 6px var(--red); }

.clock { font-family: var(--font-mono); font-size: 12px; color: var(--muted); }

/* ── sidebar ─────────────────────────────────────────────────── */
.sidebar {
  background: var(--bg1);
  border-right: 1px solid var(--border);
  overflow-y: auto;
  padding: 16px 0;
}
.nav-section {
  padding: 0 14px;
  margin-bottom: 4px;
  font-size: 10px;
  letter-spacing: .1em;
  text-transform: uppercase;
  color: var(--muted);
}
.nav-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 16px;
  cursor: pointer;
  border-radius: 0;
  color: var(--muted);
  font-size: 13px;
  border-left: 2px solid transparent;
  transition: all .15s;
  user-select: none;
}
.nav-item:hover { background: var(--bg2); color: var(--text); }
.nav-item.active {
  background: rgba(79,143,255,.08);
  color: var(--accent);
  border-left-color: var(--accent);
}
.nav-badge {
  margin-left: auto;
  background: var(--red);
  color: #fff;
  font-size: 10px;
  font-weight: 600;
  padding: 1px 6px;
  border-radius: 10px;
  min-width: 18px;
  text-align: center;
}
.nav-badge.yellow { background: var(--yellow); color: #1a1200; }
.nav-badge.green  { background: var(--green);  color: #001a0d; }

/* ── main ────────────────────────────────────────────────────── */
.main {
  overflow-y: auto;
  padding: 20px;
  display: flex;
  flex-direction: column;
  gap: 16px;
}

/* ── page titles ─────────────────────────────────────────────── */
.page { display: none; flex-direction: column; gap: 16px; }
.page.active { display: flex; }
.page-title {
  font-size: 15px;
  font-weight: 600;
  color: var(--text);
  display: flex;
  align-items: center;
  gap: 10px;
}
.page-title small {
  font-size: 11px;
  font-weight: 400;
  color: var(--muted);
}

/* ── cards ───────────────────────────────────────────────────── */
.card {
  background: var(--bg1);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  overflow: hidden;
}
.card-header {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 16px;
  border-bottom: 1px solid var(--border);
  font-size: 12px;
  font-weight: 500;
  color: var(--muted);
  letter-spacing: .04em;
  text-transform: uppercase;
}
.card-header .icon { color: var(--accent); }
.card-body { padding: 16px; }

/* ── summary tiles ───────────────────────────────────────────── */
.tiles {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 12px;
}
.tile {
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 14px 16px;
  display: flex;
  flex-direction: column;
  gap: 6px;
  position: relative;
  overflow: hidden;
  transition: border-color .2s;
}
.tile:hover { border-color: var(--border2); }
.tile::before {
  content: '';
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 2px;
  background: var(--accent);
  opacity: .6;
}
.tile.green::before { background: var(--green); }
.tile.yellow::before { background: var(--yellow); }
.tile.red::before    { background: var(--red); }
.tile.purple::before { background: var(--purple); }
.tile.teal::before   { background: var(--teal); }

.tile-label {
  font-size: 10px;
  letter-spacing: .06em;
  text-transform: uppercase;
  color: var(--muted);
}
.tile-value {
  font-size: 26px;
  font-weight: 600;
  font-variant-numeric: tabular-nums;
  line-height: 1;
  color: var(--text);
}
.tile-sub {
  font-size: 10px;
  color: var(--muted);
  font-family: var(--font-mono);
}

/* ── table ───────────────────────────────────────────────────── */
.tbl { width: 100%; border-collapse: collapse; }
.tbl th {
  padding: 8px 12px;
  text-align: left;
  font-size: 10px;
  letter-spacing: .08em;
  text-transform: uppercase;
  color: var(--muted);
  border-bottom: 1px solid var(--border);
  font-weight: 500;
}
.tbl td {
  padding: 10px 12px;
  border-bottom: 1px solid rgba(100,120,200,.06);
  color: var(--text);
  font-size: 12px;
}
.tbl tr:last-child td { border-bottom: none; }
.tbl tr:hover td { background: rgba(79,143,255,.04); }
.mono { font-family: var(--font-mono); font-size: 11px; }
.muted { color: var(--muted); }

/* ── badges ──────────────────────────────────────────────────── */
.badge {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 10px;
  font-weight: 600;
  letter-spacing: .04em;
  text-transform: uppercase;
}
.badge-red    { background: rgba(255,79,107,.15);  color: var(--red);    border: 1px solid rgba(255,79,107,.3);  }
.badge-yellow { background: rgba(255,200,74,.15);  color: var(--yellow); border: 1px solid rgba(255,200,74,.3);  }
.badge-green  { background: rgba(61,255,160,.12);  color: var(--green);  border: 1px solid rgba(61,255,160,.25); }
.badge-blue   { background: rgba(79,143,255,.15);  color: var(--accent); border: 1px solid rgba(79,143,255,.3);  }
.badge-purple { background: rgba(181,127,255,.15); color: var(--purple); border: 1px solid rgba(181,127,255,.3); }
.badge-teal   { background: rgba(0,212,200,.12);   color: var(--teal);   border: 1px solid rgba(0,212,200,.25);  }
.badge-dim    { background: var(--bg3);            color: var(--muted);  border: 1px solid var(--border);       }

/* ── alert items ─────────────────────────────────────────────── */
.alert-list { display: flex; flex-direction: column; gap: 6px; }
.alert-row {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  padding: 10px 14px;
  border-radius: var(--radius);
  background: var(--bg2);
  border: 1px solid var(--border);
  border-left-width: 3px;
  animation: slideUp .25s ease;
}
@keyframes slideUp {
  from { opacity: 0; transform: translateY(6px); }
  to   { opacity: 1; transform: translateY(0); }
}
.alert-row.crit { border-left-color: var(--red);    background: rgba(255,79,107,.04); }
.alert-row.warn { border-left-color: var(--yellow); background: rgba(255,200,74,.04); }
.alert-row.info { border-left-color: var(--accent); background: rgba(79,143,255,.04); }
.alert-meta { display: flex; flex-direction: column; gap: 3px; flex: 1; min-width: 0; }
.alert-type { font-size: 11px; font-weight: 600; }
.alert-msg  { font-family: var(--font-mono); font-size: 11px; color: var(--muted); word-break: break-all; }
.alert-ts   { font-size: 10px; color: var(--dim); white-space: nowrap; }

/* ── packet feed ─────────────────────────────────────────────── */
.packet-feed {
  font-family: var(--font-mono);
  font-size: 11px;
  display: flex;
  flex-direction: column;
  gap: 2px;
  max-height: 260px;
  overflow-y: auto;
}
.pkt {
  display: grid;
  grid-template-columns: 60px 56px 110px 1fr 1fr;
  gap: 8px;
  padding: 4px 8px;
  border-radius: 4px;
  align-items: center;
  transition: background .1s;
}
.pkt:hover { background: var(--bg2); }
.pkt-ts   { color: var(--dim); }
.pkt-op   { }
.pkt-op.REQUEST { color: var(--accent); }
.pkt-op.REPLY   { color: var(--green);  }
.pkt-ip   { color: var(--text); }
.pkt-mac  { color: var(--muted); }

/* ── topology ────────────────────────────────────────────────── */
#topology-svg {
  width: 100%;
  height: 280px;
  display: block;
}

/* ── chart ───────────────────────────────────────────────────── */
.chart-wrap { position: relative; height: 140px; }
canvas.chart { width: 100%; height: 100%; display: block; }

/* ── metric bars ─────────────────────────────────────────────── */
.metric-rows { display: flex; flex-direction: column; gap: 10px; }
.metric-row  { display: flex; flex-direction: column; gap: 4px; }
.metric-head { display: flex; justify-content: space-between; font-size: 11px; }
.metric-name { color: var(--muted); }
.metric-val  { color: var(--text); font-weight: 600; }
.bar-track {
  height: 4px;
  background: var(--bg3);
  border-radius: 2px;
  overflow: hidden;
}
.bar-fill {
  height: 100%;
  border-radius: 2px;
  transition: width .4s ease;
}
.bar-fill.green  { background: var(--green);  }
.bar-fill.yellow { background: var(--yellow); }
.bar-fill.red    { background: var(--red);    }
.bar-fill.blue   { background: var(--accent); }

/* ── stat grid ───────────────────────────────────────────────── */
.stat-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 6px 16px;
}
.stat-line {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 5px 0;
  border-bottom: 1px solid rgba(100,120,200,.06);
}
.stat-line:last-child { border-bottom: none; }
.stat-k { color: var(--muted); font-size: 11px; }
.stat-v { font-size: 11px; font-weight: 600; font-family: var(--font-mono); }
.stat-v.green  { color: var(--green); }
.stat-v.yellow { color: var(--yellow); }
.stat-v.red    { color: var(--red); }
.stat-v.blue   { color: var(--accent); }
.stat-v.purple { color: var(--purple); }

/* ── empty state ─────────────────────────────────────────────── */
.empty {
  padding: 40px 20px;
  text-align: center;
  color: var(--dim);
  font-size: 12px;
  letter-spacing: .04em;
}
.empty svg { margin-bottom: 10px; opacity: .3; }

/* ── scrollbar ───────────────────────────────────────────────── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--bg3); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--dim); }

/* ── grid helpers ─────────────────────────────────────────────── */
.grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
.grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px; }

@media (max-width: 960px) {
  .grid-2, .grid-3 { grid-template-columns: 1fr; }
  .shell { grid-template-columns: 1fr; }
  .sidebar { display: none; }
}
</style>
</head>
<body>
<div class="shell">

  <!-- ── topbar ── -->
  <header class="topbar">
    <div class="topbar-logo">
      <svg width="22" height="22" viewBox="0 0 22 22" fill="none">
        <circle cx="11" cy="11" r="10" stroke="#4f8fff" stroke-width="1.5"/>
        <path d="M6 11h10M11 6v10" stroke="#4f8fff" stroke-width="1.5" stroke-linecap="round"/>
        <circle cx="11" cy="11" r="3" fill="#4f8fff" opacity=".4"/>
      </svg>
      ARPwatch
    </div>
    <span style="color:var(--dim);font-size:11px;font-family:var(--font-mono)">OFFLINE LAB · DRY-RUN</span>
    <div class="topbar-sep"></div>
    <div class="pill" id="pill-capture"><span class="pill-dot"></span>Capture</div>
    <div class="pill" id="pill-detection"><span class="pill-dot"></span>Detection</div>
    <div class="pill" id="pill-mitigation"><span class="pill-dot"></span>Mitigation</div>
    <div class="clock" id="clock">--:--:--</div>
  </header>

  <!-- ── sidebar ── -->
  <nav class="sidebar">
    <div class="nav-section" style="margin-top:4px;margin-bottom:12px;">Navigation</div>
    <div class="nav-item active" data-page="overview" onclick="navigate(this)">
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><rect x="1" y="1" width="6" height="6" rx="1" stroke="currentColor" stroke-width="1.3"/><rect x="9" y="1" width="6" height="6" rx="1" stroke="currentColor" stroke-width="1.3"/><rect x="1" y="9" width="6" height="6" rx="1" stroke="currentColor" stroke-width="1.3"/><rect x="9" y="9" width="6" height="6" rx="1" stroke="currentColor" stroke-width="1.3"/></svg>
      Overview
    </div>
    <div class="nav-item" data-page="alerts" onclick="navigate(this)">
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M8 2L2 12h12L8 2z" stroke="currentColor" stroke-width="1.3" stroke-linejoin="round"/><path d="M8 7v3M8 11.5v.5" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg>
      Alerts
      <span class="nav-badge" id="nb-alerts">0</span>
    </div>
    <div class="nav-item" data-page="bindings" onclick="navigate(this)">
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><circle cx="4" cy="8" r="2.5" stroke="currentColor" stroke-width="1.3"/><circle cx="12" cy="8" r="2.5" stroke="currentColor" stroke-width="1.3"/><path d="M6.5 8h3" stroke="currentColor" stroke-width="1.3"/></svg>
      Bindings
    </div>
    <div class="nav-item" data-page="topology" onclick="navigate(this)">
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="3" r="2" stroke="currentColor" stroke-width="1.3"/><circle cx="2" cy="13" r="2" stroke="currentColor" stroke-width="1.3"/><circle cx="14" cy="13" r="2" stroke="currentColor" stroke-width="1.3"/><path d="M8 5v2M8 7L2 11M8 7l6 4" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg>
      Topology
    </div>
    <div class="nav-item" data-page="packets" onclick="navigate(this)">
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><rect x="1" y="4" width="14" height="8" rx="1.5" stroke="currentColor" stroke-width="1.3"/><path d="M5 4V3a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v1" stroke="currentColor" stroke-width="1.3"/></svg>
      Packet Feed
    </div>
    <div class="nav-item" data-page="attacks" onclick="navigate(this)">
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M2 14l5-5M9 7l2-5 4 4-5 2z" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/></svg>
      Attack Events
      <span class="nav-badge yellow" id="nb-attacks">0</span>
    </div>
    <div class="nav-item" data-page="mitigation" onclick="navigate(this)">
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M8 2l5 3v4a6 6 0 0 1-5 4 6 6 0 0 1-5-4V5l5-3z" stroke="currentColor" stroke-width="1.3" stroke-linejoin="round"/></svg>
      Mitigation
      <span class="nav-badge green" id="nb-mitigations">0</span>
    </div>
    <div class="nav-item" data-page="metrics" onclick="navigate(this)">
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M1 13l4-5 3 2 4-6 3 4" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/></svg>
      Evaluation
    </div>
  </nav>

  <!-- ── main ── -->
  <main class="main">

    <!-- ══ Overview ══ -->
    <div id="page-overview" class="page active">
      <div class="page-title">Overview <small>Live system state</small></div>
      <div class="tiles" id="overview-tiles">
        <div class="tile blue">
          <div class="tile-label">Packets</div>
          <div class="tile-value" id="t-packets">0</div>
          <div class="tile-sub">processed</div>
        </div>
        <div class="tile red">
          <div class="tile-label">Alerts</div>
          <div class="tile-value" id="t-alerts">0</div>
          <div class="tile-sub">total generated</div>
        </div>
        <div class="tile green">
          <div class="tile-label">Bindings</div>
          <div class="tile-value" id="t-bindings">0</div>
          <div class="tile-sub">IP→MAC learned</div>
        </div>
        <div class="tile yellow">
          <div class="tile-label">Attacks</div>
          <div class="tile-value" id="t-attacks">0</div>
          <div class="tile-sub">ground truth events</div>
        </div>
        <div class="tile purple">
          <div class="tile-label">Mitigations</div>
          <div class="tile-value" id="t-mitigations">0</div>
          <div class="tile-sub">actions taken</div>
        </div>
        <div class="tile teal">
          <div class="tile-label">MITM Sigs</div>
          <div class="tile-value" id="t-mitm">0</div>
          <div class="tile-sub">two-way detected</div>
        </div>
      </div>

      <!-- alert timeline -->
      <div class="card">
        <div class="card-header">
          <svg class="icon" width="14" height="14" viewBox="0 0 14 14" fill="none"><path d="M1 11l3-4 2 2 3-5 3 3" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/></svg>
          Alert Timeline — last 5 min
        </div>
        <div class="card-body">
          <div class="chart-wrap"><canvas id="timeline-chart" class="chart"></canvas></div>
        </div>
      </div>

      <div class="grid-2">
        <!-- recent alerts -->
        <div class="card">
          <div class="card-header">
            <svg class="icon" width="14" height="14" viewBox="0 0 14 14" fill="none"><path d="M7 2L2 11h10L7 2z" stroke="currentColor" stroke-width="1.3" stroke-linejoin="round"/><path d="M7 6v3" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg>
            Recent Alerts
          </div>
          <div class="card-body">
            <div class="alert-list" id="ov-alerts">
              <div class="empty">No alerts yet</div>
            </div>
          </div>
        </div>

        <!-- detection stats -->
        <div class="card">
          <div class="card-header">
            <svg class="icon" width="14" height="14" viewBox="0 0 14 14" fill="none"><circle cx="7" cy="7" r="5.5" stroke="currentColor" stroke-width="1.3"/><path d="M7 4v3l2 2" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg>
            Detection Engine
          </div>
          <div class="card-body">
            <div class="stat-grid" id="ov-det-stats"></div>
          </div>
        </div>
      </div>
    </div>

    <!-- ══ Alerts ══ -->
    <div id="page-alerts" class="page">
      <div class="page-title">Alerts <small>All generated alerts</small></div>
      <div class="card">
        <div class="card-body">
          <div class="alert-list" id="full-alerts"><div class="empty">No alerts yet</div></div>
        </div>
      </div>
    </div>

    <!-- ══ Bindings ══ -->
    <div id="page-bindings" class="page">
      <div class="page-title">IP→MAC Bindings <small>Learned ARP table</small></div>
      <div class="card">
        <div class="card-body" style="padding:0">
          <table class="tbl">
            <thead>
              <tr>
                <th>IP Address</th>
                <th>MAC Address</th>
                <th>Role</th>
                <th>First Seen</th>
                <th>Last Seen</th>
                <th>Count</th>
              </tr>
            </thead>
            <tbody id="bindings-body">
              <tr><td colspan="6" class="empty">Waiting for ARP traffic…</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- ══ Topology ══ -->
    <div id="page-topology" class="page">
      <div class="page-title">Network Topology <small>Live node graph</small></div>
      <div class="card">
        <div class="card-header">
          <svg class="icon" width="14" height="14" viewBox="0 0 14 14" fill="none"><circle cx="7" cy="3" r="2" stroke="currentColor" stroke-width="1.2"/><circle cx="2" cy="11" r="2" stroke="currentColor" stroke-width="1.2"/><circle cx="12" cy="11" r="2" stroke="currentColor" stroke-width="1.2"/><path d="M7 5v1M7 6L2 9M7 6l5 3" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/></svg>
          Node Map
        </div>
        <div class="card-body" style="padding:0">
          <svg id="topology-svg"></svg>
        </div>
      </div>
    </div>

    <!-- ══ Packets ══ -->
    <div id="page-packets" class="page">
      <div class="page-title">Packet Feed <small>Recent ARP frames</small></div>
      <div class="card">
        <div class="card-header" style="font-family:var(--font-mono)">
          TS &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; OP &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; SENDER IP &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; SENDER MAC &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; TARGET IP
        </div>
        <div class="card-body" style="padding:8px">
          <div class="packet-feed" id="packet-feed"><div class="empty">No packets yet…</div></div>
        </div>
      </div>
    </div>

    <!-- ══ Attacks ══ -->
    <div id="page-attacks" class="page">
      <div class="page-title">Attack Events <small>Ground-truth labeled events</small></div>
      <div class="card">
        <div class="card-body">
          <div class="alert-list" id="attack-list"><div class="empty">No attack events recorded</div></div>
        </div>
      </div>
    </div>

    <!-- ══ Mitigation ══ -->
    <div id="page-mitigation" class="page">
      <div class="page-title">Mitigation Actions <small>Defensive responses (DRY-RUN)</small></div>
      <div class="grid-2">
        <div class="card">
          <div class="card-header">
            <svg class="icon" width="14" height="14" viewBox="0 0 14 14" fill="none"><path d="M7 1l5 3v4a6 6 0 0 1-5 4 6 6 0 0 1-5-4V4l5-3z" stroke="currentColor" stroke-width="1.2" stroke-linejoin="round"/></svg>
            Engine Status
          </div>
          <div class="card-body">
            <div class="stat-grid" id="mit-stats"></div>
          </div>
        </div>
        <div class="card">
          <div class="card-header">
            <svg class="icon" width="14" height="14" viewBox="0 0 14 14" fill="none"><path d="M1 10l5-5M8 5l2-4 4 4-4 2z" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/></svg>
            Action Log
          </div>
          <div class="card-body">
            <div class="alert-list" id="mit-list"><div class="empty">No actions yet</div></div>
          </div>
        </div>
      </div>
    </div>

    <!-- ══ Metrics ══ -->
    <div id="page-metrics" class="page">
      <div class="page-title">Evaluation Metrics <small>Detection performance</small></div>
      <div class="grid-2">
        <div class="card">
          <div class="card-header">
            <svg class="icon" width="14" height="14" viewBox="0 0 14 14" fill="none"><path d="M1 11l3-4 2 2 3-5 3 4" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/></svg>
            Performance Ratios
          </div>
          <div class="card-body">
            <div class="metric-rows" id="perf-bars"></div>
          </div>
        </div>
        <div class="card">
          <div class="card-header">
            <svg class="icon" width="14" height="14" viewBox="0 0 14 14" fill="none"><rect x="1" y="1" width="12" height="12" rx="2" stroke="currentColor" stroke-width="1.2"/><path d="M4 7h2l1.5-3 2 6 1-3h1.5" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/></svg>
            Alert Type Breakdown
          </div>
          <div class="card-body">
            <div id="type-breakdown"></div>
          </div>
        </div>
      </div>
      <div class="card">
        <div class="card-header">Confusion Matrix</div>
        <div class="card-body">
          <div id="confusion-matrix" style="display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:12px;"></div>
        </div>
      </div>
    </div>

  </main><!-- .main -->
</div><!-- .shell -->

<script>
// ── State ───────────────────────────────────────────────────────────────────
let D = {};        // last fetched data
let chartData = []; // timeline data

// ── Navigation ──────────────────────────────────────────────────────────────
function navigate(el) {
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  el.classList.add('active');
  const page = el.dataset.page;
  document.getElementById('page-' + page).classList.add('active');
}

// ── Clock ────────────────────────────────────────────────────────────────────
function tickClock() {
  document.getElementById('clock').textContent = new Date().toLocaleTimeString();
}
setInterval(tickClock, 1000); tickClock();

// ── Helpers ──────────────────────────────────────────────────────────────────
const fmt = {
  time(ts) {
    if (!ts) return '—';
    return new Date(ts * 1000).toLocaleTimeString();
  },
  ago(ts) {
    if (!ts) return '';
    const d = Date.now()/1000 - ts;
    if (d < 60) return `${Math.floor(d)}s ago`;
    if (d < 3600) return `${Math.floor(d/60)}m ago`;
    return `${Math.floor(d/3600)}h ago`;
  },
  pct(v) { return (v * 100).toFixed(1) + '%'; },
  shortTs(ts) {
    const d = new Date(ts * 1000);
    return d.toLocaleTimeString([], {hour12:false,hour:'2-digit',minute:'2-digit',second:'2-digit'});
  }
};

function severityClass(s) {
  return s === 'critical' ? 'crit' : s === 'warning' ? 'warn' : 'info';
}
function severityBadge(s) {
  const cls = s === 'critical' ? 'badge-red' : s === 'warning' ? 'badge-yellow' : 'badge-blue';
  return `<span class="badge ${cls}">${s}</span>`;
}
function typeBadge(t) {
  const map = {
    mapping_change: 'badge-red',
    gateway_impersonation: 'badge-red',
    two_way_spoofing: 'badge-red',
    duplicate_mapping: 'badge-yellow',
    mac_spoofing: 'badge-purple',
    reply_rate_exceeded: 'badge-yellow',
    gratuitous_arp_flood: 'badge-yellow',
    baseline_violation: 'badge-blue',
  };
  return `<span class="badge ${map[t] || 'badge-dim'}">${t.replace(/_/g,' ')}</span>`;
}
function setPill(id, state) {
  const el = document.getElementById(id);
  el.className = 'pill ' + state;
}

// ── Fetch ────────────────────────────────────────────────────────────────────
async function fetchData() {
  try {
    const r = await fetch('/api/data');
    D = await r.json();
    render();
  } catch(e) { /* retry */ }
}

// ── Render ───────────────────────────────────────────────────────────────────
function render() {
  const stats  = D.stats || {};
  const det    = stats.detection || {};
  const cap    = stats.capture   || {};
  const mit    = stats.mitigation|| {};
  const alerts = D.alerts   || [];
  const attacks= D.attacks  || [];
  const mits   = D.mitigations || [];
  const pkts   = D.recent_packets || [];
  const binds  = D.bindings || {};

  // Pills
  setPill('pill-capture',    cap.running  ? 'on' : 'off');
  setPill('pill-detection',  det.baseline_complete ? 'on' : 'warn');
  setPill('pill-mitigation', mit.enabled  ? 'on' : 'warn');

  // Overview tiles
  el('t-packets').textContent    = det.packets_processed || 0;
  el('t-alerts').textContent     = det.alerts_generated  || 0;
  el('t-bindings').textContent   = det.bindings_learned  || 0;
  el('t-attacks').textContent    = attacks.length;
  el('t-mitigations').textContent= mits.length;
  el('t-mitm').textContent       = det.mitm_signatures   || 0;

  // Nav badges
  el('nb-alerts').textContent     = alerts.length;
  el('nb-attacks').textContent    = attacks.length;
  el('nb-mitigations').textContent= mits.length;

  // Overview det stats
  const byType = det.alerts_by_type || {};
  el('ov-det-stats').innerHTML = statLines([
    ['Packets processed',  det.packets_processed || 0,  'blue'],
    ['Alerts generated',   det.alerts_generated  || 0,  'yellow'],
    ['Bindings learned',   det.bindings_learned  || 0,  'green'],
    ['Header anomalies',   det.header_inconsistencies || 0, det.header_inconsistencies ? 'red' : ''],
    ['MITM signatures',    det.mitm_signatures   || 0,  det.mitm_signatures ? 'red' : ''],
    ['Baseline',           det.baseline_complete ? 'complete' : 'learning', det.baseline_complete ? 'green' : 'yellow'],
  ]);

  // Recent alerts (overview — 5 items)
  renderAlerts('ov-alerts', alerts.slice(0,5));

  // Full alerts
  renderAlerts('full-alerts', alerts);

  // Bindings table
  renderBindings(binds);

  // Topology
  renderTopology(binds, attacks);

  // Packet feed
  renderPacketFeed(pkts);

  // Attacks
  renderAttackList(attacks);

  // Mitigation
  el('mit-stats').innerHTML = statLines([
    ['Enabled',         mit.enabled   ? 'yes' : 'no',  mit.enabled ? 'green' : 'yellow'],
    ['Dry-run',         mit.dry_run   ? 'yes' : 'no',  ''],
    ['Firewall backend',mit.firewall_backend || '—',   'blue'],
    ['Active blocks',   mit.active_blocks || 0,         mit.active_blocks ? 'red' : ''],
    ['Corrective ARPs', mit.corrective_arp_sent || 0,  'green'],
    ['FW blocks added', mit.firewall_blocks_added || 0,''],
    ['Failed actions',  mit.actions_failed || 0,       mit.actions_failed ? 'red' : ''],
    ['Dry-run actions', mit.dry_run_actions || 0,      'blue'],
  ]);
  renderMitigationList(mits);

  // Metrics
  renderMetrics(det, alerts, attacks);

  // Timeline chart
  updateChart(D.alert_history || []);
}

function el(id) { return document.getElementById(id); }

function statLines(rows) {
  return rows.map(([k, v, cls]) =>
    `<div class="stat-line">
      <span class="stat-k">${k}</span>
      <span class="stat-v ${cls || ''}">${v}</span>
    </div>`
  ).join('');
}

// ── Alerts ───────────────────────────────────────────────────────────────────
function renderAlerts(containerId, alerts) {
  const c = el(containerId);
  if (!alerts.length) { c.innerHTML = '<div class="empty">No alerts yet</div>'; return; }
  c.innerHTML = alerts.map(a => `
    <div class="alert-row ${severityClass(a.severity)}">
      <div class="alert-meta">
        <div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap">
          ${typeBadge(a.alert_type)} ${severityBadge(a.severity)}
          <span class="alert-ts">${fmt.time(a.timestamp)} · ${fmt.ago(a.timestamp)}</span>
        </div>
        <div class="alert-msg">${escHtml(a.message)}</div>
        <div style="display:flex;gap:8px;margin-top:2px">
          <span class="muted mono">${a.sender_ip}</span>
          <span class="muted mono">${a.sender_mac}</span>
          ${a.previous_mac ? `<span class="muted">prev: <span class="mono">${a.previous_mac}</span></span>` : ''}
        </div>
      </div>
    </div>`).join('');
}

// ── Bindings ──────────────────────────────────────────────────────────────────
function renderBindings(bindings) {
  const tbody = el('bindings-body');
  const entries = Object.entries(bindings);
  if (!entries.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty">Waiting for ARP traffic…</td></tr>';
    return;
  }
  tbody.innerHTML = entries.map(([ip, b]) => {
    const role = b.is_gateway
      ? '<span class="badge badge-teal">Gateway</span>'
      : b.is_static
      ? '<span class="badge badge-purple">Static</span>'
      : '<span class="badge badge-dim">Learned</span>';
    return `<tr>
      <td class="mono">${ip}</td>
      <td class="mono">${b.mac}</td>
      <td>${role}</td>
      <td class="mono muted">${fmt.time(b.first_seen)}</td>
      <td class="mono muted">${fmt.time(b.last_seen)}</td>
      <td class="mono">${b.seen_count}</td>
    </tr>`;
  }).join('');
}

// ── Topology SVG ──────────────────────────────────────────────────────────────
let lastTopoHash = '';
function renderTopology(bindings, attacks) {
  const hash = JSON.stringify({b: Object.keys(bindings), a: attacks.length});
  if (hash === lastTopoHash) return;
  lastTopoHash = hash;

  const svg = el('topology-svg');
  const W = svg.clientWidth || 600;
  const H = 280;
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);

  const nodes = Object.entries(bindings).map(([ip, b]) => ({ ip, mac: b.mac, gw: b.is_gateway }));
  if (!nodes.length) {
    svg.innerHTML = '<text x="50%" y="50%" text-anchor="middle" fill="#333a55" font-size="13">Waiting for ARP traffic…</text>';
    return;
  }

  // Attacker MACs — those that triggered attacks
  const attackerMacs = new Set((attacks || []).map(a => a.attacker_mac).filter(Boolean));

  // Position: gateway in centre-top, others in semicircle
  const cx = W / 2, cy = H / 2;
  const r  = Math.min(W, H) * 0.35;
  const gwNode = nodes.find(n => n.gw) || nodes[0];
  gwNode.x = cx; gwNode.y = H * 0.25;

  const others = nodes.filter(n => n !== gwNode);
  others.forEach((n, i) => {
    const angle = Math.PI * (i + 1) / (others.length + 1);
    n.x = cx + r * Math.cos(Math.PI - angle);
    n.y = H * 0.55 + r * 0.4 * Math.sin(angle);
  });

  let lines = '';
  others.forEach(n => {
    const isAttacker = attackerMacs.has(n.mac);
    const stroke = isAttacker ? 'rgba(255,79,107,.5)' : 'rgba(79,143,255,.2)';
    const dash   = isAttacker ? 'stroke-dasharray="4 3"' : '';
    lines += `<line x1="${gwNode.x}" y1="${gwNode.y}" x2="${n.x}" y2="${n.y}" stroke="${stroke}" stroke-width="${isAttacker ? 1.5 : 1}" ${dash}/>`;
  });

  const nodeHtml = nodes.map(n => {
    const isAttacker = attackerMacs.has(n.mac);
    const fill   = n.gw ? '#4f8fff' : isAttacker ? '#ff4f6b' : '#3dffa0';
    const glow   = n.gw ? '#4f8fff' : isAttacker ? '#ff4f6b' : '#3dffa0';
    const label  = n.gw ? 'Gateway' : isAttacker ? 'Attacker' : 'Host';
    const rNode  = n.gw ? 18 : 14;
    return `
      <circle cx="${n.x}" cy="${n.y}" r="${rNode+4}" fill="${glow}" opacity=".12"/>
      <circle cx="${n.x}" cy="${n.y}" r="${rNode}" fill="${fill}" opacity=".85"/>
      <text x="${n.x}" y="${n.y + 4}" text-anchor="middle" fill="#0c0e14" font-size="9" font-weight="600">${label}</text>
      <text x="${n.x}" y="${n.y + rNode + 14}" text-anchor="middle" fill="#d4d8f0" font-size="10" font-family="JetBrains Mono,monospace">${n.ip}</text>
      <text x="${n.x}" y="${n.y + rNode + 26}" text-anchor="middle" fill="#5a6180" font-size="9" font-family="JetBrains Mono,monospace">${n.mac}</text>`;
  }).join('');

  svg.innerHTML = lines + nodeHtml;
}

// ── Packet Feed ───────────────────────────────────────────────────────────────
function renderPacketFeed(pkts) {
  const c = el('packet-feed');
  if (!pkts.length) { c.innerHTML = '<div class="empty">No packets yet…</div>'; return; }
  c.innerHTML = [...pkts].reverse().map(p => `
    <div class="pkt">
      <span class="pkt-ts">${fmt.shortTs(p.ts)}</span>
      <span class="pkt-op ${p.op}">${p.op}</span>
      <span class="pkt-ip">${p.sender_ip}</span>
      <span class="pkt-mac">${p.sender_mac}</span>
      <span class="pkt-ip muted">${p.target_ip}${p.gratuitous ? ' <span style="color:var(--purple)">[GRAT]</span>' : ''}</span>
    </div>`).join('');
}

// ── Attack List ───────────────────────────────────────────────────────────────
function renderAttackList(attacks) {
  const c = el('attack-list');
  if (!attacks.length) { c.innerHTML = '<div class="empty">No attack events recorded</div>'; return; }
  c.innerHTML = attacks.map(a => `
    <div class="alert-row warn">
      <div class="alert-meta">
        <div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap">
          <span class="badge badge-red">${(a.attack_type||'unknown').replace(/_/g,' ')}</span>
          <span class="badge badge-dim">${a.event_id || ''}</span>
          <span class="alert-ts">${fmt.time(a.timestamp)} · ${fmt.ago(a.timestamp)}</span>
        </div>
        <div class="alert-msg">${escHtml(a.description || '')}</div>
        <div style="display:flex;gap:8px;margin-top:3px">
          <span class="muted">attacker: <span class="mono">${a.attacker_mac}</span></span>
          <span class="muted">target: <span class="mono">${a.target_ip}</span></span>
        </div>
      </div>
    </div>`).join('');
}

// ── Mitigation List ───────────────────────────────────────────────────────────
function renderMitigationList(mits) {
  const c = el('mit-list');
  if (!mits.length) { c.innerHTML = '<div class="empty">No actions taken</div>'; return; }
  c.innerHTML = mits.map(m => `
    <div class="alert-row info">
      <div class="alert-meta">
        <div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap">
          <span class="badge badge-teal">${(m.action_type||'').replace(/_/g,' ')}</span>
          ${m.dry_run ? '<span class="badge badge-dim">DRY-RUN</span>' : ''}
          <span class="alert-ts">${fmt.time(m.timestamp)}</span>
        </div>
        <div class="alert-msg">${escHtml(m.details || '')}</div>
      </div>
    </div>`).join('');
}

// ── Metrics ───────────────────────────────────────────────────────────────────
function renderMetrics(det, alerts, attacks) {
  const n = det.alerts_generated || 0;
  const byType = det.alerts_by_type || {};

  // Naive estimates from available data
  const tp = alerts.filter(a => a.severity === 'critical').length;
  const fp = alerts.filter(a => a.severity !== 'critical').length;
  const fn = Math.max(0, attacks.length - tp);
  const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
  const recall    = tp + fn > 0 ? tp / (tp + fn) : 0;
  const f1        = precision + recall > 0 ? 2 * precision * recall / (precision + recall) : 0;

  const bars = [
    ['Precision',  precision, precision > .6 ? 'green' : precision > .3 ? 'yellow' : 'red'],
    ['Recall',     recall,    recall > .6 ? 'green' : recall > .3 ? 'yellow' : 'red'],
    ['F1 Score',   f1,        f1 > .6 ? 'green' : f1 > .3 ? 'yellow' : 'red'],
    ['Alert rate', Math.min(1, n / Math.max(1, (det.packets_processed || 1))), 'blue'],
  ];

  el('perf-bars').innerHTML = bars.map(([name, val, cls]) => `
    <div class="metric-row">
      <div class="metric-head">
        <span class="metric-name">${name}</span>
        <span class="metric-val">${fmt.pct(val)}</span>
      </div>
      <div class="bar-track"><div class="bar-fill ${cls}" style="width:${(val*100).toFixed(1)}%"></div></div>
    </div>`).join('');

  // Type breakdown
  const types = Object.entries(byType).sort((a,b) => b[1]-a[1]);
  el('type-breakdown').innerHTML = types.length
    ? types.map(([k,v]) => `
        <div class="stat-line">
          ${typeBadge(k)}
          <span class="stat-v blue">${v}</span>
        </div>`).join('')
    : '<div class="empty">No data</div>';

  // Confusion matrix
  el('confusion-matrix').innerHTML = [
    ['TP', tp, 'green'],
    ['FP', fp, 'yellow'],
    ['FN', fn, 'red'],
    ['TN', '—', ''],
  ].map(([label, val, cls]) => `
    <div class="tile ${cls}" style="text-align:center">
      <div class="tile-label">${label}</div>
      <div class="tile-value" style="font-size:20px">${val}</div>
    </div>`).join('');
}

// ── Timeline Chart ─────────────────────────────────────────────────────────────
let chartDrawn = false;
function updateChart(history) {
  const canvas = el('timeline-chart');
  if (!canvas) return;

  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.parentElement.getBoundingClientRect();
  if (rect.width === 0) return;

  canvas.width  = rect.width  * dpr;
  canvas.height = rect.height * dpr;
  canvas.style.width  = rect.width  + 'px';
  canvas.style.height = rect.height + 'px';

  const ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);

  const W = rect.width, H = rect.height;
  const pad = { top: 12, right: 12, bottom: 28, left: 36 };
  const iW = W - pad.left - pad.right;
  const iH = H - pad.top  - pad.bottom;

  ctx.clearRect(0, 0, W, H);

  const now = Date.now() / 1000;
  const buckets = 30;
  const bucketSize = 10;
  const data = new Array(buckets).fill(0);

  (history || []).forEach(a => {
    const idx = Math.floor((a.timestamp - (now - buckets * bucketSize)) / bucketSize);
    if (idx >= 0 && idx < buckets) data[idx]++;
  });

  const maxVal = Math.max(...data, 1);

  // Grid lines
  ctx.strokeStyle = 'rgba(100,120,200,.08)';
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = pad.top + iH - (i / 4) * iH;
    ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(pad.left + iW, y); ctx.stroke();
    ctx.fillStyle = '#333a55'; ctx.font = '9px ' + getComputedStyle(document.body).fontFamily;
    ctx.textAlign = 'right';
    ctx.fillText(Math.round((i/4)*maxVal), pad.left - 4, y + 3);
  }

  // Area fill
  const grad = ctx.createLinearGradient(0, pad.top, 0, pad.top + iH);
  grad.addColorStop(0, 'rgba(79,143,255,.25)');
  grad.addColorStop(1, 'rgba(79,143,255,.0)');

  ctx.beginPath();
  data.forEach((val, i) => {
    const x = pad.left + (i / (buckets - 1)) * iW;
    const y = pad.top  + iH - (val / maxVal) * iH;
    if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  });
  ctx.lineTo(pad.left + iW, pad.top + iH);
  ctx.lineTo(pad.left, pad.top + iH);
  ctx.closePath();
  ctx.fillStyle = grad;
  ctx.fill();

  // Line
  ctx.beginPath();
  ctx.strokeStyle = '#4f8fff';
  ctx.lineWidth = 1.5;
  ctx.lineJoin = 'round';
  data.forEach((val, i) => {
    const x = pad.left + (i / (buckets - 1)) * iW;
    const y = pad.top  + iH - (val / maxVal) * iH;
    if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  });
  ctx.stroke();

  // Dots on non-zero
  data.forEach((val, i) => {
    if (val === 0) return;
    const x = pad.left + (i / (buckets - 1)) * iW;
    const y = pad.top  + iH - (val / maxVal) * iH;
    ctx.beginPath();
    ctx.arc(x, y, 3, 0, Math.PI * 2);
    ctx.fillStyle = '#4f8fff';
    ctx.fill();
  });

  // X-axis labels (every 5 buckets)
  ctx.fillStyle = '#333a55'; ctx.textAlign = 'center';
  for (let i = 0; i < buckets; i += 5) {
    const bucketStart = now - (buckets - i) * bucketSize;
    const label = new Date(bucketStart * 1000).toLocaleTimeString([], {minute:'2-digit',second:'2-digit'});
    const x = pad.left + (i / (buckets - 1)) * iW;
    ctx.fillText(label, x, H - 4);
  }
}

// ── Escape HTML ───────────────────────────────────────────────────────────────
function escHtml(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;');
}

// ── Init ──────────────────────────────────────────────────────────────────────
fetchData();
setInterval(fetchData, 1000);
</script>
</body>
</html>"""


def create_dashboard(config: Optional[VisualizationConfig] = None) -> WebDashboard:
    """Factory function to create web dashboard."""
    return WebDashboard(config)
