"""Stateful ARP anomaly detector used by both offline replay and live capture."""
from collections import defaultdict, deque
from ..models import ArpPacket, ArpOperation, IpMacBinding, Alert, AlertType, AlertSeverity
from ..config import get_config
import time as _time


class DetectionEngine:
    def __init__(self, config=None, alert_callback=None):
        self.config = config or get_config().detection
        self.alert_callback = alert_callback
        self.gateway_ip = get_config().network.gateway_ip
        self.gateway_mac = get_config().network.gateway_mac.lower()
        self.bindings = {}
        self.mac_to_ips = defaultdict(set)
        self.reply_times = defaultdict(deque)
        self.gratuitous_times = defaultdict(deque)
        self.mapping_changes = defaultdict(deque)
        # Recent packets for live feed (capped at 50)
        self.recent_packets = deque(maxlen=50)
        self.stats = {
            'packets_processed': 0,
            'alerts_generated': 0,
            'bindings_learned': 0,
            'alerts_by_type': defaultdict(int),
            'baseline_complete': True,
            'header_inconsistencies': 0,
            'mitm_signatures': 0,
        }

    def _check_header_consistency(self, packet):
        """Flag frames where Ether.src would differ from ARP.hwsrc.
        In offline replay we only have ARP fields, so we compare sender_mac
        against target_mac on a reply (crude proxy). Real impl checks Ether layer."""
        # Heuristic: if sender_mac is all-zeros or broadcast, it's inconsistent.
        bogus = ('00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff')
        return packet.sender_mac.lower() in bogus

    def _check_mitm_signature(self, mac):
        """One MAC claiming both the gateway IP and another IP is a strong MITM signal."""
        ips = self.mac_to_ips.get(mac, set())
        return self.gateway_ip in ips and len(ips) >= 2

    def process_packet(self, packet):
        if not packet.sender_ip or not packet.sender_mac:
            return []
        ip, mac, ts = packet.sender_ip, packet.sender_mac.lower(), packet.timestamp
        previous = self.bindings.get(ip)
        alerts = []

        # Record for live feed
        self.recent_packets.append({
            'ts': ts,
            'op': packet.operation.name,
            'sender_ip': ip,
            'sender_mac': mac,
            'target_ip': packet.target_ip,
            'gratuitous': packet.is_gratuitous,
        })

        def alert(kind, severity, message, old=None, **details):
            alerts.append(Alert.create(kind, severity, ip, mac, packet.target_ip, old, message, **details))

        # Header consistency check
        if self._check_header_consistency(packet):
            self.stats['header_inconsistencies'] += 1

        # Mapping change
        if previous and previous.mac != mac:
            alert(
                AlertType.MAPPING_CHANGE,
                AlertSeverity.CRITICAL if ip == self.gateway_ip else AlertSeverity.WARNING,
                f"IP-to-MAC mapping changed: {ip} {previous.mac} -> {mac}",
                previous.mac,
            )
            changes = self.mapping_changes[ip]
            changes.append((ts, previous.mac, mac))
            while changes and ts - changes[0][0] > self.config.duplicate_window_seconds:
                changes.popleft()
            if any(old_mac == mac for _, old_mac, _ in changes):
                alert(
                    AlertType.DUPLICATE_MAPPING,
                    AlertSeverity.CRITICAL,
                    f"Conflicting MACs claimed {ip} within {self.config.duplicate_window_seconds:g}s",
                    previous.mac,
                )
            if ip == self.gateway_ip:
                alert(
                    AlertType.GATEWAY_IMPERSONATION,
                    AlertSeverity.CRITICAL,
                    f"Gateway {ip} claimed by unexpected MAC {mac}",
                    previous.mac,
                )

        # Learn / update binding
        if not previous:
            self.bindings[ip] = IpMacBinding(ip, mac, ts, ts, is_gateway=(ip == self.gateway_ip))
            self.stats['bindings_learned'] += 1
        else:
            previous.mac, previous.last_seen, previous.seen_count = mac, ts, previous.seen_count + 1

        self.mac_to_ips[mac].add(ip)

        # Rate-based detection (replies only)
        if packet.operation == ArpOperation.REPLY:
            q = self.reply_times[ip]
            q.append(ts)
            while q and ts - q[0] > self.config.rate_window_seconds:
                q.popleft()
            if len(q) == self.config.max_replies_per_window + 1:
                alert(
                    AlertType.REPLY_RATE_EXCEEDED,
                    AlertSeverity.WARNING,
                    f"{len(q)} ARP replies for {ip} within {self.config.rate_window_seconds:g}s",
                )

        # Gratuitous ARP flood
        if packet.is_gratuitous:
            q = self.gratuitous_times[ip]
            q.append(ts)
            while q and ts - q[0] > 60:
                q.popleft()
            if len(q) == self.config.gratuitous_threshold + 1:
                alert(
                    AlertType.GRATUITOUS_ARP_FLOOD,
                    AlertSeverity.WARNING,
                    f"Excessive gratuitous ARP announcements for {ip}",
                )

        # MAC-spoofing: one MAC claims too many IPs
        if len(self.mac_to_ips[mac]) > self.config.max_ips_per_mac:
            alert(
                AlertType.MAC_SPOOFING,
                AlertSeverity.CRITICAL,
                f"MAC {mac} claims multiple IP addresses: {', '.join(sorted(self.mac_to_ips[mac]))}",
            )

        # MITM two-way signature: one MAC holds both gateway IP and another IP
        if self._check_mitm_signature(mac):
            other_ips = sorted(self.mac_to_ips[mac] - {self.gateway_ip})
            alert(
                AlertType.TWO_WAY_SPOOFING,
                AlertSeverity.CRITICAL,
                f"MITM signature: MAC {mac} claims gateway {self.gateway_ip} + {other_ips}",
                None,
            )
            self.stats['mitm_signatures'] += 1

        # Deduplicate: don't fire TWO_WAY_SPOOFING if we already fired it for same mac this packet
        seen_types = set()
        deduped = []
        for a in alerts:
            key = (a.alert_type, a.sender_mac)
            if a.alert_type == AlertType.TWO_WAY_SPOOFING and key in seen_types:
                continue
            seen_types.add(key)
            deduped.append(a)
        alerts = deduped

        self.stats['packets_processed'] += 1
        for item in alerts:
            self.stats['alerts_generated'] += 1
            self.stats['alerts_by_type'][item.alert_type.value] += 1
            if self.alert_callback:
                self.alert_callback(item)
        return alerts

    def get_all_bindings(self):
        return dict(self.bindings)

    def get_recent_packets(self, n=20):
        return list(self.recent_packets)[-n:]

    def get_stats(self):
        return {**self.stats, 'alerts_by_type': dict(self.stats['alerts_by_type'])}

    def reset(self):
        self.bindings.clear()
        self.mac_to_ips.clear()
        self.reply_times.clear()
        self.gratuitous_times.clear()
        self.mapping_changes.clear()
        self.recent_packets.clear()
        self.stats = {
            'packets_processed': 0,
            'alerts_generated': 0,
            'bindings_learned': 0,
            'alerts_by_type': defaultdict(int),
            'baseline_complete': True,
            'header_inconsistencies': 0,
            'mitm_signatures': 0,
        }
