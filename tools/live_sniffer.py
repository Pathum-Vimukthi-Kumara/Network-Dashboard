import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, List, Optional, Tuple

try:
    from scapy.all import sniff, TCP, UDP, ICMP, IP, get_if_list, get_if_addr, Raw  # type: ignore
    try:
        # Windows-only; provides rich interface details
        from scapy.arch.windows import get_windows_if_list  # type: ignore
    except Exception:  # pragma: no cover
        get_windows_if_list = None  # type: ignore
except Exception:
    sniff = None  # type: ignore
    TCP = None  # type: ignore
    UDP = None  # type: ignore
    ICMP = None  # type: ignore
    IP = None  # type: ignore
    Raw = None  # type: ignore
    get_if_list = None  # type: ignore
    get_if_addr = None  # type: ignore
    get_windows_if_list = None  # type: ignore

try:
    from .http_flood_detector import HttpFloodDetector
except ImportError:
    try:
        from http_flood_detector import HttpFloodDetector
    except ImportError:
        HttpFloodDetector = None


def is_ack_only(pkt) -> bool:
    if TCP is None or IP is None:
        return False
    if pkt is None or TCP not in pkt or IP not in pkt:
        return False
    flags = pkt[TCP].flags
    return bool((flags & 0x10) and not (flags & 0x02 or flags & 0x01 or flags & 0x04))


@dataclass
class LiveSnapshot:
    started_at: float
    total_packets: int
    ack_only_packets: int
    per_sec: List[Tuple[int, int]]
    top_src: List[Tuple[str, int]]
    top_tcp_dport: List[Tuple[int, int]]
    top_udp_dport: List[Tuple[int, int]]
    per_proto: Dict[str, int]
    alerts: List[Dict]


class LiveAckSniffer:
    """Live sniffer for TCP/UDP/ICMP with comprehensive DDoS detection."""

    def __init__(self, iface: Optional[str], window_s: int = 10, threshold: int = 200, 
                 syn_threshold: int = 400, udp_threshold: int = 500, icmp_threshold: int = 200,
                 http_threshold: int = 50) -> None:
        if sniff is None:
            raise RuntimeError("Scapy not available for live capture. Install scapy and Npcap (Windows).")
        self.iface = iface
        self.window_s = int(window_s)
        self.threshold = int(threshold)
        self.syn_threshold = int(syn_threshold)
        self.udp_threshold = int(udp_threshold)
        self.icmp_threshold = int(icmp_threshold)
        self.http_threshold = int(http_threshold)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

        # state
        self.started_at = time.time()
        self.total_packets = 0
        self.ack_only_packets = 0
        self.per_src_window: Dict[str, Deque[float]] = defaultdict(deque)
        self.per_sec_total: Dict[int, int] = defaultdict(int)
        self.per_tcp_dport_total: Dict[int, int] = defaultdict(int)
        self.per_udp_dport_total: Dict[int, int] = defaultdict(int)
        self.alerted_at: Dict[str, float] = {}
        self.alerts: List[Dict] = []
        self.per_proto: Dict[str, int] = defaultdict(int)
        
        # DDoS detection windows (per destination)
        self.syn_windows: Dict[str, Deque[float]] = defaultdict(deque)
        self.udp_windows: Dict[str, Deque[float]] = defaultdict(deque)
        self.icmp_windows: Dict[str, Deque[float]] = defaultdict(deque)
        self.syn_alerted_at: Dict[str, float] = {}
        self.udp_alerted_at: Dict[str, float] = {}
        self.icmp_alerted_at: Dict[str, float] = {}
        
        # HTTP flood detector
        self.http_detector = HttpFloodDetector(window_s, http_threshold) if HttpFloodDetector else None
        self.http_alerts: List[Dict] = []

    @staticmethod
    def list_interfaces() -> List[str]:
        if get_if_list is None:
            return []
        return list(get_if_list())

    @staticmethod
    def list_interfaces_detailed() -> List[Dict[str, str]]:
        """Return a list of interfaces with friendly labels and IPs.

        Each item: {
            'name': scapy_device_name,
            'desc': description_or_name,
            'ipv4': comma_separated_ipv4s,
            'ipv6': comma_separated_ipv6s,
            'mac': mac_or_empty,
            'label': f"{desc} — {ipv4s} [{name}]"
        }
        """
        items: List[Dict[str, str]] = []
        try:
            if get_windows_if_list is not None:
                # Windows-rich info
                for it in get_windows_if_list():  # type: ignore
                    name = it.get("name") or ""
                    desc = it.get("description") or name
                    ips = it.get("ips") or []
                    ipv4s = [ip for ip in ips if "." in str(ip)]
                    ipv6s = [ip for ip in ips if ":" in str(ip)]
                    mac = it.get("mac") or ""
                    ipv4 = ", ".join(map(str, ipv4s))
                    ipv6 = ", ".join(map(str, ipv6s))
                    label = f"{desc} — {ipv4 or 'no IPv4'} [{name}]"
                    items.append({
                        "name": name,
                        "desc": desc,
                        "ipv4": ipv4,
                        "ipv6": ipv6,
                        "mac": mac,
                        "label": label,
                    })
            elif get_if_list is not None:
                # Cross-platform fallback with minimal info
                for name in get_if_list():  # type: ignore
                    try:
                        ipv4_addr = get_if_addr(name) if get_if_addr is not None else ""
                    except Exception:
                        ipv4_addr = ""
                    desc = name
                    label = f"{desc} — {ipv4_addr or 'no IPv4'}"
                    items.append({
                        "name": name,
                        "desc": desc,
                        "ipv4": ipv4_addr,
                        "ipv6": "",
                        "mac": "",
                        "label": label,
                    })
        except Exception:
            # On any failure, fallback to simple names
            if get_if_list is not None:
                for name in get_if_list():  # type: ignore
                    items.append({
                        "name": name,
                        "desc": name,
                        "ipv4": "",
                        "ipv6": "",
                        "mac": "",
                        "label": name,
                    })
        return items

    def _handler(self, pkt):
        self.total_packets += 1
        if IP not in pkt:
            return

        ts = float(pkt.time)
        ts_sec = int(ts)
        src = pkt[IP].src
        dst = pkt[IP].dst

        self.per_sec_total[ts_sec] += 1

        # Protocol accounting and DDoS detection
        if TCP in pkt:
            self.per_proto["TCP"] += 1
            dport = int(pkt[TCP].dport)
            self.per_tcp_dport_total[dport] += 1
            flags = pkt[TCP].flags
            
            # Simple HTTP detection for any TCP traffic
            if self.http_detector:
                if self.http_detector.process_http_packet(src, dst, dport, ts):
                    self.alerts.append({
                        "src": src, "target": dst, "ts": ts,
                        "count": len(self.http_detector.http_windows[src]),
                        "window_s": self.window_s, "kind": "http_flood"
                    })
            
            # ACK-only flood detection (per source)
            if is_ack_only(pkt):
                self.ack_only_packets += 1
                dq = self.per_src_window[src]
                dq.append(ts)
                cutoff = ts - self.window_s
                while dq and dq[0] < cutoff:
                    dq.popleft()
                count = len(dq)
                last_alert = self.alerted_at.get(src, 0.0)
                if count > self.threshold and (ts - last_alert) >= self.window_s:
                    self.alerts.append({
                        "src": src, "dst": dst, "ts": ts, "count": count, 
                        "window_s": self.window_s, "kind": "ack_flood"
                    })
                    self.alerted_at[src] = ts
            
            # SYN flood detection (per destination): SYN set, ACK not set
            elif (flags & 0x02) and not (flags & 0x10):
                dq = self.syn_windows[dst]
                dq.append(ts)
                cutoff = ts - self.window_s
                while dq and dq[0] < cutoff:
                    dq.popleft()
                count = len(dq)
                last_alert = self.syn_alerted_at.get(dst, 0.0)
                if count > self.syn_threshold and (ts - last_alert) >= self.window_s:
                    self.alerts.append({
                        "target": dst, "ts": ts, "count": count,
                        "window_s": self.window_s, "kind": "syn_flood"
                    })
                    self.syn_alerted_at[dst] = ts
            
            # HTTP flood detection (check for HTTP traffic on common ports)
            if self.http_detector and dport in [80, 443, 8080, 3000, 9999]:
                if Raw in pkt:
                    payload = bytes(pkt[Raw])
                    if b'GET ' in payload or b'POST ' in payload or b'HTTP/' in payload:
                        if self.http_detector.process_http_packet(src, dst, dport, ts):
                            # Add HTTP flood alert to main alerts
                            self.alerts.append({
                                "src": src, "target": dst, "ts": ts, 
                                "count": len(self.http_detector.http_windows[src]),
                                "window_s": self.window_s, "kind": "http_flood"
                            })
                    
        elif UDP in pkt:
            self.per_proto["UDP"] += 1
            dport = int(pkt[UDP].dport)
            self.per_udp_dport_total[dport] += 1
            
            # UDP flood detection (per destination)
            dq = self.udp_windows[dst]
            dq.append(ts)
            cutoff = ts - self.window_s
            while dq and dq[0] < cutoff:
                dq.popleft()
            count = len(dq)
            last_alert = self.udp_alerted_at.get(dst, 0.0)
            if count > self.udp_threshold and (ts - last_alert) >= self.window_s:
                self.alerts.append({
                    "target": dst, "ts": ts, "count": count,
                    "window_s": self.window_s, "kind": "udp_flood"
                })
                self.udp_alerted_at[dst] = ts
                
        elif ICMP in pkt:
            self.per_proto["ICMP"] += 1
            
            # ICMP flood detection (per destination) - only for echo requests (type 8)
            if pkt[ICMP].type == 8:
                dq = self.icmp_windows[dst]
                dq.append(ts)
                cutoff = ts - self.window_s
                while dq and dq[0] < cutoff:
                    dq.popleft()
                count = len(dq)
                last_alert = self.icmp_alerted_at.get(dst, 0.0)
                if count > self.icmp_threshold and (ts - last_alert) >= self.window_s:
                    self.alerts.append({
                        "target": dst, "ts": ts, "count": count,
                        "window_s": self.window_s, "kind": "icmp_flood"
                    })
                    self.icmp_alerted_at[dst] = ts
        else:
            self.per_proto["OTHER"] += 1

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self.started_at = time.time()

        def run():
            # BPF filter to capture main L3/L4 without overwhelming
            if sniff is None:
                return
            try:
                sniff(
                    iface=self.iface,
                    prn=self._handler,
                    store=False,
                    filter="tcp or udp or icmp",
                    stop_filter=lambda _: self._stop.is_set(),
                )
            except Exception:
                # Allow thread to exit quietly; error will be surfaced on snapshot if needed
                pass

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def snapshot(self) -> LiveSnapshot:
        top_src = sorted(
            ((src, len(dq)) for src, dq in self.per_src_window.items()), key=lambda kv: kv[1], reverse=True
        )
        top_tcp = sorted(self.per_tcp_dport_total.items(), key=lambda kv: kv[1], reverse=True)
        top_udp = sorted(self.per_udp_dport_total.items(), key=lambda kv: kv[1], reverse=True)
        per_sec_series = sorted(self.per_sec_total.items(), key=lambda kv: kv[0])
        return LiveSnapshot(
            started_at=self.started_at,
            total_packets=self.total_packets,
            ack_only_packets=self.ack_only_packets,
            per_sec=per_sec_series,
            top_src=top_src,
            top_tcp_dport=top_tcp,
            top_udp_dport=top_udp,
            per_proto=dict(self.per_proto),
            alerts=list(self.alerts),
        )
