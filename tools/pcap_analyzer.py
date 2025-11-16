from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, List, Optional, Tuple

try:
    from scapy.all import PcapReader, TCP, UDP, ICMP, IP  # type: ignore
except Exception:
    PcapReader = None  # type: ignore
    TCP = None  # type: ignore
    UDP = None  # type: ignore
    ICMP = None  # type: ignore
    IP = None  # type: ignore


def _tcp_flags_to_str(flags: int) -> str:
    # FIN 0x01, SYN 0x02, RST 0x04, PSH 0x08, ACK 0x10, URG 0x20, ECE 0x40, CWR 0x80
    mapping = (
        (0x02, "S"),
        (0x10, "A"),
        (0x01, "F"),
        (0x04, "R"),
        (0x08, "P"),
        (0x20, "U"),
        (0x40, "E"),
        (0x80, "C"),
    )
    out = "".join(ch for bit, ch in mapping if flags & bit)
    return out or "-"


@dataclass
class FullAlert:
    kind: str
    ts: float
    target: str
    count: int
    window_s: int


class PcapFullAnalyzer:
    def __init__(self, syn_threshold: int = 400, udp_threshold: int = 500, icmp_threshold: int = 200, window_s: int = 10):
        self.window_s = int(window_s)
        self.syn_threshold = int(syn_threshold)
        self.udp_threshold = int(udp_threshold)
        self.icmp_threshold = int(icmp_threshold)

    def analyze(self, pcap_path: str, max_rows: int = 50000) -> Dict:
        if PcapReader is None:
            raise RuntimeError("Scapy not available. Install with: pip install scapy")

        reader = PcapReader(pcap_path)
        total = 0
        per_sec: Dict[int, int] = defaultdict(int)
        per_proto: Dict[str, int] = defaultdict(int)
        top_src: Dict[str, int] = defaultdict(int)
        top_dst: Dict[str, int] = defaultdict(int)
        tcp_dports: Dict[int, int] = defaultdict(int)
        udp_dports: Dict[int, int] = defaultdict(int)

        # Flood state (per destination)
        syn_win: Dict[str, Deque[float]] = defaultdict(deque)
        udp_win: Dict[str, Deque[float]] = defaultdict(deque)
        icmp_win: Dict[str, Deque[float]] = defaultdict(deque)
        last_alert_syn: Dict[str, float] = {}
        last_alert_udp: Dict[str, float] = {}
        last_alert_icmp: Dict[str, float] = {}
        alerts: List[FullAlert] = []

        # Packet table rows (limited)
        rows: List[Dict] = []

        try:
            for pkt in reader:
                total += 1
                ts = float(getattr(pkt, 'time', 0.0))
                ts_sec = int(ts)
                per_sec[ts_sec] += 1

                if IP in pkt:
                    src = pkt[IP].src
                    dst = pkt[IP].dst
                else:
                    # skip non-IP traffic in this simple analyzer
                    continue

                top_src[src] += 1
                top_dst[dst] += 1

                proto = "OTHER"
                sport = None
                dport = None
                flags_str = ""
                length = int(len(pkt))

                if TCP in pkt:
                    proto = "TCP"
                    sport = int(pkt[TCP].sport)
                    dport = int(pkt[TCP].dport)
                    flags_val = int(pkt[TCP].flags)
                    flags_str = _tcp_flags_to_str(flags_val)
                    tcp_dports[dport] += 1
                    # SYN flood detection (per destination): SYN set, ACK not set
                    if (flags_val & 0x02) and not (flags_val & 0x10):
                        dq = syn_win[dst]
                        dq.append(ts)
                        cutoff = ts - self.window_s
                        while dq and dq[0] < cutoff:
                            dq.popleft()
                        if len(dq) > self.syn_threshold and ts - last_alert_syn.get(dst, 0.0) >= self.window_s:
                            alerts.append(FullAlert("syn_flood", ts, dst, len(dq), self.window_s))
                            last_alert_syn[dst] = ts

                elif UDP in pkt:
                    proto = "UDP"
                    sport = int(pkt[UDP].sport)
                    dport = int(pkt[UDP].dport)
                    udp_dports[dport] += 1
                    dq = udp_win[dst]
                    dq.append(ts)
                    cutoff = ts - self.window_s
                    while dq and dq[0] < cutoff:
                        dq.popleft()
                    if len(dq) > self.udp_threshold and ts - last_alert_udp.get(dst, 0.0) >= self.window_s:
                        alerts.append(FullAlert("udp_flood", ts, dst, len(dq), self.window_s))
                        last_alert_udp[dst] = ts

                elif ICMP in pkt:
                    proto = "ICMP"
                    icmp_type = int(pkt[ICMP].type)
                    # ICMP echo request is type 8
                    if icmp_type == 8:
                        dq = icmp_win[dst]
                        dq.append(ts)
                        cutoff = ts - self.window_s
                        while dq and dq[0] < cutoff:
                            dq.popleft()
                        if len(dq) > self.icmp_threshold and ts - last_alert_icmp.get(dst, 0.0) >= self.window_s:
                            alerts.append(FullAlert("icmp_flood", ts, dst, len(dq), self.window_s))
                            last_alert_icmp[dst] = ts

                per_proto[proto] += 1

                if len(rows) < max_rows:
                    rows.append(
                        {
                            "ts": ts,
                            "src": src,
                            "dst": dst,
                            "proto": proto,
                            "sport": sport,
                            "dport": dport,
                            "flags": flags_str,
                            "len": length,
                        }
                    )
        finally:
            reader.close()

        return {
            "total_packets": total,
            "per_sec": sorted(per_sec.items(), key=lambda kv: kv[0]),
            "per_proto": dict(per_proto),
            "top_src": sorted(top_src.items(), key=lambda kv: kv[1], reverse=True),
            "top_dst": sorted(top_dst.items(), key=lambda kv: kv[1], reverse=True),
            "top_tcp_dport": sorted(tcp_dports.items(), key=lambda kv: kv[1], reverse=True),
            "top_udp_dport": sorted(udp_dports.items(), key=lambda kv: kv[1], reverse=True),
            "packets": rows,
            "alerts": [a.__dict__ for a in alerts],
            "window_s": self.window_s,
            "thresholds": {
                "syn": self.syn_threshold,
                "udp": self.udp_threshold,
                "icmp": self.icmp_threshold,
            },
        }


__all__ = ["PcapFullAnalyzer"]
