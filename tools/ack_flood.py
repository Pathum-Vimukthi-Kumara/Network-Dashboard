from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Callable, Deque, Dict, Iterable, List, Optional, Tuple

try:
    # scapy is free and widely used
    from scapy.all import PcapReader, TCP, IP  # type: ignore
except Exception as e:  # pragma: no cover
    PcapReader = None  # type: ignore
    TCP = None  # type: ignore
    IP = None  # type: ignore


@dataclass
class AlertEvent:
    src: str
    ts: float
    count: int
    window_s: int
    kind: str = "ack_flood"


def is_ack_only(pkt) -> bool:
    """Return True if packet is TCP ACK-only (ACK set, not SYN/FIN/RST)."""
    if TCP is None or IP is None:
        return False
    if pkt is None or TCP not in pkt or IP not in pkt:
        return False
    flags = pkt[TCP].flags
    # Flags bits: FIN 0x01, SYN 0x02, RST 0x04, PSH 0x08, ACK 0x10
    return bool((flags & 0x10) and not (flags & 0x02 or flags & 0x01 or flags & 0x04))


class AckFloodAnalyzer:
    """
    Analyze pcap files for potential ACK flood activity using a sliding time window.

    Contract:
    - Input: path to .pcap/.pcapng readable by Scapy
    - Parameters: window_s (int seconds), threshold (int ACK-only packets per window per source)
    - Output: dict with totals, per-second series, per-source counts, and alert events
    - Error modes: if scapy missing or file invalid, raises RuntimeError with message
    """

    def __init__(self, window_s: int = 10, threshold: int = 200) -> None:
        self.window_s = int(window_s)
        self.threshold = int(threshold)

    def analyze_pcap(
        self,
        pcap_path: str,
        max_packets: Optional[int] = None,
        progress_cb: Optional[Callable[[int], None]] = None,
    ) -> Dict:
        if PcapReader is None:
            raise RuntimeError(
                "Scapy not available. Install with: pip install scapy"
            )

        per_src: Dict[str, int] = defaultdict(int)
        per_sec_total: Dict[int, int] = defaultdict(int)
        state: Dict[str, Deque[float]] = defaultdict(deque)
        alerted_at: Dict[str, float] = {}
        alerts: List[AlertEvent] = []

        total = 0
        ack_only_total = 0

        reader = PcapReader(pcap_path)
        try:
            for pkt in reader:
                total += 1
                if TCP not in pkt or IP not in pkt:
                    if max_packets and total >= max_packets:
                        break
                    continue

                if not is_ack_only(pkt):
                    if max_packets and total >= max_packets:
                        break
                    continue

                ack_only_total += 1
                src = pkt[IP].src
                ts_float: float = float(pkt.time)
                ts_sec = int(ts_float)
                per_src[src] += 1
                per_sec_total[ts_sec] += 1

                dq = state[src]
                dq.append(ts_float)
                cutoff = ts_float - self.window_s
                while dq and dq[0] < cutoff:
                    dq.popleft()
                count = len(dq)
                # throttle: alert at most once per window per src
                last_alert = alerted_at.get(src, 0.0)
                if count > self.threshold and (ts_float - last_alert) >= self.window_s:
                    alerts.append(
                        AlertEvent(src=src, ts=ts_float, count=count, window_s=self.window_s)
                    )
                    alerted_at[src] = ts_float

                if progress_cb and (total % 5000 == 0):
                    progress_cb(total)

                if max_packets and total >= max_packets:
                    break
        finally:
            reader.close()

        # top talkers by ack-only packets
        top_src = sorted(per_src.items(), key=lambda kv: kv[1], reverse=True)
        # Normalize per-second series to a sorted list of tuples
        per_sec_series = sorted(per_sec_total.items(), key=lambda kv: kv[0])

        return {
            "total_packets": total,
            "ack_only_packets": ack_only_total,
            "unique_src": len(per_src),
            "top_src": top_src,  # List[Tuple[src, count]]
            "per_sec": per_sec_series,  # List[Tuple[int_second, count]]
            "alerts": [a.__dict__ for a in alerts],
            "window_s": self.window_s,
            "threshold": self.threshold,
        }


__all__ = ["AckFloodAnalyzer", "is_ack_only", "AlertEvent"]
