from collections import defaultdict, deque
import time
from typing import Dict, Deque, List

class HttpFloodDetector:
    """Detects HTTP flood attacks by monitoring HTTP request patterns."""
    
    def __init__(self, window_s: int = 10, threshold: int = 50):
        self.window_s = window_s
        self.threshold = threshold
        self.http_windows: Dict[str, Deque[float]] = defaultdict(deque)
        self.alerted_at: Dict[str, float] = {}
        self.alerts: List[Dict] = []
    
    def process_http_packet(self, src_ip: str, dst_ip: str, dst_port: int, ts: float) -> bool:
        """Process HTTP packet and return True if alert triggered."""
        # Detect HTTP floods on any port for demo purposes
        # if dst_port not in [80, 443, 8080, 3000, 9999]:  # Common HTTP ports
        #     return False
            
        # Track requests per source IP
        dq = self.http_windows[src_ip]
        dq.append(ts)
        
        # Clean old entries
        cutoff = ts - self.window_s
        while dq and dq[0] < cutoff:
            dq.popleft()
        
        count = len(dq)
        last_alert = self.alerted_at.get(src_ip, 0.0)
        
        if count > self.threshold and (ts - last_alert) >= self.window_s:
            self.alerts.append({
                "src": src_ip,
                "target": dst_ip,
                "ts": ts,
                "count": count,
                "window_s": self.window_s,
                "kind": "http_flood"
            })
            self.alerted_at[src_ip] = ts
            return True
        return False