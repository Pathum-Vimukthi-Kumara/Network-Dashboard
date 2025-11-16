import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
from queue import Queue, Empty
from typing import Dict, List, Optional, Tuple


def _read_eve(eve_path: str) -> List[dict]:
    alerts: List[dict] = []
    if not os.path.exists(eve_path):
        return alerts
    with open(eve_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if obj.get("event_type") == "alert" and "alert" in obj:
                    alerts.append(obj)
            except Exception:
                # skip bad lines
                continue
    return alerts


def run_suricata_on_pcap(
    pcap_path: str,
    suricata_exe: str = "suricata",
    config_path: Optional[str] = None,
    extra_args: Optional[List[str]] = None,
) -> Dict:
    """
    Run Suricata offline on a PCAP and return parsed EVE alerts.

    Returns dict: { alerts: [...], top_signatures: [(sig, count)], severity_counts: {sev: n} }
    """
    # temp output directory for Suricata logs
    work_dir = tempfile.mkdtemp(prefix="suricata_eve_")
    try:
        cmd = [suricata_exe, "-r", pcap_path, "-l", work_dir]
        if config_path:
            cmd += ["-c", config_path]
        if extra_args:
            cmd += list(extra_args)
        # Disable checksum check to avoid drops on offloaded captures
        cmd += ["-k", "none"]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=300)
        if proc.returncode != 0:
            raise RuntimeError(f"Suricata failed: {proc.returncode}\nSTDERR:\n{proc.stderr}\nSTDOUT:\n{proc.stdout}")

        # parse eve.json
        eve_path = os.path.join(work_dir, "eve.json")
        alerts = _read_eve(eve_path)
        # Aggregate
        top_signatures: List[Tuple[str, int]] = []
        if alerts:
            sig_counts: Dict[str, int] = {}
            sev_counts: Dict[str, int] = {}
            cat_counts: Dict[str, int] = {}
            for a in alerts:
                sig = a.get("alert", {}).get("signature") or "(unknown)"
                sev = str(a.get("alert", {}).get("severity"))
                cat = a.get("alert", {}).get("category") or "(uncategorized)"
                sig_counts[sig] = sig_counts.get(sig, 0) + 1
                sev_counts[sev] = sev_counts.get(sev, 0) + 1
                cat_counts[cat] = cat_counts.get(cat, 0) + 1
            top_signatures = sorted(sig_counts.items(), key=lambda kv: kv[1], reverse=True)
        else:
            sev_counts = {}
            cat_counts = {}
        return {
            "alerts": alerts,
            "top_signatures": top_signatures,
            "severity_counts": sev_counts,
            "category_counts": cat_counts,
            "work_dir": work_dir,
        }
    except Exception as e:
        # keep logs for debugging
        return {"error": str(e), "work_dir": work_dir, "alerts": [], "top_signatures": [], "severity_counts": {}, "category_counts": {}}


# -------- Live mode helpers ---------
class SuricataLiveRunner:
    """Run Suricata in live mode on an interface and write logs to a temp dir.

    Usage:
        r = SuricataLiveRunner("Ethernet")
        r.start()
        # read eve.json at r.eve_path
        r.stop()
    """

    def __init__(
        self,
        interface: Optional[str],
        suricata_exe: str = "suricata",
        config_path: Optional[str] = None,
        extra_args: Optional[List[str]] = None,
    ) -> None:
        self.interface = interface
        self.suricata_exe = suricata_exe
        self.config_path = config_path
        self.extra_args = list(extra_args) if extra_args else []
        self.work_dir: Optional[str] = None
        self.proc: Optional[subprocess.Popen] = None

    @property
    def eve_path(self) -> Optional[str]:
        if not self.work_dir:
            return None
        return os.path.join(self.work_dir, "eve.json")

    def start(self) -> None:
        if self.proc and self.proc.poll() is None:
            return
        self.work_dir = tempfile.mkdtemp(prefix="suricata_live_")
        cmd = [self.suricata_exe]
        # Prefer interface live mode; fallback to -i any if None
        if self.interface:
            cmd += ["-i", self.interface]
        else:
            cmd += ["-i", "any"]
        cmd += ["-l", self.work_dir]
        if self.config_path:
            cmd += ["-c", self.config_path]
        if self.extra_args:
            cmd += self.extra_args
        cmd += ["-k", "none"]  # Disable checksum validation to avoid offload drops
        # Start Suricata as a background process
        self.proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=(subprocess.CREATE_NEW_PROCESS_GROUP if hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP") else 0),
        )

    def stop(self, timeout: float = 2.0) -> None:
        if self.proc is None:
            return
        try:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=timeout)
            except Exception:
                self.proc.kill()
        finally:
            self.proc = None


class EveAlertStreamer:
    """Tail an eve.json file and emit Suricata alert events in near real-time."""

    def __init__(self, eve_path: str) -> None:
        self.eve_path = eve_path
        self._q: "Queue[dict]" = Queue()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return

        def run():
            # Wait until file exists
            while not os.path.exists(self.eve_path) and not self._stop.is_set():
                time.sleep(0.2)
            try:
                with open(self.eve_path, "r", encoding="utf-8", errors="ignore") as f:
                    # Seek to end initially; we only want new events
                    f.seek(0, os.SEEK_END)
                    while not self._stop.is_set():
                        pos = f.tell()
                        line = f.readline()
                        if not line:
                            time.sleep(0.2)
                            f.seek(pos)
                            continue
                        try:
                            obj = json.loads(line.strip())
                            if obj.get("event_type") == "alert" and "alert" in obj:
                                self._q.put(obj)
                        except Exception:
                            # Ignore parsing errors
                            pass
            except Exception:
                # File may be missing if Suricata didn't start correctly; just exit
                return

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1.5)

    def drain_alerts(self, max_items: int = 100) -> List[dict]:
        out: List[dict] = []
        for _ in range(max_items):
            try:
                out.append(self._q.get_nowait())
            except Empty:
                break
        return out


def windows_block_ip(remote_ip: str) -> Tuple[bool, str]:
    """Block a remote IP using Windows Advanced Firewall. Requires admin privileges.

    Returns (ok, message)
    """
    rule_name = f"Block_{remote_ip}_{int(time.time())}"
    cmd = [
        "netsh",
        "advfirewall",
        "firewall",
        "add",
        "rule",
        f"name={rule_name}",
        "dir=in",
        "action=block",
        f"remoteip={remote_ip}",
        "enable=yes",
    ]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
        if proc.returncode == 0:
            return True, rule_name
        return False, proc.stderr.strip() or proc.stdout.strip() or "Failed to add firewall rule"
    except Exception as e:
        return False, str(e)
