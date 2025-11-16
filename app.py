import os
from datetime import datetime
from tempfile import NamedTemporaryFile
import json
import csv

import streamlit as st

try:
    import pandas as pd
except Exception as e:  # pragma: no cover
    pd = None

try:
    from pymongo import MongoClient
except Exception:  # pragma: no cover
    MongoClient = None

from tools.ack_flood import AckFloodAnalyzer
try:
    from tools.live_sniffer import LiveAckSniffer
except Exception:
    LiveAckSniffer = None  # type: ignore
try:
    from tools.pcap_analyzer import PcapFullAnalyzer
except Exception:
    PcapFullAnalyzer = None  # type: ignore
try:
    from tools.suricata_integration import (
        run_suricata_on_pcap,
        SuricataLiveRunner,
        EveAlertStreamer,
        windows_block_ip,
    )
except Exception:
    run_suricata_on_pcap = None  # type: ignore
    SuricataLiveRunner = None  # type: ignore
    EveAlertStreamer = None  # type: ignore
    windows_block_ip = None  # type: ignore

st.set_page_config(page_title="Network ACK Flood Dashboard", layout="wide")

st.title("🛡️ Network Security Dashboard — DDoS Detection & Analysis")

# Mode selection: Upload vs Live
mode = st.radio("Mode", options=["Upload PCAP", "Live capture"], horizontal=True)

# Always-on quick start so there's never a completely blank page
with st.container():
    st.markdown(
        "**Quick start:** Upload a PCAP to analyze offline, or switch to Live capture to see packets and alerts in real time."
    )

# Defaults to satisfy static analyzers when not in upload mode
uploaded = None  # type: ignore
result = {
    "total_packets": 0,
    "ack_only_packets": 0,
    "unique_src": 0,
    "alerts": [],
    "per_sec": [],
    "top_src": [],
}
full_result = None  # ensure defined for both modes
suri_result = None   # ensure defined for both modes

with st.sidebar:
    st.header("Detection Settings")
    window_s = st.number_input("Sliding window (seconds)", min_value=1, max_value=120, value=10)
    threshold = st.number_input(
        "🔴 ACK flood threshold (packets per source)",
        min_value=10,
        max_value=100000,
        value=200,
        step=10,
        help="Detects ACK flood attacks from a specific source IP"
    )
    st.markdown("---")
    st.subheader("🚨 DDoS Detection Thresholds")
    st.caption("Configure thresholds for different types of DDoS attacks. Lower values = more sensitive detection.")
    syn_th = st.number_input("🟠 SYN flood threshold (packets per destination)", min_value=10, max_value=500000, value=400, step=10, help="Detects SYN flood attacks targeting a specific destination")
    udp_th = st.number_input("🔵 UDP flood threshold (packets per destination)", min_value=10, max_value=500000, value=500, step=10, help="Detects UDP flood attacks targeting a specific destination")
    icmp_th = st.number_input("🟣 ICMP flood threshold (pings per destination)", min_value=10, max_value=500000, value=200, step=10, help="Detects ICMP ping flood attacks targeting a specific destination")
    http_th = st.number_input("🟡 HTTP flood threshold (requests per source)", min_value=5, max_value=1000, value=10, step=1, help="Detects HTTP flood attacks from a specific source IP")
    st.markdown("---")
    st.subheader("Suricata IDS (optional, upload mode)")
    use_suricata = st.checkbox("Run Suricata on uploaded PCAP", value=False)
    suri_exe = st.text_input("suricata executable path", value="suricata", disabled=not use_suricata)
    suri_cfg = st.text_input("suricata.yaml (optional)", value="", disabled=not use_suricata)
    st.caption("Requires Suricata installed. EVE JSON must be enabled in the config.")
    st.header("Storage (Optional)")
    st.caption("Save results to MongoDB Atlas using a connection string. Keep secrets out of code.")
    # Streamlit < 1.25 doesn't have st.toggle; fall back to checkbox.
    if hasattr(st, "toggle"):
        use_db = st.toggle("Save results to MongoDB", value=False)  # type: ignore[attr-defined]
    else:
        use_db = st.checkbox("Save results to MongoDB", value=False)
    default_uri = os.getenv("MONGODB_URI", "")
    mongo_uri = st.text_input(
        "MongoDB connection string",
        value=default_uri,
        type="password",
        help=(
            "Example: mongodb+srv://user:password@cluster0.xxxxx.mongodb.net/\n"
            "If your password contains special characters like @, use URL-encoding (e.g., %40)."
        ),
        disabled=not use_db,
    )
    db_name = st.text_input("Database name", value="network_analysis", disabled=not use_db)
    col_name = st.text_input("Collection name", value="network", disabled=not use_db)
    # Persist config in session for access outside the sidebar scope
    st.session_state.mongo_cfg = {
        "use_db": bool(use_db),
        "mongo_uri": mongo_uri,
        "db_name": db_name,
        "col_name": col_name,
    }
    if use_db:
        test_clicked = st.button("Test MongoDB connection")
        if test_clicked:
            if MongoClient is None:
                st.session_state.mongo_ok = False
                st.error("pymongo is not installed. Run `pip install pymongo`.")
            elif not mongo_uri:
                st.session_state.mongo_ok = False
                st.warning("Enter a MongoDB connection string.")
            else:
                try:
                    client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
                    _ = client.server_info()
                    st.session_state.mongo_ok = True
                    st.success("MongoDB connection OK.")
                except Exception as e:
                    st.session_state.mongo_ok = False
                    st.error(f"MongoDB connection failed: {e}")
        # Show last known status if available
        if "mongo_ok" in st.session_state:
            if st.session_state.mongo_ok:
                st.caption("Status: connected (recent test)")
            else:
                st.caption("Status: not connected (recent test)")
    st.markdown("---")
    st.caption(
        "Upload a .pcap or .pcapng file. The app will count TCP ACK-only packets per source IP,"
        " aggregate per second, and flag potential floods when counts exceed the threshold in the window."
    )

if mode == "Upload PCAP":
    uploaded = st.file_uploader("Upload PCAP / PCAPNG", type=["pcap", "pcapng"]) 
    if uploaded is None:
        st.info("Upload a capture file to begin, or switch to Live capture above.")

if mode == "Upload PCAP" and uploaded is not None:
    # Persist upload to a temp file so scapy can read it
    with NamedTemporaryFile(delete=False, suffix="_upload.pcap") as tmp:
        tmp.write(uploaded.getbuffer())
        tmp_path = tmp.name

    st.write("Analyzing uploaded file…")

    # ACK-only analyzer
    analyzer = AckFloodAnalyzer(window_s=int(window_s), threshold=int(threshold))
    with st.spinner("Parsing packets and computing metrics…"):
        result = analyzer.analyze_pcap(tmp_path)

    # Full analysis for Wireshark-like tables and DDoS heuristics
    full_result = None
    if PcapFullAnalyzer is not None:
        with st.spinner("Building full traffic summary…"):
            full_result = PcapFullAnalyzer(
                syn_threshold=int(syn_th), udp_threshold=int(udp_th), icmp_threshold=int(icmp_th), window_s=int(window_s)
            ).analyze(tmp_path, max_rows=50000)

    # Optional Suricata IDS
    suri_result = None
    if use_suricata and run_suricata_on_pcap is not None:
        with st.spinner("Running Suricata IDS (this may take a bit)…"):
            try:
                suri_result = run_suricata_on_pcap(tmp_path, suricata_exe=suri_exe, config_path=(suri_cfg or None))
            except Exception as e:
                st.error(f"Suricata failed: {e}")

    # Clean up temp file
    try:
        os.remove(tmp_path)
    except Exception:
        pass

# Summary metrics
col1, col2, col3, col4 = st.columns(4)
if mode == "Upload PCAP":
    col1.metric("Total packets (processed)", f"{result['total_packets']:,}")
    col2.metric("ACK-only packets", f"{result['ack_only_packets']:,}")
    col3.metric("Unique source IPs (ACK-only)", f"{result['unique_src']:,}")
    col4.metric("Alerts triggered", f"{len(result['alerts']):,}")

# Charts
left, right = st.columns([2, 1])

# Time series chart for ACK-only per second
per_sec = result["per_sec"] if mode == "Upload PCAP" else None
if mode == "Upload PCAP" and per_sec:
    # Build DataFrame for plotting
    if pd is None:
        st.warning("pandas not installed; install with `pip install pandas` for charts.")
    else:
        ts = [datetime.fromtimestamp(t) for t, _ in per_sec]
        counts = [c for _, c in per_sec]
        df_ts = pd.DataFrame({"time": ts, "ack_only": counts}).set_index("time")
        left.subheader("ACK-only packets per second")
        left.line_chart(df_ts, height=300)
else:
    left.info("No ACK-only packets found.")

# Top talkers
top_src = result["top_src"] if mode == "Upload PCAP" else None
if mode == "Upload PCAP" and top_src and pd is not None:
    top_df = pd.DataFrame(top_src, columns=["src", "ack_only_count"]).head(20)
    right.subheader("Top sources by ACK-only packets")
    right.dataframe(top_df, use_container_width=True, hide_index=True)
else:
    right.info("Top talkers table requires pandas.")

# Alerts table
st.subheader("🚨 ACK Flood Alerts")
alerts = result["alerts"] if mode == "Upload PCAP" else []
if mode == "Upload PCAP" and alerts:
    if pd is None:
        for a in alerts:
            t = datetime.fromtimestamp(a["ts"]).strftime("%H:%M:%S")
            st.error(
                f"🔴 {t}: ACK flood from {a['src']} — {a['count']} ACKs in {a['window_s']}s"
            )
    else:
        # Enhanced display for upload mode alerts
        rows = []
        for a in alerts:
            rows.append({
                "Time": datetime.fromtimestamp(a["ts"]).strftime("%H:%M:%S"),
                "Type": "🔴 ACK Flood",
                "Source IP": a["src"],
                "Count": a["count"],
                "Window": f"{a['window_s']}s"
            })
        a_df = pd.DataFrame(rows)
        st.dataframe(a_df, use_container_width=True, hide_index=True)
else:
    st.success("✅ No ACK flood attacks detected.")

# Extra tabs for full analysis (upload mode)
if mode == "Upload PCAP" and 'full_result' in locals() and full_result:
    st.markdown("---")
    tabs = ["Packets", "Top Ports", "Proto counts"]
    if 'suri_result' in locals() and suri_result and suri_result.get("alerts"):
        tabs.append("Suricata IDS")
    t_objs = st.tabs(tabs)
    # map tab names
    if len(t_objs) >= 3:
        t1, t2, t3 = t_objs[:3]
    else:
        t1, t2, t3 = t_objs[0], t_objs[1], t_objs[2]

    if pd is not None:
        # Packet table (capped)
        with t1:
            rows = full_result.get("packets", [])
            if rows:
                df = pd.DataFrame(rows)
                df["time"] = df["ts"].apply(lambda x: datetime.fromtimestamp(x))
                df = df[["time", "src", "dst", "proto", "sport", "dport", "flags", "len"]]
                st.dataframe(df, use_container_width=True, hide_index=True)
            else:
                st.info("No packet rows available.")

        # Top ports
        with t2:
            tcp_ports = full_result.get("top_tcp_dport", [])
            udp_ports = full_result.get("top_udp_dport", [])
            c1, c2 = st.columns(2)
            if tcp_ports:
                c1.subheader("Top TCP destination ports")
                c1.dataframe(pd.DataFrame(tcp_ports, columns=["dport", "count"]).head(25), use_container_width=True, hide_index=True)
            if udp_ports:
                c2.subheader("Top UDP destination ports")
                c2.dataframe(pd.DataFrame(udp_ports, columns=["dport", "count"]).head(25), use_container_width=True, hide_index=True)

        # Protocol counts + DDoS alerts
        with t3:
            per_proto = full_result.get("per_proto", {})
            if per_proto:
                st.bar_chart(pd.DataFrame.from_dict(per_proto, orient="index", columns=["count"]))
            f_alerts = full_result.get("alerts", [])
            st.subheader("🚨 DDoS Attack Alerts (Upload Analysis)")
            if f_alerts:
                # Enhanced DDoS alerts display
                rows = []
                for a in f_alerts:
                    kind = a.get("kind", "unknown")
                    time_str = datetime.fromtimestamp(a["ts"]).strftime("%H:%M:%S")
                    
                    if kind == "syn_flood":
                        emoji = "🟠"
                        description = f"SYN flood targeting {a['target']}"
                    elif kind == "udp_flood":
                        emoji = "🔵"
                        description = f"UDP flood targeting {a['target']}"
                    elif kind == "icmp_flood":
                        emoji = "🟣"
                        description = f"ICMP flood targeting {a['target']}"
                    else:
                        emoji = "⚠️"
                        description = f"Unknown attack: {kind}"
                    
                    rows.append({
                        "Time": time_str,
                        "Type": f"{emoji} {kind.replace('_', ' ').title()}",
                        "Target": a["target"],
                        "Count": a["count"],
                        "Window": f"{a['window_s']}s",
                        "Description": description
                    })
                
                a_df = pd.DataFrame(rows)
                st.dataframe(a_df, use_container_width=True, hide_index=True)
            else:
                st.success("✅ No DDoS attacks detected with current thresholds.")

    # Suricata tab
    if 'suri_result' in locals() and suri_result and suri_result.get("alerts"):
        t_suri = t_objs[-1]
        with t_suri:
            st.subheader("Suricata alerts")
            alerts = suri_result.get("alerts", [])
            if pd is not None:
                rows = []
                for a in alerts:
                    alert = a.get("alert", {})
                    rows.append({
                        "time": a.get("timestamp"),
                        "src": f"{a.get('src_ip')}:{a.get('src_port')}",
                        "dst": f"{a.get('dest_ip')}:{a.get('dest_port')}",
                        "proto": a.get("proto"),
                        "signature": alert.get("signature"),
                        "category": alert.get("category"),
                        "severity": alert.get("severity"),
                    })
                df = pd.DataFrame(rows)
                st.dataframe(df, use_container_width=True, hide_index=True)
                # Summaries
                st.write("")
                c1, c2 = st.columns(2)
                top_sig = suri_result.get("top_signatures", [])
                if top_sig:
                    c1.subheader("Top signatures")
                    c1.dataframe(pd.DataFrame(top_sig, columns=["signature", "count"]).head(20), use_container_width=True, hide_index=True)
                sev_counts = suri_result.get("severity_counts", {})
                if sev_counts:
                    c2.subheader("Severity distribution")
                    c2.bar_chart(pd.DataFrame.from_dict(sev_counts, orient="index", columns=["count"]))
            else:
                st.write(f"Total alerts: {len(alerts)}")

# Persist to MongoDB if enabled (upload mode only)
if mode == "Upload PCAP" and use_db:
    if MongoClient is None:
        st.error("pymongo is not installed. Add it to requirements or run `pip install pymongo`.")
    elif not mongo_uri:
        st.warning("Enter a MongoDB connection string or set MONGODB_URI environment variable.")
    else:
        coll = None
        try:
            client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
            # test connection
            _ = client.server_info()
            db = client[db_name]
            coll = db[col_name]
            doc = {
                "uploaded_name": "upload",
                "analyzed_at": datetime.utcnow().isoformat() + "Z",
                "settings": {"window_s": int(window_s), "threshold": int(threshold)},
                "summary": {
                    "total_packets": int(result["total_packets"]),
                    "ack_only_packets": int(result["ack_only_packets"]),
                    "unique_src": int(result["unique_src"]),
                    "alerts": len(result["alerts"]),
                },
                # store small slices to keep doc size reasonable
                "top_src": result["top_src"][:50],
                "per_sec": result["per_sec"][-600:],  # last 10 min if 1Hz
                "alerts_list": result["alerts"],
            }
            coll.insert_one(doc)
            st.success("Saved run summary to MongoDB.")
        except Exception as e:
            st.error(
                "Could not save to MongoDB. Check the URI (URL-encode special characters) and network access.\n" + str(e)
            )

        # Show recent history
        if coll is not None:
            try:
                recent = list(
                    coll.find({}, {"_id": 0, "uploaded_name": 1, "analyzed_at": 1, "summary": 1})
                    .sort("analyzed_at", -1)
                    .limit(10)
                )
                if recent and pd is not None:
                    hist_df = pd.json_normalize(recent)
                    st.subheader("Recent runs (MongoDB)")
                    st.dataframe(hist_df, use_container_width=True, hide_index=True)
            except Exception:
                pass

if mode == "Live capture":
    st.markdown("---")
    if LiveAckSniffer is None:
        st.error("Live capture module not available.")
        st.stop()

    # Interface selection with enhanced display
    st.subheader("🌐 Network Interface Selection")
    
    # Build friendly interface labels with underlying device names
    iface_details = []
    try:
        if LiveAckSniffer and hasattr(LiveAckSniffer, "list_interfaces_detailed"):
            iface_details = LiveAckSniffer.list_interfaces_detailed()  # type: ignore
    except Exception:
        iface_details = []
    if not iface_details:
        try:
            names = LiveAckSniffer.list_interfaces() if LiveAckSniffer else []
        except Exception:
            names = []
        iface_details = [{"name": n, "label": n, "ipv4": ""} for n in names]

    if not iface_details:
        st.error("❌ No network interfaces found. Install Npcap and run as Administrator.")
        st.stop()
    
    # Create enhanced labels with status indicators
    enhanced_labels = []
    for it in iface_details:
        name = it.get("name", "")
        desc = it.get("desc", name)
        ipv4 = it.get("ipv4", "")
        
        # Add status indicators
        if ipv4:
            status = "🟢 Active"
            label = f"{status} {desc} ({ipv4})"
        else:
            status = "🔴 No IP"
            label = f"{status} {desc}"
        
        enhanced_labels.append(label)
    
    # Prefer default index with an interface having IPv4
    default_idx = 0
    for idx, it in enumerate(iface_details):
        if (it.get("ipv4") or "").strip():
            default_idx = idx
            break
    
    chosen_label = st.selectbox(
        "Select network interface for live capture:", 
        options=enhanced_labels, 
        index=min(default_idx, max(0, len(enhanced_labels)-1)),
        help="Choose an interface with an active IP address (🟢) for best results. Interfaces without IP (🔴) may not capture traffic properly."
    )
    
    # Map label back to underlying device name
    selected_iface = None
    for idx, it in enumerate(iface_details):
        if enhanced_labels[idx] == chosen_label:
            selected_iface = it.get("name")
            # Fix interface name mapping for Windows
            if "Wi-Fi" in it.get("desc", "") and "192.168.8.100" in it.get("ipv4", ""):
                selected_iface = "Wi-Fi"
            break
    
    # Display selected interface info
    if selected_iface:
        selected_info = next((it for it in iface_details if it.get("name") == selected_iface), {})
        if selected_info.get("ipv4"):
            st.success(f"✅ Selected: {selected_info.get('desc', selected_iface)} with IP {selected_info.get('ipv4')}")
        else:
            st.warning(f"⚠️ Selected interface has no IP address. Live capture may not work properly.")
    st.subheader("Suricata IDS (live) — optional")
    enable_suri_live = st.checkbox("Enable Suricata during live capture", value=False)
    suri_exe_live = st.text_input("suricata executable path (live)", value="suricata", disabled=not enable_suri_live)
    suri_cfg_live = st.text_input("suricata.yaml (optional, live)", value="", disabled=not enable_suri_live)
    colA, colB = st.columns([1,1])
    start_clicked = colA.button("Start capture", type="primary")
    stop_clicked = colB.button("Stop capture")

    if "sniffer" not in st.session_state:
        st.session_state.sniffer = None
    if "suri_runner" not in st.session_state:
        st.session_state.suri_runner = None
    if "suri_stream" not in st.session_state:
        st.session_state.suri_stream = None
    if "live_suri_alerts" not in st.session_state:
        st.session_state.live_suri_alerts = []
    if "blocked_ips" not in st.session_state:
        st.session_state.blocked_ips = set()

    if start_clicked:
        try:
            if not LiveAckSniffer:
                raise RuntimeError("LiveAckSniffer not available")
            st.session_state.sniffer = LiveAckSniffer(
                iface=selected_iface,
                window_s=int(window_s),
                threshold=int(threshold),
                syn_threshold=int(syn_th),
                udp_threshold=int(udp_th),
                icmp_threshold=int(icmp_th),
                http_threshold=int(http_th),  # HTTP requests per source in window
            )
            st.session_state.sniffer.start()
            # Start Suricata live if requested
            if enable_suri_live and SuricataLiveRunner is not None:
                try:
                    runner = SuricataLiveRunner(
                        interface=selected_iface,
                        suricata_exe=suri_exe_live,
                        config_path=(suri_cfg_live or None),
                    )
                    runner.start()
                    st.session_state.suri_runner = runner
                    if runner.eve_path and EveAlertStreamer is not None:
                        stream = EveAlertStreamer(runner.eve_path)
                        stream.start()
                        st.session_state.suri_stream = stream
                except Exception as e:
                    st.warning(f"Could not start Suricata live: {e}")
        except Exception as e:
            st.error(str(e))

    if stop_clicked and st.session_state.sniffer is not None:
        # Take a final snapshot before stopping
        try:
            final_snap = st.session_state.sniffer.snapshot()
        except Exception:
            final_snap = None
        st.session_state.sniffer.stop()
        st.session_state.sniffer = None
        # Stop Suricata if running
        try:
            _stream = st.session_state.get("suri_stream")
            if _stream is not None:
                _stream.stop()
        except Exception:
            pass
        try:
            _runner = st.session_state.get("suri_runner")
            if _runner is not None:
                _runner.stop()
        except Exception:
            pass
        st.session_state.suri_stream = None
        st.session_state.suri_runner = None
        # Stash results for saving
        st.session_state.last_live_result = {
            "snapshot": final_snap.__dict__ if final_snap else None,
            "suri_alerts": list(st.session_state.get("live_suri_alerts", [])),
            "blocked_ips": list(st.session_state.get("blocked_ips", set())),
            "stopped_at": datetime.utcnow().isoformat() + "Z",
        }
        st.session_state.show_save_modal = True

    # Auto-refresh while running
    if st.session_state.sniffer is not None:
        # Auto-refresh: compatible fallback for older Streamlit versions
        snap = st.session_state.sniffer.snapshot()

        col1.metric("Total packets (processed)", f"{snap.total_packets:,}")
        col2.metric("ACK-only packets", f"{snap.ack_only_packets:,}")
        col3.metric("Unique src (window)", f"{len(snap.top_src):,}")
        col4.metric("Alerts triggered", f"{len(snap.alerts):,}")

        # Charts/tables
        left, right = st.columns([2,1])
        if pd is not None and snap.per_sec:
            ts = [datetime.fromtimestamp(t) for t, _ in snap.per_sec[-600:]]
            counts = [c for _, c in snap.per_sec[-600:]]
            df_ts = pd.DataFrame({"time": ts, "ack_only": counts}).set_index("time")
            left.subheader("ACK-only packets per second (live)")
            left.line_chart(df_ts, height=300)
        else:
            left.info("Waiting for packets…")

        # Per-protocol status and top ports
        if pd is not None:
            proto_counts = getattr(snap, "per_proto", {}) or {}
            if proto_counts:
                right.subheader("Protocol counts (live)")
                right.bar_chart(pd.DataFrame.from_dict(proto_counts, orient="index", columns=["count"]))

            # Removed destination port displays as requested

        st.subheader("🚨 DDoS Attack Alerts (Live)")
        if snap.alerts:
            # Group alerts by type for better display
            alert_types = {"ack_flood": [], "syn_flood": [], "udp_flood": [], "icmp_flood": [], "http_flood": []}
            for alert in snap.alerts:
                kind = alert.get("kind", "unknown")
                if kind in alert_types:
                    alert_types[kind].append(alert)
            
            # Display summary metrics
            col_a, col_b, col_c, col_d, col_e = st.columns(5)
            col_a.metric("🔴 ACK Floods", len(alert_types["ack_flood"]))
            col_b.metric("🟠 SYN Floods", len(alert_types["syn_flood"]))
            col_c.metric("🔵 UDP Floods", len(alert_types["udp_flood"]))
            col_d.metric("🟣 ICMP Floods", len(alert_types["icmp_flood"]))
            col_e.metric("🟡 HTTP Floods", len(alert_types["http_flood"]))
            
            if pd is not None:
                # Enhanced alerts table with better formatting
                rows = []
                for a in snap.alerts[-50:]:  # Show last 50 alerts
                    kind = a.get("kind", "unknown")
                    time_str = datetime.fromtimestamp(a["ts"]).strftime("%H:%M:%S")
                    
                    if kind == "ack_flood":
                        emoji = "🔴"
                        source = a.get("src", "unknown")
                        target = a.get("dst", "unknown")
                        description = f"ACK flood from {source} to {target}"
                    elif kind == "syn_flood":
                        emoji = "🟠"
                        target = a.get("target", "unknown")
                        description = f"SYN flood targeting {target}"
                        source = "Multiple sources"
                    elif kind == "udp_flood":
                        emoji = "🔵"
                        target = a.get("target", "unknown")
                        description = f"UDP flood targeting {target}"
                        source = "Multiple sources"
                    elif kind == "icmp_flood":
                        emoji = "🟣"
                        target = a.get("target", "unknown")
                        description = f"ICMP flood targeting {target}"
                        source = "Multiple sources"
                    elif kind == "http_flood":
                        emoji = "🟡"
                        source = a.get("src", "unknown")
                        target = a.get("target", "unknown")
                        description = f"HTTP flood from {source} to {target}"
                    else:
                        emoji = "⚠️"
                        description = f"Unknown attack type: {kind}"
                        source = "Unknown"
                    
                    rows.append({
                        "Time": time_str,
                        "Type": f"{emoji} {kind.replace('_', ' ').title()}",
                        "Count": a["count"],
                        "Window": f"{a['window_s']}s",
                        "Description": description
                    })
                
                if rows:
                    a_df = pd.DataFrame(rows)
                    st.dataframe(a_df, use_container_width=True, hide_index=True)
            else:
                # Fallback display without pandas
                for a in snap.alerts[-20:]:
                    kind = a.get("kind", "unknown")
                    t = datetime.fromtimestamp(a["ts"]).strftime("%H:%M:%S")
                    
                    if kind == "ack_flood":
                        st.error(f"🔴 {t}: ACK flood from {a.get('src')} — {a['count']} packets in {a['window_s']}s")
                    elif kind == "syn_flood":
                        st.error(f"🟠 {t}: SYN flood targeting {a.get('target')} — {a['count']} SYNs in {a['window_s']}s")
                    elif kind == "udp_flood":
                        st.error(f"🔵 {t}: UDP flood targeting {a.get('target')} — {a['count']} packets in {a['window_s']}s")
                    elif kind == "icmp_flood":
                        st.error(f"🟣 {t}: ICMP flood targeting {a.get('target')} — {a['count']} pings in {a['window_s']}s")
                    elif kind == "http_flood":
                        st.error(f"🟡 {t}: HTTP flood from {a.get('src')} — {a['count']} requests in {a['window_s']}s")
        else:
            st.success("✅ No DDoS attacks detected. System is secure.")

        # Live Suricata alerts section (if enabled)
        _stream = st.session_state.get("suri_stream")
        if _stream is not None:
            st.markdown("---")
            st.subheader("Suricata alerts (live)")
            # Drain new alerts and toast them
            new_alerts = _stream.drain_alerts(max_items=200)
            if new_alerts:
                # append to history
                st.session_state.live_suri_alerts.extend(new_alerts)
                # popups
                for a in new_alerts[:10]:  # cap to avoid spam
                    sig = a.get("alert", {}).get("signature", "Suricata alert")
                    src = a.get("src_ip")
                    dst = a.get("dest_ip")
                    msg = f"{sig} — {src} → {dst}"
                    if hasattr(st, "toast"):
                        st.toast(msg)
                    else:
                        st.warning(msg)

            # Show recent alerts table with Block buttons
            if st.session_state.live_suri_alerts:
                if pd is not None:
                    rows = []
                    for a in st.session_state.live_suri_alerts[-200:]:
                        alert = a.get("alert", {})
                        rows.append({
                            "time": a.get("timestamp"),
                            "src_ip": a.get("src_ip"),
                            "src_port": a.get("src_port"),
                            "dest_ip": a.get("dest_ip"),
                            "dest_port": a.get("dest_port"),
                            "proto": a.get("proto"),
                            "signature": alert.get("signature"),
                            "severity": alert.get("severity"),
                            "category": alert.get("category"),
                        })
                    df = pd.DataFrame(rows)
                    st.dataframe(df, use_container_width=True, hide_index=True)
                else:
                    st.write(f"Total alerts: {len(st.session_state.live_suri_alerts)}")

                # Per-alert block controls (for last 20)
                st.caption("Block source IPs via Windows Firewall (requires admin).")
                last_alerts = st.session_state.live_suri_alerts[-20:]
                for idx, a in enumerate(last_alerts):
                    src_ip = a.get("src_ip")
                    sig = a.get("alert", {}).get("signature", "alert")
                    cols = st.columns([4,1])
                    cols[0].write(f"{a.get('timestamp')} — {sig} — {src_ip} → {a.get('dest_ip')}")
                    disabled = (src_ip in st.session_state.blocked_ips) or (windows_block_ip is None)
                    if cols[1].button("Block", key=f"block_{idx}_{src_ip}", disabled=disabled):
                        ok, msg = windows_block_ip(src_ip) if windows_block_ip else (False, "blocker not available")
                        if ok:
                            st.session_state.blocked_ips.add(src_ip)
                            st.success(f"Blocked {src_ip} (rule: {msg})")
                        else:
                            st.error(f"Failed to block {src_ip}: {msg}")

        # simple auto-refresh using sleep + experimental_rerun
        import time as _time
        _time.sleep(2)
        try:
            st.experimental_rerun()
        except Exception:
            pass

    # Offer save dialog after stopping live capture
    if st.session_state.get("show_save_modal"):
        # Prefer modern modal if available; else show inline block
        def _render_save_ui(container):
            container.subheader("Save live run data")
            ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
            default_folder = f"NetworkDashboard_{ts_str}"
            desktop = os.path.join(os.path.expanduser("~"), "Desktop")
            desktop_ok = os.path.isdir(desktop)
            base_dir = desktop if desktop_ok else os.getcwd()
            target_dir = container.text_input(
                "Save folder",
                value=os.path.join(base_dir, default_folder),
                help=("Destination folder to store JSON/CSV files. "
                      + ("Desktop detected." if desktop_ok else "Desktop not found; using current directory.")),
            )

            c1, c2 = container.columns(2)
            save_files = c1.button("Save to Desktop as files")
            save_db = c2.button("Save to MongoDB")

            data = st.session_state.get("last_live_result") or {}
            snap = data.get("snapshot")
            suri_alerts_live = data.get("suri_alerts", [])

            if save_files:
                try:
                    os.makedirs(target_dir, exist_ok=True)
                    # Write JSON bundle
                    json_path = os.path.join(target_dir, "live_run.json")
                    with open(json_path, "w", encoding="utf-8") as f:
                        json.dump(data, f, ensure_ascii=False, indent=2)
                    # Write CSVs for convenience
                    if snap and snap.get("per_sec"):
                        with open(os.path.join(target_dir, "per_sec.csv"), "w", newline="", encoding="utf-8") as f:
                            w = csv.writer(f)
                            w.writerow(["timestamp", "ack_only"])
                            for t, c in snap.get("per_sec", []):
                                w.writerow([t, c])
                    if snap and snap.get("top_src"):
                        with open(os.path.join(target_dir, "top_src.csv"), "w", newline="", encoding="utf-8") as f:
                            w = csv.writer(f)
                            w.writerow(["src", "ack_only_count"])
                            for src, c in snap.get("top_src", []):
                                w.writerow([src, c])
                    if suri_alerts_live:
                        with open(os.path.join(target_dir, "suri_alerts.json"), "w", encoding="utf-8") as f:
                            json.dump(suri_alerts_live, f, ensure_ascii=False, indent=2)
                    container.success(f"Saved to {target_dir}")
                    # Close modal after save
                    st.session_state.show_save_modal = False
                except Exception as e:
                    container.error(f"Failed to save files: {e}")

            if save_db:
                cfg = st.session_state.get("mongo_cfg", {})
                use_db_cfg = bool(cfg.get("use_db"))
                mongo_uri_cfg = cfg.get("mongo_uri") or ""
                db_name_cfg = cfg.get("db_name") or "network_analysis"
                col_name_cfg = cfg.get("col_name") or "network"

                if not st.session_state.get("last_live_result"):
                    container.warning("No data to save.")
                elif not use_db_cfg:
                    container.warning("Enable 'Save results to MongoDB' in the sidebar.")
                elif MongoClient is None:
                    container.error("pymongo is not installed.")
                elif not mongo_uri_cfg:
                    container.warning("Enter MongoDB connection string in the sidebar.")
                else:
                    try:
                        client = MongoClient(mongo_uri_cfg, serverSelectionTimeoutMS=5000)
                        _ = client.server_info()
                        db = client[db_name_cfg]
                        coll = db[col_name_cfg]
                        doc = {
                            "run_type": "live",
                            "saved_at": datetime.utcnow().isoformat() + "Z",
                            "settings": {"window_s": int(window_s), "threshold": int(threshold)},
                            "snapshot": snap,
                            "suri_alerts": suri_alerts_live,
                            "blocked_ips": data.get("blocked_ips", []),
                        }
                        coll.insert_one(doc)
                        container.success("Saved live run to MongoDB.")
                        st.session_state.show_save_modal = False
                    except Exception as e:
                        container.error(f"Could not save to MongoDB: {e}")

        if hasattr(st, "modal"):
            with st.modal("Save options", key="save_live_modal", max_width=800):
                _render_save_ui(st)
        else:
            save_box = st.container()
            _render_save_ui(save_box)

st.caption("Tip: For live capture on Windows, install Npcap and run Streamlit with admin privileges for best results. This dashboard uses free tools: Streamlit + Scapy + pandas.")
