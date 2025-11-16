# 🛡️ Network Security Dashboard (Free Tools)

A comprehensive, free, web-based security dashboard for real-time multi-layer DDoS detection and PCAP analysis. Detects Layer 3/4/7 attacks including ACK floods, SYN floods, UDP floods, ICMP floods, and HTTP floods with intelligent interface selection and visual alerts.

**Technologies**: Python + Streamlit + Scapy + pandas + MongoDB  
**Platforms**: Windows, macOS, Linux  
**Detection**: Multi-layer DDoS protection (L3/L4/L7)

## 🚀 Features

### 🛡️ **Multi-Layer DDoS Detection**
- **🔴 ACK Flood Detection**: Layer 4 - TCP ACK-only packet floods from source IPs
- **🟠 SYN Flood Detection**: Layer 4 - TCP SYN flood attacks targeting destinations  
- **🔵 UDP Flood Detection**: Layer 3 - UDP amplification and flood attacks per destination
- **🟣 ICMP Flood Detection**: Layer 3 - ICMP ping flood (ping of death) attacks
- **🟡 HTTP Flood Detection**: Layer 7 - Application-level HTTP request floods

### 📊 **Analysis Capabilities**
- **Upload Analysis**: Analyze `.pcap` / `.pcapng` files with Wireshark-like views
- **Real-time Monitoring**: Live capture with per-second trends and protocol analysis
- **Smart Interface Selection**: Automatic detection of active network interfaces
- **Interactive Alerts**: Visual alerts with emojis and detailed descriptions

### 🔧 **Advanced Features**
- **Suricata IDS Integration**: Rule-based detection with signature analysis
- **Windows Firewall Integration**: One-click IP blocking for detected threats
- **Data Persistence**: Optional MongoDB storage for analysis history
- **Configurable Thresholds**: Adjust sensitivity for each attack type

## 🛠️ Technology Stack

### **Core Technologies**
- **🐍 Python 3.8+**: Main programming language
- **🌊 Streamlit**: Web dashboard framework
- **📦 Scapy**: Packet capture and analysis
- **🐼 pandas**: Data manipulation and analysis
- **📈 Plotly**: Interactive charts and visualizations

### **Network Capture**
- **🔍 Npcap**: Windows packet capture driver
- **🌐 Raw Sockets**: Linux/macOS packet capture
- **⚡ Multi-threading**: Real-time packet processing

### **Detection Algorithms**
- **⏱️ Sliding Window**: Time-based attack detection
- **📊 Statistical Analysis**: Threshold-based alerting
- **🔄 Real-time Processing**: Live traffic analysis

### **Optional Components**
- **🛡️ Suricata IDS**: Rule-based intrusion detection
- **🍃 MongoDB**: Data persistence and history
- **🔥 Windows Firewall**: Automated IP blocking

## 📋 Requirements
- **Python 3.8+**
- **Packages**: `streamlit`, `scapy`, `pandas`, `plotly`, `pymongo`
- **Windows**: Npcap driver (run as Administrator)
- **Optional**: Suricata IDS with EVE JSON output

## Setup (Windows PowerShell)
```powershell
# Navigate to the project folder
cd "d:\basic_network_security\Network DashBoard"

# Create and activate a venv (optional but recommended)
python -m venv .venv
. .venv\Scripts\Activate.ps1

# Install dependencies (free)
pip install -r requirements.txt
```

## Run the web dashboard
```powershell
# Start Streamlit
streamlit run app.py
```
Then open the URL shown (typically http://localhost:8501) and upload a PCAP.

### Live capture (optional)
- On Windows, install Npcap and run your shell as Administrator.
- In the app, switch mode to "Live capture", pick an interface, and click Start.
- The dashboard shows ACK-only per-second trends, protocol mix, and top TCP/UDP destination ports. Alerts appear if ACK-only thresholds are exceeded.

#### Suricata (live IDS, optional)
- Toggle "Enable Suricata during live capture" in the Live section.
- If Suricata isn’t in PATH, provide the full path (e.g., `C:\\Program Files\\Suricata\\suricata.exe`).
- Optionally specify `suricata.yaml` that has EVE JSON enabled.
- The app tails `eve.json` and pops up alerts (signature, src → dst). A table shows recent alerts.
- You can click "Block" next to an alert to add a Windows Advanced Firewall rule blocking the source IP.
  - Requires running the shell as Administrator.
  - Uses: `netsh advfirewall firewall add rule dir=in action=block remoteip=<src>`

### Optional: Save results to MongoDB Atlas (free tier)
1. Create a MongoDB Atlas cluster (free shared tier works).
2. Get your connection string (mongodb+srv://...). If your password contains special characters like `@`, URL-encode them (e.g., `@` -> `%40`).
3. Set an environment variable before launching the app, or paste the URI in the sidebar when toggling “Save results to MongoDB”.

```powershell
$env:MONGODB_URI = "mongodb+srv://USERNAME:PASSWORD@cluster0.xxxxx.mongodb.net/"  # encode special chars!
streamlit run app.py
```
4. By default, the app saves a run summary into `network_analysis.network` (you can change these in the sidebar).

## Interface Selection Guide

### 🔍 Test Your Interfaces
Run the interface test script to see which interface to choose:
```powershell
python test_interfaces.py
```

### 🌐 Choosing the Right Interface
- **✅ RECOMMENDED**: Interfaces with active IPv4 addresses (🟢)
- **⚠️ AVOID**: Loopback (127.x.x.x) and APIPA (169.254.x.x) interfaces
- **❌ SKIP**: Interfaces without IP addresses (🔴)

### 📝 Common Interface Types
- **Ethernet**: Physical network connection (best for testing)
- **Wi-Fi**: Wireless connection (good for wireless attack detection)
- **VPN**: Virtual interfaces (limited traffic visibility)
- **Loopback**: Local testing only (not recommended for DDoS detection)

## Create a Test Capture (Optional)
- With Wireshark GUI: Start a capture and save to a `.pcap` file
- With tshark (replace interface name):
```powershell
tshark -i "Your Interface Name" -w d:\captures\capture.pcap
```

## 🔍 Attack Detection Capabilities

### **Layer 3 (Network Layer) Attacks**

#### 🔵 **UDP Flood Detection**
- **Method**: Tracks UDP packets per destination IP
- **Algorithm**: Sliding window analysis (default: 10 seconds)
- **Threshold**: 500 UDP packets per destination
- **Detects**: UDP amplification attacks, UDP flood attacks
- **Use Case**: DNS amplification, NTP amplification, memcached attacks

#### 🟣 **ICMP Flood Detection**
- **Method**: Monitors ICMP echo requests (ping packets)
- **Algorithm**: Per-destination traffic pattern analysis
- **Threshold**: 200 ICMP pings per destination in 10 seconds
- **Detects**: Ping flood attacks, ping of death
- **Use Case**: ICMP-based DDoS, network reconnaissance floods

### **Layer 4 (Transport Layer) Attacks**

#### 🔴 **ACK Flood Detection**
- **Method**: Monitors TCP ACK-only packets (ACK flag set, no SYN/FIN/RST)
- **Algorithm**: Per-source IP sliding window tracking
- **Threshold**: 200 ACK packets per source in 10 seconds
- **Detects**: TCP ACK flood attacks from compromised hosts
- **Use Case**: Botnet-generated ACK floods, connection state exhaustion

#### 🟠 **SYN Flood Detection**
- **Method**: Identifies TCP SYN packets without ACK (new connections)
- **Algorithm**: Per-destination IP sliding window monitoring
- **Threshold**: 400 SYN packets per destination in 10 seconds
- **Detects**: SYN flood attacks targeting servers
- **Use Case**: TCP connection exhaustion, server resource depletion

### **Layer 7 (Application Layer) Attacks**

#### 🟡 **HTTP Flood Detection**
- **Method**: Analyzes HTTP request patterns and frequency
- **Algorithm**: Request rate monitoring per source IP
- **Threshold**: 10 HTTP requests per source in 10 seconds
- **Detects**: HTTP GET/POST floods, application-layer DDoS
- **Use Case**: Web server overload, API abuse, slowloris attacks

### **⚙️ Detection Algorithm**
```python
# Sliding Window Algorithm
for packet in traffic_stream:
    timestamp = packet.time
    source_ip = packet.src
    
    # Add to sliding window
    window[source_ip].append(timestamp)
    
    # Remove old entries
    cutoff = timestamp - window_size
    while window[source_ip] and window[source_ip][0] < cutoff:
        window[source_ip].popleft()
    
    # Check threshold
    if len(window[source_ip]) > threshold:
        trigger_alert(source_ip, len(window[source_ip]))
```

### **🎛️ Configurable Parameters**
- **Window Size**: 1-120 seconds (default: 10s)
- **Thresholds**: Adjustable per attack type
- **Sensitivity**: Lower values = more sensitive detection
- **Interface Selection**: Automatic or manual selection

### Suricata IDS (optional, upload mode)
- If Suricata is installed, enable "Run Suricata on uploaded PCAP" in the sidebar.
- Optionally provide the path to suricata (e.g., `C:\\Program Files\\Suricata\\suricata.exe`) and a `suricata.yaml` config path.
- The app runs Suricata offline against the uploaded PCAP and parses `eve.json` for alerts. You’ll see a "Suricata IDS" tab with alerts, top signatures, and a severity breakdown.

## Project structure
```
Network DashBoard/
├─ app.py                        # Streamlit web UI (upload + live capture)
├─ requirements.txt              # Python dependencies
├─ README.md                     # This file
└─ tools/
  ├─ ack_flood.py               # ACK-only detector logic (Scapy-based)
  ├─ live_sniffer.py            # Threaded live capture and stats
  ├─ pcap_analyzer.py           # Wireshark-like offline analysis + DDoS heuristics
  └─ suricata_integration.py    # Run Suricata on a PCAP and parse eve.json
                                 # Live runner + eve.json tail + Windows block helper
```

## Notes
- Large PCAP files may take time to parse; start with short captures to calibrate thresholds.
- Streamlit and the listed libraries are free/open-source.
- Some Streamlit features vary by version; the app includes fallbacks for toggles/auto-refresh.
- Security: Don’t hard-code credentials. Prefer environment variables. URL-encode special characters in passwords.

## Troubleshooting

### 🐍 Python/Package Issues
- **Streamlit not found**: Ensure venv is activated and run `pip install -r requirements.txt`
- **Scapy import errors**: Install Npcap on Windows, run as Administrator
- **Pandas missing**: Charts require pandas - install with `pip install pandas`

### 🌐 Network Interface Issues  
- **No interfaces found**: Install Npcap, run as Administrator
- **No traffic captured**: Choose interface with active IP (🟢), avoid loopback
- **Permission denied**: Run PowerShell/Command Prompt as Administrator

### 📊 Detection Issues
- **No alerts triggered**: Lower thresholds in sidebar for more sensitive detection
- **Too many false positives**: Increase thresholds to reduce sensitivity
- **Missing attack types**: Ensure you're using live capture mode for real-time detection

### 🔍 Suricata Issues
- **Suricata not found**: Verify installation with `suricata -V`
- **No IDS alerts**: Check that `suricata.yaml` enables EVE JSON output
- **Path issues**: Provide full path to suricata executable in settings

### 💾 File/Storage Issues
- **PCAP read errors**: Confirm file is valid PCAP/PCAPNG format
- **MongoDB connection failed**: Check URI format, URL-encode special characters
- **Large files slow**: Start with smaller captures to test thresholds
