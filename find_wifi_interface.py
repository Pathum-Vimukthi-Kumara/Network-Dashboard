#!/usr/bin/env python3
"""Find the correct Wi-Fi interface for capture."""

try:
    from scapy.all import get_if_list, get_if_addr
    from scapy.arch.windows import get_windows_if_list
except ImportError:
    print("❌ Scapy not available")
    exit(1)

def find_wifi_interface():
    print("🔍 Mapping interfaces to IP addresses...")
    
    # Get detailed Windows interface info
    win_interfaces = get_windows_if_list()
    
    for iface in win_interfaces:
        name = iface.get('name', '')
        desc = iface.get('description', '')
        ips = iface.get('ips', [])
        
        # Look for our Wi-Fi IP
        for ip in ips:
            if str(ip) == '192.168.8.100':
                print(f"✅ Found Wi-Fi interface:")
                print(f"   Device: {name}")
                print(f"   Description: {desc}")
                print(f"   IP: {ip}")
                return name
    
    print("❌ Wi-Fi interface with IP 192.168.8.100 not found")
    return None

if __name__ == "__main__":
    wifi_device = find_wifi_interface()
    
    if wifi_device:
        print(f"\n📡 Testing capture on Wi-Fi interface...")
        try:
            from scapy.all import sniff
            packets = sniff(iface=wifi_device, count=3, timeout=10)
            print(f"✅ Captured {len(packets)} packets on Wi-Fi interface!")
            for i, pkt in enumerate(packets):
                print(f"  Packet {i+1}: {pkt.summary()}")
        except Exception as e:
            print(f"❌ Capture failed: {e}")
    else:
        print("❌ Cannot test - Wi-Fi interface not found")