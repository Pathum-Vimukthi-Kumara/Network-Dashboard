#!/usr/bin/env python3
"""Test packet capture to verify Npcap is working."""

try:
    from scapy.all import sniff, get_if_list
    print("✅ Scapy imported successfully")
except ImportError as e:
    print(f"❌ Scapy import failed: {e}")
    exit(1)

def test_interfaces():
    print("\n🔍 Available interfaces:")
    interfaces = get_if_list()
    for i, iface in enumerate(interfaces):
        print(f"{i+1}. {iface}")
    return interfaces

def test_capture(iface, count=5):
    print(f"\n📡 Testing capture on {iface} (capturing {count} packets)...")
    try:
        packets = sniff(iface=iface, count=count, timeout=10)
        print(f"✅ Captured {len(packets)} packets")
        for i, pkt in enumerate(packets[:3]):
            print(f"  Packet {i+1}: {pkt.summary()}")
        return True
    except Exception as e:
        print(f"❌ Capture failed: {e}")
        return False

if __name__ == "__main__":
    interfaces = test_interfaces()
    
    # Test Wi-Fi interface (should contain "Wi-Fi" or your interface name)
    wifi_iface = None
    for iface in interfaces:
        if "Wi-Fi" in iface or "192.168.8.100" in str(iface):
            wifi_iface = iface
            break
    
    if wifi_iface:
        print(f"\n🎯 Testing Wi-Fi interface: {wifi_iface}")
        if test_capture(wifi_iface):
            print("✅ Packet capture is working!")
        else:
            print("❌ Packet capture failed. Run as Administrator or install Npcap.")
    else:
        print("❌ Wi-Fi interface not found. Try running as Administrator.")