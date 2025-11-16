#!/usr/bin/env python3
"""
Simple script to test and display available network interfaces.
Run this to see which interface you should choose for live capture.
"""

try:
    from scapy.all import get_if_list, get_if_addr
    try:
        from scapy.arch.windows import get_windows_if_list
    except ImportError:
        get_windows_if_list = None
except ImportError:
    print("❌ Scapy not installed. Run: pip install scapy")
    exit(1)

def test_interfaces():
    print("🌐 Network Interface Analysis")
    print("=" * 50)
    
    # Get detailed interface info if available
    if get_windows_if_list:
        print("📋 Detailed Interface Information (Windows):")
        interfaces = get_windows_if_list()
        
        for i, iface in enumerate(interfaces, 1):
            name = iface.get('name', 'Unknown')
            desc = iface.get('description', name)
            ips = iface.get('ips', [])
            mac = iface.get('mac', 'Unknown')
            
            ipv4_addrs = [str(ip) for ip in ips if '.' in str(ip)]
            ipv6_addrs = [str(ip) for ip in ips if ':' in str(ip)]
            
            status = "🟢 ACTIVE" if ipv4_addrs else "🔴 NO IP"
            
            print(f"\n{i}. {status} {desc}")
            print(f"   Device: {name}")
            print(f"   MAC: {mac}")
            if ipv4_addrs:
                print(f"   IPv4: {', '.join(ipv4_addrs)}")
            if ipv6_addrs:
                print(f"   IPv6: {', '.join(ipv6_addrs[:2])}...")  # Show first 2 IPv6
            
            # Recommendation
            if ipv4_addrs and not any(ip.startswith(('127.', '169.254.')) for ip in ipv4_addrs):
                print(f"   ✅ RECOMMENDED for live capture")
            elif ipv4_addrs:
                print(f"   ⚠️  Local/loopback interface")
            else:
                print(f"   ❌ Not suitable for capture")
    
    else:
        # Fallback for non-Windows or when detailed info unavailable
        print("📋 Basic Interface Information:")
        interfaces = get_if_list()
        
        for i, name in enumerate(interfaces, 1):
            try:
                ip = get_if_addr(name)
                status = "🟢 ACTIVE" if ip and ip != "0.0.0.0" else "🔴 NO IP"
                print(f"{i}. {status} {name}")
                if ip and ip != "0.0.0.0":
                    print(f"   IP: {ip}")
                    if not ip.startswith(('127.', '169.254.')):
                        print(f"   ✅ RECOMMENDED for live capture")
                    else:
                        print(f"   ⚠️  Local/loopback interface")
                else:
                    print(f"   ❌ Not suitable for capture")
            except Exception as e:
                print(f"{i}. ❓ {name} (Error: {e})")
    
    print("\n" + "=" * 50)
    print("💡 RECOMMENDATIONS:")
    print("• Choose interfaces marked with ✅ RECOMMENDED")
    print("• Avoid loopback (127.x.x.x) and APIPA (169.254.x.x) addresses")
    print("• For best results, run as Administrator on Windows")
    print("• Install Npcap if you haven't already")
    
    print("\n🚀 To start the dashboard:")
    print("streamlit run app.py")

if __name__ == "__main__":
    test_interfaces()