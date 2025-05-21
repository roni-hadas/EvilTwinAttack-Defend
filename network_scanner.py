"""
network_scanner.py

This script scans for nearby Wi-Fi networks by capturing beacon and probe response frames.
It uses channel hopping to detect networks across all standard 2.4GHz channels (1–13),
and extracts SSID, BSSID, and operating channel information.

Dependencies:
- scapy
- iwconfig (must be available on the system)
- Interface must be in monitor mode.
"""

from scapy.all import *
from threading import Thread
import os
import time

def channel_hopper(iface, stop_flag):
    """
    Continuously hops through Wi-Fi channels (1 to 13) on the specified interface.

    Parameters:
    - iface (str): Wireless interface name in monitor mode.
    - stop_flag (dict): Shared flag to stop hopping when scan completes.
    """
    ch = 1
    while not stop_flag["stop"]:
        os.system(f"iwconfig {iface} channel {ch}")
        time.sleep(1)  # Wait to capture packets on each channel
        ch = 1 if ch == 13 else ch + 1

def scan_networks(iface, timeout=10):
    """
    Scans for Wi-Fi networks by sniffing beacon and probe response frames.

    Parameters:
    - iface (str): Wireless interface in monitor mode.
    - timeout (int): Duration of the scan in seconds (default: 10).

    Returns:
    - List of tuples (SSID, BSSID, Channel) for each unique network found.
    """
    networks = {}
    stop_flag = {"stop": False}

    def parse_packet(pkt):
        # Check for beacon or probe response frames
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            ssid = None
            bssid = pkt.addr3
            try:
                # Extract SSID from the packet
                ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
            except:
                pass

            if ssid is None or ssid.strip() == "":
                return  # Ignore hidden or malformed SSIDs

            # Only add network if it's new
            if bssid and bssid not in networks:
                channel = None
                try:
                    # Get the channel using Scapy's network_stats helper
                    stats = pkt[Dot11Beacon].network_stats() if pkt.haslayer(Dot11Beacon) else pkt[Dot11ProbeResp].network_stats()
                    channel = stats.get("channel")
                except:
                    pass

                networks[bssid] = (ssid, channel)

    print(f"[*] Scanning for networks on {iface} for {timeout} seconds...")

    # Start the channel hopper thread
    hopper = Thread(target=channel_hopper, args=(iface, stop_flag))
    hopper.daemon = True
    hopper.start()

    # Sniff packets and parse them with our handler
    sniff(iface=iface, prn=parse_packet, timeout=timeout, store=0)

    # Stop the channel hopper after timeout
    stop_flag["stop"] = True
    hopper.join()

    # Return formatted list of discovered networks
    return [(ssid, bssid, channel) for bssid, (ssid, channel) in networks.items()]