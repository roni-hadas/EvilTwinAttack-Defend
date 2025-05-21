"""
client_scanner.py

This script scans for Wi-Fi clients either probing for or associated with a specific SSID/BSSID.
It uses Scapy to sniff packets and identify client MAC addresses that are either sending probe
requests or are actively communicating with a given access point.
"""

from scapy.all import *

def find_clients(iface, target_bssid, target_ssid, timeout=15):
    """
    Scans for Wi-Fi clients probing for or connected to the specified SSID/BSSID.

    Parameters:
    - iface (str): The name of the interface to sniff on (must be in monitor mode).
    - target_bssid (str): The MAC address of the access point (AP) to detect associations with.
    - target_ssid (str or None): The SSID to filter probe requests by.
    - timeout (int): Duration of the scan in seconds (default: 15).

    Returns:
    - List of unique client MAC addresses detected.
    """
    clients = set()

    def packet_handler(pkt):
        # === Probe Request Detection ===
        if pkt.haslayer(Dot11ProbeReq) and pkt.haslayer(Dot11Elt):
            ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
            mac = pkt.addr2
            # If the SSID matches the target (or any if target_ssid is None)
            if target_ssid is None or ssid == target_ssid:
                if mac and mac not in clients:
                    clients.add(mac)
                    print(f"[+] Probe Request from {mac} for SSID: {ssid}")

        # === Associated Client Detection via Data Frames ===
        elif pkt.haslayer(Dot11) and pkt.type == 2:
            # Check if the AP is involved in the communication
            if pkt.addr1 and pkt.addr2:
                if target_bssid in [pkt.addr1, pkt.addr2, pkt.addr3]:
                    mac = pkt.addr2 if pkt.addr2 != target_bssid else pkt.addr1
                    if mac and mac not in clients:
                        clients.add(mac)
                        print(f"[+] Associated Client Detected: {mac} on SSID: {target_ssid}")

    print(f"[*] Scanning for clients on {iface} (timeout={timeout}s)...")
    # Start sniffing packets and apply the packet handler for each
    sniff(iface=iface, prn=packet_handler, timeout=timeout, store=0)

    return list(clients)