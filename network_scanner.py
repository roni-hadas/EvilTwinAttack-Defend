from scapy.all import *
from threading import Thread
import os
import time

def channel_hopper(iface, stop_flag):
    ch = 1
    while not stop_flag["stop"]:
        os.system(f"iwconfig {iface} channel {ch}")
        time.sleep(1)
        ch = 1 if ch == 13 else ch + 1

def scan_networks(iface, timeout=10):
    networks = {}
    stop_flag = {"stop": False}

    def parse_packet(pkt):
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            ssid = None
            bssid = pkt.addr3
            try:
                ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
            except:
                pass

            if ssid is None or ssid.strip() == "":
                return

            if bssid and bssid not in networks:
                channel = None
                try:
                    stats = pkt[Dot11Beacon].network_stats() if pkt.haslayer(Dot11Beacon) else pkt[Dot11ProbeResp].network_stats()
                    channel = stats.get("channel")
                except:
                    pass

                networks[bssid] = (ssid, channel)

    print(f"[*] Scanning for networks on {iface} for {timeout} seconds...")
    hopper = Thread(target=channel_hopper, args=(iface, stop_flag))
    hopper.daemon = True
    hopper.start()
    sniff(iface=iface, prn=parse_packet, timeout=timeout, store=0)
    stop_flag["stop"] = True
    hopper.join()

    return [(ssid, bssid, channel) for bssid, (ssid, channel) in networks.items()]