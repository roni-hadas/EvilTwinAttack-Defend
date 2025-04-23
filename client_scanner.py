from scapy.all import *

def find_clients(iface, target_ssid=None, target_bssid=None, timeout=15):
    clients = set()

    def packet_handler(pkt):
        # Probe Request Filtering
        if pkt.haslayer(Dot11ProbeReq) and pkt.haslayer(Dot11Elt):
            ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
            mac = pkt.addr2
            if target_ssid is None or ssid == target_ssid:
                if mac and mac not in clients:
                    clients.add(mac)
                    print(f"[+] Probe Request from {mac} for SSID: {ssid}")

        # Data Frame Filtering (associated clients)
        elif pkt.haslayer(Dot11) and pkt.type == 2:
            if pkt.addr1 and pkt.addr2:
                if target_bssid in [pkt.addr1, pkt.addr2, pkt.addr3]:
                    mac = pkt.addr2 if pkt.addr2 != target_bssid else pkt.addr1
                    if mac and mac not in clients:
                        clients.add(mac)
                        print(f"[+] Associated Client Detected: {mac}")

    print(f"[*] Scanning for clients on {iface} (timeout={timeout}s)...")
    sniff(iface=iface, prn=packet_handler, timeout=timeout, store=0)
    return list(clients)