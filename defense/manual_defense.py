import os, time
from threading import Thread
from collections import defaultdict
from scapy.all import AsyncSniffer
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Deauth, Dot11Disas, Dot11Elt

# ----------- GLOBAL THRESHOLDS -----------
ALERT_WINDOW   = 2         # seconds
DEAUTH_LIMIT   = 10        # deauth frames in window
SHORT_BEACON   = 242       # beacon size threshold
ETWIN_LIMIT    = 5         # suspect count threshold
SIGNAL_CUTOFF  = -80       # dBm, ignore weak signal APs
HOP_CHANNELS   = list(range(1, 14))

# ----------- STATE HOLDERS -----------
class Stats:
    deauth_cnt      = 0
    etwin_last_ts   = 0
    deauth_last_ts  = 0

class NetworkDetails:
    def __init__(self, user_mac, real_ap_mac, ssid):
        self.user_mac        = user_mac
        self.real_ap_mac     = real_ap_mac
        self.target_ssid     = ssid
        self.suspect_counts  = defaultdict(int)  # fake BSSID : count

# ----------- MODE SWITCHING -----------
def set_monitor_mode(interface):
    os.system(f"sudo ip link set {interface} down")
    os.system(f"sudo iw dev {interface} set type monitor")
    os.system(f"sudo ip link set {interface} up")
    print(f"[+] {interface} set to MONITOR mode")

def set_managed_mode(interface):
    os.system(f"sudo ip link set {interface} down")
    os.system(f"sudo iw dev {interface} set type managed")
    os.system(f"sudo ip link set {interface} up")
    print(f"[+] {interface} set back to MANAGED mode")

# ----------- CHANNEL HOPPING -----------
def change_channel(interface):
    idx = 0
    while True:
        os.system(f"iwconfig {interface} channel {HOP_CHANNELS[idx]} >/dev/null 2>&1")
        idx = (idx + 1) % len(HOP_CHANNELS)
        time.sleep(0.5)

# ----------- DEAUTH DETECTION -----------
def detect_deauth(pkt, ts, nd: NetworkDetails):
    if not pkt.haslayer(Dot11):
        return

    dot11 = pkt[Dot11]
    subtype = dot11.subtype
    protected = dot11.FCfield & 0x40
    source_mac = dot11.addr2

    if source_mac not in [nd.real_ap_mac, nd.user_mac]:
        return

    if ts - Stats.deauth_last_ts >= ALERT_WINDOW:
        if Stats.deauth_cnt > DEAUTH_LIMIT:
            print(f"🚨 DEAUTH flood detected – {Stats.deauth_cnt} frames in {ALERT_WINDOW}s")
        Stats.deauth_cnt = 0
        Stats.deauth_last_ts = ts

    if subtype in (10, 12) and not protected:
        Stats.deauth_cnt += 1

# ----------- EVIL TWIN DETECTION -----------
def detect_evil_twin(pkt, ts, nd: NetworkDetails):
    if not pkt.haslayer(Dot11Elt) or not pkt.haslayer(Dot11):
        return

    try:
        ssid = pkt[Dot11Elt].info.decode(errors="ignore")
    except Exception as e:
        print(f"[DEBUG] Failed to decode SSID: {e}")
        return

    bssid = pkt[Dot11].addr2
    if not ssid or not bssid:
        print("[DEBUG] Packet skipped – missing SSID or BSSID")
        return

    print(f"[DEBUG] SSID={ssid}, BSSID={bssid}")

    if ssid != nd.target_ssid:
        print(f"[DEBUG] Skipped – SSID '{ssid}' does not match target SSID '{nd.target_ssid}'")
        return

    if bssid.lower() == nd.real_ap_mac.lower():
        return
    else:
        print(f"[DEBUG] Found bssid --> {bssid} that not matched real bssid {nd.real_ap_mac}")

    # if hasattr(pkt, 'dBm_AntSignal'):
    #     if pkt.dBm_AntSignal < SIGNAL_CUTOFF:
    #         print(f"[DEBUG] Skipped – signal too weak ({pkt.dBm_AntSignal} dBm)")
    #         return

    # Count suspicious BSSID
    nd.suspect_counts[bssid] += 1
    print(f"[DEBUG] Counted suspicious BSSID: {bssid} → {nd.suspect_counts[bssid]} times")

    # Check time window
    if ts - Stats.etwin_last_ts >= ALERT_WINDOW:
        suspects = {mac: count for mac, count in nd.suspect_counts.items() if count >= ETWIN_LIMIT}
        if suspects:
            print(f"\n🚨 Possible EVIL-TWIN activity detected!")
            for mac, count in suspects.items():
                print(f"⚠️  BSSID {mac} seen {count} times with SSID '{ssid}'")

        nd.suspect_counts.clear()
        Stats.etwin_last_ts = ts


# ----------- PACKET HANDLER -----------
def process_packet(pkt, nd):
    ts = int(time.time())
    detect_deauth(pkt, ts, nd)
    detect_evil_twin(pkt, ts, nd)

# ----------- MAIN -----------
if __name__ == "__main__":
    iface = input("Enter your wireless interface (e.g. wlan0): ").strip()

    set_monitor_mode(iface)

    ssid = input("Enter SSID to defend: ").strip()
    bssid = input("Enter real AP MAC address (BSSID): ").strip()
    user_mac = input("Enter your device MAC address: ").strip()

    nd = NetworkDetails(user_mac, bssid, ssid)

    # Channel hopper thread
    hopper = Thread(target=change_channel, args=(iface,), daemon=True)
    hopper.start()

    print(f"\n🔍 Monitoring interface {iface} for SSID: '{ssid}' and AP: {bssid}")
    print("⏳ Press Ctrl+C to stop.\n")

    sniffer = AsyncSniffer(iface=iface, prn=lambda pkt: process_packet(pkt, nd))
    sniffer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Stopping monitor...")
        sniffer.stop()
        set_managed_mode(iface)
        print("[+] Done.")