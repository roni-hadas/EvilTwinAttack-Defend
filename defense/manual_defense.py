import os, time
from threading import Thread
from collections import defaultdict
from scapy.all import AsyncSniffer, sendp, RadioTap, Dot11, Dot11Deauth
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Deauth, Dot11Disas, Dot11Elt

# ----------- GLOBAL THRESHOLDS -----------
ALERT_WINDOW   = 2
DEAUTH_LIMIT   = 30
SHORT_BEACON   = 242
ETWIN_LIMIT    = 5
SIGNAL_CUTOFF  = -80
HOP_CHANNELS   = list(range(1, 14))

# ----------- STATE HOLDERS -----------
class Stats:
    deauth_cnt      = 0
    etwin_last_ts   = 0
    deauth_last_ts  = 0

class NetworkDetails:
    def __init__(self, user_mac, real_ap_mac, ssid, defend=False):
        self.user_mac        = user_mac
        self.real_ap_mac     = real_ap_mac
        self.target_ssid     = ssid
        self.suspect_counts  = defaultdict(int)
        self.defend_mode     = defend

# ----------- MODE SWITCHING -----------
def set_monitor_mode(interface):

    # Check if interface exists
    if not os.path.exists(f"/sys/class/net/{interface}"):
        print(f"[-] Interface {interface} does not exist. Please check the name.")
        exit(1)


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

# ----------- DEAUTH ATTACK DETECTION -----------
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
            print(f"\n🚨 DEAUTH flood detected – {Stats.deauth_cnt} frames in {ALERT_WINDOW}s")
        Stats.deauth_cnt = 0
        Stats.deauth_last_ts = ts

    if subtype in (10, 12) and not protected:
        Stats.deauth_cnt += 1

# ----------- DEAUTH TO EVIL TWIN -----------
def send_deauth_to_ap(fake_bssid, iface, count=5):
    pkt = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=fake_bssid, addr3=fake_bssid)/Dot11Deauth()
    print(f"[!] Sending DEAUTH to Evil Twin BSSID {fake_bssid}")
    sendp(pkt, iface=iface, count=count, inter=0.1, verbose=0)

# ----------- EVIL TWIN DETECTION -----------
def detect_evil_twin(pkt, ts, nd: NetworkDetails, iface):
    if not pkt.haslayer(Dot11Elt) or not pkt.haslayer(Dot11):
        return

    try:
        ssid = pkt[Dot11Elt].info.decode(errors="ignore")
    except:
        return

    bssid = pkt[Dot11].addr2
    if not ssid or not bssid or ssid != nd.target_ssid:
        return
    if bssid.lower() == nd.real_ap_mac.lower():
        return
    if hasattr(pkt, 'dBm_AntSignal') and pkt.dBm_AntSignal < SIGNAL_CUTOFF:
        return

    nd.suspect_counts[bssid] += 1

    if ts - Stats.etwin_last_ts >= ALERT_WINDOW:
        suspects = {mac: count for mac, count in nd.suspect_counts.items() if count >= ETWIN_LIMIT}
        if suspects:
            print(f"\n🚨 Possible EVIL-TWIN activity detected!")
            for mac, count in suspects.items():
                print(f"⚠️  BSSID {mac} seen {count} times with SSID '{ssid}'")
                if nd.defend_mode:
                    send_deauth_to_ap(mac, iface)

        nd.suspect_counts.clear()
        Stats.etwin_last_ts = ts

# ----------- PACKET HANDLER -----------
def process_packet(pkt, nd, iface):
    ts = int(time.time())
    detect_deauth(pkt, ts, nd)
    detect_evil_twin(pkt, ts, nd, iface)

# ----------- MAIN -----------
if __name__ == "__main__":
    iface = input("Enter your wireless interface (e.g. wlan0): ").strip()
    set_monitor_mode(iface)

    print("\nChoose mode:")
    print("1. Detect and Defend")
    print("2. Only Detect")
    mode = input("Enter option (1 or 2): ").strip()
    defend_mode = (mode == "1")

    ssid = input("Enter SSID to defend: ").strip()
    bssid = input("Enter real AP MAC address (BSSID): ").strip()
    user_mac = input("Enter your device MAC address: ").strip()
    nd = NetworkDetails(user_mac, bssid, ssid, defend=defend_mode)

    hopper = Thread(target=change_channel, args=(iface,), daemon=True)
    hopper.start()

    print(f"\n🔍 Monitoring interface {iface} for SSID: '{ssid}' and AP: {bssid}")
    print("⏳ Press Ctrl+C to stop.\n")

    sniffer = AsyncSniffer(iface=iface, prn=lambda pkt: process_packet(pkt, nd, iface))
    sniffer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Stopping monitor...")
        sniffer.stop()
        set_managed_mode(iface)
        print("[+] Done.")
