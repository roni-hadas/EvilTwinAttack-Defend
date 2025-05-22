import os, time
from threading import Thread
from scapy.all import AsyncSniffer
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Deauth, Dot11Disas

# ----------- GLOBAL THRESHOLDS -----------
ALERT_WINDOW   = 2          # seconds to accumulate frames
DEAUTH_LIMIT   = 10         # > N deauth frames in the window  → alert
SHORT_BEACON   = 242        # bytes; shorter beacons often indicate Evil-Twin tools
ETWIN_LIMIT    = 5          # > N suspicious frames in the window → alert
HOP_CHANNELS = list(range(1,14))
IFACE = "wlan0mon"
# ----------- STATE HOLDERS -----------
class Stats:
    deauth_cnt   = 0
    etwin_cnt    = 0
    last_ts      = 0        # time of last reset (seconds)

# ----------- 1) DETECT & ALERT – DEAUTH ATTACK -----------
def detect_deauth(pkt, ts):
    """
    Detects a Deauthentication/Disassociation flood.
    Prints an alert when more than DEAUTH_LIMIT such frames
    are observed within ALERT_WINDOW seconds.
    """
    # reset counters once per time window
    if ts - Stats.last_ts >= ALERT_WINDOW:
        if Stats.deauth_cnt > DEAUTH_LIMIT:
            print(f"🚨 DEAUTH flood detected – {Stats.deauth_cnt} frames in {ALERT_WINDOW}s")
        Stats.deauth_cnt = 0
        Stats.last_ts    = ts

    # count only unprotected Deauth / Disas frames
    if pkt.haslayer(Dot11):
        dot11 = pkt[Dot11]
        subtype = dot11.subtype
        protected = dot11.FCfield & 0x40       # bit 6 → Protected Frame
        if subtype in (10, 12) and not protected:  # 10=Disas, 12=Deauth
            Stats.deauth_cnt += 1

# ----------- 2) DETECT & ALERT – EVIL-TWIN -----------
def detect_evil_twin(pkt, ts):
    """
    Detects Evil-Twin behavior:
    • unusually short Beacon frames
    • OR unprotected management/action frames (subtypes 10,12,40)
    Prints an alert when more than ETWIN_LIMIT suspicious frames
    are seen within ALERT_WINDOW seconds.
    """
    # reset counters once per time window
    if ts - Stats.last_ts >= ALERT_WINDOW:
        if Stats.etwin_cnt > ETWIN_LIMIT:
            print(f"🚨 Possible EVIL-TWIN activity – {Stats.etwin_cnt} suspect frames in {ALERT_WINDOW}s")
        Stats.etwin_cnt = 0
        Stats.last_ts   = ts

    # condition 1: short beacon
    if pkt.haslayer(Dot11Beacon) and len(pkt) < SHORT_BEACON:
        Stats.etwin_cnt += 1
        return

    # condition 2: other risky management / action frames
    if pkt.haslayer(Dot11):
        dot11 = pkt[Dot11]
        subtype   = dot11.subtype          # 10=Disas  12=Deauth  40=Action
        protected = dot11.FCfield & 0x40   # bit 6
        if subtype in (10, 12, 40) and not protected:
            Stats.etwin_cnt += 1



def change_channel(interface):
    idx =0
    while True:
        ch = HOP_CHANNELS[idx]
        os.system(f"iwconfig {interface} channel {ch}")
        # switch channel from 1 to 14 each 0.5s
        idx = idx % 14 + 1
        time.sleep(0.5)

def process_packet(pkt):
    ts = int(time.time())
    if pkt.haslayer(Dot11):
        detect_deauth(pkt, ts)
        detect_evil_twin(pkt, ts)


if __name__ == "__main__":
    hooper = Thread(target=change_channel, daemon=True)
    hopper.start()

    print(f"Starting Ids on {IFACE}")
    sniffer = AsyncSniffer(iface = IFACE, prn = process_packet)
    sniffer.start()

    try:
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        prinst("Stopping...")