import subprocess
import numpy as np
import joblib
import os
import time
from threading import Thread

HOP_CHANNELS = list(range(1, 14))  # Channels 1 to 13

def change_channel(interface):
    idx = 0
    while True:
        ch = HOP_CHANNELS[idx]
        os.system(f"iwconfig {interface} channel {ch}")
        idx = (idx + 1) % len(HOP_CHANNELS)
        time.sleep(0.5)  # Dwell time per channel

# Load the trained RandomForest model and label encoder
model = joblib.load("trained_rf_model.pkl")
le = joblib.load("label_encoder.pkl")

# Define the wireless interface in monitor mode
INTERFACE = "wlan0mon"

# Load feature names (excluding the 'Label' column)
with open("feature_header.txt") as f:
    feature_names = [col.strip() for col in f.readline().strip().split(',') if col.strip() != "Label"]

n_features = len(feature_names)
print(n_features)

# Build the tshark command to capture only the required fields
cmd = [
    "sudo", "tshark", "-i", INTERFACE,
    "-l",                         # Line-buffered output
    "-T", "fields",               # Output only selected fields
    "-E", "header=n",
    "-E", "separator=,",
    "-E", "occurrence=f"
]

# Add each feature field to the command
for field in feature_names:
    cmd.extend(["-e", field])

# Start channel hopper thread
hopper = Thread(target=change_channel, args=(INTERFACE,), daemon=True)
hopper.start()

# Start the tshark subprocess
proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)

print("📡 Real-time IDS started. Listening on interface:", INTERFACE)
print("Press Ctrl+C to stop.\n")

# Process tshark output line-by-line
for line in proc.stdout:
    parts = line.strip().split(',')

    # Pad missing values with empty strings to match expected length
    if len(parts) < n_features:
        parts += [''] * (n_features - len(parts))
    elif len(parts) > n_features:
        parts = parts[:n_features]

    try:
        # Convert all values to float, replacing missing entries with 0.0
        row = [float(x) if x not in (None, '', 'nan', 'NaN') else 0.0 for x in parts]
        X = np.array(row, dtype=np.float32).reshape(1, -1)

        # Predict using the trained model
        pred = model.predict(X)[0]
        label = le.inverse_transform([pred])[0]

        # Alert only if the label is not 'Normal'
        if label != "Normal":
            print(f"🚨 ALERT: Suspicious activity detected → {label}")

    except Exception as e:
        print(f"[!] Error processing packet: {e}")
