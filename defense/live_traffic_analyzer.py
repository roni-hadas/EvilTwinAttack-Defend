import subprocess
import numpy as np
import joblib

# Load trained RandomForest model and label encoder
model = joblib.load("trained_rf_model.pkl")
le = joblib.load("label_encoder.pkl")

# Define wireless interface in monitor mode
INTERFACE = "wlan0mon"

# Load feature names from file (excluding 'Label')
with open("feature_header.txt") as f:
    feature_names = [col.strip() for col in f.readline().strip().split(',') if col.strip() != "Label"]

n_features = len(feature_names)

# Build tshark command with selected fields
cmd = [
    "sudo", "tshark", "-i", INTERFACE,
    "-l",  # Line-buffered output
    "-T", "fields",  # Extract only specified fields
    "-E", "header=n",
    "-E", "separator=,",
    "-E", "occurrence=f"
]

# Add each feature as a -e <field> argument
for field in feature_names:
    cmd.extend(["-e", field])

# Start tshark subprocess
proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)

print("📡 Real-time IDS started. Listening on interface:", INTERFACE)
print("Press Ctrl+C to stop.\n")

# Process each line of tshark output
for line in proc.stdout:
    parts = line.strip().split(',')

    # Skip malformed packets with incorrect number of features
    if len(parts) != n_features:
        continue

    try:
        # Convert values to float, replace missing with 0.0
        row = [float(x) if x else 0.0 for x in parts]
        X = np.array(row, dtype=np.float32).reshape(1, -1)

        # Predict using the trained model
        pred = model.predict(X)[0]
        label = le.inverse_transform([pred])[0]

        # Alert if the prediction is not "Normal"
        if label != "Normal":
            print(f"🚨 ALERT: Suspicious activity detected → {label}")

    except Exception as e:
        print(f"[!] Error processing packet: {e}")
