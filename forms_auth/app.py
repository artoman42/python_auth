from flask import Flask, request, jsonify, redirect, url_for, session, send_file
import os
import json
app = Flask(__name__)
app.secret_key = os.urandom(24)

users = [
    {'login': 'Login', 'password': 'Password', 'username': 'Username'},
    {'login': 'Login1', 'password': 'Password1', 'username': 'Username1'}
]

SESSION_FILE = 'sessions.json'

def load_sessions():
    try:
        with open(SESSION_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_sessions(sessions):
    with open(SESSION_FILE, 'w') as f:
        json.dump(sessions, f)

@app.before_request
def load_session():
    session.update(load_sessions().get(request.cookies.get('session', ''), {}))

@app.after_request
def save_session(response):
    save_sessions({request.cookies.get('session', ''): dict(session)})
    return response

@app.route('/', methods=['GET'])
def index():
    if 'username' in session:
        return jsonify({'username': session['username'], 'logout': '/logout'})
    return send_file('index.html')

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    login = data.get('login')
    password = data.get('password')

    user = next((u for u in users if u['login'] == login and u['password'] == password), None)
    if user:
        session['username'] = user['username']
        session['login'] = user['login']
        return jsonify({'username': login})
    return ('', 401)  # Unauthorized

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)

