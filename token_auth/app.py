from flask import Flask, request, jsonify, redirect, send_file
import json
import uuid

app = Flask(__name__)

SESSION_KEY = 'Authorization'
SESSION_FILE = './sessions.json'
USERS = [
    {
        'login': 'Login',
        'password': 'Password',
        'username': 'Username',
    },
    {
        'login': 'Login1',
        'password': 'Password1',
        'username': 'Username1',
    }
]

class Session:
    def __init__(self):
        try:
            with open(SESSION_FILE, 'r') as f:
                self.sessions = json.load(f)
        except FileNotFoundError:
            self.sessions = {}

    def store_sessions(self):
        with open(SESSION_FILE, 'w') as f:
            json.dump(self.sessions, f)

    def set(self, key, value):
        if not value:
            value = {}
        self.sessions[key] = value
        self.store_sessions()

    def get(self, key):
        return self.sessions.get(key)

    def init(self):
        session_id = str(uuid.uuid4())
        self.set(session_id, {})
        return session_id

    def destroy(self, session_id):
        self.sessions.pop(session_id, None)
        self.store_sessions()

sessions = Session()

@app.route('/', methods=['GET'])
def index():
    session_id = request.headers.get(SESSION_KEY)
    if session_id:
        username = sessions.get(session_id).get('username')
        if username:
            return jsonify({
                'username': username,
                'logout': '/logout'
            })
    return redirect('/login')

@app.route('/login', methods=['GET'])
def login_page():
    return send_file('index.html')

@app.route('/logout', methods=['GET'])
def logout():
    session_id = request.headers.get(SESSION_KEY)
    sessions.destroy(session_id)
    return redirect('/login')

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    login = data.get('login')
    password = data.get('password')

    user = next((user for user in USERS if user['login'] == login and user['password'] == password), None)

    if user:
        session_id = sessions.init()
        sessions.set(session_id, {'username': user['username'], 'login': user['login']})
        return jsonify({'token': session_id}), 200

    return 'Unauthorized', 401

if __name__ == '__main__':
    app.run(debug=True, port=5000)
