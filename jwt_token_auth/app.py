from flask import Flask, request, jsonify, redirect, send_file
import json
import uuid
import jwt
import datetime


app = Flask(__name__)

SECRET_KEY = 'your_secret_key'
ALGORITHM = 'HS256'  
TOKEN_EXPIRATION_TIME = 10 # in seconds

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
        self.sessions = {}

    def set(self, key, value):
        self.sessions[key] = value

    def get(self, key):
        return self.sessions.get(key)

    def destroy(self, session_id):
        self.sessions.pop(session_id, None)

sessions = Session()
# todo expiration // unix time
def generate_token(username):
    expiration_time =  datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(seconds=TOKEN_EXPIRATION_TIME)
    payload = {
        'username': username,
        'exp': expiration_time
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token

def decode_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None

@app.route('/', methods=['GET'])
def index():
    token = request.headers.get('Authorization')
    if token:
        decoded_token = decode_token(token)
        print(token)
        print(decoded_token)
        if decoded_token:
            username = decoded_token.get('username')
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
    sessions.destroy(request.headers.get('Authorization'))
    return redirect('/login')

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    login = data.get('login')
    password = data.get('password')

    user = next((user for user in USERS if user['login'] == login and user['password'] == password), None)

    if user:
        token = generate_token(user['username'])
        return jsonify({'token': token}), 200

    return 'Unauthorized', 401

if __name__ == '__main__':
    app.run(debug=True, port=5000)
