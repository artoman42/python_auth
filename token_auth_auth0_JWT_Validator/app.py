from flask import Flask, request, jsonify, redirect, send_file
from json import JSONEncoder
import json
import uuid
import requests
import os
import json
from datetime import datetime, timedelta, timezone
from dateutil import parser 
from validator import Auth0JWTBearerTokenValidator
from authlib.integrations.flask_oauth2 import ResourceProtector


api_keys_path =  os.path.join(os.path.dirname(os.path.abspath(__file__)), 'api-keys.json')

def get_api_keys_data(path = api_keys_path):
    print(path)
    if os.path.exists(path):
        with open(path, 'r') as file:
            api_keys_data = json.load(file)
            
            # print(api_keys_data)
        return api_keys_data
    else:
        print(f"File '{api_keys_path}' not found.")
        return None
    

require_auth = ResourceProtector()
validator = Auth0JWTBearerTokenValidator(
    get_api_keys_data()["domain"],
    get_api_keys_data()["api_identifier"]
)
require_auth.register_token_validator(validator)
app = Flask(__name__)

SESSION_KEY = 'Authorization'
SESSION_FILE = './sessions.json'

class Session:
    def __init__(self):
        try:
            with open(SESSION_FILE, 'r') as f:
                # Load the JSON data from the file
                self.sessions = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            # Handle the case when file not found or JSON decoding error
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
        expires_at_str = sessions.get(session_id).get('expires_at')
        expires_at_utc = datetime.fromisoformat(expires_at_str).replace(tzinfo=timezone.utc)

        current_time_utc = datetime.now(timezone.utc)

        if current_time_utc > expires_at_utc:
            print("Session expired")
            return redirect('/login')
        print(f"Current time UTC - {current_time_utc}")
        print(f"expires_at_utc - {expires_at_utc}")
        if (expires_at_utc - current_time_utc).total_seconds() < 45:
            
            return 'Need to refresh', 512

        username = sessions.get(session_id).get('login')
        if username:
            return jsonify({
                'username': username,
                'logout': '/logout'
            })
    return redirect('/login')

@app.route('/api/refresh_token', methods=['POST'])
@require_auth(None)
def refresh_token_():
    data = request.json
    session_id = data.get('token')
    print("Refreshing token")
    _refresh_token = get_refresh_token(sessions.get(session_id).get('login'), sessions.get(session_id).get('password'))
    print(f"Refresh token - {_refresh_token}")
    new_access_token = refresh_access_token(_refresh_token)
    print("Access_token refreshed..")
    print(new_access_token)

    expires_at_utc = datetime.now(timezone.utc) + timedelta(seconds=new_access_token['expires_in'])
    sessions.set(new_access_token['access_token'], {
        'login': sessions.get(session_id).get('login'),
        'password': sessions.get(session_id).get('password'),
        'expires_at': expires_at_utc.isoformat()
    })
    return jsonify(new_access_token), 200
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

    # user = next((user for user in USERS if user['login'] == login and user['password'] == password), None)
    token = get_access_token_password_typ(login, password)
    if token is not None:
        # session_id = sessions.init()
        sessions.set(token['access_token'], {'login': login,
                                             'password':password,
                                              'expires_at':(datetime.now(timezone.utc) + timedelta(seconds=token['expires_in'])).isoformat()})
        # print(sessions.get(session_id))
        # token['login'] = login

        return jsonify(token), 200

    return 'Unauthorized', 401

@app.route('/api/signup', methods=['POST'])
def signup():
    
    data = request.json
    login = data.get('login')
    password = data.get('password')
    
    access_token = get_acces_token()

    response = create_user(login, password, access_token)

    if 'created_at' in response:
        return 'Signed Up', 200
    else :
        return response['message'], 401

def get_acces_token():
    api_keys_data = get_api_keys_data()
    url = f'https://{api_keys_data["domain"]}/oauth/token'
    headers = {'content-type': 'application/x-www-form-urlencoded'}
    data = {
        'grant_type': 'client_credentials',
        'audience': api_keys_data['api_identifier'],
        'client_id': api_keys_data['client_id'],
        'client_secret': api_keys_data['client_secret']
    }
    response = requests.post(url, headers=headers, data=data)
    
    return response.json()['access_token']

def create_user(login, password, access_token):
    api_keys_data = get_api_keys_data()
    url = f'https://{api_keys_data["domain"]}/api/v2/users'
    headers = {
        'content-type': 'application/x-www-form-urlencoded',
        'Authorization': f'Bearer {access_token}'
        }
    data = {
        "email":login,
        "password":password,
        "connection":"Username-Password-Authentication"
    }
    response = requests.post(url, headers=headers, data=data)
    
    return response.json()

def get_refresh_token(login, password):
    api_keys_data = get_api_keys_data()
    url = f'https://{api_keys_data["domain"]}/oauth/token'
    headers = {'content-type': 'application/x-www-form-urlencoded'}
    data = {
        'grant_type': 'password',
        'username': login,
        'password': password,
        'audience': api_keys_data['api_identifier'],
        'scope': 'offline_access',
        'client_id': api_keys_data['client_id'],
        'client_secret': api_keys_data['client_secret'],
        'realm':'Username-Password-Authentication'
    }

    response = requests.post(url, headers=headers, data=data)
    token_data = response.json()
    print(token_data)
    return token_data['refresh_token']

def refresh_access_token(refresh_token):
    api_keys_data = get_api_keys_data()
    url = f'https://{api_keys_data["domain"]}/oauth/token'
    headers = {'content-type': 'application/x-www-form-urlencoded'}
    data = {
        'grant_type': 'refresh_token',
        'client_id': api_keys_data['client_id'],
        'client_secret': api_keys_data['client_secret'],
        'refresh_token':refresh_token
    }
    response = requests.post(url, headers=headers, data=data)
    token_data = response.json()
    print(f"New access_token - {token_data}")
    return token_data
    

def get_access_token_password_typ(login, password):
    api_keys_data = get_api_keys_data()
    url = f'https://{api_keys_data["domain"]}/oauth/token'
    headers = {'content-type': 'application/x-www-form-urlencoded'}
    data = {
        'grant_type': 'password',
        'username': login,
        'password': password,
        'audience': api_keys_data['api_identifier'],
        # 'scope': 'read:users update:users',
        'client_id': api_keys_data['client_id'],
        'client_secret': api_keys_data['client_secret']
    }
# myuser@example.com
# NEWSTRONGER$#strong123PASWORD
    response = requests.post(url, headers=headers, data=data)
    token_data = response.json()
    print(token_data)
    return token_data

if __name__ == '__main__':
    app.run(debug=True, port=5000)
