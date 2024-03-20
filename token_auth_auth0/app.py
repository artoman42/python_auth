from flask import Flask, request, jsonify, redirect, send_file
from json import JSONEncoder
import json
import uuid
import requests
import os
import json
import datetime
from dateutil import parser 
app = Flask(__name__)

SESSION_KEY = 'Authorization'
SESSION_FILE = './sessions.json'

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
    # print(f"Session_id - {session_id}")
    if session_id:
        # print(sessions.get(session_id))
        # print(session_id)
        # print(sessions.get(session_id))
        
        
        expires_at = parser.parse(sessions.get(session_id).get('expires_at')).replace(tzinfo=None) #, '%Y-%m-%dT%H:%M:%S.%f%z'
        print(f"Expires at - {expires_at}")
        print(f"Now - {datetime.datetime.now()}")
        print(f"{datetime.datetime.now() < expires_at}")
        if datetime.datetime.now() > expires_at:
            print("Session expired")
            return redirect('/login')
        
        if (expires_at - datetime.datetime.now()).total_seconds() < 30:
            print("Refreshing token")
            refresh_token = get_refresh_token(sessions.get(session_id).get('login'), sessions.get(session_id).get('password'))
            print(f"Refresh token - {refresh_token}")
            new_access_token = refresh_access_token(refresh_token)
            print("Access_token refreshed..")
            sessions.set(new_access_token['access_token'], {'login': sessions.get(session_id).get('login'),
                                             'password': sessions.get(session_id).get('password'),
                                              'expires_at':(datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(seconds=new_access_token['expires_in'])).isoformat()})
            # print(sessions.get(session_id))
            # token['login'] = login

            return redirect('/')

        username = sessions.get(session_id).get('login')
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

    # user = next((user for user in USERS if user['login'] == login and user['password'] == password), None)
    token = get_access_token_password_typ(login, password)
    if token is not None:
        # session_id = sessions.init()
        sessions.set(token['access_token'], {'login': login,
                                             'password':password,
                                              'expires_at':(datetime.datetime.now() + datetime.timedelta(seconds=token['expires_in'])).isoformat()})
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
