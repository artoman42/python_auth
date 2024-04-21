from flask import Flask, request, jsonify, redirect, send_file
from json import JSONEncoder
import json
import uuid
import requests
import os
import json
from datetime import datetime, timedelta, timezone
from dateutil import parser 

from urllib.parse import quote_plus, urlencode

from authlib.integrations.flask_client import OAuth
# from dotenv import find_dotenv, load_dotenv
from flask import Flask, redirect, render_template, session, url_for

with open('./api-keys.json', 'r') as file:
    env = json.load(file)

app = Flask(__name__)

app.secret_key = env.get("APP_SECRET_KEY")

oauth = OAuth(app)

oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration'
)

@app.route('/login', methods=['GET'])
def login_page():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )

@app.route("/callback", methods=["GET", "POST"])
def callback():
    print(f"request args - {request.args}")
    code = request.args.get("code")
    print(f'code  - {code}')
    token = oauth.auth0.authorize_access_token()
    print(f"token - {token}")
    # token_2 = get_access_token_by_code(code)
    # print(f"token_2 - {token_2}")
    session["user"] = token
    session["code"] = code
    return redirect('/')

# myexample@xmail.com
# $%ThEStrOn1323

@app.route("/")
def home():
    if "code" in session:
        print(session['code'])
    print(f"session ----- \n{session}")
    return render_template("home.html", session=session.get('user'), pretty=json.dumps(session.get('user'), indent=4))


@app.route('/logout', methods=['GET'])
def logout():
    session.clear()
    return redirect(
        "https://" + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )

def get_access_token_by_code(code):
    token_endpoint = f"https://{env.get('AUTH0_DOMAIN')}/oauth/token"
    token_response = requests.post(
        token_endpoint,
        json={
            "client_id": env.get("AUTH0_CLIENT_ID"),
            "client_secret": env.get("AUTH0_CLIENT_SECRET"),
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": url_for("callback", _external=True)
        }
    )
    if token_response.status_code == 200:
        token_data = token_response.json()
        print(token_data)
        access_token = token_data.get("access_token")

        return access_token
    else:
        return "Failed to exchange authorization code for access token", 400

if __name__ == '__main__':
    app.run(debug=True, port=3000)
