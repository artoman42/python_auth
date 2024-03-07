from flask import Flask, request, Response
import base64

app = Flask(__name__)
port = 3000

@app.route('/')
def index():
    authorization_header = request.headers.get('Authorization')
    print('\n=======================================================\n')
    print('authorization_header', authorization_header)

    if not authorization_header:
        return Response('Unauthorized', 401, {'WWW-Authenticate': 'Basic realm="Ukraine"'})

    authorization_base64_part = authorization_header.split(' ')[1]
    decoded_authorization_header = base64.b64decode(authorization_base64_part).decode('utf-8')
    print('decoded_authorization_header', decoded_authorization_header)

    login, password = decoded_authorization_header.split(':')
    print('Login/Password', login, password)

    if login == 'DateArt' and password == '2408':
        return 'Hello ' + login
    else:
        return Response('Unauthorized', 401, {'WWW-Authenticate': 'Basic realm="Ukraine"'})

if __name__ == '__main__':
    app.run(port=port)
