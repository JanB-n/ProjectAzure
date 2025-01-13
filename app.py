from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import jwt
import datetime
import json
from azure.storage.blob import BlobServiceClient
from werkzeug.security import generate_password_hash, check_password_hash

connect_str = ""
blob_service_client = BlobServiceClient.from_connection_string(connect_str)
container = "data"

# App configuration
app = Flask(__name__)

#do wywalenia do env
app.secret_key = 'this_is_the_most_secret_key'


cors = CORS(app)


# Utility function to create JWT token
def create_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)
    }
    return jwt.encode(payload, app.secret_key, algorithm='HS256')

# Utility function to decode JWT token
def decode_token(token):
    try:
        payload = jwt.decode(token, app.secret_key, algorithms=['HS256'])
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# Routes
@app.route('/register', methods=['GET'])
def registerview():
    return render_template('register.html')


@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    blob_client = blob_service_client.get_blob_client(container=container, blob=username)
    if blob_client.exists():
        return jsonify({'message': 'Username already exists.'}), 400

    hashed_password = generate_password_hash(password)

    data = {"username": username, "password": hashed_password}

    blob_client.upload_blob(data=json.dumps(data))

    return jsonify({'message': 'Registration successful!'}), 201

@app.route('/login', methods=['GET'])
def loginview():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    blob_client = blob_service_client.get_blob_client(container=container, blob=username)

    blob = blob_client.download_blob().readall()
    try:
        data = json.loads(blob)
    except:
        return jsonify({'message': 'Data was saved in a bad format.'}), 400

    if not blob_client.exists() or not check_password_hash(data['password'], password):
        return jsonify({'message': 'Invalid username or password.'}), 401

    token = create_token(data['username'])
    print(token)
    return jsonify({'token': token}), 200


@app.route('/dashboard', methods=['GET'])
def dashboard():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'message': 'Token is missing.'}), 401

    token = auth_header.split(' ')[1]
    user_id = decode_token(token)
    if not user_id:
        return jsonify({'message': 'Invalid or expired token.'}), 401

    return jsonify({'message': 'Welcome to the dashboard!', 'user_id': user_id}), 200

@app.route('/logout', methods=['POST'])
def logout():
    # JWT logout is typically handled on the client-side by discarding the token.
    return jsonify({'message': 'Logout successful.'}), 200

# Main entry point
if __name__ == '__main__':
    app.run(debug=True)