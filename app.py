from flask import Flask, request, jsonify, render_template, redirect, url_for, make_response
from flask_cors import CORS
import jwt
import datetime
import json
import os
from azure.storage.blob import BlobServiceClient
from werkzeug.security import generate_password_hash, check_password_hash

connect_str = os.getenv("CONNECT_STR")
function_str = os.getenv("FUNCTION_STR")

blob_service_client = BlobServiceClient.from_connection_string(connect_str)
container = "data"

app = Flask(__name__)

app.secret_key = os.getenv("SECRET_KEY")

cors = CORS(app)

def authenticate(token):
    username = decode_token(token)
    if not username:
        return False, None

    blob_client = blob_service_client.get_blob_client(container=container, blob=username)
    if blob_client.exists():
        return True, username
    return False, None

def create_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    return jwt.encode(payload, app.secret_key, algorithm='HS256')

def decode_token(token):
    try:
        payload = jwt.decode(token, app.secret_key, algorithms=['HS256'])
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

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

    try:
        blob = blob_client.download_blob().readall()
        user_data = json.loads(blob)
    except:
        return jsonify({'message': 'Invalid username or password.'})

    if not blob_client.exists() or not check_password_hash(user_data['password'], password):
        return jsonify({'message': 'Invalid username or password.'}), 401

    token = create_token(username)
    response = make_response({'message': 'Login successful!'})
    response.set_cookie('Authorization', token, httponly=True, samesite='Lax')  # Save token in cookies
    return response, 200

@app.route('/logout', methods=['POST'])
def logout():
    response = make_response({'message': 'Logged out successfully!'})
    response.delete_cookie('Authorization')  
    return response, 200

@app.route('/', methods=['GET'])
def dashboardview():
    token = request.cookies.get('Authorization') 
    if token:
        authenticated, username = authenticate(token)
        if authenticated:
            return render_template("dashboard.html", username=username, function_str=function_str)
    return redirect(url_for('loginview'))  

if __name__ == '__main__':
    app.run(debug=True)