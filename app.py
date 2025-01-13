from flask import Flask, request, jsonify
from flask_cors import CORS, cross_origin
from flask_sqlalchemy import SQLAlchemy
import pyodbc
import jwt
import datetime
from werkzeug.security import generate_password_hash, check_password_hash

# App configuration
app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = (
    'mssql+pyodbc://<USERNAME>:<PASSWORD>@<SERVER>/<DATABASE>?driver=ODBC+Driver+18+for+SQL+Server'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

cors = CORS(app)

db = SQLAlchemy(app)

# Database model
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

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
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Username already exists.'}), 400

    hashed_password = generate_password_hash(password, method='sha256')
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'Registration successful!'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({'message': 'Invalid username or password.'}), 401

    token = create_token(user.id)
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
    with app.app_context():
        db.create_all()  # Ensure all database tables are created
    app.run(debug=True)