import pytest
from app import app, blob_service_client
import json
import os
from unittest.mock import patch
from werkzeug.security import generate_password_hash

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
    return app.test_client()

@pytest.fixture
def mock_blob_service_client():
    with patch.object(blob_service_client, 'get_blob_client') as mock_client:
        yield mock_client

def test_register(client, mock_blob_service_client):
    mock_blob_client = mock_blob_service_client.return_value
    mock_blob_client.exists.return_value = False

    response = client.post('/register', json={
        'username': 'testuser',
        'password': 'password123'
    })

    assert response.status_code == 201
    assert b'Registration successful!' in response.data

    mock_blob_client.exists.return_value = True
    response = client.post('/register', json={
        'username': 'testuser',
        'password': 'password123'
    })

    assert response.status_code == 400
    assert b'Username already exists.' in response.data

def test_login(client, mock_blob_service_client):
    mock_blob_client = mock_blob_service_client.return_value
    mock_blob_client.exists.return_value = True
    mock_blob_client.download_blob.return_value.readall.return_value = json.dumps({
        'username': 'Jan',
        'password': generate_password_hash('password123')
    })

    with patch('werkzeug.security.check_password_hash') as mock_check_password:
        mock_check_password.return_value = True

        response = client.post('/login', json={
            'username': 'Jan',
            'password': 'password123'
        })


        assert response.status_code == 200
        cookies = response.headers.getlist('Set-Cookie')
        assert any('Authorization' in cookie for cookie in cookies)

def test_login_invalid_password(client, mock_blob_service_client):
    mock_blob_client = mock_blob_service_client.return_value
    mock_blob_client.exists.return_value = True
    mock_blob_client.download_blob.return_value.readall.return_value = json.dumps({
        'username': 'testuser',
        'password': 'hashedpassword'
    })

    with patch('werkzeug.security.check_password_hash') as mock_check_password:
        mock_check_password.return_value = False

        response = client.post('/login', json={
            'username': 'testuser',
            'password': 'wrongpassword'
        })

        assert response.status_code == 401
        assert b'Invalid username or password.' in response.data

def test_dashboard(client, mock_blob_service_client):
    mock_blob_client = mock_blob_service_client.return_value
    mock_blob_client.exists.return_value = True
    mock_blob_client.download_blob.return_value.readall.return_value = json.dumps({
        'username': 'testuser',
        'password': generate_password_hash('password123')  
    })

    with patch('werkzeug.security.check_password_hash') as mock_check_password:
        mock_check_password.return_value = True

        response = client.post('/login', json={
            'username': 'testuser',
            'password': 'password123'
        })

        cookies = response.headers.getlist('Set-Cookie')
        token = None
        for cookie in cookies:
            if 'Authorization' in cookie:
                token = cookie.split('=')[1].split(';')[0]  

        assert token is not None, "Token is missing in the cookies."

        headers = {
            'Cookie': f'Authorization={token}'
        }

        response = client.get('/', headers=headers)

        assert response.status_code == 200
        assert b'Dashboard' in response.data  




def test_logout(client):
    response = client.post('/logout')

    assert response.status_code == 200

    assert b'Logged out successfully!' in response.data

    cookies = response.headers.getlist('Set-Cookie')
    assert any('Authorization=;' in cookie for cookie in cookies), "Authorization cookie was not removed."

