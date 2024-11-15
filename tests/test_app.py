import sys
import os
import pytest

# Add the Backend directory to the system path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Backend')))

from Backend.app import app  # Import the Flask app from Backend.app

# Now you can proceed with your tests


@pytest.fixture
def client():
    with app.test_client() as client:
        yield client

def test_admin_dashboard(client):
    response = client.get('/admin-dashboard')
    assert response.status_code == 200
    assert b'Admin Dashboard' in response.data

def test_promote_user(client):
    response = client.post('/promote_user/user@example.com')
    assert response.status_code == 302  # Redirect
    assert b'admin' in str(response.data)

def test_demote_user(client):
    response = client.post('/demote_user/admin@example.com')
    assert response.status_code == 302  # Redirect
    assert b'user' in str(response.data)
