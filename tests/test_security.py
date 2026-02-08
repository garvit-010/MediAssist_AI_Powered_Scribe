import pytest
from app.models import User, Case, EncryptedString
from cryptography.fernet import Fernet
import os

def test_encryption_decryption(app, db_session):
    with app.app_context():
        from app.extensions import db
        # cipher_suite is now initialized in conftest.py
        user = User(
            username='secret_user',
            password_hash='...',
            role='patient',
            full_name='Sensitive Name'
        )
        db_session.add(user)
        db_session.commit()
        
        # Check DB directly to see if it's encrypted (not "Sensitive Name")
        from sqlalchemy import text
        result = db_session.execute(text(f"SELECT full_name FROM user WHERE username='secret_user'")).fetchone()
        assert result[0] != 'Sensitive Name'
        
        # Check if it decrypts automatically on access
        queried_user = User.query.filter_by(username='secret_user').first()
        assert queried_user.full_name == 'Sensitive Name'

def test_route_protection_patient(client):
    # Try to access patient intake without login
    response = client.get('/patient/intake', follow_redirects=True)
    # Should redirect to landing
    assert response.request.path == '/'

def test_route_protection_doctor(client):
    # Try to access doctor dashboard without login
    response = client.get('/doctor/dashboard', follow_redirects=True)
    # Should redirect to landing
    assert response.request.path == '/'

def test_role_access_restriction(client, authenticated_patient):
    # Patient trying to access doctor dashboard
    # app.py landing() redirects logged-in patient to /patient/intake
    response = client.get('/doctor/dashboard', follow_redirects=True)
    assert response.request.path == '/patient/intake'

def test_doctor_access_restriction(client, authenticated_doctor):
    # Doctor trying to access patient intake
    # app.py landing() redirects logged-in doctor to /doctor/dashboard
    response = client.get('/patient/intake', follow_redirects=True)
    assert response.request.path == '/doctor/dashboard'
