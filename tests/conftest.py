import pytest
import os
import tempfile
from cryptography.fernet import Fernet

# Set encryption key BEFORE importing app so cipher_suite is initialized correctly
os.environ["FERNET_KEY"] = Fernet.generate_key().decode()

from app import app as flask_app, db as _db, User

@pytest.fixture
def app():
    # Setup test configuration
    db_fd, db_path = tempfile.mkstemp()
    flask_app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
    flask_app.config['TESTING'] = True
    flask_app.config['WTF_CSRF_ENABLED'] = False
    flask_app.config['SECRET_KEY'] = 'test_secret_key'
    
    # Ensure Whisper doesn't load for every test if possible, or mock it
    # For now, we assume it's already loaded or we mock it in specific tests
    
    with flask_app.app_context():
        _db.create_all()
        yield flask_app
        _db.session.remove()
        _db.drop_all()

    os.close(db_fd)
    os.unlink(db_path)

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def db(app):
    return _db

@pytest.fixture
def runner(app):
    return app.test_cli_runner()

@pytest.fixture
def authenticated_patient(client, app):
    with app.app_context():
        from werkzeug.security import generate_password_hash
        patient = User(
            username='test_patient',
            password_hash=generate_password_hash('password'),
            role='patient',
            full_name='Test Patient'
        )
        _db.session.add(patient)
        _db.session.commit()
        
        with client.session_transaction() as sess:
            sess['user_id'] = patient.id
            sess['role'] = 'patient'
            sess['account_name'] = 'Test Patient'
            sess['language'] = 'en'
            
        return patient

@pytest.fixture
def authenticated_doctor(client, app):
    with app.app_context():
        from werkzeug.security import generate_password_hash
        doctor = User(
            username='test_doctor',
            password_hash=generate_password_hash('password'),
            role='doctor',
            full_name='Dr. Test',
            specialty='General Medicine'
        )
        _db.session.add(doctor)
        _db.session.commit()
        
        with client.session_transaction() as sess:
            sess['user_id'] = doctor.id
            sess['role'] = 'doctor'
            sess['name'] = 'Dr. Test'
            sess['language'] = 'en'
            
        return doctor
