import pytest
from app.extensions import db
from app.models import User, Case
from flask import session

def test_get_user_by_username_none(app):
    with app.app_context():
        from app.utils import get_user_by_username
        assert get_user_by_username(None) is None

def test_get_user_by_id_invalid(app):
    with app.app_context():
        from app.utils import get_user_by_id
        assert get_user_by_id("invalid") is None
        assert get_user_by_id(None) is None

def test_patient_login_wrong_password(client, app):
    from werkzeug.security import generate_password_hash
    with app.app_context():
        user = User(username="p_login", password_hash=generate_password_hash("correct"), role="patient", full_name="P")
        db.session.add(user)
        db.session.commit()
    
    response = client.post('/patient/login', data={
        "username": "p_login",
        "password": "wrong"
    }, follow_redirects=True)
    assert "Invalid username or password" in response.data.decode()

def test_patient_login_user_not_found(client):
    response = client.post('/patient/login', data={
        "username": "nonexistent",
        "password": "password"
    }, follow_redirects=True)
    assert "Invalid username or password" in response.data.decode()

def test_doctor_login_user_not_found(client):
    response = client.post('/doctor/login', data={
        "username": "nonexistent_doc",
        "password": "password"
    }, follow_redirects=True)
    assert "Invalid credentials" in response.data.decode()

def test_get_doctor_cases_not_found(app):
    with app.app_context():
        from app.utils import get_cases_for_doctor
        # Assuming ID 99999 doesn't exist
        assert get_cases_for_doctor(99999) == []

def test_doctor_edit_exception(client, app, db_session, mocker):
    from werkzeug.security import generate_password_hash
    with app.app_context():
        doctor = User(username="edit_ex_doc", password_hash=generate_password_hash("p"), role="doctor", full_name="D")
        patient = User(username="edit_ex_pat", password_hash=generate_password_hash("p"), role="patient", full_name="P")
        db_session.add_all([doctor, patient])
        db_session.commit()
        case = Case(id="EX_CASE", patient_id=patient.id, doctor_id=doctor.id, raw_data={}, ai_analysis={"doctor_view": {}}, status="Pending")
        db_session.add(case)
        db_session.commit()
        
        with client.session_transaction() as sess:
            sess['user_id'] = doctor.id
            sess['role'] = 'doctor'
            
        # Mock commit to raise exception
        mocker.patch('app.db.session.commit', side_effect=Exception("DB Error"))
        
        response = client.post('/doctor/edit/EX_CASE', data={
            "subjective[]": ["Test"]
        }, follow_redirects=True)
        assert "Error updating case" in response.data.decode()

def test_patient_result_not_found(client, app, db_session):
    from werkzeug.security import generate_password_hash
    with app.app_context():
        patient = User(username="res_p", password_hash=generate_password_hash("p"), role="patient", full_name="P")
        db_session.add(patient)
        db_session.commit()
        with client.session_transaction() as sess:
            sess['user_id'] = patient.id
            sess['role'] = 'patient'
        response = client.get('/patient/result/NONEXISTENT', follow_redirects=True)
        assert "Case not found" in response.data.decode()

def test_patient_result_access_denied(client, app, db_session):
    from werkzeug.security import generate_password_hash
    with app.app_context():
        p1 = User(username="res_p1", password_hash=generate_password_hash("p"), role="patient", full_name="P1")
        p2 = User(username="res_p2", password_hash=generate_password_hash("p"), role="patient", full_name="P2")
        db_session.add_all([p1, p2])
        db_session.commit()
        case = Case(id="P1_CASE", patient_id=p1.id, doctor_id=1, raw_data={}, ai_analysis={}, status="Pending")
        db_session.add(case)
        db_session.commit()
        
        with client.session_transaction() as sess:
            sess['user_id'] = p2.id
            sess['role'] = 'patient'
        response = client.get('/patient/result/P1_CASE', follow_redirects=True)
        assert "Case not found or access denied." in response.data.decode()

def test_transcribe_audio_no_model(client, app, db_session, mocker):
    from werkzeug.security import generate_password_hash
    with app.app_context():
        patient = User(username="trans_p", password_hash=generate_password_hash("p"), role="patient", full_name="P")
        db_session.add(patient)
        db_session.commit()
        with client.session_transaction() as sess:
            sess['user_id'] = patient.id
            sess['role'] = 'patient'
            
        mocker.patch('app.routes.main.get_audio_model', return_value=None)
        import io
        data = {'audio': (io.BytesIO(b"fake audio"), 'test.webm')}
        response = client.post('/transcribe', data=data, content_type='multipart/form-data')
        assert response.status_code == 503
        assert "Transcriber model not loaded" in response.json['error']

def test_transcribe_audio_empty_filename(client, app, db_session):
    from werkzeug.security import generate_password_hash
    with app.app_context():
        patient = User(username="trans_p2", password_hash=generate_password_hash("p"), role="patient", full_name="P")
        db_session.add(patient)
        db_session.commit()
        with client.session_transaction() as sess:
            sess['user_id'] = patient.id
            sess['role'] = 'patient'
            
        import io
        data = {'audio': (io.BytesIO(b""), '')}
        response = client.post('/transcribe', data=data, content_type='multipart/form-data')
        assert response.status_code == 400
        assert "No selected file" in response.json['error']

def test_set_language_invalid(client):
    response = client.get('/set_language/invalid_lang', follow_redirects=True)
    assert response.status_code == 200

def test_ratelimit_handler(client):
    from app.utils import ratelimit_handler
    with client.application.test_request_context():
        response = ratelimit_handler(Exception("limit"))
        assert response.status_code == 302
