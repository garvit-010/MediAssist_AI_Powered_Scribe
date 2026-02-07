import pytest
import json
from unittest.mock import patch, MagicMock
from app import db, User, Case

def test_patient_intake_submission_success(client, authenticated_patient, mocker):
    # Mock Ollama API response
    mock_ollama_response = MagicMock()
    mock_ollama_response.status_code = 200
    mock_ollama_response.json.return_value = {
        "response": json.dumps({
            "patient_view": {
                "primary_diagnosis": "Viral Fever",
                "summary": "You have a viral fever.",
                "pathophysiology": "Your body is fighting a virus.",
                "care_plan": ["Rest"],
                "red_flags": ["High fever"],
                "severity_score": 3
            },
            "doctor_view": {
                "subjective": "Patient reports fever.",
                "objective": "Temp 38C",
                "assessment": "Viral illness",
                "plan": "Supportive care",
                "subjective_list": ["Fever"],
                "objective_list": ["Temp 38C"],
                "assessment_list": ["Viral illness"],
                "plan_list": ["Rest"],
                "urgency_level": "Low",
                "follow_up_required": False
            },
            "safety": {"is_safe": True, "warnings": []}
        })
    }
    mocker.patch('requests.post', return_value=mock_ollama_response)

    # Create a doctor for the intake
    with client.application.app_context():
        doctor = User(username='doc1', password_hash='...', role='doctor', full_name='Dr. Smith')
        db.session.add(doctor)
        db.session.commit()
        doctor_id = doctor.id

    # Submit intake form
    data = {
        'symptoms': 'I have a high fever and headache since yesterday.',
        'doctor_id': str(doctor_id),
        'language': 'English',
        'age': '30',
        'gender': 'Male',
        'temperature': '38.5',
        'blood_pressure': '120/80'
    }
    
    response = client.post('/patient/submit', data=data, follow_redirects=True)
    
    assert response.status_code == 200
    # Check if case was created in DB
    with client.application.app_context():
        case = Case.query.filter_by(patient_id=authenticated_patient.id).first()
        assert case is not None
        assert case.ai_analysis['patient_view']['primary_diagnosis'] == "Viral Fever"

def test_patient_intake_ai_fallback(client, authenticated_patient, mocker):
    # Mock ConnectionError for Ollama
    import requests
    mocker.patch('requests.post', side_effect=requests.exceptions.ConnectionError)

    # Create a doctor
    with client.application.app_context():
        doctor = User(username='doc2', password_hash='...', role='doctor', full_name='Dr. Jones')
        db.session.add(doctor)
        db.session.commit()
        doctor_id = doctor.id

    data = {
        'symptoms': 'Fever and chills for two days.',
        'doctor_id': str(doctor_id),
        'language': 'English'
    }
    
    response = client.post('/patient/submit', data=data, follow_redirects=True)
    
    assert response.status_code == 200
    # Check if fallback analysis was used
    with client.application.app_context():
        case = Case.query.filter_by(patient_id=authenticated_patient.id).first()
        assert case is not None
        # Verify it's the fallback analysis (which uses build_predefined_ai_analysis)
        assert case.ai_analysis['patient_view']['primary_diagnosis'] == 'Fever and chills for two days.'

def test_voice_transcription_endpoint(client, authenticated_patient, mocker):
    # Mock Whisper model
    mock_whisper = MagicMock()
    mock_whisper.transcribe.return_value = {"text": "I feel sick."}
    mocker.patch('app.audio_model', mock_whisper)
    
    # Mock temp file operations to avoid actual file system usage if possible
    # or just let it write to a temp file since it's a test
    
    data = {
        'audio': (MagicMock(), 'test.webm')
    }
    
    response = client.post('/transcribe', data=data, content_type='multipart/form-data')
    
    assert response.status_code == 200
    assert response.json['text'] == "I feel sick."
