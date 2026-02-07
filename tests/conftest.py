"""
Pytest configuration and shared fixtures for MediAssist tests.
"""
from __future__ import annotations

import os
import sys
from datetime import datetime
from typing import Any, Generator
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask
from flask.testing import FlaskClient

# Ensure the app module is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Set testing environment variables before importing app
os.environ["TESTING"] = "true"
os.environ["FLASK_SECRET_KEY"] = "test-secret-key"
os.environ["FERNET_KEY"] = "tW_xNc0yDqX9CpxqpKN6I3sZ9r1G2v6BAAFL5X9K9Rc="  # Test key


@pytest.fixture(scope="session")
def mock_whisper() -> Generator[MagicMock, None, None]:
    """Mock the whisper model loading to avoid loading heavy models in tests."""
    with patch("whisper.load_model") as mock_load:
        mock_model = MagicMock()
        mock_model.transcribe.return_value = {"text": "Test transcription"}
        mock_load.return_value = mock_model
        yield mock_model


@pytest.fixture(scope="function")
def app(mock_whisper: MagicMock) -> Generator[Flask, None, None]:
    """Create application for testing with in-memory SQLite database."""
    # Import here to ensure mock is applied
    with patch("whisper.load_model", return_value=mock_whisper):
        from app import app as flask_app, db

        flask_app.config.update({
            "TESTING": True,
            "WTF_CSRF_ENABLED": False,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "SESSION_COOKIE_SECURE": False,
            "SERVER_NAME": "localhost.localdomain",
        })

        with flask_app.app_context():
            db.create_all()
            yield flask_app
            db.session.remove()
            db.drop_all()


@pytest.fixture(scope="function")
def client(app: Flask) -> FlaskClient:
    """Create a test client for the Flask application."""
    return app.test_client()


@pytest.fixture(scope="function")
def db_session(app: Flask) -> Generator[Any, None, None]:
    """Provide a transactional database session for tests."""
    from app import db
    
    with app.app_context():
        connection = db.engine.connect()
        transaction = connection.begin()
        
        yield db.session
        
        db.session.rollback()
        transaction.rollback()
        connection.close()


@pytest.fixture
def sample_user_data() -> dict[str, Any]:
    """Sample user data for testing."""
    return {
        "username": "testpatient",
        "password": "TestPassword123!",
        "role": "patient",
        "full_name": "John Test Patient",
        "specialty": None,
        "doctor_unique_id": None,
    }


@pytest.fixture
def sample_doctor_data() -> dict[str, Any]:
    """Sample doctor data for testing."""
    return {
        "username": "testdoctor",
        "password": "DoctorPassword123!",
        "role": "doctor",
        "full_name": "Dr. Jane Test",
        "specialty": "General Medicine",
        "doctor_unique_id": "DOC001",
    }


@pytest.fixture
def sample_case_data() -> dict[str, Any]:
    """Sample case data for testing."""
    return {
        "id": "TEST1234",
        "patient_id": 1,
        "doctor_id": 2,
        "timestamp": datetime.now(),
        "raw_data": {
            "patient_name": "John Doe",
            "age": "45",
            "gender": "Male",
            "symptoms": "Fever and headache for 3 days",
            "temp": "38.5",
            "bp": "120/80",
            "weight": "75",
            "height": "175",
            "allergies": "None",
            "current_meds": "None",
            "language": "English",
        },
        "ai_analysis": {
            "patient_view": {
                "primary_diagnosis": "Viral Fever",
                "summary": "You have a mild viral infection.",
                "pathophysiology": "Your body is fighting a virus.",
                "care_plan": ["Rest", "Stay hydrated"],
                "red_flags": ["High fever above 39.5C"],
                "severity_score": 3,
            },
            "doctor_view": {
                "subjective": "Patient reports fever for 3 days.",
                "objective": "Temp 38.5C, BP 120/80",
                "assessment": "Likely viral illness",
                "plan": "Supportive care, follow up if worsening",
                "subjective_list": ["Fever 3 days", "Headache"],
                "objective_list": ["Temp 38.5C", "BP 120/80"],
                "assessment_list": ["Viral fever", "Rule out bacterial"],
                "plan_list": ["Rest", "Paracetamol PRN"],
                "possible_conditions": [
                    {"name": "Viral Fever", "confidence": 0.85},
                    {"name": "Flu", "confidence": 0.60},
                ],
                "urgency_level": "Low",
                "follow_up_required": True,
            },
            "safety": {"is_safe": True, "warnings": []},
        },
        "status": "Pending Review",
    }


@pytest.fixture
def authenticated_patient_session(
    client: FlaskClient, app: Flask, sample_user_data: dict[str, Any]
) -> Generator[FlaskClient, None, None]:
    """Create a client with an authenticated patient session."""
    from app import db, User
    from werkzeug.security import generate_password_hash

    with app.app_context():
        user = User(
            username=sample_user_data["username"],
            password_hash=generate_password_hash(sample_user_data["password"]),
            role="patient",
            full_name=sample_user_data["full_name"],
        )
        db.session.add(user)
        db.session.commit()
        user_id = user.id

    with client.session_transaction() as sess:
        sess["user_id"] = user_id
        sess["role"] = "patient"
        sess["account_name"] = sample_user_data["full_name"]

    yield client


@pytest.fixture
def authenticated_doctor_session(
    client: FlaskClient, app: Flask, sample_doctor_data: dict[str, Any]
) -> Generator[FlaskClient, None, None]:
    """Create a client with an authenticated doctor session."""
    from app import db, User
    from werkzeug.security import generate_password_hash

    with app.app_context():
        user = User(
            username=sample_doctor_data["username"],
            password_hash=generate_password_hash(sample_doctor_data["password"]),
            role="doctor",
            full_name=sample_doctor_data["full_name"],
            specialty=sample_doctor_data["specialty"],
            doctor_unique_id=sample_doctor_data["doctor_unique_id"],
        )
        db.session.add(user)
        db.session.commit()
        user_id = user.id

    with client.session_transaction() as sess:
        sess["user_id"] = user_id
        sess["role"] = "doctor"
        sess["account_name"] = sample_doctor_data["full_name"]

    yield client
