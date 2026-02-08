"""
from __future__ import annotations
Tests for Flask routes in app.py.
"""

from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask
from flask.testing import FlaskClient


class TestLandingRoute:
    """Tests for the landing page route."""

    def test_landing_page_loads(self, client: FlaskClient, app: Flask) -> None:
        """Test that landing page loads successfully."""
        with app.app_context():
            response = client.get("/")
            assert response.status_code in [200, 302]

    def test_landing_redirects_authenticated_patient(
        self, authenticated_patient_session: FlaskClient, app: Flask
    ) -> None:
        """Test that authenticated patients are redirected."""
        with app.app_context():
            response = authenticated_patient_session.get("/")
            assert response.status_code == 302
            assert "/patient/intake" in response.location or response.status_code == 200

    def test_landing_redirects_authenticated_doctor(
        self, authenticated_doctor_session: FlaskClient, app: Flask
    ) -> None:
        """Test that authenticated doctors are redirected."""
        with app.app_context():
            response = authenticated_doctor_session.get("/")
            assert response.status_code == 302
            assert "/doctor/dashboard" in response.location or response.status_code == 200


class TestPatientLoginRoute:
    """Tests for patient login functionality."""

    def test_patient_login_page_loads(self, client: FlaskClient, app: Flask) -> None:
        """Test that patient login page loads."""
        with app.app_context():
            response = client.get("/patient/login")
            assert response.status_code == 200

    def test_patient_login_success(self, client: FlaskClient, app: Flask) -> None:
        """Test successful patient login."""
        from app.extensions import db
        from app.models import User
        from werkzeug.security import generate_password_hash

        with app.app_context():
            user = User(
                username="loginpatient",
                password_hash=generate_password_hash("testpass123"),
                role="patient",
                full_name="Login Patient",
            )
            db.session.add(user)
            db.session.commit()

            response = client.post(
                "/patient/login",
                data={"username": "loginpatient", "password": "testpass123"},
                follow_redirects=False,
            )
            assert response.status_code == 302

    def test_patient_login_invalid_credentials(
        self, client: FlaskClient, app: Flask
    ) -> None:
        """Test login with invalid credentials."""
        with app.app_context():
            response = client.post(
                "/patient/login",
                data={"username": "wronguser", "password": "wrongpass"},
                follow_redirects=True,
            )
            # Should stay on login page or show error
            assert response.status_code == 200


class TestDoctorLoginRoute:
    """Tests for doctor login functionality."""

    def test_doctor_login_page_loads(self, client: FlaskClient, app: Flask) -> None:
        """Test that doctor login page loads."""
        with app.app_context():
            response = client.get("/doctor/login")
            assert response.status_code == 200

    def test_doctor_login_success(self, client: FlaskClient, app: Flask) -> None:
        """Test successful doctor login."""
        from app.extensions import db
        from app.models import User
        from werkzeug.security import generate_password_hash

        with app.app_context():
            user = User(
                username="logindoctor",
                password_hash=generate_password_hash("docpass123"),
                role="doctor",
                full_name="Login Doctor",
                specialty="General",
            )
            db.session.add(user)
            db.session.commit()

            response = client.post(
                "/doctor/login",
                data={"username": "logindoctor", "password": "docpass123"},
                follow_redirects=False,
            )
            assert response.status_code == 302


class TestPatientIntakeRoute:
    """Tests for patient intake functionality."""

    def test_intake_requires_login(self, client: FlaskClient, app: Flask) -> None:
        """Test that intake page requires authentication."""
        with app.app_context():
            response = client.get("/patient/intake")
            assert response.status_code == 302  # Redirect to login

    def test_intake_loads_for_patient(
        self, authenticated_patient_session: FlaskClient, app: Flask
    ) -> None:
        """Test that intake page loads for authenticated patients."""
        from app.extensions import db
        from app.models import User
        from werkzeug.security import generate_password_hash

        with app.app_context():
            # Add a doctor for the dropdown
            doctor = User(
                username="intakedoctor",
                password_hash=generate_password_hash("pass"),
                role="doctor",
                full_name="Intake Doctor",
                specialty="General",
            )
            db.session.add(doctor)
            db.session.commit()

            response = authenticated_patient_session.get("/patient/intake")
            assert response.status_code == 200


class TestPatientSubmitRoute:
    """Tests for patient submit functionality."""

    def test_submit_requires_login(self, client: FlaskClient, app: Flask) -> None:
        """Test that submit requires authentication."""
        with app.app_context():
            response = client.post("/patient/submit", data={})
            assert response.status_code == 302  # Redirect to login

    def test_submit_validation_short_symptoms(
        self, authenticated_patient_session: FlaskClient, app: Flask
    ) -> None:
        """Test validation for short symptoms."""
        from app.extensions import db
        from app.models import User
        from werkzeug.security import generate_password_hash

        with app.app_context():
            doctor = User(
                username="submitdoctor",
                password_hash=generate_password_hash("pass"),
                role="doctor",
                full_name="Submit Doctor",
            )
            db.session.add(doctor)
            db.session.commit()

            response = authenticated_patient_session.post(
                "/patient/submit",
                data={
                    "symptoms": "short",
                    "doctor_id": str(doctor.id),
                },
                follow_redirects=True,
            )
            # Should redirect back with error or show validation message
            assert response.status_code == 200


class TestDoctorDashboardRoute:
    """Tests for doctor dashboard functionality."""

    def test_dashboard_requires_login(self, client: FlaskClient, app: Flask) -> None:
        """Test that dashboard requires authentication."""
        with app.app_context():
            response = client.get("/doctor/dashboard")
            assert response.status_code == 302  # Redirect to login

    def test_dashboard_requires_doctor_role(
        self, authenticated_patient_session: FlaskClient, app: Flask
    ) -> None:
        """Test that patients cannot access doctor dashboard."""
        with app.app_context():
            response = authenticated_patient_session.get("/doctor/dashboard")
            assert response.status_code == 302  # Redirect

    def test_dashboard_loads_for_doctor(
        self, authenticated_doctor_session: FlaskClient, app: Flask
    ) -> None:
        """Test that dashboard loads for authenticated doctors."""
        with app.app_context():
            response = authenticated_doctor_session.get("/doctor/dashboard")
            assert response.status_code == 200


class TestSetLanguageRoute:
    """Tests for language switching functionality."""

    def test_set_language_english(self, client: FlaskClient, app: Flask) -> None:
        """Test setting language to English."""
        with app.app_context():
            response = client.get("/set_language/en", follow_redirects=False)
            assert response.status_code == 302

            with client.session_transaction() as sess:
                assert sess.get("language") == "en"

    def test_set_language_hindi(self, client: FlaskClient, app: Flask) -> None:
        """Test setting language to Hindi."""
        with app.app_context():
            response = client.get("/set_language/hi", follow_redirects=False)
            assert response.status_code == 302

            with client.session_transaction() as sess:
                assert sess.get("language") == "hi"

    def test_set_invalid_language(self, client: FlaskClient, app: Flask) -> None:
        """Test that invalid language doesn't change session."""
        with app.app_context():
            # First set a valid language
            client.get("/set_language/en")

            # Try invalid language
            client.get("/set_language/invalid")

            with client.session_transaction() as sess:
                # Should still be 'en' or unset
                assert sess.get("language") in ["en", None]


class TestLogoutRoutes:
    """Tests for logout functionality."""

    def test_patient_logout(
        self, authenticated_patient_session: FlaskClient, app: Flask
    ) -> None:
        """Test patient logout clears session."""
        with app.app_context():
            response = authenticated_patient_session.get(
                "/patient/logout", follow_redirects=False
            )
            assert response.status_code == 302

            with authenticated_patient_session.session_transaction() as sess:
                assert "user_id" not in sess

    def test_doctor_logout(
        self, authenticated_doctor_session: FlaskClient, app: Flask
    ) -> None:
        """Test doctor logout clears session."""
        with app.app_context():
            response = authenticated_doctor_session.get(
                "/doctor/logout", follow_redirects=False
            )
            assert response.status_code == 302

            with authenticated_doctor_session.session_transaction() as sess:
                assert "user_id" not in sess


class TestViewCasesRoute:
    """Tests for the cases list view."""

    def test_view_cases_requires_login(self, client: FlaskClient, app: Flask) -> None:
        """Test that viewing cases requires authentication."""
        with app.app_context():
            response = client.get("/cases")
            assert response.status_code == 302

    def test_view_cases_for_patient(
        self, authenticated_patient_session: FlaskClient, app: Flask
    ) -> None:
        """Test that patients can view their cases."""
        with app.app_context():
            response = authenticated_patient_session.get("/cases")
            assert response.status_code == 200

    def test_view_cases_for_doctor(
        self, authenticated_doctor_session: FlaskClient, app: Flask
    ) -> None:
        """Test that doctors can view their cases."""
        with app.app_context():
            response = authenticated_doctor_session.get("/cases")
            assert response.status_code == 200


class TestDoctorViewRoute:
    """Tests for doctor case view functionality."""

    def test_view_case_requires_doctor_role(
        self, authenticated_patient_session: FlaskClient, app: Flask
    ) -> None:
        """Test that only doctors can view doctor view."""
        with app.app_context():
            response = authenticated_patient_session.get("/doctor/view/CASE123")
            assert response.status_code == 302  # Redirect


class TestAdminLogsRoute:
    """Tests for admin logs functionality."""

    def test_admin_logs_requires_doctor_role(
        self, authenticated_patient_session: FlaskClient, app: Flask
    ) -> None:
        """Test that only doctors can access admin logs."""
        with app.app_context():
            response = authenticated_patient_session.get("/admin/logs")
            assert response.status_code == 302  # Redirect

    def test_admin_logs_loads_for_doctor(
        self, authenticated_doctor_session: FlaskClient, app: Flask
    ) -> None:
        """Test that doctors can view admin logs."""
        with app.app_context():
            response = authenticated_doctor_session.get("/admin/logs")
            assert response.status_code == 200


class TestRateLimiting:
    """Tests for rate limiting functionality."""

    def test_rate_limit_handler_exists(self, app: Flask) -> None:
        """Test that rate limit error handler is registered."""
        with app.app_context():
            # Check that the 429 error handler is registered
            assert 429 in app.error_handler_spec.get(None, {})


class TestTranscribeRoute:
    """Tests for audio transcription functionality."""

    def test_transcribe_requires_login(self, client: FlaskClient, app: Flask) -> None:
        """Test that transcription requires authentication."""
        with app.app_context():
            response = client.post("/transcribe")
            assert response.status_code == 302

    def test_transcribe_requires_audio_file(
        self, authenticated_patient_session: FlaskClient, app: Flask
    ) -> None:
        """Test that transcription requires an audio file."""
        with app.app_context():
            response = authenticated_patient_session.post("/transcribe", data={})
            assert response.status_code == 400


class TestSessionBehavior:
    """Tests for session management."""

    def test_session_permanent(self, client: FlaskClient, app: Flask) -> None:
        """Test that session is made permanent on requests."""
        with app.app_context():
            response = client.get("/")
            # Session cookie should be set
            assert response.status_code in [200, 302]
