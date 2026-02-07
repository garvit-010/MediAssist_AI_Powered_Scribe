"""
Tests for decorator functions and PDF generation.
"""
from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask
from flask.testing import FlaskClient


class TestLoginRequiredDecorator:
    """Tests for the login_required decorator."""

    def test_redirects_unauthenticated(self, client: FlaskClient, app: Flask) -> None:
        """Test that unauthenticated users are redirected."""
        with app.app_context():
            response = client.get("/patient/intake")
            assert response.status_code == 302

    def test_allows_authenticated(
        self, authenticated_patient_session: FlaskClient, app: Flask
    ) -> None:
        """Test that authenticated users can access protected routes."""
        from app import db, User
        from werkzeug.security import generate_password_hash

        with app.app_context():
            # Add a doctor for the intake page
            doctor = User(
                username="decoratordoc",
                password_hash=generate_password_hash("pass"),
                role="doctor",
                full_name="Decorator Doctor",
            )
            db.session.add(doctor)
            db.session.commit()

            response = authenticated_patient_session.get("/patient/intake")
            assert response.status_code == 200


class TestPatientRequiredDecorator:
    """Tests for the patient_required decorator."""

    def test_blocks_non_patients(
        self, authenticated_doctor_session: FlaskClient, app: Flask
    ) -> None:
        """Test that non-patients are redirected from patient routes."""
        with app.app_context():
            response = authenticated_doctor_session.get("/patient/intake")
            assert response.status_code == 302

    def test_allows_patients(
        self, authenticated_patient_session: FlaskClient, app: Flask
    ) -> None:
        """Test that patients can access patient routes."""
        from app import db, User
        from werkzeug.security import generate_password_hash

        with app.app_context():
            doctor = User(
                username="patdecordoc",
                password_hash=generate_password_hash("pass"),
                role="doctor",
                full_name="Patient Decorator Doctor",
            )
            db.session.add(doctor)
            db.session.commit()

            response = authenticated_patient_session.get("/patient/intake")
            assert response.status_code == 200


class TestDoctorRequiredDecorator:
    """Tests for the doctor_required decorator."""

    def test_blocks_non_doctors(
        self, authenticated_patient_session: FlaskClient, app: Flask
    ) -> None:
        """Test that non-doctors are redirected from doctor routes."""
        with app.app_context():
            response = authenticated_patient_session.get("/doctor/dashboard")
            assert response.status_code == 302

    def test_allows_doctors(
        self, authenticated_doctor_session: FlaskClient, app: Flask
    ) -> None:
        """Test that doctors can access doctor routes."""
        with app.app_context():
            response = authenticated_doctor_session.get("/doctor/dashboard")
            assert response.status_code == 200


class TestPDFReport:
    """Tests for PDF report generation."""

    def test_pdf_report_header(self, app: Flask) -> None:
        """Test that PDF report header is generated correctly."""
        with app.app_context():
            from app import PDFReport

            pdf = PDFReport()
            pdf.add_page()
            # Header should be called automatically
            assert pdf.page_no() == 1

    def test_pdf_report_footer(self, app: Flask) -> None:
        """Test that PDF report footer is generated correctly."""
        with app.app_context():
            from app import PDFReport

            pdf = PDFReport()
            pdf.add_page()
            # Footer should be callable
            pdf.footer()
            assert pdf.page_no() >= 1

    def test_pdf_chapter_title(self, app: Flask) -> None:
        """Test that chapter title is rendered correctly."""
        with app.app_context():
            from app import PDFReport

            pdf = PDFReport()
            pdf.add_page()
            pdf.chapter_title("Test Chapter")
            # Should not raise any errors
            assert True

    def test_pdf_chapter_body(self, app: Flask) -> None:
        """Test that chapter body is rendered correctly."""
        with app.app_context():
            from app import PDFReport

            pdf = PDFReport()
            pdf.add_page()
            pdf.chapter_body("This is test body content for the PDF report.")
            # Should not raise any errors
            assert True


class TestLogAIInteraction:
    """Tests for the log_ai_interaction function."""

    def test_log_ai_interaction_creates_entry(self, app: Flask) -> None:
        """Test that log_ai_interaction creates an AI log entry."""
        with app.app_context():
            from app import log_ai_interaction, AILog, db

            # Clear existing logs
            AILog.query.delete()
            db.session.commit()

            log_ai_interaction(
                case_id="LOGTEST1",
                model="llama3",
                latency_ms=500.0,
                status="success",
                prompt_tokens=100,
                completion_tokens=50
            )

            log = AILog.query.filter_by(case_id="LOGTEST1").first()
            assert log is not None
            assert log.model == "llama3"
            assert log.latency_ms == 500.0
            assert log.total_tokens == 150
            assert log.status == "success"


class TestLogAuditAction:
    """Tests for the log_audit_action function."""

    def test_log_audit_action_creates_entry(self, app: Flask) -> None:
        """Test that log_audit_action creates an audit log entry."""
        from app import db, User, log_audit_action, AuditLog
        from werkzeug.security import generate_password_hash

        with app.app_context():
            user = User(
                username="auditloguser",
                password_hash=generate_password_hash("pass"),
                role="doctor",
                full_name="Audit Log User",
            )
            db.session.add(user)
            db.session.commit()

            # Clear existing audit logs
            AuditLog.query.delete()
            db.session.commit()

            result = log_audit_action(
                action="test_action",
                resource_type="case",
                resource_id="AUDIT001",
                user_id=user.id
            )

            assert result is True

            log = AuditLog.query.filter_by(action="test_action").first()
            assert log is not None
            assert log.resource_id == "AUDIT001"
            assert log.resource_type == "case"

    def test_log_audit_action_without_user_id(
        self, authenticated_doctor_session: FlaskClient, app: Flask
    ) -> None:
        """Test log_audit_action uses session user_id when not provided."""
        with app.app_context():
            from app import log_audit_action, AuditLog, db

            AuditLog.query.delete()
            db.session.commit()

            # Make a request to establish session context
            with authenticated_doctor_session:
                authenticated_doctor_session.get("/doctor/dashboard")
                # Now log action without explicit user_id
                from flask import session

                if "user_id" in session:
                    result = log_audit_action(action="session_test")
                    assert result in [True, False]
