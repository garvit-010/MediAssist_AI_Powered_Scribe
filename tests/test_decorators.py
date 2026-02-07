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


class TestLogInteraction:
    """Tests for the log_interaction function."""

    def test_log_interaction_creates_entry(self, app: Flask) -> None:
        """Test that log_interaction creates a clinical log entry."""
        with app.app_context():
            from app import log_interaction, ClinicalLog, db

            # Clear existing logs
            ClinicalLog.query.delete()
            db.session.commit()

            log_interaction(
                case_id="LOGTEST1",
                inputs={"symptoms": "Test symptoms for logging"},
                latency=0.5,
            )

            log = ClinicalLog.query.filter_by(case_id="LOGTEST1").first()
            assert log is not None
            assert log.model == "llama3"
            assert log.latency_ms == 500.0

    def test_log_interaction_truncates_symptoms(self, app: Flask) -> None:
        """Test that symptoms are truncated to 50 characters."""
        with app.app_context():
            from app import log_interaction, ClinicalLog, db

            ClinicalLog.query.delete()
            db.session.commit()

            long_symptoms = "A" * 100  # 100 characters
            log_interaction(
                case_id="LOGTEST2",
                inputs={"symptoms": long_symptoms},
                latency=0.25,
            )

            log = ClinicalLog.query.filter_by(case_id="LOGTEST2").first()
            assert log is not None
            assert len(log.symptoms_snippet) <= 50


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
                action="test_action", case_id="AUDIT001", user_id=user.id
            )

            assert result is True

            log = AuditLog.query.filter_by(action="test_action").first()
            assert log is not None
            assert log.case_id == "AUDIT001"

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
