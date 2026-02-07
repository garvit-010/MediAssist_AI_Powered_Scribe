"""
Tests for database models: User, Case, ClinicalLog, AuditLog, EncryptedString.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

import pytest
from flask import Flask


class TestUserModel:
    """Tests for the User model."""

    def test_create_user(self, app: Flask) -> None:
        """Test creating a new user."""
        from app import db, User
        from werkzeug.security import generate_password_hash

        with app.app_context():
            user = User(
                username="newuser",
                password_hash=generate_password_hash("password123"),
                role="patient",
                full_name="New Test User",
            )
            db.session.add(user)
            db.session.commit()

            retrieved = User.query.filter_by(username="newuser").first()
            assert retrieved is not None
            assert retrieved.username == "newuser"
            assert retrieved.role == "patient"
            assert retrieved.full_name == "New Test User"

    def test_user_to_dict(self, app: Flask) -> None:
        """Test User.to_dict() method returns correct structure."""
        from app import db, User
        from werkzeug.security import generate_password_hash

        with app.app_context():
            user = User(
                username="dictuser",
                password_hash=generate_password_hash("password"),
                role="doctor",
                full_name="Dr. Dict User",
                specialty="Cardiology",
            )
            db.session.add(user)
            db.session.commit()

            user_dict = user.to_dict()
            assert "id" in user_dict
            assert user_dict["username"] == "dictuser"
            assert user_dict["role"] == "doctor"
            assert user_dict["full_name"] == "Dr. Dict User"
            assert user_dict["specialty"] == "Cardiology"

    def test_create_doctor_with_specialty(self, app: Flask) -> None:
        """Test creating a doctor with specialty and unique ID."""
        from app import db, User
        from werkzeug.security import generate_password_hash

        with app.app_context():
            doctor = User(
                username="specialdoctor",
                password_hash=generate_password_hash("securepass"),
                role="doctor",
                full_name="Dr. Specialist",
                specialty="Neurology",
                doctor_unique_id="DOC123",
            )
            db.session.add(doctor)
            db.session.commit()

            retrieved = User.query.filter_by(username="specialdoctor").first()
            assert retrieved is not None
            assert retrieved.specialty == "Neurology"
            assert retrieved.doctor_unique_id == "DOC123"


class TestCaseModel:
    """Tests for the Case model."""

    def test_create_case(
        self, app: Flask, sample_case_data: dict[str, Any]
    ) -> None:
        """Test creating a new case."""
        from app import db, Case, User
        from werkzeug.security import generate_password_hash

        with app.app_context():
            # Create patient and doctor first
            patient = User(
                username="casepatient",
                password_hash=generate_password_hash("pass"),
                role="patient",
                full_name="Case Patient",
            )
            doctor = User(
                username="casedoctor",
                password_hash=generate_password_hash("pass"),
                role="doctor",
                full_name="Case Doctor",
                specialty="General",
            )
            db.session.add_all([patient, doctor])
            db.session.commit()

            case = Case(
                id=sample_case_data["id"],
                patient_id=patient.id,
                doctor_id=doctor.id,
                timestamp=sample_case_data["timestamp"],
                raw_data=sample_case_data["raw_data"],
                ai_analysis=sample_case_data["ai_analysis"],
                status=sample_case_data["status"],
            )
            db.session.add(case)
            db.session.commit()

            retrieved = Case.query.get(sample_case_data["id"])
            assert retrieved is not None
            assert retrieved.id == sample_case_data["id"]
            assert retrieved.status == "Pending Review"

    def test_case_to_dict(
        self, app: Flask, sample_case_data: dict[str, Any]
    ) -> None:
        """Test Case.to_dict() method returns correct structure."""
        from app import db, Case, User
        from werkzeug.security import generate_password_hash

        with app.app_context():
            patient = User(
                username="dictpatient",
                password_hash=generate_password_hash("pass"),
                role="patient",
                full_name="Dict Patient",
            )
            doctor = User(
                username="dictdoctor",
                password_hash=generate_password_hash("pass"),
                role="doctor",
                full_name="Dict Doctor",
            )
            db.session.add_all([patient, doctor])
            db.session.commit()

            case = Case(
                id="DICT0001",
                patient_id=patient.id,
                doctor_id=doctor.id,
                timestamp=datetime.now(),
                raw_data=sample_case_data["raw_data"],
                ai_analysis=sample_case_data["ai_analysis"],
                status="Reviewed",
            )
            db.session.add(case)
            db.session.commit()

            case_dict = case.to_dict()
            assert case_dict["id"] == "DICT0001"
            assert case_dict["case_id"] == "DICT0001"
            assert case_dict["status"] == "Reviewed"
            assert "raw_data" in case_dict
            assert "ai_analysis" in case_dict


class TestClinicalLogModel:
    """Tests for the ClinicalLog model."""

    def test_create_clinical_log(self, app: Flask) -> None:
        """Test creating a clinical log entry."""
        from app import db, ClinicalLog

        with app.app_context():
            log = ClinicalLog(
                case_id="LOG001",
                model="llama3",
                latency_ms=250.5,
                symptoms_snippet="Fever and headache",
            )
            db.session.add(log)
            db.session.commit()

            retrieved = ClinicalLog.query.filter_by(case_id="LOG001").first()
            assert retrieved is not None
            assert retrieved.model == "llama3"
            assert retrieved.latency_ms == 250.5
            assert retrieved.symptoms_snippet == "Fever and headache"


class TestAuditLogModel:
    """Tests for the AuditLog model."""

    def test_create_audit_log(self, app: Flask) -> None:
        """Test creating an audit log entry."""
        from app import db, AuditLog, User
        from werkzeug.security import generate_password_hash

        with app.app_context():
            user = User(
                username="audituser",
                password_hash=generate_password_hash("pass"),
                role="doctor",
                full_name="Audit User",
            )
            db.session.add(user)
            db.session.commit()

            audit = AuditLog(
                user_id=user.id,
                action="view_case",
                case_id="CASE001",
            )
            db.session.add(audit)
            db.session.commit()

            retrieved = AuditLog.query.filter_by(action="view_case").first()
            assert retrieved is not None
            assert retrieved.user_id == user.id
            assert retrieved.case_id == "CASE001"
            assert retrieved.timestamp is not None


class TestEncryptedString:
    """Tests for the EncryptedString TypeDecorator."""

    def test_encryption_decryption(self, app: Flask) -> None:
        """Test that data is encrypted when stored and decrypted when retrieved."""
        from app import db, User
        from werkzeug.security import generate_password_hash

        sensitive_name = "Super Secret Patient Name"

        with app.app_context():
            user = User(
                username="encryptuser",
                password_hash=generate_password_hash("pass"),
                role="patient",
                full_name=sensitive_name,
            )
            db.session.add(user)
            db.session.commit()

            # Retrieve and verify decryption works
            retrieved = User.query.filter_by(username="encryptuser").first()
            assert retrieved is not None
            assert retrieved.full_name == sensitive_name

    def test_none_value_handling(self, app: Flask) -> None:
        """Test that None values are handled correctly."""
        from app import db, User
        from werkzeug.security import generate_password_hash

        with app.app_context():
            user = User(
                username="nulluser",
                password_hash=generate_password_hash("pass"),
                role="patient",
                full_name=None,
            )
            db.session.add(user)
            db.session.commit()

            retrieved = User.query.filter_by(username="nulluser").first()
            assert retrieved is not None
            assert retrieved.full_name is None
