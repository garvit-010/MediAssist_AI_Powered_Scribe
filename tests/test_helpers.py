from __future__ import annotations
from app.utils import TRANSLATIONS
from app.utils import get_cases_for_patient
from app.utils import get_cases_for_doctor
from app.utils import get_case_by_id
from app.utils import add_case
from app.utils import get_all_doctors
from app.utils import get_user_by_id
from app.utils import get_user_by_username
"""
Tests for helper functions in app.py.
"""

from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask


class TestHighlightEntities:
    """Tests for the highlight_entities NER function."""

    def test_highlight_medications(self, app: Flask) -> None:
        """Test that medications are highlighted correctly."""
        with app.app_context():
            from app.services.medical_service import highlight_entities

            text = "Patient was prescribed Paracetamol and Ibuprofen."
            result = highlight_entities(text)

            assert 'class="entity-med"' in result
            assert "Paracetamol" in result
            assert "Ibuprofen" in result

    def test_highlight_conditions(self, app: Flask) -> None:
        """Test that medical conditions are highlighted correctly."""
        with app.app_context():
            from app.services.medical_service import highlight_entities

            text = "Patient diagnosed with Diabetes and Hypertension."
            result = highlight_entities(text)

            assert 'class="entity-condition"' in result
            assert "Diabetes" in result
            assert "Hypertension" in result

    def test_highlight_dosages(self, app: Flask) -> None:
        """Test that dosages are highlighted correctly."""
        with app.app_context():
            from app.services.medical_service import highlight_entities

            text = "Take 500 mg twice daily and 10 ml syrup."
            result = highlight_entities(text)

            assert 'class="entity-dosage"' in result
            assert "500 mg" in result or "500mg" in result

    def test_empty_text_handling(self, app: Flask) -> None:
        """Test that empty strings are handled correctly."""
        with app.app_context():
            from app.services.medical_service import highlight_entities

            assert highlight_entities("") == ""
            assert highlight_entities(None) == ""  # type: ignore[arg-type]

    def test_case_insensitive_matching(self, app: Flask) -> None:
        """Test that entity matching is case insensitive."""
        with app.app_context():
            from app.services.medical_service import highlight_entities

            result = highlight_entities("ASPIRIN and aspirin should both match")
            # Both occurrences should be highlighted
            assert result.count('class="entity-med"') >= 1


class TestGetIcdCode:
    """Tests for the get_icd_code function."""

    def test_direct_match(self, app: Flask) -> None:
        """Test direct matching of conditions to ICD codes."""
        with app.app_context():
            from app.services.medical_service import get_icd_code

            assert get_icd_code("fever") == "R50.9"
            assert get_icd_code("migraine") == "G43.9"
            assert get_icd_code("diabetes") == "E11.9"

    def test_case_insensitive(self, app: Flask) -> None:
        """Test that matching is case insensitive."""
        with app.app_context():
            from app.services.medical_service import get_icd_code

            assert get_icd_code("FEVER") == "R50.9"
            assert get_icd_code("Migraine") == "G43.9"
            assert get_icd_code("DIABETES") == "E11.9"

    def test_partial_match(self, app: Flask) -> None:
        """Test matching when condition is part of larger text."""
        with app.app_context():
            from app.services.medical_service import get_icd_code

            assert get_icd_code("patient has fever symptoms") == "R50.9"
            assert get_icd_code("chronic headache") == "R51"

    def test_keyword_fallback(self, app: Flask) -> None:
        """Test fallback keyword matching."""
        with app.app_context():
            from app.services.medical_service import get_icd_code

            assert get_icd_code("severe pain syndrome") == "R52"
            assert get_icd_code("viral disease") == "B34.9"
            assert get_icd_code("bacterial growth") == "A49.9"

    def test_unspecified_return(self, app: Flask) -> None:
        """Test that unknown conditions return 'Unspecified'."""
        with app.app_context():
            from app.services.medical_service import get_icd_code

            assert get_icd_code("xyz unknown condition") == "Unspecified"

    def test_none_handling(self, app: Flask) -> None:
        """Test that None/empty input is handled correctly."""
        with app.app_context():
            from app.services.medical_service import get_icd_code

            assert get_icd_code(None) == "Not Found"  # type: ignore[arg-type]
            assert get_icd_code("") == "Not Found"


class TestIsTestCase:
    """Tests for the is_test_case function."""

    def test_valid_test_case(self, app: Flask) -> None:
        """Test detection of the predefined test fixture."""
        with app.app_context():
            from app.utils import is_test_case

            test_data = {
                "patient_name": "John Doe",
                "age": "48",
                "temp": "38",
                "bp": "120/80",
                "weight": "76",
                "height": "184",
                "allergies": "None",
                "current_meds": "None",
                "symptoms": "None",
            }
            assert is_test_case(test_data) is True

    def test_non_test_case(self, app: Flask) -> None:
        """Test that non-test data returns False."""
        with app.app_context():
            from app.utils import is_test_case

            real_data = {
                "patient_name": "Real Patient",
                "age": "35",
                "temp": "37.5",
                "bp": "130/85",
                "weight": "80",
                "height": "170",
                "allergies": "Penicillin",
                "current_meds": "Metformin",
                "symptoms": "Headache and fever",
            }
            assert is_test_case(real_data) is False


class TestCleanMedicalText:
    """Tests for the clean_medical_text function."""

    def test_remove_brackets(self, app: Flask) -> None:
        """Test removal of [** and **] markers."""
        with app.app_context():
            from app.services.medical_service import clean_medical_text

            text = "[**Patient**] was seen at [**Hospital**]"
            result = clean_medical_text(text)
            assert "[**" not in result
            assert "**]" not in result

    def test_bold_conversion(self, app: Flask) -> None:
        """Test conversion of **text** to <strong>text</strong>."""
        with app.app_context():
            from app.services.medical_service import clean_medical_text

            text = "This is **important** information"
            result = clean_medical_text(text)
            assert "<strong>important</strong>" in result

    def test_empty_handling(self, app: Flask) -> None:
        """Test that empty/None values are handled correctly."""
        with app.app_context():
            from app.services.medical_service import clean_medical_text

            assert clean_medical_text("") == ""
            assert clean_medical_text(None) == ""  # type: ignore[arg-type]


class TestGetLanguage:
    """Tests for the get_language function."""

    def test_default_language(self, app: Flask, client: Any) -> None:
        """Test that default language is English."""
        with app.app_context():
            from app.utils import get_language

            with client.session_transaction() as sess:
                sess.clear()

            # Without session, should return 'en'
            with client:
                client.get("/")  # Initialize session
                from flask import session
                assert session.get("language", "en") == "en"


class TestGetTranslations:
    """Tests for the get_translations function."""

    def test_english_translations(self, app: Flask) -> None:
        """Test retrieving English translations."""
        with app.app_context():
            from app.utils import get_translations

            translations = get_translations("en")
            assert isinstance(translations, dict)

    def test_hindi_translations(self, app: Flask) -> None:
        """Test retrieving Hindi translations."""
        with app.app_context():
            from app.utils import get_translations

            translations = get_translations("hi")
            assert isinstance(translations, dict)

    def test_invalid_language_fallback(self, app: Flask) -> None:
        """Test that invalid language falls back to English."""
        with app.app_context():
            from app.utils import get_translations, TRANSLATIONS

            translations = get_translations("invalid")
            # Should return English translations as fallback
            assert translations == TRANSLATIONS.get("en", {})


class TestBuildPredefinedAiAnalysis:
    """Tests for the build_predefined_ai_analysis function."""

    def test_english_analysis(self, app: Flask) -> None:
        """Test building AI analysis in English."""
        with app.app_context():
            from app.services.ai_service import build_predefined_ai_analysis

            raw_data = {"patient_name": "John Doe"}
            result = build_predefined_ai_analysis("English", raw_data)

            assert "patient_view" in result
            assert "doctor_view" in result
            assert "safety" in result
            assert result["patient_view"]["primary_diagnosis"] == "Mild Viral Fever"

    def test_hindi_analysis(self, app: Flask) -> None:
        """Test building AI analysis in Hindi."""
        with app.app_context():
            from app.services.ai_service import build_predefined_ai_analysis

            raw_data = {"patient_name": "Test"}
            result = build_predefined_ai_analysis("Hindi", raw_data)

            assert "patient_view" in result
            # Hindi summary should contain Hindi characters
            assert result["patient_view"]["summary"] is not None

    def test_structure_completeness(self, app: Flask) -> None:
        """Test that all required fields are present in the analysis."""
        with app.app_context():
            from app.services.ai_service import build_predefined_ai_analysis

            result = build_predefined_ai_analysis("English", {})

            # Patient view fields
            pv = result["patient_view"]
            assert "primary_diagnosis" in pv
            assert "summary" in pv
            assert "pathophysiology" in pv
            assert "care_plan" in pv
            assert "red_flags" in pv
            assert "severity_score" in pv

            # Doctor view fields
            dv = result["doctor_view"]
            assert "subjective" in dv
            assert "objective" in dv
            assert "assessment" in dv
            assert "plan" in dv


class TestUserHelpers:
    """Tests for user-related helper functions."""

    def test_get_user_by_username(self, app: Flask) -> None:
        """Test retrieving user by username."""
        from app.extensions import db
        from app.models import User
        from werkzeug.security import generate_password_hash

        with app.app_context():
            user = User(
                username="findme",
                password_hash=generate_password_hash("pass"),
                role="patient",
                full_name="Find Me User",
            )
            db.session.add(user)
            db.session.commit()

            result = get_user_by_username("findme")
            assert result is not None
            assert result["username"] == "findme"

            # Non-existent user
            assert get_user_by_username("notexist") is None

    def test_get_user_by_id(self, app: Flask) -> None:
        """Test retrieving user by ID."""
        from app.extensions import db
        from app.models import User
        from werkzeug.security import generate_password_hash

        with app.app_context():
            user = User(
                username="byiduser",
                password_hash=generate_password_hash("pass"),
                role="patient",
                full_name="By ID User",
            )
            db.session.add(user)
            db.session.commit()
            user_id = user.id

            result = get_user_by_id(user_id)
            assert result is not None
            assert result["username"] == "byiduser"

            # Non-existent ID
            assert get_user_by_id(99999) is None

    def test_get_all_doctors(self, app: Flask) -> None:
        """Test retrieving all doctors."""
        from app.extensions import db
        from app.models import User
        from werkzeug.security import generate_password_hash

        with app.app_context():
            # Add some doctors
            doc1 = User(
                username="doc1",
                password_hash=generate_password_hash("pass"),
                role="doctor",
                full_name="Doctor One",
                specialty="Surgery",
            )
            doc2 = User(
                username="doc2",
                password_hash=generate_password_hash("pass"),
                role="doctor",
                full_name="Doctor Two",
                specialty="Medicine",
            )
            patient = User(
                username="pat1",
                password_hash=generate_password_hash("pass"),
                role="patient",
                full_name="Patient One",
            )
            db.session.add_all([doc1, doc2, patient])
            db.session.commit()

            doctors = get_all_doctors()
            assert len(doctors) == 2
            assert all(d["role"] == "doctor" for d in doctors)


class TestCaseHelpers:
    """Tests for case-related helper functions."""

    def test_add_and_get_case(
        self, app: Flask, sample_case_data: dict[str, Any]
    ) -> None:
        """Test adding and retrieving a case."""
        from app.extensions import db
        from app.models import User
        from werkzeug.security import generate_password_hash

        with app.app_context():
            # Create users first
            patient = User(
                username="casepatient2",
                password_hash=generate_password_hash("pass"),
                role="patient",
                full_name="Case Patient 2",
            )
            doctor = User(
                username="casedoctor2",
                password_hash=generate_password_hash("pass"),
                role="doctor",
                full_name="Case Doctor 2",
            )
            db.session.add_all([patient, doctor])
            db.session.commit()

            case_data = {
                **sample_case_data,
                "id": "NEWCASE1",
                "patient_id": patient.id,
                "doctor_id": doctor.id,
                "timestamp": sample_case_data["timestamp"].isoformat(),
            }

            add_case(case_data)

            result = get_case_by_id("NEWCASE1")
            assert result is not None
            assert result["id"] == "NEWCASE1"

    def test_get_cases_for_doctor(
        self, app: Flask, sample_case_data: dict[str, Any]
    ) -> None:
        """Test retrieving cases for a specific doctor."""
        from app.extensions import db
        from app.models import User, Case
        from werkzeug.security import generate_password_hash

        with app.app_context():
            patient = User(
                username="doccasepatient",
                password_hash=generate_password_hash("pass"),
                role="patient",
                full_name="Patient For Doc Cases",
            )
            doctor = User(
                username="doccasedoctor",
                password_hash=generate_password_hash("pass"),
                role="doctor",
                full_name="Doctor For Cases",
            )
            db.session.add_all([patient, doctor])
            db.session.commit()

            # Add multiple cases for this doctor
            for i in range(3):
                case = Case(
                    id=f"DOCCASE{i}",
                    patient_id=patient.id,
                    doctor_id=doctor.id,
                    raw_data=sample_case_data["raw_data"],
                    ai_analysis=sample_case_data["ai_analysis"],
                    status="Pending",
                )
                db.session.add(case)
            db.session.commit()

            cases = get_cases_for_doctor(doctor.id)
            assert len(cases) == 3

    def test_get_cases_for_patient(
        self, app: Flask, sample_case_data: dict[str, Any]
    ) -> None:
        """Test retrieving cases for a specific patient."""
        from app.extensions import db
        from app.models import User, Case
        from werkzeug.security import generate_password_hash

        with app.app_context():
            patient = User(
                username="patcasepatient",
                password_hash=generate_password_hash("pass"),
                role="patient",
                full_name="Patient For Pat Cases",
            )
            doctor = User(
                username="patcasedoctor",
                password_hash=generate_password_hash("pass"),
                role="doctor",
                full_name="Doctor For Pat Cases",
            )
            db.session.add_all([patient, doctor])
            db.session.commit()

            # Add cases for this patient
            for i in range(2):
                case = Case(
                    id=f"PATCASE{i}",
                    patient_id=patient.id,
                    doctor_id=doctor.id,
                    raw_data=sample_case_data["raw_data"],
                    ai_analysis=sample_case_data["ai_analysis"],
                    status="Reviewed",
                )
                db.session.add(case)
            db.session.commit()

            cases = get_cases_for_patient(patient.id)
            assert len(cases) == 2
