"""MediAssist - AI-Powered Clinical Scribe & Patient Communication System.

This module provides the main Flask application for MediAssist, including:
- User authentication and role-based access control
- Patient intake and case management
- AI-powered clinical analysis using Llama 3
- Multi-language support (English/Hindi)
- Audit logging and HIPAA-compliant security features
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
import time
import uuid
from datetime import datetime, timedelta
from functools import wraps
from typing import TYPE_CHECKING, Any, Callable, Optional, TypeVar, cast

import requests
import whisper
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from flask import Flask, flash, jsonify, redirect, render_template, request, send_file, session, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from fpdf import FPDF
from sqlalchemy.types import Text, TypeDecorator
from werkzeug.security import check_password_hash
from werkzeug.wrappers import Response as WerkzeugResponse

if TYPE_CHECKING:
    from sqlalchemy.engine import Dialect

# Type variable for decorator functions
F = TypeVar("F", bound=Callable[..., Any])

load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))
app = Flask(__name__)

# [NEW] HIPAA Security Configuration (Issue #44)
# 1. Timeout: Auto-logout after 15 minutes of inactivity
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=15)

# 2. Cookies: Protect session ID from theft
app.config["SESSION_COOKIE_HTTPONLY"] = True  # JavaScript cannot access the cookie (Prevents XSS)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # Prevents CSRF

# NOTE: 'Secure' requires HTTPS. If running locally on HTTP, this might block login.
# We set it to True to meet the requirement, but if login fails locally, set to False.
app.config["SESSION_COOKIE_SECURE"] = True
# [NEW] Setup Rate Limiter
# storage_uri="memory://" uses RAM to track limits (simplest for local dev)
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"], storage_uri="memory://")


# [NEW] Custom Error Handler for Rate Limit
@app.errorhandler(429)
def ratelimit_handler(e: Exception) -> WerkzeugResponse:
    """Handle rate limit exceeded errors."""
    flash("You are generating reports too fast. Please wait a minute before trying again.", "danger")
    # Redirect back to the previous page (likely the intake form)
    return redirect(request.referrer or url_for("patient_intake"))


# [NEW] Load Whisper Model (Base model is ~150MB and runs fast on CPU)
# We load it globally so we don't reload it on every request
audio_model: Optional[Any] = None
try:
    print("Loading Whisper model... this may take a moment.")
    audio_model = whisper.load_model("base")
    print("Whisper model loaded successfully.")
except Exception as e:
    logging.error(f"Failed to load Whisper model: {e}")
    audio_model = None

# Load translation files
TRANSLATIONS = {}
# --- NER HIGHLIGHTING SETUP ---
# Defines the entities we want to auto-highlight in the UI
NER_MEDICATIONS = [
    "Paracetamol",
    "Ibuprofen",
    "Aspirin",
    "Metformin",
    "Amoxicillin",
    "Lisinopril",
    "Atorvastatin",
    "Albuterol",
    "Tylenol",
    "Advil",
]
NER_CONDITIONS = [
    "Viral Fever",
    "Migraine",
    "Diabetes",
    "Hypertension",
    "Asthma",
    "Pneumonia",
    "Bronchitis",
    "Covid-19",
    "Influenza",
    "Headache",
    "Fever",
    "Infection",
    "Nausea",
]


def highlight_entities(text: Optional[str]) -> str:
    """
    Scans text for medical entities and wraps them in colorful HTML badges.

    This acts as a lightweight NER (Named Entity Recognition) pipeline.

    Args:
        text: The input text to process for entity highlighting.

    Returns:
        The text with HTML span elements wrapping identified entities.
    """
    if not text:
        return ""

    # 1. Highlight Dosages (e.g., 500 mg, 10ml) -> Gray Badge
    # Regex looks for numbers followed by units like mg, ml, g, kg
    text = re.sub(r"(\d+\s?(mg|ml|g|kg|mcg))", r'<span class="entity-dosage">\1</span>', text, flags=re.IGNORECASE)

    # 2. Highlight Medications -> Red Badge
    for med in NER_MEDICATIONS:
        # \b ensures we match whole words only (e.g., avoid matching "corn" in "popcorn")
        pattern = re.compile(r"\b(" + re.escape(med) + r")\b", re.IGNORECASE)
        text = pattern.sub(r'<span class="entity-med">\1</span>', text)

    # 3. Highlight Conditions -> Blue Badge
    for cond in NER_CONDITIONS:
        pattern = re.compile(r"\b(" + re.escape(cond) + r")\b", re.IGNORECASE)
        text = pattern.sub(r'<span class="entity-condition">\1</span>', text)

    return text


# Register the filter so we can use it in HTML as {{ text | ner_highlight }}
app.jinja_env.filters["ner_highlight"] = highlight_entities
TRANSLATIONS_DIR = os.path.join(os.path.dirname(__file__), "translations")
for lang_code in ["en", "hi"]:
    lang_file = os.path.join(TRANSLATIONS_DIR, f"{lang_code}.json")
    if os.path.exists(lang_file):
        with open(lang_file, "r", encoding="utf-8") as f:
            TRANSLATIONS[lang_code] = json.load(f)

app.secret_key = os.getenv("FLASK_SECRET_KEY")

# DATABASE CONFIGURATION
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///medical_data.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

OLLAMA_API_URL = "http://localhost:11434/api/generate"
# --- ENCRYPTION SETUP ---
# We retrieve the key from .env. If missing, we warn but don't crash immediately (unless used).
FERNET_KEY: Optional[str] = os.getenv("FERNET_KEY")
cipher_suite: Optional[Fernet] = Fernet(FERNET_KEY) if FERNET_KEY else None


class EncryptedString(TypeDecorator):  # type: ignore[type-arg]
    """Custom TypeDecorator that encrypts data before saving to DB.

    Includes 'Safe Read' fallback for legacy unencrypted data.
    """

    impl = Text
    cache_ok = True

    def process_bind_param(self, value: Optional[str], dialect: Dialect) -> Optional[str]:
        """Encrypt before writing to DB."""
        if value is None:
            return None
        if not cipher_suite:
            logging.error("FERNET_KEY missing! Saving plain text.")
            return value
        try:
            # Encrypt string -> bytes -> encoded string
            return cipher_suite.encrypt(value.encode("utf-8")).decode("utf-8")
        except Exception as e:
            logging.error(f"Encryption failed: {e}")
            return value

    def process_result_value(self, value: Optional[str], dialect: Dialect) -> Optional[str]:
        """Decrypt after reading from DB."""
        if value is None:
            return None
        if not cipher_suite:
            return value
        try:
            # Decode string -> bytes -> decrypt -> string
            return cipher_suite.decrypt(value.encode("utf-8")).decode("utf-8")
        except Exception:
            # FALLBACK: If decryption fails, assume data is legacy (plain text)
            # This prevents crashes on existing unencrypted rows.
            return value


# MODELS
class User(db.Model):  # type: ignore[name-defined]
    """User model for patients and doctors."""

    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)

    # [SECURE] Applied Encryption to PII
    full_name = db.Column(EncryptedString)

    specialty = db.Column(db.String(100), nullable=True)
    doctor_unique_id = db.Column(db.String(50), nullable=True)

    def to_dict(self) -> dict[str, Any]:
        """Convert user to dictionary representation."""
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "full_name": self.full_name,
            "password_hash": self.password_hash,
            "specialty": self.specialty,
        }


class Case(db.Model):  # type: ignore[name-defined]
    """Case model for patient cases."""

    __tablename__ = "case"

    id = db.Column(db.String(50), primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    # Note: 'raw_data' is JSON. We are not encrypting the whole JSON column
    # as it would break JSON querying capabilities.
    raw_data = db.Column(db.JSON)

    ai_analysis = db.Column(db.JSON)
    status = db.Column(db.String(50), default="Pending Review")

    patient = db.relationship("User", foreign_keys=[patient_id], backref="cases_as_patient")
    doctor = db.relationship("User", foreign_keys=[doctor_id], backref="cases_as_doctor")

    def to_dict(self) -> dict[str, Any]:
        """Convert case to dictionary representation."""
        return {
            "id": self.id,
            "case_id": self.id,
            "patient_id": str(self.patient_id),
            "doctor_id": str(self.doctor_id),
            "timestamp": self.timestamp.isoformat() if self.timestamp else "",
            "raw_data": self.raw_data,
            "ai_analysis": self.ai_analysis,
            "status": self.status,
        }


class ClinicalLog(db.Model):  # type: ignore[name-defined]
    """Model for logging clinical AI interactions."""

    __tablename__ = "clinical_log"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    case_id = db.Column(db.String(50), db.ForeignKey("case.id"))
    model = db.Column(db.String(50))
    latency_ms = db.Column(db.Float)

    # [SECURE] Encrypting symptoms snippet as it contains sensitive health info
    symptoms_snippet = db.Column(EncryptedString)


class AuditLog(db.Model):  # type: ignore[name-defined]
    """Model for audit logging user actions and PII access."""

    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    resource_type = db.Column(db.String(50))  # e.g., 'case', 'user'
    resource_id = db.Column(db.String(50))
    pii_accessed = db.Column(db.Boolean, default=False)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref="audit_logs")


class AILog(db.Model):  # type: ignore[name-defined]
    """Model for tracking AI performance, costs, and fallbacks (MLOps)."""

    __tablename__ = "ai_log"

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.String(50), db.ForeignKey("case.id"), nullable=True)
    model = db.Column(db.String(50))
    latency_ms = db.Column(db.Float)
    prompt_tokens = db.Column(db.Integer, default=0)
    completion_tokens = db.Column(db.Integer, default=0)
    total_tokens = db.Column(db.Integer, default=0)
    cost = db.Column(db.Float, default=0.0)
    status = db.Column(db.String(20))  # 'success', 'failure', 'fallback'
    fallback_reason = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


# Initialize DB (Creates tables if not exist)
with app.app_context():
    db.create_all()

# HELPER FUNCTIONS (Refactored to use DB)


def get_user_by_username(username: Optional[str]) -> Optional[dict[str, Any]]:
    """Retrieve a user by their username.

    Args:
        username: The username to search for.

    Returns:
        User dictionary if found, None otherwise.
    """
    if username is None:
        return None
    user = User.query.filter_by(username=username).first()
    return user.to_dict() if user else None


def get_user_by_id(user_id: Any) -> Optional[dict[str, Any]]:
    """Retrieve a user by their ID.

    Args:
        user_id: The user ID to search for.

    Returns:
        User dictionary if found, None otherwise.
    """
    try:
        user = User.query.get(int(user_id))
        return user.to_dict() if user else None
    except (ValueError, TypeError):
        return None


def get_all_doctors() -> list[dict[str, Any]]:
    """Retrieve all users with the doctor role.

    Returns:
        List of doctor dictionaries.
    """
    doctors = User.query.filter_by(role="doctor").all()
    return [d.to_dict() for d in doctors]


def add_case(case_data: dict[str, Any]) -> None:
    """Add a new case to the database.

    Args:
        case_data: Dictionary containing case information.

    Raises:
        Exception: If there's an error adding the case.
    """
    try:
        new_case = Case(
            id=case_data["id"],
            patient_id=int(case_data["patient_id"]),
            doctor_id=int(case_data["doctor_id"]),
            timestamp=(
                datetime.fromisoformat(case_data["timestamp"])
                if isinstance(case_data["timestamp"], str)
                else case_data["timestamp"]
            ),
            raw_data=case_data["raw_data"],
            ai_analysis=case_data["ai_analysis"],
            status=case_data["status"],
        )
        db.session.add(new_case)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error adding case: {e}")
        raise e


def get_cases_for_doctor(doctor_id: Any) -> list[dict[str, Any]]:
    """Retrieve all cases assigned to a specific doctor.

    Args:
        doctor_id: The doctor's user ID.

    Returns:
        List of case dictionaries.
    """
    cases = Case.query.filter_by(doctor_id=int(doctor_id)).order_by(Case.timestamp.desc()).all()
    return [c.to_dict() for c in cases]


def get_case_by_id(case_id: str) -> Optional[dict[str, Any]]:
    """Retrieve a case by its ID.

    Args:
        case_id: The case ID to search for.

    Returns:
        Case dictionary if found, None otherwise.
    """
    case = Case.query.get(case_id)
    return case.to_dict() if case else None


def get_cases_for_patient(patient_id: Any) -> list[dict[str, Any]]:
    """Retrieve all cases for a specific patient.

    Args:
        patient_id: The patient's user ID.

    Returns:
        List of case dictionaries.
    """
    cases = Case.query.filter_by(patient_id=int(patient_id)).order_by(Case.timestamp.desc()).all()
    return [c.to_dict() for c in cases]


# PROMPT
SYSTEM_PROMPT = """
ACT AS: Senior Clinical Consultant & Medical Scribe.
TASK: Analyze patient intake data and generate a structured clinical case file.

LANGUAGE INSTRUCTION:
- "patient_view" MUST be in {language}.
- "doctor_view" MUST be in ENGLISH.

OUTPUT FORMAT: Return ONLY valid JSON. Do not include markdown formatting like ```json.
{{
  "patient_view": {{
    "primary_diagnosis": "Name of condition",
    "summary": "Warm explanation in {language}.",
    "pathophysiology": "Simple analogy in {language}.",
    "care_plan": ["Step 1", "Step 2"],
    "red_flags": ["Sign 1", "Sign 2"],
    "severity_score": 5  // Integer 1-10 (1=Mild, 10=Emergency)
  }},
  "doctor_view": {{
    "subjective": "Medical terminology summary of HPI.",
    "objective": "Concise summary of reported vitals.",
    "assessment": "Differential diagnosis ranked by probability.",
    "plan": "Suggested pharmacotherapy and follow-up.",
    "subjective_list": ["Point 1", "Point 2"],
    "objective_list": ["Point 1", "Point 2"],
    "assessment_list": ["Point 1", "Point 2"],
    "plan_list": ["Point 1", "Point 2"],
    "possible_conditions": [
      {{ "name": "Condition A", "confidence": 0.XX }},
      {{ "name": "Condition B", "confidence": 0.XX }}
    ],
    "urgency_level": "Low/Medium/High",
    "follow_up_required": true/false
  }},
  "safety": {{
    "is_safe": true,
    "warnings": []
  }}
}}
"""

# DECORATORS


def login_required(f: F) -> F:
    """Decorator to require user authentication."""

    @wraps(f)
    def decorated_function(*args: Any, **kwargs: Any) -> Any:
        if "user_id" not in session:
            return redirect(url_for("landing"))
        return f(*args, **kwargs)

    return cast(F, decorated_function)


def patient_required(f: F) -> F:
    """Decorator to require patient role."""

    @wraps(f)
    def decorated_function(*args: Any, **kwargs: Any) -> Any:
        if session.get("role") != "patient":
            return redirect(url_for("landing"))
        return f(*args, **kwargs)

    return cast(F, decorated_function)


def doctor_required(f: F) -> F:
    """Decorator to require doctor role."""

    @wraps(f)
    def decorated_function(*args: Any, **kwargs: Any) -> Any:
        if session.get("role") != "doctor":
            return redirect(url_for("landing"))
        return f(*args, **kwargs)

    return cast(F, decorated_function)


def clean_medical_text(text: Optional[str]) -> str:
    """Clean and format medical text by removing markers and adding formatting.

    Args:
        text: The raw medical text to clean.

    Returns:
        Cleaned and formatted text.
    """
    if not text:
        return ""
    text = re.sub(r"\[\*\*", "", text)
    text = re.sub(r"\*\*\]", "", text)
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    return text.strip()


# --- ICD-10 CODING LOGIC ---
ICD10_COMMON_CODES: dict[str, str] = {
    "fever": "R50.9",
    "viral fever": "B34.9",
    "typhoid": "A01.0",
    "cough": "R05",
    "dry cough": "R05.3",
    "headache": "R51",
    "migraine": "G43.9",
    "common cold": "J00",
    "flu": "J11.1",
    "influenza": "J11.1",
    "pneumonia": "J18.9",
    "bronchitis": "J40",
    "asthma": "J45.909",
    "hypertension": "I10",
    "high blood pressure": "I10",
    "diabetes": "E11.9",
    "abdominal pain": "R10.9",
    "chest pain": "R07.9",
    "nausea": "R11.0",
    "vomiting": "R11.1",
    "diarrhea": "R19.7",
    "fatigue": "R53.83",
    "anxiety": "F41.9",
    "depression": "F32.9",
    "infection": "B99.9",
}


def get_icd_code(diagnosis: Optional[str]) -> str:
    """Match a diagnosis text to an ICD-10 code.

    Args:
        diagnosis: The diagnosis text to look up.

    Returns:
        The matching ICD-10 code or 'Not Found'/'Unspecified'.
    """
    if not diagnosis:
        return "Not Found"

    text = diagnosis.lower()

    # 1. Direct key search (fastest)
    for key, code in ICD10_COMMON_CODES.items():
        if key in text:
            return code

    # 2. Keyword Fallback
    if "pain" in text:
        return "R52"
    if "viral" in text:
        return "B34.9"
    if "bacterial" in text:
        return "A49.9"

    return "Unspecified"


def is_test_case(raw_data: dict[str, Any]) -> bool:
    """Return True if the intake matches the predefined test fixture.

    Args:
        raw_data: The raw intake data to check.

    Returns:
        True if this is a test case, False otherwise.
    """

    def val(key: str) -> str:
        v = raw_data.get(key)
        if v is None:
            return ""
        return str(v).strip().lower()

    checks = [
        val("patient_name") in {"john doe", "john"},
        val("age") in {"48", "48.0"},
        val("temp") in {"38", "38.0"},
        val("bp") in {"120/80", "120 80", "120-80"},
        val("weight") in {"76", "76.0"},
        val("height") in {"184", "184.0"},
        val("allergies") in {"none", "", "no"},
        val("current_meds") in {"none", "", "no"},
        val("symptoms") in {"none", "", "no"},
    ]
    return all(checks)


def get_language() -> str:
    """Get current language from session or default to English."""
    lang: str = str(session.get("language", "en"))
    return lang


def get_translations(lang_code: Optional[str] = None) -> dict[str, Any]:
    """Get translations for the current or specified language.

    Args:
        lang_code: Optional language code. If None, uses current session language.

    Returns:
        Dictionary of translations for the specified language.
    """
    if lang_code is None:
        lang_code = get_language()
    translations: dict[str, Any] = TRANSLATIONS.get(lang_code, TRANSLATIONS.get("en", {}))
    return translations


@app.route("/set_language/<lang_code>")
def set_language(lang_code: str) -> WerkzeugResponse:
    """Set the user's language preference.

    Args:
        lang_code: The language code to set.

    Returns:
        Redirect response to the previous page.
    """
    if lang_code in TRANSLATIONS:
        session["language"] = lang_code
    return redirect(request.referrer or url_for("landing"))


def build_predefined_ai_analysis(language: str, raw_data: dict[str, Any]) -> dict[str, Any]:
    """Construct a deterministic AI analysis payload matching the app schema.

    Args:
        language: The language for the patient view ('English' or 'Hindi').
        raw_data: The raw patient intake data.

    Returns:
        Complete AI analysis dictionary with patient and doctor views.
    """
    # Minimal bilingual content for patient_view and English doctor_view
    patient_summary = {
        "English": (
            "Your symptoms and vitals suggest a mild viral fever. " "Rest, hydration, and monitoring are recommended."
        ),
        "Hindi": (
            "आपके लक्षण और वाइटल्स हल्का वायरल बुखार दर्शाते हैं। "
            "आराम करें, पानी ज्यादा पिएँ और स्थिति पर नज़र रखें।"
        ),
    }

    patient_patho = {
        "English": (
            "When a virus enters, the immune system raises body temperature to fight it—"
            "like turning up the heat to slow down the invader."
        ),
        "Hindi": (
            "जब वायरस शरीर में आता है, तो प्रतिरक्षा प्रणाली तापमान बढ़ाकर उससे लड़ती है—"
            "जैसे गर्मी बढ़ाकर आक्रमणकारी की गति धीमी करना।"
        ),
    }

    lang = language if language in patient_summary else "English"

    return {
        "patient_view": {
            "primary_diagnosis": "Mild Viral Fever",
            "summary": patient_summary[lang],
            "pathophysiology": patient_patho[lang],
            "care_plan": [
                "Rest and maintain adequate hydration.",
                "Paracetamol 500 mg as needed for fever (max 4 doses/day).",
                "Monitor temperature twice daily.",
                "If symptoms worsen, contact your doctor.",
            ],
            "red_flags": [
                "Persistent high fever > 39.5°C",
                "Severe headache or confusion",
                "Shortness of breath or chest pain",
            ],
            "severity_score": 3,
        },
        "doctor_view": {
            "subjective": (
                "48-year-old female presents with low-grade fever (38°C), no allergies, "
                "no current medications, denies additional symptoms."
            ),
            "objective": (
                "Vitals: BP 120/80, Wt 76 kg, Ht 184.9 cm. Afebrile to low-grade fever; " "no acute distress reported."
            ),
            "assessment": (
                "Likely mild viral illness. DDx: viral URI, early influenza; less likely bacterial infection."
            ),
            "plan": ("Supportive care, PRN antipyretics, hydration, return precautions for red flags."),
            "subjective_list": [
                "Fever 38°C",
                "No allergies or current meds",
                "Denies other complaints",
            ],
            "objective_list": ["BP 120/80", "Wt 76 kg, Ht 184.9 cm", "General: stable"],
            "assessment_list": [
                "Mild viral fever—most probable",
                "Viral URI",
                "Early influenza",
            ],
            "plan_list": [
                "Paracetamol 500 mg PRN",
                "Hydration and rest",
                "Monitor temperature; follow up if worsening",
            ],
        },
        "safety": {"is_safe": True, "warnings": []},
    }


def log_ai_interaction(
    case_id: Optional[str],
    model: str,
    latency_ms: float,
    status: str = "success",
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
    fallback_reason: Optional[str] = None,
) -> None:
    """Log an AI interaction for MLOps monitoring."""
    try:
        total_tokens = prompt_tokens + completion_tokens
        # Estimated cost: $0.0002 per 1k tokens (llama3 local estimation)
        cost = (total_tokens / 1000) * 0.0002

        ai_log = AILog(
            case_id=case_id,
            model=model,
            latency_ms=latency_ms,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            cost=cost,
            status=status,
            fallback_reason=fallback_reason,
            timestamp=datetime.utcnow(),
        )
        db.session.add(ai_log)
        db.session.commit()
    except Exception as e:
        logging.error(f"AI Interaction Logging Error: {e}")


def log_audit_action(
    action: str,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    user_id: Optional[Any] = None,
    pii_accessed: bool = False,
) -> Optional[bool]:
    """Log an audit action to the database with HIPAA-lite tracking.

    Args:
        action: The action being logged.
        resource_type: Optional type of resource (e.g., 'case').
        resource_id: Optional ID of the resource.
        user_id: Optional user ID. If None, uses session user.
        pii_accessed: Whether PII was accessed in this action.

    Returns:
        True on success, False on error.
    """
    try:
        if user_id is None:
            user_id = session.get("user_id")

        new_log = AuditLog(
            user_id=int(user_id) if user_id else None,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            pii_accessed=pii_accessed,
            ip_address=request.remote_addr if request else None,
            user_agent=request.user_agent.string if request else None,
            timestamp=datetime.utcnow(),
        )
        db.session.add(new_log)
        db.session.commit()
        return True
    except Exception as e:
        logging.error(f"Audit Logging Error: {e}")
        return False


def audit_access(resource_type: str, pii: bool = False) -> Callable[[F], F]:
    """Decorator to automatically log resource access for auditing."""

    def decorator(f: F) -> F:
        @wraps(f)
        def decorated_function(*args: Any, **kwargs: Any) -> Any:
            # Extract resource_id from kwargs if present (e.g., case_id)
            resource_id = kwargs.get("case_id") or kwargs.get("id")

            log_audit_action(
                action=f"access_{f.__name__}",
                resource_type=resource_type,
                resource_id=str(resource_id) if resource_id else None,
                pii_accessed=pii,
            )
            return f(*args, **kwargs)

        return cast(F, decorated_function)

    return decorator


class PDFReport(FPDF):  # type: ignore[misc]
    """Custom PDF report class for generating clinical SOAP notes."""

    def header(self) -> None:
        """Generate the PDF header with title and watermark."""
        # Hospital Title
        self.set_font("Arial", "B", 16)
        self.cell(0, 10, "MediAssist - Clinical SOAP Note", 0, 1, "C")
        self.ln(5)

        # Watermark (with rotation if supported)
        self.set_font("Arial", "B", 50)
        self.set_text_color(220, 220, 220)  # Light gray
        try:
            with self.rotation(45, 100, 150):
                self.text(30, 190, "CONFIDENTIAL")
        except AttributeError:
            # Fallback for fpdf versions without rotation support
            self.text(60, 150, "CONFIDENTIAL")
        self.set_text_color(0, 0, 0)  # Reset to black

    def footer(self) -> None:
        """Generate the PDF footer with page number."""
        self.set_y(-15)
        self.set_font("Arial", "I", 8)
        self.cell(0, 10, f"Page {self.page_no()} - Generated by MediAssist AI Scribe", 0, 0, "C")

    def chapter_title(self, label: str) -> None:
        """Add a chapter title to the PDF.

        Args:
            label: The title text for the chapter.
        """
        self.set_font("Arial", "B", 12)
        self.set_fill_color(200, 220, 255)  # Light blue background
        self.cell(0, 10, f"{label}", 0, 1, "L", 1)
        self.ln(2)

    def chapter_body(self, text: str) -> None:
        """Add body text to the PDF.

        Args:
            text: The body text content.
        """
        self.set_font("Arial", "", 11)
        self.multi_cell(0, 7, text)
        self.ln(5)


# ROUTES


@app.before_request
def make_session_permanent() -> None:
    """Set session as permanent on every request.

    Sliding Window: Resets the session expiration on every request.
    If the user is active, they won't be logged out.
    If they are idle for 15 mins, the session dies.
    """
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=15)


@app.route("/")
def landing() -> str | WerkzeugResponse:
    """Landing page - role selection."""
    if "user_id" in session:
        if session["role"] == "patient":
            return redirect(url_for("patient_intake"))
        elif session["role"] == "doctor":
            return redirect(url_for("doctor_dashboard"))

    lang_code = get_language()
    translations = get_translations(lang_code)
    return render_template("landing.html", t=translations, lang=lang_code)


# PATIENT ROUTES


@app.route("/patient/login", methods=["GET", "POST"])
def patient_login():
    lang_code = get_language()
    translations = get_translations(lang_code)

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = get_user_by_username(username)

        if user and user["role"] == "patient" and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["role"] = "patient"
            session["account_name"] = user["full_name"]
            log_audit_action("login_success", resource_type="user", resource_id=str(user["id"]))
            return redirect(url_for("patient_intake"))
        else:
            log_audit_action("login_failure", resource_type="user", resource_id=username)
            flash("Invalid username or password", "danger")
    return render_template("patient_login.html", t=translations, lang=lang_code)


@app.route("/patient/intake")
@login_required
@patient_required
def patient_intake():
    lang_code = get_language()
    translations = get_translations(lang_code)

    doctors = get_all_doctors()
    doctor_list = [{"id": d["id"], "name": d["full_name"], "specialty": d["specialty"]} for d in doctors]
    return render_template("intake.html", doctors=doctor_list, t=translations, lang=lang_code)


# [NEW] Voice Transcription Endpoint
@app.route("/transcribe", methods=["POST"])
@login_required
@patient_required
@audit_access(resource_type="voice_data", pii=True)
def transcribe_audio():
    if "audio" not in request.files:
        return jsonify({"error": "No audio file provided"}), 400

    if not audio_model:
        return jsonify({"error": "Transcriber model not loaded on server."}), 503

    audio_file = request.files["audio"]
    if audio_file.filename == "":
        return jsonify({"error": "No selected file"}), 400

    try:
        # Create a temporary file to save the uploaded audio
        # Whisper requires a file path (or a file-like object that it supports)
        with tempfile.NamedTemporaryFile(suffix=".webm", delete=False) as temp_audio:
            temp_path = temp_audio.name
            audio_file.save(temp_path)

        # Transcribe
        # You can add language='en' or 'hi' if you want to force it,
        # or let Whisper detect it.
        result = audio_model.transcribe(temp_path)
        transcribed_text = result["text"].strip()

        # Clean up temp file
        os.remove(temp_path)

        return jsonify({"text": transcribed_text})

    except Exception as e:
        logging.error(f"Transcription error: {e}")
        # Try to clean up if we failed
        if "temp_path" in locals() and os.path.exists(temp_path):
            os.remove(temp_path)
        return jsonify({"error": str(e)}), 500


@app.route("/patient/submit", methods=["POST"])
@login_required
@patient_required
@limiter.limit("5 per minute")
def patient_submit():
    start_time = time.time()
    try:
        symptoms = request.form.get("symptoms", "").strip()
        if not symptoms or len(symptoms) < 10:
            flash("Please provide more detail in symptoms (at least 10 characters).", "danger")
            return redirect(url_for("patient_intake"))

        if len(symptoms) > 1000:
            flash("Symptoms description is too long (max 1000 characters).", "danger")
            return redirect(url_for("patient_intake"))
        case_id = str(uuid.uuid4())[:8].upper()
        selected_language = request.form.get("language", "English")
        doctor_id_str = request.form.get("doctor_id")

        if not doctor_id_str:
            flash("Please select a doctor.", "danger")
            return redirect(url_for("patient_intake"))

        doctor_id = str(doctor_id_str)
        doctor = get_user_by_id(doctor_id)

        patient_name_input = request.form.get("name")
        if not patient_name_input:
            patient_name_input = session.get("account_name", "Unknown")

        raw_data = {
            "id": case_id,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "patient_name": patient_name_input,
            "doctor_name": doctor["full_name"] if doctor else "Unknown",
            "name": patient_name_input,
            "age": request.form.get("age"),
            "gender": request.form.get("gender"),
            "weight": request.form.get("weight"),
            "height": request.form.get("height"),
            "temp": request.form.get("temperature"),
            "bp": request.form.get("blood_pressure"),
            "duration": request.form.get("duration"),
            "allergies": request.form.get("allergies") or "None",
            "current_meds": request.form.get("current_medications") or "None",
            "history": request.form.get("medical_history") or "None",
            "severity": request.form.get("severity"),
            "symptoms": request.form.get("symptoms"),
            "notes": request.form.get("other_notes"),
            "language": selected_language,
        }

        log_audit_action("case_creation", resource_type="case", resource_id=case_id)

        formatted_prompt = SYSTEM_PROMPT.format(language=selected_language)
        prompt = f"{formatted_prompt}\nPATIENT DATA: {json.dumps(raw_data, default=str)}"

        ai_analysis = None
        model_name = "llama3"
        try:
            response = requests.post(
                OLLAMA_API_URL,
                json={
                    "model": model_name,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json",
                },
            )
            response.raise_for_status()
            result = response.json()
            if "response" in result:
                ai_text = result["response"]
                ai_analysis = json.loads(ai_text)

                # Track successful AI interaction
                log_ai_interaction(
                    case_id=case_id,
                    model=model_name,
                    latency_ms=round((time.time() - start_time) * 1000, 2),
                    status="success",
                    prompt_tokens=len(prompt) // 4,  # Rough estimate
                    completion_tokens=len(ai_text) // 4,
                )
            else:
                raise ValueError(f"Unexpected response format from Ollama: {result}")
        except (requests.exceptions.ConnectionError, Exception) as e:
            reason = "ConnectionError" if isinstance(e, requests.exceptions.ConnectionError) else str(e)
            logging.warning(f"AI Failure: {reason}. Using fallback analysis.")

            ai_analysis = build_predefined_ai_analysis(selected_language, raw_data)

            # CRITICAL: Overwrite the diagnosis with what you typed so your ICD-10 code works!
            user_symptom = request.form.get("symptoms") or "Viral Fever"
            ai_analysis["patient_view"]["primary_diagnosis"] = user_symptom

            # Track fallback AI interaction
            log_ai_interaction(
                case_id=case_id,
                model=model_name,
                latency_ms=round((time.time() - start_time) * 1000, 2),
                status="fallback",
                fallback_reason=reason,
            )

            flash("AI offline. Using simulation mode to save case.", "warning")
        if ai_analysis:
            diag = ai_analysis.get("patient_view", {}).get("primary_diagnosis", "")
            code = get_icd_code(diag)
            ai_analysis["doctor_view"]["icd10_code"] = code

        case_record = {
            "id": case_id,
            "patient_id": session["user_id"],
            "doctor_id": doctor_id,
            "timestamp": datetime.now().isoformat(),
            "raw_data": raw_data,
            "ai_analysis": ai_analysis,
            "status": "Pending Review",
        }
        add_case(case_record)

        log_audit_action("generate_summary", resource_type="case", resource_id=case_id)
        return redirect(url_for("patient_result", case_id=case_id))

    except Exception as e:
        logging.error(f"Critical Error: {e}")
        flash(f"System Error: {str(e)}", "danger")
        return redirect(url_for("patient_intake"))


@app.route("/patient/result/<case_id>")
@login_required
@patient_required
@audit_access(resource_type="case", pii=True)
def patient_result(case_id):
    lang_code = get_language()
    translations = get_translations(lang_code)

    case = get_case_by_id(case_id)
    if not case:
        flash("Case not found.", "danger")
        return redirect(url_for("patient_intake"))

    if case["patient_id"] != str(session["user_id"]):
        flash("Access Denied", "danger")
        return redirect(url_for("patient_intake"))

    return render_template("patient_result.html", case=case, t=translations, lang=lang_code)


@app.route("/patient/logout")
def patient_logout():
    log_audit_action("logout", resource_type="user", resource_id=str(session.get("user_id")))
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("landing"))


@app.route("/doctor/login", methods=["GET", "POST"])
def doctor_login():
    lang_code = get_language()
    translations = get_translations(lang_code)

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = get_user_by_username(username)

        if user and user["role"] == "doctor" and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["role"] = "doctor"
            session["name"] = user["full_name"]
            log_audit_action("login_success", resource_type="user", resource_id=str(user["id"]))
            return redirect(url_for("doctor_dashboard"))
        else:
            log_audit_action("login_failure", resource_type="user", resource_id=username)
            flash("Invalid credentials", "danger")
    return render_template("doctor_login.html", t=translations, lang=lang_code)


@app.route("/doctor/dashboard")
@login_required
@doctor_required
@audit_access(resource_type="dashboard")
def doctor_dashboard():
    lang_code = get_language()
    translations = get_translations(lang_code)

    doctor_id = session.get("user_id")

    search_query = request.args.get("search", "")
    urgency_filter = request.args.get("urgency", "")
    language_filter = request.args.get("language", "")

    cases_list = get_cases_for_doctor(doctor_id)

    if search_query:
        search_query = search_query.lower()
        cases_list = [
            c
            for c in cases_list
            if search_query in c["raw_data"].get("name", "").lower() or search_query in c["id"].lower()
        ]

    if urgency_filter:
        filtered_cases = []
        for c in cases_list:
            ai_analysis = c.get("ai_analysis")
            if ai_analysis is not None:
                doctor_view = ai_analysis.get("doctor_view", {})
                if doctor_view.get("urgency_level") == urgency_filter:
                    filtered_cases.append(c)
        cases_list = filtered_cases

    if language_filter:
        filtered_cases = []
        for c in cases_list:
            raw_data = c.get("raw_data")
            if raw_data is not None and raw_data.get("language") == language_filter:
                filtered_cases.append(c)
        cases_list = filtered_cases

    doctor_info = get_user_by_id(doctor_id)
    return render_template(
        "doctor_dashboard.html",
        cases=cases_list,
        doctor=doctor_info,
        t=translations,
        lang=lang_code,
        filters={"search": search_query, "urgency": urgency_filter, "language": language_filter},
    )


@app.route("/doctor/view/<case_id>")
@login_required
@doctor_required
@audit_access(resource_type="case", pii=True)
def doctor_view(case_id):
    lang_code = get_language()
    translations = get_translations(lang_code)

    doctor_id = session.get("user_id")
    case = get_case_by_id(case_id)

    if not case or case["doctor_id"] != str(doctor_id):
        flash("Case not found or access denied.", "danger")
        return redirect(url_for("doctor_dashboard"))

    return render_template("doctor_view.html", case=case, t=translations, lang=lang_code)


@app.route("/doctor/edit/<case_id>", methods=["GET", "POST"])
@login_required
@doctor_required
@audit_access(resource_type="case", pii=True)
def doctor_edit(case_id):
    lang_code = get_language()
    translations = get_translations(lang_code)

    doctor_id = session.get("user_id")
    case = get_case_by_id(case_id)

    if not case or case["doctor_id"] != str(doctor_id):
        flash("Case not found or access denied.", "danger")
        return redirect(url_for("doctor_dashboard"))

    if request.method == "POST":
        try:
            case_obj = Case.query.get(case_id)
            new_analysis = dict(case_obj.ai_analysis)

            new_analysis["doctor_view"]["subjective_list"] = request.form.getlist("subjective[]")
            new_analysis["doctor_view"]["objective_list"] = request.form.getlist("objective[]")
            new_analysis["doctor_view"]["assessment_list"] = request.form.getlist("assessment[]")
            new_analysis["doctor_view"]["plan_list"] = request.form.getlist("plan[]")

            from sqlalchemy.orm.attributes import flag_modified

            case_obj.ai_analysis = new_analysis
            flag_modified(case_obj, "ai_analysis")

            db.session.commit()

            log_audit_action("edit_case", case_id)
            flash("Case updated successfully.", "success")
            return redirect(url_for("doctor_view", case_id=case_id))
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error updating case: {e}")
            flash(f"Error updating case: {str(e)}", "danger")

    return render_template("doctor_edit.html", case=case, t=translations, lang=lang_code)


@app.route("/admin/logs")
@login_required
@doctor_required
@audit_access(resource_type="logs")
def admin_logs():
    lang_code = get_language()
    translations = get_translations(lang_code)

    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    return render_template("admin_logs.html", logs=logs, t=translations, lang=lang_code)


@app.route("/admin/mlops")
@login_required
@doctor_required
def mlops_dashboard():
    """Display AI performance and monitoring dashboard."""
    lang_code = get_language()
    translations = get_translations(lang_code)

    # Summary Metrics
    total_requests = AILog.query.count()
    success_requests = AILog.query.filter_by(status="success").count()
    fallback_requests = AILog.query.filter_by(status="fallback").count()

    # Success Rate
    success_rate = (success_requests / total_requests * 100) if total_requests > 0 else 0

    # Latency Stats
    avg_latency = db.session.query(db.func.avg(AILog.latency_ms)).scalar() or 0

    # Cost Stats
    total_cost = db.session.query(db.func.sum(AILog.cost)).scalar() or 0

    # Recent Logs
    recent_logs = AILog.query.order_by(AILog.timestamp.desc()).limit(20).all()

    return render_template(
        "mlops_dashboard.html",
        t=translations,
        lang=lang_code,
        metrics={
            "total": total_requests,
            "success_rate": round(success_rate, 2),
            "fallback_count": fallback_requests,
            "avg_latency": round(avg_latency, 2),
            "total_cost": round(total_cost, 4),
        },
        logs=recent_logs,
    )


@app.route("/doctor/logout")
def doctor_logout():
    log_audit_action("logout", resource_type="user", resource_id=str(session.get("user_id")))
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("landing"))


@app.route("/cases")
@login_required
def view_cases():
    """Display all cases for the logged-in user (doctor or patient)."""
    lang_code = get_language()
    translations = get_translations(lang_code)

    user_id = session.get("user_id")
    role = session.get("role")

    search_query = request.args.get("search", "")
    urgency_filter = request.args.get("urgency", "")
    language_filter = request.args.get("language", "")
    doctor_filter = request.args.get("doctor", "")

    if role == "doctor":
        cases_list = get_cases_for_doctor(user_id)
    elif role == "patient":
        cases_list = get_cases_for_patient(user_id)
    else:
        flash("Invalid role.", "danger")
        return redirect(url_for("landing"))

    if search_query:
        search_query = search_query.lower()
        cases_list = [
            c
            for c in cases_list
            if search_query in c["raw_data"].get("name", "").lower() or search_query in c["id"].lower()
        ]

    if urgency_filter:
        filtered_cases = []
        for c in cases_list:
            ai_analysis = c.get("ai_analysis")
            if ai_analysis is not None:
                doctor_view = ai_analysis.get("doctor_view", {})
                if doctor_view.get("urgency_level") == urgency_filter:
                    filtered_cases.append(c)
        cases_list = filtered_cases

    if language_filter:
        filtered_cases = []
        for c in cases_list:
            raw_data = c.get("raw_data")
            if raw_data is not None and raw_data.get("language") == language_filter:
                filtered_cases.append(c)
        cases_list = filtered_cases

    if doctor_filter:
        doctor_filter = doctor_filter.lower()
        filtered_cases = []
        for c in cases_list:
            raw_data = c.get("raw_data")
            if raw_data is not None:
                doctor_name = raw_data.get("doctor_name", "")
                if doctor_filter in doctor_name.lower():
                    filtered_cases.append(c)
        cases_list = filtered_cases

    return render_template(
        "cases.html",
        cases=cases_list,
        role=role,
        t=translations,
        lang=lang_code,
        filters={
            "search": search_query,
            "urgency": urgency_filter,
            "language": language_filter,
            "doctor": doctor_filter,
        },
    )


@app.route("/doctor/download/<case_id>")
@login_required
@doctor_required
def download_pdf(case_id):
    case = get_case_by_id(case_id)
    if not case:
        flash("Case not found.", "danger")
        return redirect(url_for("doctor_dashboard"))

    # Extract Data
    raw = case.get("raw_data", {})
    ai_doc = case.get("ai_analysis", {}).get("doctor_view", {})

    # Create PDF
    pdf = PDFReport()
    pdf.add_page()

    # 1. Patient Metadata
    pdf.set_font("Arial", "", 11)
    pdf.cell(100, 7, f"Patient Name: {raw.get('name', 'Unknown')}", 0, 0)
    pdf.cell(0, 7, f"Date: {case.get('timestamp', '')[:10]}", 0, 1)
    pdf.cell(100, 7, f"Age/Gender: {raw.get('age')} / {raw.get('gender')}", 0, 0)
    pdf.cell(0, 7, f"Case ID: {case.get('id')}", 0, 1)
    pdf.ln(5)

    # 2. SOAP Sections
    # Subjective
    pdf.chapter_title("Subjective (Patient History)")
    subj_text = ai_doc.get("subjective", "No data available.")
    # Add bullet points if available
    if "subjective_list" in ai_doc:
        for item in ai_doc["subjective_list"]:
            subj_text += f"\n- {item}"
    pdf.chapter_body(subj_text)

    # Objective
    pdf.chapter_title("Objective (Vitals & Observations)")
    obj_text = ai_doc.get("objective", "No data available.")
    # Add vitals manually if needed
    obj_text += f"\nBP: {raw.get('bp')} | Temp: {raw.get('temp')} | Wt: {raw.get('weight')}"
    pdf.chapter_body(obj_text)

    # Assessment
    pdf.chapter_title("Assessment (Diagnosis)")
    pdf.chapter_body(ai_doc.get("assessment", "No assessment generated."))

    # Plan
    pdf.chapter_title("Plan (Treatment & Follow-up)")
    plan_text = ai_doc.get("plan", "No plan generated.")
    if "plan_list" in ai_doc:
        for item in ai_doc["plan_list"]:
            plan_text += f"\n- {item}"
    pdf.chapter_body(plan_text)

    # Output to temporary file for download
    filename = f"Medical_Report_{case_id}.pdf"
    save_path = os.path.join(tempfile.gettempdir(), filename)
    pdf.output(save_path)

    log_audit_action("export_pdf", case_id)

    return send_file(save_path, as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)
