import logging
from datetime import datetime
from typing import Any, Optional
from cryptography.fernet import Fernet
from sqlalchemy.types import Text, TypeDecorator
from .extensions import db
from flask import current_app

# --- ENCRYPTION SETUP ---
_cipher_suite: Optional[Fernet] = None

def get_cipher_suite():
    global _cipher_suite
    if _cipher_suite is None:
        key = current_app.config.get("FERNET_KEY")
        if key:
            _cipher_suite = Fernet(key)
        else:
            logging.error("FERNET_KEY missing!")
    return _cipher_suite

class EncryptedString(TypeDecorator):
    """Custom TypeDecorator that encrypts data before saving to DB."""
    impl = Text
    cache_ok = True

    def process_bind_param(self, value: Optional[str], dialect: Any) -> Optional[str]:
        if value is None:
            return None
        cipher = get_cipher_suite()
        if not cipher:
            return value
        try:
            return cipher.encrypt(value.encode("utf-8")).decode("utf-8")
        except Exception as e:
            logging.error(f"Encryption failed: {e}")
            return value

    def process_result_value(self, value: Optional[str], dialect: Any) -> Optional[str]:
        if value is None:
            return None
        cipher = get_cipher_suite()
        if not cipher:
            return value
        try:
            return cipher.decrypt(value.encode("utf-8")).decode("utf-8")
        except Exception:
            return value

class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    full_name = db.Column(EncryptedString)
    specialty = db.Column(db.String(100), nullable=True)
    doctor_unique_id = db.Column(db.String(50), nullable=True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "full_name": self.full_name,
            "password_hash": self.password_hash,
            "specialty": self.specialty,
        }

class Case(db.Model):
    __tablename__ = "case"
    id = db.Column(db.String(50), primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    raw_data = db.Column(db.JSON)
    ai_analysis = db.Column(db.JSON)
    status = db.Column(db.String(50), default="Pending Review")

    patient = db.relationship("User", foreign_keys=[patient_id], backref="cases_as_patient")
    doctor = db.relationship("User", foreign_keys=[doctor_id], backref="cases_as_doctor")

    def to_dict(self) -> dict[str, Any]:
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

class ClinicalLog(db.Model):
    __tablename__ = "clinical_log"
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    case_id = db.Column(db.String(50), db.ForeignKey("case.id"))
    model = db.Column(db.String(50))
    latency_ms = db.Column(db.Float)
    symptoms_snippet = db.Column(EncryptedString)

class AuditLog(db.Model):
    __tablename__ = "audit_log"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    resource_type = db.Column(db.String(50))
    resource_id = db.Column(db.String(50))
    pii_accessed = db.Column(db.Boolean, default=False)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship("User", backref="audit_logs")

class AILog(db.Model):
    __tablename__ = "ai_log"
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.String(50), db.ForeignKey("case.id"), nullable=True)
    model = db.Column(db.String(50))
    latency_ms = db.Column(db.Float)
    prompt_tokens = db.Column(db.Integer, default=0)
    completion_tokens = db.Column(db.Integer, default=0)
    total_tokens = db.Column(db.Integer, default=0)
    cost = db.Column(db.Float, default=0.0)
    status = db.Column(db.String(20))
    fallback_reason = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
