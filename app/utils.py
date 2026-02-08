import json
import os
import logging
from functools import wraps
from typing import Any, Callable, TypeVar, cast, Optional
from flask import redirect, url_for, session, request, current_app, Response as WerkzeugResponse
from .models import User, Case, AuditLog, db
from datetime import datetime

TRANSLATIONS: dict[str, Any] = {}

def ratelimit_handler(e: Exception):
    from flask import flash, redirect, url_for, request
    log_audit_action("rate_limit_exceeded", resource_type="api", resource_id=request.remote_addr)
    flash("Too many requests. Please slow down.", "warning")
    return redirect(request.referrer or url_for("auth.landing"))

def load_translations(app_root: str) -> None:
    global TRANSLATIONS
    translations_dir = os.path.join(os.path.dirname(app_root), "translations")
    for lang_code in ["en", "hi"]:
        lang_file = os.path.join(translations_dir, f"{lang_code}.json")
        if os.path.exists(lang_file):
            try:
                with open(lang_file, "r", encoding="utf-8") as f:
                    TRANSLATIONS[lang_code] = json.load(f)
            except Exception as e:
                logging.error(f"Error loading translation {lang_code}: {e}")

F = TypeVar("F", bound=Callable[..., Any])

def login_required(f: F) -> F:
    @wraps(f)
    def decorated_function(*args: Any, **kwargs: Any) -> Any:
        if "user_id" not in session:
            return redirect(url_for("auth.landing"))
        return f(*args, **kwargs)
    return cast(F, decorated_function)

def patient_required(f: F) -> F:
    @wraps(f)
    def decorated_function(*args: Any, **kwargs: Any) -> Any:
        if session.get("role") != "patient":
            return redirect(url_for("auth.landing"))
        return f(*args, **kwargs)
    return cast(F, decorated_function)

def doctor_required(f: F) -> F:
    @wraps(f)
    def decorated_function(*args: Any, **kwargs: Any) -> Any:
        if session.get("role") != "doctor":
            return redirect(url_for("auth.landing"))
        return f(*args, **kwargs)
    return cast(F, decorated_function)

def log_audit_action(
    action: str,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    user_id: Optional[Any] = None,
    pii_accessed: bool = False,
) -> Optional[bool]:
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
    def decorator(f: F) -> F:
        @wraps(f)
        def decorated_function(*args: Any, **kwargs: Any) -> Any:
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

def get_user_by_username(username: Optional[str]) -> Optional[dict[str, Any]]:
    if username is None:
        return None
    user = User.query.filter_by(username=username).first()
    return user.to_dict() if user else None

def get_user_by_id(user_id: Any) -> Optional[dict[str, Any]]:
    try:
        user = User.query.get(int(user_id))
        return user.to_dict() if user else None
    except (ValueError, TypeError):
        return None

def get_all_doctors() -> list[dict[str, Any]]:
    doctors = User.query.filter_by(role="doctor").all()
    return [d.to_dict() for d in doctors]

def get_case_by_id(case_id: str) -> Optional[dict[str, Any]]:
    from .models import Case
    case = Case.query.get(case_id)
    return case.to_dict() if case else None

def get_cases_for_doctor(doctor_id: Any) -> list[dict[str, Any]]:
    from .models import Case
    cases = Case.query.filter_by(doctor_id=int(doctor_id)).order_by(Case.timestamp.desc()).all()
    return [c.to_dict() for c in cases]

def get_cases_for_patient(patient_id: Any) -> list[dict[str, Any]]:
    from .models import Case
    cases = Case.query.filter_by(patient_id=int(patient_id)).order_by(Case.timestamp.desc()).all()
    return [c.to_dict() for c in cases]

def is_test_case(raw_data: dict[str, Any]) -> bool:
    """Return True if the intake matches the predefined test fixture."""
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
    ]
    return all(checks)

def add_case(case_data: dict[str, Any]) -> None:
    """Add a new case to the database."""
    from .models import Case
    from .extensions import db
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
            status=case_data.get("status", "Pending Review"),
        )
        db.session.add(new_case)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error adding case: {e}")
        raise

def get_language() -> str:
    return str(session.get("language", "en"))

def get_translations(lang_code: Optional[str] = None) -> dict[str, Any]:
    if lang_code is None:
        lang_code = get_language()
    return TRANSLATIONS.get(lang_code, TRANSLATIONS.get("en", {}))
