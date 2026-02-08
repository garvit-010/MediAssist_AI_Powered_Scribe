import os
import uuid
import tempfile
import logging
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify
from ..utils import (
    login_required, patient_required, audit_access, 
    get_all_doctors, get_user_by_id, get_language, 
    get_translations, log_audit_action, get_case_by_id
)
from ..models import Case, db
from ..services.ai_service import get_audio_model, analyze_case
from ..extensions import limiter

patient_bp = Blueprint("patient", __name__, url_prefix="/patient")

@patient_bp.route("/login", methods=["GET", "POST"])
def patient_login():
    lang_code = get_language()
    translations = get_translations(lang_code)

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        from ..utils import get_user_by_username
        from werkzeug.security import check_password_hash
        user = get_user_by_username(username)

        if user and user["role"] == "patient" and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["role"] = "patient"
            session["account_name"] = user["full_name"]
            log_audit_action("login_success", resource_type="user", resource_id=str(user["id"]))
            return redirect(url_for("patient.patient_intake"))
        else:
            log_audit_action("login_failure", resource_type="user", resource_id=username)
            flash("Invalid username or password", "danger")
    return render_template("patient_login.html", t=translations, lang=lang_code)

@patient_bp.route("/logout")
def logout():
    log_audit_action("logout")
    session.clear()
    return redirect(url_for("auth.landing"))

@patient_bp.route("/intake")
@login_required
@patient_required
def patient_intake():
    lang_code = get_language()
    translations = get_translations(lang_code)
    doctors = get_all_doctors()
    doctor_list = [{"id": d["id"], "name": d["full_name"], "specialty": d["specialty"]} for d in doctors]
    return render_template("intake.html", doctors=doctor_list, t=translations, lang=lang_code)

@patient_bp.route("/submit", methods=["POST"])
@login_required
@patient_required
@limiter.limit("5 per minute")
def patient_submit():
    try:
        symptoms = request.form.get("symptoms", "").strip()
        if not symptoms or len(symptoms) < 10:
            flash("Please provide more detail in symptoms (at least 10 characters).", "danger")
            return redirect(url_for("patient.patient_intake"))

        case_id = str(uuid.uuid4())[:8].upper()
        selected_language = request.form.get("language", "English")
        doctor_id = request.form.get("doctor_id")
        doctor = get_user_by_id(doctor_id)

        raw_data = {
            "id": case_id,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "patient_name": session.get("account_name", "Unknown"),
            "doctor_name": doctor["full_name"] if doctor else "Unknown",
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
            "symptoms": symptoms,
            "notes": request.form.get("other_notes"),
            "language": selected_language,
        }

        log_audit_action("case_creation", resource_type="case", resource_id=case_id)
        ai_analysis = analyze_case(raw_data, selected_language)

        new_case = Case(
            id=case_id,
            patient_id=session["user_id"],
            doctor_id=int(doctor_id),
            raw_data=raw_data,
            ai_analysis=ai_analysis,
            status="Pending Review"
        )
        db.session.add(new_case)
        db.session.commit()

        return redirect(url_for("patient.patient_result", case_id=case_id))
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error submitting case: {e}")
        flash("An error occurred while submitting your case.", "danger")
        return redirect(url_for("patient.patient_intake"))

@patient_bp.route("/result/<case_id>")
@login_required
@patient_required
@audit_access(resource_type="case", pii=True)
def patient_result(case_id):
    case = get_case_by_id(case_id)
    if not case or int(case["patient_id"]) != session["user_id"]:
        flash("Case not found or access denied.", "danger")
        return redirect(url_for("patient.patient_intake"))

    lang_code = get_language()
    translations = get_translations(lang_code)
    return render_template("patient_result.html", case=case, t=translations, lang=lang_code)
