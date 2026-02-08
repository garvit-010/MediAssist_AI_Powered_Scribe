import os
import tempfile
import logging
from flask import Blueprint, render_template, request, session, flash, redirect, url_for, jsonify
from ..utils import (
    login_required, patient_required, audit_access, 
    get_language, get_translations, get_cases_for_doctor, get_cases_for_patient
)
from ..services.ai_service import get_audio_model

main_bp = Blueprint("main", __name__)

@main_bp.route("/transcribe", methods=["POST"])
@login_required
@patient_required
@audit_access(resource_type="voice_data", pii=True)
def transcribe_audio():
    if "audio" not in request.files:
        return jsonify({"error": "No audio file provided"}), 400

    audio_model = get_audio_model()
    if not audio_model:
        return jsonify({"error": "Transcriber model not loaded on server."}), 503

    audio_file = request.files["audio"]
    if audio_file.filename == "":
        return jsonify({"error": "No selected file"}), 400

    try:
        with tempfile.NamedTemporaryFile(suffix=".webm", delete=False) as temp_audio:
            temp_path = temp_audio.name
            audio_file.save(temp_path)

        result = audio_model.transcribe(temp_path)
        transcribed_text = result["text"].strip()
        os.remove(temp_path)
        return jsonify({"text": transcribed_text})
    except Exception as e:
        logging.error(f"Transcription error: {e}")
        if 'temp_path' in locals() and os.path.exists(temp_path):
            os.remove(temp_path)
        return jsonify({"error": str(e)}), 500

@main_bp.route("/cases")
@login_required
def view_cases():
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
        return redirect(url_for("auth.landing"))

    if search_query:
        search_query = search_query.lower()
        cases_list = [c for c in cases_list if search_query in c["raw_data"].get("name", "").lower() or search_query in c["id"].lower()]

    if urgency_filter:
        cases_list = [c for c in cases_list if c.get("ai_analysis", {}).get("doctor_view", {}).get("urgency_level") == urgency_filter]

    if language_filter:
        cases_list = [c for c in cases_list if c.get("raw_data", {}).get("language") == language_filter]

    if doctor_filter:
        doctor_filter = doctor_filter.lower()
        cases_list = [c for c in cases_list if doctor_filter in c.get("raw_data", {}).get("doctor_name", "").lower()]

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
