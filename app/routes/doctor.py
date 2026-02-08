import os
import tempfile
import logging
from flask import Blueprint, render_template, request, redirect, url_for, session, flash, send_file
from werkzeug.security import check_password_hash
from sqlalchemy.orm.attributes import flag_modified
from ..utils import (
    login_required, doctor_required, audit_access,
    get_cases_for_doctor, get_user_by_id, get_case_by_id,
    get_language, get_translations, log_audit_action,
    get_user_by_username
)
from ..models import Case, db
from ..services.pdf_service import PDFReport

doctor_bp = Blueprint("doctor", __name__, url_prefix="/doctor")

@doctor_bp.route("/login", methods=["GET", "POST"])
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
            return redirect(url_for("doctor.doctor_dashboard"))
        else:
            log_audit_action("login_failure", resource_type="user", resource_id=username)
            flash("Invalid credentials", "danger")
    return render_template("doctor_login.html", t=translations, lang=lang_code)

@doctor_bp.route("/logout")
def logout():
    log_audit_action("logout")
    session.clear()
    return redirect(url_for("auth.landing"))

@doctor_bp.route("/dashboard")
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
        cases_list = [c for c in cases_list if search_query in c["raw_data"].get("name", "").lower() or search_query in c["id"].lower()]

    if urgency_filter:
        cases_list = [c for c in cases_list if c.get("ai_analysis", {}).get("doctor_view", {}).get("urgency_level") == urgency_filter]

    if language_filter:
        cases_list = [c for c in cases_list if c.get("raw_data", {}).get("language") == language_filter]

    doctor_info = get_user_by_id(doctor_id)
    return render_template(
        "doctor_dashboard.html",
        cases=cases_list,
        doctor=doctor_info,
        t=translations,
        lang=lang_code,
        filters={"search": search_query, "urgency": urgency_filter, "language": language_filter},
    )

@doctor_bp.route("/view/<case_id>")
@login_required
@doctor_required
@audit_access(resource_type="case", pii=True)
def doctor_view(case_id):
    lang_code = get_language()
    translations = get_translations(lang_code)
    doctor_id = session.get("user_id")
    case = get_case_by_id(case_id)

    if not case or int(case["doctor_id"]) != doctor_id:
        flash("Case not found or access denied.", "danger")
        return redirect(url_for("doctor.doctor_dashboard"))

    return render_template("doctor_view.html", case=case, t=translations, lang=lang_code)

@doctor_bp.route("/edit/<case_id>", methods=["GET", "POST"])
@login_required
@doctor_required
@audit_access(resource_type="case", pii=True)
def doctor_edit(case_id):
    lang_code = get_language()
    translations = get_translations(lang_code)
    doctor_id = session.get("user_id")
    case = get_case_by_id(case_id)

    if not case or int(case["doctor_id"]) != doctor_id:
        flash("Case not found or access denied.", "danger")
        return redirect(url_for("doctor.doctor_dashboard"))

    if request.method == "POST":
        try:
            case_obj = Case.query.get(case_id)
            new_analysis = dict(case_obj.ai_analysis)

            new_analysis["doctor_view"]["subjective_list"] = request.form.getlist("subjective[]")
            new_analysis["doctor_view"]["objective_list"] = request.form.getlist("objective[]")
            new_analysis["doctor_view"]["assessment_list"] = request.form.getlist("assessment[]")
            new_analysis["doctor_view"]["plan_list"] = request.form.getlist("plan[]")

            case_obj.ai_analysis = new_analysis
            flag_modified(case_obj, "ai_analysis")
            db.session.commit()

            log_audit_action("edit_case", resource_type="case", resource_id=case_id)
            flash("Case updated successfully.", "success")
            return redirect(url_for("doctor.doctor_view", case_id=case_id))
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error updating case: {e}")
            flash(f"Error updating case: {str(e)}", "danger")

    return render_template("doctor_edit.html", case=case, t=translations, lang=lang_code)

@doctor_bp.route("/download/<case_id>")
@login_required
@doctor_required
def download_pdf(case_id):
    case = get_case_by_id(case_id)
    if not case:
        flash("Case not found.", "danger")
        return redirect(url_for("doctor.doctor_dashboard"))

    raw = case.get("raw_data", {})
    ai_doc = case.get("ai_analysis", {}).get("doctor_view", {})

    pdf = PDFReport()
    pdf.add_page()
    pdf.set_font("Arial", "", 11)
    pdf.cell(100, 7, f"Patient Name: {raw.get('name', 'Unknown')}", 0, 0)
    pdf.cell(0, 7, f"Date: {case.get('timestamp', '')[:10]}", 0, 1)
    pdf.cell(100, 7, f"Age/Gender: {raw.get('age')} / {raw.get('gender')}", 0, 0)
    pdf.cell(0, 7, f"Case ID: {case.get('id')}", 0, 1)
    pdf.ln(5)

    pdf.chapter_title("Subjective (Patient History)")
    subj_text = ai_doc.get("subjective", "No data available.")
    if "subjective_list" in ai_doc:
        for item in ai_doc["subjective_list"]:
            subj_text += f"\n- {item}"
    pdf.chapter_body(subj_text)

    pdf.chapter_title("Objective (Vitals & Observations)")
    obj_text = ai_doc.get("objective", "No data available.")
    obj_text += f"\nBP: {raw.get('bp')} | Temp: {raw.get('temp')} | Wt: {raw.get('weight')}"
    pdf.chapter_body(obj_text)

    pdf.chapter_title("Assessment (Diagnosis)")
    pdf.chapter_body(ai_doc.get("assessment", "No assessment generated."))

    pdf.chapter_title("Plan (Treatment & Follow-up)")
    plan_text = ai_doc.get("plan", "No plan generated.")
    if "plan_list" in ai_doc:
        for item in ai_doc["plan_list"]:
            plan_text += f"\n- {item}"
    pdf.chapter_body(plan_text)

    filename = f"Medical_Report_{case_id}.pdf"
    save_path = os.path.join(tempfile.gettempdir(), filename)
    pdf.output(save_path)
    log_audit_action("export_pdf", resource_type="case", resource_id=case_id)
    return send_file(save_path, as_attachment=True)
