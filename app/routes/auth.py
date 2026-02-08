from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from werkzeug.security import check_password_hash, generate_password_hash
from ..utils import get_user_by_username, get_language, get_translations, log_audit_action
from ..models import User, db

auth_bp = Blueprint("auth", __name__)

@auth_bp.route("/")
def landing():
    if "user_id" in session:
        if session["role"] == "patient":
            return redirect(url_for("patient.patient_intake"))
        elif session["role"] == "doctor":
            return redirect(url_for("doctor.doctor_dashboard"))

    lang_code = get_language()
    translations = get_translations(lang_code)
    return render_template("landing.html", t=translations, lang=lang_code)

@auth_bp.route("/set_language/<lang_code>")
def set_language(lang_code: str):
    from flask import current_app
    if lang_code in current_app.translations:
        session["language"] = lang_code
    return redirect(request.referrer or url_for("auth.landing"))

@auth_bp.route("/logout")
def logout():
    log_audit_action("logout")
    session.clear()
    return redirect(url_for("auth.landing"))

@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    lang_code = get_language()
    translations = get_translations(lang_code)

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        role = request.form.get("role")
        full_name = request.form.get("full_name")
        specialty = request.form.get("specialty")

        if User.query.filter_by(username=username).first():
            flash("Username already exists", "danger")
            return redirect(url_for("auth.register"))

        new_user = User(
            username=username,
            password_hash=generate_password_hash(password),
            role=role,
            full_name=full_name,
            specialty=specialty if role == "doctor" else None
        )
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful. Please login.", "success")
        return redirect(url_for("auth.landing"))

    return render_template("register.html", t=translations, lang=lang_code)
