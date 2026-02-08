from flask import Blueprint, render_template, session
from ..utils import login_required, doctor_required, audit_access, get_language, get_translations
from ..models import AuditLog, AILog, db

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

@admin_bp.route("/logs")
@login_required
@doctor_required
@audit_access(resource_type="logs")
def admin_logs():
    lang_code = get_language()
    translations = get_translations(lang_code)
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    return render_template("admin_logs.html", logs=logs, t=translations, lang=lang_code)

@admin_bp.route("/mlops")
@login_required
@doctor_required
def mlops_dashboard():
    lang_code = get_language()
    translations = get_translations(lang_code)

    total_requests = AILog.query.count()
    success_requests = AILog.query.filter_by(status="success").count()
    fallback_requests = AILog.query.filter_by(status="fallback").count()
    success_rate = (success_requests / total_requests * 100) if total_requests > 0 else 0
    avg_latency = db.session.query(db.func.avg(AILog.latency_ms)).scalar() or 0
    total_cost = db.session.query(db.func.sum(AILog.cost)).scalar() or 0
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
