import pytest
from app import AuditLog, AILog, User, Case
from datetime import datetime

def test_audit_logging_on_access(client, app, db_session):
    """Test that accessing a route with @audit_access creates an audit log."""
    from werkzeug.security import generate_password_hash
    
    with app.app_context():
        # Create a doctor user
        doctor = User(
            username="audit_doc",
            password_hash=generate_password_hash("password"),
            role="doctor",
            full_name="Audit Doctor"
        )
        db_session.add(doctor)
        db_session.commit()
        
        # Log in as doctor
        with client.session_transaction() as sess:
            sess['user_id'] = doctor.id
            sess['role'] = 'doctor'
            sess['name'] = doctor.full_name
            
        # Access doctor dashboard (decorated with @audit_access)
        response = client.get('/doctor/dashboard')
        assert response.status_code == 200
        
        # Check if audit log was created
        logs = AuditLog.query.filter_by(user_id=doctor.id, action="access_doctor_dashboard").all()
        assert len(logs) == 1
        assert logs[0].resource_type == "dashboard"
        assert logs[0].pii_accessed is False
        assert logs[0].ip_address is not None

def test_pii_access_audit(client, app, db_session):
    """Test that accessing PII-sensitive routes flags the audit log."""
    from werkzeug.security import generate_password_hash
    import uuid
    
    with app.app_context():
        doctor = User(
            username="pii_doc",
            password_hash=generate_password_hash("password"),
            role="doctor",
            full_name="PII Doctor"
        )
        patient = User(
            username="pii_patient",
            password_hash=generate_password_hash("password"),
            role="patient",
            full_name="PII Patient"
        )
        db_session.add(doctor)
        db_session.add(patient)
        db_session.commit()
        
        case_id = str(uuid.uuid4())[:8].upper()
        case = Case(
            id=case_id,
            patient_id=patient.id,
            doctor_id=doctor.id,
            raw_data={"name": "PII Patient"},
            ai_analysis={
                "doctor_view": {"urgency_level": "High"},
                "safety": {"is_safe": True},
                "patient_view": {"primary_diagnosis": "Test Diagnosis"}
            },
            status="Pending Review"
        )
        db_session.add(case)
        db_session.commit()
        
        # Log in as doctor
        with client.session_transaction() as sess:
            sess['user_id'] = doctor.id
            sess['role'] = 'doctor'
            sess['name'] = doctor.full_name
            
        # Access doctor view (decorated with @audit_access(pii=True))
        response = client.get(f'/doctor/view/{case_id}')
        assert response.status_code == 200
        
        # Check audit log
        log = AuditLog.query.filter_by(user_id=doctor.id, action="access_doctor_view").first()
        assert log is not None
        assert log.pii_accessed is True
        assert log.resource_type == "case"
        assert log.resource_id == case_id

def test_ai_monitoring_logs(client, app, db_session):
    """Test that AI interactions are logged correctly for MLOps."""
    from app import log_ai_interaction
    
    with app.app_context():
        log_ai_interaction(
            case_id="TEST-AI",
            model="llama3",
            latency_ms=1500.0,
            status="success",
            prompt_tokens=100,
            completion_tokens=50
        )
        
        log = AILog.query.filter_by(case_id="TEST-AI").first()
        assert log is not None
        assert log.model == "llama3"
        assert log.latency_ms == 1500.0
        assert log.total_tokens == 150
        assert log.cost > 0
        assert log.status == "success"

def test_mlops_dashboard_metrics(client, app, db_session):
    """Test that the MLOps dashboard displays correct metrics."""
    from werkzeug.security import generate_password_hash
    from app import AILog
    
    with app.app_context():
        # Setup doctor
        doctor = User(
            username="mlops_admin",
            password_hash=generate_password_hash("password"),
            role="doctor",
            full_name="Admin Doctor"
        )
        db_session.add(doctor)
        
        # Add some AI logs
        log1 = AILog(model="llama3", latency_ms=1000, status="success", cost=0.01, timestamp=datetime.utcnow())
        log2 = AILog(model="llama3", latency_ms=2000, status="fallback", cost=0.00, timestamp=datetime.utcnow())
        db_session.add(log1)
        db_session.add(log2)
        db_session.commit()
        
        # Log in
        with client.session_transaction() as sess:
            sess['user_id'] = doctor.id
            sess['role'] = 'doctor'
            
        response = client.get('/admin/mlops')
        assert response.status_code == 200
        content = response.data.decode()
        
        # Check if metrics are in the response
        assert "50.0%" in content  # Success rate (1 success, 1 fallback)
        assert "1500.0ms" in content  # Avg latency
        assert "Total Requests" in content
        assert "Total Token Cost" in content
