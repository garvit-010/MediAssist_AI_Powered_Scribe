import pytest
from app.utils import audit_access
from app.models import AuditLog, AILog, User, Case
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
    from app.services.ai_service import log_ai_interaction
    
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
    from app.models import AILog
    
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

def test_doctor_edit_case(client, app, db_session):
    """Test editing a case by a doctor."""
    from werkzeug.security import generate_password_hash
    import uuid
    
    with app.app_context():
        doctor = User(
            username="edit_doc",
            password_hash=generate_password_hash("password"),
            role="doctor",
            full_name="Edit Doctor"
        )
        patient = User(
            username="edit_patient",
            password_hash=generate_password_hash("password"),
            role="patient",
            full_name="Edit Patient"
        )
        db_session.add(doctor)
        db_session.add(patient)
        db_session.commit()
        
        case_id = str(uuid.uuid4())[:8].upper()
        case = Case(
            id=case_id,
            patient_id=patient.id,
            doctor_id=doctor.id,
            raw_data={"name": "Edit Patient"},
            ai_analysis={
                "doctor_view": {
                    "subjective_list": ["Initial subjective"],
                    "objective_list": ["Initial objective"],
                    "assessment_list": ["Initial assessment"],
                    "plan_list": ["Initial plan"],
                    "subjective": "Initial",
                    "objective": "Initial",
                    "assessment": "Initial",
                    "plan": "Initial"
                },
                "safety": {"is_safe": True},
                "patient_view": {"primary_diagnosis": "Test"}
            },
            status="Pending Review"
        )
        db_session.add(case)
        db_session.commit()
        
        with client.session_transaction() as sess:
            sess['user_id'] = doctor.id
            sess['role'] = 'doctor'
            
        # GET edit page
        response = client.get(f'/doctor/edit/{case_id}')
        assert response.status_code == 200
        
        # POST edit
        data = {
            "subjective[]": ["Updated subjective"],
            "objective[]": ["Updated objective"],
            "assessment[]": ["Updated assessment"],
            "plan[]": ["Updated plan"]
        }
        response = client.post(f'/doctor/edit/{case_id}', data=data, follow_redirects=True)
        assert response.status_code == 200
        
        # Verify changes
        updated_case = Case.query.get(case_id)
        assert updated_case.ai_analysis["doctor_view"]["subjective_list"] == ["Updated subjective"]
        
        # Check audit log
        log = AuditLog.query.filter_by(user_id=doctor.id, action="edit_case").first()
        assert log is not None

def test_download_pdf(client, app, db_session):
    """Test downloading a case report as PDF."""
    from werkzeug.security import generate_password_hash
    import uuid
    
    with app.app_context():
        doctor = User(
            username="pdf_doc",
            password_hash=generate_password_hash("password"),
            role="doctor",
            full_name="PDF Doctor"
        )
        patient = User(
            username="pdf_patient",
            password_hash=generate_password_hash("password"),
            role="patient",
            full_name="PDF Patient"
        )
        db_session.add(doctor)
        db_session.add(patient)
        db_session.commit()
        
        case_id = str(uuid.uuid4())[:8].upper()
        case = Case(
            id=case_id,
            patient_id=patient.id,
            doctor_id=doctor.id,
            raw_data={"name": "PDF Patient", "age": "30", "gender": "Male"},
            ai_analysis={
                "doctor_view": {
                    "subjective": "Subj",
                    "objective": "Obj",
                    "assessment": "Asst",
                    "plan": "Plan",
                    "subjective_list": ["S1"],
                    "plan_list": ["P1"]
                }
            },
            timestamp=datetime.utcnow(),
            status="Completed"
        )
        db_session.add(case)
        db_session.commit()
        
        with client.session_transaction() as sess:
            sess['user_id'] = doctor.id
            sess['role'] = 'doctor'
            
        response = client.get(f'/doctor/download/{case_id}')
        assert response.status_code == 200
        assert response.mimetype == 'application/pdf'
        
        # Check audit log
        log = AuditLog.query.filter_by(user_id=doctor.id, action="export_pdf").first()
        assert log is not None
        assert log.resource_id == case_id
        assert log.resource_type == "case"

def test_doctor_dashboard_filters(client, app, db_session):
    """Test filtering cases on the doctor dashboard."""
    from werkzeug.security import generate_password_hash
    import uuid
    
    with app.app_context():
        doctor = User(
            username="filter_doc",
            password_hash=generate_password_hash("password"),
            role="doctor",
            full_name="Filter Doctor"
        )
        patient = User(
            username="filter_patient",
            password_hash=generate_password_hash("password"),
            role="patient",
            full_name="Filter Patient"
        )
        db_session.add(doctor)
        db_session.add(patient)
        db_session.commit()
        
        # Create cases with different attributes
        case1 = Case(
            id="C1", patient_id=patient.id, doctor_id=doctor.id,
            raw_data={"name": "Alice", "language": "English"},
            ai_analysis={"doctor_view": {"urgency_level": "High"}},
            status="Completed"
        )
        case2 = Case(
            id="C2", patient_id=patient.id, doctor_id=doctor.id,
            raw_data={"name": "Bob", "language": "Hindi"},
            ai_analysis={"doctor_view": {"urgency_level": "Low"}},
            status="Completed"
        )
        db_session.add(case1)
        db_session.add(case2)
        db_session.commit()
        
        with client.session_transaction() as sess:
            sess['user_id'] = doctor.id
            sess['role'] = 'doctor'
            
        # Test search filter
        response = client.get('/doctor/dashboard?search=Alice')
        assert "Alice" in response.data.decode()
        assert "Bob" not in response.data.decode()
        
        # Test urgency filter
        response = client.get('/doctor/dashboard?urgency=Low')
        assert "Bob" in response.data.decode()
        assert "Alice" not in response.data.decode()
        
        # Test language filter
        response = client.get('/doctor/dashboard?language=Hindi')
        assert "Bob" in response.data.decode()
        assert "Alice" not in response.data.decode()

def test_view_cases_filters(client, app, db_session):
    """Test filtering cases on the view_cases page."""
    from werkzeug.security import generate_password_hash
    
    with app.app_context():
        doctor = User(
            username="vfilter_doc",
            password_hash=generate_password_hash("password"),
            role="doctor",
            full_name="VFilter Doctor"
        )
        patient = User(
            username="vfilter_patient",
            password_hash=generate_password_hash("password"),
            role="patient",
            full_name="VFilter Patient"
        )
        db_session.add(doctor)
        db_session.add(patient)
        db_session.commit()
        
        case1 = Case(
            id="VC1", patient_id=patient.id, doctor_id=doctor.id,
            raw_data={"name": "Alice", "language": "English", "doctor_name": "Dr. X"},
            ai_analysis={"doctor_view": {"urgency_level": "High"}},
            status="Completed"
        )
        db_session.add(case1)
        db_session.commit()
        
        with client.session_transaction() as sess:
            sess['user_id'] = doctor.id
            sess['role'] = 'doctor'
            
        # Test doctor name filter
        response = client.get('/cases?doctor=Dr. X')
        assert "VC1" in response.data.decode()
        
        response = client.get('/cases?doctor=Dr. Y')
        assert "VC1" not in response.data.decode()

def test_doctor_login_failure_audit(client, app, db_session):
    """Test that failed doctor login is audited."""
    from werkzeug.security import generate_password_hash
    
    with app.app_context():
        doctor = User(
            username="login_fail_doc",
            password_hash=generate_password_hash("correct_password"),
            role="doctor",
            full_name="Login Fail Doctor"
        )
        db_session.add(doctor)
        db_session.commit()
        
        response = client.post('/doctor/login', data={
            "username": "login_fail_doc",
            "password": "wrong_password"
        }, follow_redirects=True)
        
        # Check audit log
        log = AuditLog.query.filter_by(action="login_failure", resource_id="login_fail_doc").first()
        assert log is not None

def test_download_pdf_not_found(client, app, db_session):
    """Test downloading PDF for non-existent case."""
    from werkzeug.security import generate_password_hash
    with app.app_context():
        doctor = User(
            username="pdf_fail_doc",
            password_hash=generate_password_hash("password"),
            role="doctor",
            full_name="PDF Fail Doctor"
        )
        db_session.add(doctor)
        db_session.commit()
        
        with client.session_transaction() as sess:
            sess['user_id'] = doctor.id
            sess['role'] = 'doctor'
            
        response = client.get('/doctor/download/NONEXISTENT', follow_redirects=True)
        assert response.status_code == 200
        assert "Case not found" in response.data.decode()

def test_view_cases_invalid_role(client, app, db_session):
    """Test view_cases with an invalid role in session."""
    from werkzeug.security import generate_password_hash
    with app.app_context():
        user = User(
            username="invalid_role_user",
            password_hash=generate_password_hash("password"),
            role="admin", # Not handled by view_cases role check
            full_name="Invalid Role User"
        )
        db_session.add(user)
        db_session.commit()
        
        with client.session_transaction() as sess:
            sess['user_id'] = user.id
            sess['role'] = 'admin'
            
        response = client.get('/cases', follow_redirects=True)
        assert "Invalid role" in response.data.decode()

def test_doctor_view_access_denied(client, app, db_session):
    """Test doctor viewing a case that doesn't belong to them."""
    from werkzeug.security import generate_password_hash
    with app.app_context():
        doc1 = User(username="doc1", password_hash=generate_password_hash("p"), role="doctor", full_name="D1")
        doc2 = User(username="doc2", password_hash=generate_password_hash("p"), role="doctor", full_name="D2")
        patient = User(username="p1", password_hash=generate_password_hash("p"), role="patient", full_name="P1")
        db_session.add_all([doc1, doc2, patient])
        db_session.commit()
        
        case = Case(id="CASE_D1", patient_id=patient.id, doctor_id=doc1.id, raw_data={}, ai_analysis={}, status="Pending")
        db_session.add(case)
        db_session.commit()
        
        with client.session_transaction() as sess:
            sess['user_id'] = doc2.id
            sess['role'] = 'doctor'
            
        response = client.get('/doctor/view/CASE_D1', follow_redirects=True)
        assert "Case not found or access denied" in response.data.decode()

def test_doctor_edit_access_denied(client, app, db_session):
    """Test doctor editing a case that doesn't belong to them."""
    from werkzeug.security import generate_password_hash
    with app.app_context():
        doc1 = User(username="edoc1", password_hash=generate_password_hash("p"), role="doctor", full_name="ED1")
        doc2 = User(username="edoc2", password_hash=generate_password_hash("p"), role="doctor", full_name="ED2")
        patient = User(username="ep1", password_hash=generate_password_hash("p"), role="patient", full_name="EP1")
        db_session.add_all([doc1, doc2, patient])
        db_session.commit()
        
        case = Case(id="ECASE_D1", patient_id=patient.id, doctor_id=doc1.id, raw_data={}, ai_analysis={}, status="Pending")
        db_session.add(case)
        db_session.commit()
        
        with client.session_transaction() as sess:
            sess['user_id'] = doc2.id
            sess['role'] = 'doctor'
            
        response = client.get('/doctor/edit/ECASE_D1', follow_redirects=True)
        assert "Case not found or access denied" in response.data.decode()
