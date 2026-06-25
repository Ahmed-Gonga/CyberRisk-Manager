from datetime import date, timedelta
from sqlalchemy.orm import Session
from . import models
from .auth import hash_password
from .utils.risk import calculate_risk_score, map_severity

VALID_CRITICALITIES = {"Low", "Medium", "High", "Critical"}
VALID_RISK_STATUSES = {"Open", "In Progress", "Mitigated", "Accepted"}
VALID_CONTROL_STATUSES = {"Not Implemented", "Partially Implemented", "Implemented"}
VALID_TREATMENTS = {"Avoid", "Mitigate", "Transfer", "Accept"}
VALID_FINDING_RATINGS = {"Low", "Medium", "High", "Critical"}
VALID_ROLES = {"Admin", "Auditor", "Risk Manager", "Viewer"}


def create_demo_user(db: Session):
    """Seed portfolio demo users for RBAC testing.

    These accounts are intentionally simple for local portfolio demonstration.
    Passwords are still stored as PBKDF2 hashes, never plaintext.
    """
    demo_users = [
        ("admin", "admin123", "Admin"),
        ("auditor", "auditor123", "Auditor"),
        ("riskmanager", "risk123", "Risk Manager"),
        ("viewer", "viewer123", "Viewer"),
    ]
    created = False
    for username, password, role in demo_users:
        user = db.query(models.User).filter_by(username=username).first()
        if not user:
            db.add(models.User(username=username, password_hash=hash_password(password), role=role))
            created = True
        elif user.role != role:
            user.role = role
            created = True
    if created:
        db.commit()


def log_action(db: Session, username: str, action: str, entity: str, entity_id=None, details: str = ""):
    entry = models.AuditLog(username=username or "system", action=action, entity=entity, entity_id=entity_id, details=details)
    db.add(entry)
    db.commit()
    return entry


def create_asset(db: Session, **data):
    asset = models.Asset(**data)
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


def update_asset(db: Session, asset: models.Asset, **data):
    for key, value in data.items():
        setattr(asset, key, value)
    db.commit()
    db.refresh(asset)
    return asset


def create_risk(db: Session, **data):
    score = calculate_risk_score(int(data["likelihood"]), int(data["impact"]))
    data["calculated_risk_score"] = score
    data["severity"] = map_severity(score)
    risk = models.Risk(**data)
    db.add(risk)
    db.commit()
    db.refresh(risk)
    return risk


def update_risk(db: Session, risk: models.Risk, **data):
    score = calculate_risk_score(int(data["likelihood"]), int(data["impact"]))
    data["calculated_risk_score"] = score
    data["severity"] = map_severity(score)
    for key, value in data.items():
        setattr(risk, key, value)
    db.commit()
    db.refresh(risk)
    return risk


def create_control(db: Session, **data):
    control = models.Control(**data)
    db.add(control)
    db.commit()
    db.refresh(control)
    return control


def update_control(db: Session, control: models.Control, **data):
    for key, value in data.items():
        setattr(control, key, value)
    db.commit()
    db.refresh(control)
    return control


def create_finding(db: Session, **data):
    finding = models.AuditFinding(**data)
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding


def update_finding(db: Session, finding: models.AuditFinding, **data):
    for key, value in data.items():
        setattr(finding, key, value)
    db.commit()
    db.refresh(finding)
    return finding


def seed_data(db: Session):
    create_demo_user(db)
    if db.query(models.Asset).count() > 0:
        return

    assets = {
        "Customer Database": create_asset(db, name="Customer Database", asset_type="Database", owner="IT Security", description="Database containing customer records and sensitive business data.", criticality="Critical", location="Private Cloud"),
        "Internal Web Application": create_asset(db, name="Internal Web Application", asset_type="Application", owner="Engineering", description="Employee-facing internal business application.", criticality="High", location="Data Center"),
        "Employee Laptop Fleet": create_asset(db, name="Employee Laptop Fleet", asset_type="Endpoint", owner="IT Operations", description="Managed employee laptops used for daily work.", criticality="Medium", location="Corporate Offices"),
        "VPN Gateway": create_asset(db, name="VPN Gateway", asset_type="Network", owner="Network Team", description="Remote access gateway for employees and administrators.", criticality="Critical", location="DMZ"),
        "Cloud Storage Bucket": create_asset(db, name="Cloud Storage Bucket", asset_type="Cloud Storage", owner="Cloud Platform", description="Object storage bucket used for application exports and backups.", criticality="High", location="Cloud"),
    }

    risks = {
        "Unauthorized access to customer database": create_risk(db, title="Unauthorized access to customer database", asset_id=assets["Customer Database"].id, threat="External attacker or malicious insider", vulnerability="Weak access governance and insufficient review of privileged accounts", likelihood=4, impact=5, status="Open", treatment_plan="Mitigate", risk_owner="Identity Team", target_date=date.today() + timedelta(days=45), recommendation="Enforce RBAC, quarterly access reviews, MFA, and database activity monitoring."),
        "Missing MFA on VPN": create_risk(db, title="Missing MFA on VPN", asset_id=assets["VPN Gateway"].id, threat="Credential stuffing and phishing", vulnerability="Single-factor authentication for remote access", likelihood=5, impact=4, status="In Progress", treatment_plan="Mitigate", risk_owner="Network Team", target_date=date.today() + timedelta(days=30), recommendation="Deploy MFA for all VPN users and monitor anomalous login attempts."),
        "Public exposure of cloud storage bucket": create_risk(db, title="Public exposure of cloud storage bucket", asset_id=assets["Cloud Storage Bucket"].id, threat="Internet-based unauthenticated access", vulnerability="Misconfigured public bucket policy", likelihood=4, impact=5, status="Open", treatment_plan="Mitigate", risk_owner="Cloud Platform", target_date=date.today() - timedelta(days=7), recommendation="Block public access, enable encryption, and implement configuration monitoring."),
        "SQL Injection in internal web application": create_risk(db, title="SQL Injection in internal web application", asset_id=assets["Internal Web Application"].id, threat="Application attacker", vulnerability="Unsanitized database queries in legacy modules", likelihood=3, impact=5, status="Open", treatment_plan="Mitigate", risk_owner="Engineering", target_date=date.today() + timedelta(days=60), recommendation="Use parameterized queries, secure code review, and application security testing."),
    }

    create_control(db, name="Multi-Factor Authentication", framework_reference="Access Control", iso27001_reference="A.5.17", nist_csf_function="PR.AC", description="Require MFA for privileged and remote access.", implementation_status="Partially Implemented", owner="IT Security", risk_id=risks["Missing MFA on VPN"].id, evidence_link="https://example.com/mfa-rollout")
    create_control(db, name="Role-Based Access Control", framework_reference="Least Privilege", iso27001_reference="A.5.15", nist_csf_function="PR.AC", description="Grant access based on job role and least privilege.", implementation_status="Implemented", owner="Identity Team", risk_id=risks["Unauthorized access to customer database"].id, evidence_link="https://example.com/access-review")
    create_control(db, name="Security Logging and Monitoring", framework_reference="Monitoring", iso27001_reference="A.8.15", nist_csf_function="DE.CM", description="Centralize logs and alert on suspicious behavior.", implementation_status="Partially Implemented", owner="SOC", risk_id=risks["Public exposure of cloud storage bucket"].id, evidence_link="https://example.com/logging-dashboard")
    create_control(db, name="Secure Coding Review", framework_reference="Secure Development", iso27001_reference="A.8.28", nist_csf_function="PR.IP", description="Review code for injection flaws and authentication weaknesses.", implementation_status="Partially Implemented", owner="Engineering", risk_id=risks["SQL Injection in internal web application"].id, evidence_link="https://example.com/code-review")
    create_control(db, name="Backup and Recovery Procedure", framework_reference="Continuity", iso27001_reference="A.8.13", nist_csf_function="RC.RP", description="Maintain tested backups and documented recovery procedures.", implementation_status="Implemented", owner="IT Operations", risk_id=None, evidence_link="https://example.com/backup-test")

    create_finding(db, finding_id="FIND-001", observation="VPN access does not consistently enforce MFA for all remote users.", risk_rating="Critical", recommendation="Complete MFA rollout and enforce conditional access for VPN authentication.", owner="Network Team", due_date=date.today() + timedelta(days=30), risk_id=risks["Missing MFA on VPN"].id, status="Open")
    create_finding(db, finding_id="FIND-002", observation="Cloud storage bucket configuration permits overly broad access.", risk_rating="Critical", recommendation="Disable public access and enable continuous configuration monitoring.", owner="Cloud Platform", due_date=date.today() - timedelta(days=7), risk_id=risks["Public exposure of cloud storage bucket"].id, status="Open")
    create_finding(db, finding_id="FIND-003", observation="Legacy application modules have insufficient input validation.", risk_rating="High", recommendation="Implement parameterized queries and secure code review before release.", owner="Engineering", due_date=date.today() + timedelta(days=60), risk_id=risks["SQL Injection in internal web application"].id, status="Open")

    log_action(db, "system", "seed", "database", details="Seeded portfolio demo data")
