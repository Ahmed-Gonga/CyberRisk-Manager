import os
from datetime import datetime
from typing import Optional

from fastapi import Depends, FastAPI, Form, HTTPException, Request, status as http_status
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy.orm import Session

from . import crud, models
from .auth import authenticate_user, create_access_token, get_api_user, login_required, require_api_role, require_role
from .database import Base, engine, get_db
from .utils.report import generate_audit_report
from .utils.risk import build_heatmap, is_overdue

app = FastAPI(title="CyberRisk Manager", description="Cyber risk management, GRC, and IT audit portfolio project")
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SECRET_KEY", "dev-change-me"), same_site="lax", https_only=False)
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

CRITICALITIES = ["Low", "Medium", "High", "Critical"]
RISK_STATUSES = ["Open", "In Progress", "Mitigated", "Accepted"]
TREATMENT_PLANS = ["Avoid", "Mitigate", "Transfer", "Accept"]
CONTROL_STATUSES = ["Not Implemented", "Partially Implemented", "Implemented"]
FINDING_STATUSES = ["Open", "In Progress", "Closed"]
ROLES = ["Admin", "Auditor", "Risk Manager", "Viewer"]
ADMIN_ONLY = {"Admin"}
REGISTRY_EDITORS = {"Admin", "Risk Manager"}
FINDING_EDITORS = {"Admin", "Auditor", "Risk Manager"}
REPORT_VIEWERS = {"Admin", "Auditor", "Risk Manager"}
AUDIT_LOG_VIEWERS = {"Admin", "Auditor"}
READ_ONLY_ROLES = {"Admin", "Auditor", "Risk Manager", "Viewer"}



def _sqlite_migrate_existing_database():
    """Small SQLite-only migration helper for users upgrading the MVP locally.

    SQLAlchemy create_all creates missing tables but does not alter existing tables.
    This keeps the portfolio app smooth for local upgrades without adding Alembic.
    """
    if not str(engine.url).startswith("sqlite"):
        return
    additions = {
        "users": [
            ("role", "VARCHAR(40) NOT NULL DEFAULT 'Admin'"),
        ],
        "risks": [
            ("treatment_plan", "VARCHAR(30) NOT NULL DEFAULT 'Mitigate'"),
            ("risk_owner", "VARCHAR(120) DEFAULT 'Security Team'"),
            ("target_date", "DATE"),
        ],
        "controls": [
            ("iso27001_reference", "VARCHAR(80) DEFAULT ''"),
            ("nist_csf_function", "VARCHAR(80) DEFAULT ''"),
        ],
    }
    with engine.begin() as conn:
        for table, columns in additions.items():
            existing = {row[1] for row in conn.exec_driver_sql(f"PRAGMA table_info({table})").fetchall()}
            for column, ddl in columns:
                if column not in existing:
                    conn.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")

def init_db():
    Base.metadata.create_all(bind=engine)
    _sqlite_migrate_existing_database()
    db = next(get_db())
    try:
        crud.seed_data(db)
    finally:
        db.close()


@app.on_event("startup")
def on_startup():
    init_db()


def ctx(request: Request, **kwargs):
    role = request.session.get("role")
    permissions = {
        "can_edit_registers": role in REGISTRY_EDITORS,
        "can_delete_registers": role in ADMIN_ONLY,
        "can_manage_findings": role in FINDING_EDITORS,
        "can_delete_findings": role in ADMIN_ONLY,
        "can_view_reports": role in REPORT_VIEWERS,
        "can_view_audit_logs": role in AUDIT_LOG_VIEWERS,
        "can_view_users": role in ADMIN_ONLY,
    }
    data = {"request": request, "user": request.session.get("username"), "role": role, **permissions}
    data.update(kwargs)
    return data


def enforce_roles(request: Request, allowed_roles: set[str]):
    guard = login_required(request)
    if guard:
        return guard
    require_role(request, allowed_roles)
    return None


def current_username(request: Request) -> str:
    return request.session.get("username", "system")


def parse_date(value: str | None):
    if not value:
        return None
    return datetime.strptime(value, "%Y-%m-%d").date()


@app.get("/", response_class=HTMLResponse)
def root(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse("/dashboard", status_code=http_status.HTTP_303_SEE_OTHER)
    return RedirectResponse("/login", status_code=http_status.HTTP_303_SEE_OTHER)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", ctx(request))


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = authenticate_user(db, username.strip(), password)
    if not user:
        return templates.TemplateResponse("login.html", ctx(request, error="Invalid username or password"), status_code=401)
    request.session.clear()
    request.session["user_id"] = user.id
    request.session["username"] = user.username
    request.session["role"] = user.role
    crud.log_action(db, user.username, "login", "user", user.id, "Successful session login")
    return RedirectResponse("/dashboard", status_code=http_status.HTTP_303_SEE_OTHER)


@app.get("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    username = current_username(request)
    request.session.clear()
    crud.log_action(db, username, "logout", "user", details="User logged out")
    return RedirectResponse("/login", status_code=http_status.HTTP_303_SEE_OTHER)


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    guard = login_required(request)
    if guard:
        return guard
    risks = db.query(models.Risk).all()
    controls = db.query(models.Control).all()
    findings = db.query(models.AuditFinding).all()
    severity_counts = {s: len([r for r in risks if r.severity == s]) for s in CRITICALITIES}
    control_counts = {s: len([c for c in controls if c.implementation_status == s]) for s in CONTROL_STATUSES}
    open_risks = [r for r in risks if r.status in {"Open", "In Progress"}]
    implemented = len([c for c in controls if c.implementation_status == "Implemented"])
    closed_findings = len([f for f in findings if f.status == "Closed"])
    stats = {
        "total_assets": db.query(models.Asset).count(),
        "total_risks": len(risks),
        "critical_risks": severity_counts["Critical"],
        "open_risks": len([r for r in risks if r.status == "Open"]),
        "implemented_controls": implemented,
        "open_findings": len([f for f in findings if f.status != "Closed"]),
        "closed_findings": closed_findings,
        "risk_reduction": round((len([r for r in risks if r.status in {"Mitigated", "Accepted"}]) / len(risks) * 100), 1) if risks else 0,
        "control_coverage": round((implemented / len(controls) * 100), 1) if controls else 0,
        "overdue_risks": len([r for r in open_risks if is_overdue(r.target_date)]),
    }
    return templates.TemplateResponse("dashboard.html", ctx(request, stats=stats, severity_counts=severity_counts, control_counts=control_counts, risks=risks[:5], heatmap=build_heatmap(risks)))


@app.get("/assets", response_class=HTMLResponse)
def assets(request: Request, db: Session = Depends(get_db)):
    guard = login_required(request)
    if guard:
        return guard
    return templates.TemplateResponse("assets.html", ctx(request, assets=db.query(models.Asset).order_by(models.Asset.created_at.desc()).all()))


@app.get("/assets/new", response_class=HTMLResponse)
def new_asset(request: Request):
    guard = enforce_roles(request, REGISTRY_EDITORS)
    if guard:
        return guard
    return templates.TemplateResponse("asset_form.html", ctx(request, asset=None, criticalities=CRITICALITIES))


@app.post("/assets/new")
def create_asset(request: Request, name: str = Form(...), asset_type: str = Form(...), owner: str = Form(...), description: str = Form(""), criticality: str = Form(...), location: str = Form(""), db: Session = Depends(get_db)):
    guard = enforce_roles(request, REGISTRY_EDITORS)
    if guard:
        return guard
    asset = crud.create_asset(db, name=name.strip(), asset_type=asset_type.strip(), owner=owner.strip(), description=description.strip(), criticality=criticality if criticality in CRITICALITIES else "Low", location=location.strip())
    crud.log_action(db, current_username(request), "create", "asset", asset.id, asset.name)
    return RedirectResponse("/assets", status_code=http_status.HTTP_303_SEE_OTHER)


@app.get("/assets/{asset_id}/edit", response_class=HTMLResponse)
def edit_asset(request: Request, asset_id: int, db: Session = Depends(get_db)):
    guard = enforce_roles(request, REGISTRY_EDITORS)
    if guard:
        return guard
    return templates.TemplateResponse("asset_form.html", ctx(request, asset=db.get(models.Asset, asset_id), criticalities=CRITICALITIES))


@app.post("/assets/{asset_id}/edit")
def update_asset(request: Request, asset_id: int, name: str = Form(...), asset_type: str = Form(...), owner: str = Form(...), description: str = Form(""), criticality: str = Form(...), location: str = Form(""), db: Session = Depends(get_db)):
    guard = enforce_roles(request, REGISTRY_EDITORS)
    if guard:
        return guard
    asset = db.get(models.Asset, asset_id)
    if asset:
        crud.update_asset(db, asset, name=name.strip(), asset_type=asset_type.strip(), owner=owner.strip(), description=description.strip(), criticality=criticality if criticality in CRITICALITIES else "Low", location=location.strip())
        crud.log_action(db, current_username(request), "update", "asset", asset.id, asset.name)
    return RedirectResponse("/assets", status_code=http_status.HTTP_303_SEE_OTHER)


@app.post("/assets/{asset_id}/delete")
def delete_asset(request: Request, asset_id: int, db: Session = Depends(get_db)):
    guard = enforce_roles(request, ADMIN_ONLY)
    if guard:
        return guard
    asset = db.get(models.Asset, asset_id)
    if asset:
        crud.log_action(db, current_username(request), "delete", "asset", asset.id, asset.name)
        db.delete(asset)
        db.commit()
    return RedirectResponse("/assets", status_code=http_status.HTTP_303_SEE_OTHER)


@app.get("/risks", response_class=HTMLResponse)
def risks(request: Request, db: Session = Depends(get_db)):
    guard = login_required(request)
    if guard:
        return guard
    return templates.TemplateResponse("risks.html", ctx(request, risks=db.query(models.Risk).order_by(models.Risk.created_at.desc()).all(), is_overdue=is_overdue))


@app.get("/risks/new", response_class=HTMLResponse)
def new_risk(request: Request, db: Session = Depends(get_db)):
    guard = enforce_roles(request, REGISTRY_EDITORS)
    if guard:
        return guard
    return templates.TemplateResponse("risk_form.html", ctx(request, risk=None, assets=db.query(models.Asset).all(), statuses=RISK_STATUSES, treatments=TREATMENT_PLANS))


@app.post("/risks/new")
def create_risk(request: Request, title: str = Form(...), asset_id: Optional[int] = Form(None), threat: str = Form(...), vulnerability: str = Form(...), likelihood: int = Form(...), impact: int = Form(...), risk_status: str = Form(..., alias="status"), treatment_plan: str = Form("Mitigate"), risk_owner: str = Form(""), target_date: str = Form(""), recommendation: str = Form(""), db: Session = Depends(get_db)):
    guard = enforce_roles(request, REGISTRY_EDITORS)
    if guard:
        return guard
    risk = crud.create_risk(db, title=title.strip(), asset_id=asset_id or None, threat=threat.strip(), vulnerability=vulnerability.strip(), likelihood=likelihood, impact=impact, status=risk_status if risk_status in RISK_STATUSES else "Open", treatment_plan=treatment_plan if treatment_plan in TREATMENT_PLANS else "Mitigate", risk_owner=risk_owner.strip() or "Security Team", target_date=parse_date(target_date), recommendation=recommendation.strip())
    crud.log_action(db, current_username(request), "create", "risk", risk.id, risk.title)
    return RedirectResponse("/risks", status_code=http_status.HTTP_303_SEE_OTHER)


@app.get("/risks/{risk_id}/edit", response_class=HTMLResponse)
def edit_risk(request: Request, risk_id: int, db: Session = Depends(get_db)):
    guard = enforce_roles(request, REGISTRY_EDITORS)
    if guard:
        return guard
    return templates.TemplateResponse("risk_form.html", ctx(request, risk=db.get(models.Risk, risk_id), assets=db.query(models.Asset).all(), statuses=RISK_STATUSES, treatments=TREATMENT_PLANS))


@app.post("/risks/{risk_id}/edit")
def update_risk(request: Request, risk_id: int, title: str = Form(...), asset_id: Optional[int] = Form(None), threat: str = Form(...), vulnerability: str = Form(...), likelihood: int = Form(...), impact: int = Form(...), risk_status: str = Form(..., alias="status"), treatment_plan: str = Form("Mitigate"), risk_owner: str = Form(""), target_date: str = Form(""), recommendation: str = Form(""), db: Session = Depends(get_db)):
    guard = enforce_roles(request, REGISTRY_EDITORS)
    if guard:
        return guard
    risk = db.get(models.Risk, risk_id)
    if risk:
        crud.update_risk(db, risk, title=title.strip(), asset_id=asset_id or None, threat=threat.strip(), vulnerability=vulnerability.strip(), likelihood=likelihood, impact=impact, status=risk_status if risk_status in RISK_STATUSES else "Open", treatment_plan=treatment_plan if treatment_plan in TREATMENT_PLANS else "Mitigate", risk_owner=risk_owner.strip() or "Security Team", target_date=parse_date(target_date), recommendation=recommendation.strip())
        crud.log_action(db, current_username(request), "update", "risk", risk.id, risk.title)
    return RedirectResponse("/risks", status_code=http_status.HTTP_303_SEE_OTHER)


@app.post("/risks/{risk_id}/delete")
def delete_risk(request: Request, risk_id: int, db: Session = Depends(get_db)):
    guard = enforce_roles(request, ADMIN_ONLY)
    if guard:
        return guard
    risk = db.get(models.Risk, risk_id)
    if risk:
        crud.log_action(db, current_username(request), "delete", "risk", risk.id, risk.title)
        db.delete(risk)
        db.commit()
    return RedirectResponse("/risks", status_code=http_status.HTTP_303_SEE_OTHER)


@app.get("/controls", response_class=HTMLResponse)
def controls(request: Request, db: Session = Depends(get_db)):
    guard = login_required(request)
    if guard:
        return guard
    return templates.TemplateResponse("controls.html", ctx(request, controls=db.query(models.Control).order_by(models.Control.created_at.desc()).all()))


@app.get("/controls/new", response_class=HTMLResponse)
def new_control(request: Request, db: Session = Depends(get_db)):
    guard = enforce_roles(request, REGISTRY_EDITORS)
    if guard:
        return guard
    return templates.TemplateResponse("control_form.html", ctx(request, control=None, risks=db.query(models.Risk).all(), statuses=CONTROL_STATUSES))


@app.post("/controls/new")
def create_control(request: Request, name: str = Form(...), framework_reference: str = Form(""), iso27001_reference: str = Form(""), nist_csf_function: str = Form(""), description: str = Form(""), implementation_status: str = Form(...), owner: str = Form(""), risk_id: Optional[int] = Form(None), evidence_link: str = Form(""), db: Session = Depends(get_db)):
    guard = enforce_roles(request, REGISTRY_EDITORS)
    if guard:
        return guard
    control = crud.create_control(db, name=name.strip(), framework_reference=framework_reference.strip(), iso27001_reference=iso27001_reference.strip(), nist_csf_function=nist_csf_function.strip(), description=description.strip(), implementation_status=implementation_status if implementation_status in CONTROL_STATUSES else "Not Implemented", owner=owner.strip(), risk_id=risk_id or None, evidence_link=evidence_link.strip())
    crud.log_action(db, current_username(request), "create", "control", control.id, control.name)
    return RedirectResponse("/controls", status_code=http_status.HTTP_303_SEE_OTHER)


@app.get("/controls/{control_id}/edit", response_class=HTMLResponse)
def edit_control(request: Request, control_id: int, db: Session = Depends(get_db)):
    guard = enforce_roles(request, REGISTRY_EDITORS)
    if guard:
        return guard
    return templates.TemplateResponse("control_form.html", ctx(request, control=db.get(models.Control, control_id), risks=db.query(models.Risk).all(), statuses=CONTROL_STATUSES))


@app.post("/controls/{control_id}/edit")
def update_control(request: Request, control_id: int, name: str = Form(...), framework_reference: str = Form(""), iso27001_reference: str = Form(""), nist_csf_function: str = Form(""), description: str = Form(""), implementation_status: str = Form(...), owner: str = Form(""), risk_id: Optional[int] = Form(None), evidence_link: str = Form(""), db: Session = Depends(get_db)):
    guard = enforce_roles(request, REGISTRY_EDITORS)
    if guard:
        return guard
    control = db.get(models.Control, control_id)
    if control:
        crud.update_control(db, control, name=name.strip(), framework_reference=framework_reference.strip(), iso27001_reference=iso27001_reference.strip(), nist_csf_function=nist_csf_function.strip(), description=description.strip(), implementation_status=implementation_status if implementation_status in CONTROL_STATUSES else "Not Implemented", owner=owner.strip(), risk_id=risk_id or None, evidence_link=evidence_link.strip())
        crud.log_action(db, current_username(request), "update", "control", control.id, control.name)
    return RedirectResponse("/controls", status_code=http_status.HTTP_303_SEE_OTHER)


@app.post("/controls/{control_id}/delete")
def delete_control(request: Request, control_id: int, db: Session = Depends(get_db)):
    guard = enforce_roles(request, ADMIN_ONLY)
    if guard:
        return guard
    control = db.get(models.Control, control_id)
    if control:
        crud.log_action(db, current_username(request), "delete", "control", control.id, control.name)
        db.delete(control)
        db.commit()
    return RedirectResponse("/controls", status_code=http_status.HTTP_303_SEE_OTHER)


@app.get("/findings", response_class=HTMLResponse)
def findings(request: Request, db: Session = Depends(get_db)):
    guard = login_required(request)
    if guard:
        return guard
    return templates.TemplateResponse("findings.html", ctx(request, findings=db.query(models.AuditFinding).order_by(models.AuditFinding.created_at.desc()).all(), is_overdue=is_overdue))


@app.get("/findings/new", response_class=HTMLResponse)
def new_finding(request: Request, db: Session = Depends(get_db)):
    guard = enforce_roles(request, FINDING_EDITORS)
    if guard:
        return guard
    return templates.TemplateResponse("finding_form.html", ctx(request, finding=None, risks=db.query(models.Risk).all(), ratings=CRITICALITIES, statuses=FINDING_STATUSES))


@app.post("/findings/new")
def create_finding(request: Request, finding_id: str = Form(...), observation: str = Form(...), risk_rating: str = Form(...), recommendation: str = Form(""), owner: str = Form(""), due_date: str = Form(""), risk_id: Optional[int] = Form(None), finding_status: str = Form("Open", alias="status"), db: Session = Depends(get_db)):
    guard = enforce_roles(request, FINDING_EDITORS)
    if guard:
        return guard
    finding = crud.create_finding(db, finding_id=finding_id.strip(), observation=observation.strip(), risk_rating=risk_rating if risk_rating in CRITICALITIES else "Medium", recommendation=recommendation.strip(), owner=owner.strip(), due_date=parse_date(due_date), risk_id=risk_id or None, status=finding_status if finding_status in FINDING_STATUSES else "Open")
    crud.log_action(db, current_username(request), "create", "finding", finding.id, finding.finding_id)
    return RedirectResponse("/findings", status_code=http_status.HTTP_303_SEE_OTHER)


@app.get("/findings/{finding_id}/edit", response_class=HTMLResponse)
def edit_finding(request: Request, finding_id: int, db: Session = Depends(get_db)):
    guard = enforce_roles(request, FINDING_EDITORS)
    if guard:
        return guard
    return templates.TemplateResponse("finding_form.html", ctx(request, finding=db.get(models.AuditFinding, finding_id), risks=db.query(models.Risk).all(), ratings=CRITICALITIES, statuses=FINDING_STATUSES))


@app.post("/findings/{finding_id}/edit")
def update_finding(request: Request, finding_id: int, finding_code: str = Form(..., alias="finding_id"), observation: str = Form(...), risk_rating: str = Form(...), recommendation: str = Form(""), owner: str = Form(""), due_date: str = Form(""), risk_id: Optional[int] = Form(None), finding_status: str = Form("Open", alias="status"), db: Session = Depends(get_db)):
    guard = enforce_roles(request, FINDING_EDITORS)
    if guard:
        return guard
    finding = db.get(models.AuditFinding, finding_id)
    if finding:
        crud.update_finding(db, finding, finding_id=finding_code.strip(), observation=observation.strip(), risk_rating=risk_rating if risk_rating in CRITICALITIES else "Medium", recommendation=recommendation.strip(), owner=owner.strip(), due_date=parse_date(due_date), risk_id=risk_id or None, status=finding_status if finding_status in FINDING_STATUSES else "Open")
        crud.log_action(db, current_username(request), "update", "finding", finding.id, finding.finding_id)
    return RedirectResponse("/findings", status_code=http_status.HTTP_303_SEE_OTHER)


@app.post("/findings/{finding_id}/delete")
def delete_finding(request: Request, finding_id: int, db: Session = Depends(get_db)):
    guard = enforce_roles(request, ADMIN_ONLY)
    if guard:
        return guard
    finding = db.get(models.AuditFinding, finding_id)
    if finding:
        crud.log_action(db, current_username(request), "delete", "finding", finding.id, finding.finding_id)
        db.delete(finding)
        db.commit()
    return RedirectResponse("/findings", status_code=http_status.HTTP_303_SEE_OTHER)


@app.get("/audit-logs", response_class=HTMLResponse)
def audit_logs(request: Request, db: Session = Depends(get_db)):
    guard = enforce_roles(request, AUDIT_LOG_VIEWERS)
    if guard:
        return guard
    logs = db.query(models.AuditLog).order_by(models.AuditLog.created_at.desc()).limit(100).all()
    return templates.TemplateResponse("audit_logs.html", ctx(request, logs=logs))


@app.get("/users", response_class=HTMLResponse)
def users(request: Request, db: Session = Depends(get_db)):
    guard = enforce_roles(request, ADMIN_ONLY)
    if guard:
        return guard
    return templates.TemplateResponse("users.html", ctx(request, users=db.query(models.User).order_by(models.User.role, models.User.username).all(), roles=ROLES))


@app.get("/reports/audit")
def audit_report(request: Request, db: Session = Depends(get_db)):
    guard = enforce_roles(request, REPORT_VIEWERS)
    if guard:
        return guard
    pdf = generate_audit_report(db.query(models.Asset).all(), db.query(models.Risk).all(), db.query(models.Control).all(), db.query(models.AuditFinding).all())
    crud.log_action(db, current_username(request), "generate", "report", details="Generated PDF audit report")
    return StreamingResponse(iter([pdf]), media_type="application/pdf", headers={"Content-Disposition": "attachment; filename=cyberrisk-audit-report.pdf"})


# REST API -----------------------------------------------------------------
@app.post("/api/token")
def api_token(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = authenticate_user(db, username.strip(), password)
    if not user:
        raise HTTPException(status_code=http_status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    return {"access_token": create_access_token(user), "token_type": "bearer", "role": user.role}


@app.get("/api/me")
def api_me(user: models.User = Depends(get_api_user)):
    return {"id": user.id, "username": user.username, "role": user.role}


@app.get("/api/assets")
def api_assets(db: Session = Depends(get_db), user: models.User = Depends(get_api_user)):
    require_api_role(user, READ_ONLY_ROLES)
    return [{"id": a.id, "name": a.name, "asset_type": a.asset_type, "owner": a.owner, "criticality": a.criticality, "location": a.location} for a in db.query(models.Asset).all()]


@app.get("/api/risks")
def api_risks(db: Session = Depends(get_db), user: models.User = Depends(get_api_user)):
    require_api_role(user, READ_ONLY_ROLES)
    return [{"id": r.id, "title": r.title, "asset": r.asset.name if r.asset else None, "likelihood": r.likelihood, "impact": r.impact, "score": r.calculated_risk_score, "severity": r.severity, "status": r.status, "treatment_plan": r.treatment_plan, "risk_owner": r.risk_owner, "target_date": str(r.target_date) if r.target_date else None} for r in db.query(models.Risk).all()]


@app.get("/api/controls")
def api_controls(db: Session = Depends(get_db), user: models.User = Depends(get_api_user)):
    require_api_role(user, READ_ONLY_ROLES)
    return [{"id": c.id, "name": c.name, "iso27001_reference": c.iso27001_reference, "nist_csf_function": c.nist_csf_function, "implementation_status": c.implementation_status, "owner": c.owner, "related_risk": c.risk.title if c.risk else None} for c in db.query(models.Control).all()]
