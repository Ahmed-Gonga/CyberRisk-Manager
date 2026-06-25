import os
os.environ["DATABASE_URL"] = "sqlite:///./test_cyberrisk.db"
os.environ["SECRET_KEY"] = "test-secret"

from fastapi.testclient import TestClient  # noqa: E402
from app.main import app, init_db  # noqa: E402

client = TestClient(app)


def login():
    return client.post("/login", data={"username": "admin", "password": "admin123"}, follow_redirects=False)


def setup_module(module):
    try:
        os.remove("test_cyberrisk.db")
    except FileNotFoundError:
        pass
    init_db()


def test_login_route():
    response = login()
    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"


def test_asset_creation():
    login()
    response = client.post("/assets/new", data={
        "name": "Test Firewall",
        "asset_type": "Network Device",
        "owner": "Security Team",
        "description": "Perimeter firewall",
        "criticality": "High",
        "location": "HQ",
    }, follow_redirects=False)
    assert response.status_code == 303
    listing = client.get("/assets")
    assert "Test Firewall" in listing.text


def test_audit_finding_route():
    login()
    response = client.post("/findings/new", data={
        "finding_id": "FIND-TST",
        "observation": "Test finding observation",
        "risk_rating": "High",
        "recommendation": "Remediate test issue",
        "owner": "Audit Team",
        "due_date": "2030-01-01",
        "risk_id": "",
        "status": "Open",
    }, follow_redirects=False)
    assert response.status_code == 303
    listing = client.get("/findings")
    assert "FIND-TST" in listing.text


def test_api_jwt_and_risk_endpoint():
    token_response = client.post("/api/token", data={"username": "admin", "password": "admin123"})
    assert token_response.status_code == 200
    token = token_response.json()["access_token"]
    risks = client.get("/api/risks", headers={"Authorization": f"Bearer {token}"})
    assert risks.status_code == 200
    assert isinstance(risks.json(), list)


def login_as(username: str, password: str):
    return client.post("/login", data={"username": username, "password": password}, follow_redirects=False)


def test_seeded_rbac_users_can_login():
    for username, password, role in [
        ("admin", "admin123", "Admin"),
        ("auditor", "auditor123", "Auditor"),
        ("riskmanager", "risk123", "Risk Manager"),
        ("viewer", "viewer123", "Viewer"),
    ]:
        response = login_as(username, password)
        assert response.status_code == 303
        dashboard = client.get("/dashboard")
        assert role in dashboard.text
        client.get("/logout")


def test_viewer_is_read_only():
    login_as("viewer", "viewer123")
    assert client.get("/assets/new").status_code == 403
    assert client.get("/risks/new").status_code == 403
    assert client.get("/controls/new").status_code == 403
    assert client.get("/findings/new").status_code == 403
    assert client.get("/assets").status_code == 200


def test_auditor_can_manage_findings_but_not_risk_registers():
    login_as("auditor", "auditor123")
    assert client.get("/findings/new").status_code == 200
    assert client.get("/risks/new").status_code == 403
    assert client.get("/audit-logs").status_code == 200


def test_risk_manager_can_manage_registers_but_not_admin_users():
    login_as("riskmanager", "risk123")
    assert client.get("/risks/new").status_code == 200
    assert client.get("/controls/new").status_code == 200
    assert client.get("/users").status_code == 403
