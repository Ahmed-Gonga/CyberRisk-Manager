# CyberRisk Manager

![CI](https://github.com/Ahmed-Gonga/CyberRisk-Manager/actions/workflows/ci.yml/badge.svg)

**Author:** Ahmed Wahba

CyberRisk Manager is a professional cyber risk management web application built with FastAPI, SQLAlchemy, SQLite, Bootstrap, Docker, and GitHub Actions.

The project is designed for a cybersecurity portfolio and demonstrates practical workflows used in IT Security, IT Audit, GRC, and Cybersecurity Consulting: asset inventory, risk assessment, control tracking, audit findings, risk treatment, reporting, API access, and audit logging.

---

## Key Capabilities

- Secure local authentication with hashed passwords
- Session-based browser authentication
- JWT authentication for REST API access
- Role-based access control with Admin, Auditor, Risk Manager, and Viewer demo users
- Asset inventory management
- Risk register with likelihood, impact, score, severity, owners, due dates, and treatment plans
- 5x5 risk heatmap
- Security control tracking with ISO 27001 and NIST CSF mappings
- Audit findings module for IT audit-style observations
- Overdue risk and finding indicators
- Executive dashboard metrics
- Dashboard charts for severity and control status
- PDF audit report generation
- Audit logging for user and data actions
- Dockerized deployment
- GitHub Actions CI pipeline
- Pytest test suite

---

## Demo Credentials and RBAC Roles

| Username | Password | Role | Access Summary |
|---|---|---|---|
| admin | admin123 | Admin | Full system access, deletes, reports, audit logs, and user role overview |
| auditor | auditor123 | Auditor | Review registers, manage audit findings, view reports, and inspect audit logs |
| riskmanager | risk123 | Risk Manager | Manage assets, risks, controls, audit findings, and reports |
| viewer | viewer123 | Viewer | Read-only access to dashboard and registers |

The UI hides unauthorized actions, and server-side RBAC returns `403 Forbidden` if a user manually attempts to access a protected route.

---

## Screenshots

### Security Dashboard

![Dashboard](screenshots/dashboard.png)

### Asset Register

![Assets](screenshots/assets.png)

### Risk Register

![Risks](screenshots/risks.png)

### Security Controls

![Controls](screenshots/controls.png)

### Audit Findings

![Audit Findings](screenshots/audit-findings.png)

### Audit Report

![Audit Report](screenshots/audit-report.png)

---

## Risk Methodology

CyberRisk Manager uses a simple 5x5 risk scoring model:

```text
Risk Score = Likelihood × Impact
```

| Score | Severity |
|---|---|
| 1-4 | Low |
| 5-9 | Medium |
| 10-16 | High |
| 17-25 | Critical |

Each risk can also include:

- Risk owner
- Target remediation date
- Treatment plan: Avoid, Mitigate, Transfer, or Accept
- Status: Open, In Progress, Mitigated, or Accepted

---

## GRC and IT Audit Features

### ISO 27001 Mapping

Controls include basic ISO 27001 references such as:

- A.5.17 Authentication Information
- A.5.15 Access Control
- A.8.15 Logging
- A.8.13 Backup
- A.8.28 Secure Coding

### NIST CSF Mapping

Controls also include NIST CSF function/category-style references such as:

- PR.AC — Protect / Access Control
- DE.CM — Detect / Continuous Monitoring
- PR.IP — Protect / Information Protection Processes
- RC.RP — Recover / Recovery Planning

### Audit Findings

The Audit Findings module includes:

- Finding ID
- Observation
- Risk rating
- Recommendation
- Owner
- Due date
- Status
- Related risk

This mirrors common IT audit and cybersecurity consulting deliverables.

---

## REST API

JWT-based API access is available for core resources.

### Get token

```bash
curl -X POST http://127.0.0.1:8000/api/token \
  -F "username=admin" \
  -F "password=admin123"
```

### Example API calls

```bash
curl http://127.0.0.1:8000/api/assets \
  -H "Authorization: Bearer <TOKEN>"

curl http://127.0.0.1:8000/api/risks \
  -H "Authorization: Bearer <TOKEN>"

curl http://127.0.0.1:8000/api/controls \
  -H "Authorization: Bearer <TOKEN>"
```

---

## Technology Stack

| Area | Technology |
|---|---|
| Backend | FastAPI |
| Database | SQLite |
| ORM | SQLAlchemy |
| Frontend | Jinja2, Bootstrap 5, Chart.js |
| Authentication | Sessions, JWT |
| Reports | ReportLab |
| Testing | Pytest |
| Linting | Ruff |
| DevOps | Docker, Docker Compose |
| CI/CD | GitHub Actions |

---

## Local Setup

```bash
git clone https://github.com/Ahmed-Gonga/CyberRisk-Manager.git
cd CyberRisk-Manager
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open:

```text
http://127.0.0.1:8000
```

---

## Docker Setup

```bash
docker compose up --build
```

Open:

```text
http://127.0.0.1:8000
```

---

## Testing and Linting

```bash
python -m pytest
ruff check app tests
```

---

## Project Documentation

Additional documentation is available under:

- `docs/Architecture.md`
- `docs/Risk_Methodology.md`
- `docs/Threat_Model.md`
- `docs/Security_Controls.md`

---

## Why This Project Is Relevant

This project demonstrates hands-on skills in:

- Cybersecurity Consulting
- Governance, Risk and Compliance
- IT Audit
- Security Governance
- Risk Management
- Control Assessment
- Audit Reporting
- Secure Backend Development
- DevSecOps fundamentals

---

## Security Disclaimer

This project is intended for educational, demonstration, and portfolio purposes. It is not production-ready without additional security hardening, secrets management, secure deployment architecture, monitoring, logging controls, access governance, rate limiting, and infrastructure security controls.

---

## Author

Ahmed Wahba

Cybersecurity | IT Audit | GRC | Risk Management

GitHub: https://github.com/Ahmed-Gonga
