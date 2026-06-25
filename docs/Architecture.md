# Architecture

CyberRisk Manager is a FastAPI web application designed for local development, portfolio demonstration, and cybersecurity consulting workflows.

## Backend

The backend uses FastAPI for routing, request handling, form processing, session authentication, and REST API endpoints.

## Database

SQLite is used for local development. SQLAlchemy provides ORM models for:

- Users
- Assets
- Risks
- Security Controls
- Audit Findings
- Audit Logs

## Frontend

The frontend uses Jinja2 templates and Bootstrap 5. Chart.js is used for dashboard charts.

## Authentication

The project includes two authentication models:

- Browser session authentication for the web UI
- JWT bearer tokens for REST API access

Passwords are hashed using PBKDF2-HMAC-SHA256 with per-password salts.

## RBAC

The User model includes a role field. The demo user is an Admin. The design supports roles such as Admin, Auditor, Risk Manager, and Viewer.

## PDF Reporting

ReportLab generates PDF audit reports containing executive summary, asset overview, risk register, critical risks, controls, audit findings, and recommendations.

## Audit Logging

Security-relevant actions such as login, logout, create, update, delete, and report generation are logged in the AuditLog table.

## Docker Deployment

The project includes a Dockerfile and docker-compose.yml for containerized local deployment.
