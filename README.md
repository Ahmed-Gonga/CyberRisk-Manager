# CyberRisk Manager Enterprise

> **A Production-Style Cyber Risk Management, IT Audit, and Governance, Risk & Compliance (GRC) Platform**

![Python](https://img.shields.io/badge/Python-3.12-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-Enterprise-green)
![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-ORM-red)
![Docker](https://img.shields.io/badge/Docker-Ready-blue)
![License](https://img.shields.io/badge/License-MIT-success)

**Author:** Ahmed Wahba

CyberRisk Manager Enterprise is a production-style cybersecurity governance, enterprise risk management, and IT audit platform developed using FastAPI.

The application demonstrates enterprise-grade implementation of cyber risk management workflows including asset inventory, risk assessment, audit findings management, security controls, executive reporting, REST APIs, JWT authentication, Role-Based Access Control (RBAC), and audit logging.

This project was built as a professional portfolio application targeting Cybersecurity Engineering, Governance, Risk & Compliance (GRC), Information Security, Security Consulting, and IT Audit roles.

---

# Enterprise Features

## Authentication & Security

* JWT Authentication
* Secure Password Hashing
* Session Authentication
* Role-Based Access Control (RBAC)
* Protected Routes
* Audit Logging
* Environment-Based Configuration

Supported Roles

* Admin
* Auditor
* Risk Manager
* Viewer

---

## Executive Dashboard

* Asset Inventory Overview
* Enterprise Risk Overview
* Critical Risk Monitoring
* Open Risk Tracking
* Implemented Controls
* Open Findings
* Closed Findings
* Executive Metrics
* Risk Heatmap
* Risk Severity Distribution
* Control Status Dashboard

---

## Asset Management

Manage organizational assets including

* Create Assets
* Update Assets
* Delete Assets
* Asset Ownership
* Criticality Classification
* Asset Location

Criticality Levels

* Low
* Medium
* High
* Critical

---

## Enterprise Risk Register

Each risk includes

* Related Asset
* Threat
* Vulnerability
* Likelihood
* Impact
* Automated Risk Score
* Severity Classification
* Risk Owner
* Treatment Plan
* Target Remediation Date
* Overdue Detection
* Recommendations

### Risk Score Formula

```
Risk Score = Likelihood × Impact
```

| Score | Severity |
| ----- | -------- |
| 1–4   | Low      |
| 5–9   | Medium   |
| 10–16 | High     |
| 17–25 | Critical |

---

## Security Controls

* ISO 27001 Mapping
* NIST Cybersecurity Framework Mapping
* Framework References
* Control Ownership
* Evidence Tracking
* Implementation Status

Example Controls

* Multi-Factor Authentication
* Role-Based Access Control
* Security Logging & Monitoring
* Secure Coding Review
* Backup & Recovery

---

## Audit Findings

Track audit observations including

* Finding ID
* Observation
* Risk Rating
* Recommendation
* Owner
* Due Date
* Status
* Overdue Detection

---

## Audit Logging

Every security-sensitive action is recorded.

Examples

* User Login
* Asset Created
* Asset Updated
* Asset Deleted
* Risk Created
* Risk Updated
* Control Modified
* Finding Closed

---

## REST API

The application exposes RESTful APIs for

* Authentication
* Assets
* Risks
* Controls
* Audit Findings
* Dashboard

Swagger Documentation

```
/docs
```

---

## PDF Audit Reporting

Generate professional audit reports including

* Executive Summary
* Asset Inventory
* Enterprise Risk Register
* Critical Risks
* Security Controls
* Audit Findings
* Recommendations
* Report Generation Date

---

# Technology Stack

### Backend

* FastAPI
* SQLAlchemy
* Pydantic

### Database

* SQLite

### Frontend

* Jinja2
* Bootstrap 5

### Authentication

* JWT
* Session Authentication
* Password Hashing

### Reporting

* ReportLab

### DevOps

* Docker
* Docker Compose
* GitHub Actions

### Testing

* Pytest

---

# Project Structure

```
CyberRisk-Manager/

├── app/
├── docs/
├── tests/
├── screenshots/
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md
```

---

# Screenshots

## Login

![Login](screenshots/login.png)

---

## Executive Dashboard

![Dashboard](screenshots/dashboard.png)

---

## Asset Management

![Assets](screenshots/assets.png)

---

## Enterprise Risk Register

![Risks](screenshots/risks.png)

---

## Security Controls

![Controls](screenshots/controls.png)

---

## Audit Findings

![Findings](screenshots/findings.png)

---

## Audit Logs

![Audit Logs](screenshots/audit-logs.png)

---

## REST API Documentation

![API](screenshots/api-docs.png)

---

## JWT Authentication

![JWT](screenshots/jwt-token.png)

---

## PDF Audit Report

![Report](screenshots/audit-report.png)

---

# Installation

Clone the repository

```bash
git clone https://github.com/Ahmed-Gonga/CyberRisk-Manager.git
```

Install dependencies

```bash
pip install -r requirements.txt
```

Run the application

```bash
uvicorn app.main:app --reload
```

Open

```
http://127.0.0.1:8000
```

---

# Docker

```bash
docker compose up --build
```

---

# Running Tests

```bash
pytest
```

---

# Default Demo Accounts

| Username    | Password   | Role         |
| ----------- | ---------- | ------------ |
| admin       | admin123   | Admin        |
| auditor     | auditor123 | Auditor      |
| riskmanager | risk123    | Risk Manager |
| viewer      | viewer123  | Viewer       |

---

# Documentation

The repository includes comprehensive documentation covering

* System Architecture
* Risk Assessment Methodology
* Threat Model
* Security Controls
* Deployment Guidance

---

# Security

CyberRisk Manager Enterprise demonstrates implementation of modern security practices including

* Password Hashing
* JWT Authentication
* Role-Based Access Control
* Audit Logging
* Input Validation
* Secure Session Management
* Environment Variable Configuration
* REST API Security

---

# About the Author

## Ahmed Wahba

Cybersecurity Engineer | IT Auditor | Governance, Risk & Compliance (GRC) | Information Security

GitHub

https://github.com/Ahmed-Gonga

---

## Project Purpose

CyberRisk Manager Enterprise serves as a production-style reference implementation demonstrating enterprise cybersecurity governance, cyber risk management, IT audit processes, secure software engineering, and GRC workflows using modern technologies and security best practices.
