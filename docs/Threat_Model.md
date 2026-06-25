# Threat Model

## Assets

- Customer Database
- Internal Web Application
- Employee Laptop Fleet
- VPN Gateway
- Cloud Storage Bucket

## Threat Actors

- External attackers
- Malicious insiders
- Phishing operators
- Cloud misconfiguration attackers
- Application attackers

## Attack Surfaces

- Login page
- Web forms
- REST API endpoints
- Database layer
- PDF reporting route
- Session and token handling

## Main Threats

- Unauthorized access
- Credential theft
- Missing MFA
- SQL injection
- Public cloud storage exposure
- Excessive privileges
- Weak monitoring

## Security Assumptions

- The application is a local portfolio MVP.
- SQLite is used for development only.
- Demo credentials are not intended for production use.
- SECRET_KEY should be changed through environment variables.

## Mitigations Implemented

- Password hashing
- Protected routes
- JWT API authentication
- Form validation
- ORM-based database access
- Audit logging
- Role field for RBAC design
- Risk and control tracking
