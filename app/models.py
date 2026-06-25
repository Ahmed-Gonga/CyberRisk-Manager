from datetime import datetime
from sqlalchemy import Column, Date, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship
from .database import Base


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    # RBAC role used by the UI and API authorization examples.
    role = Column(String(40), nullable=False, default="Admin")
    created_at = Column(DateTime, default=datetime.utcnow)


class Asset(Base):
    __tablename__ = "assets"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(120), nullable=False, index=True)
    asset_type = Column(String(80), nullable=False)
    owner = Column(String(120), nullable=False)
    description = Column(Text, default="")
    criticality = Column(String(20), nullable=False)
    location = Column(String(120), default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    risks = relationship("Risk", back_populates="asset", cascade="all, delete")


class Risk(Base):
    __tablename__ = "risks"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(180), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True)
    threat = Column(String(180), nullable=False)
    vulnerability = Column(String(180), nullable=False)
    likelihood = Column(Integer, nullable=False)
    impact = Column(Integer, nullable=False)
    calculated_risk_score = Column(Integer, nullable=False)
    severity = Column(String(20), nullable=False)
    status = Column(String(30), nullable=False, default="Open")
    treatment_plan = Column(String(30), nullable=False, default="Mitigate")
    risk_owner = Column(String(120), default="Security Team")
    target_date = Column(Date, nullable=True)
    recommendation = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    asset = relationship("Asset", back_populates="risks")
    controls = relationship("Control", back_populates="risk", cascade="all, delete")
    findings = relationship("AuditFinding", back_populates="risk", cascade="all, delete")


class Control(Base):
    __tablename__ = "controls"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(160), nullable=False)
    framework_reference = Column(String(120), default="")
    iso27001_reference = Column(String(80), default="")
    nist_csf_function = Column(String(80), default="")
    description = Column(Text, default="")
    implementation_status = Column(String(40), nullable=False)
    owner = Column(String(120), default="")
    risk_id = Column(Integer, ForeignKey("risks.id"), nullable=True)
    evidence_link = Column(String(255), default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    risk = relationship("Risk", back_populates="controls")


class AuditFinding(Base):
    __tablename__ = "audit_findings"
    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(String(40), unique=True, index=True, nullable=False)
    observation = Column(Text, nullable=False)
    risk_rating = Column(String(20), nullable=False)
    recommendation = Column(Text, default="")
    owner = Column(String(120), default="")
    due_date = Column(Date, nullable=True)
    risk_id = Column(Integer, ForeignKey("risks.id"), nullable=True)
    status = Column(String(30), nullable=False, default="Open")
    created_at = Column(DateTime, default=datetime.utcnow)
    risk = relationship("Risk", back_populates="findings")


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(80), default="system")
    action = Column(String(80), nullable=False)
    entity = Column(String(80), nullable=False)
    entity_id = Column(Integer, nullable=True)
    details = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)
