from pydantic import BaseModel, Field


class AssetInput(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    asset_type: str = Field(min_length=2, max_length=80)
    owner: str = Field(min_length=2, max_length=120)
    description: str = ""
    criticality: str
    location: str = ""


class RiskInput(BaseModel):
    title: str = Field(min_length=3, max_length=180)
    asset_id: int | None = None
    threat: str = Field(min_length=3, max_length=180)
    vulnerability: str = Field(min_length=3, max_length=180)
    likelihood: int = Field(ge=1, le=5)
    impact: int = Field(ge=1, le=5)
    status: str
    recommendation: str = ""


class ControlInput(BaseModel):
    name: str = Field(min_length=3, max_length=160)
    framework_reference: str = ""
    description: str = ""
    implementation_status: str
    owner: str = ""
    risk_id: int | None = None
    evidence_link: str = ""
