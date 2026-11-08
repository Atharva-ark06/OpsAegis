from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field
from app.models.entities import FindingSeverity, FindingStatus
class AssetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    asset_type: str = Field(min_length=1, max_length=80)
    environment: str = Field(default="unknown", max_length=80)
class AssetRead(AssetCreate):
    id: int
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)
class FindingCreate(BaseModel):
    source_engine: str = Field(min_length=1, max_length=40)
    source_native_id: str | None = Field(default=None, max_length=255)
    title: str = Field(min_length=1, max_length=500)
    description: str | None = None
    severity: FindingSeverity = FindingSeverity.unknown
    status: FindingStatus = FindingStatus.new
    asset_id: int | None = None
    evidence_uri: str | None = Field(default=None, max_length=1024)
class FindingRead(FindingCreate):
    id: int
    first_seen_at: datetime
    last_seen_at: datetime
    model_config = ConfigDict(from_attributes=True)
class IncidentCreate(BaseModel):
    title: str = Field(min_length=1, max_length=500)
    severity: FindingSeverity = FindingSeverity.unknown
    status: str = Field(default="open", min_length=1, max_length=40)
    description: str | None = None
class IncidentRead(IncidentCreate):
    id: int
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)
