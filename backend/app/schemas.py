from datetime import datetime
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field
from app.models.entities import FindingSeverity, FindingStatus

class AssetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    asset_type: str = Field(min_length=1, max_length=80)
    environment: str = Field(default="unknown", max_length=80)
class AssetRead(AssetCreate):
    id: int
    source_engine: str | None = None
    external_id: str | None = None
    ip_address: str | None = None
    os_name: str | None = None
    agent_status: str | None = None
    last_seen_at: datetime | None = None
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
class FindingStatusUpdate(BaseModel):
    status: FindingStatus
class IncidentCreate(BaseModel):
    title: str = Field(min_length=1, max_length=500)
    severity: FindingSeverity = FindingSeverity.unknown
    description: str | None = None
class IncidentUpdate(BaseModel):
    status: Literal["open", "investigating", "contained", "resolved", "closed"] | None = None
    assigned_to_user_id: int | None = None
    resolution: str | None = Field(default=None, max_length=10000)
class IncidentRead(BaseModel):
    id: int
    title: str
    severity: FindingSeverity
    status: Literal["open", "investigating", "contained", "resolved", "closed"]
    description: str | None
    assigned_to_user_id: int | None
    resolution: str | None
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None
    model_config = ConfigDict(from_attributes=True)
