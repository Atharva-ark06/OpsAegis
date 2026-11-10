from datetime import datetime
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from app.models.entities import UserRole

class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int

class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    role: UserRole = UserRole.viewer

class UserRead(BaseModel):
    id: int
    email: EmailStr
    role: UserRole
    is_active: bool
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class AuditRead(BaseModel):
    id: int
    actor_user_id: int | None
    action: str
    target: str
    detail: str | None
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class BootstrapRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)


class UserUpdate(BaseModel):
    role: UserRole | None = None
    is_active: bool | None = None
    model_config = ConfigDict(extra='forbid')
