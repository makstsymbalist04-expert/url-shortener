from datetime import datetime
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, HttpUrl


class Registration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=3, max_length=100, pattern=r"^[a-zA-Z0-9_.-]+$")
    password: str = Field(min_length=10, max_length=128)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    username: str
    role: str


class LinkIn(BaseModel):
    original_url: HttpUrl
    expires_at: AwareDatetime | None = None
    max_clicks: int | None = Field(default=None, gt=0)


class LinkOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    user_id: int
    original_url: str
    code: UUID
    expires_at: datetime | None
    clicks: int
    max_clicks: int | None
    deleted_at: datetime | None
