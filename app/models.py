import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, String, Text, Uuid, and_, func, or_
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    __table_args__ = (CheckConstraint("role IN ('user', 'premium')"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(100), unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(String(10), default="user", server_default="user")


class Link(Base):
    __tablename__ = "links"
    __table_args__ = (
        CheckConstraint("clicks >= 0"),
        CheckConstraint("max_clicks IS NULL OR max_clicks > 0"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    original_url: Mapped[str] = mapped_column(Text)
    code: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    clicks: Mapped[int] = mapped_column(default=0, server_default="0")
    max_clicks: Mapped[int | None]
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    @classmethod
    def active(cls):
        # clock_timestamp reflects actual time even after waiting for a row lock.
        return and_(
            cls.deleted_at.is_(None),
            or_(cls.expires_at.is_(None), cls.expires_at > func.clock_timestamp()),
            or_(cls.max_clicks.is_(None), cls.clicks < cls.max_clicks),
        )


class AuthorizationCode(Base):
    __tablename__ = "authorization_codes"
    digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    client_id: Mapped[str] = mapped_column(String(100))
    redirect_uri: Mapped[str] = mapped_column(Text)
    challenge: Mapped[str] = mapped_column(String(43))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AccessToken(Base):
    __tablename__ = "access_tokens"
    digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
