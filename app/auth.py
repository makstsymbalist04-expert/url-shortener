import base64
import hashlib
import html
import re
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

from argon2 import PasswordHasher, Type
from argon2.exceptions import VerificationError
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import OAuth2AuthorizationCodeBearer
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.concurrency import run_in_threadpool

from app.config import settings
from app.db import get_db
from app.models import AccessToken, AuthorizationCode, User
from app.schemas import Registration, UserOut

router = APIRouter(prefix="/auth", tags=["Authentication"])
passwords = PasswordHasher(type=Type.ID)
dummy_hash = passwords.hash(secrets.token_urlsafe(32))
oauth = OAuth2AuthorizationCodeBearer(authorizationUrl="/auth/authorize", tokenUrl="/auth/token")


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


async def current_user(token: str = Depends(oauth), db: AsyncSession = Depends(get_db)):
    user = await db.scalar(
        select(User)
        .join(AccessToken)
        .where(AccessToken.digest == digest(token), AccessToken.expires_at > func.clock_timestamp())
    )
    if user is None:
        raise HTTPException(401, "Invalid or expired token", headers={"WWW-Authenticate": "Bearer"})
    return user


@router.post("/register", response_model=UserOut, status_code=201)
async def register(data: Registration, db: AsyncSession = Depends(get_db)):
    user = User(username=data.username, password_hash=await run_in_threadpool(passwords.hash, data.password))
    try:
        async with db.begin_nested():
            db.add(user)
            await db.flush()
    except IntegrityError:
        raise HTTPException(409, "Username already exists") from None
    return user


def validate_client(client_id, redirect_uri, response_type, code_challenge, code_challenge_method):
    if client_id != settings.oauth_client_id or redirect_uri != settings.oauth_redirect_uri:
        raise HTTPException(400, "Unregistered client or redirect URI")
    if response_type != "code" or code_challenge_method != "S256":
        raise HTTPException(400, "Authorization code with PKCE S256 required")
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", code_challenge):
        raise HTTPException(400, "Invalid PKCE challenge")


@router.get("/authorize", response_class=HTMLResponse)
async def authorize(
    client_id: str,
    redirect_uri: str,
    response_type: str,
    code_challenge: str,
    code_challenge_method: str,
    state: str,
    scope: str = "",
):
    validate_client(client_id, redirect_uri, response_type, code_challenge, code_challenge_method)
    if scope:
        raise HTTPException(400, "Scopes are not supported")
    csrf = secrets.token_urlsafe(32)
    fields = dict(
        client_id=client_id,
        redirect_uri=redirect_uri,
        response_type=response_type,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        state=state,
        csrf=csrf,
    )
    hidden = "".join(
        f'<input type="hidden" name="{k}" value="{html.escape(v, quote=True)}">' for k, v in fields.items()
    )
    response = HTMLResponse(
        "<!doctype html><html><head><title>Authorize URL Shortener</title></head>"
        "<body><h1>URL Shortener</h1><p>Allow this application to manage your links?</p>"
        f'<form method="post" action="/auth/authorize">{hidden}'
        '<label>Username <input name="username" required autocomplete="username"></label><br>'
        '<label>Password <input name="password" type="password" required '
        'autocomplete="current-password"></label><br><button>Sign in and authorize</button>'
        "</form></body></html>",
        headers={
            "Cache-Control": "no-store",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'none'; form-action 'self'; frame-ancestors 'none'",
        },
    )
    response.set_cookie(
        "oauth_csrf",
        csrf,
        httponly=True,
        samesite="lax",
        secure=settings.secure_cookies,
        max_age=300,
        path="/auth/authorize",
    )
    return response


@router.post("/authorize")
async def login(
    request: Request,
    username: str = Form(),
    password: str = Form(),
    client_id: str = Form(),
    redirect_uri: str = Form(),
    response_type: str = Form(),
    code_challenge: str = Form(),
    code_challenge_method: str = Form(),
    state: str = Form(),
    csrf: str = Form(),
    db: AsyncSession = Depends(get_db),
):
    validate_client(client_id, redirect_uri, response_type, code_challenge, code_challenge_method)
    if not secrets.compare_digest(csrf, request.cookies.get("oauth_csrf", "")):
        raise HTTPException(400, "Invalid CSRF token")
    user = await db.scalar(select(User).where(User.username == username))
    try:
        await run_in_threadpool(passwords.verify, user.password_hash if user else dummy_hash, password)
    except VerificationError:
        raise HTTPException(401, "Invalid credentials") from None
    if user is None:
        raise HTTPException(401, "Invalid credentials")
    code = secrets.token_urlsafe(32)
    db.add(
        AuthorizationCode(
            digest=digest(code),
            user_id=user.id,
            client_id=client_id,
            redirect_uri=redirect_uri,
            challenge=code_challenge,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        )
    )
    await db.flush()
    response = RedirectResponse(redirect_uri + "?" + urlencode({"code": code, "state": state}), 302)
    response.delete_cookie("oauth_csrf", path="/auth/authorize")
    response.headers["Cache-Control"] = "no-store"
    return response


@router.post("/token")
async def token(
    grant_type: str = Form(),
    code: str = Form(),
    client_id: str = Form(),
    redirect_uri: str = Form(),
    code_verifier: str = Form(),
    db: AsyncSession = Depends(get_db),
):
    if grant_type != "authorization_code":
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)
    if not re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", code_verifier):
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "Invalid PKCE verifier"}, status_code=400
        )
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).rstrip(b"=").decode()
    )
    # DELETE RETURNING consumes the code atomically, including concurrent exchanges.
    row = (
        await db.execute(
            delete(AuthorizationCode)
            .where(
                AuthorizationCode.digest == digest(code),
                AuthorizationCode.client_id == client_id,
                AuthorizationCode.redirect_uri == redirect_uri,
                AuthorizationCode.challenge == challenge,
                AuthorizationCode.expires_at > func.clock_timestamp(),
            )
            .returning(AuthorizationCode.user_id)
        )
    ).first()
    if row is None:
        return JSONResponse({"error": "invalid_grant"}, status_code=400)
    value = secrets.token_urlsafe(48)
    db.add(
        AccessToken(
            digest=digest(value),
            user_id=row.user_id,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=settings.access_token_seconds),
        )
    )
    await db.flush()
    return JSONResponse(
        {"access_token": value, "token_type": "bearer", "expires_in": settings.access_token_seconds},
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


@router.get("/me", response_model=UserOut)
async def me(user: User = Depends(current_user)):
    return user
