import asyncio
import base64
import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import pytest_asyncio
from bs4 import BeautifulSoup
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.auth import digest
from app.config import settings
from app.db import get_db
from app.main import app
from app.models import AccessToken, Base, User


@pytest_asyncio.fixture
async def client():
    # Deliberately require a separate PostgreSQL database, never erase the app DB.
    url = os.environ.get("TEST_DATABASE_URL")
    if not url or url == settings.database_url or not url.rsplit("/", 1)[-1].endswith("_test"):
        pytest.fail("Set TEST_DATABASE_URL to a separate PostgreSQL database ending in _test")
    engine = create_async_engine(url)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    async def override():
        async with factory() as session:
            async with session.begin():
                yield session

    app.dependency_overrides[get_db] = override
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c:
        c.factory = factory
        yield c
    app.dependency_overrides.clear()
    await engine.dispose()


async def account(client, name="alice", role="user"):
    response = await client.post("/auth/register", json={"username": name, "password": "a-good-password"})
    assert response.status_code == 201, response.text
    uid = response.json()["id"]
    value = secrets.token_urlsafe(32)
    async with client.factory.begin() as db:
        user = await db.get(User, uid)
        user.role = role
        db.add(
            AccessToken(
                digest=digest(value), user_id=uid, expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
            )
        )
    return {"Authorization": "Bearer " + value}


async def create(client, headers, **kwargs):
    return await client.post(
        "/links", headers=headers, json={"original_url": "https://example.com/", **kwargs}
    )


async def test_redirect_clicks_duplicate(client):
    h = await account(client)
    first = await create(client, h)
    assert first.status_code == 201
    row = first.json()
    assert row["code"][14] == "4"
    duplicate = await create(client, h)
    assert duplicate.status_code == 200
    assert duplicate.json()["code"] == row["code"]
    r = await client.get("/" + row["code"])
    assert r.status_code == 302 and r.headers["location"] == "https://example.com/"
    assert (await client.get("/links", headers=h)).json()[0]["clicks"] == 1


@pytest.mark.parametrize(("role", "limit"), [("user", 3), ("premium", 5)])
async def test_quota_and_reuse_at_limit(client, role, limit):
    h = await account(client, role=role)
    for i in range(limit):
        assert (await create(client, h, original_url=f"https://example.com/{i}")).status_code == 201
    assert (await create(client, h, original_url="https://example.com/0")).status_code == 200
    assert (await create(client, h, original_url="https://example.com/extra")).status_code == 403


async def test_ownership_and_soft_delete(client):
    a, b = await account(client), await account(client, "bob")
    row = (await create(client, a)).json()
    assert (await client.get("/links", headers=b)).json() == []
    assert (await client.delete(f"/links/{row['id']}", headers=b)).status_code == 404
    assert (await client.delete(f"/links/{row['id']}", headers=a)).status_code == 204
    assert (await client.get("/" + row["code"])).status_code == 404
    assert (await client.get("/links", headers=a)).json() == []
    assert (await create(client, a)).json()["code"] != row["code"]


async def test_expired_and_exhausted_do_not_count(client):
    h = await account(client)
    expired = (
        await create(client, h, expires_at=(datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat())
    ).json()
    assert (await client.get("/" + expired["code"])).status_code == 419
    exhausted = (await create(client, h, max_clicks=1)).json()
    assert exhausted["code"] != expired["code"]
    assert (await client.get("/" + exhausted["code"])).status_code == 302
    assert (await client.get("/" + exhausted["code"])).status_code == 419
    for i in range(3):
        assert (await create(client, h, original_url=f"https://example.com/{i}")).status_code == 201


async def test_parallel_click_limit(client):
    h = await account(client)
    row = (await create(client, h, max_clicks=3)).json()
    results = await asyncio.gather(*(client.get("/" + row["code"]) for _ in range(15)))
    assert [r.status_code for r in results].count(302) == 3
    assert [r.status_code for r in results].count(419) == 12
    assert (await client.get("/links", headers=h)).json()[0]["clicks"] == 3


async def test_parallel_creation(client):
    h = await account(client)
    results = await asyncio.gather(*(create(client, h) for _ in range(8)))
    assert len({r.json()["code"] for r in results}) == 1
    results = await asyncio.gather(
        *(create(client, h, original_url=f"https://example.com/{i}") for i in range(8))
    )
    assert [r.status_code for r in results].count(201) == 2
    assert [r.status_code for r in results].count(403) == 6


async def test_validation_and_auth(client):
    assert (await client.get("/links")).status_code == 401
    assert (await client.get("/links", headers={"Authorization": "Bearer fake"})).status_code == 401
    assert (await client.get("/invalid")).status_code == 404
    assert (await client.get("/00000000-0000-4000-8000-000000000000")).status_code == 404
    h = await account(client)
    for payload in (
        {"original_url": "javascript:alert(1)"},
        {"max_clicks": 0},
        {"expires_at": "2030-01-01T00:00:00"},
    ):
        assert (await create(client, h, **payload)).status_code == 422
    assert (
        await client.post(
            "/auth/register", json={"username": "evil", "password": "a-good-password", "role": "premium"}
        )
    ).status_code == 422
    assert (
        await client.post("/auth/register", json={"username": "alice", "password": "a-good-password"})
    ).status_code == 409


async def test_oauth_code_flow_pkce_and_replay(client):
    await account(client)
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    params = {
        "client_id": settings.oauth_client_id,
        "redirect_uri": settings.oauth_redirect_uri,
        "response_type": "code",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": "random-state",
    }
    page = await client.get("/auth/authorize", params=params)
    assert page.status_code == 200
    csrf = BeautifulSoup(page.text, "html.parser").find("input", {"name": "csrf"})["value"]
    form = {**params, "csrf": csrf, "username": "alice", "password": "wrong-password"}
    assert (await client.post("/auth/authorize", data=form)).status_code == 401
    form["password"] = "a-good-password"
    assert (await client.post("/auth/authorize", data={**form, "csrf": "wrong"})).status_code == 400
    response = await client.post("/auth/authorize", data=form)
    assert response.status_code == 302
    query = parse_qs(urlparse(response.headers["location"]).query)
    assert query["state"] == ["random-state"]
    exchange = {
        "grant_type": "authorization_code",
        "code": query["code"][0],
        "client_id": settings.oauth_client_id,
        "redirect_uri": settings.oauth_redirect_uri,
        "code_verifier": verifier,
    }
    assert (await client.post("/auth/token", data={**exchange, "code_verifier": "x" * 43})).status_code == 400
    token = await client.post("/auth/token", data=exchange)
    assert token.status_code == 200, token.text
    assert (await client.post("/auth/token", data=exchange)).status_code == 400
    auth = {"Authorization": "Bearer " + token.json()["access_token"]}
    assert (await client.get("/auth/me", headers=auth)).json()["username"] == "alice"
    async with client.factory() as db:
        stored = await db.scalar(text("SELECT password_hash FROM users WHERE username='alice'"))
        assert stored.startswith("$argon2id$")
    assert (
        await client.get("/auth/authorize", params={**params, "redirect_uri": "https://evil.com"})
    ).status_code == 400
