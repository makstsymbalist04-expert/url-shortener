from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Response
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import current_user, router
from app.config import settings
from app.db import get_db
from app.models import Link, User
from app.schemas import LinkIn, LinkOut

app = FastAPI(
    title="URL Shortener",
    swagger_ui_init_oauth={"clientId": settings.oauth_client_id, "usePkceWithAuthorizationCodeGrant": True},
)
app.include_router(router)
LIMITS = {"user": 3, "premium": 5}


async def own_link(id: int, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    link = await db.scalar(
        select(Link).where(Link.id == id, Link.user_id == user.id, Link.deleted_at.is_(None))
    )
    if link is None:
        raise HTTPException(404, "Link not found")
    return link


@app.post("/links", response_model=LinkOut, status_code=201)
async def create_link(
    data: LinkIn, response: Response, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)
):
    # Serialize creates per owner, preventing duplicate URLs and quota races.
    await db.execute(select(User.id).where(User.id == user.id).with_for_update())
    url = str(data.original_url)
    existing = await db.scalar(
        select(Link).where(Link.user_id == user.id, Link.original_url == url, Link.active())
    )
    if existing:
        response.status_code = 200
        return existing
    count = await db.scalar(
        select(func.count()).select_from(Link).where(Link.user_id == user.id, Link.active())
    )
    if count >= LIMITS[user.role]:
        raise HTTPException(403, "Active link limit reached")
    link = Link(user_id=user.id, original_url=url, expires_at=data.expires_at, max_clicks=data.max_clicks)
    db.add(link)
    await db.flush()
    return link


@app.get("/links", response_model=list[LinkOut])
async def list_links(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    # Include expired/exhausted links so users can inspect their history; omit deleted.
    return (
        await db.scalars(
            select(Link).where(Link.user_id == user.id, Link.deleted_at.is_(None)).order_by(Link.id)
        )
    ).all()


@app.delete("/links/{id}", status_code=204)
async def delete_link(link: Link = Depends(own_link), db: AsyncSession = Depends(get_db)):
    await db.execute(update(Link).where(Link.id == link.id).values(deleted_at=func.clock_timestamp()))
    return Response(status_code=204)


@app.get("/{code}")
async def redirect(code: str, db: AsyncSession = Depends(get_db)):
    try:
        value = UUID(code)
    except ValueError:
        raise HTTPException(404, "Link not found") from None
    # Condition and increment are ONE SQL statement; max_clicks cannot be overshot.
    url = await db.scalar(
        update(Link)
        .where(Link.code == value, Link.active())
        .values(clicks=Link.clicks + 1)
        .returning(Link.original_url)
    )
    if url is None:
        found = await db.scalar(select(Link.id).where(Link.code == value, Link.deleted_at.is_(None)))
        raise HTTPException(
            419 if found is not None else 404,
            "Link expired or exhausted" if found is not None else "Link not found",
        )
    return RedirectResponse(url, status_code=302, headers={"Cache-Control": "no-store"})
