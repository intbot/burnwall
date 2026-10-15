"""Cursor Usage API.

Run locally:  .venv\\Scripts\\python -m uvicorn app.main:app --host 127.0.0.1 --port 8787
"""
import asyncio
import logging
import re
import threading
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request
from pydantic import BaseModel, Field

from . import cycle, db, ingest, usage
from .auth import User, admin_user, current_user
from .config import Settings, load_settings

log = logging.getLogger("cursor_usage")
MONTH_RE = re.compile(r"^\d{4}-(0[1-9]|1[0-2])$")
router = APIRouter()


def get_conn(request: Request):
    conn = db.connect(request.app.state.settings.db_path)
    try:
        yield conn
    finally:
        conn.close()


def _now(request: Request) -> datetime:
    return request.app.state.clock()


def _month(month: str | None, now: datetime, conn, settings: Settings) -> str:
    """The billing period asked for, or the one that contains now."""
    if month is None:
        return cycle.current(now, cycle.anchor(conn, settings.billing_cycle))
    if not MONTH_RE.match(month):
        raise HTTPException(422, "month must look like 2026-10")
    return month


def _summary(conn, email: str, month: str | None, request: Request) -> dict:
    now = _now(request)
    try:
        s = request.app.state.settings
        return usage.summary(conn, email, _month(month, now, conn, s), now, s.default_limit_dollars, s.org_name,
                             s.rules, s.billing_cycle)
    except ValueError as e:
        raise HTTPException(422, str(e)) from e


def run_sync(app: FastAPI) -> dict:
    if not app.state.sync_lock.acquire(blocking=False):
        raise RuntimeError("A sync is already running")
    try:
        result = ingest.sync(app.state.settings)
        app.state.last_sync_error = None
        log.info("sync done: %s", result)
        return result
    except Exception as e:
        app.state.last_sync_error = f"{type(e).__name__}: {e}"
        raise
    finally:
        app.state.sync_lock.release()


async def _sync_loop(app: FastAPI) -> None:
    while True:
        try:
            await asyncio.to_thread(run_sync, app)
        except Exception:
            log.exception("sync failed")
        await asyncio.sleep(app.state.settings.sync_minutes * 60)


@asynccontextmanager
async def lifespan(app: FastAPI):
    s: Settings = app.state.settings
    task = None
    if s.sync_enabled and s.cursor_admin_api_key:
        task = asyncio.create_task(_sync_loop(app))
    elif s.sync_enabled:
        log.warning("CURSOR_ADMIN_API_KEY is not set; background sync is off")
    yield
    if task:
        task.cancel()


# ---- routes ---------------------------------------------------------------

@router.get("/health")
def health(request: Request, conn=Depends(get_conn)):
    s: Settings = request.app.state.settings
    cursor_start = db.get_state(conn, "billing_cycle_start")
    a = cycle.anchor(conn, s.billing_cycle)
    period = cycle.current(_now(request), a)
    start, end = cycle.bounds(period, a)
    return {"status": "ok", "auth_mode": s.auth_mode,
            "last_sync_at": db.get_state(conn, "last_sync_at"),
            "billing_cycle": s.billing_cycle,
            "billing_cycle_start": cursor_start,          # Cursor's current cycle start, from /teams/spend
            "period": period, "period_start": start.isoformat(), "period_end": end.isoformat(),
            # false means the periods shown don't line up with Cursor's cycle (BILLING_CYCLE=calendar on a mid-month cycle)
            "period_matches_cursor": None if cursor_start is None else start == datetime.fromisoformat(cursor_start),
            "last_sync_error": request.app.state.last_sync_error}


@router.get("/api/me")
def me(request: Request, user: User = Depends(current_user), conn=Depends(get_conn)):
    row = conn.execute("SELECT name, limit_dollars FROM members WHERE email = ?", (user.email,)).fetchone()
    return {"email": user.email, "name": row["name"] if row else None, "is_admin": user.is_admin,
            "is_cursor_member": row is not None,
            "dev_tools": user.is_admin and request.app.state.settings.dev_tools}


@router.get("/api/me/summary")
def my_summary(request: Request, month: str | None = Query(None, description="YYYY-MM, default this month"),
               user: User = Depends(current_user), conn=Depends(get_conn)):
    return _summary(conn, user.email, month, request)


@router.get("/api/admin/users")
def admin_users(request: Request, month: str | None = None, _: User = Depends(admin_user), conn=Depends(get_conn)):
    now = _now(request)
    s = request.app.state.settings
    return usage.team_overview(conn, _month(month, now, conn, s), now, s.default_limit_dollars, s.billing_cycle, s.rules)


@router.get("/api/admin/users/{email}/summary")
def admin_user_summary(email: str, request: Request, month: str | None = None,
                       _: User = Depends(admin_user), conn=Depends(get_conn)):
    return _summary(conn, email, month, request)


class NoticeIn(BaseModel):
    text: str = Field(min_length=1, max_length=400)
    target: str = Field("*", description="'*' for everyone, or one person's email")


@router.get("/api/admin/notices")
def list_notices(_: User = Depends(admin_user), conn=Depends(get_conn)):
    return [dict(r) for r in conn.execute("SELECT * FROM notices ORDER BY created_at DESC").fetchall()]


@router.post("/api/admin/notices", status_code=201)
def post_notice(body: NoticeIn, request: Request, user: User = Depends(admin_user), conn=Depends(get_conn)):
    target = body.target.strip().lower() or "*"
    if target != "*" and "@" not in target:
        raise HTTPException(422, "target must be '*' or an email")
    with conn:
        cur = conn.execute("INSERT INTO notices (created_at, created_by, target, text) VALUES (?, ?, ?, ?)",
                           (_now(request).isoformat(), user.email, target, body.text.strip()))
    return dict(conn.execute("SELECT * FROM notices WHERE id = ?", (cur.lastrowid,)).fetchone())


@router.delete("/api/admin/notices/{notice_id}", status_code=204)
def delete_notice(notice_id: int, _: User = Depends(admin_user), conn=Depends(get_conn)):
    with conn:
        if conn.execute("DELETE FROM notices WHERE id = ?", (notice_id,)).rowcount == 0:
            raise HTTPException(404, "No such notice")


@router.get("/api/dev/users")
def dev_users(request: Request, _: User = Depends(admin_user), conn=Depends(get_conn)):
    """User picker for testing. Only exists when DEV_TOOLS=true."""
    if not request.app.state.settings.dev_tools:
        raise HTTPException(404, "Not Found")
    now = _now(request)
    s = request.app.state.settings
    return usage.member_list(conn, _month(None, now, conn, s), s.default_limit_dollars, s.billing_cycle)


@router.post("/api/admin/sync")
async def admin_sync(request: Request, _: User = Depends(admin_user)):
    if not request.app.state.settings.cursor_admin_api_key:
        raise HTTPException(503, "CURSOR_ADMIN_API_KEY is not set")
    try:
        return await asyncio.to_thread(run_sync, request.app)
    except RuntimeError as e:
        raise HTTPException(409 if "already running" in str(e) else 502, str(e)) from e


def _check_auth(s: Settings) -> None:
    """Fail at start-up, not on the first request, when sign-in is half configured."""
    missing = {"oidc": [("OIDC_ISSUER", s.oidc_issuer), ("OIDC_AUDIENCES", s.oidc_audiences)],
               "entra": [("ENTRA_TENANT_ID", s.entra_tenant_id), ("ENTRA_AUDIENCES", s.entra_audiences)]}
    if s.auth_mode not in ("dev", *missing):
        raise RuntimeError(f"AUTH_MODE must be dev, oidc or entra, not {s.auth_mode!r}")
    unset = [name for name, value in missing.get(s.auth_mode, []) if not value]
    if unset:
        raise RuntimeError(f"AUTH_MODE={s.auth_mode} needs {' and '.join(unset)}")


def create_app(settings: Settings | None = None, clock=None) -> FastAPI:
    app = FastAPI(title="Cursor Usage API", version="0.1.0", lifespan=lifespan)
    app.state.settings = settings or load_settings()
    _check_auth(app.state.settings)
    app.state.clock = clock or (lambda: datetime.now(timezone.utc))
    app.state.sync_lock = threading.Lock()
    app.state.last_sync_error = None
    app.include_router(router)
    return app


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
app = create_app()
