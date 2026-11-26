"""FastAPI application for the Cisco security advisory dashboard."""

from __future__ import annotations

import hashlib
import logging
import os
import re
import secrets
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock
from typing import Any, Literal
from uuid import uuid4

import jwt
import httpx
from dotenv import load_dotenv
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from jwt import InvalidTokenError
from pydantic import BaseModel, Field, field_validator
from pwdlib import PasswordHash
from postgrest.exceptions import APIError
from supabase import Client, SupabaseException

from supabase_client import create_resilient_client

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

ROOT = Path(__file__).resolve().parent
PUBLIC = ROOT / "public"
TOKEN_ISSUER = "cisco-advisory-dashboard"
TOKEN_AUDIENCE = "cisco-advisory-api"
TOKEN_TTL_SECONDS = 15 * 60
COOKIE_NAME = "cisco_dashboard_session"
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
password_hasher = PasswordHash.recommended()
_dummy_hash = password_hasher.hash(secrets.token_urlsafe(24))
_supabase: Client | None = None
_supabase_lock = Lock()

app = FastAPI(
    title="Cisco Security Intelligence API",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


class LoginBody(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    token_mode: Literal["cookie", "bearer"] = "cookie"

    @field_validator("username")
    @classmethod
    def normalize_username(cls, value: str) -> str:
        value = value.strip().casefold()
        if not USERNAME_RE.fullmatch(value):
            raise ValueError("Use 3–64 letters, numbers, dots, underscores, or hyphens")
        return value


class ProductCreate(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    notes: str = Field(default="", max_length=500)

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        value = " ".join(value.split())
        if len(value) < 2:
            raise ValueError("Product name must contain at least two characters")
        return value


class ProductState(BaseModel):
    is_active: bool


class ScraperSettingsUpdate(BaseModel):
    enabled: bool
    interval_minutes: int

    @field_validator("interval_minutes")
    @classmethod
    def allowed_interval(cls, value: int) -> int:
        if value not in {60, 360, 1440}:
            raise ValueError("Choose hourly, every six hours, or daily")
        return value


def database() -> Client:
    """Return the server-only Supabase client or report missing configuration."""
    global _supabase
    with _supabase_lock:
        if _supabase is None:
            url = os.getenv("SUPABASE_URL")
            key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
            if not url or not key:
                raise HTTPException(
                    status_code=503,
                    detail="Server database configuration is incomplete.",
                )
            try:
                _supabase = create_resilient_client(url, key)
            except (SupabaseException, httpx.InvalidURL) as error:
                raise HTTPException(
                    status_code=503,
                    detail="Server database configuration is invalid.",
                ) from error
        return _supabase


def github_scraper_config() -> tuple[str, str, str, str] | None:
    """Return GitHub Actions dispatch settings when they are fully configured."""
    token = os.getenv("SCRAPER_GITHUB_TOKEN")
    repository = os.getenv("SCRAPER_GITHUB_REPOSITORY", "")
    branch = os.getenv("SCRAPER_GITHUB_BRANCH", "main")
    workflow = os.getenv("SCRAPER_GITHUB_WORKFLOW", "cisco-scraper.yml")
    if (
        not token
        or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)
        or not re.fullmatch(r"[A-Za-z0-9_.-]+\.ya?ml", workflow)
        or not re.fullmatch(r"[A-Za-z0-9._/-]+", branch)
    ):
        return None
    return token, repository, branch, workflow


def local_scraper_allowed() -> bool:
    """Allow in-process local scrapes outside hosted serverless runtimes."""
    if os.getenv("VERCEL"):
        return False
    forced = os.getenv("SCRAPER_ALLOW_LOCAL", "true").casefold()
    return forced not in {"0", "false", "no", "off"}


def scraper_runner() -> Literal["github", "local", "unconfigured"]:
    if github_scraper_config() is not None:
        return "github"
    if local_scraper_allowed():
        return "local"
    return "unconfigured"


def mark_scraper_run_failed(run_id: int, message: str, *, queued_only: bool = False) -> None:
    statuses = ["queued"] if queued_only else ["queued", "running"]
    try:
        database().table("scraper_runs").update(
            {
                "status": "failed",
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "message": message,
            }
        ).eq("id", run_id).in_("status", statuses).execute()
    except (APIError, httpx.HTTPError):
        logging.exception("Could not mark scraper run %s as failed", run_id)


def run_local_scraper(run_id: int) -> None:
    """Execute main.py for a queued dashboard run outside the request worker."""
    env = os.environ.copy()
    # Prefer the user's normal Playwright cache when a sandbox path is injected.
    sandbox_path = env.get("PLAYWRIGHT_BROWSERS_PATH", "")
    if "cursor-sandbox-cache" in sandbox_path:
        env.pop("PLAYWRIGHT_BROWSERS_PATH", None)
    try:
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "main.py"),
                "--once",
                "--run-id",
                str(run_id),
            ],
            cwd=str(ROOT),
            env=env,
            capture_output=True,
            text=True,
            timeout=14 * 60,
            check=False,
        )
    except subprocess.TimeoutExpired:
        mark_scraper_run_failed(run_id, "The local scraper timed out.")
        logging.error("Local scraper timed out for run %s", run_id)
        return
    except OSError as error:
        mark_scraper_run_failed(run_id, "The local scraper could not be started.")
        logging.error("Local scraper failed to start for run %s (%s)", run_id, error)
        return

    if completed.returncode != 0:
        mark_scraper_run_failed(run_id, "The local scraper exited with an error.")
        detail = (completed.stderr or completed.stdout or "").strip()
        logging.error(
            "Local scraper failed for run %s (exit %s)%s",
            run_id,
            completed.returncode,
            f": {detail[-1500:]}" if detail else "",
        )
    else:
        logging.info("Local scraper finished for run %s", run_id)


def jwt_secret() -> str:
    secret = os.getenv("JWT_SECRET", "")
    if len(secret.encode("utf-8")) < 32:
        raise HTTPException(
            status_code=503,
            detail="Server authentication configuration is incomplete.",
        )
    return secret


def client_address(request: Request) -> str:
    """Use the ASGI server's client address and its trusted proxy configuration."""
    return request.client.host if request.client else "unknown"


def rate_key(username: str, address: str) -> str:
    return hashlib.sha256(f"{username}\0{address}".encode()).hexdigest()


def consume_login_attempt(client: Client, username: str, address: str) -> bool:
    allowed = True
    for key in {rate_key(username, address), rate_key(username, "account")}:
        result = client.rpc(
            "consume_login_attempt",
            {"p_key_hash": key, "p_window_seconds": 900, "p_max_attempts": 8},
        ).execute()
        allowed = bool(result.data) and allowed
    return allowed


def token_from_request(request: Request) -> str | None:
    authorization = request.headers.get("authorization", "")
    if authorization:
        scheme, _, value = authorization.partition(" ")
        if scheme.casefold() != "bearer" or not value:
            raise HTTPException(status_code=401, detail="Invalid authorization header")
        return value
    return request.cookies.get(COOKIE_NAME)


def current_user(request: Request) -> dict[str, str]:
    token = token_from_request(request)
    if not token:
        raise HTTPException(status_code=401, detail="Authentication required")
    try:
        claims = jwt.decode(
            token,
            jwt_secret(),
            algorithms=["HS256"],
            issuer=TOKEN_ISSUER,
            audience=TOKEN_AUDIENCE,
            options={"require": ["exp", "iat", "nbf", "sub", "jti", "iss", "aud"]},
        )
    except InvalidTokenError as error:
        raise HTTPException(status_code=401, detail="Session expired or invalid") from error

    try:
        result = (
            database()
            .table("app_sessions")
            .select("session_id,username,revoked_at")
            .eq("session_id", claims["jti"])
            .eq("username", claims["sub"])
            .is_("revoked_at", "null")
            .limit(1)
            .execute()
        )
    except APIError as error:
        logging.error("Session lookup failed (Supabase code %s)", error.code)
        raise HTTPException(status_code=503, detail="Authentication service unavailable") from error
    sessions = getattr(result, "data", None) or []
    if not sessions:
        raise HTTPException(status_code=401, detail="Session expired or revoked")
    try:
        account = (
            database()
            .table("app_users")
            .select("username,role,is_active")
            .eq("username", claims["sub"])
            .limit(1)
            .execute()
        )
    except APIError as error:
        logging.error("Account status lookup failed (Supabase code %s)", error.code)
        raise HTTPException(status_code=503, detail="Authentication service unavailable") from error
    accounts = getattr(account, "data", None) or []
    if not accounts or not accounts[0].get("is_active"):
        raise HTTPException(status_code=401, detail="Account is inactive")
    return {
        "username": accounts[0]["username"],
        "role": accounts[0]["role"],
        "jti": claims["jti"],
    }


def set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        COOKIE_NAME,
        token,
        max_age=TOKEN_TTL_SECONDS,
        httponly=True,
        secure=bool(os.getenv("VERCEL")) or os.getenv("COOKIE_SECURE", "").casefold() == "true",
        samesite="strict",
        path="/",
    )


def add_security_headers(response: Response) -> Response:
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; "
        "frame-ancestors 'none'; form-action 'self'"
    )
    if os.getenv("VERCEL_ENV") == "production":
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    return response


@app.middleware("http")
async def security_middleware(request: Request, call_next: Any) -> Response:
    response = await call_next(request)
    add_security_headers(response)
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


# Vercel serves public/ separately, so the function may ship without these files.
if (PUBLIC / "index.html").is_file():
    @app.get("/", include_in_schema=False)
    async def home() -> FileResponse:
        return FileResponse(PUBLIC / "index.html", media_type="text/html")

if (PUBLIC / "assets").is_dir():
    app.mount("/assets", StaticFiles(directory=PUBLIC / "assets"), name="assets")


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


def read_advisory_feed(limit: int) -> dict[str, Any]:
    feed = database().rpc(
        "read_advisory_feed", {"p_limit": min(max(limit, 1), 500)}
    ).execute().data
    if not isinstance(feed, dict):
        raise HTTPException(status_code=503, detail="Advisory feed configuration is incomplete.")
    return feed


@app.get("/api/ready")
def readiness() -> JSONResponse:
    try:
        jwt_secret()
        read_advisory_feed(1)
    except (HTTPException, APIError, httpx.HTTPError):
        return JSONResponse({"status": "unavailable"}, status_code=503)
    return JSONResponse({"status": "ready"})


@app.post("/api/auth/login")
def login(body: LoginBody, request: Request, response: Response) -> dict[str, Any]:
    secret = jwt_secret()
    client = database()
    try:
        if not consume_login_attempt(client, body.username, client_address(request)):
            raise HTTPException(
                status_code=429,
                detail="Too many sign-in attempts. Try again in 15 minutes.",
                headers={"Retry-After": "900"},
            )
        user_result = (
            client.table("app_users")
            .select("username,password_hash,role,is_active")
            .eq("username", body.username)
            .limit(1)
            .execute()
        )
    except HTTPException:
        raise
    except APIError as error:
        logging.error("Login lookup failed (Supabase code %s)", error.code)
        raise HTTPException(status_code=503, detail="Authentication service unavailable") from error

    users = getattr(user_result, "data", None) or []
    user = users[0] if users else None
    encoded_hash = user["password_hash"] if user else _dummy_hash
    try:
        password_ok = password_hasher.verify(body.password, encoded_hash)
    except Exception:
        password_ok = False
    if not user or not user.get("is_active") or not password_ok:
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    now = datetime.now(timezone.utc)
    expires = now + timedelta(seconds=TOKEN_TTL_SECONDS)
    session_id = str(uuid4())
    claims = {
        "sub": user["username"],
        "role": user["role"],
        "jti": session_id,
        "iat": now,
        "nbf": now,
        "exp": expires,
        "iss": TOKEN_ISSUER,
        "aud": TOKEN_AUDIENCE,
    }
    token = jwt.encode(claims, secret, algorithm="HS256")
    try:
        client.table("app_sessions").insert(
            {
                "session_id": session_id,
                "username": user["username"],
                "expires_at": expires.isoformat(),
            }
        ).execute()
    except APIError as error:
        logging.error("Session creation failed (Supabase code %s)", error.code)
        raise HTTPException(status_code=503, detail="Could not create a secure session") from error

    user_info = {"username": user["username"], "role": user["role"]}
    if body.token_mode == "bearer":
        return {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": TOKEN_TTL_SECONDS,
            "user": user_info,
        }
    set_session_cookie(response, token)
    return {"user": user_info}


@app.post("/api/auth/logout")
def logout(
    request: Request,
    response: Response,
    user: dict[str, str] = Depends(current_user),
) -> dict[str, str]:
    try:
        database().table("app_sessions").update(
            {"revoked_at": datetime.now(timezone.utc).isoformat()}
        ).eq("session_id", user["jti"]).execute()
    except APIError as error:
        logging.error("Session revoke failed (Supabase code %s)", error.code)
        raise HTTPException(status_code=503, detail="Could not end the session") from error
    response.delete_cookie(COOKIE_NAME, path="/", httponly=True, secure=bool(os.getenv("VERCEL")) or os.getenv("COOKIE_SECURE", "").casefold() == "true", samesite="strict")
    return {"status": "signed_out"}


@app.get("/api/auth/session")
async def session(user: dict[str, str] = Depends(current_user)) -> dict[str, Any]:
    return {"user": {"username": user["username"], "role": user["role"]}}


@app.get("/api/advisories")
def advisories(
    limit: int = 100,
    user: dict[str, str] = Depends(current_user),
) -> dict[str, Any]:
    del user
    try:
        feed = read_advisory_feed(limit)
    except APIError as error:
        if error.code in {"PGRST202", "PGRST205"}:
            raise HTTPException(
                status_code=503,
                detail="The advisory schema is missing or outdated. Apply supabase_schema.sql.",
            ) from error
        logging.error("Advisory query failed (Supabase code %s)", error.code)
        raise HTTPException(status_code=503, detail="Advisory data is temporarily unavailable") from error

    data = feed["items"]
    products = {
        product
        for advisory in data
        for product in (advisory.get("affected_products") or [])
    }
    releases = {
        release
        for advisory in data
        for release in (advisory.get("fixed_releases") or [])
    }
    return {
        **feed,
        "products": len(products),
        "fixed_releases": len(releases),
    }


@app.get("/api/admin/overview")
async def admin_overview(user: dict[str, str] = Depends(current_user)) -> dict[str, str]:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Administrator access required")
    return {"status": "ready"}


def require_admin(user: dict[str, str]) -> None:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Administrator access required")


@app.get("/api/admin/products")
def list_tracked_products(
    user: dict[str, str] = Depends(current_user),
) -> dict[str, Any]:
    require_admin(user)
    try:
        result = (
            database()
            .table("tracked_products")
            .select("id,name,notes,is_active,created_by,created_at,updated_at")
            .order("id", desc=True)
            .limit(500)
            .execute()
        )
    except APIError as error:
        logging.error("Tracked product query failed (Supabase code %s)", error.code)
        raise HTTPException(status_code=503, detail="Product list is unavailable") from error
    return {"items": getattr(result, "data", None) or []}


@app.post("/api/admin/products", status_code=201)
def add_tracked_product(
    body: ProductCreate,
    user: dict[str, str] = Depends(current_user),
) -> dict[str, Any]:
    require_admin(user)
    try:
        result = (
            database()
            .table("tracked_products")
            .insert(
                {
                    "name": body.name,
                    "notes": body.notes.strip(),
                    "created_by": user["username"],
                }
            )
            .select("id,name,notes,is_active,created_by,created_at,updated_at")
            .execute()
        )
    except APIError as error:
        if error.code == "23505":
            raise HTTPException(status_code=409, detail="That product is already on the list") from error
        logging.error("Tracked product insert failed (Supabase code %s)", error.code)
        raise HTTPException(status_code=503, detail="Could not add that product") from error
    rows = getattr(result, "data", None) or []
    if not rows:
        raise HTTPException(status_code=503, detail="Could not confirm the saved product")
    return {"item": rows[0]}


@app.patch("/api/admin/products/{product_id}")
def set_tracked_product_state(
    product_id: int,
    body: ProductState,
    user: dict[str, str] = Depends(current_user),
) -> dict[str, str]:
    require_admin(user)
    try:
        result = (
            database()
            .table("tracked_products")
            .update({"is_active": body.is_active, "updated_at": datetime.now(timezone.utc).isoformat()})
            .eq("id", product_id)
            .select("id")
            .execute()
        )
    except APIError as error:
        logging.error("Tracked product update failed (Supabase code %s)", error.code)
        raise HTTPException(status_code=503, detail="Could not update that product") from error
    if not getattr(result, "data", None):
        raise HTTPException(status_code=404, detail="Product was not found")
    return {"status": "updated"}


@app.delete("/api/admin/products/{product_id}", status_code=204)
def delete_tracked_product(
    product_id: int,
    user: dict[str, str] = Depends(current_user),
) -> Response:
    require_admin(user)
    try:
        result = database().table("tracked_products").delete().eq("id", product_id).select("id").execute()
    except APIError as error:
        logging.error("Tracked product delete failed (Supabase code %s)", error.code)
        raise HTTPException(status_code=503, detail="Could not delete that product") from error
    if not getattr(result, "data", None):
        raise HTTPException(status_code=404, detail="Product was not found")
    return Response(status_code=204)


@app.get("/api/admin/scraper/settings")
def get_scraper_settings(
    user: dict[str, str] = Depends(current_user),
) -> dict[str, Any]:
    require_admin(user)
    try:
        result = (
            database()
            .table("scraper_settings")
            .select("enabled,interval_minutes,last_run_at,updated_at")
            .eq("id", 1)
            .limit(1)
            .execute()
        )
        recent_runs = (
            database()
            .table("scraper_runs")
            .select("id,run_source,status,started_at,finished_at,advisory_count,message,created_at")
            .order("id", desc=True)
            .limit(10)
            .execute()
        )
    except APIError as error:
        logging.error("Scraper settings query failed (Supabase code %s)", error.code)
        raise HTTPException(status_code=503, detail="Scraper settings are unavailable") from error
    settings = (getattr(result, "data", None) or [None])[0]
    runs = getattr(recent_runs, "data", None) or []
    runner = scraper_runner()
    return {
        "settings": settings,
        "latest_run": runs[0] if runs else None,
        "runs": runs,
        "runner": runner,
        "manual_runs_available": runner != "unconfigured",
    }


@app.put("/api/admin/scraper/settings")
def update_scraper_settings(
    body: ScraperSettingsUpdate,
    user: dict[str, str] = Depends(current_user),
) -> dict[str, str]:
    require_admin(user)
    try:
        database().table("scraper_settings").update(
            {
                "enabled": body.enabled,
                "interval_minutes": body.interval_minutes,
                "updated_by": user["username"],
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
        ).eq("id", 1).execute()
    except APIError as error:
        logging.error("Scraper settings update failed (Supabase code %s)", error.code)
        raise HTTPException(status_code=503, detail="Could not save scraper settings") from error
    return {"status": "saved"}


@app.post("/api/admin/scraper/run", status_code=202)
def trigger_scraper(
    background_tasks: BackgroundTasks,
    user: dict[str, str] = Depends(current_user),
) -> dict[str, Any]:
    require_admin(user)
    github = github_scraper_config()
    runner = scraper_runner()
    if runner == "unconfigured":
        raise HTTPException(
            status_code=503,
            detail=(
                "Manual scraping is not configured. For local runs, start the app "
                "outside Vercel. For hosted deployments, set SCRAPER_GITHUB_REPOSITORY "
                "and SCRAPER_GITHUB_TOKEN, then restart the app. See README.md."
            ),
        )

    try:
        run_id = database().rpc(
            "claim_scraper_run",
            {"p_source": "manual", "p_requested_by": user["username"]},
        ).execute().data
    except (APIError, httpx.HTTPError) as error:
        logging.error("Scraper queue request failed (%s)", type(error).__name__)
        raise HTTPException(status_code=503, detail="Could not confirm the scraper queue request") from error
    if run_id is None:
        raise HTTPException(status_code=409, detail="A scraper run is already queued or running")

    if runner == "local":
        background_tasks.add_task(run_local_scraper, run_id)
        return {"status": "queued", "run_id": run_id, "runner": "local"}

    assert github is not None
    token, repository, branch, workflow = github
    url = f"https://api.github.com/repos/{repository}/actions/workflows/{workflow}/dispatches"
    try:
        with httpx.Client(timeout=8) as client:
            response = client.post(
                url,
                headers={
                    "Accept": "application/vnd.github+json",
                    "Authorization": f"Bearer {token}",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                json={"ref": branch, "inputs": {"run_source": "manual", "run_id": str(run_id)}},
            )
    except httpx.HTTPError as error:
        logging.warning("GitHub dispatch could not be confirmed for run %s (%s)", run_id, type(error).__name__)
        raise HTTPException(
            status_code=502,
            detail=f"GitHub did not confirm run #{run_id}. Check Operations for its status.",
        ) from error
    if response.status_code != 204:
        if 400 <= response.status_code < 500:
            mark_scraper_run_failed(run_id, "GitHub rejected the run request.", queued_only=True)
            detail = "GitHub rejected the scraper request. Check the repository, branch, workflow, and token permissions."
        else:
            detail = f"GitHub did not confirm run #{run_id}. Check Operations for its status."
        raise HTTPException(status_code=502, detail=detail)

    return {"status": "queued", "run_id": run_id, "runner": "github"}


@app.exception_handler(httpx.TransportError)
async def upstream_unavailable(request: Request, error: httpx.TransportError) -> JSONResponse:
    logging.warning("Upstream service unavailable for %s (%s)", request.url.path, type(error).__name__)
    response = JSONResponse({"detail": "The data service is temporarily unavailable."}, status_code=503)
    response.headers["Cache-Control"] = "no-store"
    return response


@app.exception_handler(Exception)
async def unexpected_error_handler(request: Request, error: Exception) -> JSONResponse:
    logging.exception("Unhandled application error on %s", request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": "An unexpected server error occurred."},
        headers={"Cache-Control": "no-store"},
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host=os.getenv("HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "8000")),
    )
