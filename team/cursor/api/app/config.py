"""Settings, read from the environment (and backend/.env when present)."""
import os
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

from .rules import Rules, load_rules

BACKEND_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BACKEND_DIR / ".env")


def _list(value: str) -> list[str]:
    return [x.strip().lower() for x in value.split(",") if x.strip()]


def _bool(value: str, default: bool) -> bool:
    return default if not value else value.strip().lower() in ("1", "true", "yes", "on")


def _default_backfill_start() -> date:
    today = datetime.now(timezone.utc).date()
    first = today.replace(day=1)
    return (first.replace(year=first.year - 1, month=12) if first.month == 1
            else first.replace(month=first.month - 1))


@dataclass(frozen=True)
class Settings:
    cursor_admin_api_key: str = ""
    auth_mode: str = "dev"                      # "dev" | "oidc" | "entra" (oidc with Entra's details filled in)
    dev_user_email: str = ""
    admin_emails: list[str] = field(default_factory=list)
    allowed_email_domains: list[str] = field(default_factory=list)   # empty = any domain the provider signs for
    oidc_issuer: str = ""
    oidc_audiences: list[str] = field(default_factory=list)
    oidc_required_scope: str = ""
    oidc_email_claims: list[str] = field(default_factory=list)       # empty = "email" (oidc) or Entra's claims
    oidc_jwks_url: str = ""                                          # empty = from the issuer's discovery document
    oidc_algorithms: list[str] = field(default_factory=lambda: ["RS256", "ES256"])
    entra_tenant_id: str = ""
    entra_audiences: list[str] = field(default_factory=list)
    entra_required_scope: str = "access_as_user"
    dev_tools: bool = False                     # testing aids (user picker); never on in production
    sync_enabled: bool = True
    sync_minutes: int = 15
    backfill_start: date = field(default_factory=_default_backfill_start)
    db_path: Path = BACKEND_DIR / "data" / "usage.db"
    default_limit_dollars: float = 200.0
    org_name: str = "your organization"       # shown in text like "from {org}'s usage"
    billing_cycle: str = "auto"                 # "auto" (Cursor's cycle start) | "calendar" (UTC months)
    rules: Rules = field(default_factory=Rules)  # coaching and model-update thresholds (rules.py)


def load_settings() -> Settings:
    env = os.environ.get
    db_path = Path(env("DB_PATH") or "data/usage.db")
    return Settings(
        cursor_admin_api_key=env("CURSOR_ADMIN_API_KEY", ""),
        auth_mode=(env("AUTH_MODE") or "dev").strip().lower(),
        dev_user_email=(env("DEV_USER_EMAIL") or "").strip().lower(),
        admin_emails=_list(env("ADMIN_EMAILS", "")),
        allowed_email_domains=[d.lstrip("@") for d in _list(env("ALLOWED_EMAIL_DOMAINS", ""))],
        oidc_issuer=env("OIDC_ISSUER", "").strip(),
        oidc_audiences=[a.strip() for a in (env("OIDC_AUDIENCES") or "").split(",") if a.strip()],
        oidc_required_scope=env("OIDC_REQUIRED_SCOPE", "").strip(),
        oidc_email_claims=[c.strip() for c in (env("OIDC_EMAIL_CLAIM") or "").split(",") if c.strip()],
        oidc_jwks_url=env("OIDC_JWKS_URL", "").strip(),
        oidc_algorithms=[a.strip() for a in (env("OIDC_ALGORITHMS") or "RS256,ES256").split(",") if a.strip()],
        entra_tenant_id=env("ENTRA_TENANT_ID", "").strip(),
        entra_audiences=[a.strip() for a in (env("ENTRA_AUDIENCES") or "").split(",") if a.strip()],
        entra_required_scope=env("ENTRA_REQUIRED_SCOPE") or "access_as_user",
        dev_tools=_bool(env("DEV_TOOLS", ""), False),
        sync_enabled=_bool(env("SYNC_ENABLED", ""), True),
        sync_minutes=int(env("SYNC_MINUTES") or 15),
        backfill_start=date.fromisoformat(env("BACKFILL_START")) if env("BACKFILL_START") else _default_backfill_start(),
        db_path=db_path if db_path.is_absolute() else BACKEND_DIR / db_path,
        org_name=(env("ORG_NAME") or "").strip() or "your organization",
        default_limit_dollars=float(env("DEFAULT_LIMIT_DOLLARS") or 200),
        billing_cycle=(env("BILLING_CYCLE") or "auto").strip().lower(),
        rules=load_rules(env),
    )
