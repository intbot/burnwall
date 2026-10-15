"""Who is calling. Dev mode (local only), or bearer tokens from an OpenID Connect provider.

AUTH_MODE=oidc accepts JWTs from any OIDC provider (Okta, Auth0, Google, Keycloak, Entra, ...): the signing keys come
from the issuer's discovery document, and the token must be for one of OIDC_AUDIENCES. AUTH_MODE=entra is the same
check with Entra's details filled in from ENTRA_TENANT_ID: both of Entra's token versions (v1 tokens have a different
issuer, and are what Entra issues for an API unless its app registration asks for v2) and its user-name claims.
"""
from dataclasses import dataclass
from functools import lru_cache

import jwt
import requests
import truststore
from fastapi import Depends, HTTPException, Request, status

from .config import Settings

truststore.inject_into_ssl()  # trust the OS cert store (corporate TLS inspection) for discovery and keys

LOOPBACK = {"127.0.0.1", "::1", "localhost", "testclient"}
ENTRA_EMAIL_CLAIMS = ["preferred_username", "upn", "email"]


@dataclass(frozen=True)
class User:
    email: str
    is_admin: bool


@dataclass(frozen=True)
class Profile:
    """How to check a token: accepted issuers, where the signing keys are, the scope and the email claim."""
    issuers: list[str]
    audiences: list[str]
    jwks_url: str
    required_scope: str
    email_claims: list[str]
    algorithms: list[str]


@lru_cache(maxsize=4)
def _jwk_client(url: str) -> jwt.PyJWKClient:
    return jwt.PyJWKClient(url, cache_keys=True, lifespan=3600)


@lru_cache(maxsize=4)
def _discovery(issuer: str) -> dict:
    """The issuer's OpenID configuration. The issuer in it must match, as the OIDC spec requires."""
    resp = requests.get(issuer.rstrip("/") + "/.well-known/openid-configuration", timeout=10)
    resp.raise_for_status()
    doc = resp.json()
    if doc.get("issuer", "").rstrip("/") != issuer.rstrip("/"):
        raise RuntimeError(f"OIDC discovery for {issuer} names a different issuer: {doc.get('issuer')}")
    return doc


def profile(settings: Settings) -> Profile:
    if settings.auth_mode == "entra":
        t = settings.entra_tenant_id
        return Profile(
            # v2 tokens use the first issuer, v1 tokens the second
            issuers=[f"https://login.microsoftonline.com/{t}/v2.0", f"https://sts.windows.net/{t}/"],
            audiences=settings.entra_audiences,
            jwks_url=f"https://login.microsoftonline.com/{t}/discovery/v2.0/keys",
            required_scope=settings.entra_required_scope,
            email_claims=settings.oidc_email_claims or ENTRA_EMAIL_CLAIMS,
            algorithms=["RS256"],
        )
    issuer = settings.oidc_issuer
    return Profile(
        issuers=[issuer, issuer.rstrip("/")] if issuer.endswith("/") else [issuer, issuer + "/"],
        audiences=settings.oidc_audiences,
        jwks_url=settings.oidc_jwks_url or _discovery(issuer)["jwks_uri"],
        required_scope=settings.oidc_required_scope,
        email_claims=settings.oidc_email_claims or ["email"],
        algorithms=settings.oidc_algorithms,
    )


def _scopes(claims: dict) -> set[str]:
    """Entra and Okta put scopes in scp (Okta as a list), Auth0 and Keycloak in scope."""
    raw = claims.get("scp") or claims.get("scope") or ""
    return set(raw.split() if isinstance(raw, str) else raw)


def verify_token(token: str, settings: Settings) -> str:
    """Validate a bearer token for this API and return the caller's email (lower-case)."""
    try:
        p = profile(settings)
    except (requests.RequestException, RuntimeError, KeyError, ValueError) as e:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, f"Can't load the identity provider's settings: {e}") from e
    if not p.audiences:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "No accepted audiences are configured")
    try:
        key = _jwk_client(p.jwks_url).get_signing_key_from_jwt(token).key
        claims = jwt.decode(token, key, algorithms=p.algorithms, audience=p.audiences, issuer=p.issuers,
                            options={"require": ["exp", "aud", "iss"]}, leeway=30)
    except jwt.PyJWKClientConnectionError as e:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, f"Can't load the identity provider's keys: {e}") from e
    except jwt.PyJWTError as e:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, f"Invalid token: {e}") from e
    if p.required_scope and p.required_scope not in _scopes(claims):
        raise HTTPException(status.HTTP_403_FORBIDDEN, f"Token is missing the {p.required_scope} scope")
    if claims.get("email_verified") is False:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "The token's email address isn't verified")
    email = next((claims[c] for c in p.email_claims if isinstance(claims.get(c), str) and "@" in claims[c]), None)
    if not email:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, f"Token has no email in {', '.join(p.email_claims)}")
    email = email.strip().lower()
    if settings.allowed_email_domains and email.rsplit("@", 1)[1] not in settings.allowed_email_domains:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "This account's email domain isn't allowed")
    return email


def current_user(request: Request) -> User:
    settings: Settings = request.app.state.settings
    if settings.auth_mode == "dev":
        if request.client is None or request.client.host not in LOOPBACK:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Dev mode only accepts requests from this machine")
        if not settings.dev_user_email:
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "DEV_USER_EMAIL is not set")
        email = settings.dev_user_email
    elif settings.auth_mode in ("entra", "oidc"):
        header = request.headers.get("Authorization", "")
        if not header.lower().startswith("bearer "):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sign in required", {"WWW-Authenticate": "Bearer"})
        email = verify_token(header[7:].strip(), settings)
    else:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, f"Unknown AUTH_MODE {settings.auth_mode!r}")
    return User(email=email, is_admin=email in settings.admin_emails)


def admin_user(user: User = Depends(current_user)) -> User:
    if not user.is_admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admins only")
    return user
