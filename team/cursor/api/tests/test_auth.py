"""Sign-in: tokens signed with a local key, so no identity provider is needed."""
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app import auth
from app.config import Settings
from app.main import create_app

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ISSUER = "https://idp.example.com/oauth2/default"
TENANT = "11111111-2222-3333-4444-555555555555"


class FakeKeys:
    def __init__(self, url):
        self.url = url

    def get_signing_key_from_jwt(self, token):
        return type("K", (), {"key": KEY.public_key()})()


@pytest.fixture(autouse=True)
def tmp_db(tmp_path, monkeypatch):
    """Keep every app in these tests on a throwaway database, never data/usage.db."""
    monkeypatch.setattr(Settings, "__init__", _with_db(Settings.__init__, tmp_path / "usage.db"))


def _with_db(init, path):
    def wrapped(self, *args, **kwargs):
        kwargs.setdefault("db_path", path)
        init(self, *args, **kwargs)
    return wrapped


@pytest.fixture(autouse=True)
def fake_idp(monkeypatch):
    seen = []
    monkeypatch.setattr(auth, "_jwk_client", lambda url: seen.append(url) or FakeKeys(url))
    monkeypatch.setattr(auth, "_discovery", lambda issuer: {"issuer": issuer, "jwks_uri": issuer + "/v1/keys"})
    return seen


def token(key=KEY, **claims) -> str:
    base = {"iss": ISSUER, "aud": "api://cursor-usage", "exp": int(time.time()) + 600, "email": "Pat@Example.com"}
    return jwt.encode({**base, **claims}, key, algorithm="RS256")


def client(**overrides) -> TestClient:
    base = dict(auth_mode="oidc", oidc_issuer=ISSUER, oidc_audiences=["api://cursor-usage"], sync_enabled=False,
                admin_emails=["pat@example.com"])
    s = Settings(**{**base, **overrides})
    return TestClient(create_app(s))


def me(c: TestClient, t: str):
    return c.get("/api/me", headers={"Authorization": f"Bearer {t}"})


def test_oidc_access_token(fake_idp):
    c = client()
    r = me(c, token())
    assert r.status_code == 200 and r.json()["email"] == "pat@example.com" and r.json()["is_admin"] is True
    assert fake_idp == [ISSUER + "/v1/keys"]   # keys found through discovery
    assert c.get("/api/me").status_code == 401


@pytest.mark.parametrize("claims, key, code", [
    ({"aud": "api://something-else"}, KEY, 401),
    ({"iss": "https://evil.example.com"}, KEY, 401),
    ({"exp": int(time.time()) - 120}, KEY, 401),
    ({}, OTHER, 401),                                   # signed by someone else
    ({"email_verified": False}, KEY, 401),
    ({"email": None, "sub": "00u123"}, KEY, 401),        # no email claim
])
def test_oidc_rejects(claims, key, code):
    assert me(client(), token(key, **claims)).status_code == code


def test_oidc_scope_and_domains():
    c = client(oidc_required_scope="usage.read", allowed_email_domains=["example.com"])
    assert me(c, token()).status_code == 403
    assert me(c, token(scp=["openid", "usage.read"])).status_code == 200          # Okta: a list
    assert me(c, token(scope="openid usage.read")).status_code == 200            # Auth0, Keycloak: a string
    assert me(c, token(scope="usage.read", email="sam@elsewhere.com")).status_code == 403


def test_oidc_id_token_and_email_claim():
    # an ID token (e.g. Google): the audience is the client ID and there are no scopes
    c = client(oidc_audiences=["client-123.apps.example.com"])
    assert me(c, token(aud="client-123.apps.example.com")).status_code == 200
    c = client(oidc_email_claims=["upn", "email"])
    assert me(c, token(upn="pat.user@example.com")).json()["email"] == "pat.user@example.com"


def test_entra_accepts_both_token_versions(fake_idp):
    s = Settings(auth_mode="entra", entra_tenant_id=TENANT, entra_audiences=["api://cursor-usage"], sync_enabled=False)
    c = TestClient(create_app(s))
    v2 = token(iss=f"https://login.microsoftonline.com/{TENANT}/v2.0", scp="access_as_user", email=None,
               preferred_username="Pat@Example.com")
    v1 = token(iss=f"https://sts.windows.net/{TENANT}/", scp="access_as_user", email=None, upn="pat@example.com")
    assert me(c, v2).json()["email"] == "pat@example.com" and me(c, v1).json()["email"] == "pat@example.com"
    assert me(c, token(iss=f"https://sts.windows.net/{TENANT}/", upn="pat@example.com")).status_code == 403   # no scope
    assert fake_idp[0] == f"https://login.microsoftonline.com/{TENANT}/discovery/v2.0/keys"


def test_half_configured_sign_in_fails_at_start():
    with pytest.raises(RuntimeError, match="OIDC_AUDIENCES"):
        create_app(Settings(auth_mode="oidc", oidc_issuer=ISSUER, sync_enabled=False))
    with pytest.raises(RuntimeError, match="AUTH_MODE must be"):
        create_app(Settings(auth_mode="saml", sync_enabled=False))
