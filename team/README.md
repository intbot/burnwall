# Burnwall team tools

The Burnwall CLI and the `editor/vscode` extension are for one developer on one machine: 100% local, no network calls
beyond the API traffic they proxy. `team/` is a separate, **self-hosted** part for a company's AI-tool admins: it
reads the organization's usage from the vendor's admin API and gives each person their own numbers, pace and coaching
inside their editor. Nothing in here is built into the CLI or the crate, and nothing is sent anywhere but the
company's own server.

| Folder | What it is |
|---|---|
| [`cursor/api`](cursor/api) | Cursor Usage API: Python + FastAPI + SQLite. Syncs a Cursor team's usage from the Cursor Admin API and serves each person's summary, coaching tips, admin notices and model updates. |
| [`cursor/extension`](cursor/extension) | Cursor Usage extension: status bar, sidebar coach and breakdown tab in Cursor, reading the API above. |

## How the pieces fit

```
Cursor Admin API ──(admin key, read-only)──▶ cursor/api ──(each person's own data, signed in)──▶ cursor/extension
                                             SQLite                                              in each person's Cursor
```

- The Admin API key stays on the server. The extension only ever sees the signed-in person's own usage (admins can
  see everyone's).
- Sign-in is OpenID Connect: Entra ID through the editor's built-in Microsoft sign-in, or any OIDC provider (Okta,
  Auth0, Google, Keycloak) with a device code. See `cursor/api/README.md`.
- Everything company-specific is configuration: the organization's name (`ORG_NAME`), default limit, billing cycle,
  and every coaching threshold (`cursor/api/app/rules.py`). No company names or values are in the code.

## Quick start

```
cd team/cursor/api
python -m venv .venv && .venv/bin/python -m pip install -r requirements-dev.txt    # Windows: .venv\Scripts\python
cp .env.example .env            # set CURSOR_ADMIN_API_KEY, DEV_USER_EMAIL, ADMIN_EMAILS, ORG_NAME
.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8787

cd ../extension
npm install && npm run package
cursor --install-extension dist/cursor-usage-0.1.0.vsix --force
```

Each folder's README has the details: configuration, sign-in per provider, the coaching rules and the API.

## Development

- API tests: `cd team/cursor/api && .venv/bin/python -m pytest -q`
- Extension type-check: `cd team/cursor/extension && npx tsc -p . --noEmit`
- CI runs both when anything under `team/` changes (`.github/workflows/team.yml`).
- `data/`, `.env`, `.venv/`, `node_modules/`, `out/` and `dist/` are git-ignored in each folder. The database holds
  people's usage; never commit it.
