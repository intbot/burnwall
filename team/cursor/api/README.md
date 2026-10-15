# Cursor Usage API

The API behind the **Cursor Usage** extension ([`../extension`](../extension)), part of Burnwall's self-hosted team
tools ([`team/`](../../README.md)). It syncs a Cursor
team's usage from the Cursor Admin API and gives each person their own month: spend against their limit, pace,
most expensive chats, coaching tips, admin notices, model updates and where their money goes by token type.

- **Stack:** Python + FastAPI, SQLite. A background job syncs from the Admin API every 15 minutes.
- **Sign-in:** `AUTH_MODE=dev` (no sign-in, every request is `DEV_USER_EMAIL`, localhost only), `AUTH_MODE=oidc`
  (bearer tokens from any OpenID Connect provider) or `AUTH_MODE=entra` (the same, with Entra's details filled in).
  See [Sign-in](#sign-in).

## Run locally

From this folder (`team/cursor/api`). Windows (PowerShell):

```
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements-dev.txt
copy .env.example .env        # set CURSOR_ADMIN_API_KEY, DEV_USER_EMAIL, ADMIN_EMAILS, ORG_NAME
.venv\Scripts\python -m uvicorn app.main:app --host 127.0.0.1 --port 8787
.venv\Scripts\python -m pytest -q   # tests
```

macOS or Linux:

```
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
cp .env.example .env
.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8787
.venv/bin/python -m pytest -q
```

`run-local.cmd` (Windows) and `run-local.sh` (macOS, Linux) start the same server and log to `data/server.log`;
`HOST` and `PORT` override the address. To keep it running after the terminal closes:
- Windows: a scheduled task, e.g. `schtasks /Create /TN CursorUsageAPI /TR <path>\run-local.cmd /SC ONCE /ST 00:00`,
  then `schtasks /Run /TN CursorUsageAPI`.
- macOS or Linux: `nohup sh run-local.sh &`, or a launchd agent / systemd user service that runs `run-local.sh`.

The first start loads everything from `BACKFILL_START` (a few minutes, because of Admin API rate limits). After that,
each sync re-fetches from the previous day onward, which takes a few seconds. Docs are at http://127.0.0.1:8787/docs.

## Configuration

Read from the environment, and from `.env` in this folder when present. See `.env.example`.

| Variable | Default | Meaning |
|---|---|---|
| `CURSOR_ADMIN_API_KEY` | | Cursor Admin API key with `admin:*` scope. Keep it in a secret store; never commit it |
| `ORG_NAME` | `your organization` | The organization's name as people know it, used in text like "New at ACME: `claude-opus-5-5`" and "from ACME's usage" |
| `DEFAULT_LIMIT_DOLLARS` | `200` | Monthly limit to assume when Cursor reports no per-person limit (Cursor's `effectivePerUserLimitDollars` wins when present) |
| `AUTH_MODE` | `dev` | `dev`, `oidc` or `entra` |
| `DEV_USER_EMAIL` | | Dev mode only: who every request is |
| `ADMIN_EMAILS` | | Comma-separated. Admins can see everyone's usage, post notices and trigger a sync |
| `ALLOWED_EMAIL_DOMAINS` | any | Comma-separated. When set, only these email domains get in (`oidc` and `entra`) |
| `OIDC_ISSUER`, `OIDC_AUDIENCES` | | `oidc` only, both required: the issuer URL and the accepted `aud` values |
| `OIDC_REQUIRED_SCOPE` | none | `oidc` only: a scope the token must carry (`scp` or `scope`) |
| `OIDC_EMAIL_CLAIM` | `email` (Entra: `preferred_username,upn,email`) | Claims to read the email from, first one present wins |
| `OIDC_JWKS_URL`, `OIDC_ALGORITHMS` | from discovery, `RS256,ES256` | Rarely needed overrides |
| `ENTRA_TENANT_ID`, `ENTRA_AUDIENCES`, `ENTRA_REQUIRED_SCOPE` | `access_as_user` scope | `entra` only |
| `DEV_TOOLS` | `false` | Testing aids for admins (the extension's "View as" picker). Leave unset in production |
| `SYNC_ENABLED`, `SYNC_MINUTES` | `true`, `15` | Background sync |
| `BACKFILL_START` | 1st of last month | First day to load into an empty database |
| `DB_PATH` | `data/usage.db` | SQLite file, relative to this folder |
| `BILLING_CYCLE` | `auto` | `auto` follows the team's Cursor billing cycle; `calendar` uses UTC calendar months |
| `COACH_*`, `NEWS_*`, `PACE_*`, … | see `app/rules.py` | Coaching, model-update, pace and alert thresholds, one variable each, e.g. `COACH_LONG_CHAT_PROMPTS=25` |
| `HOST`, `PORT` | `127.0.0.1`, `8787` | Address for `run-local.cmd` / `run-local.sh` |

**Billing periods** follow the team's Cursor cycle: `subscriptionCycleStart` from `/teams/spend`, which the sync
stores. A period is named by the month it starts in, so with a cycle on the 15th, `2026-10` is Oct 15 to Nov 15, and
the extension shows it as "Oct 15 – Nov 14". Until the first sync has seen the cycle, periods are UTC calendar months.
`/health` shows the current period and `period_matches_cursor`.

**Thresholds** live in `app/rules.py`, one field per number, and each field can be set with an environment variable
named after it in upper case. Personal thresholds (shares of a person's spend, prompt counts per person) suit any team
size. The team-wide prompt counts assume a hundred or more active people; a smaller team wants them lower, roughly in
proportion: `COACH_CURRENT_MODEL_MIN_PROMPTS` (a version counts as the one the team has moved to),
`NEWS_NEW_MODEL_MIN_PROMPTS` (a model counts as new to the team) and `NEWS_FREE_MIN_PROMPTS` (a free period).
`PACE_WATCH_SHARE` (0.8) sets both the "watch" status and the extension's alert, which the summary returns as
`alerts.watch_share`.

## Sign-in

`AUTH_MODE=oidc` accepts a JWT from any OpenID Connect provider. The signing keys come from the issuer's discovery
document (`<issuer>/.well-known/openid-configuration`), so the API only needs the issuer and the audience. It checks
the signature, issuer, audience and expiry, an optional scope, `email_verified` when the token has it, and
`ALLOWED_EMAIL_DOMAINS`. The email it reads must match the address Cursor's Admin API reports for the person, or they
see no usage; `OIDC_EMAIL_CLAIM` picks the claim.

`AUTH_MODE=entra` is `oidc` with Entra's details filled in from `ENTRA_TENANT_ID`. It accepts both Entra token
versions (v1 tokens, which Entra issues for an API unless its app registration asks for v2, have a different issuer)
and reads the email from `preferred_username` or `upn`.

| Provider | API settings | Extension settings (`cursorUsage.*`) |
|---|---|---|
| Entra ID | `AUTH_MODE=entra`, `ENTRA_TENANT_ID`, `ENTRA_AUDIENCES=api://<api-app-id>,<api-app-id>` | `entra.tenantId`, `entra.clientId`, `entra.scope` (Microsoft sign-in built into the editor) |
| Okta | `AUTH_MODE=oidc`, `OIDC_ISSUER=https://<org>.okta.com/oauth2/default`, `OIDC_AUDIENCES=api://default` | `oidc.issuer` (same URL), `oidc.clientId` |
| Auth0 | `OIDC_ISSUER=https://<tenant>.auth0.com/` (trailing slash), `OIDC_AUDIENCES=<api identifier>` | `oidc.issuer`, `oidc.clientId`, `oidc.audience=<api identifier>` |
| Keycloak | `OIDC_ISSUER=https://<host>/realms/<realm>`, `OIDC_AUDIENCES=<client or audience mapper value>` | `oidc.issuer`, `oidc.clientId` |
| Google | `OIDC_ISSUER=https://accounts.google.com`, `OIDC_AUDIENCES=<client id>`, `ALLOWED_EMAIL_DOMAINS=<your domain>` | `oidc.issuer`, `oidc.clientId`, `oidc.clientSecret`, `oidc.tokenType=id`, `oidc.scopes=openid email profile` |

For `oidc` sign-in, register a **public** app (no client secret) and turn on the **device authorization grant**
(Okta: "Device Authorization" grant type; Auth0: "Device Code" grant; Keycloak: "OAuth 2.0 Device Authorization
Grant"; Google: a "TVs and Limited Input devices" client, whose secret Google doesn't treat as confidential). Google
access tokens aren't JWTs, so with Google the extension sends the ID token and the API's audience is the client ID;
always set `ALLOWED_EMAIL_DOMAINS` with Google, since any Google account can sign in to such a client.

`/health` reports `auth_mode`; nothing else about sign-in is exposed. The API refuses to start when the chosen mode
is missing its required settings.

## API

| API | Who | Returns |
|---|---|---|
| `GET /health` | anyone | Sync status, Cursor's cycle start and the current period |
| `GET /api/me` | signed in | Email, name, is_admin |
| `GET /api/me/summary?month=YYYY-MM` | signed in | Everything the extension shows for the billing period (`period_start`, `period_end`): spend, limit, pace, projected date to reach the limit, daily spend, spend by model, top chats, top prompt, coaching (`coach`), notices, model updates (`model_updates`), the token-type breakdown (`tokens`), `org_name` and the alert level (`alerts`) |
| `GET /api/admin/users?month=` | admin | Everyone's spend, pace and status |
| `GET /api/admin/users/{email}/summary` | admin | Someone else's summary |
| `POST /api/admin/sync` | admin | Sync now |
| `GET /api/admin/notices` | admin | Every notice, newest first |
| `POST /api/admin/notices` | admin | Post a notice: `{"text": "...", "target": "*"}` or one person's email |
| `DELETE /api/admin/notices/{id}` | admin | Remove a notice |
| `GET /api/dev/users` | admin, `DEV_TOOLS=true` only | Every member with name and month-to-date spend |

Per-person limits come from Cursor's `effectivePerUserLimitDollars`. Usage records appear in the Admin API about
2 minutes after the prompt.

## Coaching

`app/coach.py` works out, from a person's own usage events, up to 3 habits to change (ranked by money at stake, each
with the person's numbers and one action) and up to 2 good habits to keep. Each bad habit has a good counterpart:

| Habit to change | Shown when | Saving estimate | Good counterpart |
|---|---|---|---|
| One long chat | Top chat ≥ $5 and ≥ 15% of the period (or ≥ $25), with ≥ 20 prompts or open ≥ 1 day | Half of what prompts after the 20th cost above the chat's own first-20 average | Short, focused chats (median ≤ 15 prompts) |
| `-fast` models | ≥ 30% of spend | The same tokens priced at the normal version's fitted rates (else 45% of `-fast` spend) | Rarely uses `-fast` |
| Max / xhigh effort | ≥ 30% of spend | Not estimated | Mostly high or medium effort |
| An older version | ≥ $20 this period on a version the team has moved on from, when the newest is ≥ 10% cheaper | The same tokens at the newest version's fitted rates, after any `-fast` saving | On the newest version |
| Huge context | ≥ 30% of spend from prompts re-reading > 5M tokens, and no long-chat tip | Not estimated | |

Numbers in the table are the defaults; each has a `COACH_*` variable.

**Older versions** come from the team's own usage, not a fixed list. Model names are split into a name and a
version (`claude-opus-5-5` and `claude-4.6-opus` are both `claude-opus`), and the newest version with at least 200
team prompts in the last 30 days (`COACH_CURRENT_MODEL_MIN_PROMPTS`, `COACH_CURRENT_MODEL_DAYS`) is the one the team
has moved to. Prices for the comparison come from the fitted
rates, so the percentage in the tip is what the newer version actually costs for the same tokens.

Other "keep doing" checks: Auto use (≥ 10 prompts), cost per prompt at or below the team median, and on pace for the
period. Keep-doing checks need at least 20 prompts in the period (`COACH_HABIT_MIN_PROMPTS`); their own levels are
the `COACH_SHORT_CHAT_*`, `COACH_CURRENT_MODEL_MIN_SHARE` / `_MAX_OLDER`, `COACH_EFFORT_*`, `COACH_NO_FAST_*` and
`COACH_AUTO_MIN_PROMPTS` variables. The total saving stacks the estimates on what each one leaves and never claims more than 60% of spend.

Tip actions use Cursor's own features as documented by Cursor: `/summarize` to compress a long chat, `@` → Chats to
bring an earlier chat into a new one, and the context ring next to the chat input.

## Where the money goes (`tokens`)

Cursor reports each prompt's token counts by type and what it charged, not a price list. `app/rates.py` fits each
model's $/M rate per token type from what the team was charged (non-negative least squares over the last 7, 14 or
30 days, whichever is the most recent window with 100+ charged prompts). The rates include any per-token fee Cursor
adds. `cache_write_models` lists which of the person's models charge for cache writes, from the same fits, so the
extension doesn't name model vendors itself.
`app/tokens.py` splits each charge by those rates, so the cost column adds up to actual spend, and prices `-fast`
prompts at the normal version's rates for the what-if.

## Model updates (`model_updates`)

Worked out from the team's usage in `app/news.py`, since Cursor's API has no model list: a model family new to the
team in the last 45 days (200+ prompts; `NEWS_RECENT_DAYS`, `NEWS_NEW_MODEL_MIN_PROMPTS`) with a price comparison to
the version before it, and free periods that
ended (shown to people who used them free).

## Notes

- Python 3.10 works, but host on 3.12 or later.
- The Admin API key covers the whole Cursor team, so this API is the only thing that holds it. The extension never sees it.
