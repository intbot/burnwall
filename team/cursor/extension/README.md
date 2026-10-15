# Cursor Usage extension

**Cursor Usage**, a Cursor (VS Code) extension that shows each person their own Cursor usage inside the editor:
spend against their limit, pace alerts, coaching tips, notices from their Cursor admin and where their money goes.
It reads everything from the Cursor Usage API (`team/cursor/api` in the Burnwall repo); it never holds the Cursor
Admin API key. It's separate from the Burnwall extension in `editor/vscode`, which reads the local Burnwall CLI.

## Build and install

```
npm install
npm run package                                   # -> dist\cursor-usage-0.1.0.vsix
cursor --install-extension dist\cursor-usage-0.1.0.vsix --force
```

Then run **Developer: Reload Window** in Cursor. The extension ID is `intbot.cursor-usage`. A company that builds
its own copy can change `publisher` in `package.json` before rolling it out (that changes the ID, so people would need
to uninstall the old one).

## What it shows

- **Status bar:** month-to-date spend against the limit and the number of tips, e.g. `$142 / $200 · 2 tips`. Click it
  for the breakdown tab.
- **Sidebar** (gauge icon; Cursor's activity bar is horizontal, so it may sit under the **⌄** overflow arrow, or run
  **Cursor Usage: Open Sidebar**): spend meter and pace, things to change, keep doing, **Show breakdown**, notices
  from your Cursor admin, and model updates.
- **Breakdown tab:** daily spend, spend by model, most expensive chats and prompt, and **Where your money goes** by
  token type with a `-fast` what-if. Tip numbers mark the rows each tip is about.
- **Pace alerts:** a notification when spend or pace crosses a threshold (`cursorUsage.notifications`).

Text that names the organization ("from ACME's usage") comes from the API's `ORG_NAME`.

## Settings

| Setting | Default | Meaning |
|---|---|---|
| `cursorUsage.apiBaseUrl` | `http://127.0.0.1:8787` | Base URL of the Cursor Usage API |
| `cursorUsage.refreshMinutes` | `10` | How often to refresh |
| `cursorUsage.notifications` | `true` | Pace and spend alerts |
| `cursorUsage.auth.provider` | `auto` | `none`, `microsoft` or `oidc`. `auto` picks `microsoft` when the `entra` settings are set, `oidc` when the `oidc` ones are, else `none` |
| `cursorUsage.entra.tenantId`, `.clientId`, `.scope` | empty | Microsoft (Entra) sign-in |
| `cursorUsage.oidc.issuer`, `.clientId` | empty | OIDC sign-in: the issuer URL and a public client with the device authorization grant |
| `cursorUsage.oidc.scopes` | `openid email profile offline_access` | Scopes to ask for (leave out `offline_access` for Google) |
| `cursorUsage.oidc.audience` | empty | Audience to ask for, for providers that need one (Auth0) |
| `cursorUsage.oidc.tokenType` | `access` | `id` to send the ID token, for providers whose access tokens aren't JWTs (Google) |
| `cursorUsage.oidc.clientSecret` | empty | Only for Google's device clients, whose secret isn't confidential |

## Commands

**Show Usage Breakdown**, **Refresh**, **Sign In**, **Sign Out**, **Open Sidebar**, and for admins **Post Notice (admins)** and
**Remove Notice (admins)** (to everyone or one person).

**Dev tools (testing only):** when the API runs with `DEV_TOOLS=true` and the caller is an admin, the breakdown tab
shows a **View as** dropdown. Picking someone switches the status bar, sidebar and tab to their data, and alerts
stay off while viewing someone else. The flag is server-side, so it can't be turned on from the extension.

## Sign-in

The API's `AUTH_MODE` decides what kind of token it accepts; set the extension to match. The API README has a
table of settings per provider.

- **`microsoft`** asks the editor's built-in Microsoft sign-in for an Entra token with
  `vscode.authentication.getSession('microsoft', [VSCODE_CLIENT_ID:…, VSCODE_TENANT:…, <api scope>])`. People sign in
  with the work account the editor already knows. VS Code ships this sign-in as its `microsoft-authentication`
  extension; check it works in your Cursor version before rolling out. If it doesn't, Entra also works with `oidc`.
- **`oidc`** works with any OpenID Connect provider through the device-code flow (RFC 8628). **Sign In** shows a short
  code, copies it, and opens the provider's sign-in page; the person enters the code and signs in there while the
  extension waits. Nothing has to redirect back to the editor, so it also works in SSH and remote windows. The refresh
  token is kept in the editor's secret storage, so people sign in once; **Sign Out** forgets it. Some companies block
  the device-code flow with conditional access, because a code can be phished; companies on Entra should use
  `microsoft`.

## Limits

- There is no API into Cursor's chat or agent, so all guidance comes from usage events after the fact, a few
  minutes behind.
- It's read-only: it never changes limits or models.

## Design

`design/concepts.html` holds the UI concepts. The extension follows Concept D (Ledger + Coach). The folder isn't
packaged into the `.vsix`.
