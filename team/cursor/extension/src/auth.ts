import * as vscode from 'vscode';

/**
 * Sign-in for the Cursor Usage API.
 *
 *   none       the API runs in dev mode
 *   microsoft  the Microsoft sign-in built into Cursor/VS Code (Entra ID)
 *   oidc       any OpenID Connect provider, with the device-code flow (RFC 8628): the person gets a short code,
 *              signs in in the browser, and the extension keeps a refresh token in the editor's secret storage.
 *              Works over SSH and remote windows because nothing has to redirect back to the editor.
 */
export type Provider = 'none' | 'microsoft' | 'oidc';

export class SignInRequired extends Error {}

interface Oidc { issuer: string; clientId: string; clientSecret: string; scopes: string; audience: string; tokenType: 'access' | 'id' }

function settings() {
  const c = vscode.workspace.getConfiguration('cursorUsage');
  const entra = { tenantId: c.get<string>('entra.tenantId') || '', clientId: c.get<string>('entra.clientId') || '',
                  scope: c.get<string>('entra.scope') || '' };
  const oidc: Oidc = {
    issuer: (c.get<string>('oidc.issuer') || '').trim().replace(/\/+$/, ''),
    clientId: (c.get<string>('oidc.clientId') || '').trim(),
    clientSecret: c.get<string>('oidc.clientSecret') || '',
    scopes: c.get<string>('oidc.scopes') || 'openid email profile offline_access',
    audience: (c.get<string>('oidc.audience') || '').trim(),
    tokenType: c.get<string>('oidc.tokenType') === 'id' ? 'id' : 'access',
  };
  let provider = c.get<string>('auth.provider') || 'auto';
  if (provider === 'auto') {
    provider = entra.tenantId && entra.clientId && entra.scope ? 'microsoft' : oidc.issuer && oidc.clientId ? 'oidc' : 'none';
  }
  return { provider: provider as Provider, entra, oidc };
}

export function provider(): Provider { return settings().provider; }

/** The line under "Sign in" in the sidebar. */
export function signInHint(): string {
  return provider() === 'microsoft' ? 'Use your work Microsoft account.'
    : 'Use your work account. You get a short code to enter on a sign-in page in your browser.';
}

let ctx: vscode.ExtensionContext | undefined;
let cached: { key: string; token: string; exp: number } | undefined;
const pending: { silent?: Promise<string | undefined>; interactive?: Promise<string | undefined> } = {};

export function initAuth(context: vscode.ExtensionContext): void { ctx = context; }

/** A bearer token for the API, or undefined in dev mode. Throws SignInRequired when a silent attempt can't get one. */
export async function getToken(interactive: boolean): Promise<string | undefined> {
  const s = settings();
  if (s.provider === 'none') { return undefined; }
  if (s.provider === 'microsoft') { return microsoftToken(s.entra, interactive); }
  // one refresh and one sign-in at a time (the views all ask at once), and a click never waits on a silent attempt
  const mode = interactive ? 'interactive' : 'silent';
  pending[mode] ??= oidcToken(s.oidc, interactive).finally(() => { pending[mode] = undefined; });
  return pending[mode];
}

/** The API turned the token down: drop it so the next call refreshes. */
export function forgetToken(): void { cached = undefined; }

export async function signOut(): Promise<void> {
  const s = settings();
  cached = undefined;
  if (s.provider === 'oidc') { await ctx?.secrets.delete(secretKey(s.oidc)); }
}

/* ---------------- microsoft ---------------- */

async function microsoftToken(e: { tenantId: string; clientId: string; scope: string }, interactive: boolean): Promise<string> {
  if (!e.tenantId || !e.clientId || !e.scope) {
    throw new Error('Set cursorUsage.entra.tenantId, .clientId and .scope to sign in with Microsoft.');
  }
  const scopes = [`VSCODE_CLIENT_ID:${e.clientId}`, `VSCODE_TENANT:${e.tenantId}`, e.scope];
  const session = await vscode.authentication.getSession('microsoft', scopes, interactive ? { createIfNone: true } : { silent: true });
  if (!session) { throw new SignInRequired('Sign in to see your Cursor usage'); }
  return session.accessToken;
}

/* ---------------- oidc, device code ---------------- */

interface Discovery { issuer: string; token_endpoint: string; device_authorization_endpoint?: string }
interface TokenResponse { access_token?: string; id_token?: string; refresh_token?: string; expires_in?: number }

const secretKey = (o: Oidc) => `cursorUsage.oidc.refresh:${o.issuer}|${o.clientId}`;
const discoveries = new Map<string, Discovery>();

async function discover(o: Oidc): Promise<Discovery> {
  const hit = discoveries.get(o.issuer);
  if (hit) { return hit; }
  const resp = await fetch(`${o.issuer}/.well-known/openid-configuration`, { signal: AbortSignal.timeout(15_000) });
  if (!resp.ok) { throw new Error(`Can't read the sign-in settings from ${o.issuer} (${resp.status})`); }
  const d = await resp.json() as Discovery;
  discoveries.set(o.issuer, d);
  return d;
}

async function post(url: string, params: Record<string, string>): Promise<{ ok: boolean; body: Record<string, unknown> }> {
  const resp = await fetch(url, {
    method: 'POST', body: new URLSearchParams(params), signal: AbortSignal.timeout(20_000),
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
  });
  let body: Record<string, unknown> = {};
  try { body = await resp.json() as Record<string, unknown>; } catch { /* not JSON */ }
  return { ok: resp.ok, body };
}

function client(o: Oidc): Record<string, string> {
  // a client secret only for providers that issue a non-confidential one for device clients (Google)
  return o.clientSecret ? { client_id: o.clientId, client_secret: o.clientSecret } : { client_id: o.clientId };
}

/** Seconds since the epoch when a JWT expires, if it is one. */
function jwtExp(token: string): number | undefined {
  try { return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString()).exp; } catch { return undefined; }
}

async function keep(o: Oidc, t: TokenResponse): Promise<string> {
  const token = o.tokenType === 'id' ? t.id_token : t.access_token;
  if (!token) { throw new Error(`The sign-in didn't return ${o.tokenType === 'id' ? 'an ID token' : 'an access token'}.`); }
  const exp = jwtExp(token) ?? Math.floor(Date.now() / 1000) + (t.expires_in ?? 300);
  cached = { key: secretKey(o), token, exp };
  if (t.refresh_token) { await ctx?.secrets.store(secretKey(o), t.refresh_token); }
  return token;
}

async function oidcToken(o: Oidc, interactive: boolean): Promise<string | undefined> {
  if (!o.issuer || !o.clientId) { throw new Error('Set cursorUsage.oidc.issuer and cursorUsage.oidc.clientId to sign in.'); }
  if (cached && cached.key === secretKey(o) && cached.exp - 60 > Date.now() / 1000) { return cached.token; }
  const d = await discover(o);
  const refresh = await ctx?.secrets.get(secretKey(o));
  if (refresh) {
    const r = await post(d.token_endpoint, { grant_type: 'refresh_token', refresh_token: refresh, ...client(o) });
    if (r.ok) { return keep(o, r.body as TokenResponse); }
    await ctx?.secrets.delete(secretKey(o));   // expired or revoked
  }
  if (!interactive) { throw new SignInRequired('Sign in to see your Cursor usage'); }
  return keep(o, await deviceFlow(o, d));
}

async function deviceFlow(o: Oidc, d: Discovery): Promise<TokenResponse> {
  if (!d.device_authorization_endpoint) {
    throw new Error(`${o.issuer} doesn't offer device sign-in. Turn on the device authorization grant for this app.`);
  }
  const start = await post(d.device_authorization_endpoint,
    { scope: o.scopes, ...(o.audience ? { audience: o.audience } : {}), ...client(o) });
  const b = start.body as { device_code?: string; user_code?: string; verification_uri?: string; verification_url?: string;
                            verification_uri_complete?: string; expires_in?: number; interval?: number; error_description?: string; error?: string };
  if (!start.ok || !b.device_code || !b.user_code) {
    throw new Error(`Sign-in couldn't start: ${b.error_description || b.error || 'no device code returned'}`);
  }
  const page = b.verification_uri_complete || b.verification_uri || b.verification_url;   // Google says verification_url
  if (!page) { throw new Error('Sign-in couldn’t start: no sign-in page returned'); }

  const go = await vscode.window.showInformationMessage(`Sign in to Cursor Usage with the code ${b.user_code}`,
    { modal: true, detail: `Copy the code, then enter it on the page that opens:\n${page}` }, 'Copy code and open');
  if (!go) { throw new SignInRequired('Sign-in cancelled'); }
  await vscode.env.clipboard.writeText(b.user_code);
  await vscode.env.openExternal(vscode.Uri.parse(page));

  return vscode.window.withProgress({
    location: vscode.ProgressLocation.Notification, cancellable: true,
    title: `Waiting for you to sign in (code ${b.user_code}, copied)`,
  }, async (_p, cancel) => {
    let wait = (b.interval ?? 5) * 1000;
    const deadline = Date.now() + (b.expires_in ?? 900) * 1000;
    while (Date.now() < deadline) {
      await new Promise(r => setTimeout(r, wait));
      if (cancel.isCancellationRequested) { throw new SignInRequired('Sign-in cancelled'); }
      const r = await post(d.token_endpoint,
        { grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: b.device_code!, ...client(o) });
      if (r.ok) { return r.body as TokenResponse; }
      const err = String(r.body.error ?? '');
      if (err === 'authorization_pending') { continue; }
      if (err === 'slow_down') { wait += 5000; continue; }
      throw new Error(err === 'access_denied' ? 'Sign-in was declined.' : err === 'expired_token' ? 'The sign-in code expired. Try again.'
        : `Sign-in failed: ${String(r.body.error_description || err || 'unknown error')}`);
    }
    throw new Error('The sign-in code expired. Try again.');
  });
}
