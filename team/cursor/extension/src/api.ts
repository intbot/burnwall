import * as vscode from 'vscode';
import { forgetToken, getToken, SignInRequired } from './auth';

export interface DailyRow { date: string; dollars: number; prompts: number }
export interface ModelRow { model: string; dollars: number; prompts: number; share: number }
export interface ChatRow {
  conversation_id: string; started: string; last_active: string; open_days: number;
  prompts_this_month: number; prompts_total: number; models: string[]; dollars: number; share: number;
}
export interface TipAction {
  cmd: 'copy' | 'how' | 'see'; label: string; text?: string; primary?: boolean;
  /** 'how': the dialog's title, and an optional button in it that copies copy_text */
  title?: string; copy_label?: string; copy_text?: string;
}
export interface TokenRow { type: 'input' | 'cache_write' | 'cache_read' | 'output'; tokens_m: number; dollars: number; rate_per_m: number | null }
export interface Tokens {
  rows: TokenRow[]; other_dollars: number; total_tokens_m: number; total_dollars: number;
  fast_what_if: {
    from_model: string | null; to_model: string | null; models: string[];
    actual_dollars: number; normal_dollars: number; saving_dollars: number;
    example: { fast_model: string; normal_model: string; fast_cache_read: number | null; normal_cache_read: number | null };
  } | null;
  /** The person's model families that wrote cache, by whether their fitted price charges for it */
  cache_write_models?: { charged: string[]; free: string[] };
}
export interface Tip {
  id: string; severity: 'crit' | 'warn'; title: string; body: string; chat_started?: string;
  at_stake_dollars: number; saving_dollars: number | null;
  pill: { dollars: number; saving: boolean; title: string };
  target: { kind: 'chat' | 'model'; ids: string[] } | null; actions: TipAction[];
}
export interface Coach {
  tips: Tip[]; keep_doing: { id: string; title: string; body: string }[];
  saving_dollars: number; saving_month_dollars: number;
  /** COACH_LONG_CHAT_PROMPTS on the API */
  long_chat_prompts?: number;
}
export interface Notice { id: number; created_at: string; text: string }
/** Worked out from the organization's usage: a new model, or a free period that ended. `{date}` in text is `date`. */
export interface ModelUpdate { date: string; kind: 'new_model' | 'free_ended'; text: string }
export interface AdminNotice extends Notice { created_by: string; target: string }
export interface Summary {
  email: string; name: string | null; month: string; as_of: string; last_sync_at: string | null;
  data_through: string | null; limit_dollars: number; spent_dollars: number; pct_used: number | null;
  reached_limit_on: string | null; is_current_month: boolean; days_in_month: number; days_elapsed: number;
  projected_dollars: number; even_pace_today_dollars: number; projected_reach_limit_date: string | null;
  status: 'ok' | 'watch' | 'over_pace' | 'over_limit'; prompts: number;
  cost_per_prompt_7d: number | null; team_median_cost_per_prompt_7d: number | null;
  daily: DailyRow[]; by_model: ModelRow[]; top_chats: ChatRow[];
  top_prompt: { ts: string; model: string; conversation_id: string | null; dollars: number; cache_read_tokens: number | null } | null;
  coach: Coach; notices: Notice[]; model_updates: ModelUpdate[]; tokens: Tokens;
  /** The billing period: Cursor's cycle, or a UTC calendar month */
  period_start?: string; period_end?: string;
  /** ORG_NAME on the API, e.g. "your organization" */
  org_name?: string;
  /** PACE_WATCH_SHARE on the API: alert when this share of the limit is used */
  alerts?: { watch_share: number };
}
export interface Me { email: string; name: string | null; is_admin: boolean; is_cursor_member: boolean; dev_tools: boolean }
export interface DevUser { email: string; name: string; spent_dollars: number; limit_dollars: number }

export class ApiError extends Error {
  constructor(message: string, readonly status?: number) { super(message); }
}

function baseUrl(): string {
  return (vscode.workspace.getConfiguration('cursorUsage').get<string>('apiBaseUrl') || 'http://127.0.0.1:8787').replace(/\/+$/, '');
}

/** Bearer token from the configured sign-in (auth.ts); undefined when the API runs in dev mode. */
async function token(interactive: boolean): Promise<string | undefined> {
  try {
    return await getToken(interactive);
  } catch (e) {
    if (e instanceof SignInRequired) { throw new ApiError(e.message, 401); }
    throw new ApiError(e instanceof Error ? e.message : String(e));
  }
}

async function request<T>(method: string, path: string, body?: unknown, interactive = false): Promise<T> {
  const base = baseUrl();
  const headers: Record<string, string> = { Accept: 'application/json' };
  const t = await token(interactive);
  if (t) { headers.Authorization = `Bearer ${t}`; }
  if (body !== undefined) { headers['Content-Type'] = 'application/json'; }
  let resp: Response;
  try {
    resp = await fetch(base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body),
                                         signal: AbortSignal.timeout(20_000) });
  } catch (e) {
    throw new ApiError(`Can't reach the Cursor Usage API at ${base}`);
  }
  if (!resp.ok) {
    if (resp.status === 401) { forgetToken(); }   // expired or revoked: refresh on the next call
    let detail = resp.statusText;
    try { detail = (await resp.json() as { detail?: string }).detail ?? detail; } catch { /* not JSON */ }
    throw new ApiError(detail, resp.status);
  }
  return (resp.status === 204 ? undefined : await resp.json()) as T;
}

const get = <T>(path: string, interactive = false) => request<T>('GET', path, undefined, interactive);

/** Dev tools only: whose usage the views show ('' = your own). */
let viewAs = '';

export const api = {
  me: (interactive = false) => get<Me>('/api/me', interactive),
  /** Your own summary, or (dev tools) the person picked in "View as". */
  summary: (month?: string, interactive = false) => {
    const q = month ? `?month=${encodeURIComponent(month)}` : '';
    return viewAs
      ? get<Summary>(`/api/admin/users/${encodeURIComponent(viewAs)}/summary${q}`, interactive)
      : get<Summary>(`/api/me/summary${q}`, interactive);
  },
  /** Only exists when the API runs with DEV_TOOLS=true. */
  devUsers: () => get<DevUser[]>('/api/dev/users'),
  notices: () => get<AdminNotice[]>('/api/admin/notices'),
  postNotice: (text: string, target: string) => request<AdminNotice>('POST', '/api/admin/notices', { text, target }),
  deleteNotice: (id: number) => request<void>('DELETE', `/api/admin/notices/${id}`),
  viewingAs: () => viewAs,
  setViewAs: (email: string) => { viewAs = email.trim().toLowerCase(); },
};
