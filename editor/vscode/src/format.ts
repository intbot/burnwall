// Pure parsing/formatting for the status bar. No `vscode` import here, so it is
// unit-testable under plain Node (see test/format.test.ts). The extension host
// code lives in extension.ts.

/** The subset of `burnwall status --json` the status bar reads. */
export interface StatusJson {
  total_cost_usd?: number;
  combined_total_usd?: number;
  blocked_requests?: number;
  security_events?: number;
  budget?: { daily_limit_usd?: number; spent_today_usd?: number };
  breakdown?: Array<{
    input_tokens?: number;
    cache_creation_tokens?: number;
    cache_read_tokens?: number;
  }>;
}

export interface StatusSummary {
  costToday: number;
  /** 0..1, or null when no prompt-side tokens were billed today. */
  cacheHitRate: number | null;
  blocked: number;
  securityEvents: number;
  /** Percent of the daily budget spent, or null when no daily limit is set. */
  budgetPercent: number | null;
}

export function summarize(s: StatusJson): StatusSummary {
  const costToday = s.combined_total_usd ?? s.total_cost_usd ?? 0;

  let cacheRead = 0;
  let promptTotal = 0;
  for (const b of s.breakdown ?? []) {
    const input = b.input_tokens ?? 0;
    const creation = b.cache_creation_tokens ?? 0;
    const read = b.cache_read_tokens ?? 0;
    cacheRead += read;
    promptTotal += input + creation + read;
  }
  const cacheHitRate = promptTotal > 0 ? cacheRead / promptTotal : null;

  const limit = s.budget?.daily_limit_usd ?? 0;
  const spent = s.budget?.spent_today_usd ?? costToday;
  const budgetPercent = limit > 0 ? (spent / limit) * 100 : null;

  return {
    costToday,
    cacheHitRate,
    blocked: s.blocked_requests ?? 0,
    securityEvents: s.security_events ?? 0,
    budgetPercent,
  };
}

/** One-line status-bar label (VS Code `$(icon)` codicons allowed). */
export function statusBarText(s: StatusSummary): string {
  const parts = [`$(flame) $${s.costToday.toFixed(2)}`];
  if (s.cacheHitRate !== null) {
    parts.push(`cache ${Math.round(s.cacheHitRate * 100)}%`);
  }
  if (s.blocked > 0) {
    parts.push(`$(shield) ${s.blocked}`);
  }
  return parts.join("  ·  ");
}

export function tooltip(s: StatusSummary): string {
  const budgetLine =
    s.budgetPercent !== null
      ? `Budget: ${s.budgetPercent.toFixed(0)}% of today's limit`
      : `Budget: no daily limit set`;
  const cacheLine =
    s.cacheHitRate !== null
      ? `Cache hit rate: ${Math.round(s.cacheHitRate * 100)}%`
      : `Cache hit rate: n/a`;
  return [
    "Burnwall — today",
    `Cost: $${s.costToday.toFixed(2)}`,
    budgetLine,
    cacheLine,
    `Blocked requests: ${s.blocked}`,
    `Security events: ${s.securityEvents}`,
    "",
    "Click for the full breakdown.",
  ].join("\n");
}
