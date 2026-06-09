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
  plan?: {
    providers?: Array<{
      provider: string;
      status: string;
      windows: Array<{ label: string; utilization: number; reset_in_secs: number }>;
    }>;
  } | null;
  coverage?: Array<{
    tool: string;
    binary: string;
    state: "protected" | "installed_not_seen" | "bypasses";
    seen_secs_ago?: number;
    reason?: string;
  }>;
}

/** Coverage verdict for one installed tool. */
export interface CoverageItem {
  tool: string;
  state: "protected" | "installed_not_seen" | "bypasses";
  seenSecsAgo: number | null;
  reason: string | null;
}

/** Subscription-plan limit headroom for one provider's binding window. */
export interface PlanSummary {
  provider: string;
  primaryLabel: string;
  /** 0..100. */
  primaryPct: number;
  primaryResetInSecs: number;
  secondaryLabel: string | null;
  secondaryPct: number | null;
  throttled: boolean;
}

export interface StatusSummary {
  costToday: number;
  /** 0..1, or null when no prompt-side tokens were billed today. */
  cacheHitRate: number | null;
  blocked: number;
  securityEvents: number;
  /** Percent of the daily budget spent, or null when no daily limit is set. */
  budgetPercent: number | null;
  /** Subscription headroom (tightest binding window), or null for API usage. */
  plan: PlanSummary | null;
  /** Per-tool coverage; empty when no supported tools are installed. */
  coverage: CoverageItem[];
}

/** "time until" label for a reset countdown: `45m`, `2h28m`, `2d7h`, `now`. */
export function humanDuration(secs: number): string {
  if (secs <= 0) {
    return "now";
  }
  const mins = Math.floor(secs / 60);
  if (mins < 60) {
    return `${mins}m`;
  }
  const hours = Math.floor(mins / 60);
  if (hours < 24) {
    return `${hours}h${String(mins % 60).padStart(2, "0")}m`;
  }
  return `${Math.floor(hours / 24)}d${hours % 24}h`;
}

/** Pick the tightest binding window across all subscription providers. */
function planSummary(s: StatusJson): PlanSummary | null {
  const providers = s.plan?.providers ?? [];
  let best: PlanSummary | null = null;
  for (const prov of providers) {
    const windows = prov.windows ?? [];
    if (windows.length === 0) {
      continue;
    }
    const primary = windows[0];
    const secondary = windows[1] ?? null;
    const cand: PlanSummary = {
      provider: prov.provider,
      primaryLabel: primary.label,
      primaryPct: primary.utilization * 100,
      primaryResetInSecs: primary.reset_in_secs,
      secondaryLabel: secondary ? secondary.label : null,
      secondaryPct: secondary ? secondary.utilization * 100 : null,
      throttled: prov.status !== "allowed",
    };
    if (!best || cand.primaryPct > best.primaryPct) {
      best = cand;
    }
  }
  return best;
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

  const coverage: CoverageItem[] = (s.coverage ?? []).map((c) => ({
    tool: c.tool,
    state: c.state,
    seenSecsAgo: c.seen_secs_ago ?? null,
    reason: c.reason ?? null,
  }));

  return {
    costToday,
    cacheHitRate,
    blocked: s.blocked_requests ?? 0,
    securityEvents: s.security_events ?? 0,
    budgetPercent,
    plan: planSummary(s),
    coverage,
  };
}

/** One-line status-bar label (VS Code `$(icon)` codicons allowed). On a
 * subscription, dollars are notional, so the binding limit window leads instead. */
export function statusBarText(s: StatusSummary): string {
  const bypassed = s.coverage.filter((c) => c.state === "bypasses");
  const bypassPart =
    bypassed.length > 0
      ? `$(warning) ${bypassed.map((c) => c.tool).join(", ")} unprotected`
      : null;
  if (s.plan) {
    const p = s.plan;
    const parts = [
      `$(flame) ${p.primaryLabel} ${Math.round(p.primaryPct)}% (${humanDuration(
        p.primaryResetInSecs,
      )})`,
    ];
    if (p.throttled) {
      parts.push("$(warning) throttled");
    }
    if (s.blocked > 0) {
      parts.push(`$(shield) ${s.blocked}`);
    }
    if (bypassPart) {
      parts.push(bypassPart);
    }
    return parts.join("  ·  ");
  }
  const parts = [`$(flame) $${s.costToday.toFixed(2)}`];
  if (s.cacheHitRate !== null) {
    parts.push(`cache ${Math.round(s.cacheHitRate * 100)}%`);
  }
  if (s.blocked > 0) {
    parts.push(`$(shield) ${s.blocked}`);
  }
  if (bypassPart) {
    parts.push(bypassPart);
  }
  return parts.join("  ·  ");
}

/** Human-readable coverage line for the tooltip. */
function coverageLine(c: CoverageItem): string {
  switch (c.state) {
    case "protected":
      return `  ${c.tool}: protected${
        c.seenSecsAgo !== null ? ` (seen ${humanDuration(c.seenSecsAgo)} ago)` : ""
      }`;
    case "bypasses":
      return `  ${c.tool}: NOT protected${c.reason ? ` — ${c.reason}` : ""}`;
    default:
      return `  ${c.tool}: installed, no traffic seen`;
  }
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
  const lines = [
    "Burnwall — today",
    `Cost: $${s.costToday.toFixed(2)}`,
    budgetLine,
    cacheLine,
    `Blocked requests: ${s.blocked}`,
    `Security events: ${s.securityEvents}`,
  ];
  if (s.plan) {
    const p = s.plan;
    lines.push(
      "",
      `Plan (${p.provider})${p.throttled ? " — THROTTLED" : ""}`,
      `${p.primaryLabel}: ${Math.round(p.primaryPct)}% used, resets ${humanDuration(
        p.primaryResetInSecs,
      )}`,
    );
    if (p.secondaryLabel !== null && p.secondaryPct !== null) {
      lines.push(`${p.secondaryLabel}: ${Math.round(p.secondaryPct)}% used`);
    }
  }
  if (s.coverage.length > 0) {
    lines.push("", "Coverage (routes through Burnwall):");
    for (const c of s.coverage) {
      lines.push(coverageLine(c));
    }
  }
  lines.push("", "Click for the full breakdown.");
  return lines.join("\n");
}
