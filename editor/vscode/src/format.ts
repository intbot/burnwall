// Pure parsing/formatting for the status bar. No `vscode` import here, so it is
// unit-testable under plain Node (see test/format.test.ts). The extension host
// code lives in extension.ts.

/** The subset of `burnwall status --json` the status bar reads. */
export interface StatusJson {
  total_cost_usd?: number;
  combined_total_usd?: number;
  proxy_running?: boolean;
  env_routing?: string;
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
  /** True when the env routes to the proxy but the proxy process is not
   * running — every request from that environment will fail (U-C1). */
  proxyDown: boolean;
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
      // Only positively-throttling statuses — Anthropic emits warning-grade
      // intermediates (`allowed_warning`) while requests still succeed (U-H4).
      throttled: ["throttled", "rejected", "blocked", "rate_limited"].includes(prov.status),
    };
    if (!best || cand.primaryPct > best.primaryPct) {
      best = cand;
    }
  }
  return best;
}

export function summarize(s: StatusJson): StatusSummary {
  // Headline figure: the proxied total. `combined_total_usd` is now deduped
  // server-side (X4), but proxied spend is the number Burnwall can vouch for;
  // the combined figure is detail for the panel, not the bar.
  const costToday = s.total_cost_usd ?? s.combined_total_usd ?? 0;

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
    proxyDown: s.env_routing === "proxied" && s.proxy_running === false,
  };
}

/** One-line status-bar label (VS Code `$(icon)` codicons allowed). On a
 * subscription, dollars are notional, so the binding limit window leads instead. */
export function statusBarText(s: StatusSummary): string {
  // Routed at a dead proxy beats every other message: the user's tools are
  // actively failing with connection-refused right now (U-C1).
  if (s.proxyDown) {
    return "$(error) Burnwall proxy DOWN — run `burnwall start`";
  }
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
  // On a flat-rate plan the dollar figure is notional (API-equivalent), not a
  // bill — label it so a subscriber doesn't read it as money owed.
  const costLine = s.plan
    ? `Cost: $${s.costToday.toFixed(2)} (notional — flat-rate plan)`
    : `Cost: $${s.costToday.toFixed(2)}`;
  const lines = [
    "Burnwall — today",
    costLine,
    budgetLine,
    cacheLine,
    `Blocked requests: ${s.blocked}`,
    `Security events: ${s.securityEvents}`,
  ];
  if (s.proxyDown) {
    lines.splice(1, 0, "⛔ PROXY DOWN — tools routed here will fail to connect. Run `burnwall start`.");
  }
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
