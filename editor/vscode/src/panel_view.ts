// Pure view model for the Burnwall panel — no `vscode` import, so it is
// unit-testable under plain Node (see test/panel.test.ts). The webview wiring
// (which needs `vscode`) lives in panel.ts.
//
// Layout: "native stat cards" (Variant 1) — a header, a row of four stat tiles
// (Spend / Budget / Cache / Blocked) with CSS bars, then a Cost-by-model table
// and the security / MCP detail. Styled entirely with VS Code theme variables
// (`--vscode-*`) so it adapts to light, dark, and high-contrast themes, and is
// rendered with NO scripts (the panel sets `enableScripts: false`).

export interface Digest {
  total_cost_usd?: number;
  turns?: number;
  blocked?: number;
  mcp_tool_calls?: number;
  models?: Array<{ provider?: string; model?: string; requests?: number; cost_usd?: number }>;
  security_by_type?: Array<{ event_type?: string; count?: number }>;
  mcp_tools?: Array<{ server?: string; tool?: string; trust_state?: string }>;
}

export interface Status {
  total_cost_usd?: number;
  blocked_requests?: number;
  security_events?: number;
  /** Enforcement blocks vs advisory alerts — kept distinct so an alert is
   * never shown as a block (mirrors the CLI's honest split). */
  security_blocked?: number;
  security_alerts?: number;
  budget?: { daily_limit_usd?: number; spent_today_usd?: number };
  /** Per-model token rows, used to derive today's cache-hit rate. */
  breakdown?: Array<{
    input_tokens?: number;
    cache_creation_tokens?: number;
    cache_read_tokens?: number;
  }>;
}

function esc(s: unknown): string {
  return String(s ?? "").replace(/[&<>"]/g, (c) => {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c] as string;
  });
}

function money(n: unknown): string {
  const v = typeof n === "number" ? n : 0;
  return `$${v.toFixed(2)}`;
}

function num(n: unknown): number {
  return typeof n === "number" && isFinite(n) ? n : 0;
}

/** Theme-token colour for a "higher is worse" gauge (budget used). */
function gaugeColor(pct: number): string {
  if (pct < 60) return "var(--vscode-charts-green, #3fb950)";
  if (pct < 85) return "var(--vscode-charts-yellow, #d29922)";
  return "var(--vscode-charts-red, #f85149)";
}

/** A thin CSS progress bar filled to `pct` (0..100) in `color`. */
function bar(pct: number, color: string): string {
  const w = Math.max(0, Math.min(100, pct));
  return `<div class="bar"><span style="width:${w.toFixed(0)}%;background:${color}"></span></div>`;
}

/** One stat tile: label, headline value, optional bar, optional sub-line. */
function card(label: string, value: string, opts: { bar?: string; sub?: string; valueColor?: string } = {}): string {
  const valStyle = opts.valueColor ? ` style="color:${opts.valueColor}"` : "";
  return `<div class="card">
    <div class="label">${esc(label)}</div>
    <div class="value"${valStyle}>${esc(value)}</div>
    ${opts.bar ?? ""}
    ${opts.sub ? `<div class="sub">${esc(opts.sub)}</div>` : ""}
  </div>`;
}

/** Render the panel HTML from the digest + status JSON. Pure. */
export function panelHtml(digest: Digest, status: Status): string {
  // ── derived figures ─────────────────────────────────────────────────────
  const todayCost = num(status.total_cost_usd);
  const turns = num(digest.turns);
  const limit = num(status.budget?.daily_limit_usd);
  const spent = status.budget?.spent_today_usd ?? todayCost;
  const budgetPct = limit > 0 ? (num(spent) / limit) * 100 : null;

  let cacheRead = 0;
  let promptTotal = 0;
  for (const b of status.breakdown ?? []) {
    const read = num(b.cache_read_tokens);
    cacheRead += read;
    promptTotal += num(b.input_tokens) + num(b.cache_creation_tokens) + read;
  }
  const cachePct = promptTotal > 0 ? (cacheRead / promptTotal) * 100 : null;

  const blocked = num(status.security_blocked ?? status.blocked_requests);
  const alerts = num(status.security_alerts);

  // ── stat tiles ──────────────────────────────────────────────────────────
  const spendCard = card("Spend", money(todayCost), { sub: `${turns} turn${turns === 1 ? "" : "s"}` });

  const budgetCard =
    budgetPct !== null
      ? card("Budget", `${budgetPct.toFixed(0)}%`, {
          bar: bar(budgetPct, gaugeColor(budgetPct)),
          sub: `of ${money(limit)} daily`,
          valueColor: gaugeColor(budgetPct),
        })
      : card("Budget", "no cap", { sub: "no daily limit set" });

  const cacheCard =
    cachePct !== null
      ? card("Cache", `${cachePct.toFixed(0)}%`, {
          bar: bar(cachePct, "var(--vscode-charts-green, #3fb950)"),
          sub: "hit rate",
          valueColor: "var(--vscode-charts-green, #3fb950)",
        })
      : card("Cache", "n/a", { sub: "no prompt tokens yet" });

  const blockedCard = card("Blocked", String(blocked), {
    sub: `${alerts} alert${alerts === 1 ? "" : "s"}`,
    valueColor: blocked > 0 ? "var(--vscode-charts-red, #f85149)" : undefined,
  });

  // ── cost-by-model table ─────────────────────────────────────────────────
  const modelRows =
    (digest.models ?? [])
      .map(
        (m) =>
          `<tr><td>${esc(m.provider)}/${esc(m.model)}</td><td class="num">${esc(m.requests ?? 0)}</td><td class="num">${money(m.cost_usd)}</td></tr>`,
      )
      .join("") || `<tr><td colspan="3" class="muted">(no spend in window)</td></tr>`;

  // ── security + MCP detail ───────────────────────────────────────────────
  const secRows =
    (digest.security_by_type ?? [])
      .map((s) => `<span class="pill">${esc(s.event_type)}: ${esc(s.count ?? 0)}</span>`)
      .join("") || `<span class="muted">no events</span>`;

  const mcpRows =
    (digest.mcp_tools ?? [])
      .map((t) => `<span class="pill">${esc(t.server)}/${esc(t.tool)} · ${esc(t.trust_state)}</span>`)
      .join("") || `<span class="muted">none</span>`;

  return `<!doctype html>
<html><head><meta charset="utf-8">
<style>
  :root { color-scheme: light dark; }
  body {
    font-family: var(--vscode-font-family);
    color: var(--vscode-foreground);
    padding: 16px; margin: 0;
    font-size: var(--vscode-font-size, 13px);
  }
  .head { display: flex; align-items: baseline; justify-content: space-between; margin-bottom: 14px; }
  .head h1 { font-size: 1.05rem; font-weight: 600; margin: 0; }
  .head .date { color: var(--vscode-descriptionForeground); font-size: .82rem; }
  .cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 18px; }
  @media (max-width: 460px) { .cards { grid-template-columns: repeat(2, 1fr); } }
  .card {
    border: 1px solid var(--vscode-panel-border, rgba(128,128,128,.35));
    border-radius: 8px; padding: 10px 12px;
    background: var(--vscode-editorWidget-background, transparent);
  }
  .card .label {
    font-size: .68rem; text-transform: uppercase; letter-spacing: .05em;
    color: var(--vscode-descriptionForeground);
  }
  .card .value { font-size: 1.5rem; font-weight: 600; line-height: 1.2; margin-top: 2px; }
  .card .sub { font-size: .76rem; color: var(--vscode-descriptionForeground); margin-top: 3px; }
  .bar {
    height: 6px; border-radius: 3px; margin-top: 7px; overflow: hidden;
    background: var(--vscode-progressBar-background, rgba(128,128,128,.22));
  }
  .bar > span { display: block; height: 100%; border-radius: 3px; }
  h2 {
    font-size: .72rem; text-transform: uppercase; letter-spacing: .05em;
    color: var(--vscode-descriptionForeground);
    margin: 18px 0 6px; font-weight: 600;
  }
  table { border-collapse: collapse; width: 100%; font-size: .86rem; }
  th {
    text-align: left; font-weight: 500; color: var(--vscode-descriptionForeground);
    border-bottom: 1px solid var(--vscode-panel-border, rgba(128,128,128,.35));
    padding: 4px 10px 4px 0;
  }
  td { padding: 5px 10px 5px 0; border-bottom: 1px solid var(--vscode-panel-border, rgba(128,128,128,.15)); }
  th.num, td.num { text-align: right; font-variant-numeric: tabular-nums; }
  .pill {
    display: inline-block; margin: 0 6px 6px 0; padding: 2px 9px;
    border-radius: 11px; font-size: .76rem;
    background: var(--vscode-badge-background, rgba(128,128,128,.18));
    color: var(--vscode-badge-foreground, inherit);
  }
  .muted { color: var(--vscode-descriptionForeground); }
</style></head><body>
  <div class="head"><h1>🔥 Burnwall</h1><span class="date">Today</span></div>

  <div class="cards">
    ${spendCard}
    ${budgetCard}
    ${cacheCard}
    ${blockedCard}
  </div>

  <h2>Cost by model</h2>
  <table>
    <tr><th>Provider / Model</th><th class="num">Req</th><th class="num">Cost</th></tr>
    ${modelRows}
  </table>

  <h2>Security blocks</h2>
  <div>${secRows}</div>

  <h2>MCP tools (${esc(digest.mcp_tool_calls ?? 0)} calls)</h2>
  <div>${mcpRows}</div>
</body></html>`;
}
