// Pure view model for the Burnwall panel — no `vscode` import, so it is
// unit-testable under plain Node (see test/panel.test.ts). The webview wiring
// (which needs `vscode`) lives in panel.ts.
//
// Layout: "native stat cards" (Variant 1) — a header, a row of four stat tiles
// (Spend / Budget / Cache / Blocked) with delta-vs-yesterday chips and CSS
// bars, a pre-rendered static SVG spend trend, then a Cost-by-model table with
// share-of-spend bars and the security / MCP detail. Styled entirely with VS
// Code theme variables (`--vscode-*`) so it adapts to light, dark, and
// high-contrast themes, and rendered with NO scripts (the panel sets
// `enableScripts: false`) — the chart is a baked `<path>`, not a charting lib.

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
  /** Dense daily-spend series (oldest → newest, zero-filled) for the SVG chart. */
  spend_series?: number[];
  /** Yesterday's baselines for the delta-vs-previous chips. */
  previous_day?: { cost_usd?: number; cache_hit_pct?: number; blocked?: number };
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

const GREEN = "var(--vscode-charts-green, #3fb950)";
const RED = "var(--vscode-charts-red, #f85149)";
const AMBER = "var(--vscode-charts-orange, #cc8a3a)";
const MUTED = "var(--vscode-descriptionForeground)";

/** Theme-token colour for a "higher is worse" gauge (budget used). */
function gaugeColor(pct: number): string {
  if (pct < 60) return GREEN;
  if (pct < 85) return "var(--vscode-charts-yellow, #d29922)";
  return RED;
}

type Trend = "higherBetter" | "higherWorse";

/** Colour for a delta given its sign and the metric's polarity. */
function deltaColor(positive: boolean, flat: boolean, trend: Trend): string {
  if (flat) return MUTED;
  if ((positive && trend === "higherBetter") || (!positive && trend === "higherWorse")) return GREEN;
  if (positive && trend === "higherWorse") return AMBER;
  return RED;
}

/** A percent-change chip (`▲ 12%` / `▼ 7%` / `→ 0%`) HTML, or "" when there is
 * no baseline to compare against (prev == 0). Mirrors term.rs::delta_chip_pct. */
function deltaChipPct(curr: number, prev: number, trend: Trend): string {
  if (!isFinite(prev) || prev === 0) return "";
  const r = Math.round(((curr - prev) / prev) * 100);
  const flat = Math.abs(r) < 1;
  const text = flat ? "→ 0%" : r > 0 ? `▲ ${r}%` : `▼ ${Math.abs(r)}%`;
  const color = deltaColor(r > 0, flat, trend);
  return `<div class="delta" style="color:${color}">${esc(text)} <span class="vs">vs yest.</span></div>`;
}

/** An absolute-count chip (`▲ 3` / `▼ 5`), or "" when the counts are equal. */
function deltaChipCount(curr: number, prev: number, trend: Trend): string {
  if (curr === prev) return "";
  const diff = curr - prev;
  const text = diff > 0 ? `▲ ${diff}` : `▼ ${Math.abs(diff)}`;
  const color = deltaColor(diff > 0, false, trend);
  return `<div class="delta" style="color:${color}">${esc(text)} <span class="vs">vs yest.</span></div>`;
}

/** A thin CSS progress bar filled to `pct` (0..100) in `color`. */
function bar(pct: number, color: string): string {
  const w = Math.max(0, Math.min(100, pct));
  return `<div class="bar"><span style="width:${w.toFixed(0)}%;background:${color}"></span></div>`;
}

/** One stat tile: label, headline value, optional delta chip, bar, sub-line. */
function card(
  label: string,
  value: string,
  opts: { delta?: string; bar?: string; sub?: string; valueColor?: string } = {},
): string {
  const valStyle = opts.valueColor ? ` style="color:${opts.valueColor}"` : "";
  return `<div class="card">
    <div class="label">${esc(label)}</div>
    <div class="value"${valStyle}>${esc(value)}</div>
    ${opts.delta ?? ""}
    ${opts.bar ?? ""}
    ${opts.sub ? `<div class="sub">${esc(opts.sub)}</div>` : ""}
  </div>`;
}

/** Pre-rendered, script-free SVG area+line of the daily-spend series. Returns
 * "" when there's nothing to plot. Colours come from theme variables, so the
 * chart adapts to the user's theme exactly like the rest of the panel. */
function spendChartSvg(series: number[] | undefined): string {
  const pts = (series ?? []).filter((v) => typeof v === "number" && isFinite(v));
  if (pts.length < 2 || pts.every((v) => v <= 0)) return "";
  const W = 600;
  const H = 140;
  const padX = 6;
  const padTop = 12;
  const padBot = 10;
  const max = Math.max(...pts);
  const n = pts.length;
  const x = (i: number) => padX + (i * (W - 2 * padX)) / (n - 1);
  const y = (v: number) => {
    const h = H - padTop - padBot;
    const frac = max > 0 ? v / max : 0;
    return padTop + (1 - frac) * h;
  };
  const line = pts.map((v, i) => `${i === 0 ? "M" : "L"}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(" ");
  const baseline = (H - padBot).toFixed(1);
  const area = `${line} L${x(n - 1).toFixed(1)},${baseline} L${x(0).toFixed(1)},${baseline} Z`;
  const lastX = x(n - 1).toFixed(1);
  const lastY = y(pts[n - 1]).toFixed(1);
  return `<div class="chartwrap">
    <svg viewBox="0 0 ${W} ${H}" width="100%" height="118" preserveAspectRatio="none" role="img" aria-label="Daily spend trend">
      <defs><linearGradient id="bwspend" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" style="stop-color:${GREEN};stop-opacity:.28"/>
        <stop offset="100%" style="stop-color:${GREEN};stop-opacity:0"/>
      </linearGradient></defs>
      <path d="${area}" fill="url(#bwspend)"/>
      <path d="${line}" fill="none" stroke="${GREEN}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>
      <circle cx="${lastX}" cy="${lastY}" r="3" fill="${GREEN}"/>
    </svg>
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

  const prev = status.previous_day ?? {};
  const prevCost = num(prev.cost_usd);
  const prevCache = num(prev.cache_hit_pct);
  const prevBlocked = num(prev.blocked);

  // ── stat tiles ──────────────────────────────────────────────────────────
  const spendCard = card("Spend", money(todayCost), {
    delta: deltaChipPct(todayCost, prevCost, "higherWorse"),
    sub: `${turns} turn${turns === 1 ? "" : "s"}`,
  });

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
          delta: deltaChipPct(cachePct, prevCache, "higherBetter"),
          bar: bar(cachePct, GREEN),
          sub: "hit rate",
          valueColor: GREEN,
        })
      : card("Cache", "n/a", { sub: "no prompt tokens yet" });

  const blockedCard = card("Blocked", String(blocked), {
    delta: deltaChipCount(blocked, prevBlocked, "higherWorse"),
    sub: `${alerts} alert${alerts === 1 ? "" : "s"}`,
    valueColor: blocked > 0 ? RED : undefined,
  });

  // ── spend trend chart ───────────────────────────────────────────────────
  const series = status.spend_series ?? [];
  const chart = spendChartSvg(series);
  const seriesTotal = series.reduce((a, b) => a + num(b), 0);
  const chartSection = chart
    ? `<h2>Spend · last ${series.length} days</h2>
       <div class="chart-meta"><span>${esc(money(seriesTotal))} total</span>${
         deltaChipPct(todayCost, prevCost, "higherWorse")
           ? `<span>${deltaChipPct(todayCost, prevCost, "higherWorse")}</span>`
           : ""
       }</div>
       ${chart}`
    : "";

  // ── cost-by-model table (with share-of-spend bars) ──────────────────────
  const models = digest.models ?? [];
  const modelTotal = models.reduce((a, m) => a + num(m.cost_usd), 0);
  const modelRows =
    models
      .map((m) => {
        const share = modelTotal > 0 ? (num(m.cost_usd) / modelTotal) * 100 : 0;
        return `<tr><td>${esc(m.provider)}/${esc(m.model)}</td><td class="num">${esc(
          m.requests ?? 0,
        )}</td><td class="num">${money(m.cost_usd)}</td><td class="share"><span class="pbar" style="width:${share.toFixed(
          0,
        )}%"></span></td></tr>`;
      })
      .join("") || `<tr><td colspan="4" class="muted">(no spend in window)</td></tr>`;

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
  .card .delta { font-size: .74rem; font-weight: 600; margin-top: 3px; }
  .card .delta .vs { color: var(--vscode-descriptionForeground); font-weight: 400; }
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
  .chartwrap {
    border: 1px solid var(--vscode-panel-border, rgba(128,128,128,.35));
    border-radius: 8px; padding: 8px 6px 4px;
    background: var(--vscode-editorWidget-background, transparent);
  }
  .chart-meta { display: flex; justify-content: space-between; font-size: .74rem; color: var(--vscode-descriptionForeground); margin-bottom: 4px; }
  .chart-meta .delta { display: inline; font-weight: 600; }
  table { border-collapse: collapse; width: 100%; font-size: .86rem; }
  th {
    text-align: left; font-weight: 500; color: var(--vscode-descriptionForeground);
    border-bottom: 1px solid var(--vscode-panel-border, rgba(128,128,128,.35));
    padding: 4px 10px 4px 0;
  }
  td { padding: 5px 10px 5px 0; border-bottom: 1px solid var(--vscode-panel-border, rgba(128,128,128,.15)); }
  th.num, td.num { text-align: right; font-variant-numeric: tabular-nums; }
  td.share { width: 22%; }
  .pbar {
    display: inline-block; height: 8px; border-radius: 2px; min-width: 2px;
    background: var(--vscode-charts-blue, #4a9eff); vertical-align: middle;
  }
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

  ${chartSection}

  <h2>Cost by model</h2>
  <table>
    <tr><th>Provider / Model</th><th class="num">Req</th><th class="num">Cost</th><th>Share</th></tr>
    ${modelRows}
  </table>

  <h2>Security blocks</h2>
  <div>${secRows}</div>

  <h2>MCP tools (${esc(digest.mcp_tool_calls ?? 0)} calls)</h2>
  <div>${mcpRows}</div>
</body></html>`;
}
