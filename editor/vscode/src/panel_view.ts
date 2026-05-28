// Pure view model for the Burnwall panel — no `vscode` import, so it is
// unit-testable under plain Node (see test/panel.test.ts). The webview wiring
// (which needs `vscode`) lives in panel.ts.

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
  budget?: { daily_limit_usd?: number; spent_today_usd?: number };
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

/** Render the panel HTML from the digest + status JSON. Pure. */
export function panelHtml(digest: Digest, status: Status): string {
  const today = money(status.total_cost_usd);
  const limit = status.budget?.daily_limit_usd ?? 0;
  const budgetLine =
    limit > 0 ? `${today} of ${money(limit)} today` : `${today} today (no daily limit set)`;

  const modelRows =
    (digest.models ?? [])
      .map(
        (m) =>
          `<tr><td>${esc(m.provider)}/${esc(m.model)}</td><td>${esc(m.requests ?? 0)}</td><td>${money(m.cost_usd)}</td></tr>`,
      )
      .join("") || `<tr><td colspan="3">(no spend in window)</td></tr>`;

  const secRows =
    (digest.security_by_type ?? [])
      .map((s) => `<li>${esc(s.event_type)}: ${esc(s.count ?? 0)}</li>`)
      .join("") || "<li>(none)</li>";

  const mcpRows =
    (digest.mcp_tools ?? [])
      .map((t) => `<li>${esc(t.server)}/${esc(t.tool)} — ${esc(t.trust_state)}</li>`)
      .join("") || "<li>(none)</li>";

  return `<!doctype html>
<html><head><meta charset="utf-8">
<style>
  body { font-family: var(--vscode-font-family); padding: 1rem; }
  h2 { margin: 1.2rem 0 0.4rem; }
  table { border-collapse: collapse; width: 100%; }
  td, th { text-align: left; padding: 2px 10px 2px 0; }
  .big { font-size: 1.3rem; font-weight: 600; }
</style></head><body>
  <div class="big">🛡️ Burnwall</div>
  <p>${esc(budgetLine)} · ${esc(digest.turns ?? 0)} turns · ${esc(digest.blocked ?? 0)} blocked · window cost ${money(digest.total_cost_usd)}</p>

  <h2>Cost by model (window)</h2>
  <table><tr><th>provider/model</th><th>req</th><th>cost</th></tr>${modelRows}</table>

  <h2>Security blocks</h2>
  <ul>${secRows}</ul>

  <h2>MCP tools (${esc(digest.mcp_tool_calls ?? 0)} calls)</h2>
  <ul>${mcpRows}</ul>
</body></html>`;
}
