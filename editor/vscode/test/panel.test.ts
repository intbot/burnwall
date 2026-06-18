import assert from "node:assert";
import { test } from "node:test";

import { panelHtml } from "../src/panel_view";

test("panelHtml renders stat cards, models, security, and MCP", () => {
  const html = panelHtml(
    {
      total_cost_usd: 3.5,
      turns: 10,
      blocked: 1,
      mcp_tool_calls: 4,
      models: [{ provider: "anthropic", model: "claude-opus-4-7", requests: 10, cost_usd: 3.5 }],
      security_by_type: [{ event_type: "path_blocked", count: 1 }],
      mcp_tools: [{ server: "fs", tool: "read", trust_state: "approved" }],
    },
    {
      total_cost_usd: 1.25,
      budget: { daily_limit_usd: 10, spent_today_usd: 1.25 },
      security_blocked: 2,
      security_alerts: 5,
      breakdown: [{ input_tokens: 100, cache_creation_tokens: 0, cache_read_tokens: 900 }],
    },
  );
  // Spend tile + model table.
  assert.ok(html.includes("$1.25"), html);
  assert.ok(html.includes("claude-opus-4-7"), html);
  assert.ok(html.includes("$3.50"), html);
  // Budget tile sub-line (13% of $10.00 daily).
  assert.ok(html.includes("of $10.00 daily"), html);
  // Cache tile derived from the breakdown (900 read / 1000 prompt = 90%).
  assert.ok(html.includes("90%"), html);
  // Blocked tile uses the honest split: 2 blocked, "5 alerts".
  assert.ok(html.includes("5 alerts"), html);
  // Security + MCP detail.
  assert.ok(html.includes("path_blocked: 1"), html);
  assert.ok(html.includes("fs/read"), html);
});

test("panelHtml renders delta chips, SVG spend chart, and share bars", () => {
  const html = panelHtml(
    {
      models: [
        { provider: "anthropic", model: "claude-opus-4-7", requests: 10, cost_usd: 8.0 },
        { provider: "openai", model: "gpt-4o", requests: 4, cost_usd: 2.0 },
      ],
    },
    {
      total_cost_usd: 0.95,
      budget: { daily_limit_usd: 10, spent_today_usd: 0.95 },
      security_blocked: 1,
      security_alerts: 0,
      breakdown: [{ input_tokens: 100, cache_creation_tokens: 0, cache_read_tokens: 900 }],
      spend_series: [0.3, 0.1, 0.4, 0.05, 0.55, 0.2, 0.95],
      previous_day: { cost_usd: 0.2, cache_hit_pct: 80, blocked: 5 },
    },
  );
  // Spend up 0.20 → 0.95 ≈ +375% → up chip; cache 90 vs 80 → up chip.
  assert.ok(html.includes("▲"), html);
  // Fewer blocks than yesterday (1 vs 5) → a down chip.
  assert.ok(html.includes("▼"), html);
  // Static SVG spend chart is present (script-free <path>), no <script>.
  assert.ok(html.includes("<svg"), html);
  assert.ok(html.includes("Spend · last 7 days"), html);
  assert.ok(!html.includes("<script"), "panel must stay script-free: " + html);
  // Share-of-spend bars in the model table.
  assert.ok(html.includes("pbar"), html);
});

test("panelHtml omits chart and chips without a baseline/series", () => {
  // No spend_series / previous_day → no chart, no chips, but no crash.
  const html = panelHtml(
    { models: [{ provider: "x", model: "m", requests: 1, cost_usd: 1 }] },
    { total_cost_usd: 1, breakdown: [{ input_tokens: 10, cache_read_tokens: 0 }] },
  );
  assert.ok(!html.includes("<svg"), "no chart without a series");
  assert.ok(!html.includes("vs yest."), "no delta chip without a baseline");
});

test("panelHtml degrades on empty/missing fields", () => {
  const html = panelHtml({}, {});
  assert.ok(html.includes("(no spend in window)"), html);
  assert.ok(html.includes("no daily limit set"), html);
});

test("panelHtml escapes HTML in field values", () => {
  const html = panelHtml(
    { models: [{ provider: "x", model: "<script>", requests: 1, cost_usd: 0 }] },
    {},
  );
  assert.ok(html.includes("&lt;script&gt;"), html);
  assert.ok(!html.includes("<script>"), html);
});
