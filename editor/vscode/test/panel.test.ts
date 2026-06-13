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
