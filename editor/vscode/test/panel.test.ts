import assert from "node:assert";
import { test } from "node:test";

import { panelHtml } from "../src/panel_view";

test("panelHtml renders models, security, MCP, and budget", () => {
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
    { total_cost_usd: 1.25, budget: { daily_limit_usd: 10, spent_today_usd: 1.25 } },
  );
  assert.ok(html.includes("claude-opus-4-7"), html);
  assert.ok(html.includes("$3.50"), html);
  assert.ok(html.includes("path_blocked: 1"), html);
  assert.ok(html.includes("fs/read"), html);
  assert.ok(html.includes("$1.25 of $10.00 today"), html);
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
