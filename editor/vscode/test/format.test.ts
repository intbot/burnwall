import assert from "node:assert";
import { test } from "node:test";

import { statusBarText, summarize, tooltip } from "../src/format";

test("summarize computes cost, blocked, cache hit rate, and budget %", () => {
  const s = summarize({
    total_cost_usd: 3.47,
    blocked_requests: 2,
    security_events: 1,
    budget: { daily_limit_usd: 10, spent_today_usd: 3.47 },
    breakdown: [{ input_tokens: 100, cache_creation_tokens: 0, cache_read_tokens: 300 }],
  });
  assert.equal(s.costToday, 3.47);
  assert.equal(s.blocked, 2);
  assert.equal(s.securityEvents, 1);
  assert.equal(s.cacheHitRate, 300 / 400);
  assert.equal(Math.round(s.budgetPercent ?? 0), 35);
});

test("combined_total_usd is preferred over total_cost_usd", () => {
  const s = summarize({ total_cost_usd: 1, combined_total_usd: 5 });
  assert.equal(s.costToday, 5);
});

test("no tokens -> null cache hit rate; no limit -> null budget %", () => {
  const s = summarize({ total_cost_usd: 2 });
  assert.equal(s.cacheHitRate, null);
  assert.equal(s.budgetPercent, null);
});

test("statusBarText omits cache when null and shield when zero blocked", () => {
  const text = statusBarText(summarize({ total_cost_usd: 2 }));
  assert.ok(text.includes("$2.00"), text);
  assert.ok(!text.includes("cache"), text);
  assert.ok(!text.includes("$(shield)"), text);
});

test("statusBarText shows cache % and blocked count when present", () => {
  const text = statusBarText(
    summarize({
      total_cost_usd: 2,
      blocked_requests: 3,
      breakdown: [{ input_tokens: 50, cache_read_tokens: 50 }],
    }),
  );
  assert.ok(text.includes("cache 50%"), text);
  assert.ok(text.includes("$(shield) 3"), text);
});

test("tooltip notes when no daily limit is set", () => {
  const tip = tooltip(summarize({ total_cost_usd: 1 }));
  assert.ok(tip.includes("no daily limit set"), tip);
});
