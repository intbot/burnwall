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

test("the bar headlines the proxied total, not the combined figure (X4/U-H3)", () => {
  // The proxied number is what Burnwall can vouch for; combined (proxied +
  // unproxied logs) is panel detail, and previously double-counted proxied
  // Claude Code into the headline.
  const s = summarize({ total_cost_usd: 1, combined_total_usd: 5 });
  assert.equal(s.costToday, 1);
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

test("subscription plan: status bar leads with the binding window, not dollars", () => {
  const s = summarize({
    total_cost_usd: 190.11,
    plan: {
      providers: [
        {
          provider: "anthropic",
          status: "allowed",
          windows: [
            { label: "5h", utilization: 0.17, reset_in_secs: 7007 },
            { label: "7d", utilization: 0.1, reset_in_secs: 198495 },
          ],
        },
      ],
    },
  });
  assert.ok(s.plan, "plan should be summarized");
  const text = statusBarText(s);
  assert.ok(text.includes("5h 17% (1h56m)"), text);
  assert.ok(!text.includes("$190"), text); // notional dollars suppressed
  const tip = tooltip(s);
  assert.ok(tip.includes("Plan (anthropic)"), tip);
  assert.ok(tip.includes("7d: 10% used"), tip);
});

test("no plan -> dollar status bar (API / fallback)", () => {
  const s = summarize({ total_cost_usd: 2, plan: null });
  assert.equal(s.plan, null);
  assert.ok(statusBarText(s).includes("$2.00"));
});

test("subscription plan: throttled flag surfaces", () => {
  const s = summarize({
    plan: {
      providers: [
        {
          provider: "anthropic",
          status: "throttled",
          windows: [{ label: "5h", utilization: 1.0, reset_in_secs: 600 }],
        },
      ],
    },
  });
  assert.ok(statusBarText(s).includes("throttled"));
});

test("warning-grade plan status is NOT throttled (U-H4)", () => {
  const s = summarize({
    plan: {
      providers: [
        {
          provider: "anthropic",
          status: "allowed_warning",
          windows: [{ label: "5h", utilization: 0.85, reset_in_secs: 600 }],
        },
      ],
    },
  });
  assert.equal(s.plan?.throttled, false);
  assert.ok(!statusBarText(s).includes("throttled"));
});

test("routed at a dead proxy beats all other status (U-C1)", () => {
  const s = summarize({
    total_cost_usd: 2,
    env_routing: "proxied",
    proxy_running: false,
  });
  assert.equal(s.proxyDown, true);
  assert.ok(statusBarText(s).includes("DOWN"));
  assert.ok(tooltip(s).includes("PROXY DOWN"));
});

test("proxy running while routed is not flagged down", () => {
  const s = summarize({
    total_cost_usd: 2,
    env_routing: "proxied",
    proxy_running: true,
  });
  assert.equal(s.proxyDown, false);
});

test("coverage: a bypassing tool warns in the status bar and tooltip", () => {
  const s = summarize({
    total_cost_usd: 2,
    coverage: [
      { tool: "Claude Code", binary: "claude", state: "protected", seen_secs_ago: 120 },
      {
        tool: "Codex CLI",
        binary: "codex",
        state: "bypasses",
        reason: "Codex on ChatGPT login routes to the ChatGPT backend",
      },
    ],
  });
  const text = statusBarText(s);
  assert.ok(text.includes("$(warning) Codex CLI unprotected"), text);
  const tip = tooltip(s);
  assert.ok(tip.includes("Coverage (routes through Burnwall):"), tip);
  assert.ok(tip.includes("Claude Code: protected (seen 2m ago)"), tip);
  assert.ok(tip.includes("Codex CLI: NOT protected"), tip);
});

test("coverage: all-protected shows no status-bar warning", () => {
  const s = summarize({
    total_cost_usd: 2,
    coverage: [{ tool: "Claude Code", binary: "claude", state: "protected", seen_secs_ago: 30 }],
  });
  assert.ok(!statusBarText(s).includes("unprotected"));
});
