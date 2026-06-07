//! User-facing configuration model. Mirrors the TOML schema in SPEC.md
//! §"Config File Format". One top-level [`Config`] struct serde-serializes
//! to the canonical `~/.burnwall/config.toml` shape.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Config {
    #[serde(default)]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub budget: BudgetConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub loop_detection: LoopDetectionConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub tools: ToolsConfig,
    #[serde(default)]
    pub waste: WasteConfig,
    #[serde(default)]
    pub rules: RulesConfig,
    #[serde(default)]
    pub mcp: McpConfig,
    #[serde(default)]
    pub resilience: ResilienceConfig,
    #[serde(default)]
    pub observability: ObservabilityConfig,
    #[serde(default)]
    pub pricing: PricingConfig,
    /// Deprecated: superseded by `[tools]`. Kept for one release as a global
    /// kill switch (`enabled = false` disables all log scraping). Prefer the
    /// per-tool `[tools]` switches. Only written back when set to a
    /// non-default value, so fresh configs don't re-introduce the old key.
    #[serde(default, skip_serializing_if = "log_scrape_is_default")]
    pub log_scrape: LogScrapeConfig,
}

fn log_scrape_is_default(c: &LogScrapeConfig) -> bool {
    *c == LogScrapeConfig::default()
}

impl Config {
    /// Whether to scrape Claude Code logs — the per-tool `[tools]` switch,
    /// gated by the deprecated global `[log_scrape]` kill switch.
    pub fn scrape_claude_code(&self) -> bool {
        self.log_scrape.enabled && self.tools.claude_code
    }

    /// Whether to scrape Codex logs.
    pub fn scrape_codex(&self) -> bool {
        self.log_scrape.enabled && self.tools.codex
    }

    /// Whether to scrape OpenCode logs.
    pub fn scrape_opencode(&self) -> bool {
        self.log_scrape.enabled && self.tools.opencode
    }

    /// Whether to scrape Aider logs.
    pub fn scrape_aider(&self) -> bool {
        self.log_scrape.enabled && self.tools.aider
    }

    /// Whether any tool's logs are scraped at all.
    pub fn any_scrape_enabled(&self) -> bool {
        self.scrape_claude_code()
            || self.scrape_codex()
            || self.scrape_opencode()
            || self.scrape_aider()
    }

    /// The per-tool selection in the shape `logscrape` consumes.
    #[cfg(feature = "logscrape")]
    pub fn scrape_tools(&self) -> crate::logscrape::Tools {
        crate::logscrape::Tools {
            claude_code: self.scrape_claude_code(),
            codex: self.scrape_codex(),
            opencode: self.scrape_opencode(),
            aider: self.scrape_aider(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProxyConfig {
    pub port: u16,
    pub host: String,
    /// Auto-inject Anthropic `cache_control` markers (ephemeral) onto
    /// the system prompt and the first message of outbound requests
    /// that have none. Off by default — Burnwall does not modify
    /// request bodies silently.
    #[serde(default)]
    pub cache_injection: bool,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            port: 4100,
            host: "127.0.0.1".to_string(),
            cache_injection: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BudgetConfig {
    /// Daily limit in USD. `0.0` = unlimited.
    pub daily: f64,
    /// Monthly limit in USD. `0.0` = unlimited.
    pub monthly: f64,
    /// Warn (don't block) at this percent of the daily limit.
    pub warn_percent: u8,
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
            daily: 50.0,
            monthly: 0.0,
            warn_percent: 80,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecurityConfig {
    pub enabled: bool,
    pub deny_paths: Vec<String>,
    pub deny_commands: Vec<String>,
    pub block_network_mounts: bool,
    pub detect_secrets: bool,
    /// Redact the `details` field in `security_events` rows and the
    /// `block_reason` in blocked `requests` rows — keeps filesystem paths
    /// out of stored data for users who sync or share the database.
    #[serde(default)]
    pub log_redact_details: bool,
    /// Egress / DLP detection (v0.6.5). When `true`, the scanner also blocks
    /// payloads carrying exfiltration-prone data the credential denylist does
    /// not cover (Luhn-valid card numbers, US SSNs). Off by default — it errs
    /// toward precision and is opt-in like other request-rewriting toggles.
    #[serde(default)]
    pub dlp: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            deny_paths: crate::security::rules::DEFAULT_DENY_PATHS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            deny_commands: crate::security::rules::DEFAULT_DENY_COMMANDS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            block_network_mounts: true,
            detect_secrets: true,
            log_redact_details: false,
            dlp: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LoopDetectionConfig {
    pub enabled: bool,
    pub max_identical_requests: u32,
    pub window_seconds: u32,
    pub max_cost_per_window: f64,
    /// Actively block the next request once rolling spend exceeds
    /// `max_cost_per_window`. Off by default — detection always logs a warning,
    /// but enforcement is opt-in so a normal spend spike does not 429 the user.
    #[serde(default)]
    pub cost_spiral_enforce: bool,
}

impl Default for LoopDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_identical_requests: 5,
            window_seconds: 300,
            max_cost_per_window: 2.0,
            cost_spiral_enforce: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LoggingConfig {
    pub level: String,
    pub file: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            file: "~/.burnwall/burnwall.log".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LogScrapeConfig {
    /// When true, `burnwall status` also scrapes local tool session logs
    /// (Claude Code, Codex) to show cross-tool spend that did not go
    /// through the proxy. Read-only — never writes to the database.
    pub enabled: bool,
}

impl Default for LogScrapeConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// Per-tool log scraping. All supported tools default ON; set one `false`
/// to skip it. Replaces the global `[log_scrape].enabled` bool.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolsConfig {
    pub claude_code: bool,
    pub codex: bool,
    // Added after the first `[tools]` shipped, so they carry per-field serde
    // defaults — an existing config that wrote only `claude_code` + `codex`
    // must still deserialize (a missing field would otherwise be an error).
    #[serde(default = "default_true")]
    pub opencode: bool,
    #[serde(default = "default_true")]
    pub aider: bool,
}

fn default_true() -> bool {
    true
}

impl Default for ToolsConfig {
    fn default() -> Self {
        Self {
            claude_code: true,
            codex: true,
            opencode: true,
            aider: true,
        }
    }
}

/// Waste-insights configuration. `enabled` toggles the whole advisory
/// engine (`burnwall waste` + the `status` teaser). Off-by-default,
/// privacy-relaxing rules and per-rule threshold overrides will hang off
/// sub-tables here in a later release.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WasteConfig {
    pub enabled: bool,
}

impl Default for WasteConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// Enabled official rule packs (v0.6). Each id names a bundled official pack;
/// `burnwall rules install <id>` adds to this list and `burnwall start` merges
/// the pack onto the runtime ruleset. A pack only ever EXTENDS the denylist
/// (invariant I2). Empty by default — no packs enabled.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct RulesConfig {
    #[serde(default)]
    pub enabled: Vec<String>,
    /// Trusted publisher keys for signed remote packs (v0.9). `burnwall rules
    /// fetch <url>` / `verify` only accept a pack whose detached Ed25519
    /// signature verifies against one of these keys. Empty by default — no
    /// remote pack is trusted until you add a publisher.
    #[serde(default)]
    pub publishers: Vec<RulePublisher>,
}

/// A trusted rule-pack publisher: a label plus a hex-encoded Ed25519 public key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RulePublisher {
    pub name: String,
    /// Hex-encoded 32-byte Ed25519 verifying key.
    pub key: String,
}

/// `[pricing]` — trust config for signed remote pricing cards. `burnwall
/// pricing update` only installs a fetched `pricing.toml` whose detached
/// Ed25519 signature verifies against one of `publishers`. Empty by default —
/// no remote card is trusted until you add a publisher key. A signed card is a
/// data-only delivery channel for the rate table the binary already understands;
/// it never grants new capabilities, only updates prices.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct PricingConfig {
    #[serde(default)]
    pub publishers: Vec<RulePublisher>,
}

/// `[mcp]` — `burnwall mcp-watch` runtime depth (v0.6.5). `servers` lets one
/// watcher front several MCP servers, routed by the first path segment
/// (`/<name>/...`). `require_approval` turns on enforce mode: a `tools/call`
/// to a tool that has not been approved via `burnwall mcp approve` is blocked
/// (403) instead of forwarded. Both default off / empty, so an upgrade keeps
/// the v0.5 single-upstream, observe-only behavior until the user opts in.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct McpConfig {
    #[serde(default)]
    pub require_approval: bool,
    #[serde(default)]
    pub servers: Vec<McpServerConfig>,
    /// Auto-approve policy (v0.9.1): glob patterns matched against
    /// `"<server>/<tool>"`. In enforce mode a matching `tools/call` skips the
    /// approval gate (forwards without a prompt). Opt-in — it *loosens*
    /// enforcement, so list only tools you trust. Globs support `*`
    /// (e.g. `filesystem/read_file`, `filesystem/*`, `*`).
    #[serde(default)]
    pub auto_approve: Vec<String>,
    /// Auto-deny policy (v0.9.1): glob patterns matched against
    /// `"<server>/<tool>"`. A matching `tools/call` is **always** blocked (403),
    /// regardless of approval — checked before everything else.
    #[serde(default)]
    pub auto_deny: Vec<String>,
}

/// One named upstream MCP server for multi-server routing. Requests to
/// `/<name>` or `/<name>/...` forward to `upstream` with the prefix stripped.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct McpServerConfig {
    pub name: String,
    pub upstream: String,
}

/// `[resilience]` — same-model endpoint failover + circuit breaking (v0.7).
/// Off by default: `enabled = false` keeps the single-upstream behavior. When
/// on, the proxy tries each provider's `endpoints` in order, skipping ones the
/// circuit breaker has opened, and falls through to the next on a connection
/// error or 5xx. Metadata only — the request body forwards unchanged.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResilienceConfig {
    pub enabled: bool,
    /// Consecutive failures before an endpoint's circuit opens.
    pub failure_threshold: u32,
    /// How long an opened circuit stays open before a half-open probe.
    pub cooldown_seconds: u64,
    /// Per-provider ordered fallback endpoints (base URLs). The primary
    /// upstream is always tried first; these are tried after it, in order.
    #[serde(default)]
    pub endpoints: Vec<FailoverEndpoints>,
}

impl Default for ResilienceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            failure_threshold: 3,
            cooldown_seconds: 30,
            endpoints: Vec::new(),
        }
    }
}

/// Failover base URLs for one provider (`anthropic` / `openai` / `google`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FailoverEndpoints {
    pub provider: String,
    pub urls: Vec<String>,
}

/// `[observability]` — local, metadata-only observability (v0.7). `otel_spans`
/// turns on OpenTelemetry GenAI span emission to `otel_file` (line-delimited
/// JSON, no prompt content, no network). Both off / empty by default.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ObservabilityConfig {
    #[serde(default)]
    pub otel_spans: bool,
    /// Span file path. Empty → `<data dir>/otel-spans.jsonl`.
    #[serde(default)]
    pub otel_file: String,
}

/// Convert the persistent config's budget block into the runtime
/// [`crate::budget::BudgetConfig`] used by [`BudgetTracker`].
impl From<&BudgetConfig> for crate::budget::BudgetConfig {
    fn from(c: &BudgetConfig) -> Self {
        Self {
            daily_usd: c.daily,
            monthly_usd: c.monthly,
            warn_percent: c.warn_percent,
        }
    }
}

/// Convert the persistent config's security block into the runtime
/// [`crate::security::Ruleset`].
impl From<&SecurityConfig> for crate::security::Ruleset {
    fn from(c: &SecurityConfig) -> Self {
        Self {
            enabled: c.enabled,
            deny_paths: c.deny_paths.clone(),
            // `allow_paths` is project-profile-only — the global config has
            // no allow list. A discovered `.burnwall.yaml` merges into this
            // afterwards (see `cli::start`).
            allow_paths: Vec::new(),
            deny_commands: c.deny_commands.clone(),
            block_network_mounts: c.block_network_mounts,
            detect_secrets: c.detect_secrets,
            detect_egress: c.dlp,
            // Pack-contributed patterns are merged in later (Phase B startup
            // wiring), like a discovered project profile.
            secret_patterns: Vec::new(),
            log_redact_details: c.log_redact_details,
        }
    }
}

impl ResilienceConfig {
    /// Build the runtime [`crate::proxy::resilience::Resilience`] from this
    /// config block, indexing the per-provider failover lists by provider name.
    pub fn to_runtime(&self) -> crate::proxy::resilience::Resilience {
        use std::collections::HashMap;
        let mut failover: HashMap<String, Vec<String>> = HashMap::new();
        for ep in &self.endpoints {
            failover
                .entry(ep.provider.clone())
                .or_default()
                .extend(ep.urls.iter().cloned());
        }
        crate::proxy::resilience::Resilience::new(
            self.enabled,
            self.failure_threshold,
            std::time::Duration::from_secs(self.cooldown_seconds),
            failover,
        )
    }
}

/// Convert the persistent loop_detection block into the runtime
/// [`crate::budget::LoopConfig`]. `hash_prefix_bytes` keeps its built-in
/// default (200) — we don't expose it as a TOML knob in v0.2.
impl From<&LoopDetectionConfig> for crate::budget::LoopConfig {
    fn from(c: &LoopDetectionConfig) -> Self {
        let defaults = crate::budget::LoopConfig::default();
        Self {
            enabled: c.enabled,
            max_identical_requests: c.max_identical_requests,
            window_seconds: c.window_seconds,
            max_cost_per_window: c.max_cost_per_window,
            cost_spiral_enforce: c.cost_spiral_enforce,
            hash_prefix_bytes: defaults.hash_prefix_bytes,
        }
    }
}
