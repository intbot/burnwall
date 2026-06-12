//! Local observability (v0.7) — metadata-only, on-machine, zero network.
//!
//! Two surfaces, both privacy-safe (no prompt content ever):
//!
//! - [`metrics`] — per-model latency percentiles, error rate, and throughput
//!   computed from the request log. The local answer to hosted LLM
//!   observability. Surfaced by `burnwall metrics`.
//! - [`otel`] — OpenTelemetry GenAI-semantic-convention spans, emitted as
//!   line-delimited JSON to a local file (never shipped over the network).
//!   Opt-in. For interop with OTel-aware tooling without leaking payloads.

pub mod attribution;
pub mod cost_export;
pub mod digest;
pub mod metrics;
pub mod otel;
pub mod wire_vs_logs;
