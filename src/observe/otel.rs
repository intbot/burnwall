//! OpenTelemetry GenAI spans, metadata-only, written to a local file.
//!
//! When enabled (`[observability].otel_spans`), each forwarded request emits
//! one span as a single JSON line to `otel_file`. The attributes follow the
//! OpenTelemetry **GenAI semantic conventions** (`gen_ai.*`) so the output
//! interoperates with OTel-aware tooling — but Burnwall never records prompt or
//! completion *content*, only counts, cost, latency, and status.
//!
//! Deliberately a **file sink, not an OTLP network exporter**: shipping spans
//! to a collector would be a network call, which Burnwall does not make beyond
//! forwarding. A user who wants them in a collector can tail the file.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde_json::{json, Value};

use crate::providers::TokenUsage;

/// Map Burnwall's internal provider tag to the OTel GenAI `gen_ai.system`
/// value.
fn gen_ai_system(provider: &str) -> &str {
    match provider {
        "anthropic" => "anthropic",
        "openai" => "openai",
        "google" => "gcp.gemini",
        other => other,
    }
}

/// Build one OTel-GenAI-convention span as JSON. Pure + side-effect-free so it
/// is unit-testable; the writer below serializes whatever this returns.
///
/// `span_id` / `trace_id` are caller-supplied hex strings (random per call).
/// `start_unix_nano` is the span start; `latency_ms` its duration.
#[allow(clippy::too_many_arguments)]
pub fn span_json(
    trace_id: &str,
    span_id: &str,
    provider: &str,
    model: &str,
    usage: &TokenUsage,
    cost_usd: f64,
    latency_ms: i64,
    http_status: i64,
    start_unix_nano: i128,
) -> Value {
    let end_unix_nano = start_unix_nano + (latency_ms.max(0) as i128) * 1_000_000;
    // OTel span status: 2 = Error, 1 = Ok (unset would be 0).
    let status_code = if http_status == 0 || http_status >= 400 {
        2
    } else {
        1
    };
    json!({
        "name": format!("chat {}", model),
        "trace_id": trace_id,
        "span_id": span_id,
        "kind": "SPAN_KIND_CLIENT",
        "start_time_unix_nano": start_unix_nano.to_string(),
        "end_time_unix_nano": end_unix_nano.to_string(),
        "status": { "code": status_code },
        "attributes": {
            "gen_ai.operation.name": "chat",
            "gen_ai.system": gen_ai_system(provider),
            "gen_ai.request.model": model,
            "gen_ai.response.model": model,
            "gen_ai.usage.input_tokens": usage.input_tokens,
            "gen_ai.usage.output_tokens": usage.output_tokens,
            // Cache + cost are Burnwall extensions, namespaced so they don't
            // collide with standard gen_ai.* keys.
            "burnwall.usage.cache_read_tokens": usage.cache_read_tokens,
            "burnwall.usage.cache_creation_tokens": usage.cache_creation_tokens,
            "burnwall.cost_usd": cost_usd,
            "burnwall.latency_ms": latency_ms,
            "http.response.status_code": http_status,
        }
    })
}

/// Append-only JSONL span sink. Cheap to clone-share behind an `Arc`; writes
/// are serialized through a `Mutex` (span volume is low — one per request).
#[derive(Debug)]
pub struct SpanWriter {
    path: PathBuf,
    file: Mutex<File>,
}

impl SpanWriter {
    /// Open (create + append) the span file at `path`, creating parent dirs.
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            path,
            file: Mutex::new(file),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Serialize and append one span as a single line. Best-effort: an I/O
    /// error is swallowed (observability must never break the proxy path).
    pub fn write_span(&self, span: &Value) {
        if let Ok(mut f) = self.file.lock() {
            let line = span.to_string();
            let _ = writeln!(f, "{}", line);
        }
    }

    /// Convenience: build + write a span for a forwarded request.
    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &self,
        provider: &str,
        model: &str,
        usage: &TokenUsage,
        cost_usd: f64,
        latency_ms: i64,
        http_status: i64,
    ) {
        let now_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i128)
            .unwrap_or(0);
        // Span started `latency_ms` ago.
        let start = now_nanos - (latency_ms.max(0) as i128) * 1_000_000;
        let span = span_json(
            &random_hex(32),
            &random_hex(16),
            provider,
            model,
            usage,
            cost_usd,
            latency_ms,
            http_status,
            start,
        );
        self.write_span(&span);
    }
}

/// A random lowercase-hex string of `bytes` bytes (so `2*bytes` chars), using
/// `uuid` (already a dependency) as the entropy source — no new crate.
fn random_hex(bytes: usize) -> String {
    let mut s = String::with_capacity(bytes * 2);
    while s.len() < bytes * 2 {
        let u = uuid::Uuid::new_v4();
        s.push_str(&u.simple().to_string());
    }
    s.truncate(bytes * 2);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn span_has_gen_ai_attributes() {
        let usage = TokenUsage {
            input_tokens: 1000,
            output_tokens: 200,
            cache_creation_tokens: 0,
            cache_read_tokens: 500,
        };
        let span = span_json(
            "trace",
            "span",
            "anthropic",
            "claude-opus-4-7",
            &usage,
            0.05,
            120,
            200,
            1_000,
        );
        let attrs = &span["attributes"];
        assert_eq!(attrs["gen_ai.system"], "anthropic");
        assert_eq!(attrs["gen_ai.request.model"], "claude-opus-4-7");
        assert_eq!(attrs["gen_ai.usage.input_tokens"], 1000);
        assert_eq!(attrs["gen_ai.usage.output_tokens"], 200);
        assert_eq!(attrs["burnwall.usage.cache_read_tokens"], 500);
        assert_eq!(attrs["http.response.status_code"], 200);
        assert_eq!(span["status"]["code"], 1);
        assert_eq!(span["name"], "chat claude-opus-4-7");
        // end = start + 120ms in nanos
        assert_eq!(
            span["end_time_unix_nano"],
            (1_000i128 + 120 * 1_000_000).to_string()
        );
    }

    #[test]
    fn error_status_maps_to_code_2() {
        let usage = TokenUsage::default();
        let span = span_json("t", "s", "openai", "gpt-5.5", &usage, 0.0, 0, 0, 0);
        assert_eq!(span["status"]["code"], 2);
        let span2 = span_json("t", "s", "openai", "gpt-5.5", &usage, 0.0, 10, 500, 0);
        assert_eq!(span2["status"]["code"], 2);
    }

    #[test]
    fn google_maps_to_gcp_gemini() {
        let usage = TokenUsage::default();
        let span = span_json(
            "t",
            "s",
            "google",
            "gemini-2.5-pro",
            &usage,
            0.0,
            10,
            200,
            0,
        );
        assert_eq!(span["attributes"]["gen_ai.system"], "gcp.gemini");
    }

    #[test]
    fn writer_appends_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("spans.jsonl");
        let w = SpanWriter::open(&path).unwrap();
        let usage = TokenUsage {
            input_tokens: 1,
            output_tokens: 1,
            cache_creation_tokens: 0,
            cache_read_tokens: 0,
        };
        w.record("anthropic", "claude-haiku-4-5", &usage, 0.001, 42, 200);
        w.record("openai", "gpt-5.5", &usage, 0.002, 99, 200);
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        let first: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["attributes"]["gen_ai.system"], "anthropic");
        let second: Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second["attributes"]["burnwall.cost_usd"], 0.002);
    }

    #[test]
    fn random_hex_has_expected_length() {
        assert_eq!(random_hex(16).len(), 32);
        assert_eq!(random_hex(32).len(), 64);
        assert_ne!(random_hex(16), random_hex(16));
    }
}
