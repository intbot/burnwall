//! Compliance crosswalk (v0.9) — a static, data-only mapping from each Burnwall
//! `event_type` / block reason to the named industry-risk controls it helps
//! evidence.
//!
//! IMPORTANT — this is a *labeling* layer, not new protection. Every control ID
//! below maps an *existing* Burnwall behaviour (a block that already happens, a
//! receipt that is already sealed) onto the vocabulary auditors use. Installing
//! Burnwall does not, by itself, make you compliant with any framework; this
//! crosswalk only helps a reviewer locate which of their named risks a given
//! Burnwall control speaks to. The mappings are deliberately conservative: a
//! control is listed only where the Burnwall behaviour is direct, primary
//! evidence for it, never where the link is aspirational. See
//! [`mappings_for`] / [`coverage_matrix`].
//!
//! Frameworks referenced (by stable identifier):
//! - **OWASP Agentic AI** — the agentic-threat taxonomy (`ASI-T*` threat IDs),
//!   with the related OWASP LLM Top 10 app risk (`LLM*`) where it is the closer
//!   fit.
//! - **OWASP MCP Top 10** — Model Context Protocol top risks (`MCP*`).
//! - **EU AI Act** — logging / record-keeping & deployer obligations, cited by
//!   article (e.g. `EU AI Act Art. 12`).

/// A named framework a Burnwall control can be cross-referenced against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framework {
    /// OWASP Agentic AI threat taxonomy (`ASI-T*`) / OWASP LLM Top 10 (`LLM*`).
    OwaspAgentic,
    /// OWASP Model Context Protocol Top 10 (`MCP*`).
    OwaspMcp,
    /// EU AI Act logging / record-keeping & deployer obligations.
    EuAiAct,
}

impl Framework {
    /// Stable, human-facing framework name (used in tables and JSON).
    pub fn name(self) -> &'static str {
        match self {
            Framework::OwaspAgentic => "OWASP Agentic AI",
            Framework::OwaspMcp => "OWASP MCP Top 10",
            Framework::EuAiAct => "EU AI Act",
        }
    }
}

/// One cross-reference: a single control in a single framework that a Burnwall
/// event_type helps evidence. Data only — no behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlRef {
    pub framework: Framework,
    /// Stable control identifier within the framework (e.g. `"ASI-T04"`,
    /// `"MCP05"`, `"EU AI Act Art. 12"`).
    pub control_id: &'static str,
    /// Short human label for the control.
    pub short_label: &'static str,
}

const fn r(
    framework: Framework,
    control_id: &'static str,
    short_label: &'static str,
) -> ControlRef {
    ControlRef {
        framework,
        control_id,
        short_label,
    }
}

/// The control references that the record-keeping receipt chain itself
/// evidences, independent of any one event type. Every Burnwall action — every
/// forward and every block — is sealed into the tamper-evident chain, which is
/// the primary evidence for AI-system logging obligations. Appended to every
/// event_type's list so a reviewer always sees the logging control alongside
/// the specific guardrail.
const RECORD_KEEPING: &[ControlRef] = &[
    r(
        Framework::EuAiAct,
        "EU AI Act Art. 12",
        "Record-keeping / automatic logging over the system's lifetime",
    ),
    r(
        Framework::EuAiAct,
        "EU AI Act Art. 26(6)",
        "Deployer retention of automatically generated logs",
    ),
];

/// The generic entry for an unrecognised / newly-added event_type. Degrades
/// gracefully: a new block kind that has not yet been cross-walked still maps
/// to the always-true record-keeping controls (the action *is* logged) plus a
/// generic agentic-misbehaviour reference, so callers never get an empty list
/// and never panic. The mapping is honest: it claims only logging coverage +
/// "a guardrail fired", not any specific threat.
const GENERIC: &[ControlRef] = &[r(
    Framework::OwaspAgentic,
    "ASI-T01",
    "Agent behaviour / unexpected action — a guardrail fired",
)];

/// Map a Burnwall `event_type` (security event) or stored block reason to the
/// list of controls it helps evidence. Always returns at least one reference
/// (the record-keeping controls); an unknown type degrades to the generic
/// entry. Order is stable for deterministic output.
pub fn mappings_for(event_type: &str) -> Vec<ControlRef> {
    let specific: &[ControlRef] = match event_type {
        // ── Filesystem / mount reads of sensitive locations ─────────────────
        "path_blocked" | "mount_blocked" => &[
            r(
                Framework::OwaspAgentic,
                "ASI-T05",
                "Unauthorized resource / sensitive-file access by an agent",
            ),
            r(
                Framework::OwaspAgentic,
                "LLM06",
                "Sensitive information disclosure",
            ),
        ],
        // ── Dangerous / destructive shell commands ──────────────────────────
        "command_blocked" | "destructive_blocked" => &[
            r(
                Framework::OwaspAgentic,
                "ASI-T04",
                "Unsafe tool / code execution (agent ran a dangerous command)",
            ),
            r(
                Framework::OwaspAgentic,
                "LLM05",
                "Improper output handling leading to command execution",
            ),
        ],
        // ── Credentials / secrets in the payload ────────────────────────────
        "secret_detected" => &[
            r(
                Framework::OwaspAgentic,
                "ASI-T06",
                "Credential / secret exposure handled by the agent",
            ),
            r(
                Framework::OwaspAgentic,
                "LLM06",
                "Sensitive information disclosure",
            ),
        ],
        // ── Regulated/sensitive data egress (cards, SSNs) ───────────────────
        "dlp_blocked" => &[
            r(
                Framework::OwaspAgentic,
                "LLM06",
                "Sensitive information disclosure (data-loss prevention)",
            ),
            r(
                Framework::EuAiAct,
                "EU AI Act Art. 10",
                "Data governance — handling of sensitive personal data",
            ),
        ],
        // ── Active exfiltration shape (DNS exfil, secret piped to network) ──
        "exfil_blocked" => &[
            r(
                Framework::OwaspAgentic,
                "ASI-T07",
                "Data exfiltration / unexpected outbound channel",
            ),
            r(
                Framework::OwaspAgentic,
                "LLM06",
                "Sensitive information disclosure",
            ),
        ],
        // ── Provider credential sent to the wrong provider's endpoint ───────
        "misdirection_blocked" => &[
            r(
                Framework::OwaspAgentic,
                "ASI-T06",
                "Credential leakage / misdirection across endpoints",
            ),
            r(
                Framework::OwaspAgentic,
                "LLM06",
                "Sensitive information disclosure",
            ),
        ],
        // ── Hidden/invisible-Unicode obfuscation in a tool call ─────────────
        "obfuscation_blocked" => &[
            r(
                Framework::OwaspAgentic,
                "ASI-T02",
                "Prompt/instruction injection via hidden content",
            ),
            r(
                Framework::OwaspAgentic,
                "LLM01",
                "Prompt injection (obfuscated / smuggled instructions)",
            ),
        ],
        // ── Planted canary credential left the machine ──────────────────────
        "canary_triggered" => &[
            r(
                Framework::OwaspAgentic,
                "ASI-T07",
                "Data exfiltration tripwire (planted canary) fired",
            ),
            r(
                Framework::OwaspAgentic,
                "LLM06",
                "Sensitive information disclosure",
            ),
        ],
        // ── Budget / loop / cost-spiral guards (request block reasons) ──────
        "budget_exceeded" | "monthly_budget_exceeded" | "session_budget_exceeded" => &[r(
            Framework::OwaspAgentic,
            "ASI-T08",
            "Resource exhaustion / unbounded consumption — spend cap enforced",
        )],
        "loop_detected" | "cost_spiral" => &[r(
            Framework::OwaspAgentic,
            "ASI-T08",
            "Runaway agent loop / unbounded consumption detected",
        )],
        // ── MCP server / tool governance ────────────────────────────────────
        "mcp_server_not_allowed" => &[
            r(
                Framework::OwaspMcp,
                "MCP01",
                "Unauthorized / unapproved MCP server or tool invocation",
            ),
            r(
                Framework::OwaspAgentic,
                "ASI-T03",
                "Tool / capability misuse (untrusted tool source)",
            ),
        ],
        "mcp_tool_unapproved" => &[
            r(
                Framework::OwaspMcp,
                "MCP01",
                "Unauthorized / unapproved MCP tool invocation",
            ),
            r(
                Framework::OwaspMcp,
                "MCP03",
                "Tool poisoning / rug-pull (advertised tool changed)",
            ),
        ],
        // ── Unknown / future event type → generic, never empty, never panic ─
        _ => GENERIC,
    };

    let mut out: Vec<ControlRef> = specific.to_vec();
    out.extend_from_slice(RECORD_KEEPING);
    out
}

/// Every Burnwall event_type / block reason that has a *specific* (non-generic)
/// crosswalk entry. Drives the full coverage matrix and the
/// every-known-type-maps test. Keep in sync with [`mappings_for`].
pub fn known_event_types() -> &'static [&'static str] {
    &[
        "path_blocked",
        "command_blocked",
        "mount_blocked",
        "secret_detected",
        "dlp_blocked",
        "exfil_blocked",
        "destructive_blocked",
        "obfuscation_blocked",
        "canary_triggered",
        "misdirection_blocked",
        "budget_exceeded",
        "monthly_budget_exceeded",
        "session_budget_exceeded",
        "loop_detected",
        "cost_spiral",
        "mcp_server_not_allowed",
        "mcp_tool_unapproved",
    ]
}

/// One row of the coverage matrix: an event type and every control it evidences.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageRow {
    pub event_type: &'static str,
    pub controls: Vec<ControlRef>,
}

/// The full coverage matrix: every known event type with its mapped controls.
/// This is the machine-readable "which named risks Burnwall covers" sheet.
pub fn coverage_matrix() -> Vec<CoverageRow> {
    known_event_types()
        .iter()
        .map(|&event_type| CoverageRow {
            event_type,
            controls: mappings_for(event_type),
        })
        .collect()
}

// ── Evidence pack: group sealed receipts by compliance regime ──────────────
//
// The crosswalk above maps each *block* to a *threat* control (OWASP / EU AI
// Act articles). The evidence pack is the complementary view auditors ask for:
// it groups the *body of sealed receipts* under the higher-level compliance
// regimes those auditors work in (SOC 2, ISO/IEC 42001, NIST AI RMF, FINRA
// 17a-4), and states — honestly — what the receipt chain does and does not
// evidence for each. The receipts are metadata only; this adds no new data.

use crate::storage::ReceiptRow;

/// A higher-level compliance regime an evidence reviewer works in. Distinct
/// from [`Framework`] (which is the per-threat crosswalk vocabulary).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Regime {
    Soc2,
    Iso42001,
    NistAiRmf,
    Finra17a4,
    EuAiAct,
}

impl Regime {
    pub fn name(self) -> &'static str {
        match self {
            Regime::Soc2 => "SOC 2",
            Regime::Iso42001 => "ISO/IEC 42001",
            Regime::NistAiRmf => "NIST AI RMF",
            Regime::Finra17a4 => "FINRA 17a-4",
            Regime::EuAiAct => "EU AI Act",
        }
    }

    /// The specific obligation within the regime that a tamper-evident,
    /// signed log of every forwarded/blocked AI action helps evidence. Worded
    /// conservatively — the receipt chain is *evidence toward* these, not a
    /// certification of them.
    pub fn obligation(self) -> &'static str {
        match self {
            Regime::Soc2 => {
                "CC7.2 / CC7.3 — monitoring & logging of system activity (security-relevant events captured and retained)"
            }
            Regime::Iso42001 => {
                "A.6 operation & A.8 records — operational logging and retention of AI-system event records"
            }
            Regime::NistAiRmf => {
                "MEASURE 2.x / MANAGE 4.x — measurable, retained records of AI-system behaviour and incidents"
            }
            Regime::Finra17a4 => {
                "17a-4 — durable, tamper-evident retention of business-relevant electronic records (model/version, action, timestamp)"
            }
            Regime::EuAiAct => {
                "Art. 12 & Art. 26(6) — automatic logging over the system lifetime and deployer retention of logs"
            }
        }
    }
}

/// Every regime the evidence pack reports on.
pub fn regimes() -> &'static [Regime] {
    &[
        Regime::Soc2,
        Regime::Iso42001,
        Regime::NistAiRmf,
        Regime::Finra17a4,
        Regime::EuAiAct,
    ]
}

/// One regime's slice of the evidence pack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceGroup {
    pub regime: &'static str,
    pub obligation: &'static str,
    /// Total sealed receipts that stand as evidence for this regime.
    pub receipt_count: usize,
    /// How many of those receipts recorded a block (a guardrail firing) vs a
    /// plain forward — both are evidence of monitoring, blocks additionally
    /// evidence active control.
    pub blocked_receipts: usize,
    pub forwarded_receipts: usize,
    /// The sequence numbers of the receipts (stable references into the chain),
    /// so a reviewer can pull any specific receipt and re-verify it.
    pub receipt_seqs: Vec<i64>,
}

/// Build the framework-grouped evidence bundle from the sealed receipts. Every
/// receipt is evidence of logging for every record-keeping regime (the whole
/// point of the chain), so each regime group references the full receipt set;
/// the blocked/forwarded split tells a reviewer how much of it is *active
/// control* vs *monitoring*. Metadata only — receipts carry no prompt content.
pub fn evidence_pack(receipts: &[ReceiptRow], public_key: Option<&str>) -> EvidencePack {
    let blocked = receipts.iter().filter(|r| r.action == "block").count();
    let forwarded = receipts.len() - blocked;
    let seqs: Vec<i64> = receipts.iter().map(|r| r.seq).collect();

    let groups: Vec<EvidenceGroup> = regimes()
        .iter()
        .map(|&regime| EvidenceGroup {
            regime: regime.name(),
            obligation: regime.obligation(),
            receipt_count: receipts.len(),
            blocked_receipts: blocked,
            forwarded_receipts: forwarded,
            receipt_seqs: seqs.clone(),
        })
        .collect();

    EvidencePack {
        public_key: public_key.map(str::to_string),
        total_receipts: receipts.len(),
        groups,
        note: "Receipts are metadata only (model, action, timestamp, cost) — no \
               prompt content, no API keys. This bundle cross-references existing, \
               tamper-evident records to the obligations auditors cite; it is not a \
               certification or legal attestation. Re-verify any receipt with \
               `burnwall audit verify`."
            .to_string(),
    }
}

/// The full framework-labelled evidence bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidencePack {
    pub public_key: Option<String>,
    pub total_receipts: usize,
    pub groups: Vec<EvidenceGroup>,
    pub note: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_known_event_type_maps_to_at_least_one_control() {
        for &et in known_event_types() {
            let m = mappings_for(et);
            assert!(
                !m.is_empty(),
                "event type {et} mapped to no controls — every type must map to ≥1"
            );
            // The record-keeping controls are always appended, so every type
            // carries the EU AI Act logging reference at minimum.
            assert!(
                m.iter().any(|c| c.framework == Framework::EuAiAct),
                "{et} should always carry the record-keeping (EU AI Act) reference"
            );
        }
    }

    #[test]
    fn unknown_event_type_degrades_to_generic_without_panic() {
        let m = mappings_for("totally_new_block_kind_v99");
        assert!(!m.is_empty(), "unknown type must still map to ≥1 control");
        // Generic agentic reference + record-keeping, nothing claiming a
        // specific threat we can't substantiate.
        assert!(
            m.iter().any(|c| c.control_id == "ASI-T01"),
            "unknown type should carry the generic agentic reference"
        );
        assert!(
            m.iter().any(|c| c.framework == Framework::EuAiAct),
            "unknown type should still carry record-keeping"
        );
        // Honesty guard: an unknown type must NOT claim a specific guardrail
        // (e.g. a credential or exfil control) it cannot substantiate.
        assert!(
            !m.iter().any(|c| c.control_id == "ASI-T07"),
            "unknown type must not over-claim exfiltration coverage"
        );
    }

    #[test]
    fn empty_string_event_type_does_not_panic() {
        let m = mappings_for("");
        assert!(!m.is_empty());
    }

    #[test]
    fn mcp_event_types_map_to_mcp_framework() {
        let m = mappings_for("mcp_server_not_allowed");
        assert!(
            m.iter().any(|c| c.framework == Framework::OwaspMcp),
            "MCP block must reference the OWASP MCP Top 10"
        );
    }

    #[test]
    fn budget_guards_map_to_resource_exhaustion() {
        for et in [
            "budget_exceeded",
            "monthly_budget_exceeded",
            "session_budget_exceeded",
            "loop_detected",
            "cost_spiral",
        ] {
            let m = mappings_for(et);
            assert!(
                m.iter().any(|c| c.control_id == "ASI-T08"),
                "{et} should map to the resource-exhaustion control"
            );
        }
    }

    #[test]
    fn coverage_matrix_covers_every_known_type_with_controls() {
        let matrix = coverage_matrix();
        assert_eq!(matrix.len(), known_event_types().len());
        for row in &matrix {
            assert!(
                !row.controls.is_empty(),
                "{} has no controls in the matrix",
                row.event_type
            );
        }
    }

    #[test]
    fn framework_names_are_stable() {
        assert_eq!(Framework::OwaspAgentic.name(), "OWASP Agentic AI");
        assert_eq!(Framework::OwaspMcp.name(), "OWASP MCP Top 10");
        assert_eq!(Framework::EuAiAct.name(), "EU AI Act");
    }

    fn receipt(seq: i64, action: &str) -> ReceiptRow {
        ReceiptRow {
            seq,
            sealed_at: "2026-06-11T00:00:00Z".into(),
            source: "request".into(),
            source_id: seq,
            timestamp: "2026-06-11T00:00:00Z".into(),
            action: action.into(),
            provider: Some("anthropic".into()),
            model: Some("claude".into()),
            detail: None,
            content_hash: "c".into(),
            prev_hash: "p".into(),
            hash: "h".into(),
            signature: "s".into(),
        }
    }

    #[test]
    fn evidence_pack_groups_by_every_regime() {
        let receipts = vec![
            receipt(1, "forward"),
            receipt(2, "block"),
            receipt(3, "security"),
        ];
        let pack = evidence_pack(&receipts, Some("deadbeef"));
        assert_eq!(pack.total_receipts, 3);
        assert_eq!(pack.public_key.as_deref(), Some("deadbeef"));
        assert_eq!(pack.groups.len(), regimes().len());
        // The named regimes auditors ask for are all present.
        let names: Vec<&str> = pack.groups.iter().map(|g| g.regime).collect();
        for expected in ["SOC 2", "ISO/IEC 42001", "NIST AI RMF", "FINRA 17a-4"] {
            assert!(names.contains(&expected), "missing regime {expected}");
        }
        // Block vs forward split is reported (1 block, 2 non-block here).
        let g = &pack.groups[0];
        assert_eq!(g.blocked_receipts, 1);
        assert_eq!(g.forwarded_receipts, 2);
        assert_eq!(g.receipt_seqs, vec![1, 2, 3]);
    }

    #[test]
    fn evidence_pack_on_empty_receipts_is_honest_and_does_not_panic() {
        let pack = evidence_pack(&[], None);
        assert_eq!(pack.total_receipts, 0);
        assert!(pack.public_key.is_none());
        assert_eq!(pack.groups.len(), regimes().len());
        for g in &pack.groups {
            assert_eq!(g.receipt_count, 0);
            assert!(g.receipt_seqs.is_empty());
        }
        // The honesty note must disclaim certification.
        assert!(pack.note.contains("not a"));
    }
}
