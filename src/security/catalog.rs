//! Rule catalog — the one place that maps a `security_events.event_type` to a
//! stable, greppable rule id and the human-readable "what / why / how to
//! proceed" that turns a block into a self-serve answer.
//!
//! This is the substrate behind the zero-telemetry support surface: we are
//! blind by design (no telemetry, local-only DB), so a block has to explain
//! itself in the moment. `burnwall explain <id>` and `burnwall doctor --export`
//! both read from here, and the same `id` is what a docs anchor (`/rules/<id>`)
//! and a future in-block "fix:" line point at — so the in-the-moment block, the
//! CLI, and the docs all speak the same vocabulary.
//!
//! Metadata only: every field here is a fixed string baked into the binary.
//! Nothing in this module touches a request body, a path, or a secret value.

/// A rule's self-explaining card. All fields are `'static` — there is no
/// per-event data here; the *event's* masked detail is joined in by the caller
/// (`explain`), so this stays free of anything that could carry a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleDoc {
    /// Stable, greppable rule id. Equal to the `security_events.event_type`
    /// string so a block, a log line, and `explain <id>` all share one token.
    pub id: &'static str,
    /// Short human title ("Denied-path access").
    pub title: &'static str,
    /// Why Burnwall blocks this class of action — the threat, in one line.
    pub why: &'static str,
    /// How to proceed when it was a false positive — the concrete next move.
    pub fix: &'static str,
    /// Docs anchor of the form `/rules/<id>` (resolved against the docs site /
    /// `docs/TROUBLESHOOTING.md`). Greppable and stable across releases.
    pub anchor: &'static str,
}

/// Every catalogued rule, in a stable display order (severity-ish, matching
/// `burnwall security --summary`). The fallback for an unknown `event_type`
/// (e.g. a future kind, or a rule-pack-authored one) is [`unknown`].
const RULES: &[RuleDoc] = &[
    RuleDoc {
        id: "canary_triggered",
        title: "Canary tripwire fired",
        why: "A credential you planted as bait (security.canaries) appeared in an outbound payload. \
               It has no legitimate use, so any request carrying it is an exfiltration signal.",
        fix: "This is almost never a false positive. If you deliberately sent the canary, remove it \
              from security.canaries or run the one call with `burnwall allow-once`.",
        anchor: "/rules/canary_triggered",
    },
    RuleDoc {
        id: "destructive_blocked",
        title: "Catastrophic command",
        why: "A tool call carried a data-loss-grade command (recursive force-delete, disk wipe, \
               destructive SQL), detected by shape rather than a literal string.",
        fix: "If you really intend it, narrow the command, or allow the single call with \
              `burnwall allow-once`. Prefer scoping the destructive action to an explicit path.",
        anchor: "/rules/destructive_blocked",
    },
    RuleDoc {
        id: "exfil_blocked",
        title: "Data-exfiltration technique",
        why: "A tool call matched a command-shaped exfiltration pattern (e.g. a secret piped to the \
               network, DNS exfiltration).",
        fix: "If the network call is legitimate, run it outside the agent or use `burnwall allow-once` \
              for the single request. Review what was being sent first.",
        anchor: "/rules/exfil_blocked",
    },
    RuleDoc {
        id: "secret_detected",
        title: "Secret / credential in payload",
        why: "The request body contained something matching a known credential pattern (API key, \
               token, private-key header). Sending it to a model would leak it.",
        fix: "Remove the credential from what the agent is about to send. If it is a false positive \
              (a fake/example key), allow the single call with `burnwall allow-once`.",
        anchor: "/rules/secret_detected",
    },
    RuleDoc {
        id: "dlp_blocked",
        title: "PII / data exfiltration",
        why: "The payload matched a data-loss pattern (card number, SSN). This is egress/DLP \
               protection against sensitive data leaving in a prompt.",
        fix: "Strip the sensitive value, or allow the single call with `burnwall allow-once` if it \
              is test data. Consider whether the value belongs in a prompt at all.",
        anchor: "/rules/dlp_blocked",
    },
    RuleDoc {
        id: "misdirection_blocked",
        title: "Credential sent to the wrong provider",
        why: "A recognized provider credential was being forwarded to a different provider's endpoint \
               (e.g. an OpenAI key in a body bound for the Anthropic upstream).",
        fix: "Point the tool at the correct provider, or disable \
              security.block_credential_misdirection if this routing is intentional.",
        anchor: "/rules/misdirection_blocked",
    },
    RuleDoc {
        id: "obfuscation_blocked",
        title: "Invisible-character obfuscation",
        why: "A tool-call argument was dense with zero-width / invisible Unicode — content being \
               hidden from filters and from your own review (instruction smuggling).",
        fix: "Inspect the source of the tool call; this usually means a poisoned input. Only \
              `allow-once` if you understand why the hidden characters are there.",
        anchor: "/rules/obfuscation_blocked",
    },
    RuleDoc {
        id: "command_blocked",
        title: "Dangerous command",
        why: "A tool call tried to run a command on the deny list (e.g. chmod 777, a fork bomb, \
               curl to an unknown host).",
        fix: "Adjust the command, relax the rule in config if it is a legitimate workflow, or \
              `burnwall allow-once` for the single call.",
        anchor: "/rules/command_blocked",
    },
    RuleDoc {
        id: "path_blocked",
        title: "Denied-path access",
        why: "A tool call referenced a protected path (~/.ssh, ~/.aws, /etc/passwd, …). Reading or \
               writing it from an agent is how credentials and keys leak.",
        fix: "If the access is intended and safe, allow the single call with `burnwall allow-once`, \
              or remove the path from the deny list in config.",
        anchor: "/rules/path_blocked",
    },
    RuleDoc {
        id: "mount_blocked",
        title: "Network-mount access",
        why: "A tool call touched a network mount (/Volumes/, an SMB/NFS share). Agent access to \
               network storage is a common data-egress path.",
        fix: "Copy what you need locally, or allow the single call with `burnwall allow-once` if the \
              mount access is deliberate.",
        anchor: "/rules/mount_blocked",
    },
];

/// The card shown for an `event_type` Burnwall doesn't have a specific entry
/// for (a future kind, or a rule-pack-authored rule). Keeps `explain` total.
const UNKNOWN: RuleDoc = RuleDoc {
    id: "unknown",
    title: "Security block",
    why: "A security rule matched this request before it was forwarded.",
    fix: "Run `burnwall security --days 7` to see recent blocks, or `burnwall allow-once` to let the \
          next request through unchecked.",
    anchor: "/rules",
};

/// Event types that are **advisory**: the request flowed (or the finding is
/// about a response / an observation), nothing was stopped. Everything else —
/// the catalog rules, paranoid-mode fail-closed, MCP enforcement denials, and
/// unknown pack-authored rules (packs are deny rules) — is an **enforcement**
/// block.
///
/// This partition exists so surfaces never count an informational alert as a
/// "block": a status claiming "156 blocked" when 153 were slow-drip *alerts*
/// overstates the firewall's interventions and erodes the trust the number is
/// there to build. Keep in sync with every `insert_security_event` call site —
/// `advisory_set_matches_the_alert_only_writers` pins the list.
const ADVISORY: &[&str] = &[
    "slow_drip_alert",        // proxy: low-and-slow exfil monitor (ALERT-ONLY)
    "billing_flip",           // proxy: subscription→metered watchdog (ALERT-ONLY)
    "response_exfil_warning", // response path: data-carrying URL warning (warn only)
    "mcp_tool_poisoning",     // mcp: poisoned description, response still forwarded
    "mcp_tool_changed",       // mcp: definition drift, advisory (approval may re-pend)
];

/// True if `event_type` records an advisory finding rather than a blocked
/// request. Unknown types count as enforcement: the only runtime-extensible
/// rule source is rule packs, and pack rules block.
pub fn is_advisory(event_type: &str) -> bool {
    ADVISORY.contains(&event_type)
}

/// Look up the catalog card for a `security_events.event_type`. Always returns
/// a card — unknown / pack-authored types fall back to [`UNKNOWN`].
pub fn lookup(event_type: &str) -> RuleDoc {
    RULES
        .iter()
        .copied()
        .find(|r| r.id == event_type)
        .unwrap_or(UNKNOWN)
}

/// All catalogued rules in display order — for docs generation and tests.
pub fn all() -> &'static [RuleDoc] {
    RULES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_known_event_type_has_a_card() {
        // The canonical event_type set from `ViolationKind::event_type`. If a
        // new kind is added there, this test fails until it gets a catalog card.
        for et in [
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
        ] {
            let card = lookup(et);
            assert_eq!(card.id, et, "card id must equal its event_type");
            assert!(!card.title.is_empty());
            assert!(!card.why.is_empty());
            assert!(!card.fix.is_empty());
            assert_eq!(card.anchor, format!("/rules/{et}"));
        }
    }

    #[test]
    fn unknown_type_falls_back_without_panicking() {
        let card = lookup("some_future_kind");
        assert_eq!(card.id, "unknown");
        assert_eq!(card.anchor, "/rules");
    }

    #[test]
    fn ids_are_unique_and_match_anchor() {
        let mut ids: Vec<&str> = all().iter().map(|r| r.id).collect();
        let n = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), n, "rule ids must be unique");
        for r in all() {
            assert_eq!(r.anchor, format!("/rules/{}", r.id));
        }
    }

    #[test]
    fn advisory_set_matches_the_alert_only_writers() {
        // Ground truth: every event_type the codebase writes via
        // insert_security_event, partitioned by whether the write site blocks
        // the request (403/429 + never forwards) or only records a finding.
        // Adding a new event_type means adding it to exactly one list here AND
        // (if advisory) to ADVISORY — this test is the drift guard.
        let blocking = [
            // ViolationKind::event_type — each accompanies a 403 block.
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
            // Paranoid fail-closed: blocked + RequestRecord::blocked.
            "paranoid_unscannable",
            // MCP enforcement denials (403, never forwarded).
            "mcp_tool_unapproved",
            "mcp_server_not_allowed",
        ];
        let advisory = [
            "slow_drip_alert",
            "billing_flip",
            "response_exfil_warning",
            "mcp_tool_poisoning",
            "mcp_tool_changed",
        ];
        for et in blocking {
            assert!(!is_advisory(et), "{et} blocks; must not classify advisory");
        }
        for et in advisory {
            assert!(is_advisory(et), "{et} is alert-only; must classify advisory");
        }
        // Unknown / pack-authored types are enforcement by default.
        assert!(!is_advisory("pack_authored_future_rule"));
    }

    #[test]
    fn docs_rules_md_covers_every_rule() {
        // docs/RULES.md is the public face of this catalog; the `/rules/<id>`
        // anchors only resolve if each id has a `## <id>` heading there. Guard
        // against drift: a new rule must get a docs section in the same change.
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/docs/RULES.md");
        let doc = std::fs::read_to_string(path)
            .expect("docs/RULES.md must exist (it backs the /rules/<id> anchors)");
        for r in all() {
            assert!(
                doc.contains(&format!("## {}", r.id)),
                "docs/RULES.md is missing a `## {}` section for rule `{}`",
                r.id,
                r.id
            );
        }
    }
}
