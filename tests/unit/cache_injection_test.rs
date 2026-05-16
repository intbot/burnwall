//! Unit tests for the Anthropic `cache_control` auto-injection logic.

use bytes::Bytes;
use serde_json::{json, Value};

use burnwall::proxy::cache_injection::{inject_if_eligible, is_messages_path};

fn body(v: Value) -> Bytes {
    Bytes::from(serde_json::to_vec(&v).unwrap())
}

fn reparse(bytes: &Bytes) -> Value {
    serde_json::from_slice(bytes).unwrap()
}

#[test]
fn string_system_prompt_is_widened_to_a_text_block_with_cache_control() {
    let req = body(json!({
        "model": "claude-sonnet-4-6",
        "system": "You are a helpful assistant.",
        "messages": [{"role": "user", "content": "Hello"}],
    }));

    let out = inject_if_eligible(&req);

    assert!(out.modified, "expected the body to be rewritten");
    let v = reparse(&out.body);
    let sys = v.get("system").unwrap();
    assert!(sys.is_array(), "system should be widened to an array");
    let block = sys.as_array().unwrap().last().unwrap();
    assert_eq!(block.get("type").unwrap(), "text");
    assert_eq!(block.get("text").unwrap(), "You are a helpful assistant.");
    assert_eq!(
        block.get("cache_control").unwrap(),
        &json!({"type": "ephemeral"})
    );
}

#[test]
fn array_system_prompt_gets_marker_on_last_block() {
    let req = body(json!({
        "system": [
            {"type": "text", "text": "Persona."},
            {"type": "text", "text": "Tools and policies."},
        ],
        "messages": [{"role": "user", "content": "Hi"}],
    }));

    let out = inject_if_eligible(&req);

    assert!(out.modified);
    let v = reparse(&out.body);
    let blocks = v.get("system").unwrap().as_array().unwrap();
    assert!(
        blocks[0].get("cache_control").is_none(),
        "first block should NOT be marked"
    );
    assert_eq!(
        blocks[1].get("cache_control").unwrap(),
        &json!({"type": "ephemeral"}),
    );
}

#[test]
fn first_message_content_string_is_widened_and_marked() {
    let req = body(json!({
        "messages": [
            {"role": "user", "content": "Read these docs and answer."},
            {"role": "user", "content": "What's next?"},
        ],
    }));

    let out = inject_if_eligible(&req);

    assert!(out.modified);
    let v = reparse(&out.body);
    let msgs = v.get("messages").unwrap().as_array().unwrap();
    assert!(
        msgs[0].get("content").unwrap().is_array(),
        "first message content should be widened to array",
    );
    let block = msgs[0]
        .get("content")
        .unwrap()
        .as_array()
        .unwrap()
        .last()
        .unwrap();
    assert_eq!(block.get("text").unwrap(), "Read these docs and answer.");
    assert_eq!(
        block.get("cache_control").unwrap(),
        &json!({"type": "ephemeral"})
    );
    // Subsequent messages stay untouched — they may be volatile across turns.
    assert!(msgs[1].get("content").unwrap().is_string());
}

#[test]
fn existing_cache_control_anywhere_disables_injection() {
    let req = body(json!({
        "system": "Long system prompt.",
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "Some context.", "cache_control": {"type": "ephemeral"}},
                ],
            },
        ],
    }));

    let out = inject_if_eligible(&req);

    assert!(!out.modified, "must not override user's existing markers");
    // Body should be byte-identical to the input.
    assert_eq!(out.body.as_ref(), req.as_ref());
}

#[test]
fn marker_on_system_alone_is_sufficient_when_messages_absent() {
    let req = body(json!({
        "system": "Just a system prompt.",
    }));

    let out = inject_if_eligible(&req);

    assert!(out.modified);
    let v = reparse(&out.body);
    let block = v.get("system").unwrap().as_array().unwrap().last().unwrap();
    assert!(block.get("cache_control").is_some());
}

#[test]
fn no_system_and_no_messages_results_in_no_modification() {
    let req = body(json!({
        "model": "claude-sonnet-4-6",
        "max_tokens": 256,
    }));

    let out = inject_if_eligible(&req);

    assert!(!out.modified);
    assert_eq!(out.body.as_ref(), req.as_ref());
}

#[test]
fn invalid_json_body_passes_through_unchanged() {
    let req = Bytes::from_static(b"not json at all");
    let out = inject_if_eligible(&req);
    assert!(!out.modified);
    assert_eq!(out.body.as_ref(), req.as_ref());
}

#[test]
fn empty_messages_array_does_not_mark_anything_in_messages() {
    let req = body(json!({
        "system": "Sys.",
        "messages": [],
    }));

    let out = inject_if_eligible(&req);
    assert!(
        out.modified,
        "system alone should still trigger modification"
    );

    let v = reparse(&out.body);
    assert!(v.get("messages").unwrap().as_array().unwrap().is_empty());
    let sys_block = v.get("system").unwrap().as_array().unwrap().last().unwrap();
    assert!(sys_block.get("cache_control").is_some());
}

#[test]
fn first_message_content_non_string_non_array_is_skipped_gracefully() {
    // Pathological input where `content` is an object — Anthropic's API
    // would reject this, but the injector must not panic or modify it.
    let req = body(json!({
        "messages": [{"role": "user", "content": {"weird": "shape"}}],
    }));

    let out = inject_if_eligible(&req);
    assert!(!out.modified);
    assert_eq!(out.body.as_ref(), req.as_ref());
}

#[test]
fn is_messages_path_recognizes_exact_and_query_suffixed() {
    assert!(is_messages_path("/v1/messages"));
    assert!(is_messages_path("/v1/messages?beta=1"));
    assert!(!is_messages_path("/v1/messages/123"));
    assert!(!is_messages_path("/v1/complete"));
    assert!(!is_messages_path("/"));
    assert!(!is_messages_path(""));
}

#[test]
fn already_marked_array_system_with_unmarked_first_message_is_left_alone() {
    // The user marked system but left messages alone — we don't add more
    // markers on top, because their existing markup is the source of truth.
    let req = body(json!({
        "system": [
            {"type": "text", "text": "Sys.", "cache_control": {"type": "ephemeral"}},
        ],
        "messages": [{"role": "user", "content": "Big stable context here."}],
    }));

    let out = inject_if_eligible(&req);
    assert!(!out.modified);
    assert_eq!(out.body.as_ref(), req.as_ref());
}
