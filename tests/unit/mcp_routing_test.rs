//! Unit tests for `burnwall::mcp::resolve_route` — the pure path → upstream
//! routing used by multi-server `mcp-watch` (v0.6.5). No I/O.

use burnwall::mcp::{resolve_route, McpServer, Route};

fn servers() -> Vec<McpServer> {
    vec![
        McpServer {
            name: "github".into(),
            upstream: "http://localhost:8080".into(),
        },
        McpServer {
            name: "filesystem".into(),
            upstream: "http://localhost:8090".into(),
        },
    ]
}

#[test]
fn named_prefix_routes_and_strips_prefix() {
    let r = resolve_route(&servers(), None, "/github/mcp").unwrap();
    assert_eq!(
        r,
        Route {
            server: "github".into(),
            upstream: "http://localhost:8080".into(),
            forward_path: "/mcp".into(),
        }
    );
}

#[test]
fn deep_path_under_named_server_is_preserved() {
    let r = resolve_route(&servers(), None, "/filesystem/rpc/v1").unwrap();
    assert_eq!(r.server, "filesystem");
    assert_eq!(r.upstream, "http://localhost:8090");
    assert_eq!(r.forward_path, "/rpc/v1");
}

#[test]
fn exact_name_match_forwards_root() {
    let r = resolve_route(&servers(), None, "/github").unwrap();
    assert_eq!(r.server, "github");
    assert_eq!(r.forward_path, "/");
}

#[test]
fn partial_token_does_not_falsely_match() {
    // `/githubfoo` must NOT match the `github` server.
    let r = resolve_route(&servers(), Some("http://fallback:9000"), "/githubfoo");
    let r = r.unwrap();
    assert_eq!(
        r.server, "default",
        "should fall through to the default route"
    );
    assert_eq!(r.forward_path, "/githubfoo");
}

#[test]
fn unmatched_path_falls_back_to_default_upstream() {
    let r = resolve_route(&servers(), Some("http://fallback:9000"), "/something/else").unwrap();
    assert_eq!(r.server, "default");
    assert_eq!(r.upstream, "http://fallback:9000");
    assert_eq!(r.forward_path, "/something/else");
}

#[test]
fn unmatched_path_with_no_default_is_none() {
    assert!(resolve_route(&servers(), None, "/unknown").is_none());
}

#[test]
fn empty_servers_with_default_routes_everything_to_default() {
    let r = resolve_route(&[], Some("http://up:1234"), "/messages").unwrap();
    assert_eq!(r.server, "default");
    assert_eq!(r.upstream, "http://up:1234");
    assert_eq!(r.forward_path, "/messages");
}

#[test]
fn root_path_falls_back_to_default() {
    let r = resolve_route(&servers(), Some("http://up:1234"), "/").unwrap();
    assert_eq!(r.server, "default");
    assert_eq!(r.forward_path, "/");
}

#[test]
fn first_matching_server_wins() {
    // Order matters: the first configured server whose prefix matches is used.
    let s = vec![
        McpServer {
            name: "a".into(),
            upstream: "http://a".into(),
        },
        McpServer {
            name: "a".into(),
            upstream: "http://a2".into(),
        },
    ];
    let r = resolve_route(&s, None, "/a/x").unwrap();
    assert_eq!(r.upstream, "http://a");
}
