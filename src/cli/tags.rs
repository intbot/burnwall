//! `burnwall tags` — attribute spend by user-set request tags.
//!
//! When a tool sets the opt-in `x-burnwall-tags` header
//! (`feature=auth,agent-run=run42,client=acme,prompt-version=v3`), the proxy
//! records the normalised labels on each forwarded row. This command rolls the
//! window's spend up by tag key → value, so a freelancer/agency can answer
//! "how much did the `acme` client cost?" or "which `feature` is burning the
//! budget?" — locally, from their own data.
//!
//! A request that carries several keys contributes its cost to each key's
//! rollup (each key is an independent slice), so a single key's values sum to
//! the total tagged spend, but totals are not additive *across* keys.

use std::collections::BTreeMap;
use std::io::Write;

use anyhow::Context;
use clap::Args;

use crate::storage::Storage;
use crate::term::{Card, Color, Styler, fill_bar, render_cards};

#[derive(Args, Debug)]
pub struct TagsArgs {
    /// Day window to analyse (default 30). Alias `-n`.
    #[arg(long, short = 'n', default_value_t = 30)]
    pub days: i64,
    /// Show only one tag key's breakdown (e.g. `--key client`).
    #[arg(long)]
    pub key: Option<String>,
    /// Emit JSON instead of the table view.
    #[arg(long)]
    pub json: bool,
}

/// One tag value's rolled-up spend within a key.
struct ValueAgg {
    value: String,
    cost: f64,
    requests: i64,
}

/// The aggregated report: per-key value breakdowns plus window totals.
struct TagReport {
    days: i64,
    total_tagged_cost: f64,
    total_tagged_requests: i64,
    by_key: BTreeMap<String, Vec<ValueAgg>>,
}

/// Pure: roll `(tags_json, cost)` rows up by key → value. Each row's cost is
/// added to every key it carries; malformed JSON or non-string values are
/// skipped (fail-open). Values within a key are sorted by cost, descending.
fn aggregate(days: i64, rows: &[(String, f64)]) -> TagReport {
    let mut acc: BTreeMap<String, BTreeMap<String, (f64, i64)>> = BTreeMap::new();
    let mut total_cost = 0.0;
    let mut total_rows = 0i64;
    for (json, cost) in rows {
        total_cost += *cost;
        total_rows += 1;
        let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(json)
        else {
            continue;
        };
        for (k, v) in map {
            if let Some(val) = v.as_str() {
                let entry = acc.entry(k).or_default().entry(val.to_string()).or_insert((0.0, 0));
                entry.0 += *cost;
                entry.1 += 1;
            }
        }
    }
    let by_key = acc
        .into_iter()
        .map(|(k, values)| {
            let mut v: Vec<ValueAgg> = values
                .into_iter()
                .map(|(value, (cost, requests))| ValueAgg {
                    value,
                    cost,
                    requests,
                })
                .collect();
            v.sort_by(|a, b| {
                b.cost
                    .partial_cmp(&a.cost)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            (k, v)
        })
        .collect();
    TagReport {
        days,
        total_tagged_cost: total_cost,
        total_tagged_requests: total_rows,
        by_key,
    }
}

pub fn run_cmd(args: TagsArgs) -> anyhow::Result<()> {
    let days = args.days.max(1);
    let storage = Storage::open_default().context("opening storage")?;
    let rows = storage.tag_rows_since_days(days)?;
    let report = aggregate(days, &rows);

    let mut out = std::io::stdout().lock();
    if args.json {
        write_json(&mut out, &report, args.key.as_deref())?;
    } else {
        write_table(&mut out, &report, args.key.as_deref())?;
    }
    Ok(())
}

fn write_table(w: &mut impl Write, r: &TagReport, key_filter: Option<&str>) -> std::io::Result<()> {
    let sty = Styler::stdout();
    writeln!(
        w,
        "🔥 {} · Attribution tags · last {} day{}",
        sty.bold("Burnwall"),
        r.days,
        if r.days == 1 { "" } else { "s" }
    )?;
    writeln!(w)?;

    if r.by_key.is_empty() {
        writeln!(
            w,
            "  (no tagged requests in this window)\n\n  Attribute spend by setting the opt-in header on requests, e.g.\n    x-burnwall-tags: feature=auth,agent-run=run42,client=acme,prompt-version=v3"
        )?;
        return Ok(());
    }

    let cards = [
        Card::new(
            "Tagged",
            &format!("${:.2}", r.total_tagged_cost),
            "in window",
        )
        .with_value_color(Color::Green),
        Card::new("Requests", &r.total_tagged_requests.to_string(), "tagged"),
        Card::new("Keys", &r.by_key.len().to_string(), "distinct"),
    ];
    writeln!(w, "{}", render_cards(&cards, 13, 2, &sty))?;
    writeln!(w)?;

    let mut shown = 0;
    for (key, values) in &r.by_key {
        if let Some(f) = key_filter {
            if key != f {
                continue;
            }
        }
        shown += 1;
        let key_total: f64 = values.iter().map(|v| v.cost).sum();
        writeln!(w, "  {} {}", sty.bold("By"), sty.bold(key))?;
        writeln!(
            w,
            "  {:<28}  {:>10}  {:>9}  Share",
            "Value", "Cost", "Requests"
        )?;
        writeln!(w, "  {}", "─".repeat(72))?;
        for v in values {
            let share = if key_total > 0.0 {
                v.cost / key_total * 100.0
            } else {
                0.0
            };
            writeln!(
                w,
                "  {:<28}  ${:>9.2}  {:>9}  {} {:>3.0}%",
                truncate(&v.value, 28),
                v.cost,
                v.requests,
                sty.paint(&fill_bar(share, 8), Color::Cyan),
                share,
            )?;
        }
        writeln!(w)?;
    }
    if let Some(f) = key_filter {
        if shown == 0 {
            writeln!(w, "  (no tag key named {f:?} in this window)")?;
        }
    }
    Ok(())
}

fn write_json(w: &mut impl Write, r: &TagReport, key_filter: Option<&str>) -> std::io::Result<()> {
    use serde_json::json;
    let keys: serde_json::Map<String, serde_json::Value> = r
        .by_key
        .iter()
        .filter(|(k, _)| key_filter.is_none_or(|f| k.as_str() == f))
        .map(|(k, values)| {
            (
                k.clone(),
                json!(values
                    .iter()
                    .map(|v| json!({
                        "value": v.value,
                        "cost_usd": v.cost,
                        "requests": v.requests,
                    }))
                    .collect::<Vec<_>>()),
            )
        })
        .collect();
    let value = json!({
        "days": r.days,
        "total_tagged_cost_usd": r.total_tagged_cost,
        "total_tagged_requests": r.total_tagged_requests,
        "by_key": keys,
    });
    writeln!(w, "{}", serde_json::to_string_pretty(&value).unwrap())
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let head: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{head}…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows() -> Vec<(String, f64)> {
        vec![
            (r#"{"client":"acme","feature":"auth"}"#.to_string(), 1.00),
            (r#"{"client":"acme","feature":"billing"}"#.to_string(), 0.50),
            (r#"{"client":"globex","feature":"auth"}"#.to_string(), 0.25),
            ("not json".to_string(), 9.99), // malformed → skipped for key rollup
        ]
    }

    #[test]
    fn rolls_up_cost_by_key_and_value() {
        let r = aggregate(30, &rows());
        // Total tagged cost counts every row (incl. the malformed-JSON one).
        assert!((r.total_tagged_cost - 11.74).abs() < 1e-9);
        assert_eq!(r.total_tagged_requests, 4);
        // `client` rollup: acme = 1.00 + 0.50 = 1.50, globex = 0.25.
        let client = &r.by_key["client"];
        assert_eq!(client[0].value, "acme");
        assert!((client[0].cost - 1.50).abs() < 1e-9);
        assert_eq!(client[0].requests, 2);
        assert_eq!(client[1].value, "globex");
        // `feature` rollup: auth = 1.00 + 0.25 = 1.25, billing = 0.50.
        let feature = &r.by_key["feature"];
        assert_eq!(feature[0].value, "auth");
        assert!((feature[0].cost - 1.25).abs() < 1e-9);
    }

    #[test]
    fn values_sort_by_cost_desc() {
        let r = aggregate(7, &rows());
        for values in r.by_key.values() {
            for w in values.windows(2) {
                assert!(w[0].cost >= w[1].cost, "values must sort by cost desc");
            }
        }
    }

    #[test]
    fn empty_input_yields_empty_report() {
        let r = aggregate(30, &[]);
        assert!(r.by_key.is_empty());
        assert_eq!(r.total_tagged_requests, 0);
    }
}
