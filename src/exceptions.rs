//! `exceptions`: documents a rule must not see. Each one is a Sigma selection (`match`) or a raw Query DSL query
//! (`query`); together they become one `must_not` in the rule's `filter`, so every rule type counts without them.

use crate::time::{Ts, parse_iso};
use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};

const KEYS: [&str; 5] = ["name", "reason", "expires", "match", "query"];

fn list(raw: &Map<String, Value>) -> Result<Vec<&Map<String, Value>>> {
    match raw.get("exceptions") {
        None | Some(Value::Null) => Ok(vec![]),
        Some(Value::Array(a)) => a.iter().map(|e| e.as_object().context("exceptions entries must be maps")).collect(),
        Some(_) => bail!("exceptions must be a list"),
    }
}

fn expires(e: &Map<String, Value>) -> Result<Option<Ts>> {
    match e.get("expires") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(parse_iso(s).with_context(|| format!("expires {s:?} is not a date (2026-12-31 or 2026-12-31T10:00:00Z)"))?)),
        Some(_) => bail!("expires must be a date"),
    }
}

/// Names of the exceptions that have expired; the file hash includes them so the rule reloads when one does.
pub fn expired(raw: &Map<String, Value>, now: Ts) -> Vec<String> {
    let all = list(raw).unwrap_or_default();
    all.into_iter().filter(|e| expires(e).ok().flatten().is_some_and(|t| t <= now)).filter_map(|e| e["name"].as_str().map(String::from)).collect()
}

/// Adds the `must_not` of the live exceptions to `filter`.
pub fn apply(raw: &Map<String, Value>, filter: &mut Vec<Value>, now: Ts) -> Result<()> {
    let mut names: Vec<&str> = Vec::new();
    let mut queries = Vec::new();
    for e in list(raw)? {
        let name = e.get("name").and_then(Value::as_str).filter(|n| !n.is_empty()).context("exceptions: every entry needs a name")?;
        let here = || format!("exception {name}");
        if let Some(k) = e.keys().find(|k| !KEYS.contains(&k.as_str())) {
            bail!("exception {name}: option {k} is not supported (name, reason, expires, match, query)");
        }
        if names.contains(&name) {
            bail!("exceptions: name {name} is used twice");
        }
        names.push(name);
        let q = match (e.get("match"), e.get("query")) {
            (Some(m), None) => crate::sigma::selection(m).with_context(here)?,
            (None, Some(q)) if q.is_object() => q.clone(),
            (None, Some(_)) => bail!("exception {name}: query must be a Query DSL map"),
            _ => bail!("exception {name}: give either match or query"),
        };
        if expires(e).with_context(here)?.is_some_and(|t| t <= now) {
            log::warn!("exception {name} of rule {} has expired and is ignored", raw.get("name").and_then(Value::as_str).unwrap_or("?"));
            continue;
        }
        queries.push(q);
    }
    if queries.is_empty() {
        return Ok(());
    }
    if filter.iter().any(|f| f.get("eql").is_some() || f.get("esql").is_some()) {
        bail!("exceptions do not work with an eql or esql filter");
    }
    filter.push(json!({"bool": {"must_not": queries}}));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(y: &str, now: &str) -> Result<Vec<Value>> {
        let raw: Map<String, Value> = serde_yaml_ng::from_str(y).unwrap();
        let mut f = vec![json!({"term": {"a": 1}})];
        apply(&raw, &mut f, parse_iso(now).unwrap())?;
        Ok(f)
    }

    #[test]
    fn exceptions() {
        let y = "exceptions:\n- {name: a, reason: x, match: {user.name|startswith: svc_, host.name: [h1, h2]}}\n- {name: b, expires: 2026-12-31, query: {term: {k: v}}}\n";
        let f = run(y, "2026-10-01").unwrap();
        let not = f[1]["bool"]["must_not"].as_array().unwrap();
        assert_eq!((f.len(), not.len()), (2, 2));
        assert_eq!(not[1], json!({"term": {"k": "v"}}));
        assert!(not[0].to_string().contains("svc_"));
        // b expired: only a is left, and the file hash can tell.
        assert_eq!(run(y, "2027-01-01").unwrap()[1]["bool"]["must_not"].as_array().unwrap().len(), 1);
        let raw: Map<String, Value> = serde_yaml_ng::from_str(y).unwrap();
        assert_eq!(expired(&raw, parse_iso("2027-01-01").unwrap()), vec!["b"]);
        assert!(expired(&raw, parse_iso("2026-10-01").unwrap()).is_empty());
        assert_eq!(run("exceptions: []\n", "2026-10-01").unwrap().len(), 1);
        for bad in [
            "exceptions: [{match: {a: 1}}]",
            "exceptions: [{name: a}]",
            "exceptions: [{name: a, match: {a: 1}, query: {}}]",
            "exceptions: [{name: a, match: {a: 1}, ticket: X}]",
            "exceptions: [{name: a, match: {a: 1}}, {name: a, match: {a: 2}}]",
            "exceptions: [{name: a, match: {a: 1}, expires: soon}]",
        ] {
            assert!(run(bad, "2026-10-01").is_err(), "{bad}");
        }
    }
}
