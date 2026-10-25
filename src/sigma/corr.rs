//! Sigma correlation rules as ElastAlert rule types:
//!
//! | Sigma                | ElastAlert                                                       |
//! |----------------------|------------------------------------------------------------------|
//! | `event_count`        | `frequency` (`gte` / `gt`)                                        |
//! | `value_count`        | `cardinality` (`gte` / `gt`)                                      |
//! | `temporal`           | `correlation`, leaves joined by `AND`                             |
//! | `temporal_ordered`   | `correlation`, leaves joined by `THEN`                            |
//!
//! A leaf of a temporal rule may be an `event_count` correlation of detection rules (a `num_events` leaf). Everything else
//! (`value_sum`, `value_avg`, `value_percentile`, chains deeper than that, `lt`, `lte`, `eq`, `neq`, ranges) is refused.

use super::corpus::{Doc, Kind};
use super::dsl;
use super::{Built, Ctx, KNOWN_KEYS, build};
use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};
use std::sync::Arc;

/// Rule options a correlation sets itself: the rule must not set them too.
const OWN_OPTIONS: &[&str] = &["type", "num_events", "timeframe", "query_key", "correlation_leaves", "correlation_query", "cardinality_field", "max_cardinality"];

pub fn references(doc: &Doc) -> Vec<String> {
    match doc.map.get("correlation").and_then(|c| c.get("rules")) {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).map(String::from).collect(),
        _ => vec![],
    }
}

/// `10m`: a number and one of s, m, h, d.
fn timespan(v: Option<&Value>) -> Result<Value> {
    let Some(Value::String(s)) = v else { bail!("timespan is required, like 10m") };
    let (n, unit) = s.split_at(s.len().saturating_sub(1));
    let n: u64 = n.parse().ok().filter(|n| *n > 0).with_context(|| format!("timespan {s:?} must be a number and a unit: 30s, 10m, 1h, 1d"))?;
    let unit = match unit {
        "s" => "seconds",
        "m" => "minutes",
        "h" => "hours",
        "d" => "days",
        _ => bail!("timespan {s:?} must be a number and a unit: 30s, 10m, 1h, 1d"),
    };
    Ok(json!({ unit: n }))
}

struct Condition {
    /// The threshold of "at least": `gte: N` is N, `gt: N` is N + 1.
    at_least: u64,
    field: Option<String>,
}

fn condition(v: Option<&Value>, what: &str) -> Result<Condition> {
    let Some(Value::Object(m)) = v else { bail!("{what} needs a condition") };
    if let Some(k) = m.keys().find(|k| !["gt", "gte", "lt", "lte", "eq", "neq", "field"].contains(&k.as_str())) {
        bail!("condition: option {k} is not supported");
    }
    let ops: Vec<&String> = m.keys().filter(|k| k.as_str() != "field").collect();
    let [op] = ops.as_slice() else { bail!("condition: exactly one of gte and gt is supported (ranges are not)") };
    let n = m[op.as_str()].as_u64().with_context(|| format!("condition: {op} must be a whole number"))?;
    let at_least = match op.as_str() {
        "gte" => n,
        "gt" => n + 1,
        other => bail!("condition: {other} is not supported, only gte and gt (a rule type here alerts when a count is reached)"),
    };
    let field = match m.get("field") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => bail!("condition: field must be one field name"),
    };
    Ok(Condition { at_least, field })
}

fn strings(v: Option<&Value>, what: &str) -> Result<Vec<String>> {
    match v {
        None | Some(Value::Null) => Ok(vec![]),
        Some(Value::String(s)) => Ok(vec![s.clone()]),
        Some(Value::Array(a)) => a.iter().map(|x| x.as_str().map(String::from).with_context(|| format!("{what} must be field names"))).collect(),
        Some(_) => bail!("{what} must be field names"),
    }
}

/// `aliases`: alias name to `{rule name: field}`.
fn aliases_of<'a>(v: Option<&'a Value>, none: &'a Map<String, Value>) -> Result<&'a Map<String, Value>> {
    let m = match v {
        None | Some(Value::Null) => return Ok(none),
        Some(Value::Object(m)) => m,
        Some(_) => bail!("aliases must be a map of alias to {{rule name: field}}"),
    };
    for (alias, per_rule) in m {
        match per_rule {
            Value::Object(r) if r.values().all(Value::is_string) => {}
            _ => bail!("aliases: {alias} must map rule names to field names"),
        }
    }
    Ok(m)
}

struct Group<'a> {
    by: Vec<String>,
    aliases: &'a Map<String, Value>,
}

impl Group<'_> {
    /// The fields a rule's events carry the `group-by` values in: the alias for that rule, else the name itself, renamed
    /// by the rule's pipelines (without any keyword suffix: the key is read from the documents).
    fn keys(&self, rule: &Doc, built: &Built) -> Result<Vec<String>> {
        self.by
            .iter()
            .map(|g| {
                let base = rule.str("name").and_then(|n| self.aliases.get(g)?.get(n)?.as_str()).unwrap_or(g);
                let mut f = built.pipe.source_fields(base);
                if f.len() != 1 {
                    bail!("group-by {g}: the pipelines map {base} to {} fields, a correlation groups by exactly one", f.len());
                }
                Ok(f.remove(0))
            })
            .collect()
    }
}

/// The detection rules a count correlation counts, with the key fields they group by, all the same.
struct Counted {
    query: Value,
    keys: Vec<String>,
    index: Option<String>,
    /// Value of `field` in the events, same in every rule.
    first_pipe_field: Option<Vec<String>>,
}

fn counted<'a>(refs: &[String], group: &Group, field: Option<&str>, ctx: &Ctx<'a>) -> Result<Counted> {
    let mut queries = Vec::new();
    let mut keys: Option<Vec<String>> = None;
    let mut index: Option<String> = None;
    let mut mapped: Option<Vec<String>> = None;
    for r in refs {
        let (doc, built) = detection(r, ctx)?;
        let k = group.keys(&doc, &built)?;
        if keys.as_ref().is_some_and(|prev| *prev != k) {
            bail!("group-by resolves to different fields in the referenced rules ({} and {}): one count cannot group by both, use a temporal correlation", keys.unwrap_or_default().join(","), k.join(","));
        }
        keys = Some(k);
        if let Some(i) = &built.index {
            if index.as_ref().is_some_and(|prev| prev != i) {
                bail!("the referenced rules ask for different indices ({} and {i})", index.unwrap_or_default());
            }
            index = Some(i.clone());
        }
        if let Some(f) = field {
            let m = built.pipe.source_fields(f);
            if m.len() != 1 || mapped.as_ref().is_some_and(|prev| *prev != m) {
                bail!("field {f}: the pipelines must map it to the same single field for every referenced rule");
            }
            mapped = Some(m);
        }
        queries.push(built.query);
    }
    Ok(Counted { query: dsl::or(queries), keys: keys.unwrap_or_default(), index, first_pipe_field: mapped })
}

fn detection<'a>(reference: &str, ctx: &Ctx<'a>) -> Result<(Arc<Doc>, Built<'a>)> {
    let doc = ctx.scope.lookup(reference).with_context(|| format!("rule {reference:?} is not in this file, sigma_rules or sigma_folders"))?;
    match doc.kind {
        Kind::Detection => {
            let built = build(doc, ctx).with_context(|| format!("rule {}", doc.label()))?;
            Ok((doc.clone(), built))
        }
        Kind::Correlation => bail!("rule {reference:?} is itself a correlation: only an event_count correlation of detection rules can be a leaf of a temporal one"),
        _ => bail!("{reference:?} is not a Sigma detection rule"),
    }
}

/// Leaf names: the reference when it is a valid name (letters, digits, `_`, `-`), else made valid, never a keyword.
fn leaf_name(reference: &str, taken: &[String]) -> String {
    let mut n: String = reference.chars().map(|c| if crate::correlation::is_name_char(c) { c } else { '_' }).collect();
    if n.is_empty() || crate::correlation::KEYWORDS.contains(&n.to_ascii_uppercase().as_str()) {
        n = format!("rule_{n}");
    }
    let mut candidate = n.clone();
    let mut i = 2;
    while taken.contains(&candidate) {
        candidate = format!("{n}_{i}");
        i += 1;
    }
    candidate
}

/// Translates the correlation `doc` into the options of `raw`. Returns the type chosen.
pub fn apply(raw: &mut Map<String, Value>, doc: &Doc, ctx: &Ctx, from_folder: bool) -> Result<()> {
    if let Some(k) = doc.map.keys().find(|k| !KNOWN_KEYS.contains(&k.as_str()) && !["correlation", "generate"].contains(&k.as_str()) || ["detection", "logsource", "fields"].contains(&k.as_str())) {
        bail!("option {k} is not supported in a correlation rule");
    }
    let Some(Value::Object(c)) = doc.map.get("correlation") else { bail!("correlation must be a map") };
    if let Some(k) = c.keys().find(|k| !["type", "rules", "group-by", "timespan", "condition", "aliases", "generate"].contains(&k.as_str())) {
        bail!("correlation: option {k} is not supported");
    }
    if let Some(f) = ctx.scope.filters_for(doc).first() {
        bail!("filter {} names this correlation: a filter applies to detection rules, name the rules the correlation refers to", f.label());
    }
    if let Some(k) = OWN_OPTIONS.iter().find(|k| raw.contains_key(**k)) {
        bail!("{k} comes from the Sigma correlation rule: remove it from the rule");
    }
    let generate = c.get("generate").or_else(|| doc.map.get("generate")).and_then(Value::as_bool).unwrap_or(false);
    if generate && !from_folder {
        bail!("generate: true asks for the referenced rules to run on their own: put them in sigma_folders, or make a rule for each");
    }
    let refs = references(doc);
    if refs.is_empty() {
        bail!("correlation: rules is required");
    }
    let ty = c.get("type").and_then(Value::as_str).context("correlation: type is required")?;
    let timeframe = timespan(c.get("timespan"))?;
    let no_aliases = Map::new();
    let aliases = aliases_of(c.get("aliases"), &no_aliases).context("correlation")?;
    let group = Group { by: strings(c.get("group-by"), "group-by")?, aliases };
    let mut out: Map<String, Value> = Map::new();
    let mut filter_query: Option<Value> = None;
    let mut index: Option<String> = None;

    match ty {
        "event_count" => {
            let cond = condition(c.get("condition"), "event_count")?;
            if cond.field.is_some() {
                bail!("event_count: condition has no field");
            }
            let n = counted(&refs, &group, None, ctx)?;
            out.insert("type".into(), "frequency".into());
            out.insert("num_events".into(), cond.at_least.into());
            set_key(&mut out, &n.keys);
            filter_query = Some(n.query);
            index = n.index;
        }
        "value_count" => {
            let cond = condition(c.get("condition"), "value_count")?;
            let field = cond.field.context("value_count: condition.field is required")?;
            let n = counted(&refs, &group, Some(&field), ctx)?;
            out.insert("type".into(), "cardinality".into());
            out.insert("cardinality_field".into(), n.first_pipe_field.and_then(|f| f.into_iter().next()).unwrap_or(field).into());
            // Alerts above max_cardinality: at least N distinct values is more than N - 1.
            out.insert("max_cardinality".into(), (cond.at_least.saturating_sub(1)).into());
            set_key(&mut out, &n.keys);
            filter_query = Some(n.query);
            index = n.index;
        }
        "temporal" | "temporal_ordered" => {
            if group.by.is_empty() {
                bail!("{ty}: group-by is required");
            }
            if refs.len() < 2 {
                bail!("{ty} needs at least two rules");
            }
            if c.get("condition").is_some() {
                let cond = condition(c.get("condition"), ty)?;
                if cond.at_least != refs.len() as u64 {
                    bail!("{ty}: a condition that is not all {} rules is not supported", refs.len());
                }
            }
            let mut names: Vec<String> = Vec::new();
            let mut leaves: Vec<(String, Value, Vec<String>)> = Vec::new();
            for r in &refs {
                let doc = ctx.scope.lookup(r).with_context(|| format!("rule {r:?} is not in this file, sigma_rules or sigma_folders"))?;
                let (mut leaf, keys) = match doc.kind {
                    Kind::Correlation => inner_leaf(doc, &group, timeframe.clone(), ctx)?,
                    _ => {
                        let (d, built) = detection(r, ctx)?;
                        let keys = group.keys(&d, &built)?;
                        (json!({"filter": [built.query], "num_events": 1, "index": built.index}), keys)
                    }
                };
                let name = leaf_name(r, &names);
                names.push(name.clone());
                if let Some(Value::Null) = leaf.get("index") {
                    leaf.as_object_mut().map(|m| m.remove("index"));
                }
                leaves.push((name, leaf, keys));
            }
            let first = leaves[0].2.clone();
            let same = leaves.iter().all(|(_, _, k)| *k == first);
            if !same && group.by.len() != 1 {
                bail!("{ty}: the rules carry the group-by fields under different names, which a correlation supports for one group-by field only");
            }
            set_key(&mut out, &first);
            let mut leaf_map = Map::new();
            for (name, mut leaf, keys) in leaves {
                if keys != first {
                    leaf["query_key"] = keys[0].clone().into();
                }
                if raw.contains_key("index") {
                    leaf.as_object_mut().map(|m| m.remove("index"));
                } else if index.is_none() {
                    index = leaf.get("index").and_then(Value::as_str).map(String::from);
                }
                leaf_map.insert(name, leaf);
            }
            out.insert("type".into(), "correlation".into());
            out.insert("correlation_leaves".into(), Value::Object(leaf_map));
            out.insert("correlation_query".into(), names.join(if ty == "temporal" { " AND " } else { " THEN " }).into());
        }
        "value_sum" | "value_avg" | "value_percentile" => bail!("correlation type {ty} is not supported"),
        other => bail!("correlation type {other:?} is not a Sigma correlation type"),
    }
    out.insert("timeframe".into(), timeframe);
    for (k, v) in out {
        raw.insert(k, v);
    }
    if let Some(q) = filter_query {
        super::push_filter(raw, q)?;
    }
    if let Some(i) = index {
        raw.entry("index").or_insert_with(|| i.into());
    }
    Ok(())
}

fn set_key(out: &mut Map<String, Value>, keys: &[String]) {
    match keys {
        [] => {}
        [one] => {
            out.insert("query_key".into(), one.clone().into());
        }
        many => {
            out.insert("query_key".into(), many.to_vec().into());
        }
    }
}

/// A temporal leaf that is an `event_count` correlation: `num_events` of its rules, grouped like the outer rule, in the
/// same window (the leaf counts inside the window of the chain, not in a window of its own).
fn inner_leaf(doc: &Arc<Doc>, outer: &Group, outer_timeframe: Value, ctx: &Ctx) -> Result<(Value, Vec<String>)> {
    let Some(Value::Object(c)) = doc.map.get("correlation") else { bail!("correlation must be a map") };
    if c.get("type").and_then(Value::as_str) != Some("event_count") {
        bail!("correlation {}: only an event_count correlation can be a leaf of a temporal one", doc.label());
    }
    if let Some(k) = c.keys().find(|k| !["type", "rules", "group-by", "timespan", "condition", "aliases", "generate"].contains(&k.as_str())) {
        bail!("correlation {}: option {k} is not supported", doc.label());
    }
    if timespan(c.get("timespan"))? != outer_timeframe {
        bail!("correlation {}: its timespan must equal the timespan of the correlation that uses it", doc.label());
    }
    let cond = condition(c.get("condition"), "event_count")?;
    let no_aliases = Map::new();
    let aliases = aliases_of(c.get("aliases"), &no_aliases).with_context(|| format!("correlation {}", doc.label()))?;
    let inner = Group { by: strings(c.get("group-by"), "group-by")?, aliases };
    let refs = references(doc);
    let n = counted(&refs, &inner, None, ctx).with_context(|| format!("correlation {}", doc.label()))?;
    // The outer group-by, read the way the outer rule sees this leaf: through the aliases named for the inner rule.
    let (_, first_built) = detection(&refs[0], ctx)?;
    let outer_keys = outer.keys(doc, &first_built)?;
    if outer_keys != n.keys {
        bail!("correlation {}: it groups by {} but the correlation that uses it by {}", doc.label(), n.keys.join(","), outer_keys.join(","));
    }
    Ok((json!({"filter": [n.query], "num_events": cond.at_least, "index": n.index}), n.keys))
}

#[cfg(test)]
mod tests {
    #[test]
    fn timespans() {
        use super::timespan;
        use serde_json::json;
        assert_eq!(timespan(Some(&json!("10m"))).unwrap(), json!({"minutes": 10}));
        assert_eq!(timespan(Some(&json!("45s"))).unwrap(), json!({"seconds": 45}));
        assert_eq!(timespan(Some(&json!("1d"))).unwrap(), json!({"days": 1}));
        for bad in ["m", "0m", "10", "1w", "-5m", "1.5h"] {
            assert!(timespan(Some(&json!(bad))).is_err(), "{bad}");
        }
        assert!(timespan(None).is_err());
    }

    #[test]
    fn leaf_names_are_valid_and_unique() {
        use super::leaf_name;
        assert_eq!(leaf_name("failed_login", &[]), "failed_login");
        assert_eq!(leaf_name("53ba33fd-3a50", &[]), "53ba33fd-3a50");
        assert_eq!(leaf_name("a b.c", &[]), "a_b_c");
        assert_eq!(leaf_name("not", &[]), "rule_not");
        assert_eq!(leaf_name("x", &["x".into()]), "x_2");
    }
}
