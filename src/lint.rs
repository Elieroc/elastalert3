//! `validate --es`: checks the fields and filters of each rule against the mappings of its indices, and asks
//! Elasticsearch whether the filters parse. Findings are warnings: a field can be mapped later by a new document.

use crate::engine::unwrap_query;
use crate::es::Es;
use crate::index;
use crate::rule::{Rule, TsType};
use crate::time::{SECOND, now};
use rustc_hash::FxHashMap;
use serde_json::{Value, json};

struct FieldType {
    kind: String,
    aggregatable: bool,
}

/// Field name -> its types (several when the indices disagree), from `_field_caps`.
#[derive(Default)]
pub struct Caps(FxHashMap<String, Vec<FieldType>>);

impl Caps {
    fn parse(resp: &Value) -> Caps {
        let mut map = FxHashMap::default();
        for (name, types) in resp["fields"].as_object().into_iter().flatten() {
            let list = types
                .as_object()
                .into_iter()
                .flatten()
                .map(|(kind, c)| FieldType { kind: kind.clone(), aggregatable: c["aggregatable"].as_bool().unwrap_or(false) })
                .collect();
            map.insert(name.clone(), list);
        }
        Caps(map)
    }

    fn get(&self, field: &str) -> Option<&Vec<FieldType>> {
        self.0.get(field)
    }

    /// An object field has no type of its own, only its sub-fields do.
    fn exists(&self, field: &str) -> bool {
        self.0.contains_key(field) || self.0.keys().any(|k| k.strip_prefix(field).is_some_and(|rest| rest.starts_with('.')))
    }
}

/// A field a filter reads, with the query that reads it.
#[derive(Debug, PartialEq)]
struct Use {
    query: &'static str,
    field: String,
    value: Option<String>,
}

const FIELD_QUERIES: [&str; 9] = ["term", "terms", "match", "match_phrase", "match_phrase_prefix", "prefix", "wildcard", "regexp", "range"];

/// The fields read by the structured queries of a filter (`query_string` and the like are not looked into).
fn filter_uses(q: &Value, out: &mut Vec<Use>) {
    match q {
        Value::Object(m) => {
            for (key, v) in m {
                if let Some(query) = FIELD_QUERIES.iter().find(|k| *k == key)
                    && let Value::Object(fields) = v
                {
                    for (field, spec) in fields.iter().filter(|(f, _)| !f.starts_with('_') && f.as_str() != "boost") {
                        let value = match spec {
                            Value::String(s) => Some(s.clone()),
                            Value::Object(o) => o.get("value").and_then(Value::as_str).map(String::from),
                            _ => None,
                        };
                        out.push(Use { query, field: field.clone(), value });
                    }
                } else if key == "exists" {
                    if let Some(f) = v.get("field").and_then(Value::as_str) {
                        out.push(Use { query: "exists", field: f.into(), value: None });
                    }
                } else {
                    filter_uses(v, out);
                }
            }
        }
        Value::Array(a) => a.iter().for_each(|v| filter_uses(v, out)),
        _ => {}
    }
}

fn kinds(types: &[FieldType]) -> String {
    types.iter().map(|t| t.kind.as_str()).collect::<Vec<_>>().join("/")
}

fn keyword_hint(caps: &Caps, field: &str) -> String {
    if caps.get(&format!("{field}.keyword")).is_some() { format!(" (use {field}.keyword)") } else { String::new() }
}

/// What looks wrong with the fields of `rule` given the mappings.
fn check(rule: &Rule, caps: &Caps) -> Vec<String> {
    if caps.0.is_empty() {
        return vec![format!("index {} matches no mapped field: the index does not exist yet, or is empty", rule.index)];
    }
    let mut out = Vec::new();
    let mut dates = vec![];
    match &rule.ingest_field {
        Some(f) => dates.push(f.as_str()),
        None if rule.timestamp_type == TsType::Iso => dates.push(rule.timestamp_field.as_str()),
        None => {}
    }
    for f in dates {
        match caps.get(f) {
            None => out.push(format!("timestamp field {f} is not in the mapping")),
            Some(t) if !t.iter().any(|t| t.kind == "date" || t.kind == "date_nanos") => out.push(format!("timestamp field {f} is {}, not a date", kinds(t))),
            Some(_) => {}
        }
    }
    let mut uses = Vec::new();
    rule.filter.iter().for_each(|f| filter_uses(f, &mut uses));
    for leaf in rule.correlation.iter().flat_map(|c| &c.leaves) {
        leaf.filter.iter().for_each(|f| filter_uses(f, &mut uses));
    }
    for u in &uses {
        if u.field.contains('*') {
            continue;
        }
        let Some(types) = caps.get(&u.field) else {
            if !caps.exists(&u.field) {
                out.push(format!("filter: {} on {}, which is not in the mapping", u.query, u.field));
            }
            continue;
        };
        if matches!(u.query, "term" | "terms" | "prefix") && types.iter().all(|t| t.kind == "text") {
            out.push(format!("filter: {} on {}, a text field: the value is compared with analyzed tokens{}", u.query, u.field, keyword_hint(caps, &u.field)));
        }
        if u.query == "wildcard" && u.value.as_deref().is_some_and(|v| v.starts_with(['*', '?'])) && types.iter().any(|t| t.kind != "wildcard") {
            out.push(format!("filter: wildcard on {} starts with a wildcard, which reads every term of the field", u.field));
        }
    }
    let mut agg: Vec<&str> = rule.top_count_keys.iter().map(String::as_str).collect();
    if rule.use_terms_query || rule.kind.is_agg_query() || rule.kind == crate::rule::Kind::Baseline {
        agg.extend(rule.query_key.iter().flat_map(|k| k.split(',')));
    }
    if rule.kind == crate::rule::Kind::Outlier {
        agg.extend(rule.raw.get("peer_field").and_then(Value::as_str));
    }
    for f in agg {
        match caps.get(f) {
            None => out.push(format!("{f} is aggregated but not in the mapping")),
            Some(t) if !t.iter().all(|t| t.aggregatable) => out.push(format!("{f} is aggregated but is {} and cannot be{}", kinds(t), keyword_hint(caps, f))),
            Some(_) => {}
        }
    }
    out
}

/// Asks Elasticsearch to parse each filter of the rule (and of each correlation leaf) on its own: a clause on an
/// unmapped field rewrites the whole `bool` to `match_none` before the other clauses are parsed.
async fn parse_errors(es: &Es, rule: &Rule, index: &str) -> Vec<String> {
    if rule.query_lang.is_some() {
        return vec![];
    }
    let mut filters: Vec<(String, &Value)> = rule.filter.iter().map(|f| (String::new(), f)).collect();
    for leaf in rule.correlation.iter().flat_map(|c| &c.leaves) {
        filters.extend(leaf.filter.iter().map(|f| (format!("leaf {}: ", leaf.name), f)));
    }
    let mut out = Vec::new();
    for (label, f) in filters {
        let body = json!({"query": unwrap_query(f)});
        match es.post(&format!("{index}/_validate/query?explain=true&allow_no_indices=true&ignore_unavailable=true"), &body).await {
            Ok(resp) if resp["valid"] == json!(false) => {
                let why = resp["explanations"].as_array().into_iter().flatten().find_map(|e| e["error"].as_str()).unwrap_or("invalid query");
                out.push(format!("{label}Elasticsearch cannot parse the filter {f}: {}", why.lines().next().unwrap_or(why)));
            }
            Ok(_) => {}
            Err(e) => out.push(format!("{label}could not validate the filter {f}: {e:#}")),
        }
    }
    out
}

/// Prints the findings of every rule; returns how many there are.
pub async fn check_rules(es: &Es, rules: &[Rule]) -> usize {
    let mut caps: FxHashMap<String, Option<Caps>> = FxHashMap::default();
    let mut total = 0;
    for rule in rules {
        let now = now();
        let index = if rule.use_strftime_index { index::format_index(&rule.index, now - 86_400 * SECOND, now, rule.search_extra_index).unwrap_or_else(|_| rule.index.clone()) } else { rule.index.clone() };
        if !caps.contains_key(&index) {
            let found = match es.get(&format!("{index}/_field_caps?fields=*&ignore_unavailable=true&allow_no_indices=true")).await {
                Ok(resp) => Some(Caps::parse(&resp)),
                Err(e) => {
                    println!("{}: cannot read the mappings of {index}: {e:#}", rule.file.display());
                    None
                }
            };
            caps.insert(index.clone(), found);
        }
        let Some(Some(c)) = caps.get(&index) else { continue };
        let mut findings = check(rule, c);
        findings.extend(parse_errors(es, rule, &index).await);
        total += findings.len();
        for f in findings {
            println!("{}: warning: {f}", rule.file.display());
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(extra: &str) -> Rule {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!("ea-lint-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("r.yaml");
        std::fs::write(&file, format!("name: lint\ntype: frequency\nnum_events: 3\ntimeframe: {{minutes: 5}}\nindex: logs-*\nalert: debug\n{extra}")).unwrap();
        let conf = crate::config::Config::load_with_defaults(&dir.join("none.yaml")).unwrap();
        let r = crate::rule::load(&file, &conf).unwrap();
        std::fs::remove_dir_all(dir).ok();
        r
    }

    fn caps(json: Value) -> Caps {
        Caps::parse(&json!({"fields": json}))
    }

    fn field(kind: &str, aggregatable: bool) -> Value {
        json!({kind: {"type": kind, "searchable": true, "aggregatable": aggregatable}})
    }

    #[test]
    fn filters_are_walked_through_bool_and_old_style_wrappers() {
        let mut uses = Vec::new();
        filter_uses(
            &json!({"bool": {"must": [{"term": {"a": "x"}}], "must_not": {"wildcard": {"b": {"value": "*z", "boost": 2}}}, "filter": [{"exists": {"field": "c"}}, {"range": {"d": {"gte": 1}}}]}}),
            &mut uses,
        );
        let mut got: Vec<_> = uses.iter().map(|u| (u.query, u.field.as_str(), u.value.as_deref())).collect();
        got.sort();
        assert_eq!(got, [("exists", "c", None), ("range", "d", None), ("term", "a", Some("x")), ("wildcard", "b", Some("*z"))]);
    }

    #[test]
    fn mapping_problems_are_reported() {
        let c = caps(json!({
            "@timestamp": field("keyword", true),
            "msg": field("text", false),
            "msg.keyword": field("keyword", true),
            "user.name": field("keyword", true),
        }));
        let r = rule("filter:\n- term: {msg: hello}\n- term: {nope: 1}\n- wildcard: {user.name: '*adm*'}\n- exists: {field: user}\nuse_terms_query: true\nquery_key: msg\n");
        let found = check(&r, &c);
        assert!(found.iter().any(|f| f.contains("timestamp field @timestamp is keyword, not a date")), "{found:?}");
        assert!(found.iter().any(|f| f.contains("term on msg, a text field") && f.contains("msg.keyword")), "{found:?}");
        assert!(found.iter().any(|f| f.contains("term on nope, which is not in the mapping")), "{found:?}");
        assert!(found.iter().any(|f| f.contains("wildcard on user.name starts with a wildcard")), "{found:?}");
        assert!(found.iter().any(|f| f.contains("msg is aggregated but is text and cannot be (use msg.keyword)")), "{found:?}");
        assert!(!found.iter().any(|f| f.contains("exists on user")), "an object field exists through its sub-fields: {found:?}");
    }

    #[test]
    fn empty_mapping_means_no_index() {
        let r = rule("");
        assert_eq!(check(&r, &Caps::default()).len(), 1);
    }
}
