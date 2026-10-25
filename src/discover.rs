//! Kibana and OpenSearch Dashboards Discover links (`generate_kibana_discover_url`,
//! `generate_opensearch_discover_url`). The state is encoded with Rison like upstream's `prison`.

use crate::config::expand_env;
use crate::field::{self, py_str};
use crate::rule::Rule;
use crate::time::{Dur, MINUTE, Ts, parse_duration_map, to_iso};
use crate::types::parse_ts;
use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};

type Doc = Map<String, Value>;

// ---- Rison (python-prison `dumps`) ----

fn rison_id_ok(s: &str) -> bool {
    // Same as prison's ID_OK_RE: letters, digits and `_-./~%+` (and anything above ASCII), not starting with a digit or `-`.
    let idchar = |c: char| c as u32 >= 127 || c.is_ascii_alphanumeric() || "_-./~%+".contains(c);
    let mut chars = s.chars();
    chars.next().is_some_and(|c| idchar(c) && !c.is_ascii_digit() && c != '-') && chars.all(idchar)
}

fn rison_string(s: &str) -> String {
    if s.is_empty() {
        return "''".into();
    }
    if rison_id_ok(s) {
        return s.into();
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' || c == '!' {
            out.push('!');
        }
        out.push(c);
    }
    out.push('\'');
    out
}

pub fn rison(v: &Value) -> String {
    match v {
        Value::Null => "!n".into(),
        Value::Bool(true) => "!t".into(),
        Value::Bool(false) => "!f".into(),
        Value::Number(_) => py_str(v).replace('+', ""),
        Value::String(s) => rison_string(s),
        Value::Array(a) => format!("!({})", a.iter().map(rison).collect::<Vec<_>>().join(",")),
        // serde_json's map is ordered by key, which is what prison does too.
        Value::Object(m) => format!("({})", m.iter().map(|(k, v)| format!("{}:{}", rison_string(k), rison(v))).collect::<Vec<_>>().join(",")),
    }
}

/// `urllib.parse.quote(s)`: everything but letters, digits, `_.-~` and `/` is percent-encoded.
pub fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"_.-~/".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `urllib.parse.quote_plus(s, safe='')`, used by `urlencode`.
pub fn quote_plus(s: &str) -> String {
    quote(s).replace('/', "%2F").replace("%20", "+")
}

/// Python `str()` of a field value: lists and dicts print as their `repr` (`['x']`), which `py_str` leaves as JSON.
fn py_repr(v: &Value) -> String {
    fn repr(v: &Value) -> String {
        match v {
            Value::String(s) => {
                let quote = if s.contains('\'') && !s.contains('"') { '"' } else { '\'' };
                let mut out = String::from(quote);
                for c in s.chars() {
                    match c {
                        '\\' => out.push_str("\\\\"),
                        '\n' => out.push_str("\\n"),
                        '\r' => out.push_str("\\r"),
                        '\t' => out.push_str("\\t"),
                        c if c == quote => {
                            out.push('\\');
                            out.push(c);
                        }
                        c if (c as u32) < 0x20 || c as u32 == 0x7f => out.push_str(&format!("\\x{:02x}", c as u32)),
                        c => out.push(c),
                    }
                }
                out.push(quote);
                out
            }
            Value::Array(a) => format!("[{}]", a.iter().map(repr).collect::<Vec<_>>().join(", ")),
            Value::Object(m) => format!("{{{}}}", m.iter().map(|(k, x)| format!("{}: {}", repr(&Value::String(k.clone())), repr(x))).collect::<Vec<_>>().join(", ")),
            other => py_str(other),
        }
    }
    match v {
        Value::String(s) => s.clone(),
        other => repr(other),
    }
}

/// `json.dumps(v, separators=(',', ':'))`: compact and ASCII only.
fn py_json(v: &Value) -> String {
    let mut out = String::new();
    for c in v.to_string().chars() {
        if (c as u32) < 0x7f {
            out.push(c);
        } else {
            let mut buf = [0u16; 2];
            for unit in c.encode_utf16(&mut buf) {
                out.push_str(&format!("\\u{unit:04x}"));
            }
        }
    }
    out
}

// ---- URLs ----

const DEFAULT_TIMEDELTA: Dur = 10 * MINUTE;

fn rule_str<'a>(rule: &'a Rule, key: &str) -> Option<&'a str> {
    rule.raw.get(key).and_then(Value::as_str).filter(|s| !s.is_empty())
}

fn rule_delta(rule: &Rule, key: &str, default: Dur) -> Dur {
    rule.raw.get(key).and_then(|v| parse_duration_map(v).ok()).unwrap_or(default)
}

/// Checks the `*_discover_*` options of a rule (called at load).
pub fn validate(rule: &Map<String, Value>, prefix: &str) -> Result<()> {
    for k in ["from_timedelta", "to_timedelta"] {
        if let Some(v) = rule.get(&format!("{prefix}_discover_{k}")) {
            parse_duration_map(v).with_context(|| format!("invalid time format for {prefix}_discover_{k}"))?;
        }
    }
    if let Some(v) = rule.get(&format!("{prefix}_discover_columns")) {
        match v.as_array() {
            Some(a) if !a.is_empty() && a.iter().all(|c| c.as_str().is_some_and(|s| !s.is_empty())) => {}
            _ => bail!("{prefix}_discover_columns must be a non-empty list of field names"),
        }
    }
    Ok(())
}

struct Common {
    app_url: String,
    index: String,
    columns: Value,
    filters: Vec<Value>,
    query_keys: Vec<String>,
    from: Ts,
    to: Ts,
}

/// Options shared by both flavours. `None` (with a warning) when the rule lacks the required ones.
fn common(rule: &Rule, m: &Doc, prefix: &str) -> Option<Common> {
    let Some(app_url) = rule_str(rule, &format!("{prefix}_discover_app_url")) else {
        log::warn!("Missing {prefix}_discover_app_url for rule {}", rule.name);
        return None;
    };
    let Some(index) = rule_str(rule, &format!("{prefix}_discover_index_pattern_id")) else {
        log::warn!("Missing {prefix}_discover_index_pattern_id for rule {}", rule.name);
        return None;
    };
    let columns = rule.raw.get(&format!("{prefix}_discover_columns")).cloned().unwrap_or_else(|| json!(["_source"]));
    let query_keys = match (&rule.query_key, rule.compound_query_key.is_empty()) {
        (Some(_), false) => rule.compound_query_key.clone(),
        (Some(q), true) => vec![q.clone()],
        (None, _) => vec![],
    };
    let Some(ts) = field::lookup(m, &rule.timestamp_field).and_then(|v| parse_ts(rule, v)) else {
        log::warn!("Cannot build the {prefix} discover link for rule {}: no usable {} in the match", rule.name, rule.timestamp_field);
        return None;
    };
    let timeframe = rule.timeframe.unwrap_or(DEFAULT_TIMEDELTA);
    let from = ts - rule_delta(rule, &format!("{prefix}_discover_from_timedelta"), timeframe);
    let to = ts + rule_delta(rule, &format!("{prefix}_discover_to_timedelta"), timeframe);
    // Old-style `- query: {...}` filters are unwrapped; the outer key breaks Discover.
    let filters = rule.filter.iter().map(|f| f.get("query").cloned().unwrap_or_else(|| f.clone())).collect();
    Some(Common { app_url: expand_env(app_url), index: index.to_string(), columns, filters, query_keys, from, to })
}

fn global_state(from: Ts, to: Ts) -> String {
    rison(&json!({"filters": [], "refreshInterval": {"pause": true, "value": 0}, "time": {"from": to_iso(from), "to": to_iso(to)}}))
}

fn state_filter(store: &str, extra: Value, meta: Value) -> Value {
    let mut f = json!({"$state": {"store": store}, "meta": meta});
    if let (Some(f), Value::Object(extra)) = (f.as_object_mut(), extra) {
        f.extend(extra);
    }
    f
}

fn missing_filter(index: &str, key: &str, view: bool) -> Value {
    let mut meta = json!({"alias": null, "disabled": false, "index": index, "key": key, "negate": true, "type": "exists", "value": "exists"});
    if view {
        meta["view"] = json!("discover");
    }
    state_filter("appState", json!({"exists": {"field": key}}), meta)
}

fn phrase_filter(index: &str, key: &str, value: &Value) -> Value {
    state_filter(
        "appState",
        json!({"query": {"match": {key: {"query": value, "type": "phrase"}}}}),
        json!({"alias": null, "disabled": false, "index": index, "key": key, "negate": false, "params": {"query": value, "type": "phrase"}, "type": "phrase", "value": py_repr(value)}),
    )
}

/// Single-element lists collapse to the element, empty values to nothing (`_normalize_query_value`).
fn normalize(v: Option<&Value>) -> Option<Value> {
    match v? {
        Value::Null => None,
        Value::String(s) if s.is_empty() => None,
        Value::Array(a) => {
            let cleaned: Vec<&Value> = a.iter().filter(|x| !x.is_null() && x.as_str() != Some("")).collect();
            match cleaned.len() {
                0 => None,
                1 => Some(cleaned[0].clone()),
                _ => Some(Value::Array(cleaned.into_iter().cloned().collect())),
            }
        }
        other => Some(other.clone()),
    }
}

/// The Discover URL as upstream builds it, before the external URL formatter.
pub fn kibana_relative(rule: &Rule, m: &Doc) -> Option<String> {
    let c = common(rule, m, "kibana")?;
    let mut app_filters = Vec::new();
    if !c.filters.is_empty() {
        let bool_filter = json!({"must": c.filters});
        let meta = json!({"alias": "filter", "disabled": false, "index": c.index, "key": "bool", "negate": false, "type": "custom", "value": py_json(&bool_filter)});
        app_filters.push(state_filter("appState", json!({"bool": bool_filter}), meta));
    }
    for key in &c.query_keys {
        app_filters.push(match normalize(field::lookup(m, key)) {
            None => missing_filter(&c.index, key, false),
            Some(v) => phrase_filter(&c.index, key, &v),
        });
    }
    let app_state = rison(&json!({"columns": c.columns, "filters": app_filters, "index": c.index, "interval": "auto"}));
    Some(format!("{}?_g={}&_a={}", c.app_url, quote(&global_state(c.from, c.to)), quote(&app_state)))
}

pub fn opensearch_relative(rule: &Rule, m: &Doc) -> Option<String> {
    let c = common(rule, m, "opensearch")?;
    let app_state = rison(&json!({"discover": {"columns": c.columns, "isDirty": false, "sort": []}, "metadata": {"indexPattern": c.index, "view": "discover"}}));
    let mut app_filters = Vec::new();
    if !c.filters.is_empty() {
        let bool_filter = json!({"bool": {"must": c.filters}});
        let meta = json!({"alias": "filter", "disabled": false, "index": c.index, "key": "query", "negate": false, "type": "custom", "value": py_json(&bool_filter)});
        app_filters.push(state_filter("appState", json!({"query": bool_filter}), meta));
    }
    for key in &c.query_keys {
        app_filters.push(match field::lookup(m, key).filter(|v| !v.is_null()) {
            None => missing_filter(&c.index, key, true),
            Some(v) => phrase_filter(&c.index, key, v),
        });
    }
    // The sort order of the keys puts the lucene query last; the placeholder name only exists to get that order.
    let filter_state = rison(&json!({"filters": app_filters, "tobereplacedbylucenequery": {"language": "lucene", "query": ""}}));
    let url = format!("{}?_g={}&_a={}&_q={}", c.app_url, quote(&global_state(c.from, c.to)), quote(&app_state), quote(&filter_state));
    Some(url.replacen("tobereplacedbylucenequery", "query", 1))
}

// ---- external URL formatters ----

/// `urljoin(base, rel)`; without a base the URL stays relative, like upstream.
fn urljoin(base: Option<&str>, rel: &str) -> Result<String> {
    match base.filter(|b| !b.is_empty()) {
        None => Ok(rel.to_string()),
        Some(b) => Ok(url::Url::parse(b).with_context(|| format!("invalid base URL {b:?}"))?.join(rel).with_context(|| format!("cannot join {rel:?} to {b:?}"))?.to_string()),
    }
}

/// Adds `security_tenant=<tenant>` to the query string (before any fragment).
pub fn append_security_tenant(url: &str, tenant: &str) -> String {
    let (rest, fragment) = match url.split_once('#') {
        Some((a, b)) => (a, Some(b)),
        None => (url, None),
    };
    let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
    let pair = format!("security_tenant={}", quote_plus(tenant));
    let query = if query.is_empty() { pair } else { format!("{query}&{pair}") };
    format!("{path}?{query}{}", fragment.map(|f| format!("#{f}")).unwrap_or_default())
}

/// True when the Kibana version is 7.16 or later, or not given (`is_kibana_atleastsevensixteen`).
pub fn kibana_has_new_shortener(version: &str) -> Result<bool> {
    let v = version.trim();
    if v.is_empty() || v == "0.0" {
        return Ok(true);
    }
    let mut parts = v.split('.').take(2).map(|p| p.parse::<u32>());
    match (parts.next(), parts.next()) {
        (Some(Ok(major)), Some(Ok(minor))) => Ok(major > 7 || (major == 7 && minor >= 16)),
        _ => bail!("invalid kibana_discover_version {version:?}"),
    }
}

/// Load-time checks for the options of `generate_kibana_discover_url`.
pub fn validate_kibana(rule: &Map<String, Value>) -> Result<()> {
    validate(rule, "kibana")?;
    if let Some(v) = rule.get("kibana_discover_version").and_then(Value::as_str) {
        kibana_has_new_shortener(v)?;
    }
    if rule.get("shorten_kibana_discover_url").and_then(Value::as_bool).unwrap_or(false) {
        let basic = rule.get("kibana_username").is_some_and(|v| !v.is_null()) && rule.get("kibana_password").is_some_and(|v| !v.is_null());
        if !basic && (rule.get("aws_region").is_some_and(|v| !v.is_null()) || std::env::var_os("AWS_DEFAULT_REGION").is_some()) {
            bail!("shorten_kibana_discover_url with AWS SigV4 authentication is not supported (use kibana_username and kibana_password)");
        }
    }
    Ok(())
}

fn flag(rule: &Rule, key: &str, default: bool) -> bool {
    rule.raw.get(key).and_then(Value::as_bool).unwrap_or(default)
}

/// Full link for the alert: the Discover URL joined to `kibana_url`, or its short form from Kibana's API.
pub async fn kibana_link(rule: &Rule, m: &Doc) -> Option<String> {
    let relative = kibana_relative(rule, m)?;
    let tenant = rule_str(rule, "kibana_discover_security_tenant");
    let base = rule_str(rule, "kibana_url");
    let result = if flag(rule, "shorten_kibana_discover_url", false) { shorten(rule, base, tenant, &relative).await } else { absolute(base, tenant, &relative) };
    match result {
        Ok(u) => Some(u),
        Err(e) => {
            log::error!("Rule {}: cannot build the Kibana discover link: {e:#}", rule.name);
            None
        }
    }
}

pub fn opensearch_link(rule: &Rule, m: &Doc) -> Option<String> {
    let relative = opensearch_relative(rule, m)?;
    match urljoin(rule_str(rule, "opensearch_url"), &relative) {
        Ok(u) => Some(u),
        Err(e) => {
            log::error!("Rule {}: cannot build the OpenSearch discover link: {e:#}", rule.name);
            None
        }
    }
}

/// `AbsoluteKibanaExternalUrlFormatter`.
fn absolute(base: Option<&str>, tenant: Option<&str>, relative: &str) -> Result<String> {
    urljoin(base, relative).map(|u| with_tenant(u, tenant))
}

fn with_tenant(url: String, tenant: Option<&str>) -> String {
    match tenant {
        Some(t) => append_security_tenant(&url, t),
        None => url,
    }
}

/// `ShortKibanaExternalUrlFormatter`: asks Kibana for a short URL and returns its `goto` link.
async fn shorten(rule: &Rule, base: Option<&str>, tenant: Option<&str>, relative: &str) -> Result<String> {
    let new_shortener = kibana_has_new_shortener(rule_str(rule, "kibana_discover_version").unwrap_or("0.0"))?;
    let api = urljoin(base, if new_shortener { "api/short_url" } else { "api/shorten_url" })?;
    let api = with_tenant(api, tenant);
    let goto = urljoin(base, "goto/")?;
    // Relative to the root of the app.
    let long = if relative.contains("://") { relative.to_string() } else { format!("/{}", relative.trim_start_matches('/')) };
    let long = with_tenant(long, tenant);
    let (body, id_field) = if new_shortener { (json!({"locatorId": "LEGACY_SHORT_URL_LOCATOR", "params": {"url": long}}), "id") } else { (json!({"url": long}), "urlId") };
    let verify = flag(rule, "kibana_verify_certs", true);
    let client = reqwest::Client::builder().danger_accept_invalid_certs(!verify).timeout(std::time::Duration::from_secs(30)).build()?;
    let mut req = client.post(&api).header("kbn-xsrf", "elastalert").header("osd-xsrf", "elastalert").json(&body);
    if let (Some(u), Some(p)) = (rule_str(rule, "kibana_username"), rule_str(rule, "kibana_password")) {
        req = req.basic_auth(u, Some(p));
    }
    let resp = req.send().await.and_then(reqwest::Response::error_for_status).map_err(|e| anyhow::anyhow!("Failed to invoke Kibana Shorten URL API: {e}"))?;
    let reply: Value = resp.json().await.context("Kibana Shorten URL API returned invalid JSON")?;
    let id = reply.get(id_field).and_then(Value::as_str).with_context(|| format!("Kibana Shorten URL API reply has no {id_field}"))?;
    Ok(with_tenant(urljoin(Some(&goto), id)?, tenant))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Expected values come from upstream's `kibana_discover.py`, `opensearch_discover.py` and the external URL
    /// formatters (2.31.0) run on the same inputs (`tests/golden/discover.json`).
    fn golden() -> Value {
        serde_json::from_str(include_str!("../tests/golden/discover.json")).unwrap()
    }

    #[test]
    fn rison_encoding() {
        let v = json!({"b": [1, "x y", null, true, false], "a": "it's!", "": 1.5, "n": {"k-1": "-5"}});
        assert_eq!(rison(&v), "('':1.5,a:'it!'s!!',b:!(1,'x y',!n,!t,!f),n:(k-1:'-5'))");
        assert_eq!(rison(&json!("abc-1")), "abc-1");
        assert_eq!(rison(&json!("2019-09-01T00:20:00Z")), "'2019-09-01T00:20:00Z'");
    }

    #[test]
    fn python_str_of_lists() {
        assert_eq!(py_repr(&json!(["x", "it's", 1, null, {"a": [true]}])), r#"['x', "it's", 1, None, {'a': [True]}]"#);
        assert_eq!(py_repr(&json!("plain")), "plain");
    }

    #[test]
    fn quote_like_python() {
        assert_eq!(quote("(a:'é b')/~_.-"), "%28a%3A%27%C3%A9%20b%27%29/~_.-");
        assert_eq!(quote_plus("a b/c"), "a+b%2Fc");
    }

    #[test]
    fn discover_urls_match_upstream() {
        let dir = std::env::temp_dir().join(format!("ea-discover-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let conf = crate::config::Config::load_with_defaults(&dir.join("none.yaml")).unwrap();
        for case in golden()["cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let mut rule = case["rule"].as_object().unwrap().clone();
            rule.extend([("name".into(), json!(name)), ("type".into(), json!("any")), ("index".into(), json!("i")), ("alert".into(), json!("debug"))]);
            let file = dir.join(format!("{name}.yaml"));
            std::fs::write(&file, Value::Object(rule).to_string()).unwrap();
            let rule = crate::rule::load(&file, &conf).unwrap();
            let m = case["match"].as_object().unwrap();
            assert_eq!(kibana_relative(&rule, m).as_deref(), case["kibana"].as_str(), "kibana {name}");
            assert_eq!(opensearch_relative(&rule, m).as_deref(), case["opensearch"].as_str(), "opensearch {name}");
        }
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn missing_options_give_no_link() {
        let dir = std::env::temp_dir().join(format!("ea-discover-missing-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let conf = crate::config::Config::load_with_defaults(&dir.join("none.yaml")).unwrap();
        let file = dir.join("r.yaml");
        std::fs::write(&file, "name: r\ntype: any\nindex: i\nalert: debug\nkibana_discover_app_url: x\n").unwrap();
        let rule = crate::rule::load(&file, &conf).unwrap();
        let m = json!({"@timestamp": "2019-09-01T00:30:00Z"}).as_object().unwrap().clone();
        assert!(kibana_relative(&rule, &m).is_none());
        assert!(opensearch_relative(&rule, &m).is_none());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn external_urls_match_upstream() {
        for f in golden()["formatters"].as_array().unwrap() {
            let (base, tenant, rel) = (f["base"].as_str(), f["tenant"].as_str(), f["rel"].as_str().unwrap());
            assert_eq!(absolute(base, tenant, rel).unwrap(), f["kibana"].as_str().unwrap(), "kibana {f}");
            assert_eq!(urljoin(base, rel).unwrap(), f["opensearch"].as_str().unwrap(), "opensearch {f}");
        }
        for t in golden()["tenant"].as_array().unwrap() {
            assert_eq!(append_security_tenant(t["url"].as_str().unwrap(), t["tenant"].as_str().unwrap()), t["out"].as_str().unwrap());
        }
    }

    #[test]
    fn kibana_versions() {
        for v in ["", " ", "0.0", "7.16", "8.0", "8.17"] {
            assert!(kibana_has_new_shortener(v).unwrap(), "{v}");
        }
        assert!(!kibana_has_new_shortener("7.15").unwrap());
        assert!(kibana_has_new_shortener("seven").is_err());
    }
}
