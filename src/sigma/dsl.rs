//! Sigma detection items into Elasticsearch Query DSL. Structured queries only (`term`, `wildcard`, `regexp`, `range`),
//! never `query_string`, so no value needs Lucene escaping. Sigma matches case-insensitively unless `cased`, which needs
//! `case_insensitive` support (Elasticsearch 7.10+, OpenSearch 2.x) and fields mapped as `keyword`.

use super::condition::Cond;
use super::modifiers::{self, Enc, Mods, Op, Part};
use super::pipeline::Resolved;
use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};

pub struct Env<'a> {
    /// Fields for keyword searches, used as written (no pipeline mapping).
    pub keyword_fields: &'a [String],
    pub pipe: &'a Resolved<'a>,
}

pub fn and(mut items: Vec<Value>) -> Value {
    if items.len() == 1 { items.remove(0) } else { json!({"bool": {"filter": items}}) }
}

pub fn or(mut items: Vec<Value>) -> Value {
    if items.len() == 1 { items.remove(0) } else { json!({"bool": {"should": items, "minimum_should_match": 1}}) }
}

pub fn not(item: Value) -> Value {
    json!({"bool": {"must_not": [item]}})
}

fn exists(field: &str) -> Value {
    json!({"exists": {"field": field}})
}

/// The whole detection as one query: each named search compiled, then combined by the condition(s). Several
/// conditions are alternatives.
pub fn detection(det: &Map<String, Value>, env: &Env) -> Result<Value> {
    if det.contains_key("timeframe") {
        bail!("detection: timeframe belongs to aggregation conditions, which are not supported");
    }
    let conds: Vec<&Value> = match det.get("condition") {
        Some(Value::Array(a)) => a.iter().collect(),
        Some(v) => vec![v],
        None => bail!("detection: missing condition"),
    };
    let mut searches: Vec<(String, Value)> = Vec::new();
    for (name, def) in det.iter().filter(|(k, _)| k.as_str() != "condition") {
        searches.push((name.clone(), search(def, env).with_context(|| format!("detection {name}"))?));
    }
    if searches.is_empty() {
        bail!("detection: no search besides condition");
    }
    let names: Vec<String> = searches.iter().map(|(n, _)| n.clone()).collect();
    let mut alternatives = Vec::new();
    for c in conds {
        let Some(src) = c.as_str() else { bail!("detection: condition must be a string or a list of strings") };
        alternatives.push(build(&super::condition::parse(src, &names)?, &searches));
    }
    Ok(or(alternatives))
}

fn build(c: &Cond, searches: &[(String, Value)]) -> Value {
    match c {
        Cond::Sel(n) => searches.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone()).unwrap_or(Value::Null),
        Cond::And(items) => and(items.iter().map(|i| build(i, searches)).collect()),
        Cond::Or(items) => or(items.iter().map(|i| build(i, searches)).collect()),
        Cond::Not(inner) => not(build(inner, searches)),
    }
}

/// A named search: a map (AND of its fields), a list of maps (OR), or keywords (OR over `sigma_keyword_fields`).
fn search(def: &Value, env: &Env) -> Result<Value> {
    match def {
        Value::Object(m) => {
            if m.is_empty() {
                bail!("empty search");
            }
            let mut items = Vec::new();
            for (key, val) in m {
                let (field, mods) = modifiers::parse_key(key)?;
                let list = scalars(val).with_context(|| key.clone())?;
                if field.is_empty() {
                    items.push(keywords(&list, &mods, env).with_context(|| key.clone())?);
                    continue;
                }
                let per_field: Vec<Value> = env.pipe.fields(field).iter().map(|f| values(f, &mods, &list)).collect::<Result<_>>().with_context(|| key.clone())?;
                items.push(or(per_field));
            }
            Ok(and(items))
        }
        Value::Array(a) if !a.is_empty() && a.iter().all(Value::is_object) => Ok(or(a.iter().map(|d| search(d, env)).collect::<Result<_>>()?)),
        Value::Array(_) | Value::String(_) => keywords(&scalars(def)?, &Mods::default(), env),
        _ => bail!("a search must be a map, a list of maps or a list of keywords"),
    }
}

/// Values without a field name: searched in each of `sigma_keyword_fields`, as `contains` unless a modifier says otherwise.
fn keywords(list: &[&Value], given: &Mods, env: &Env) -> Result<Value> {
    if env.keyword_fields.is_empty() {
        bail!("keyword searches (values without a field) need sigma_keyword_fields: the fields to look in");
    }
    let mods = Mods { op: if given.op == Op::Equals { Op::Contains } else { given.op }, all: given.all, cased: given.cased, windash: given.windash, re_i: given.re_i, enc: given.enc.clone() };
    let per_field: Vec<Value> = env.keyword_fields.iter().map(|f| values(f, &mods, list)).collect::<Result<_>>()?;
    Ok(or(per_field))
}

/// An `add_condition` of a pipeline: `field: value` or `field: [values]`, matched like a Sigma value.
pub fn condition_clause(field: &str, v: &Value) -> Result<Value> {
    values(field, &Mods::default(), &scalars(v)?)
}

fn scalars(v: &Value) -> Result<Vec<&Value>> {
    let list: Vec<&Value> = match v {
        Value::Array(a) => a.iter().collect(),
        v => vec![v],
    };
    if list.is_empty() {
        bail!("empty value list");
    }
    if list.iter().any(|v| v.is_object() || v.is_array()) {
        bail!("values must be strings, numbers, booleans or null");
    }
    Ok(list)
}

/// Values of one field: alternatives, or all required with the `all` modifier.
fn values(field: &str, m: &Mods, list: &[&Value]) -> Result<Value> {
    let items: Vec<Value> = list.iter().map(|v| item(field, m, v)).collect::<Result<_>>()?;
    Ok(if m.all { and(items) } else { or(items) })
}

fn term(field: &str, value: Value, case_insensitive: bool) -> Value {
    if case_insensitive { json!({"term": {field: {"value": value, "case_insensitive": true}}}) } else { json!({"term": {field: {"value": value}}}) }
}

fn as_text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn item(field: &str, m: &Mods, v: &Value) -> Result<Value> {
    match m.op {
        Op::Exists => match v {
            Value::Bool(true) => Ok(exists(field)),
            Value::Bool(false) => Ok(not(exists(field))),
            _ => bail!("exists takes true or false"),
        },
        Op::Cmp(bound) => match v {
            Value::Number(_) => Ok(json!({"range": {field: {bound: v}}})),
            Value::String(s) if s.parse::<f64>().is_ok() => Ok(json!({"range": {field: {bound: s}}})),
            _ => bail!("{bound} takes a number"),
        },
        Op::Cidr => match v {
            Value::String(s) => Ok(term(field, json!(s), false)),
            _ => bail!("cidr takes a network like 10.0.0.0/8"),
        },
        Op::Re => {
            let Value::String(s) = v else { bail!("re takes a regular expression string") };
            let (re, insensitive) = regex(s)?;
            let mut body = json!({"value": re, "flags": "NONE"});
            if m.re_i || insensitive {
                body["case_insensitive"] = json!(true);
            }
            Ok(json!({"regexp": {field: body}}))
        }
        Op::Equals | Op::Contains | Op::StartsWith | Op::EndsWith => text(field, m, v),
    }
}

fn text(field: &str, m: &Mods, v: &Value) -> Result<Value> {
    let plain = m.op == Op::Equals && m.enc.is_empty() && !m.windash;
    match v {
        Value::Null if plain => return Ok(not(exists(field))),
        Value::Null => bail!("null only combines with plain equality"),
        Value::Bool(_) | Value::Number(_) if plain => return Ok(term(field, v.clone(), false)),
        _ => {}
    }
    let s = as_text(v).context("unsupported value")?;
    let mut raws = vec![s];
    if m.windash {
        raws = raws.iter().flat_map(|r| modifiers::windash(r)).collect();
    }
    let mut variants: Vec<Vec<Part>> = Vec::new();
    for raw in &raws {
        let parts = modifiers::parse_pattern(raw);
        if m.enc.is_empty() {
            variants.push(parts);
            continue;
        }
        if modifiers::has_wildcard(&parts) {
            bail!("value {raw:?}: wildcards cannot be encoded ({})", enc_names(&m.enc));
        }
        variants.extend(modifiers::encode(&modifiers::literal(&parts), &m.enc)?.iter().map(|e| e.chars().map(Part::Lit).collect()));
    }
    let clauses = variants.into_iter().map(|p| pattern(field, modifiers::wrap(p, m.op), !m.cased)).collect();
    Ok(or(clauses))
}

fn enc_names(encs: &[Enc]) -> String {
    encs.iter().map(|e| format!("{e:?}").to_lowercase()).collect::<Vec<_>>().join("|")
}

fn pattern(field: &str, parts: Vec<Part>, case_insensitive: bool) -> Value {
    if modifiers::has_wildcard(&parts) {
        let w = modifiers::render_wildcard(&parts);
        if case_insensitive { json!({"wildcard": {field: {"value": w, "case_insensitive": true}}}) } else { json!({"wildcard": {field: {"value": w}}}) }
    } else {
        term(field, json!(modifiers::literal(&parts)), case_insensitive)
    }
}

/// Sigma regular expressions (PCRE, unanchored) into Lucene's, which are anchored and have no `\d`, `\w`, `\s`, `\b`,
/// look-around or lazy quantifiers. What cannot be expressed is refused rather than approximated.
pub fn regex(src: &str) -> Result<(String, bool)> {
    match src.strip_prefix("(?i)") {
        Some(rest) => Ok((regex_body(rest)?, true)),
        None => Ok((regex_body(src)?, false)),
    }
}

fn regex_body(src: &str) -> Result<String> {
    let chars: Vec<char> = src.chars().collect();
    let (mut i, mut out, mut in_class) = (0, String::new(), false);
    let start_anchor = chars.first() == Some(&'^');
    if start_anchor {
        i = 1;
    }
    let mut end_anchor = false;
    let mut prev_quant = false;
    while i < chars.len() {
        let c = chars[i];
        let mut quant = false;
        match c {
            '\\' => {
                i += 1;
                let Some(&e) = chars.get(i) else { bail!("regular expression {src:?} ends with a backslash") };
                let (class, neg) = match e {
                    'd' | 'D' => ("0-9", e == 'D'),
                    'w' | 'W' => ("a-zA-Z0-9_", e == 'W'),
                    's' | 'S' => (" \\t\\r\\n\\f", e == 'S'),
                    _ => ("", false),
                };
                if !class.is_empty() {
                    if in_class && neg {
                        bail!("regular expression {src:?}: \\{e} inside a character class is not supported");
                    }
                    let class = class.replace("\\t", "\t").replace("\\r", "\r").replace("\\n", "\n").replace("\\f", "\u{c}");
                    match (in_class, neg) {
                        (true, _) => out.push_str(&class),
                        (false, false) => out.push_str(&format!("[{class}]")),
                        (false, true) => out.push_str(&format!("[^{class}]")),
                    }
                } else if matches!(e, 't' | 'n' | 'r' | 'f') {
                    out.push(match e {
                        't' => '\t',
                        'n' => '\n',
                        'r' => '\r',
                        _ => '\u{c}',
                    });
                } else if e.is_ascii_alphanumeric() {
                    bail!("regular expression {src:?}: \\{e} is not supported by Elasticsearch regular expressions");
                } else {
                    out.push('\\');
                    out.push(e);
                }
            }
            '[' if !in_class => {
                in_class = true;
                out.push(c);
                if chars.get(i + 1) == Some(&'^') {
                    out.push('^');
                    i += 1;
                }
                // A leading ] is a literal member.
                if chars.get(i + 1) == Some(&']') {
                    out.push_str("\\]");
                    i += 1;
                }
            }
            ']' if in_class => {
                in_class = false;
                out.push(c);
            }
            '(' if !in_class => {
                if chars.get(i + 1) == Some(&'?') {
                    if chars.get(i + 2) == Some(&':') {
                        i += 2;
                        out.push('(');
                    } else {
                        bail!("regular expression {src:?}: (? groups (look-around, flags, named groups) are not supported");
                    }
                } else {
                    out.push('(');
                }
            }
            '$' if !in_class && i + 1 == chars.len() => end_anchor = true,
            '^' | '$' if !in_class => bail!("regular expression {src:?}: anchors inside the expression are not supported"),
            '"' => out.push_str("\\\""),
            '?' | '+' | '*' | '}' if !in_class => {
                if c == '?' && prev_quant {
                    bail!("regular expression {src:?}: lazy quantifiers are not supported");
                }
                quant = true;
                out.push(c);
            }
            c => out.push(c),
        }
        prev_quant = quant;
        i += 1;
    }
    if in_class {
        bail!("regular expression {src:?}: unterminated character class");
    }
    Ok(format!("{}({out}){}", if start_anchor { "" } else { ".*" }, if end_anchor { "" } else { ".*" }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn det(y: &str) -> Result<Value> {
        let Value::Object(m) = serde_yaml_ng::from_str::<Value>(y).unwrap() else { panic!() };
        detection(&m, &Env { keyword_fields: &["message".to_string()], pipe: &Resolved::default() })
    }

    #[test]
    fn plain_and_wildcard_values() {
        let q = det("sel: {Image|endswith: '\\cmd.exe', User: admin}\ncondition: sel").unwrap();
        assert_eq!(
            q,
            json!({"bool": {"filter": [
                {"wildcard": {"Image": {"value": "*\\\\cmd.exe", "case_insensitive": true}}},
                {"term": {"User": {"value": "admin", "case_insensitive": true}}},
            ]}})
        );
    }

    #[test]
    fn lists_are_alternatives_and_all_requires_each() {
        let q = det("sel: {A|contains: [x, y]}\ncondition: sel").unwrap();
        assert_eq!(q["bool"]["minimum_should_match"], 1);
        assert_eq!(q["bool"]["should"].as_array().unwrap().len(), 2);
        let q = det("sel: {A|contains|all: [x, y]}\ncondition: sel").unwrap();
        assert_eq!(q["bool"]["filter"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn null_exists_numbers_and_ranges() {
        assert_eq!(det("s: {A: null}\ncondition: s").unwrap(), json!({"bool": {"must_not": [{"exists": {"field": "A"}}]}}));
        assert_eq!(det("s: {A|exists: true}\ncondition: s").unwrap(), json!({"exists": {"field": "A"}}));
        assert_eq!(det("s: {A: 4624}\ncondition: s").unwrap(), json!({"term": {"A": {"value": 4624}}}));
        assert_eq!(det("s: {A|gte: 10}\ncondition: s").unwrap(), json!({"range": {"A": {"gte": 10}}}));
        assert_eq!(det("s: {A|cidr: 10.0.0.0/8}\ncondition: s").unwrap(), json!({"term": {"A": {"value": "10.0.0.0/8"}}}));
    }

    #[test]
    fn cased_drops_case_insensitive() {
        let q = det("s: {A|cased: Foo}\ncondition: s").unwrap();
        assert_eq!(q, json!({"term": {"A": {"value": "Foo"}}}));
    }

    #[test]
    fn condition_combines_searches() {
        let q = det("a: {X: 1}\nb: {Y: 2}\nfilter: {Z: 3}\ncondition: (a or b) and not filter").unwrap();
        let f = q["bool"]["filter"].as_array().unwrap();
        assert_eq!(f.len(), 2);
        assert!(f[0]["bool"]["should"].is_array());
        assert!(f[1]["bool"]["must_not"].is_array());
        // A list of conditions is an OR.
        let q = det("a: {X: 1}\nb: {Y: 2}\ncondition: [a, b]").unwrap();
        assert_eq!(q["bool"]["should"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn keywords_and_list_of_maps() {
        let q = det("kw: [foo, bar]\ncondition: kw").unwrap();
        assert_eq!(q["bool"]["should"][0]["wildcard"]["message"]["value"], "*foo*");
        let q = det("s:\n  - {A: 1}\n  - {B: 2}\ncondition: s").unwrap();
        assert_eq!(q["bool"]["should"].as_array().unwrap().len(), 2);
        let err = detection(&serde_yaml_ng::from_str::<serde_json::Map<String, Value>>("kw: [foo]\ncondition: kw").unwrap(), &Env { keyword_fields: &[], pipe: &Resolved::default() }).unwrap_err();
        assert!(format!("{err:#}").contains("sigma_keyword_fields"));
    }

    #[test]
    fn encoded_values() {
        let q = det("s: {A|base64: foo}\ncondition: s").unwrap();
        assert_eq!(q["term"]["A"]["value"], "Zm9v");
        let q = det("s: {A|base64offset|contains: foobar}\ncondition: s").unwrap();
        assert_eq!(q["bool"]["should"].as_array().unwrap().len(), 3);
        assert_eq!(q["bool"]["should"][1]["wildcard"]["A"]["value"], "*Zvb2Jhc*");
        let q = det("s: {A|windash|contains: ' -enc'}\ncondition: s").unwrap();
        assert_eq!(q["bool"]["should"].as_array().unwrap().len(), 5);
        assert!(format!("{:#}", det("s: {A|base64: 'a*'}\ncondition: s").unwrap_err()).contains("cannot be encoded"));
    }

    #[test]
    fn pipeline_maps_fields() {
        use super::super::pipeline::{LogSource, Pipeline, load};
        let p: Vec<Pipeline> = vec![load("ecs_windows", std::path::Path::new(".")).unwrap().0];
        let src = LogSource { product: Some("windows".into()), ..LogSource::default() };
        let r = Resolved::new(&p, &src, ".keyword");
        let Value::Object(m) = serde_yaml_ng::from_str::<Value>("s: {Image|endswith: '\\\\a.exe'}\nk: [foo]\ncondition: s or k").unwrap() else { panic!() };
        let q = detection(&m, &Env { keyword_fields: &["message".into()], pipe: &r }).unwrap();
        let should = q["bool"]["should"].as_array().unwrap();
        assert!(should[0]["wildcard"]["process.executable.keyword"].is_object() || should[1]["wildcard"]["process.executable.keyword"].is_object());
        assert!(should.iter().any(|c| c["wildcard"]["message"].is_object()));
    }

    #[test]
    fn keyword_keys_with_modifiers() {
        let q = det("kw:\n  '|all': [foo, bar]\ncondition: kw").unwrap();
        // One clause per keyword field, each requiring both keywords.
        assert_eq!(q["bool"]["filter"].as_array().unwrap().len(), 2);
        assert_eq!(q["bool"]["filter"][0]["wildcard"]["message"]["value"], "*foo*");
        let q = det("kw:\n  '|startswith': foo\ncondition: kw").unwrap();
        assert_eq!(q["wildcard"]["message"]["value"], "foo*");
    }

    #[test]
    fn rejects_unsupported() {
        for (y, want) in [
            ("s: {A|fieldref: B}\ncondition: s", "not supported"),
            ("s: {A: 1}\ncondition: s | count() > 2", "aggregations"),
            ("s: {A: 1}\ntimeframe: 5m\ncondition: s", "timeframe"),
            ("s: {A: 1}", "missing condition"),
            ("s: {A|exists: maybe}\ncondition: s", "true or false"),
            ("s: {A|contains: null}\ncondition: s", "null"),
            ("s: {A: [{B: 1}]}\ncondition: s", "values must be"),
        ] {
            let err = format!("{:#}", det(y).unwrap_err());
            assert!(err.contains(want), "{y}: {err}");
        }
    }

    #[test]
    fn regex_translation() {
        assert_eq!(regex_body(r"\d+\.exe$").unwrap(), r".*([0-9]+\.exe)");
        assert_eq!(regex_body(r"^cmd|powershell").unwrap(), "(cmd|powershell).*");
        assert_eq!(regex_body(r"(?:a|b)[\w-]+").unwrap(), ".*((a|b)[a-zA-Z0-9_-]+).*");
        assert_eq!(regex_body(r"\S").unwrap(), ".*([^ \t\r\n\u{c}]).*");
        assert_eq!(regex_body(r#"a"b"#).unwrap(), r#".*(a\"b).*"#);
        for (re, want) in [(r"\bfoo", "not supported"), (r"(?i)foo", "(? groups"), (r"a+?", "lazy"), (r"a^b", "anchors"), (r"[abc", "unterminated"), (r"[\D]", "inside a character class")] {
            assert!(regex_body(re).unwrap_err().to_string().contains(want), "{re}");
        }
        assert_eq!(regex("(?i)abc").unwrap(), (".*(abc).*".to_string(), true));
        assert!(regex("a(?i)bc").unwrap_err().to_string().contains("(? groups"));
        let q = det("s: {A|re|i: 'ab.*'}\ncondition: s").unwrap();
        assert_eq!(q, json!({"regexp": {"A": {"value": ".*(ab.*).*", "flags": "NONE", "case_insensitive": true}}}));
    }
}
