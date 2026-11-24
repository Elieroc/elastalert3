//! Catalogue of the options of each rule type: `rule_types.yaml`, printed by `elastalert rule-types [TYPE]`.

use anyhow::{Result, bail};
use serde_json::{Map, Value, json};

fn catalog() -> Map<String, Value> {
    serde_yaml_ng::from_str(include_str!("rule_types.yaml")).expect("rule_types.yaml is valid")
}

/// One entry: the catalogue's fields plus `type` and the section of the documentation.
fn entry(name: &str, mut e: Map<String, Value>) -> Value {
    e.remove("example");
    let mut out = Map::from_iter([("type".to_string(), json!(name))]);
    out.extend(e);
    out.entry("one_of").or_insert(json!([]));
    out.insert("doc".into(), json!(format!("https://elastalert3.neopipe.fr/ruletypes.html#{}", name.replace('_', "-"))));
    Value::Object(out)
}

pub fn cmd(name: Option<&str>) -> Result<()> {
    let mut all = catalog();
    let out = match name {
        None => Value::Array(all.iter().map(|(n, e)| json!({"type": n, "summary": e["summary"]})).collect()),
        Some(n) => match all.remove(n) {
            Some(Value::Object(e)) => entry(n, e),
            _ => bail!("unknown rule type {n:?}; valid types: {}", all.keys().cloned().collect::<Vec<_>>().join(", ")),
        },
    };
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::Config, rule};

    fn load(ty: &str, body: &Map<String, Value>) -> Result<()> {
        let dir = std::env::temp_dir().join(format!("ea-rule-types-{}-{ty}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("r.yaml");
        std::fs::write(&file, format!("name: {ty}\ntype: {ty}\nindex: logs-*\nalert: debug\n{}", if body.is_empty() { String::new() } else { serde_yaml_ng::to_string(body).unwrap() })).unwrap();
        let conf = Config::load_with_defaults(&dir.join("none.yaml")).unwrap();
        rule::load(&file, &conf).map(|_| ())
    }

    fn names(e: &Value, k: &str) -> Vec<String> {
        e[k].as_array().into_iter().flatten().filter_map(|f| f["name"].as_str()).map(String::from).collect()
    }

    /// The catalogue must not drift from the loader: the example loads, and dropping any unconditional
    /// required option (or every member of a one_of group) is refused.
    #[test]
    fn catalogue_matches_the_loader() {
        for (ty, e) in catalog() {
            let example: Map<String, Value> = serde_yaml_ng::from_str(e["example"].as_str().unwrap()).unwrap_or_default();
            if let Err(err) = load(&ty, &example) {
                panic!("{ty}: the example does not load: {err:#}");
            }
            let optional = names(&e, "optional");
            let mut cut: Vec<Vec<String>> = e["required"].as_array().unwrap().iter().filter(|f| f.get("required_if").is_none()).map(|f| vec![f["name"].as_str().unwrap().to_string()]).collect();
            cut.extend(e.get("one_of").and_then(Value::as_array).into_iter().flatten().map(|g| g.as_array().unwrap().iter().map(|k| k.as_str().unwrap().to_string()).collect()));
            for keys in cut {
                let mut r = example.clone();
                keys.iter().for_each(|k| drop(r.remove(k)));
                assert!(load(&ty, &r).is_err(), "{ty}: loads without {keys:?}, which the catalogue says is required");
            }
            for f in e["required"].as_array().unwrap().iter().chain(e["optional"].as_array().unwrap()) {
                assert!(f["name"].is_string() && f["type"].is_string() && f["description"].is_string(), "{ty}: incomplete field {f}");
            }
            assert!(optional.iter().all(|o| !names(&e, "required").contains(o)), "{ty}: an option is both required and optional");
        }
    }

    #[test]
    fn every_loadable_type_has_an_entry() {
        let src = include_str!("rule.rs");
        let body = &src[src.find("let kind = match raw[\"type\"].as_str()").unwrap()..];
        let body = &body[..body.find("other => bail!").unwrap()];
        let loadable: Vec<&str> = body.lines().filter_map(|l| l.trim().strip_prefix("Some(\"")?.split('"').next()).collect();
        assert_eq!(loadable.len(), catalog().len());
        for t in loadable {
            assert!(catalog().contains_key(t), "{t} has no entry in rule_types.yaml");
        }
    }
}
