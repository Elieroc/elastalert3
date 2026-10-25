//! Sigma documents. One file may hold several YAML documents (`---`): the rule, the detection rules a correlation refers
//! to, filters. A `Corpus` is the set of documents a rule can look its references up in.

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Kind {
    Detection,
    Correlation,
    /// A meta filter (`filter:` with `rules`, `selection`, `condition`).
    Filter,
    Other,
}

#[derive(Debug)]
pub struct Doc {
    pub path: PathBuf,
    pub map: Map<String, Value>,
    pub kind: Kind,
}

impl Doc {
    pub fn str(&self, key: &str) -> Option<&str> {
        self.map.get(key).and_then(Value::as_str)
    }

    /// A rule is referred to by its `id` or its `name` (YAML reads an id like `1234` as a number).
    pub fn is(&self, reference: &str) -> bool {
        ["id", "name"].iter().any(|k| match self.map.get(*k) {
            Some(Value::String(s)) => s == reference,
            Some(Value::Number(n)) => n.to_string() == reference,
            _ => false,
        })
    }

    /// What the rule is called in messages.
    pub fn label(&self) -> String {
        self.str("name").or_else(|| self.str("id")).or_else(|| self.str("title")).unwrap_or("(unnamed)").to_string()
    }
}

/// Every document of a file, without environment expansion: Sigma values hold `$` and `%` freely.
pub fn read_docs(path: &Path) -> Result<Vec<Arc<Doc>>> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut out = Vec::new();
    for de in serde_yaml_ng::Deserializer::from_str(&text) {
        let v = Value::deserialize(de).with_context(|| format!("parsing {}", path.display()))?;
        let map = match v {
            Value::Null => continue,
            Value::Object(m) => m,
            _ => bail!("{}: every document must be a YAML map", path.display()),
        };
        let kind = if map.contains_key("correlation") {
            Kind::Correlation
        } else if map.contains_key("filter") {
            Kind::Filter
        } else if map.contains_key("detection") {
            Kind::Detection
        } else {
            Kind::Other
        };
        out.push(Arc::new(Doc { path: path.to_path_buf(), map, kind }));
    }
    Ok(out)
}

#[derive(Clone, Debug, Default)]
pub struct Corpus {
    docs: Vec<Arc<Doc>>,
}

fn yaml_files(path: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if path.is_dir() {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(path).with_context(|| format!("reading {}", path.display()))?.filter_map(|e| e.ok().map(|e| e.path())).collect();
        entries.sort();
        for e in entries {
            yaml_files(&e, out)?;
        }
    } else if matches!(path.extension().and_then(|e| e.to_str()), Some("yml" | "yaml")) {
        out.push(path.to_path_buf());
    }
    Ok(())
}

impl Corpus {
    pub fn from_docs(docs: Vec<Arc<Doc>>) -> Corpus {
        Corpus { docs }
    }

    /// The documents of files and folders (searched recursively). With `lenient`, a file that does not parse is left
    /// out: it fails on its own when it is loaded as a rule.
    pub fn from_paths(paths: &[PathBuf], lenient: bool) -> Result<Corpus> {
        let mut files = Vec::new();
        for p in paths {
            if !p.exists() {
                bail!("{} does not exist", p.display());
            }
            yaml_files(p, &mut files)?;
        }
        let mut docs = Vec::new();
        for f in files {
            match read_docs(&f) {
                Ok(d) => docs.extend(d),
                Err(_) if lenient => {}
                Err(e) => return Err(e),
            }
        }
        Ok(Corpus { docs })
    }

    /// Adds the documents of `other`; the ones already here keep priority in lookups.
    pub fn extend(&mut self, other: &Corpus) {
        self.docs.extend(other.docs.iter().cloned());
    }

    pub fn docs(&self) -> &[Arc<Doc>] {
        &self.docs
    }

    pub fn lookup(&self, reference: &str) -> Option<&Arc<Doc>> {
        self.docs.iter().find(|d| d.kind != Kind::Filter && d.is(reference))
    }

    /// The meta filters that name `doc` in their `rules`.
    pub fn filters_for(&self, doc: &Doc) -> Vec<&Arc<Doc>> {
        self.docs
            .iter()
            .filter(|f| f.kind == Kind::Filter)
            .filter(|f| filter_rules(f).iter().any(|r| doc.is(r)))
            .collect()
    }
}

/// `filter.rules`: one reference or a list of them.
pub fn filter_rules(filter: &Doc) -> Vec<&str> {
    match filter.map.get("filter").and_then(|f| f.get("rules")) {
        Some(Value::String(s)) => vec![s.as_str()],
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).collect(),
        _ => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(name: &str, text: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("ea3-corpus-{}", std::process::id())).join(name);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, text).unwrap();
        p
    }

    #[test]
    fn multi_document_files_are_classified_and_looked_up() {
        let p = write(
            "multi.yml",
            "title: c\ncorrelation: {type: event_count}\n---\ntitle: d\nname: failed\nid: 1111\ndetection: {s: {A: 1}, condition: s}\n---\ntitle: f\nfilter: {rules: [failed], selection: {B: 2}, condition: selection}\n---\n---\ntitle: o\n",
        );
        let docs = read_docs(&p).unwrap();
        assert_eq!(docs.iter().map(|d| d.kind).collect::<Vec<_>>(), vec![Kind::Correlation, Kind::Detection, Kind::Filter, Kind::Other]);
        let c = Corpus::from_docs(docs);
        assert_eq!(c.lookup("failed").unwrap().str("title"), Some("d"));
        assert_eq!(c.lookup("1111").unwrap().label(), "failed");
        assert!(c.lookup("nope").is_none());
        let d = c.lookup("failed").unwrap();
        assert_eq!(c.filters_for(d).len(), 1);
        assert_eq!(filter_rules(c.filters_for(d)[0]), vec!["failed"]);
    }

    #[test]
    fn folders_are_searched_and_bad_files_can_be_skipped() {
        let a = write("dir/a.yml", "title: a\nname: a\ndetection: {s: {A: 1}, condition: s}\n");
        write("dir/b.yaml", "title: [broken\n");
        write("dir/notes.txt", "nothing");
        let dir = a.parent().unwrap().to_path_buf();
        assert!(Corpus::from_paths(std::slice::from_ref(&dir), false).is_err());
        let c = Corpus::from_paths(&[dir], true).unwrap();
        assert_eq!(c.docs().len(), 1);
        assert!(Corpus::from_paths(&[PathBuf::from("/nonexistent/x")], true).unwrap_err().to_string().contains("does not exist"));
    }
}
