//! The `condition` of a Sigma rule: `and` / `or` / `not`, parentheses, `1 of sel*`, `all of sel*`, `1 of them`, `all of them`.
//! Aggregations (`| count() by ...`) are not part of the grammar: Sigma correlation rules replace them.

use anyhow::{Result, bail};

#[derive(Clone, Debug, PartialEq)]
pub enum Cond {
    Sel(String),
    And(Vec<Cond>),
    Or(Vec<Cond>),
    Not(Box<Cond>),
}

fn tokens(src: &str) -> Result<Vec<String>> {
    if src.contains('|') {
        bail!("condition {src:?}: aggregations (| count() ...) are not supported");
    }
    let mut out = Vec::new();
    let mut word = String::new();
    for c in src.chars() {
        if c.is_whitespace() || c == '(' || c == ')' {
            if !word.is_empty() {
                out.push(std::mem::take(&mut word));
            }
            if !c.is_whitespace() {
                out.push(c.to_string());
            }
        } else {
            word.push(c);
        }
    }
    if !word.is_empty() {
        out.push(word);
    }
    Ok(out)
}

/// `*` is the only wildcard of a selection name pattern.
fn glob(pattern: &str, name: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == name,
        Some((head, rest)) => {
            let Some(mut tail) = name.strip_prefix(head) else { return false };
            let mut parts = rest.split('*').peekable();
            while let Some(p) = parts.next() {
                if parts.peek().is_none() {
                    return tail.ends_with(p);
                }
                match tail.find(p) {
                    Some(i) => tail = &tail[i + p.len()..],
                    None => return false,
                }
            }
            true
        }
    }
}

struct Parser<'a> {
    toks: Vec<String>,
    pos: usize,
    names: &'a [String],
}

impl Parser<'_> {
    fn peek(&self) -> Option<&str> {
        self.toks.get(self.pos).map(String::as_str)
    }

    fn eat(&mut self, word: &str) -> bool {
        let hit = self.peek() == Some(word);
        if hit {
            self.pos += 1;
        }
        hit
    }

    fn or(&mut self) -> Result<Cond> {
        let mut items = vec![self.and()?];
        while self.eat("or") {
            items.push(self.and()?);
        }
        Ok(join(items, Cond::Or))
    }

    fn and(&mut self) -> Result<Cond> {
        let mut items = vec![self.not()?];
        while self.eat("and") {
            items.push(self.not()?);
        }
        Ok(join(items, Cond::And))
    }

    fn not(&mut self) -> Result<Cond> {
        if self.eat("not") { Ok(Cond::Not(Box::new(self.not()?))) } else { self.atom() }
    }

    fn atom(&mut self) -> Result<Cond> {
        let Some(tok) = self.peek().map(String::from) else { bail!("condition ends too early") };
        self.pos += 1;
        match tok.as_str() {
            "(" => {
                let inner = self.or()?;
                if !self.eat(")") {
                    bail!("condition: missing )");
                }
                Ok(inner)
            }
            "1" | "all" if self.peek() == Some("of") => {
                self.pos += 1;
                let Some(target) = self.peek().map(String::from) else { bail!("condition: {tok} of what?") };
                self.pos += 1;
                let hits: Vec<Cond> = self
                    .names
                    .iter()
                    .filter(|n| if target == "them" { !n.starts_with('_') } else { glob(&target, n) })
                    .map(|n| Cond::Sel(n.clone()))
                    .collect();
                if hits.is_empty() {
                    bail!("condition: {tok} of {target} matches no selection");
                }
                Ok(join(hits, if tok == "all" { Cond::And } else { Cond::Or }))
            }
            "of" | "and" | "or" | ")" => bail!("condition: unexpected {tok:?}"),
            _ if tok.chars().next().is_some_and(|c| c.is_ascii_digit()) && self.peek() == Some("of") => {
                bail!("condition: only '1 of' and 'all of' are supported, not {tok:?} of")
            }
            _ if self.names.contains(&tok) => Ok(Cond::Sel(tok)),
            _ => bail!("condition: unknown selection {tok:?} (selections: {})", self.names.join(", ")),
        }
    }
}

fn join(mut items: Vec<Cond>, many: fn(Vec<Cond>) -> Cond) -> Cond {
    if items.len() == 1 { items.remove(0) } else { many(items) }
}

pub fn parse(src: &str, names: &[String]) -> Result<Cond> {
    let mut p = Parser { toks: tokens(src)?, pos: 0, names };
    let c = p.or()?;
    if let Some(t) = p.peek() {
        bail!("condition {src:?}: unexpected {t:?}");
    }
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(n: &[&str]) -> Vec<String> {
        n.iter().map(|s| s.to_string()).collect()
    }

    fn sel(n: &str) -> Cond {
        Cond::Sel(n.into())
    }

    #[test]
    fn precedence_and_parens() {
        let n = names(&["a", "b", "c"]);
        assert_eq!(parse("a or b and not c", &n).unwrap(), Cond::Or(vec![sel("a"), Cond::And(vec![sel("b"), Cond::Not(Box::new(sel("c")))])]));
        assert_eq!(parse("(a or b) and c", &n).unwrap(), Cond::And(vec![Cond::Or(vec![sel("a"), sel("b")]), sel("c")]));
        assert_eq!(parse("not(a)", &n).unwrap(), Cond::Not(Box::new(sel("a"))));
    }

    #[test]
    fn quantifiers() {
        let n = names(&["sel_a", "sel_b", "filter", "_hidden"]);
        assert_eq!(parse("1 of sel_*", &n).unwrap(), Cond::Or(vec![sel("sel_a"), sel("sel_b")]));
        assert_eq!(parse("all of sel_*", &n).unwrap(), Cond::And(vec![sel("sel_a"), sel("sel_b")]));
        assert_eq!(parse("all of them", &n).unwrap(), Cond::And(vec![sel("sel_a"), sel("sel_b"), sel("filter")]));
        assert_eq!(parse("1 of filter", &n).unwrap(), sel("filter"));
        assert_eq!(parse("sel_a and not 1 of f*", &n).unwrap(), Cond::And(vec![sel("sel_a"), Cond::Not(Box::new(sel("filter")))]));
    }

    #[test]
    fn rejects_bad_conditions() {
        let n = names(&["a", "b"]);
        for (src, want) in [
            ("a | count() > 3", "aggregations"),
            ("a and", "ends too early"),
            ("c", "unknown selection"),
            ("1 of x*", "matches no selection"),
            ("2 of them", "only '1 of'"),
            ("(a or b", "missing )"),
            ("a b", "unexpected"),
            ("a or or b", "unexpected"),
        ] {
            let err = parse(src, &n).unwrap_err().to_string();
            assert!(err.contains(want), "{src}: {err}");
        }
    }
}
