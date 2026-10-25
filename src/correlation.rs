//! `correlation_query` of a `correlation` rule: the boolean expression over the rule's leaves, and its progress for one chain.

use anyhow::{Result, bail};

#[derive(Clone, Copy, Debug, PartialEq)]
enum Op {
    And,
    Or,
    Then,
}

impl Op {
    fn name(self) -> &'static str {
        match self {
            Op::And => "AND",
            Op::Or => "OR",
            Op::Then => "THEN",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Expr {
    /// Index into the rule's leaves.
    Leaf(usize),
    Not(Box<Expr>),
    And(Vec<Expr>),
    Or(Vec<Expr>),
    Then(Vec<Expr>),
}

/// A `correlation_query`, split for evaluation: what must happen, and what must not happen within the window.
#[derive(Clone, Debug)]
pub struct Query {
    pub positive: Expr,
    /// Operands of the top-level `NOT`s.
    pub negated: Vec<Expr>,
    /// `... THEN NOT x`: the negated part counts only after `positive` completed (otherwise from the start of the chain).
    pub after: bool,
    /// The query with upper-case keywords, and each negated operand the same way, for alert text.
    pub text: String,
    pub negated_text: Vec<String>,
}

pub const KEYWORDS: [&str; 4] = ["AND", "OR", "THEN", "NOT"];

#[derive(Debug, PartialEq)]
enum Tok {
    Open,
    Close,
    Not,
    Op(Op),
    Name(String),
}

fn tokens(src: &str) -> Result<Vec<Tok>> {
    let mut out = Vec::new();
    let mut chars = src.char_indices().peekable();
    while let Some(&(i, c)) = chars.peek() {
        match c {
            '(' | ')' => {
                out.push(if c == '(' { Tok::Open } else { Tok::Close });
                chars.next();
            }
            c if c.is_whitespace() => {
                chars.next();
            }
            c if is_name_char(c) => {
                let mut end = i;
                while let Some(&(j, c)) = chars.peek().filter(|(_, c)| is_name_char(*c)) {
                    end = j + c.len_utf8();
                    chars.next();
                }
                let word = &src[i..end];
                out.push(match word.to_ascii_uppercase().as_str() {
                    "AND" => Tok::Op(Op::And),
                    "OR" => Tok::Op(Op::Or),
                    "THEN" => Tok::Op(Op::Then),
                    "NOT" => Tok::Not,
                    _ => Tok::Name(word.to_string()),
                });
            }
            _ => bail!("unexpected character {c:?}"),
        }
    }
    Ok(out)
}

pub fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

struct Parser<'a> {
    toks: Vec<Tok>,
    pos: usize,
    leaves: &'a [String],
}

impl Parser<'_> {
    fn next(&mut self) -> Option<&Tok> {
        self.pos += 1;
        self.toks.get(self.pos - 1)
    }

    /// Operands joined by one operator: mixing operators needs parentheses.
    fn seq(&mut self) -> Result<Expr> {
        let mut items = vec![self.unary()?];
        let mut op: Option<Op> = None;
        while let Some(&Tok::Op(o)) = self.toks.get(self.pos) {
            if let Some(p) = op
                && p != o
            {
                bail!("{} and {} cannot be mixed without parentheses", p.name(), o.name());
            }
            op = Some(o);
            self.pos += 1;
            items.push(self.unary()?);
        }
        Ok(match op {
            None => items.pop().expect("one operand"),
            Some(o) => join(o, items),
        })
    }

    fn unary(&mut self) -> Result<Expr> {
        let leaves = self.leaves;
        match self.next() {
            Some(Tok::Not) => Ok(Expr::Not(Box::new(self.unary()?))),
            Some(Tok::Open) => {
                let e = self.seq()?;
                match self.next() {
                    Some(Tok::Close) => Ok(e),
                    _ => bail!("missing ')'"),
                }
            }
            Some(Tok::Name(n)) => match leaves.iter().position(|l| l == n) {
                Some(i) => Ok(Expr::Leaf(i)),
                None => bail!("unknown leaf {n} (leaves: {})", leaves.join(", ")),
            },
            Some(Tok::Close) => bail!("unexpected ')'"),
            Some(Tok::Op(o)) => bail!("{} needs a leaf or '(' on each side", o.name()),
            None => bail!("unexpected end of the query"),
        }
    }
}

/// `(a AND b) AND c` is `a AND b AND c`.
fn join(op: Op, items: Vec<Expr>) -> Expr {
    let mut flat = Vec::new();
    for e in items {
        match (op, e) {
            (Op::And, Expr::And(sub)) | (Op::Or, Expr::Or(sub)) | (Op::Then, Expr::Then(sub)) => flat.extend(sub),
            (_, e) => flat.push(e),
        }
    }
    match op {
        Op::And => Expr::And(flat),
        Op::Or => Expr::Or(flat),
        Op::Then => Expr::Then(flat),
    }
}

fn render(e: &Expr, leaves: &[String]) -> String {
    let wrap = |e: &Expr| match e {
        Expr::And(_) | Expr::Or(_) | Expr::Then(_) => format!("({})", render(e, leaves)),
        _ => render(e, leaves),
    };
    let list = |items: &[Expr], sep: &str| items.iter().map(wrap).collect::<Vec<_>>().join(sep);
    match e {
        Expr::Leaf(i) => leaves[*i].clone(),
        Expr::Not(x) => format!("NOT {}", wrap(x)),
        Expr::And(items) => list(items, " AND "),
        Expr::Or(items) => list(items, " OR "),
        Expr::Then(items) => list(items, " THEN "),
    }
}

fn has_not(e: &Expr) -> bool {
    match e {
        Expr::Leaf(_) => false,
        Expr::Not(_) => true,
        Expr::And(items) | Expr::Or(items) | Expr::Then(items) => items.iter().any(has_not),
    }
}

fn mark_used(e: &Expr, used: &mut [bool]) {
    match e {
        Expr::Leaf(i) => used[*i] = true,
        Expr::Not(x) => mark_used(x, used),
        Expr::And(items) | Expr::Or(items) | Expr::Then(items) => items.iter().for_each(|x| mark_used(x, used)),
    }
}

fn one_or(items: Vec<Expr>, many: fn(Vec<Expr>) -> Expr) -> Expr {
    if items.len() == 1 { items.into_iter().next().expect("one item") } else { many(items) }
}

const NOT_PLACE: &str = "NOT can only be used at the top of correlation_query, as `x AND NOT y` or `x THEN NOT y`";

/// Parses `src` over the leaf names. Every leaf must be used; `NOT` only at the top, next to something that happens.
pub fn parse(src: &str, leaves: &[String]) -> Result<Query> {
    let mut p = Parser { toks: tokens(src)?, pos: 0, leaves };
    if p.toks.is_empty() {
        bail!("correlation_query is empty");
    }
    let e = p.seq()?;
    match p.toks.get(p.pos) {
        None => {}
        Some(Tok::Close) => bail!("unexpected ')'"),
        Some(_) => bail!("missing AND, OR or THEN between two operands"),
    }
    let mut used = vec![false; leaves.len()];
    mark_used(&e, &mut used);
    if let Some(i) = used.iter().position(|u| !u) {
        bail!("leaf {} is not used in correlation_query", leaves[i]);
    }
    let text = render(&e, leaves);
    let (positive, negated, after) = match e {
        Expr::Not(_) => bail!("{NOT_PLACE}"),
        Expr::And(items) => {
            let (neg, pos): (Vec<Expr>, Vec<Expr>) = items.into_iter().partition(|x| matches!(x, Expr::Not(_)));
            if pos.is_empty() {
                bail!("{NOT_PLACE}");
            }
            let neg = neg.into_iter().map(|x| if let Expr::Not(inner) = x { *inner } else { unreachable!("partitioned") }).collect();
            (one_or(pos, Expr::And), neg, false)
        }
        Expr::Then(mut items) if matches!(items.last(), Some(Expr::Not(_))) => {
            let Some(Expr::Not(inner)) = items.pop() else { unreachable!("checked above") };
            (one_or(items, Expr::Then), vec![*inner], true)
        }
        e => (e, vec![], false),
    };
    if has_not(&positive) || negated.iter().any(has_not) {
        bail!("{NOT_PLACE}");
    }
    if matches!(positive, Expr::Leaf(_)) && negated.is_empty() {
        bail!("correlation_query needs at least two leaves joined by AND, OR or THEN");
    }
    let negated_text = negated.iter().map(|x| render(x, leaves)).collect();
    Ok(Query { positive, negated, after, text, negated_text })
}

/// Marks the leaves that a fresh `Progress` of `e` takes: the ones that can start a chain.
pub fn first_leaves(e: &Expr, out: &mut [bool]) {
    match e {
        Expr::Leaf(i) => out[*i] = true,
        Expr::And(items) | Expr::Or(items) => items.iter().for_each(|x| first_leaves(x, out)),
        Expr::Then(items) => first_leaves(&items[0], out),
        Expr::Not(_) => unreachable!("NOT is split off at load"),
    }
}

/// Progress of one chain through an expression without `NOT`.
#[derive(Clone, Debug)]
pub struct Progress {
    pub done: bool,
    /// Leaf: events taken. `THEN`: the operand being waited for.
    n: u64,
    children: Vec<Progress>,
}

impl Progress {
    pub fn new(e: &Expr) -> Self {
        let children = match e {
            Expr::And(items) | Expr::Or(items) | Expr::Then(items) => items.iter().map(Progress::new).collect(),
            Expr::Leaf(_) | Expr::Not(_) => vec![],
        };
        Progress { done: false, n: 0, children }
    }

    /// Hands one document, matching the leaves `tags`, to the expression; true when a leaf took it, and `took[leaf]`
    /// set for each leaf that did. `need` is `num_events` per leaf. After a `THEN` operand completes, the next one only
    /// counts the documents that follow, so a document matching both sides counts once.
    pub fn feed(&mut self, e: &Expr, tags: &[usize], need: &[u64], took: &mut [bool]) -> bool {
        if self.done {
            return false;
        }
        match e {
            Expr::Leaf(i) => {
                if !tags.contains(i) {
                    return false;
                }
                self.n += 1;
                self.done = self.n >= need[*i];
                took[*i] = true;
                true
            }
            Expr::And(items) | Expr::Or(items) => {
                let mut any = false;
                for (p, x) in self.children.iter_mut().zip(items) {
                    any |= p.feed(x, tags, need, took);
                }
                self.done = if matches!(e, Expr::And(_)) { self.children.iter().all(|p| p.done) } else { self.children.iter().any(|p| p.done) };
                any
            }
            Expr::Then(items) => {
                let i = self.n as usize;
                let any = self.children[i].feed(&items[i], tags, need, took);
                if self.children[i].done {
                    self.n += 1;
                    self.done = self.n as usize == items.len();
                }
                any
            }
            Expr::Not(_) => unreachable!("NOT is split off at load"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(n: &[&str]) -> Vec<String> {
        n.iter().map(|s| s.to_string()).collect()
    }

    fn q(src: &str) -> Result<Query> {
        parse(src, &names(&["a", "b", "c", "d"]))
    }

    #[test]
    fn parses_and_renders() {
        let query = q("(a or b) and C").unwrap_err();
        assert!(query.to_string().contains("unknown leaf C"), "{query}");
        let query = q("(a or b) and c THEN d").unwrap_err();
        assert!(query.to_string().contains("AND and THEN cannot be mixed without parentheses"), "{query}");
        let query = q("((a or b) and c) then d").unwrap();
        assert_eq!(query.text, "((a OR b) AND c) THEN d");
        assert_eq!(query.positive, Expr::Then(vec![Expr::And(vec![Expr::Or(vec![Expr::Leaf(0), Expr::Leaf(1)]), Expr::Leaf(2)]), Expr::Leaf(3)]));
        // Same operator nested is flattened.
        assert_eq!(q("(a THEN b) THEN (c THEN d)").unwrap().positive, Expr::Then((0..4).map(Expr::Leaf).collect()));
        assert_eq!(parse("a-1 AND b_2", &names(&["a-1", "b_2"])).unwrap().text, "a-1 AND b_2");
    }

    #[test]
    fn splits_negations() {
        let query = q("a THEN b THEN NOT (c OR d)").unwrap();
        assert_eq!(query.positive, Expr::Then(vec![Expr::Leaf(0), Expr::Leaf(1)]));
        assert_eq!(query.negated, vec![Expr::Or(vec![Expr::Leaf(2), Expr::Leaf(3)])]);
        assert!(query.after);
        assert_eq!(query.negated_text, vec!["c OR d"]);
        assert_eq!(query.text, "a THEN b THEN NOT (c OR d)");
        let query = q("a AND NOT b AND (c OR d) AND NOT b").unwrap();
        assert_eq!(query.positive, Expr::And(vec![Expr::Leaf(0), Expr::Or(vec![Expr::Leaf(2), Expr::Leaf(3)])]));
        assert_eq!(query.negated, vec![Expr::Leaf(1), Expr::Leaf(1)]);
        assert!(!query.after);
        // A leaf can be used twice, also once positive and once negated.
        let query = parse("a THEN NOT a", &names(&["a"])).unwrap();
        assert_eq!((query.positive, query.negated), (Expr::Leaf(0), vec![Expr::Leaf(0)]));
    }

    #[test]
    fn rejects_bad_queries() {
        let err = |s: &str| q(s).map(|_| ()).unwrap_err().to_string();
        assert!(err("").contains("empty"));
        assert!(err("a AND b AND c").contains("leaf d is not used"));
        assert!(err("a AND (b OR c AND d)").contains("cannot be mixed"));
        assert!(err("(a AND b").contains("missing ')'"));
        assert!(err("a AND b) OR (c AND d)").contains("unexpected ')'"));
        assert!(err("a b c d").contains("missing AND, OR or THEN"));
        assert!(err("a AND OR b").contains("OR needs a leaf"));
        assert!(err("a AND b AND c AND d AND").contains("unexpected end"));
        assert!(err("a AND b, c AND d").contains("unexpected character ','"));
        for s in ["NOT (a AND b AND c AND d)", "a OR NOT b OR c OR d", "a THEN NOT b THEN c THEN d", "(a AND NOT b) THEN c THEN d", "NOT a AND NOT b AND NOT c AND NOT d", "a AND b AND c AND NOT NOT d"] {
            assert!(err(s).contains("NOT can only be used at the top"), "{s}: {}", err(s));
        }
        assert!(parse("a", &names(&["a"])).unwrap_err().to_string().contains("at least two leaves"));
        assert!(parse("a THEN a", &names(&["a"])).is_ok());
    }

    /// Feeds leaf events in order: whether each was taken, and whether the expression is done.
    fn run(src: &str, need: &[u64], leaves: &[usize]) -> (Vec<bool>, bool) {
        let query = q(src).unwrap();
        let mut p = Progress::new(&query.positive);
        let took = leaves.iter().map(|l| p.feed(&query.positive, &[*l], need, &mut [false; 4])).collect();
        (took, p.done)
    }

    #[test]
    fn then_is_strict_and_counts_num_events() {
        let one = [1, 1, 1, 1];
        assert_eq!(run("(a THEN b) AND (c AND d)", &one, &[1, 0, 1, 2, 3]), (vec![false, true, true, true, true], true));
        assert!(!run("(a THEN b) AND (c AND d)", &one, &[1, 0, 2, 3]).1, "b before a does not count");
        // b must follow the third a, not the first.
        let need = [3, 1, 1, 1];
        assert_eq!(run("(a THEN b) OR (c AND d)", &need, &[0, 0, 1, 0, 1]), (vec![true, true, false, true, true], true));
        // One event does not complete two THEN operands of the same leaf.
        let (took, done) = parse("a THEN a", &names(&["a"])).map(|query| {
            let mut p = Progress::new(&query.positive);
            let took = p.feed(&query.positive, &[0], &[1], &mut [false]);
            (took, p.done)
        }).unwrap();
        assert!(took && !done);
        // A document matching both sides of a THEN counts for the first one only, whatever the leaf order.
        for src in ["a THEN b", "b THEN a"] {
            let query = q(&format!("({src}) AND c AND d")).unwrap();
            let mut p = Progress::new(&query.positive);
            let mut took = [false; 4];
            p.feed(&query.positive, &[0, 1], &one, &mut took);
            assert_eq!(took, if src == "a THEN b" { [true, false, false, false] } else { [false, true, false, false] }, "{src}");
            p.feed(&query.positive, &[0, 1], &one, &mut took);
            assert_eq!(took[..2], [true, true], "{src}");
        }
    }

    #[test]
    fn or_and_and_inside_then() {
        let one = [1, 1, 1, 1];
        // Any branch of an OR completes it; inside AND the order is free.
        assert_eq!(run("a THEN (b OR c) THEN d", &one, &[0, 2, 3]).1, true);
        assert_eq!(run("a THEN (b AND c) THEN d", &one, &[0, 2, 1, 3]).1, true);
        assert_eq!(run("a THEN (b AND c) THEN d", &one, &[0, 2, 3, 1]).1, false);
        // Events of a done operand are not taken anymore.
        assert_eq!(run("a THEN (b AND c AND d)", &one, &[0, 0, 1]).0, vec![true, false, true]);
    }
}
