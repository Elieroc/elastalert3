//! Field modifiers of a Sigma detection (`CommandLine|contains|all`) and the value patterns they build.

use anyhow::{Result, bail};

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum Op {
    #[default]
    Equals,
    Contains,
    StartsWith,
    EndsWith,
    Re,
    Cidr,
    Exists,
    /// Elasticsearch `range` bound: gt, gte, lt or lte.
    Cmp(&'static str),
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Enc {
    Utf16Le,
    Utf16Be,
    Utf16,
    Base64,
    Base64Offset,
}

#[derive(Debug, Default)]
pub struct Mods {
    pub op: Op,
    pub all: bool,
    pub cased: bool,
    pub windash: bool,
    /// `re|i`: case-insensitive regular expression.
    pub re_i: bool,
    /// Applied to each value in the order written.
    pub enc: Vec<Enc>,
}

/// `field|mod|mod` into the field name and its modifiers. The name is empty for a key like `|contains`, which applies
/// its modifiers to keywords.
pub fn parse_key(key: &str) -> Result<(&str, Mods)> {
    let mut parts = key.split('|');
    let field = parts.next().unwrap_or_default();
    let mut m = Mods::default();
    for word in parts {
        let mut set_op = |op: Op| -> Result<()> {
            if m.op != Op::Equals {
                bail!("{key}: modifier {word} conflicts with {:?}", m.op);
            }
            m.op = op;
            Ok(())
        };
        match word {
            "contains" => set_op(Op::Contains)?,
            "startswith" => set_op(Op::StartsWith)?,
            "endswith" => set_op(Op::EndsWith)?,
            "re" => set_op(Op::Re)?,
            "cidr" => set_op(Op::Cidr)?,
            "exists" => set_op(Op::Exists)?,
            "gt" => set_op(Op::Cmp("gt"))?,
            "gte" => set_op(Op::Cmp("gte"))?,
            "lt" => set_op(Op::Cmp("lt"))?,
            "lte" => set_op(Op::Cmp("lte"))?,
            "all" => m.all = true,
            "cased" => m.cased = true,
            "windash" => m.windash = true,
            "base64" => m.enc.push(Enc::Base64),
            "base64offset" => m.enc.push(Enc::Base64Offset),
            "utf16le" | "wide" => m.enc.push(Enc::Utf16Le),
            "utf16be" => m.enc.push(Enc::Utf16Be),
            "utf16" => m.enc.push(Enc::Utf16),
            "i" | "s" if m.op == Op::Re => m.re_i |= word == "i",
            "m" if m.op == Op::Re => bail!("{key}: the re|m flag (multi-line anchors) is not supported"),
            _ => bail!("{key}: modifier {word:?} is not supported"),
        }
    }
    if !m.enc.is_empty() && matches!(m.op, Op::Re | Op::Cidr | Op::Exists | Op::Cmp(_)) {
        bail!("{key}: encoding modifiers only combine with equality, contains, startswith and endswith");
    }
    Ok((field, m))
}

/// One piece of a Sigma string value: `*` and `?` are wildcards unless escaped.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Part {
    Lit(char),
    Many,
    One,
}

/// `\*`, `\?` and `\\` are literal characters; any other backslash is literal too (Windows paths).
pub fn parse_pattern(s: &str) -> Vec<Part> {
    let mut out = Vec::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if matches!(chars.peek(), Some('*' | '?' | '\\')) => out.push(Part::Lit(chars.next().unwrap_or('\\'))),
            '*' => out.push(Part::Many),
            '?' => out.push(Part::One),
            c => out.push(Part::Lit(c)),
        }
    }
    out
}

pub fn has_wildcard(parts: &[Part]) -> bool {
    parts.iter().any(|p| !matches!(p, Part::Lit(_)))
}

pub fn literal(parts: &[Part]) -> String {
    parts.iter().filter_map(|p| if let Part::Lit(c) = p { Some(*c) } else { None }).collect()
}

/// Elasticsearch `wildcard` syntax of a pattern: literal `*`, `?` and `\` get a backslash.
pub fn render_wildcard(parts: &[Part]) -> String {
    let mut out = String::new();
    for p in parts {
        match p {
            Part::Many => out.push('*'),
            Part::One => out.push('?'),
            Part::Lit(c @ ('*' | '?' | '\\')) => {
                out.push('\\');
                out.push(*c);
            }
            Part::Lit(c) => out.push(*c),
        }
    }
    out
}

/// `*` around the value for `contains`, in front for `endswith`, behind for `startswith`; neighbouring `*` collapse.
pub fn wrap(mut parts: Vec<Part>, op: Op) -> Vec<Part> {
    if matches!(op, Op::Contains | Op::EndsWith) && parts.first() != Some(&Part::Many) {
        parts.insert(0, Part::Many);
    }
    if matches!(op, Op::Contains | Op::StartsWith) && parts.last() != Some(&Part::Many) {
        parts.push(Part::Many);
    }
    parts
}

/// The value with every `-` that starts an argument written as `/`, en dash, em dash and horizontal bar too.
pub fn windash(s: &str) -> Vec<String> {
    let chars: Vec<char> = s.chars().collect();
    let starts_arg = |i: usize| chars[i] == '-' && (i == 0 || chars[i - 1] == ' ');
    if !(0..chars.len()).any(starts_arg) {
        return vec![s.into()];
    }
    let mut out = vec![s.to_string()];
    for dash in ['/', '\u{2013}', '\u{2014}', '\u{2015}'] {
        out.push(chars.iter().enumerate().map(|(i, &c)| if starts_arg(i) { dash } else { c }).collect());
    }
    out
}

fn utf16(s: &[u8], be: bool, bom: bool) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(s)?;
    let mut out = if bom { vec![0xff, 0xfe] } else { vec![] };
    for u in text.encode_utf16() {
        out.extend(if be { u.to_be_bytes() } else { u.to_le_bytes() });
    }
    Ok(out)
}

pub fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |n, (i, b)| n | (*b as u32) << (16 - 8 * i));
        for i in 0..4 {
            out.push(if i <= chunk.len() { ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
        }
    }
    out
}

/// The three alignments of `base64offset`: what remains of the encoding whatever the offset in the encoded text.
fn base64_offsets(bytes: &[u8]) -> Vec<Vec<u8>> {
    const START: [usize; 3] = [0, 2, 3];
    (0..3)
        .map(|i| {
            let padded: Vec<u8> = std::iter::repeat_n(b' ', i).chain(bytes.iter().copied()).collect();
            let enc = base64(&padded).into_bytes();
            let end = enc.len() - [0, 3, 2][(bytes.len() + i) % 3];
            enc[START[i].min(end)..end].to_vec()
        })
        .collect()
}

/// Applies the encodings of `mods` to a literal value. A value with a wildcard cannot be encoded.
pub fn encode(value: &str, encs: &[Enc]) -> Result<Vec<String>> {
    let mut cur: Vec<Vec<u8>> = vec![value.as_bytes().to_vec()];
    for e in encs {
        let mut next = Vec::new();
        for bytes in &cur {
            match e {
                Enc::Utf16Le => next.push(utf16(bytes, false, false)?),
                Enc::Utf16Be => next.push(utf16(bytes, true, false)?),
                Enc::Utf16 => next.push(utf16(bytes, false, true)?),
                Enc::Base64 => next.push(base64(bytes).into_bytes()),
                Enc::Base64Offset => next.extend(base64_offsets(bytes)),
            }
        }
        cur = next;
    }
    cur.into_iter()
        .map(|b| String::from_utf8(b).map_err(|_| anyhow::anyhow!("value {value:?} does not encode to text: end the modifiers with base64 or base64offset")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_modifiers() {
        let (f, m) = parse_key("CommandLine|contains|all").unwrap();
        assert_eq!((f, m.op, m.all), ("CommandLine", Op::Contains, true));
        let (_, m) = parse_key("Image|windash|cased|endswith").unwrap();
        assert!(m.windash && m.cased && m.op == Op::EndsWith);
        let (f, m) = parse_key("|all").unwrap();
        assert!(f.is_empty() && m.all);
        let (_, m) = parse_key("x|re|i|s").unwrap();
        assert!(m.re_i);
        let (_, m) = parse_key("x|utf16le|base64offset|contains").unwrap();
        assert_eq!(m.enc, vec![Enc::Utf16Le, Enc::Base64Offset]);
        for (key, want) in [
            ("x|fieldref", "not supported"),
            ("x|contains|startswith", "conflicts"),
            ("x|re|m", "re|m"),
            ("x|i", "not supported"),
            ("x|re|base64", "encoding"),
        ] {
            assert!(parse_key(key).unwrap_err().to_string().contains(want), "{key}");
        }
    }

    #[test]
    fn patterns_and_escapes() {
        use Part::*;
        assert_eq!(parse_pattern(r"a*b?"), vec![Lit('a'), Many, Lit('b'), One]);
        assert_eq!(parse_pattern(r"a\*b"), vec![Lit('a'), Lit('*'), Lit('b')]);
        assert_eq!(parse_pattern(r"C:\Windows\\*"), vec![Lit('C'), Lit(':'), Lit('\\'), Lit('W'), Lit('i'), Lit('n'), Lit('d'), Lit('o'), Lit('w'), Lit('s'), Lit('\\'), Many]);
        assert_eq!(render_wildcard(&parse_pattern(r"C:\x*\?")), r"C:\\x*\?");
        assert!(has_wildcard(&parse_pattern("a*")) && !has_wildcard(&parse_pattern(r"a\*")));
        assert_eq!(render_wildcard(&wrap(parse_pattern("a"), Op::Contains)), "*a*");
        assert_eq!(render_wildcard(&wrap(parse_pattern("*a"), Op::EndsWith)), "*a");
        assert_eq!(render_wildcard(&wrap(parse_pattern("a"), Op::StartsWith)), "a*");
    }

    #[test]
    fn windash_variants() {
        assert_eq!(windash("calc"), vec!["calc"]);
        let v = windash("cmd -enc -x");
        assert_eq!(v.len(), 5);
        assert_eq!(v[1], "cmd /enc /x");
        assert_eq!(v[2], "cmd \u{2013}enc \u{2013}x");
        assert_eq!(windash("a-b"), vec!["a-b"]);
    }

    #[test]
    fn base64_matches_reference() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        assert_eq!(encode("foo", &[Enc::Base64]).unwrap(), vec!["Zm9v"]);
        assert_eq!(encode("foobar", &[Enc::Base64Offset]).unwrap(), vec!["Zm9vYmFy", "Zvb2Jhc", "mb29iYX"]);
    }

    #[test]
    fn utf16_then_base64() {
        // "A" in UTF-16LE is 41 00 -> "QQA="
        assert_eq!(encode("A", &[Enc::Utf16Le, Enc::Base64]).unwrap(), vec!["QQA="]);
        assert_eq!(encode("A", &[Enc::Utf16Be, Enc::Base64]).unwrap(), vec!["AEE="]);
        assert_eq!(encode("A", &[Enc::Utf16, Enc::Base64]).unwrap(), vec!["//5BAA=="]);
        assert!(encode("A", &[Enc::Utf16Le]).is_ok());
        assert!(encode("é", &[Enc::Utf16Le]).unwrap_err().to_string().contains("does not encode"));
    }
}
