//! Time handling. Everything internal is UTC microseconds since the epoch (`Ts`),
//! durations are microseconds too (`Dur`). Formatting follows ElastAlert's output.

use anyhow::{Context, Result, bail};
use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeZone, Utc};
use serde_json::Value;
use std::sync::OnceLock;

pub type Ts = i64;
pub type Dur = i64;

pub const SECOND: Dur = 1_000_000;
pub const MINUTE: Dur = 60 * SECOND;

pub fn now() -> Ts {
    Utc::now().timestamp_micros()
}

/// `{days: 1, hours: 2}` style map -> duration. Same units as Python's timedelta kwargs.
pub fn parse_duration_map(v: &Value) -> Result<Dur> {
    let map = v.as_object().context("time value must be a map like {minutes: 5}")?;
    let mut total = 0f64;
    for (unit, n) in map {
        let n = n.as_f64().with_context(|| format!("time unit {unit} must be a number"))?;
        let mult = match unit.as_str() {
            "weeks" => 7.0 * 86_400e6,
            "days" => 86_400e6,
            "hours" => 3_600e6,
            "minutes" => 60e6,
            "seconds" => 1e6,
            "milliseconds" => 1e3,
            "microseconds" => 1.0,
            _ => bail!("unknown time unit {unit}"),
        };
        total += n * mult;
    }
    Ok(total.round() as Dur)
}

/// `hours=2` (CLI `--silence`, `--patience`).
pub fn parse_duration_arg(s: &str) -> Result<Dur> {
    let (unit, n) = s.split_once('=').context("expected <unit>=<number>, e.g. hours=2")?;
    let n: f64 = n.trim().parse().context("duration number")?;
    parse_duration_map(&serde_json::json!({ unit.trim(): n }))
}

/// Lenient ISO8601 parse. Naive timestamps are taken as UTC.
pub fn parse_iso(s: &str) -> Option<Ts> {
    let s = s.trim();
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.timestamp_micros());
    }
    for f in ["%Y-%m-%dT%H:%M:%S%.f%z", "%Y-%m-%d %H:%M:%S%.f%z"] {
        if let Ok(dt) = DateTime::parse_from_str(s, f) {
            return Some(dt.timestamp_micros());
        }
    }
    for f in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%dT%H:%M"] {
        if let Ok(dt) = NaiveDateTime::parse_from_str(s, f) {
            return Some(dt.and_utc().timestamp_micros());
        }
    }
    NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .ok()
        .map(|d| d.and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp_micros())
}

fn utc(ts: Ts) -> DateTime<Utc> {
    Utc.timestamp_micros(ts).single().unwrap_or_default()
}

/// ElastAlert's `dt_to_ts`: ISO with `Z`, no fraction when whole seconds,
/// milliseconds when the micros are a multiple of 1000, else micros.
pub fn to_iso(ts: Ts) -> String {
    let dt = utc(ts);
    let us = ts.rem_euclid(SECOND);
    if us == 0 {
        dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
    } else if us % 1000 == 0 {
        format!("{}.{:03}Z", dt.format("%Y-%m-%dT%H:%M:%S"), us / 1000)
    } else {
        format!("{}.{:06}Z", dt.format("%Y-%m-%dT%H:%M:%S"), us)
    }
}

/// ISO text with the offset of `tz` (Python `isoformat()` of an aware datetime): fraction only when non-zero.
pub fn to_iso_in(ts: Ts, tz: &chrono_tz::Tz) -> String {
    let dt = utc(ts).with_timezone(tz);
    let us = ts.rem_euclid(SECOND);
    let base = dt.format("%Y-%m-%dT%H:%M:%S").to_string();
    let off = dt.format("%:z").to_string();
    if us == 0 { format!("{base}{off}") } else { format!("{base}.{us:06}{off}") }
}

fn local_tz() -> chrono_tz::Tz {
    static TZ: OnceLock<chrono_tz::Tz> = OnceLock::new();
    *TZ.get_or_init(|| {
        std::env::var("TZ")
            .ok()
            .or_else(|| iana_time_zone::get_timezone().ok())
            .and_then(|n| n.trim_start_matches(':').parse().ok())
            .unwrap_or(chrono_tz::UTC)
    })
}

/// ElastAlert's `pretty_ts`: `YYYY-MM-DD HH:MM TZ`, local time unless `local` is false.
pub fn pretty(ts: Ts, local: bool, fmt: Option<&str>) -> String {
    let fmt = fmt.unwrap_or("%Y-%m-%d %H:%M %Z");
    if local {
        utc(ts).with_timezone(&local_tz()).format(fmt).to_string()
    } else {
        utc(ts).format(fmt).to_string()
    }
}

/// Python `str(timedelta)`: `0:15:00`, `1 day, 2:00:00`.
pub fn pretty_duration(d: Dur) -> String {
    let secs = d.div_euclid(SECOND);
    let us = d.rem_euclid(SECOND);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let mut s = String::new();
    if days != 0 {
        s = format!("{days} day{}, ", if days.abs() != 1 { "s" } else { "" });
    }
    s += &format!("{}:{:02}:{:02}", rem / 3600, rem % 3600 / 60, rem % 60);
    if us != 0 {
        s += &format!(".{us:06}");
    }
    s
}

// ---- timestamp_type: custom ----

#[derive(Clone, Copy, Debug, PartialEq)]
enum Tok {
    Lit(char),
    Year,
    Month,
    Day,
    Hour,
    Minute,
    Second,
    Micro,
    Offset,
}

/// One term of a `timestamp_format_expr` / `timestamp_to_datetime_format_expr`: a string literal or `ts[a:b]`.
#[derive(Clone, Debug, PartialEq)]
enum Part {
    Lit(String),
    Slice(Option<i64>, Option<i64>),
}

/// `timestamp_type: custom`: Python `strftime` / `strptime` formats plus the two optional `ts` expressions.
/// Upstream evaluates the expressions with Python `eval`; only `'literal'` and `ts[a:b]` joined by `+` are accepted,
/// anything else is rejected at load.
#[derive(Clone, Debug)]
pub struct CustomTs {
    format: Vec<Tok>,
    format_expr: Option<Vec<Part>>,
    parse_expr: Option<Vec<Part>>,
}

impl CustomTs {
    pub fn new(format: &str, format_expr: Option<&str>, parse_expr: Option<&str>) -> Result<CustomTs> {
        let mut toks = Vec::new();
        let mut it = format.chars();
        while let Some(c) = it.next() {
            toks.push(match c {
                '%' => match it.next() {
                    Some('Y') => Tok::Year,
                    Some('m') => Tok::Month,
                    Some('d') => Tok::Day,
                    Some('H') => Tok::Hour,
                    Some('M') => Tok::Minute,
                    Some('S') => Tok::Second,
                    Some('f') => Tok::Micro,
                    Some('z') => Tok::Offset,
                    Some('%') => Tok::Lit('%'),
                    d => bail!("timestamp_format {format:?}: directive %{} is not supported (%Y %m %d %H %M %S %f %z %%)", d.unwrap_or(' ')),
                },
                c => Tok::Lit(c),
            });
        }
        let expr = |name: &str, e: Option<&str>| e.map(|e| parse_ts_expr(e).with_context(|| format!("{name} {e:?}"))).transpose();
        Ok(CustomTs { format: toks, format_expr: expr("timestamp_format_expr", format_expr)?, parse_expr: expr("timestamp_to_datetime_format_expr", parse_expr)? })
    }

    /// Python `dt_to_ts_with_format` followed by `timestamp_format_expr`.
    pub fn format(&self, ts: Ts) -> String {
        use chrono::{Datelike, Timelike};
        let dt = utc(ts);
        let mut out = String::new();
        for t in &self.format {
            match t {
                Tok::Lit(c) => out.push(*c),
                Tok::Year => out += &format!("{:04}", dt.year()),
                Tok::Month => out += &format!("{:02}", dt.month()),
                Tok::Day => out += &format!("{:02}", dt.day()),
                Tok::Hour => out += &format!("{:02}", dt.hour()),
                Tok::Minute => out += &format!("{:02}", dt.minute()),
                Tok::Second => out += &format!("{:02}", dt.second()),
                Tok::Micro => out += &format!("{:06}", ts.rem_euclid(SECOND)),
                Tok::Offset => out += "+0000",
            }
        }
        match &self.format_expr {
            Some(e) => eval_ts_expr(e, &out),
            None => out,
        }
    }

    /// `timestamp_to_datetime_format_expr` followed by Python `strptime`; no offset means UTC.
    pub fn parse(&self, s: &str) -> Option<Ts> {
        let s = match &self.parse_expr {
            Some(e) => eval_ts_expr(e, s),
            None => s.to_string(),
        };
        let mut rest = s.as_str();
        let (mut y, mut mo, mut d, mut h, mut mi, mut sec, mut us, mut off) = (1900, 1, 1, 0, 0, 0, 0, 0i64);
        for t in &self.format {
            match t {
                Tok::Lit(' ') => {
                    let n = rest.len() - rest.trim_start().len();
                    (n > 0).then_some(())?;
                    rest = &rest[n..];
                }
                Tok::Lit(c) => rest = rest.strip_prefix(*c)?,
                Tok::Year => y = digits(&mut rest, 4, 4)? as i32,
                Tok::Month => mo = digits(&mut rest, 1, 2)?,
                Tok::Day => d = digits(&mut rest, 1, 2)?,
                Tok::Hour => h = digits(&mut rest, 1, 2)?,
                Tok::Minute => mi = digits(&mut rest, 1, 2)?,
                Tok::Second => sec = digits(&mut rest, 1, 2)?,
                Tok::Micro => {
                    let n = rest.bytes().take(6).take_while(u8::is_ascii_digit).count();
                    us = digits(&mut rest, 1, 6)? * 10u32.pow(6 - n as u32);
                }
                Tok::Offset => {
                    if let Some(r) = rest.strip_prefix('Z') {
                        rest = r;
                    } else {
                        let sign = match rest.chars().next()? {
                            '+' => 1,
                            '-' => -1,
                            _ => return None,
                        };
                        rest = &rest[1..];
                        let hh = digits(&mut rest, 2, 2)?;
                        rest = rest.strip_prefix(':').unwrap_or(rest);
                        off = sign * (hh as i64 * 3600 + digits(&mut rest, 2, 2)? as i64 * 60);
                    }
                }
            }
        }
        rest.is_empty().then_some(())?;
        let naive = NaiveDate::from_ymd_opt(y, mo, d)?.and_hms_micro_opt(h, mi, sec, us)?;
        Some(naive.and_utc().timestamp_micros() - off * SECOND)
    }
}

/// Reads `min..=max` leading ASCII digits.
fn digits(s: &mut &str, min: usize, max: usize) -> Option<u32> {
    let n = s.bytes().take(max).take_while(u8::is_ascii_digit).count();
    (n >= min).then_some(())?;
    let v = s[..n].parse().ok()?;
    *s = &s[n..];
    Some(v)
}

fn parse_ts_expr(src: &str) -> Result<Vec<Part>> {
    let unsupported = || anyhow::anyhow!("not supported: only 'literal' and ts[a:b] joined by + are (it is a Python expression upstream)");
    let mut parts = Vec::new();
    let mut rest = src.trim();
    loop {
        if let Some(q) = rest.chars().next().filter(|c| *c == '\'' || *c == '"') {
            let end = rest[1..].find(q).ok_or_else(unsupported)? + 1;
            let lit = &rest[1..end];
            if lit.contains('\\') {
                return Err(unsupported());
            }
            parts.push(Part::Lit(lit.to_string()));
            rest = &rest[end + 1..];
        } else if let Some(r) = rest.strip_prefix("ts[") {
            let end = r.find(']').ok_or_else(unsupported)?;
            let (a, b) = r[..end].split_once(':').ok_or_else(unsupported)?;
            let bound = |x: &str| match x.trim() {
                "" => Ok(None),
                n => n.parse().map(Some).map_err(|_| unsupported()),
            };
            parts.push(Part::Slice(bound(a)?, bound(b)?));
            rest = &r[end + 1..];
        } else {
            return Err(unsupported());
        }
        rest = rest.trim_start();
        match rest.strip_prefix('+') {
            Some(r) => rest = r.trim_start(),
            None if rest.is_empty() => return Ok(parts),
            None => return Err(unsupported()),
        }
    }
}

/// Python slice semantics on characters: negative bounds count from the end, out-of-range bounds are clamped.
fn eval_ts_expr(parts: &[Part], ts: &str) -> String {
    let chars: Vec<char> = ts.chars().collect();
    let n = chars.len() as i64;
    let bound = |b: Option<i64>, default: i64| b.map_or(default, |b| if b < 0 { b + n } else { b }.clamp(0, n)) as usize;
    parts
        .iter()
        .map(|p| match p {
            Part::Lit(s) => s.clone(),
            Part::Slice(a, b) => {
                let (a, b) = (bound(*a, 0), bound(*b, n));
                chars[a..a.max(b)].iter().collect()
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_roundtrip_matches_python_format() {
        let t = parse_iso("2024-03-01T10:00:00Z").unwrap();
        assert_eq!(to_iso(t), "2024-03-01T10:00:00Z");
        assert_eq!(to_iso(t + 120_000), "2024-03-01T10:00:00.120Z");
        assert_eq!(to_iso(t + 123_456), "2024-03-01T10:00:00.123456Z");
        assert_eq!(parse_iso("2024-03-01T12:00:00+02:00"), Some(t));
        assert_eq!(parse_iso("2024-03-01 10:00:00"), Some(t));
        assert_eq!(parse_iso("2024-03-01T10:00:00.000+0000"), Some(t));
    }

    #[test]
    fn custom_timestamp_graylog_and_docs_examples() {
        // Graylog "yyyy-MM-dd HH:mm:ss.SSS" mapping, Python %f gives 6 digits, ts[:23] cuts to ms.
        let c = CustomTs::new("%Y-%m-%d %H:%M:%S.%f", Some("ts[:23]"), None).unwrap();
        let t = parse_iso("2026-09-16T23:58:06.271Z").unwrap();
        assert_eq!(c.format(t), "2026-09-16 23:58:06.271");
        assert_eq!(c.parse("2026-09-16 23:58:06.271"), Some(t));
        assert_eq!(c.parse("2026-09-16 23:58:06.27"), Some(t - 1_000));
        assert_eq!(c.parse("2026-09-16 23:58:06"), None);
        assert_eq!(c.parse("2026-09-16 23:58:06.271x"), None);
        // upstream docs
        let c = CustomTs::new("%Y-%m-%dT%H:%M:%S.%fZ", Some("ts[:23] + ts[26:]"), None).unwrap();
        assert_eq!(c.format(t), "2026-09-16T23:58:06.271Z");
        let c = CustomTs::new("%Y-%m-%dT%H:%M:%S.%f", None, Some("ts[:23]")).unwrap();
        assert_eq!(c.parse("2026-09-16T23:58:06.271123456"), Some(t));
        // default format, negative and clamped bounds, offsets
        let c = CustomTs::new("%Y-%m-%dT%H:%M:%SZ", Some("ts[:-1] + 'x' + ts[-1:99]"), None).unwrap();
        assert_eq!(c.format(parse_iso("2024-03-01T10:00:00Z").unwrap()), "2024-03-01T10:00:00xZ");
        let c = CustomTs::new("%Y-%m-%d %H:%M:%S %z", None, None).unwrap();
        let t = parse_iso("2024-03-01T10:00:00Z").unwrap();
        assert_eq!(c.format(t), "2024-03-01 10:00:00 +0000");
        assert_eq!(c.parse("2024-03-01 12:00:00 +02:00"), Some(t));
        assert_eq!(c.parse("2024-03-01  10:00:00 Z"), Some(t));
    }

    #[test]
    fn custom_timestamp_rejects_what_it_cannot_run() {
        let err = |f: &str, e: Option<&str>| format!("{:#}", CustomTs::new(f, e, None).unwrap_err());
        assert!(err("%b %d", None).contains("%b is not supported"));
        for e in ["dt.year", "ts.replace('a','b')", "ts[3]", "__import__('os')", "ts[:3] +", "'a\\n'"] {
            assert!(err("%Y", Some(e)).contains("not supported"), "{e}");
        }
    }

    #[test]
    fn durations() {
        assert_eq!(pretty_duration(15 * MINUTE), "0:15:00");
        assert_eq!(pretty_duration(26 * 60 * MINUTE), "1 day, 2:00:00");
        assert_eq!(parse_duration_map(&serde_json::json!({"minutes": 15})).unwrap(), 15 * MINUTE);
        assert_eq!(parse_duration_arg("hours=2").unwrap(), 120 * MINUTE);
    }
}
