//! Rule types: they receive query results and emit matches. State is per rule (never shared).

use crate::correlation::{Progress, Query};
use crate::es::Es;
use crate::field::{self, py_str};
use crate::rule::{Kind, Rule, TsType};
use crate::time::{Dur, Ts, pretty, pretty_duration, to_iso};
use anyhow::Result;
use rustc_hash::{FxHashMap, FxHashSet};
use serde_json::{Map, Value, json};
use std::collections::VecDeque;

pub type Doc = Map<String, Value>;

/// One hit from Elasticsearch with its parsed timestamp.
#[derive(Clone)]
pub struct Event {
    pub ts: Ts,
    pub doc: Doc,
}

impl Event {
    fn placeholder(rule: &Rule, ts: Ts, qk: Option<Value>) -> Event {
        let mut doc = Doc::new();
        doc.insert(rule.timestamp_field.clone(), json!(to_iso(ts)));
        doc.insert("placeholder".into(), json!(true));
        if let (Some(k), Some(v)) = (&rule.query_key, qk) {
            doc.insert(k.clone(), v);
        }
        Event { ts, doc }
    }

    fn is_placeholder(&self) -> bool {
        self.doc.contains_key("placeholder")
    }
}

/// A Python number: counts and sums stay integers until a float is added (`0` vs `0.0` shows in alerts).
#[derive(Clone, Copy, Debug)]
pub enum Num {
    I(i64),
    F(f64),
}

impl Num {
    fn f(self) -> f64 {
        match self {
            Num::I(i) => i as f64,
            Num::F(f) => f,
        }
    }

    fn json(self) -> Value {
        match self {
            Num::I(i) => json!(i),
            Num::F(f) => json!(f),
        }
    }

    fn from_json(v: &Value) -> Option<Num> {
        v.as_i64().map(Num::I).or_else(|| v.as_f64().map(Num::F))
    }

    fn plus(self, o: Num, sign: i64) -> Num {
        match (self, o) {
            (Num::I(a), Num::I(b)) => Num::I(a + sign * b),
            (a, b) => Num::F(a.f() + sign as f64 * b.f()),
        }
    }
}

/// Time-ordered events covering less than `timeframe`. Oldest are evicted on append.
pub struct EventWindow {
    timeframe: Dur,
    data: VecDeque<(Event, Num)>,
    count: Num,
}

impl EventWindow {
    pub fn new(timeframe: Dur) -> Self {
        EventWindow { timeframe, data: VecDeque::new(), count: Num::I(0) }
    }

    /// Inserts in timestamp order (after equal timestamps) and evicts while the span >= timeframe.
    /// Returns what was evicted, oldest first.
    pub fn append(&mut self, ev: Event, count: Num) -> Vec<(Event, Num)> {
        let pos = self.data.partition_point(|(e, _)| e.ts <= ev.ts);
        self.data.insert(pos, (ev, count));
        if count.f() != 0.0 {
            self.count = self.count.plus(count, 1);
        }
        let mut evicted = Vec::new();
        while self.duration() >= self.timeframe {
            let Some(old) = self.data.pop_front() else { break };
            if old.1.f() != 0.0 {
                self.count = self.count.plus(old.1, -1);
            }
            evicted.push(old);
        }
        evicted
    }

    fn duration(&self) -> Dur {
        match (self.data.front(), self.data.back()) {
            (Some(a), Some(b)) => b.0.ts - a.0.ts,
            _ => 0,
        }
    }

    pub fn count(&self) -> Num {
        self.count
    }

    fn clear(&mut self) {
        self.data.clear();
        self.count = Num::I(0);
    }

    pub fn last_ts(&self) -> Option<Ts> {
        self.data.back().map(|(e, _)| e.ts)
    }

    /// Mean of the counts (the field values) of non-placeholder entries.
    fn mean(&self) -> Option<f64> {
        let vals: Vec<f64> = self.data.iter().filter(|(e, _)| !e.is_placeholder()).map(|(_, c)| c.f()).collect();
        (!vals.is_empty()).then(|| vals.iter().sum::<f64>() / vals.len() as f64)
    }

    /// Smallest / largest value (the first one on ties), placeholders (0) included like upstream.
    fn min(&self) -> Option<Num> {
        self.data.iter().map(|(_, c)| *c).reduce(|a, b| if b.f() < a.f() { b } else { a })
    }

    fn max(&self) -> Option<Num> {
        self.data.iter().map(|(_, c)| *c).reduce(|a, b| if b.f() > a.f() { b } else { a })
    }
}

/// Converts the parsed timestamp back to the rule's wire format (ElastAlert's `add_match`).
pub fn ts_value(rule: &Rule, ts: Ts) -> Value {
    match rule.timestamp_type {
        TsType::Iso => json!(to_iso(ts)),
        TsType::Unix => json!(ts.div_euclid(1_000_000)),
        TsType::UnixMs => json!(ts.div_euclid(1_000)),
    }
}

fn into_match(rule: &Rule, mut ev: Event) -> Doc {
    let v = ts_value(rule, ev.ts);
    if !field::set(&mut ev.doc, &rule.timestamp_field, v.clone()) {
        ev.doc.insert(rule.timestamp_field.clone(), v);
    }
    ev.doc
}

const ALL: &str = "\"all\"";

/// Group key: JSON text of the query_key value (so `1` and `"1"` stay apart, like Python dict keys).
fn group_key(rule: &Rule, doc: &Doc) -> String {
    match &rule.query_key {
        Some(qk) => field::lookup(doc, qk).map_or_else(|| "null".into(), Value::to_string),
        None => ALL.into(),
    }
}

fn key_value(key: &str) -> Value {
    serde_json::from_str(key).unwrap_or_else(|_| json!(key))
}

/// Python truthiness of a JSON value.
fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
        Some(Value::Bool(true)) => true,
    }
}

fn opt_f64(rule: &Rule, key: &str) -> Option<f64> {
    rule.raw.get(key).and_then(Value::as_f64)
}

fn opt_bool(rule: &Rule, key: &str) -> bool {
    rule.raw.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn tf(rule: &Rule) -> Dur {
    rule.timeframe.unwrap_or_default()
}

pub enum RuleType {
    Any,
    Frequency(Frequency),
    Spike(Spike),
    Flatline(Flatline),
    Compare(Compare),
    NewTerm(NewTerm),
    Cardinality(Cardinality),
    MetricAgg(MetricAgg),
    Percentage(Percentage),
    Correlation(Correlation),
}

impl RuleType {
    pub fn new(rule: &Rule) -> Result<Self> {
        Ok(match rule.kind {
            Kind::Any => RuleType::Any,
            Kind::Frequency => RuleType::Frequency(Frequency::default()),
            Kind::Spike => RuleType::Spike(Spike::new(rule)),
            Kind::Flatline => RuleType::Flatline(Flatline::new(rule)),
            Kind::Blacklist | Kind::Whitelist | Kind::Change => RuleType::Compare(Compare::new(rule)?),
            Kind::NewTerm => RuleType::NewTerm(NewTerm::new(rule)?),
            Kind::Cardinality => RuleType::Cardinality(Cardinality::new(rule)),
            Kind::MetricAggregation => RuleType::MetricAgg(MetricAgg::new(rule)),
            Kind::PercentageMatch => RuleType::Percentage(Percentage::new(rule)),
            Kind::SpikeAggregation => RuleType::Spike(Spike::new(rule)),
            Kind::Correlation => RuleType::Correlation(Correlation::new(rule)),
        })
    }

    /// One-time async setup (new_term loads existing terms). Safe to call every run.
    pub async fn init(&mut self, rule: &Rule, es: &Es, end: Option<Ts>) -> Result<()> {
        match self {
            RuleType::NewTerm(n) => n.init(rule, es, end).await,
            _ => Ok(()),
        }
    }

    pub fn add_data(&mut self, rule: &Rule, events: Vec<Event>, matches: &mut Vec<Doc>) {
        match self {
            RuleType::Any => matches.extend(events.into_iter().map(|e| into_match(rule, e))),
            RuleType::Frequency(f) => f.add_data(rule, events, matches),
            RuleType::Spike(s) => s.add_data(rule, events, matches),
            RuleType::Flatline(f) => f.add_data(rule, events, matches),
            RuleType::Compare(c) => c.add_data(rule, events, matches),
            RuleType::NewTerm(n) => n.add_data(rule, events, matches),
            RuleType::Cardinality(c) => c.add_data(rule, events, matches),
            // Correlation events arrive tagged with their leaves, through `add_correlation`.
            RuleType::MetricAgg(_) | RuleType::Percentage(_) | RuleType::Correlation(_) => {}
        }
    }

    /// Events of every leaf of a `correlation` rule for one query range, oldest first, each with the leaves it matched.
    pub fn add_correlation(&mut self, rule: &Rule, events: Vec<(Vec<usize>, Event)>, matches: &mut Vec<Doc>) {
        if let RuleType::Correlation(c) = self {
            c.add_events(rule, events, matches);
        }
    }

    /// `correlation`: matches completing at or before `ts` were alerted before a restart; replaying them only rebuilds state.
    pub fn suppress_until(&mut self, ts: Ts) {
        if let RuleType::Correlation(c) = self {
            c.suppress_until = Some(ts);
        }
    }

    /// Result of an aggregation query (`Kind::is_agg_query`): `payload` is the response's `aggregations`.
    pub fn add_aggregation(&mut self, rule: &Rule, ts: Ts, payload: &Value, matches: &mut Vec<Doc>) {
        match self {
            RuleType::MetricAgg(a) => walk_buckets(ts, payload, &mut |t, qk, b| a.check(rule, t, qk, b, matches)),
            RuleType::Percentage(p) => walk_buckets(ts, payload, &mut |t, qk, b| p.check(rule, t, qk, b, matches)),
            RuleType::Spike(s) => s.add_aggregation(rule, ts, payload, matches),
            _ => {}
        }
    }

    /// Result of a count query: `count` documents up to `ts`.
    pub fn add_count(&mut self, rule: &Rule, ts: Ts, count: i64, matches: &mut Vec<Doc>) {
        let ev = || Event { ts, doc: Doc::from_iter([(rule.timestamp_field.clone(), json!(to_iso(ts)))]) };
        match self {
            RuleType::Frequency(f) => f.add_one(rule, ALL.into(), ev(), count, matches),
            RuleType::Spike(s) => s.handle_event(rule, ev(), Num::I(count), ALL.into(), matches),
            RuleType::Flatline(f) => f.add_counted(rule, ALL.into(), ev(), count, matches),
            _ => {}
        }
    }

    /// Result of a terms query: one bucket per `query_key` value.
    pub fn add_terms(&mut self, rule: &Rule, ts: Ts, buckets: &[(Value, i64)], matches: &mut Vec<Doc>) {
        let Some(qk) = rule.query_key.clone() else { return };
        for (key, count) in buckets {
            let ev = Event { ts, doc: Doc::from_iter([(rule.timestamp_field.clone(), json!(to_iso(ts))), (qk.clone(), key.clone())]) };
            let k = key.to_string();
            match self {
                RuleType::Frequency(f) => f.add_one(rule, k, ev, *count, matches),
                RuleType::Spike(s) => s.handle_event(rule, ev, Num::I(*count), k, matches),
                RuleType::Flatline(f) => f.add_counted(rule, k, ev, *count, matches),
                RuleType::NewTerm(n) => n.add_term_bucket(rule, ts, &qk, key, matches),
                _ => {}
            }
        }
    }

    /// Called with the end of each queried segment; drops stale state and may produce matches
    /// (flatline, spike placeholders, min_cardinality).
    pub fn garbage_collect(&mut self, rule: &Rule, ts: Ts, matches: &mut Vec<Doc>) {
        match self {
            RuleType::Frequency(f) => f.occurrences.retain(|_, w| w.last_ts().is_some_and(|t| ts - t <= tf(rule))),
            RuleType::Spike(s) => s.garbage_collect(rule, ts, matches),
            RuleType::Flatline(f) => f.garbage_collect(rule, ts, matches),
            RuleType::Cardinality(c) => c.garbage_collect(rule, ts, matches),
            RuleType::Correlation(c) => c.garbage_collect(rule, ts, matches),
            _ => {}
        }
    }

    /// Silence key part for rules whose matches don't carry the query_key (flatline).
    pub fn silence_key(&self, m: &Doc) -> Option<String> {
        matches!(self, RuleType::Flatline(_)).then(|| m.get("key").map(py_str)).flatten()
    }

    /// Query filters this type adds (blacklist / whitelist terms).
    pub fn extra_filter(&self, rule: &Rule) -> Option<Value> {
        match self {
            RuleType::Compare(c) => c.extra_filter(rule),
            _ => None,
        }
    }

    /// The type-specific sentence in the alert body.
    pub fn match_str(&self, rule: &Rule, m: &Doc, ts_fmt: Option<&str>) -> String {
        let ts = || field::lookup(m, &rule.timestamp_field).and_then(|v| parse_ts(rule, v));
        let lt = rule.use_local_time;
        match self {
            RuleType::Frequency(_) => {
                let Some(ts) = ts() else { return String::new() };
                let start = pretty(ts - tf(rule), lt, ts_fmt);
                let end = pretty(ts, lt, ts_fmt);
                format!("At least {} events occurred between {start} and {end}\n\n", rule.num_events)
            }
            RuleType::Spike(s) => {
                let Some(ts) = ts() else { return String::new() };
                let at = pretty(ts, lt, ts_fmt);
                if let Some(t) = &s.agg_type {
                    let key = rule.raw.get("metric_agg_key").map(py_str).unwrap_or_default();
                    let round = |k: &str| m.get(k).map_or_else(|| "None".into(), round2);
                    return format!(
                        "An abnormal {t} of {key} ({}) occurred around {at}.\nPreceding that time, there was a {t} of {key} of ({}) within {}\n\n",
                        round("spike_count"),
                        round("reference_count"),
                        pretty_duration(tf(rule))
                    );
                }
                let (cur, refc) = (m.get("spike_count").and_then(Value::as_f64).unwrap_or(0.0), m.get("reference_count").and_then(Value::as_f64).unwrap_or(0.0));
                match &s.field_value {
                    None => format!(
                        "An abnormal number ({}) of events occurred around {at}.\nPreceding that time, there were only {} events within {}\n\n",
                        cur as i64,
                        refc as i64,
                        pretty_duration(tf(rule))
                    ),
                    Some(f) => format!(
                        "An abnormal average value ({cur:.2}) of field '{f}' occurred around {at}.\nPreceding that time, the field had an average value of ({refc:.2}) within {}\n\n",
                        pretty_duration(tf(rule))
                    ),
                }
            }
            RuleType::Flatline(f) => {
                let Some(ts) = ts() else { return String::new() };
                format!(
                    "An abnormally low number of events occurred around {}.\nBetween {} and {}, there were less than {} events.\n\n",
                    pretty(ts, lt, ts_fmt),
                    pretty(ts - tf(rule), lt, ts_fmt),
                    pretty(ts, lt, ts_fmt),
                    py_str(&f.threshold)
                )
            }
            RuleType::Cardinality(c) => {
                let Some(ts) = ts() else { return String::new() };
                let (start, end) = (pretty(ts - tf(rule), lt, ts_fmt), pretty(ts, lt, ts_fmt));
                match c.max {
                    Some(max) => format!("A maximum of {} unique {}(s) occurred since last alert or between {start} and {end}\n\n", py_num(max), c.field),
                    None => format!("Less than {} unique {}(s) occurred since last alert or between {start} and {end}\n\n", py_num(c.min.unwrap_or(0.0)), c.field),
                }
            }
            RuleType::Correlation(c) => c.match_str(rule, m, ts_fmt),
            RuleType::MetricAgg(a) => {
                let shown = m.get(&a.key).map_or_else(|| "None".into(), |v| rule.raw.get("metric_format_string").and_then(Value::as_str).map_or_else(|| py_str(v), |f| format_number(f, v)));
                let opt = |k: &str| rule.raw.get(k).map_or_else(|| "None".into(), py_str);
                format!(
                    "Threshold violation, {}:{} {shown} (min: {} max : {}) \n\n",
                    a.ty,
                    rule.raw.get("metric_agg_key").map(py_str).unwrap_or_default(),
                    opt("min_threshold"),
                    opt("max_threshold")
                )
            }
            RuleType::Percentage(_) => {
                let pct = m.get("percentage");
                let shown = pct.map_or_else(|| "None".into(), |v| rule.raw.get("percentage_format_string").and_then(Value::as_str).map_or_else(|| py_str(v), |f| format_number(f, v)));
                let opt = |k: &str| rule.raw.get(k).map_or_else(|| "None".into(), py_str);
                format!(
                    "Percentage violation, value: {shown} (min: {} max : {}) of {} items\n\n",
                    opt("min_percentage"),
                    opt("max_percentage"),
                    m.get("denominator").map_or_else(|| "None".into(), py_str)
                )
            }
            _ => String::new(),
        }
    }
}

/// Python `round(x, 2)` printed with `str()`: integers stay integers.
fn round2(v: &Value) -> String {
    match v.as_f64() {
        Some(f) if !v.is_i64() && !v.is_u64() => py_str(&json!(format!("{f:.2}").parse::<f64>().unwrap_or(f))),
        _ => py_str(v),
    }
}

/// `'{:.2f}'.format(v)` and `'%.2f' % v` for the specs used on metrics (`f`, `%`, `d`, `.N` precision);
/// anything else prints like `str(v)`.
fn format_number(fmt: &str, v: &Value) -> String {
    let f = v.as_f64().unwrap_or(f64::NAN);
    let one = |spec: &str| {
        let (prec, ty) = match spec.rsplit_once('.') {
            Some((_, p)) => (p.trim_end_matches(|c: char| c.is_ascii_alphabetic() || c == '%').parse::<usize>().ok(), spec.chars().last()),
            None => (None, spec.chars().last()),
        };
        match ty {
            Some('f' | 'F') => format!("{f:.*}", prec.unwrap_or(6)),
            Some('%') => format!("{:.*}%", prec.unwrap_or(6), f * 100.0),
            Some('d' | 'i') => format!("{}", f as i64),
            _ => py_str(v),
        }
    };
    if let (true, Some(end)) = (fmt.starts_with('{'), fmt.find('}')) {
        let spec = fmt[1..end].split_once(':').map_or("", |(_, s)| s);
        return format!("{}{}", one(spec), &fmt[end + 1..]);
    }
    let (mut out, mut chars) = (String::new(), fmt.chars().peekable());
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
        } else if chars.peek() == Some(&'%') {
            chars.next();
            out.push('%');
        } else {
            let mut spec = String::new();
            for n in chars.by_ref() {
                spec.push(n);
                if n.is_ascii_alphabetic() {
                    break;
                }
            }
            out.push_str(&one(&spec));
        }
    }
    out
}

fn py_num(f: f64) -> String {
    if f.fract() == 0.0 { format!("{}", f as i64) } else { f.to_string() }
}

/// Reads a timestamp value according to `timestamp_type`.
pub fn parse_ts(rule: &Rule, v: &Value) -> Option<Ts> {
    match (rule.timestamp_type, v) {
        (TsType::Iso, Value::String(s)) => crate::time::parse_iso(s),
        (TsType::Unix, v) => num(v).map(|n| (n * 1e6) as Ts),
        (TsType::UnixMs, v) => num(v).map(|n| (n * 1e3) as Ts),
        _ => None,
    }
}

fn num(v: &Value) -> Option<f64> {
    v.as_f64().or_else(|| v.as_str()?.parse().ok())
}

// ---- frequency ----

#[derive(Default)]
pub struct Frequency {
    occurrences: FxHashMap<String, EventWindow>,
}

impl Frequency {
    fn add_data(&mut self, rule: &Rule, events: Vec<Event>, matches: &mut Vec<Doc>) {
        for ev in events {
            let key = group_key(rule, &ev.doc);
            self.add_one(rule, key, ev, 1, matches);
        }
    }

    fn add_one(&mut self, rule: &Rule, key: String, ev: Event, count: i64, matches: &mut Vec<Doc>) {
        let window = self.occurrences.entry(key.clone()).or_insert_with(|| EventWindow::new(tf(rule)));
        window.append(ev, Num::I(count));
        if window.count().f() >= rule.num_events as f64 {
            let mut w = self.occurrences.remove(&key).expect("window just used");
            let (last, _) = w.data.pop_back().expect("non-empty window");
            let mut m = into_match(rule, last);
            if rule.attach_related {
                let related: Vec<Value> = w.data.into_iter().map(|(e, _)| Value::Object(into_match(rule, e))).collect();
                m.insert("related_events".into(), Value::Array(related));
            }
            matches.push(m);
        }
    }
}

// ---- flatline ----

pub struct Flatline {
    occurrences: FxHashMap<String, EventWindow>,
    first_event: FxHashMap<String, Ts>,
    threshold: Value,
}

impl Flatline {
    fn new(rule: &Rule) -> Self {
        Flatline { occurrences: FxHashMap::default(), first_event: FxHashMap::default(), threshold: rule.raw.get("threshold").cloned().unwrap_or(json!(0)) }
    }

    fn add_counted(&mut self, rule: &Rule, key: String, ev: Event, count: i64, matches: &mut Vec<Doc>) {
        self.occurrences.entry(key.clone()).or_insert_with(|| EventWindow::new(tf(rule))).append(ev, Num::I(count));
        self.check(rule, &key, matches);
    }

    fn add_data(&mut self, rule: &Rule, events: Vec<Event>, matches: &mut Vec<Doc>) {
        let mut last_key = None;
        for ev in events {
            let key = group_key(rule, &ev.doc);
            self.occurrences.entry(key.clone()).or_insert_with(|| EventWindow::new(tf(rule))).append(ev, Num::I(1));
            last_key = Some(key);
        }
        // Like upstream, only the last event's key is checked after a batch; the rest wait for garbage_collect.
        if let Some(k) = last_key.filter(|k| self.occurrences.contains_key(k)) {
            self.check(rule, &k, matches);
        }
    }

    fn check(&mut self, rule: &Rule, key: &str, matches: &mut Vec<Doc>) {
        let Some(window) = self.occurrences.get(key) else { return };
        let Some((last_ev, _)) = window.data.back() else { return };
        let most_recent = last_ev.ts;
        let first = *self.first_event.entry(key.to_string()).or_insert(most_recent);
        if most_recent - first < tf(rule) {
            return;
        }
        let count = window.count().f();
        let threshold = self.threshold.as_f64().unwrap_or(0.0);
        if count < threshold {
            let mut m = into_match(rule, Event { ts: last_ev.ts, doc: last_ev.doc.clone() });
            m.insert("key".into(), key_value(key));
            m.insert("count".into(), json!(count as i64));
            m.insert("threshold".into(), self.threshold.clone());
            matches.push(m);
            if opt_bool(rule, "forget_keys") {
                self.first_event.remove(key);
                self.occurrences.remove(key);
            } else {
                let least_recent = window.data.front().map_or(most_recent, |(e, _)| e.ts);
                self.first_event.insert(key.to_string(), least_recent.min(most_recent - tf(rule)));
            }
        }
    }

    fn garbage_collect(&mut self, rule: &Rule, ts: Ts, matches: &mut Vec<Doc>) {
        let mut keys: Vec<String> = self.occurrences.keys().cloned().collect();
        if keys.is_empty() && rule.query_key.is_none() {
            keys.push(ALL.into());
        }
        for key in keys {
            // A zero-count event slides the window so old events are evicted and absence is noticed.
            let ev = Event { ts, doc: Doc::from_iter([(rule.timestamp_field.clone(), json!(to_iso(ts)))]) };
            self.occurrences.entry(key.clone()).or_insert_with(|| EventWindow::new(tf(rule))).append(ev, Num::I(0));
            self.first_event.entry(key.clone()).or_insert(ts);
            self.check(rule, &key, matches);
        }
    }
}

// ---- spike ----

pub struct Spike {
    ref_windows: FxHashMap<String, EventWindow>,
    cur_windows: FxHashMap<String, EventWindow>,
    first_event: FxHashMap<String, Ts>,
    skip_checks: FxHashMap<String, Ts>,
    ref_filled_once: bool,
    field_value: Option<String>,
    /// `metric_agg_type` of a spike_aggregation rule; the windows then hold aggregated values.
    agg_type: Option<String>,
}

impl Spike {
    fn new(rule: &Rule) -> Self {
        Spike {
            ref_windows: FxHashMap::default(),
            cur_windows: FxHashMap::default(),
            first_event: FxHashMap::default(),
            skip_checks: FxHashMap::default(),
            ref_filled_once: false,
            field_value: (rule.kind == Kind::Spike).then(|| rule.raw.get("field_value").and_then(Value::as_str).map(String::from)).flatten(),
            agg_type: (rule.kind == Kind::SpikeAggregation).then(|| rule.raw.get("metric_agg_type").map(py_str).unwrap_or_default()),
        }
    }

    fn add_data(&mut self, rule: &Rule, events: Vec<Event>, matches: &mut Vec<Doc>) {
        for ev in events {
            let qk = match &rule.query_key {
                Some(q) => match field::lookup(&ev.doc, q) {
                    Some(v) if !v.is_null() => v.to_string(),
                    _ => json!("other").to_string(),
                },
                None => ALL.to_string(),
            };
            match &self.field_value {
                Some(f) => {
                    // Upstream checks the literal top-level key, then reads it by path.
                    if !ev.doc.contains_key(f) {
                        continue;
                    }
                    let Some(v) = field::lookup(&ev.doc, f).filter(|v| !v.is_null()) else { continue };
                    match num(v) {
                        Some(n) => self.handle_event(rule, ev, Num::I(n as i64), qk, matches),
                        None => log::warn!("{f} is not a number: {}", py_str(v)),
                    }
                }
                None => self.handle_event(rule, ev, Num::I(1), qk, matches),
            }
        }
    }

    fn values(&self, qk: &str) -> (Option<Num>, Option<Num>) {
        let (r, c) = (&self.ref_windows[qk], &self.cur_windows[qk]);
        let mean = |w: &EventWindow| w.mean().map(Num::F);
        match self.agg_type.as_deref() {
            Some("avg") => (mean(r), mean(c)),
            Some("min") => (r.min(), c.min()),
            Some("max") => (r.max(), c.max()),
            _ if self.field_value.is_some() => (mean(r), mean(c)),
            _ => (Some(r.count()), Some(c.count())),
        }
    }

    fn find_matches(&self, rule: &Rule, refv: Option<f64>, cur: Option<f64>) -> bool {
        if self.field_value.is_none() && cur.is_some() && refv.is_some() {
            if cur < Some(opt_f64(rule, "threshold_cur").unwrap_or(0.0)) || refv < Some(opt_f64(rule, "threshold_ref").unwrap_or(0.0)) {
                return false;
            }
        } else if refv.is_none_or(|r| r == 0.0) || cur.is_none_or(|c| c == 0.0) {
            return false;
        }
        let (r, c) = (refv.unwrap_or(0.0), cur.unwrap_or(0.0));
        let h = opt_f64(rule, "spike_height").unwrap_or(1.0);
        let (down, up) = (c <= r / h, c >= r * h);
        match rule.raw.get("spike_type").and_then(Value::as_str) {
            Some("up") => up,
            Some("down") => down,
            _ => up || down,
        }
    }

    pub fn handle_event(&mut self, rule: &Rule, ev: Event, count: Num, qk: String, matches: &mut Vec<Doc>) {
        let timeframe = tf(rule);
        let ev_ts = ev.ts;
        self.first_event.entry(qk.clone()).or_insert(ev_ts);
        self.ref_windows.entry(qk.clone()).or_insert_with(|| EventWindow::new(timeframe));
        let evicted = self.cur_windows.entry(qk.clone()).or_insert_with(|| EventWindow::new(timeframe)).append(ev, count);
        let ref_w = self.ref_windows.get_mut(&qk).expect("inserted above");
        for (e, c) in evicted {
            ref_w.append(e, c);
        }

        if ev_ts - self.first_event[&qk] < 2 * timeframe {
            if !self.ref_filled_once {
                return;
            }
            if !(rule.query_key.is_some() && opt_bool(rule, "alert_on_new_data")) {
                return;
            }
            if self.skip_checks.get(&qk).is_some_and(|until| ev_ts < *until) {
                return;
            }
        } else {
            self.ref_filled_once = true;
        }

        let (refv, cur) = self.values(&qk);
        if !self.find_matches(rule, refv.map(Num::f), cur.map(Num::f)) {
            return;
        }
        let w = &self.cur_windows[&qk];
        let pick = if self.field_value.is_some() { w.data.iter().find(|(e, _)| !e.is_placeholder()) } else { w.data.iter().find(|(_, c)| c.f() != 0.0) };
        let Some((src, _)) = pick.or(w.data.back()) else { return };
        let (m_ts, mut m) = (src.ts, into_match(rule, Event { ts: src.ts, doc: src.doc.clone() }));
        m.insert("spike_count".into(), cur.map_or(Value::Null, Num::json));
        m.insert("reference_count".into(), refv.map_or(Value::Null, Num::json));
        matches.push(m);
        self.ref_windows.get_mut(&qk).expect("exists").clear();
        self.first_event.remove(&qk);
        self.skip_checks.insert(qk, m_ts + 2 * timeframe);
    }

    /// `SpikeMetricAggregationRule.add_aggregation_data`: one tracker per (nested) term bucket.
    fn add_aggregation(&mut self, rule: &Rule, ts: Ts, payload: &Value, matches: &mut Vec<Doc>) {
        let node = metric_key(rule);
        match payload.get("bucket_aggs") {
            Some(terms) => self.unwrap_terms(rule, ts, terms, &node, &mut Vec::new(), matches),
            None => {
                // No term split: the whole payload is the aggregation.
                let doc = Doc::from_iter([(rule.timestamp_field.clone(), json!(to_iso(ts)))]);
                if let Some(v) = self.agg_value(&payload[&node]) {
                    self.handle_event(rule, Event { ts, doc }, v, ALL.into(), matches);
                }
            }
        }
    }

    /// A null metric (no document in the bucket) is skipped; upstream fails on it.
    fn agg_value(&self, node: &Value) -> Option<Num> {
        metric_values(self.agg_type.as_deref().unwrap_or_default(), node).first().and_then(Num::from_json)
    }

    fn unwrap_terms(&mut self, rule: &Rule, ts: Ts, terms: &Value, node: &str, path: &mut Vec<String>, matches: &mut Vec<Doc>) {
        for term in terms["buckets"].as_array().into_iter().flatten() {
            path.push(py_str(&term["key"]));
            match term.get("bucket_aggs").filter(|b| truthy(Some(b))) {
                Some(inner) => self.unwrap_terms(rule, ts, inner, node, path, matches),
                None => {
                    if let Some(v) = self.agg_value(&term[node]) {
                        let qk = path.join(",");
                        let mut doc = Doc::from_iter([(rule.timestamp_field.clone(), json!(to_iso(ts)))]);
                        doc.extend(rule.query_key.clone().map(|k| (k, json!(qk))));
                        self.handle_event(rule, Event { ts, doc }, v, json!(qk).to_string(), matches);
                    }
                }
            }
            path.pop();
        }
    }

    fn garbage_collect(&mut self, rule: &Rule, ts: Ts, matches: &mut Vec<Doc>) {
        let keys: Vec<String> = self.cur_windows.keys().cloned().collect();
        for qk in keys {
            if qk != ALL && self.ref_windows[&qk].count().f() == 0.0 && self.cur_windows[&qk].count().f() == 0.0 {
                self.cur_windows.remove(&qk);
                self.ref_windows.remove(&qk);
                continue;
            }
            let ph = Event::placeholder(rule, ts, (qk != ALL).then(|| key_value(&qk)));
            self.handle_event(rule, ph, Num::I(0), qk, matches);
        }
    }
}

// ---- metric_aggregation / percentage_match ----

/// Name of the metric aggregation in the query and the match: `metric_<key>_<type>`.
fn metric_key(rule: &Rule) -> String {
    let get = |k: &str| rule.raw.get(k).map(py_str).unwrap_or_default();
    format!("metric_{}_{}", get("metric_agg_key"), get("metric_agg_type"))
}

/// Metric(s) of an aggregation node: its `value`, or for percentiles the `values` by ascending percent.
fn metric_values(ty: &str, node: &Value) -> Vec<Value> {
    if ty != "percentiles" {
        return vec![node["value"].clone()];
    }
    let mut v: Vec<(f64, &Value)> = node["values"].as_object().into_iter().flatten().map(|(k, v)| (k.parse().unwrap_or(f64::MAX), v)).collect();
    v.sort_by(|a, b| a.0.total_cmp(&b.0));
    v.into_iter().map(|(_, v)| v.clone()).collect()
}

/// Start of a `date_histogram` bucket.
fn bucket_ts(b: &Value) -> Option<Ts> {
    match b["key_as_string"].as_str() {
        Some(s) => crate::time::parse_iso(s),
        None => b["key"].as_f64().map(|ms| (ms * 1e3) as Ts),
    }
}

/// `BaseAggregationRule.add_aggregation_data`: calls `f(timestamp, query_key, bucket)` for every leaf bucket
/// (one per interval, per term, or the payload itself).
fn walk_buckets(ts: Ts, payload: &Value, f: &mut dyn FnMut(Ts, Option<&Value>, &Value)) {
    let intervals = |qk: Option<&Value>, buckets: &Value, f: &mut dyn FnMut(Ts, Option<&Value>, &Value)| {
        for b in buckets.as_array().into_iter().flatten() {
            f(bucket_ts(b).unwrap_or(ts), qk, b);
        }
    };
    if let Some(iv) = payload.get("interval_aggs") {
        intervals(None, &iv["buckets"], f);
    } else if let Some(terms) = payload.get("bucket_aggs") {
        for term in terms["buckets"].as_array().into_iter().flatten() {
            match term.get("interval_aggs") {
                Some(iv) => intervals(Some(&term["key"]), &iv["buckets"], f),
                None => f(ts, Some(&term["key"]), term),
            }
        }
    } else {
        f(ts, None, payload);
    }
}

/// `query_key: a.b` + value -> `{a: {b: value}}` (upstream `expand_string_into_dict`).
fn expand_into(doc: &mut Doc, path: &str, v: Value) {
    fn nested(path: &str, v: Value) -> Value {
        match path.split_once('.') {
            Some((head, rest)) => json!({ head: nested(rest, v) }),
            None => json!({ path: v }),
        }
    }
    match path.split_once('.') {
        Some((head, rest)) => doc.insert(head.into(), nested(rest, v)),
        None => doc.insert(path.into(), v),
    };
}

pub struct MetricAgg {
    key: String,
    ty: String,
    min: Option<f64>,
    max: Option<f64>,
}

impl MetricAgg {
    fn new(rule: &Rule) -> Self {
        MetricAgg { key: metric_key(rule), ty: rule.raw.get("metric_agg_type").map(py_str).unwrap_or_default(), min: opt_f64(rule, "min_threshold"), max: opt_f64(rule, "max_threshold") }
    }

    fn crossed(&self, v: &Value) -> bool {
        v.as_f64().is_some_and(|v| self.max.is_some_and(|m| v > m) || self.min.is_some_and(|m| v < m))
    }

    fn formatted(&self, rule: &Rule, m: &mut Doc, v: &Value) {
        if let Some(f) = rule.raw.get("metric_format_string").and_then(Value::as_str) {
            m.insert(format!("{}_formatted", self.key), json!(format_number(f, v)));
            m.insert("metric_agg_value_formatted".into(), json!(format_number(f, v)));
        }
    }

    fn check(&self, rule: &Rule, ts: Ts, qk: Option<&Value>, bucket: &Value, matches: &mut Vec<Doc>) {
        if !rule.compound_query_key.is_empty() {
            return self.check_nested(rule, ts, bucket, &rule.compound_query_key, &mut Doc::new(), matches);
        }
        let v = metric_values(&self.ty, &bucket[&self.key]).into_iter().next().unwrap_or(Value::Null);
        if !self.crossed(&v) {
            return;
        }
        let mut m = Doc::from_iter([(self.key.clone(), v.clone()), ("metric_agg_value".into(), v.clone())]);
        self.formatted(rule, &mut m, &v);
        if let (Some(q), Some(k)) = (&rule.query_key, qk) {
            expand_into(&mut m, q, k.clone());
        }
        matches.push(into_match(rule, Event { ts, doc: m }));
    }

    /// Compound `query_key`: one terms level per key, the metric sits in the innermost bucket.
    fn check_nested(&self, rule: &Rule, ts: Ts, node: &Value, keys: &[String], data: &mut Doc, matches: &mut Vec<Doc>) {
        let Some(k) = keys.first() else { return };
        data.insert(k.clone(), node["key"].clone());
        if let Some(terms) = node.get("bucket_aggs") {
            for t in terms["buckets"].as_array().into_iter().flatten() {
                self.check_nested(rule, ts, t, &keys[1..], data, matches);
            }
            return;
        }
        let values: Vec<Value> = match node.get("interval_aggs") {
            Some(iv) => iv["buckets"].as_array().into_iter().flatten().map(|b| b[&self.key]["value"].clone()).collect(),
            None => metric_values(&self.ty, &node[&self.key]),
        };
        for v in values.into_iter().filter(|v| self.crossed(v)) {
            data.insert(self.key.clone(), v.clone());
            let joined: Vec<String> = rule.compound_query_key.iter().map(|k| data.get(k).map_or_else(|| "None".into(), py_str)).collect();
            data.insert(rule.query_key.clone().unwrap_or_default(), json!(joined.join(",")));
            self.formatted(rule, data, &v);
            matches.push(into_match(rule, Event { ts, doc: data.clone() }));
        }
    }
}

pub struct Percentage {
    min: Option<f64>,
    max: Option<f64>,
    min_denominator: f64,
}

impl Percentage {
    fn new(rule: &Rule) -> Self {
        Percentage { min: opt_f64(rule, "min_percentage"), max: opt_f64(rule, "max_percentage"), min_denominator: opt_f64(rule, "min_denominator").unwrap_or(0.0) }
    }

    fn check(&self, rule: &Rule, ts: Ts, qk: Option<&Value>, bucket: &Value, matches: &mut Vec<Doc>) {
        let b = &bucket["percentage_match_aggs"]["buckets"];
        let (Some(hit), Some(other)) = (b["match_bucket"]["doc_count"].as_i64(), b["_other_"]["doc_count"].as_i64()) else { return };
        let total = hit + other;
        if total == 0 || (total as f64) < self.min_denominator {
            return;
        }
        let pct = hit as f64 / total as f64 * 100.0;
        if !(self.max.is_some_and(|m| pct > m) || self.min.is_some_and(|m| pct < m)) {
            return;
        }
        let mut m = Doc::from_iter([("percentage".to_string(), json!(pct)), ("denominator".to_string(), json!(total))]);
        if let Some(f) = rule.raw.get("percentage_format_string").and_then(Value::as_str) {
            m.insert("percentage_formatted".into(), json!(format_number(f, &json!(pct))));
        }
        if let (Some(q), Some(k)) = (&rule.query_key, qk) {
            expand_into(&mut m, q, k.clone());
        }
        matches.push(into_match(rule, Event { ts, doc: m }));
    }
}

// ---- blacklist / whitelist / change ----

pub struct Compare {
    kind: Kind,
    key: String,
    keys: Vec<String>,
    list: FxHashSet<String>,
    ignore_null: bool,
    last_values: FxHashMap<String, Vec<Option<Value>>>,
    last_time: FxHashMap<String, Ts>,
    change_map: FxHashMap<String, (Vec<Option<Value>>, Vec<Option<Value>>)>,
}

impl Compare {
    fn new(rule: &Rule) -> Result<Self> {
        let list_name = match rule.kind {
            Kind::Blacklist => "blacklist",
            Kind::Whitelist => "whitelist",
            _ => "",
        };
        let mut list = FxHashSet::default();
        if let Some(Value::Array(entries)) = rule.raw.get(list_name) {
            for e in entries {
                let e = py_str(e);
                match e.strip_prefix("!file") {
                    Some(path) => {
                        let path = path.trim();
                        let text = std::fs::read_to_string(path).map_err(|err| anyhow::anyhow!("{path}: {err}"))?;
                        list.extend(text.lines().map(|l| l.trim_end().to_string()));
                    }
                    None => {
                        list.insert(e);
                    }
                }
            }
        }
        Ok(Compare {
            kind: rule.kind,
            key: rule.compare_key.join(","),
            keys: rule.compare_key.clone(),
            list,
            ignore_null: opt_bool(rule, "ignore_null"),
            last_values: FxHashMap::default(),
            last_time: FxHashMap::default(),
            change_map: FxHashMap::default(),
        })
    }

    /// Terms appended to the query so ES only returns candidates (upstream `enhance_filter`).
    fn extra_filter(&self, rule: &Rule) -> Option<Value> {
        if rule.raw.get("filter_by_list").and_then(Value::as_bool) == Some(false) || self.kind == Kind::Change {
            return None;
        }
        let mut terms: Vec<&String> = self.list.iter().collect();
        terms.sort();
        let parts: Vec<String> = terms
            .into_iter()
            .map(|t| if t.starts_with('/') && t.ends_with('/') { format!("{}:{t}", self.key) } else { format!("{}:\"{t}\"", self.key) })
            .collect();
        let query = if self.kind == Kind::Whitelist { format!("NOT {}", parts.join(" AND NOT ")) } else { parts.join(" OR ") };
        Some(json!({"query_string": {"query": query}}))
    }

    fn add_data(&mut self, rule: &Rule, events: Vec<Event>, matches: &mut Vec<Doc>) {
        for ev in events {
            let hit = match self.kind {
                Kind::Blacklist => field::lookup(&ev.doc, &self.key).and_then(Value::as_str).is_some_and(|t| self.list.contains(t)),
                Kind::Whitelist => match field::lookup(&ev.doc, &self.key) {
                    None | Some(Value::Null) => !self.ignore_null,
                    Some(Value::String(t)) => !self.list.contains(t.as_str()),
                    Some(_) => true,
                },
                _ => self.changed(rule, &ev),
            };
            if hit {
                let mut m = into_match(rule, Event { ts: ev.ts, doc: ev.doc });
                if self.kind == Kind::Change {
                    let qk = rule.query_key.as_ref().and_then(|q| field::lookup(&m, q)).map_or_else(|| "null".to_string(), Value::to_string);
                    if let Some((old, new)) = self.change_map.get(&qk) {
                        m.insert("old_value".into(), json!(old));
                        m.insert("new_value".into(), json!(new));
                    }
                }
                matches.push(m);
            }
        }
    }

    fn changed(&mut self, rule: &Rule, ev: &Event) -> bool {
        let key = rule.query_key.as_ref().and_then(|q| field::lookup(&ev.doc, q)).map_or_else(|| "null".to_string(), Value::to_string);
        let values: Vec<Option<Value>> = self.keys.iter().map(|k| field::lookup(&ev.doc, k).cloned()).collect();
        if self.ignore_null && values.iter().any(|v| !matches!(v, Some(Value::Bool(_))) && !truthy(v.as_ref())) {
            return false;
        }
        let mut changed = false;
        if let Some(prev) = self.last_values.get(&key) {
            changed = prev.iter().zip(&values).any(|(a, b)| a != b);
            if changed {
                self.change_map.insert(key.clone(), (prev.clone(), values.clone()));
                if let Some(t) = self.last_time.get(&key) {
                    changed = ev.ts - t <= tf(rule);
                }
            }
        }
        self.last_values.insert(key.clone(), values);
        if rule.timeframe.is_some() {
            self.last_time.insert(key, ev.ts);
        }
        changed
    }
}

// ---- new_term ----

pub struct NewTerm {
    /// One entry per field (a composite field is a list of sub-fields).
    fields: Vec<Vec<String>>,
    seen: Vec<FxHashSet<String>>,
    ready: bool,
}

fn kw(field: &str, rule: &Rule) -> String {
    if rule.raw.get("use_keyword_postfix").and_then(Value::as_bool).unwrap_or(true) && !field.ends_with(".keyword") {
        format!("{field}.keyword")
    } else {
        field.to_string()
    }
}

impl NewTerm {
    fn new(rule: &Rule) -> Result<Self> {
        let raw = rule.raw.get("fields").or(rule.raw.get("query_key")).cloned().unwrap_or(Value::Null);
        let list = match raw {
            Value::Array(a) => a,
            Value::String(s) => vec![Value::String(s)],
            _ => anyhow::bail!("fields or query_key must be specified"),
        };
        if list.is_empty() {
            anyhow::bail!("fields must not be an empty list");
        }
        let fields: Vec<Vec<String>> = list
            .iter()
            .map(|f| match f {
                Value::Array(sub) => sub.iter().map(py_str).collect(),
                other => vec![py_str(other)],
            })
            .collect();
        Ok(NewTerm { seen: vec![FxHashSet::default(); fields.len()], fields, ready: false })
    }

    /// Loads every value seen in the last `terms_window_size` (30 days) with composite aggregations.
    async fn init(&mut self, rule: &Rule, es: &Es, end: Option<Ts>) -> Result<()> {
        if self.ready {
            return Ok(());
        }
        let window = rule.raw.get("terms_window_size").map(crate::time::parse_duration_map).transpose()?.unwrap_or(30 * 24 * 60 * crate::time::MINUTE);
        let end = end.unwrap_or_else(crate::time::now);
        let start = end - window;
        let index = if rule.use_strftime_index { crate::index::format_index(&rule.index, start, end, rule.search_extra_index)? } else { rule.index.clone() };
        let mut must = vec![json!({"range": {&rule.timestamp_field: {"lt": ts_value(rule, end), "gte": ts_value(rule, start)}}})];
        must.extend(rule.filter.iter().map(|f| f.get("query").cloned().unwrap_or_else(|| f.clone())));
        for (i, fields) in self.fields.iter().enumerate() {
            let sources: Vec<Value> = fields.iter().enumerate().map(|(n, f)| json!({format!("f{n}"): {"terms": {"field": kw(f, rule)}}})).collect();
            let mut after: Option<Value> = None;
            loop {
                let mut comp = json!({"size": 1000, "sources": sources});
                if let Some(a) = &after {
                    comp["after"] = a.clone();
                }
                let body = json!({"size": 0, "query": {"bool": {"filter": must}}, "aggs": {"values": {"composite": comp}}});
                let resp = es.search(&index, &body).await.map_err(|e| anyhow::anyhow!("Error searching for existing terms: {e:#}"))?;
                let buckets = resp["aggregations"]["values"]["buckets"].as_array().cloned().unwrap_or_default();
                for b in &buckets {
                    let vals: Vec<Value> = (0..fields.len()).map(|n| b["key"][format!("f{n}")].clone()).collect();
                    self.seen[i].insert(if fields.len() == 1 { vals[0].to_string() } else { Value::Array(vals).to_string() });
                }
                after = resp["aggregations"]["values"].get("after_key").cloned().filter(|_| !buckets.is_empty());
                if after.is_none() {
                    break;
                }
            }
            log::info!("Found {} unique values for {}", self.seen[i].len(), fields.join(","));
        }
        self.ready = true;
        Ok(())
    }

    /// `use_terms_query`: each bucket key not seen before is a new term.
    fn add_term_bucket(&mut self, rule: &Rule, ts: Ts, qk: &str, key: &Value, matches: &mut Vec<Doc>) {
        let k = key.to_string();
        if !self.seen[0].contains(&k) {
            let mut m = Doc::from_iter([(qk.to_string(), key.clone()), (rule.timestamp_field.clone(), ts_value(rule, ts))]);
            m.insert("new_field".into(), json!(self.fields[0][0]));
            matches.push(m);
            self.seen[0].insert(k);
        }
    }

    fn add_data(&mut self, rule: &Rule, events: Vec<Event>, matches: &mut Vec<Doc>) {
        let alert_missing = opt_bool(rule, "alert_on_missing_field");
        for ev in events {
            for (i, fields) in self.fields.iter().enumerate() {
                let vals: Vec<Option<&Value>> = fields.iter().map(|f| field::lookup(&ev.doc, f)).collect();
                let key = if fields.len() == 1 {
                    vals[0].filter(|v| truthy(Some(v))).map(Value::to_string)
                } else if vals.iter().all(|v| truthy(*v)) {
                    Some(Value::Array(vals.iter().map(|v| (*v).cloned().unwrap_or(Value::Null)).collect()).to_string())
                } else {
                    None
                };
                let name = if fields.len() == 1 { json!(fields[0]) } else { json!(fields) };
                match key {
                    None if alert_missing => {
                        let mut m = ev.doc.clone();
                        m.insert("missing_field".into(), name);
                        matches.push(into_match(rule, Event { ts: ev.ts, doc: m }));
                    }
                    Some(k) if !self.seen[i].contains(&k) => {
                        let mut m = ev.doc.clone();
                        m.insert("new_field".into(), name);
                        matches.push(into_match(rule, Event { ts: ev.ts, doc: m }));
                        self.seen[i].insert(k);
                    }
                    _ => {}
                }
            }
        }
    }
}

// ---- cardinality ----

pub struct Cardinality {
    field: String,
    max: Option<f64>,
    min: Option<f64>,
    cache: FxHashMap<String, FxHashMap<String, Ts>>,
    first_event: FxHashMap<String, Ts>,
}

impl Cardinality {
    fn new(rule: &Rule) -> Self {
        Cardinality {
            field: rule.raw.get("cardinality_field").map(py_str).unwrap_or_default(),
            max: opt_f64(rule, "max_cardinality"),
            min: opt_f64(rule, "min_cardinality"),
            cache: FxHashMap::default(),
            first_event: FxHashMap::default(),
        }
    }

    fn add_data(&mut self, rule: &Rule, events: Vec<Event>, matches: &mut Vec<Doc>) {
        for ev in events {
            let key = group_key(rule, &ev.doc);
            self.cache.entry(key.clone()).or_default();
            self.first_event.entry(key.clone()).or_insert(ev.ts);
            let Some(v) = field::lookup(&ev.doc, &self.field).filter(|v| !v.is_null()) else { continue };
            self.cache.get_mut(&key).expect("inserted").insert(v.to_string(), ev.ts);
            self.check(rule, &key, ev.ts, Some(&ev.doc), true, matches);
        }
    }

    fn check(&mut self, rule: &Rule, key: &str, ts: Ts, doc: Option<&Doc>, gc: bool, matches: &mut Vec<Doc>) {
        let elapsed = ts - self.first_event.get(key).copied().unwrap_or(ts);
        let n = self.cache.get(key).map_or(0, |c| c.len()) as f64;
        let over = self.max.is_some_and(|m| n > m);
        let under = self.min.is_some_and(|m| n < m) && elapsed > tf(rule);
        if over || under {
            if gc {
                self.garbage_collect(rule, ts, matches);
                self.check(rule, key, ts, doc, false, matches);
            } else {
                self.first_event.remove(key);
                let mut d = doc.cloned().unwrap_or_default();
                d.entry(rule.timestamp_field.clone()).or_insert_with(|| json!(to_iso(ts)));
                matches.push(into_match(rule, Event { ts, doc: d }));
            }
        }
    }

    fn garbage_collect(&mut self, rule: &Rule, ts: Ts, matches: &mut Vec<Doc>) {
        let keys: Vec<String> = self.cache.keys().cloned().collect();
        for qk in keys {
            if let Some(terms) = self.cache.get_mut(&qk) {
                terms.retain(|_, last| ts - *last <= tf(rule));
            }
            if self.min.is_some() {
                let mut ph = Doc::from_iter([(rule.timestamp_field.clone(), json!(to_iso(ts)))]);
                if let Some(q) = &rule.query_key {
                    ph.insert(q.clone(), key_value(&qk));
                }
                self.check(rule, &qk, ts, Some(&ph), false, matches);
            }
        }
    }
}

/// Progress of one pivot value through the `correlation_query` of a `correlation` rule.
struct Chain {
    /// Time of the first event; the window `timeframe` is measured from here.
    first_ts: Ts,
    positive: Progress,
    negated: Vec<Progress>,
    /// With a `NOT` in the query: the event that completed the positive part, waiting for the end of the window.
    completed: Option<Event>,
    leaves: Vec<LeafRec>,
}

#[derive(Clone, Default)]
struct LeafRec {
    count: u64,
    first: Ts,
    last: Ts,
    /// The newest event of the leaf.
    doc: Option<Doc>,
}

/// `correlation`: the leaves happen on the same `query_key` value within `timeframe` of the first one, as the
/// `correlation_query` combines them. One match per completed chain; with a `NOT`, at the end of the window.
pub struct Correlation {
    names: Vec<String>,
    need: Vec<u64>,
    /// Leaves that can start a chain; other events of a pivot without one are skipped before anything is allocated.
    starts: Vec<bool>,
    query: Query,
    chains: FxHashMap<String, Chain>,
    /// Matches completing at or before this time were alerted by a previous run; replaying them only rebuilds state.
    suppress_until: Option<Ts>,
}

impl Correlation {
    fn new(rule: &Rule) -> Self {
        let spec = rule.correlation.as_ref().expect("correlation rules always have leaves");
        let mut starts = vec![false; spec.leaves.len()];
        crate::correlation::first_leaves(&spec.query.positive, &mut starts);
        Correlation {
            names: spec.leaves.iter().map(|l| l.name.clone()).collect(),
            need: spec.leaves.iter().map(|l| l.num_events).collect(),
            starts,
            query: spec.query.clone(),
            chains: FxHashMap::default(),
            suppress_until: None,
        }
    }

    fn add_events(&mut self, rule: &Rule, events: Vec<(Vec<usize>, Event)>, matches: &mut Vec<Doc>) {
        for (tags, ev) in events {
            self.add_event(rule, &tags, ev, matches);
        }
    }

    fn add_event(&mut self, rule: &Rule, tags: &[usize], ev: Event, matches: &mut Vec<Doc>) {
        let key = group_key(rule, &ev.doc);
        if self.chains.get(&key).is_some_and(|c| ev.ts - c.first_ts > tf(rule)) {
            let chain = self.chains.remove(&key).expect("checked above");
            self.expired(rule, &key, chain, matches);
        }
        let q = &self.query;
        let fresh = !self.chains.contains_key(&key);
        if fresh && !tags.iter().any(|t| self.starts[*t]) {
            return;
        }
        let chain = self.chains.entry(key.clone()).or_insert_with(|| Chain {
            first_ts: ev.ts,
            positive: Progress::new(&q.positive),
            negated: q.negated.iter().map(Progress::new).collect(),
            completed: None,
            leaves: vec![LeafRec::default(); self.names.len()],
        });
        let was_done = chain.positive.done;
        let mut took = vec![false; self.names.len()];
        let fed = chain.positive.feed(&q.positive, tags, &self.need, &mut took);
        if chain.positive.violated {
            // A `NOT` between two steps happened before the next step.
            self.chains.remove(&key);
            return;
        }
        if fed {
            for (rec, _) in chain.leaves.iter_mut().zip(&took).filter(|(_, t)| **t) {
                if rec.count == 0 {
                    rec.first = ev.ts;
                }
                rec.count += 1;
                rec.last = ev.ts;
                rec.doc = Some(ev.doc.clone());
            }
        } else if fresh {
            // Only an event of the positive part starts a chain.
            self.chains.remove(&key);
            return;
        }
        // `THEN NOT x`: x counts only after the positive part, and not with the event that completed it.
        if !q.after || was_done {
            let mut violated = false;
            for (p, x) in chain.negated.iter_mut().zip(&q.negated) {
                p.feed(x, tags, &self.need, &mut took);
                violated |= p.done;
            }
            if violated {
                self.chains.remove(&key);
                return;
            }
        }
        if chain.positive.done && !was_done {
            if q.negated.is_empty() {
                let chain = self.chains.remove(&key).expect("present");
                self.emit(rule, &key, &chain, ev, None, matches);
            } else {
                chain.completed = Some(ev);
            }
        }
    }

    /// A chain whose window ended: with a `NOT` in the query and the positive part complete, that is the match.
    fn expired(&mut self, rule: &Rule, key: &str, mut chain: Chain, matches: &mut Vec<Doc>) {
        if let Some(ev) = chain.completed.take() {
            self.emit(rule, key, &chain, ev, Some(chain.first_ts + tf(rule)), matches);
        }
    }

    /// `event` completed the positive part; `window_end` is set when the match is the end of the window (a `NOT` held).
    fn emit(&self, rule: &Rule, key: &str, chain: &Chain, event: Event, window_end: Option<Ts>, matches: &mut Vec<Doc>) {
        let completed = window_end.unwrap_or(event.ts);
        if self.suppress_until.is_some_and(|t| completed <= t) {
            return;
        }
        let mut leaves = Map::new();
        for (name, rec) in self.names.iter().zip(&chain.leaves) {
            if rec.count == 0 {
                leaves.insert(name.clone(), Value::Null);
                continue;
            }
            let mut o = rec.doc.clone().unwrap_or_default();
            o.insert("count".into(), json!(rec.count));
            o.insert("first".into(), json!(to_iso(rec.first)));
            o.insert("last".into(), json!(to_iso(rec.last)));
            leaves.insert(name.clone(), Value::Object(o));
        }
        let info = json!({
            "key": key_value(key),
            "query": self.query.text,
            "first": to_iso(chain.first_ts),
            "last": to_iso(completed),
            "absent": if window_end.is_some() { json!(self.query.negated_text) } else { Value::Null },
            "leaves": leaves,
        });
        let mut m = into_match(rule, event);
        m.insert("correlation".into(), info);
        matches.push(m);
    }

    /// Drops chains whose window has ended; with a `NOT` in the query, the complete ones become matches.
    fn garbage_collect(&mut self, rule: &Rule, ts: Ts, matches: &mut Vec<Doc>) {
        let mut due: Vec<(Ts, String)> = self.chains.iter().filter(|(_, c)| ts - c.first_ts > tf(rule)).map(|(k, c)| (c.first_ts, k.clone())).collect();
        due.sort();
        for (_, key) in due {
            if let Some(chain) = self.chains.remove(&key) {
                self.expired(rule, &key, chain, matches);
            }
        }
    }

    fn match_str(&self, rule: &Rule, m: &Doc, ts_fmt: Option<&str>) -> String {
        let Some(info) = m.get("correlation") else { return String::new() };
        let when = |k: &str| info.get(k).and_then(Value::as_str).and_then(crate::time::parse_iso).map(|t| pretty(t, rule.use_local_time, ts_fmt));
        let (Some(first), Some(last)) = (when("first"), when("last")) else { return String::new() };
        let key = info.get("key").map_or_else(|| "None".into(), py_str);
        let query = &self.query.text;
        match info.get("absent").and_then(Value::as_array) {
            Some(absent) => {
                let absent: Vec<&str> = absent.iter().filter_map(Value::as_str).collect();
                format!("Correlated events for {key} ({query}) started at {first} and no {} within {}\n\n", absent.join(" or "), pretty_duration(tf(rule)))
            }
            None => format!("Correlated events for {key} ({query}) between {first} and {last}\n\n"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(ts: Ts) -> Event {
        Event { ts, doc: Doc::new() }
    }

    #[test]
    fn window_evicts_at_timeframe() {
        let mut w = EventWindow::new(10);
        w.append(ev(0), Num::I(1));
        w.append(ev(5), Num::I(1));
        assert_eq!(w.count().f(), 2.0);
        let gone = w.append(ev(10), Num::I(1)); // span 10 >= 10 -> evict ts 0
        assert_eq!(gone.len(), 1);
        assert_eq!(w.count().f(), 2.0);
        w.append(ev(7), Num::I(1)); // out of order insert
        assert_eq!(w.data.iter().map(|(e, _)| e.ts).collect::<Vec<_>>(), vec![5, 7, 10]);
    }

    fn rule_from(yaml: &str) -> Rule {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!("ea-types-{}-{}", std::process::id(), NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("r.yaml");
        std::fs::write(&f, format!("name: t\nindex: x\nalert: debug\n{yaml}")).unwrap();
        let conf = crate::config::Config::load_with_defaults(&dir.join("none.yaml")).unwrap();
        let rule = crate::rule::load(&f, &conf).unwrap();
        std::fs::remove_dir_all(dir).ok();
        rule
    }

    const MIN: Ts = 60_000_000;

    /// A correlation rule over leaves named in `leaves` (sorted, so leaf `i` is the i-th name), with `query`.
    fn corr_rule(leaves: &[(&str, u64)], query: &str, hours: i64) -> (Rule, RuleType) {
        let list: String = leaves.iter().map(|(n, k)| format!("  {n}: {{num_events: {k}, filter: [{{term: {{k: {n}}}}}]}}\n")).collect();
        let rule = rule_from(&format!("type: correlation\nquery_key: host.name\ntimeframe: {{hours: {hours}}}\ncorrelation_query: '{query}'\ncorrelation_leaves:\n{list}"));
        let rt = RuleType::new(&rule).unwrap();
        (rule, rt)
    }

    /// `outbound` is leaf 0, `tool` leaf 1.
    fn corr() -> (Rule, RuleType) {
        corr_rule(&[("outbound", 1), ("tool", 1)], "tool THEN outbound", 1)
    }

    fn cev(leaf: usize, host: &str, minute: i64) -> (usize, Event) {
        let ts = 1_700_000_000_000_000 + minute * MIN;
        (leaf, Event { ts, doc: Doc::from_iter([("host".to_string(), json!({"name": host})), ("@timestamp".into(), json!(to_iso(ts))), ("who".into(), json!(format!("{host}-{leaf}-{minute}")))]) })
    }

    fn feed(rule: &Rule, rt: &mut RuleType, events: Vec<(usize, Event)>) -> Vec<Doc> {
        let mut out = Vec::new();
        rt.add_correlation(rule, events.into_iter().map(|(leaf, ev)| (vec![leaf], ev)).collect(), &mut out);
        out
    }

    const OUT: usize = 0;
    const TOOL: usize = 1;

    #[test]
    fn correlation_then_matches_once_per_chain() {
        let (rule, mut rt) = corr();
        let m = feed(&rule, &mut rt, vec![cev(TOOL, "a", 0), cev(OUT, "a", 10)]);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0]["who"], json!("a-0-10"), "the match is the event that completed the chain");
        let info = &m[0]["correlation"];
        assert_eq!(info["key"], json!("a"));
        assert_eq!(info["query"], json!("tool THEN outbound"));
        assert_eq!(info["absent"], Value::Null);
        assert_eq!(info["leaves"]["tool"]["who"], json!("a-1-0"));
        assert_eq!(info["leaves"]["tool"]["count"], json!(1));
        assert_eq!(info["leaves"]["outbound"]["host"], json!({"name": "a"}));
        // The chain was reset: a second outbound alone is nothing.
        assert!(feed(&rule, &mut rt, vec![cev(OUT, "a", 20)]).is_empty());
        let text = rt.match_str(&rule, &m[0], None);
        assert!(text.starts_with("Correlated events for a (tool THEN outbound) between "), "{text}");
    }

    #[test]
    fn correlation_then_needs_order_window_and_same_pivot() {
        let (rule, mut rt) = corr();
        assert!(feed(&rule, &mut rt, vec![cev(OUT, "a", 0), cev(TOOL, "a", 5)]).is_empty(), "wrong order");
        let (rule, mut rt) = corr();
        assert!(feed(&rule, &mut rt, vec![cev(TOOL, "a", 0), cev(OUT, "a", 61)]).is_empty(), "outside the window of the first event");
        let (rule, mut rt) = corr();
        assert!(feed(&rule, &mut rt, vec![cev(TOOL, "a", 0), cev(OUT, "b", 5)]).is_empty(), "different pivot");
        let (rule, mut rt) = corr();
        // The window is measured from the first event: a later start event does not move it.
        assert!(feed(&rule, &mut rt, vec![cev(TOOL, "a", 0), cev(TOOL, "a", 50), cev(OUT, "a", 70)]).is_empty());
        let (rule, mut rt) = corr();
        assert_eq!(feed(&rule, &mut rt, vec![cev(TOOL, "a", 0), cev(OUT, "a", 60)]).len(), 1, "exactly timeframe is inside");
    }

    #[test]
    fn correlation_state_survives_between_runs_and_pivots_are_independent() {
        let (rule, mut rt) = corr();
        assert!(feed(&rule, &mut rt, vec![cev(TOOL, "a", 0), cev(TOOL, "b", 1)]).is_empty());
        let m = feed(&rule, &mut rt, vec![cev(OUT, "b", 5), cev(OUT, "a", 6)]);
        assert_eq!(m.iter().map(|d| d["correlation"]["key"].clone()).collect::<Vec<_>>(), vec![json!("b"), json!("a")]);
    }

    #[test]
    fn correlation_and_or_and_num_events() {
        let (rule, mut rt) = corr_rule(&[("outbound", 1), ("tool", 1)], "tool and outbound", 1);
        assert_eq!(feed(&rule, &mut rt, vec![cev(OUT, "a", 0), cev(TOOL, "a", 3)]).len(), 1, "AND takes any order");
        // ok is leaf 1: it must follow the third failure, the one before does not count.
        let (rule, mut rt) = corr_rule(&[("fail", 3), ("ok", 1)], "fail THEN ok", 1);
        let m = feed(&rule, &mut rt, vec![cev(0, "a", 0), cev(0, "a", 1), cev(1, "a", 2), cev(0, "a", 3), cev(1, "a", 4)]);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0]["who"], json!("a-1-4"));
        assert_eq!(m[0]["correlation"]["leaves"]["fail"]["count"], json!(3));
        assert_eq!(m[0]["correlation"]["leaves"]["ok"]["count"], json!(1));
        // Either failure kind, then a success; the other branch's leaf stays null.
        let (rule, mut rt) = corr_rule(&[("rdp", 2), ("ssh", 2), ("success", 1)], "(ssh OR rdp) THEN success", 1);
        let m = feed(&rule, &mut rt, vec![cev(1, "a", 0), cev(0, "a", 1), cev(0, "a", 2), cev(2, "a", 3)]);
        assert_eq!(m.len(), 1);
        let leaves = &m[0]["correlation"]["leaves"];
        assert_eq!((&leaves["rdp"]["count"], &leaves["ssh"]["count"]), (&json!(2), &json!(1)));
        let (rule, mut rt) = corr_rule(&[("rdp", 2), ("ssh", 2), ("success", 1)], "(ssh OR rdp) THEN success", 1);
        let m = feed(&rule, &mut rt, vec![cev(0, "a", 1), cev(0, "a", 2), cev(2, "a", 3)]);
        assert_eq!(m[0]["correlation"]["leaves"]["ssh"], Value::Null);
        assert!(feed(&rule, &mut rt, vec![cev(1, "a", 10), cev(0, "a", 11), cev(2, "a", 12)]).is_empty(), "one of each is not enough");
    }

    #[test]
    fn correlation_document_matching_several_leaves_counts_once() {
        let both = |minute| {
            let (_, ev) = cev(0, "a", minute);
            vec![(vec![0, 1], ev)]
        };
        let mut out = Vec::new();
        // AND: the document completes the chain and does not start the next one.
        let (rule, mut rt) = corr_rule(&[("x", 1), ("y", 1)], "x AND y", 1);
        rt.add_correlation(&rule, both(0), &mut out);
        assert_eq!(out.len(), 1);
        assert!(feed(&rule, &mut rt, vec![cev(0, "a", 1)]).is_empty());
        // THEN is strict whatever the leaf order: the second side needs a later document.
        for query in ["x THEN y", "y THEN x"] {
            let (rule, mut rt) = corr_rule(&[("x", 1), ("y", 1)], query, 1);
            let mut out = Vec::new();
            rt.add_correlation(&rule, both(0), &mut out);
            assert!(out.is_empty(), "{query}");
            let second = if query == "x THEN y" { 1 } else { 0 };
            assert_eq!(feed(&rule, &mut rt, vec![cev(second, "a", 1)]).len(), 1, "{query}");
        }
    }

    #[test]
    fn correlation_events_outside_the_query_start_nothing() {
        // finished (leaf 0) alone does not open a chain that started would then complete late.
        let (rule, mut rt) = corr_rule(&[("finished", 1), ("started", 1)], "started THEN NOT finished", 2);
        let mut out = feed(&rule, &mut rt, vec![cev(0, "a", 0)]);
        rt.garbage_collect(&rule, 1_700_000_000_000_000 + 500 * MIN, &mut out);
        assert!(out.is_empty());
    }

    /// `finished` is leaf 0, `started` leaf 1.
    fn absent_rule() -> (Rule, RuleType) {
        corr_rule(&[("finished", 1), ("started", 1)], "started THEN NOT finished", 2)
    }

    #[test]
    fn correlation_then_not_fires_at_the_deadline() {
        let (rule, mut rt) = absent_rule();
        let mut out = Vec::new();
        assert!(feed(&rule, &mut rt, vec![cev(1, "a", 0), cev(1, "b", 1), cev(0, "b", 30)]).is_empty());
        rt.garbage_collect(&rule, 1_700_000_000_000_000 + 119 * MIN, &mut out);
        assert!(out.is_empty(), "still inside the window");
        rt.garbage_collect(&rule, 1_700_000_000_000_000 + 121 * MIN, &mut out);
        assert_eq!(out.len(), 1, "only a lacks its end");
        assert_eq!(out[0]["correlation"]["key"], json!("a"));
        assert_eq!(out[0]["correlation"]["absent"], json!(["finished"]));
        assert_eq!(out[0]["who"], json!("a-1-0"));
        assert_eq!(out[0]["correlation"]["last"], json!(to_iso(1_700_000_000_000_000 + 120 * MIN)));
        let text = rt.match_str(&rule, &out[0], None);
        assert!(text.contains("(started THEN NOT finished) started at ") && text.contains(" and no finished within 2:00:00"), "{text}");
        rt.garbage_collect(&rule, 1_700_000_000_000_000 + 200 * MIN, &mut out);
        assert_eq!(out.len(), 1, "fires once");
    }

    #[test]
    fn correlation_then_not_fires_when_a_late_event_arrives() {
        let (rule, mut rt) = absent_rule();
        // The end shows up after the deadline: too late, the first chain is a match and the late event starts nothing.
        let m = feed(&rule, &mut rt, vec![cev(1, "a", 0), cev(0, "a", 130)]);
        assert_eq!(m.len(), 1);
        // A new start after the deadline opens a fresh chain.
        let m = feed(&rule, &mut rt, vec![cev(1, "c", 0), cev(1, "c", 150)]);
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn correlation_not_between_steps_guards_the_gap() {
        // a (leaf 0) THEN NOT b (leaf 1) THEN c (leaf 2).
        let q = "a THEN NOT b THEN c";
        let leaves = [("a", 1), ("b", 1), ("c", 1)];
        let (rule, mut rt) = corr_rule(&leaves, q, 1);
        let m = feed(&rule, &mut rt, vec![cev(0, "x", 0), cev(2, "x", 5)]);
        assert_eq!(m.len(), 1, "no b between a and c");
        assert_eq!(m[0]["correlation"]["query"], json!(q));
        assert_eq!(m[0]["correlation"]["leaves"]["b"], Value::Null);
        let (rule, mut rt) = corr_rule(&leaves, q, 1);
        assert!(feed(&rule, &mut rt, vec![cev(0, "x", 0), cev(1, "x", 2), cev(2, "x", 5)]).is_empty(), "b between a and c kills the chain");
        // The killed chain is gone: c alone starts nothing, and a new a opens a fresh one.
        assert!(feed(&rule, &mut rt, vec![cev(2, "x", 6)]).is_empty());
        assert_eq!(feed(&rule, &mut rt, vec![cev(0, "x", 10), cev(2, "x", 11)]).len(), 1);
        // A b before a, or another pivot's b, is not in the gap.
        let (rule, mut rt) = corr_rule(&leaves, q, 1);
        assert_eq!(feed(&rule, &mut rt, vec![cev(1, "x", 0), cev(0, "x", 1), cev(1, "y", 2), cev(2, "x", 3)]).len(), 1);
        // A b after c is out of the gap too.
        let (rule, mut rt) = corr_rule(&leaves, q, 1);
        let mut out = feed(&rule, &mut rt, vec![cev(0, "x", 0), cev(2, "x", 1), cev(1, "x", 2)]);
        assert_eq!(out.len(), 1);
        out.clear();
        // A document matching both b and c is a b: the chain is dead.
        let (rule, mut rt) = corr_rule(&leaves, q, 1);
        rt.add_correlation(&rule, vec![(vec![0], cev(0, "x", 0).1), (vec![1, 2], cev(1, "x", 1).1)], &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn correlation_and_not_counts_from_the_start_of_the_chain() {
        // a (leaf 0) and c (leaf 2) without any b (leaf 1) in the window.
        let (rule, mut rt) = corr_rule(&[("a", 1), ("b", 1), ("c", 1)], "a AND c AND NOT b", 1);
        let mut out = feed(&rule, &mut rt, vec![cev(0, "x", 0), cev(1, "x", 1), cev(2, "x", 2)]);
        out.extend(feed(&rule, &mut rt, vec![cev(0, "y", 0), cev(2, "y", 2)]));
        rt.garbage_collect(&rule, 1_700_000_000_000_000 + 90 * MIN, &mut out);
        assert_eq!(out.len(), 1, "x saw a b");
        assert_eq!(out[0]["correlation"]["key"], json!("y"));
        assert_eq!(out[0]["who"], json!("y-2-2"), "the match is the event that completed the positive part");
        // THEN NOT: a b before the positive part completed does not count.
        let (rule, mut rt) = corr_rule(&[("a", 1), ("b", 1), ("c", 1)], "(a AND c) THEN NOT b", 1);
        let mut out = feed(&rule, &mut rt, vec![cev(0, "x", 0), cev(1, "x", 1), cev(2, "x", 2)]);
        rt.garbage_collect(&rule, 1_700_000_000_000_000 + 90 * MIN, &mut out);
        assert_eq!(out.len(), 1);
        // A leaf may be positive and negated: one start and no second one.
        let (rule, mut rt) = corr_rule(&[("a", 1)], "a THEN NOT a", 1);
        let mut out = feed(&rule, &mut rt, vec![cev(0, "x", 0), cev(0, "x", 5), cev(0, "y", 0)]);
        rt.garbage_collect(&rule, 1_700_000_000_000_000 + 90 * MIN, &mut out);
        assert_eq!(out.iter().map(|d| d["correlation"]["key"].clone()).collect::<Vec<_>>(), vec![json!("y")]);
        // num_events on a negated leaf: fewer than that many.
        let (rule, mut rt) = corr_rule(&[("a", 1), ("b", 2)], "a THEN NOT b", 1);
        let mut out = feed(&rule, &mut rt, vec![cev(0, "x", 0), cev(1, "x", 5), cev(0, "y", 0), cev(1, "y", 5), cev(1, "y", 6)]);
        rt.garbage_collect(&rule, 1_700_000_000_000_000 + 90 * MIN, &mut out);
        assert_eq!(out.iter().map(|d| d["correlation"]["key"].clone()).collect::<Vec<_>>(), vec![json!("x")]);
    }

    #[test]
    fn correlation_replay_does_not_alert_twice() {
        let (rule, mut rt) = corr();
        rt.suppress_until(1_700_000_000_000_000 + 10 * MIN);
        assert!(feed(&rule, &mut rt, vec![cev(TOOL, "a", 0), cev(OUT, "a", 10)]).is_empty());
        assert_eq!(feed(&rule, &mut rt, vec![cev(TOOL, "a", 11), cev(OUT, "a", 12)]).len(), 1);
        // A chain started before the restart still completes after it.
        let (rule, mut rt) = corr();
        rt.suppress_until(1_700_000_000_000_000 + 10 * MIN);
        assert!(feed(&rule, &mut rt, vec![cev(TOOL, "a", 5)]).is_empty());
        assert_eq!(feed(&rule, &mut rt, vec![cev(OUT, "a", 20)]).len(), 1);
    }

    fn matches_of(rule: &Rule, ts: Ts, payload: Value) -> Vec<Doc> {
        let mut rt = RuleType::new(rule).unwrap();
        let mut out = Vec::new();
        rt.add_aggregation(rule, ts, &payload, &mut out);
        out
    }

    #[test]
    fn metric_aggregation_thresholds_and_query_key() {
        let rule = rule_from("type: metric_aggregation\nmetric_agg_key: cpu.load\nmetric_agg_type: avg\nmax_threshold: 80\nquery_key: host.name\nmetric_format_string: '{:.1f}%'\n");
        let payload = json!({"bucket_aggs": {"buckets": [
            {"key": "a", "doc_count": 3, "metric_cpu.load_avg": {"value": 91.25}},
            {"key": "b", "doc_count": 3, "metric_cpu.load_avg": {"value": 10.0}},
            {"key": "c", "doc_count": 0, "metric_cpu.load_avg": {"value": null}},
        ]}});
        let m = matches_of(&rule, 1_700_000_000_000_000, payload);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0]["host"], json!({"name": "a"}));
        assert_eq!(m[0]["metric_cpu.load_avg"], json!(91.25));
        assert_eq!(m[0]["metric_agg_value_formatted"], json!("91.2%"));
        assert_eq!(m[0]["@timestamp"], json!("2023-11-14T22:13:20Z"));
        let text = RuleType::new(&rule).unwrap().match_str(&rule, &m[0], None);
        assert_eq!(text, "Threshold violation, avg:cpu.load 91.2% (min: None max : 80) \n\n");
    }

    #[test]
    fn metric_aggregation_compound_key_and_intervals() {
        let rule = rule_from("type: metric_aggregation\nmetric_agg_key: bytes\nmetric_agg_type: sum\nmin_threshold: 5\nquery_key: [a, b]\nbucket_interval: {minutes: 5}\nbuffer_time: {minutes: 15}\n");
        let leaf = |k: &str, v: f64| json!({"key": k, "interval_aggs": {"buckets": [{"metric_bytes_sum": {"value": v}}, {"metric_bytes_sum": {"value": 9.0}}]}});
        let payload = json!({"bucket_aggs": {"buckets": [{"key": "x", "bucket_aggs": {"buckets": [leaf("y", 1.0), leaf("z", 7.0)]}}]}});
        let m = matches_of(&rule, 0, payload);
        assert_eq!(m.len(), 1);
        assert_eq!((&m[0]["a"], &m[0]["b"], &m[0]["a,b"]), (&json!("x"), &json!("y"), &json!("x,y")));
        assert_eq!(m[0]["metric_bytes_sum"], json!(1.0));
    }

    #[test]
    fn percentage_match_bounds_and_denominator() {
        let rule = rule_from("type: percentage_match\nmatch_bucket_filter: [{term: {ok: true}}]\nmax_percentage: 60\nmin_denominator: 10\nbucket_interval: {minutes: 5}\n");
        let bucket = |key: &str, hit: i64, other: i64| json!({"key_as_string": key, "percentage_match_aggs": {"buckets": {"match_bucket": {"doc_count": hit}, "_other_": {"doc_count": other}}}});
        let payload = json!({"interval_aggs": {"buckets": [
            bucket("2024-03-01T10:00:00.000Z", 8, 2),  // 80% of 10: match
            bucket("2024-03-01T10:05:00.000Z", 3, 1),  // below min_denominator
            bucket("2024-03-01T10:10:00.000Z", 5, 5),  // 50%: fine
        ]}});
        let m = matches_of(&rule, 0, payload);
        assert_eq!(m.len(), 1);
        assert_eq!((&m[0]["percentage"], &m[0]["denominator"], &m[0]["@timestamp"]), (&json!(80.0), &json!(10), &json!("2024-03-01T10:00:00Z")));
        let text = RuleType::new(&rule).unwrap().match_str(&rule, &m[0], None);
        assert_eq!(text, "Percentage violation, value: 80.0 (min: None max : 60) of 10 items\n\n");
    }

    #[test]
    fn spike_aggregation_sum_keeps_decimals() {
        let rule = rule_from("type: spike_aggregation\nmetric_agg_key: bytes\nmetric_agg_type: sum\nspike_height: 2\nspike_type: up\ntimeframe: {minutes: 1}\nuse_local_time: false\n");
        let mut rt = RuleType::new(&rule).unwrap();
        let mut out = Vec::new();
        for (secs, v) in [(0, 10.0), (60, 10.0), (120, 50.0)] {
            rt.add_aggregation(&rule, secs * 1_000_000, &json!({"metric_bytes_sum": {"value": v}}), &mut out);
        }
        assert_eq!(out.len(), 1);
        assert_eq!((&out[0]["spike_count"], &out[0]["reference_count"]), (&json!(50.0), &json!(10.0)));
        let text = rt.match_str(&rule, &out[0], Some("%H:%M"));
        assert_eq!(text, "An abnormal sum of bytes (50.0) occurred around 00:02.\nPreceding that time, there was a sum of bytes of (10.0) within 0:01:00\n\n");
    }

    #[test]
    fn number_formats() {
        assert_eq!(format_number("{:.2%}", &json!(0.5)), "50.00%");
        assert_eq!(format_number("{:.2f} ms", &json!(3)), "3.00 ms");
        assert_eq!(format_number("%.1f%%", &json!(12.34)), "12.3%");
        assert_eq!(format_number("%d items", &json!(4.9)), "4 items");
        assert_eq!(round2(&json!(12.345)), "12.35");
        assert_eq!(round2(&json!(7)), "7");
    }

    #[test]
    fn python_truthiness() {
        assert!(!truthy(Some(&json!(0))));
        assert!(!truthy(Some(&json!(""))));
        assert!(truthy(Some(&json!("a"))));
        assert!(!truthy(None));
    }
}
