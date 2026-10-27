//! One rule run: pick the time range, query ES page by page, feed the rule type,
//! then silence/realert and alert on each match. Same semantics as ElastAlert's `run_rule`.

use crate::alert;
use crate::alerters::{Alerter, View};
use crate::discover;
use crate::enhancements::Outcome;
use crate::es::Es;
use crate::field::{self, py_str};
use crate::index;
use crate::metrics::Metrics;
use crate::querylang::{self, QueryLang};
use crate::rule::{Aggregation, Kind, Rule, TsType};
use crate::time::{Dur, MINUTE, SECOND, Ts, now, parse_iso, pretty, to_iso};
use crate::types::{Event, RuleType, match_time, parse_ts, ts_value};
use crate::writeback::{Kind as Wb, Writeback};
use anyhow::{Context, Result, bail};
use rustc_hash::{FxHashMap, FxHashSet, FxHasher};
use serde_json::{Map, Value, json};
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

type Doc = Map<String, Value>;

/// Realert/silence state shared by all rules (several rules may share a `realert_key`).
#[derive(Default)]
pub struct Silences(Mutex<FxHashMap<String, (Ts, i32)>>);

impl Silences {
    pub fn is_silenced(&self, key: &str) -> bool {
        self.0.lock().unwrap().get(key).is_some_and(|(until, _)| now() < *until)
    }

    pub fn get(&self, key: &str) -> Option<(Ts, i32)> {
        self.0.lock().unwrap().get(key).copied()
    }

    /// Merge a silence read from ES: never shortens one we already know.
    pub fn raise(&self, key: &str, until: Ts, exponent: i32) {
        let mut m = self.0.lock().unwrap();
        if m.get(key).is_none_or(|(u, _)| *u < until) {
            m.insert(key.to_string(), (until, exponent));
        }
    }

    pub fn set(&self, key: &str, until: Ts, exponent: i32) {
        self.0.lock().unwrap().insert(key.to_string(), (until, exponent));
    }
}

/// Everything a rule task needs besides its own state.
pub struct Ctx {
    pub es: Es,
    pub writeback: Writeback,
    pub silences: Arc<Silences>,
    pub metrics: Arc<Metrics>,
    pub notifier: Option<Arc<crate::notify::Notifier>>,
    pub debug: bool,
    /// Rules disabled after a panic (`disable_rules_on_error`); shown in the log, cleared on reload.
    pub disabled: Arc<Mutex<Vec<String>>>,
    pub disable_rules_on_error: bool,
    pub use_pit: bool,
    /// Global `run_every`: count and terms queries read this much per query.
    pub run_every: Dur,
    pub old_query_limit: Dur,
    pub alert_time_limit: Dur,
    pub scroll_keepalive: String,
    pub ts_fmt: Option<String>,
}

/// An alert that has not reached every alerter yet. Kept in memory and mirrored in ES (`alert_sent: false`).
pub struct Pending {
    pub id: String,
    pub matches: Vec<Doc>,
    pub done: Vec<bool>,
    pub attempts: u32,
    pub next_try: Ts,
    pub alert_time: Ts,
    pub exception: String,
    /// Ids of the docs of an aggregated alert's other matches (deleted once the alert is fully sent).
    pub child_ids: Vec<String>,
}

/// Matches waiting for their aggregation time, one group per `aggregation_key` value.
struct AggGroup {
    alert_time: Ts,
    head_id: String,
    matches: Vec<Doc>,
    child_ids: Vec<String>,
}

pub struct RuleState {
    pub rule: Rule,
    rtype: RuleType,
    alerters: Vec<Alerter>,
    /// The rule as each alerter sees it, when its `alert:` entry has options of its own.
    alert_rules: Vec<Option<Rule>>,
    pub pending: Vec<Pending>,
    agg: FxHashMap<String, AggGroup>,
    starttime: Option<Ts>,
    previous_endtime: Option<Ts>,
    minimum_starttime: Option<Ts>,
    /// Seconds added to `date_histogram` buckets so they start at the query start (`bucket_interval`).
    bucket_offset: i64,
    /// Hash of `_id` -> event time, to skip hits already seen in overlapping windows.
    seen: FxHashMap<u64, Ts>,
    /// `correlation`: whether hits carry the leaves they matched (`matched_queries`), and the tagged events (with
    /// their dedup hash) gathered for the range.
    corr_group: bool,
    corr_buf: Vec<(usize, Event, u64)>,
    /// `read_doc_values`: per index, the `docvalue_fields` to ask for, or `None` when a field cannot be read that way.
    doc_values: FxHashMap<String, Option<Vec<Value>>>,
    /// Documents to query instead of ES (`test-rule --data`).
    pub mock: Option<Vec<Doc>>,
    /// `limit_execution`: whether a run has happened since the rule was (re)loaded.
    pub has_run_once: bool,
    /// `limit_execution_coverage`: where the next run resumes after a pause.
    next_min_start: Option<Ts>,
    /// Counters for the current run.
    hits: u64,
    dupes: u64,
    alerts_sent: AtomicU64,
    alerts_not_sent: AtomicU64,
}

/// Name of the query clause of a correlation leaf; `matched_queries` of a hit lists the leaves it matched.
const LEAF_PREFIX: &str = "ea3_leaf_";
/// Temporary key on a hit's document: the leaves it matched.
const LEAVES_KEY: &str = "_ea3_leaves";

/// Old-style `- query: {...}` filter entries are unwrapped.
pub fn unwrap_query(f: &Value) -> Value {
    f.get("query").cloned().unwrap_or_else(|| f.clone())
}

/// One clause for the leaves `members` (indexes into `leaves`) that share an index: any of them, each named.
fn leaves_filter(leaves: &[crate::rule::Leaf], members: &[usize]) -> Value {
    let named: Vec<Value> = members
        .iter()
        .map(|&i| json!({"bool": {"filter": leaves[i].filter.iter().map(unwrap_query).collect::<Vec<_>>(), "_name": format!("{LEAF_PREFIX}{i}")}}))
        .collect();
    json!({"bool": {"should": named, "minimum_should_match": 1}})
}

/// Leaves a hit matched, from its `matched_queries` (a list of names, or a map of name to score).
fn matched_leaves(hit: &Value) -> Vec<usize> {
    let names: Vec<&str> = match hit.get("matched_queries") {
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).collect(),
        Some(Value::Object(m)) => m.keys().map(String::as_str).collect(),
        _ => Vec::new(),
    };
    let mut leaves: Vec<usize> = names.into_iter().filter_map(|n| n.strip_prefix(LEAF_PREFIX)?.parse().ok()).collect();
    leaves.sort_unstable();
    leaves
}

fn id_hash(id: &str) -> u64 {
    let mut h = FxHasher::default();
    id.hash(&mut h);
    h.finish()
}

/// The `docvalue_fields` entries for `include`, from a `_field_caps` response; the reason when one field cannot be read
/// from doc values (missing, an object, a text field, several types, or a type whose doc values differ from `_source`).
fn doc_values_of(include: &[String], caps: &Value) -> std::result::Result<Vec<Value>, String> {
    const KINDS: [&str; 12] = ["keyword", "long", "integer", "short", "byte", "double", "float", "half_float", "scaled_float", "boolean", "ip", "date"];
    let mut out = Vec::new();
    for f in include {
        let types = caps["fields"][f.as_str()].as_object().filter(|t| !t.is_empty()).ok_or_else(|| format!("field {f} is not mapped to a single value type"))?;
        let (kind, cap) = match types.iter().collect::<Vec<_>>()[..] {
            [(kind, cap)] => (kind.as_str(), cap),
            _ => return Err(format!("field {f} has several types")),
        };
        if !KINDS.contains(&kind) || cap["aggregatable"] != json!(true) {
            return Err(format!("field {f} is {kind} without doc values"));
        }
        out.push(if kind == "date" { json!({"field": f, "format": "strict_date_optional_time"}) } else { json!({"field": f}) });
    }
    Ok(out)
}

/// Where to cut the range (`start`, `end`] in two, on a millisecond (the resolution of Elasticsearch dates); `None`
/// when a half would be shorter than that.
fn split_point(start: Ts, end: Ts) -> Option<Ts> {
    let mid = (start + (end - start) / 2).div_euclid(1_000) * 1_000;
    (mid > start && mid < end).then_some(mid)
}

/// Retry delay: 30 s doubling per attempt, at most one hour.
fn backoff(attempts: u32) -> Dur {
    (30 * SECOND << attempts.min(7)).min(60 * MINUTE)
}

impl RuleState {
    pub fn new(rule: Rule) -> Result<Self> {
        let mut alerters = Vec::new();
        let mut alert_rules = Vec::new();
        for (name, config) in rule.alerts.iter().zip(&rule.alert_configs) {
            let own = config.as_ref().map(|c| rule.with_alert_config(c)).transpose().with_context(|| format!("options of the alert {name}"))?;
            alerters.push(Alerter::from_rule(name, own.as_ref().unwrap_or(&rule))?);
            alert_rules.push(own);
        }
        Ok(RuleState {
            rtype: RuleType::new(&rule)?,
            alerters,
            alert_rules,
            pending: Vec::new(),
            agg: FxHashMap::default(),
            rule,
            starttime: None,
            previous_endtime: None,
            minimum_starttime: None,
            bucket_offset: 0,
            seen: FxHashMap::default(),
            corr_group: false,
            corr_buf: Vec::new(),
            doc_values: FxHashMap::default(),
            mock: None,
            has_run_once: false,
            next_min_start: None,
            hits: 0,
            dupes: 0,
            alerts_sent: AtomicU64::new(0),
            alerts_not_sent: AtomicU64::new(0),
        })
    }

    /// Only for building queries (`test-rule`): no alerters are created.
    pub fn new_for_query(rule: &Rule) -> Self {
        RuleState {
            rtype: RuleType::new(rule).unwrap_or(RuleType::Any),
            alerters: vec![],
            alert_rules: vec![],
            pending: vec![],
            agg: FxHashMap::default(),
            rule: rule.clone(),
            starttime: None,
            previous_endtime: None,
            minimum_starttime: None,
            bucket_offset: 0,
            seen: FxHashMap::default(),
            corr_group: false,
            corr_buf: Vec::new(),
            doc_values: FxHashMap::default(),
            mock: None,
            has_run_once: false,
            next_min_start: None,
            hits: 0,
            dupes: 0,
            alerts_sent: AtomicU64::new(0),
            alerts_not_sent: AtomicU64::new(0),
        }
    }

    /// After a reload: keep the query position, dedup set, unsent alerts and open aggregation groups.
    pub fn carry_over(&mut self, old: RuleState) {
        (self.starttime, self.previous_endtime, self.minimum_starttime, self.seen, self.pending, self.agg) =
            (old.starttime, old.previous_endtime, old.minimum_starttime, old.seen, old.pending, old.agg);
        if self.rule.kind.replays_window()
            && let Some(prev) = old.previous_endtime
        {
            // Open chains (or last positions) were lost with the old rule type: read the window again, without alerting twice.
            self.starttime = Some(prev - self.rule.timeframe.unwrap_or_default());
            self.rtype.suppress_until(prev);
            self.seen.clear();
        }
        let n = self.alerters.len();
        self.pending.iter_mut().for_each(|p| p.done.resize(n, false));
        if self.rule.aggregation.is_none() {
            // Aggregation was switched off: whatever is waiting goes out as soon as possible.
            for g in self.agg.values_mut() {
                g.alert_time = 0;
            }
        }
    }

    fn aggregating(&self) -> bool {
        self.rule.kind.is_agg_query()
    }

    fn counting(&self) -> bool {
        self.rule.use_count_query || self.rule.use_terms_query
    }

    // ---- queries ----

    fn range_field(&self) -> &str {
        self.rule.ingest_field.as_deref().unwrap_or(&self.rule.timestamp_field)
    }

    fn range_value(&self, ts: Ts) -> Value {
        if let (Some(tz), true) = (&self.rule.query_timezone, self.rule.timestamp_type == TsType::Iso || self.rule.ingest_field.is_some()) {
            return json!(crate::time::to_iso_in(ts, tz));
        }
        if self.rule.ingest_field.is_some() { json!(to_iso(ts)) } else { ts_value(&self.rule, ts) }
    }

    pub fn filters(&self, start: Ts, end: Ts, extra: Vec<Value>) -> Value {
        let mut must = vec![json!({"range": {self.range_field(): {"gt": self.range_value(start), "lte": self.range_value(end)}}})];
        // Old-style `- query: {...}` filter entries are unwrapped.
        must.extend(self.rule.filter.iter().map(unwrap_query));
        must.extend(self.rtype.extra_filter(&self.rule));
        must.extend(extra);
        json!({"bool": {"filter": {"bool": {"must": must}}}})
    }

    /// Range filter + user filters + timestamp sort, the query every hit search uses.
    pub fn query(&self, start: Ts, end: Ts) -> Value {
        let mut q = json!({
            "query": self.filters(start, end, vec![]),
            "sort": [{&self.rule.timestamp_field: {"order": "asc"}}],
            "_source": {"includes": self.rule.include},
        });
        if let Some(f) = &self.rule.include_fields {
            q["fields"] = json!(f);
        }
        if let Some(n) = self.rule.terminate_after {
            q["terminate_after"] = json!(n);
        }
        self.with_timeout(q)
    }

    /// Adds the rule's `search_timeout` to a search body.
    fn with_timeout(&self, mut body: Value) -> Value {
        if let Some(t) = self.rule.search_timeout {
            body["timeout"] = json!(format!("{}ms", t / 1_000));
        }
        body
    }

    pub fn index_for(&self, start: Ts, end: Ts) -> Result<String> {
        if self.rule.use_strftime_index { index::format_index(&self.rule.index, start, end, self.rule.search_extra_index) } else { Ok(self.rule.index.clone()) }
    }

    /// Turns raw hits into events: merges `fields`, parses the timestamp, copies metadata,
    /// builds compound query keys.
    fn process_hits(&self, hits: &mut [Value]) -> Result<Vec<Event>> {
        let mut out = Vec::with_capacity(hits.len());
        for hit in hits.iter_mut() {
            let mut doc = match hit.get_mut("_source").map(Value::take) {
                Some(Value::Object(m)) => m,
                _ => Map::new(),
            };
            if let Some(fields) = hit.get("fields").and_then(Value::as_object) {
                for (k, v) in fields {
                    let v = match v {
                        Value::Array(a) if a.len() == 1 => a[0].clone(),
                        other => other.clone(),
                    };
                    doc.entry(k.clone()).or_insert(v);
                }
            }
            let ts_raw = field::lookup(&doc, &self.rule.timestamp_field).with_context(|| {
                format!(
                    "the configured timestamp_field '{}' was not found in the query results. Available fields: {:?}",
                    self.rule.timestamp_field,
                    doc.keys().collect::<Vec<_>>()
                )
            })?;
            let ts = parse_ts(&self.rule, ts_raw).with_context(|| format!("cannot parse timestamp {ts_raw}"))?;
            for meta in ["_id", "_index", "_type"] {
                if let Some(v) = hit.get(meta) {
                    doc.insert(meta.into(), v.clone());
                }
            }
            if self.corr_group {
                doc.insert(LEAVES_KEY.into(), json!(matched_leaves(hit)));
            }
            for (key, parts) in [(&self.rule.query_key,&self.rule.compound_query_key), (&self.rule.aggregation_key, &self.rule.compound_aggregation_key)] {
                if let (Some(key), false) = (key, parts.is_empty()) {
                    let joined: Vec<String> = parts.iter().map(|k| field::lookup(&doc, k).map_or_else(|| "None".into(), py_str)).collect();
                    doc.insert(key.clone(), json!(joined.join(", ")));
                }
            }
            out.push(Event { ts, doc });
        }
        Ok(out)
    }

    /// Dedups a page of hits, feeds the fresh ones to the rule type.
    fn on_hits(&mut self, ctx: &Ctx, start: Ts, end: Ts, mut hits: Vec<Value>, scrolling: bool, matches: &mut Vec<Doc>) -> Result<()> {
        self.hits += hits.len() as u64;
        let (lt, fmt) = (self.rule.use_local_time, ctx.ts_fmt.as_deref());
        log::info!(
            "Queried rule {} from {} to {}: {} / {} hits{}",
            self.rule.name,
            pretty(start, lt, fmt),
            pretty(end, lt, fmt),
            self.hits,
            hits.len(),
            if scrolling { " (scrolling..)" } else { "" }
        );
        let events = self.process_hits(&mut hits)?;
        if self.corr_group {
            // A document matching several leaves is staged once per leaf.
            let before = events.len();
            let mut per_leaf: Vec<Vec<Event>> = vec![Vec::new(); self.rule.correlation.as_ref().map_or(0, |c| c.leaves.len())];
            for mut ev in events {
                let leaves: Vec<usize> = match ev.doc.remove(LEAVES_KEY) {
                    Some(Value::Array(a)) => a.iter().filter_map(|v| v.as_u64().map(|n| n as usize)).filter(|n| *n < per_leaf.len()).collect(),
                    _ => Vec::new(),
                };
                if let Some((last, rest)) = leaves.split_last() {
                    for l in rest {
                        per_leaf[*l].push(ev.clone());
                    }
                    per_leaf[*last].push(ev);
                }
            }
            // `num_hits` counted a document once per leaf it matched, when each leaf was a search of its own.
            self.hits += per_leaf.iter().map(Vec::len).sum::<usize>() as u64;
            self.hits = self.hits.saturating_sub(before as u64);
            for (leaf, evs) in per_leaf.into_iter().enumerate().filter(|(_, e)| !e.is_empty()) {
                self.stage_leaf_events(leaf, evs);
            }
            return Ok(());
        }
        let before = events.len();
        let fresh: Vec<Event> = events
            .into_iter()
            .filter(|e| match e.doc.get("_id").and_then(Value::as_str) {
                Some(id) => self.seen.insert(id_hash(id), e.ts).is_none(),
                None => true,
            })
            .collect();
        self.dupes += (before - fresh.len()) as u64;
        if !fresh.is_empty() {
            self.rtype.add_data(&self.rule, fresh, matches);
        }
        Ok(())
    }

    /// Queries [start, end] and feeds the result to the rule type (hits, count or terms).
    async fn run_query(&mut self, ctx: &Ctx, start: Ts, end: Ts, matches: &mut Vec<Doc>) -> Result<()> {
        if self.mock.is_some() {
            return self.run_mock(ctx, start, end, matches);
        }
        if self.rule.kind == Kind::Correlation {
            return self.correlation_query(ctx, start, end, matches).await;
        }
        let index = self.index_for(start, end)?;
        if self.aggregating() {
            return self.agg_query(ctx, &index, start, end, matches).await;
        }
        if self.rule.use_count_query {
            let body = json!({"query": self.filters(start, end, vec![])});
            let count = ctx.es.count(&index, &body).await.map_err(|e| anyhow::anyhow!("Error running count query: {e:#}"))?;
            self.hits += count;
            let (lt, fmt) = (self.rule.use_local_time, ctx.ts_fmt.as_deref());
            log::info!("Queried rule {} from {} to {}: {} hits", self.rule.name, pretty(start, lt, fmt), pretty(end, lt, fmt), count);
            self.rtype.add_count(&self.rule, end, count as i64, matches);
            return Ok(());
        }
        if self.rule.use_terms_query {
            let buckets = self.terms(ctx, &index, start, end, self.rule.query_key.clone().unwrap_or_default(), self.rule.terms_size, vec![]).await?;
            self.hits += buckets.len() as u64;
            let (lt, fmt) = (self.rule.use_local_time, ctx.ts_fmt.as_deref());
            log::info!("Queried rule {} from {} to {}: {} buckets", self.rule.name, pretty(start, lt, fmt), pretty(end, lt, fmt), buckets.len());
            self.rtype.add_terms(&self.rule, end, &buckets, matches);
            return Ok(());
        }
        if let Some(lang) = self.rule.query_lang {
            return self.lang_query(ctx, lang, &index, start, end, matches).await;
        }
        self.hit_search(ctx, &index, start, end, matches).await
    }

    /// Plain hit search over (start, end]: one plain request when the result fits a page, else point in time when
    /// available, scroll otherwise.
    async fn hit_search(&mut self, ctx: &Ctx, index: &str, start: Ts, end: Ts, matches: &mut Vec<Doc>) -> Result<()> {
        let mut body = self.query(start, end);
        if self.rule.read_doc_values
            && let Some(fields) = self.doc_value_fields(ctx, index).await
        {
            body["_source"] = json!(false);
            body["docvalue_fields"] = json!(fields);
        }
        if ctx.use_pit && ctx.es.supports_pit().await {
            // Most runs return less than a page: a plain request saves opening and closing the PIT. A full page may
            // be cut short, so it is dropped and the range is read again under the PIT (`search_after` needs it).
            let size = self.rule.max_query_size;
            if size > 0 {
                let mut probe = body.clone();
                probe["size"] = json!(size);
                probe["track_total_hits"] = json!(false);
                let mut resp = ctx.es.search_with(index, &probe, &self.rule.search_params).await?;
                check_shards(&resp, self.rule.allow_degraded, &self.rule.name)?;
                let hits = match resp["hits"]["hits"].take() {
                    Value::Array(a) => a,
                    _ => Vec::new(),
                };
                if (hits.len() as u64) < size {
                    return self.on_hits(ctx, start, end, hits, false, matches);
                }
            }
            match ctx.es.pit_open(index, "1m", &self.rule.search_params).await {
                Ok(id) => return self.pit_pages(ctx, start, end, body, id, matches).await,
                Err(e) => log::warn!("rule {}: point in time unavailable ({e:#}), using scroll", self.rule.name),
            }
        }
        self.scroll_pages(ctx, start, end, index, body, matches).await
    }

    /// `read_doc_values`: `docvalue_fields` for the fields the rule fetches, when every one of them is a single-type,
    /// aggregatable keyword, number, boolean, ip or date in `index`; otherwise `None` and `_source` is read.
    async fn doc_value_fields(&mut self, ctx: &Ctx, index: &str) -> Option<Vec<Value>> {
        if let Some(known) = self.doc_values.get(index) {
            return known.clone();
        }
        // A compound `query_key` is in the list as `a,b`; its parts are there too.
        let include: Vec<String> = self.rule.include.iter().filter(|f| !f.contains(',')).cloned().collect();
        let names = include.join(",");
        let resp = match ctx.es.get(&format!("{index}/_field_caps?fields={}&ignore_unavailable=true&allow_no_indices=true", crate::discover::quote_plus(&names))).await {
            Ok(r) => r,
            Err(e) => {
                log::warn!("Rule {}: cannot read the mappings of {index} for read_doc_values, reading _source: {e:#}", self.rule.name);
                return None;
            }
        };
        let fields = doc_values_of(&include, &resp);
        match &fields {
            Ok(_) => log::info!("Rule {}: reading {} from doc values in {index}", self.rule.name, names),
            Err(why) => log::warn!("Rule {}: read_doc_values is on but {why} in {index}, reading _source", self.rule.name),
        }
        let fields = fields.ok();
        self.doc_values.insert(index.to_string(), fields.clone());
        fields
    }

    /// `correlation` rules: one search per index (the filters of the leaves reading it are named alternatives added to
    /// the rule's, and each hit says which leaves it matched), all events merged by time and handed to the rule type
    /// together. Dedup hashes are only recorded once every search succeeded, so a failed run reads the range again.
    async fn correlation_query(&mut self, ctx: &Ctx, start: Ts, end: Ts, matches: &mut Vec<Doc>) -> Result<()> {
        let spec = self.rule.correlation.clone().expect("correlation rules always have leaves");
        let (base_filter, base_index) = (self.rule.filter.clone(), self.rule.index.clone());
        let mut searches: Vec<(String, Vec<usize>)> = Vec::new();
        for (i, leaf) in spec.leaves.iter().enumerate() {
            let index = leaf.index.clone().unwrap_or_else(|| base_index.clone());
            match searches.iter_mut().find(|(ix, _)| *ix == index) {
                Some((_, members)) => members.push(i),
                None => searches.push((index, vec![i])),
            }
        }
        let mut result = Ok(());
        self.corr_group = true;
        for (index, members) in searches {
            self.rule.filter = base_filter.iter().cloned().chain([leaves_filter(&spec.leaves, &members)]).collect();
            self.rule.index = index;
            result = async {
                let index = self.index_for(start, end)?;
                self.hit_search(ctx, &index, start, end, &mut Vec::new()).await
            }
            .await;
            if result.is_err() {
                break;
            }
        }
        (self.rule.filter, self.rule.index, self.corr_group) = (base_filter, base_index, false);
        let mut staged = std::mem::take(&mut self.corr_buf);
        result?;
        for (_, ev, hash) in &staged {
            self.seen.insert(*hash, ev.ts);
        }
        let doc_ref = |ev: &Event| -> Option<(String, String)> {
            let get = |k: &str| ev.doc.get(k).and_then(Value::as_str).map(String::from);
            Some((get("_index")?, get("_id")?))
        };
        staged.sort_by_cached_key(|(leaf, ev, _)| (ev.ts, doc_ref(ev), *leaf));
        // A document matching several leaves is one event with all of them.
        let mut events: Vec<(Vec<usize>, Event)> = Vec::with_capacity(staged.len());
        for (leaf, ev, _) in staged {
            match events.last_mut() {
                Some((tags, last)) if last.ts == ev.ts && doc_ref(last).is_some() && doc_ref(last) == doc_ref(&ev) => tags.push(leaf),
                _ => events.push((vec![leaf], ev)),
            }
        }
        self.rtype.add_correlation(&self.rule, events, matches);
        Ok(())
    }

    /// Keeps the new events of a correlation leaf: the pivot value is mapped from the leaf's own field, events without one are skipped.
    fn stage_leaf_events(&mut self, leaf: usize, events: Vec<Event>) {
        let rule = &self.rule;
        let leaf_key = rule.correlation.as_ref().and_then(|c| c.leaves[leaf].query_key.clone());
        let qk = rule.query_key.clone().unwrap_or_default();
        let before = events.len();
        let mut kept = 0;
        for mut ev in events {
            if let Some(sk) = &leaf_key
                && let Some(v) = field::lookup(&ev.doc, sk).cloned()
            {
                ev.doc.insert(qk.clone(), v);
            }
            let parts = if rule.compound_query_key.is_empty() { std::slice::from_ref(&qk) } else { &rule.compound_query_key[..] };
            if leaf_key.is_some() && !ev.doc.contains_key(&qk) || parts.iter().any(|k| field::lookup(&ev.doc, k).is_none_or(Value::is_null)) {
                continue;
            }
            let hash = match ev.doc.get("_id").and_then(Value::as_str) {
                Some(id) => id_hash(&format!("{leaf}\0{id}")),
                None => 0,
            };
            if hash != 0 && self.seen.contains_key(&hash) {
                self.dupes += 1;
                continue;
            }
            kept += 1;
            self.corr_buf.push((leaf, ev, hash));
        }
        log::debug!("Rule {}: leaf {} kept {kept} of {before} events", rule.name, rule.correlation.as_ref().map_or("", |c| c.leaves[leaf].name.as_str()));
    }

    /// EQL / ES|QL rules: one request per range, no paging (upstream cannot page them either), so results beyond
    /// `max_query_size` are lost and a warning says so. With `split_on_limit` a range that fills the limit is cut in
    /// two and each half is read on its own, again if needed, down to a millisecond.
    async fn lang_query(&mut self, ctx: &Ctx, lang: QueryLang, index: &str, start: Ts, end: Ts, matches: &mut Vec<Doc>) -> Result<()> {
        let size = self.rule.max_query_size;
        let mut todo = vec![(start, end)];
        while let Some((s, e)) = todo.pop() {
            let query = self.filters(s, e, vec![]);
            let body = querylang::request(&query, lang, size, &self.rule.timestamp_field).with_context(|| format!("no {} query found in the rule filter", lang.key()))?;
            let (hits, total) = match lang {
                QueryLang::Eql => {
                    let mut resp = ctx.es.eql_search(index, &body).await?;
                    let total = resp.pointer("/hits/total/value").and_then(Value::as_u64).unwrap_or(0);
                    (querylang::eql_hits(&mut resp)?, total)
                }
                QueryLang::Esql => {
                    let resp = ctx.es.esql_query(&body).await?;
                    let hits = querylang::esql_hits(&resp, index);
                    let n = hits.len() as u64;
                    (hits, n)
                }
            };
            let n = hits.len() as u64;
            let full = size > 0 && (total > n || n >= size);
            if full && self.rule.split_on_limit && let Some(mid) = split_point(s, e) {
                // Right half first on the stack, so the left (older) one is read first.
                todo.extend([(mid, e), (s, mid)]);
                continue;
            }
            self.on_hits(ctx, s, e, hits, false, matches)?;
            if full {
                log::warn!("Rule {}: {} queries cannot be paged, results beyond max_query_size ({size}) are not seen", self.rule.name, lang.key());
            }
        }
        Ok(())
    }

    /// metric_aggregation / percentage_match / spike_aggregation: the rule's aggregation, optionally split by
    /// `bucket_interval` (date histogram) and by each `query_key` field (terms), as upstream's `get_aggregation_query`.
    async fn agg_query(&mut self, ctx: &Ctx, index: &str, start: Ts, end: Ts, matches: &mut Vec<Doc>) -> Result<()> {
        let rule = &self.rule;
        let mut aggs = rule.agg_query.clone().expect("aggregation rule types always have one");
        if let Some((period, _)) = &rule.bucket_interval {
            let mut histogram = json!({"field": rule.timestamp_field, "fixed_interval": period});
            if self.bucket_offset > 0 {
                histogram["offset"] = json!(format!("+{}s", self.bucket_offset));
            }
            aggs = json!({"interval_aggs": {"date_histogram": histogram, "aggs": aggs}});
        }
        if let Some(qk) = &rule.query_key {
            let min = rule.raw.get("min_doc_count").and_then(Value::as_u64).unwrap_or(1);
            for field in qk.split(',').rev() {
                aggs = json!({"bucket_aggs": {"terms": {"field": field, "size": rule.terms_size, "min_doc_count": min}, "aggs": aggs}});
            }
        }
        let body = self.with_timeout(json!({"query": self.filters(start, end, vec![]), "size": 0, "aggs": aggs}));
        let resp = ctx.es.search_with(index, &body, &self.rule.search_params).await.map_err(|e| anyhow::anyhow!("Error running query: {e:#}"))?;
        check_timeout(&resp, self.rule.allow_degraded, &self.rule.name)?;
        let total = resp["hits"]["total"]["value"].as_u64().or_else(|| resp["hits"]["total"].as_u64()).unwrap_or(0);
        self.hits += total;
        let (lt, fmt) = (self.rule.use_local_time, ctx.ts_fmt.as_deref());
        log::info!("Queried rule {} from {} to {}: {} hits", self.rule.name, pretty(start, lt, fmt), pretty(end, lt, fmt), total);
        if let Some(payload) = resp.get("aggregations") {
            self.rtype.add_aggregation(&self.rule, end, payload, matches);
        }
        Ok(())
    }

    /// Terms aggregation `field` -> (key, doc_count), most frequent first.
    #[allow(clippy::too_many_arguments)]
    async fn terms(&self, ctx: &Ctx, index: &str, start: Ts, end: Ts, field: String, size: u64, extra: Vec<Value>) -> Result<Vec<(Value, i64)>> {
        let min = self.rule.raw.get("min_doc_count").and_then(Value::as_u64).unwrap_or(1);
        let body = self.with_timeout(json!({
            "query": self.filters(start, end, extra), "size": 0,
            "aggs": {"counts": {"terms": {"field": field, "size": size, "min_doc_count": min}}},
        }));
        let resp = ctx.es.search_with(index, &body, &self.rule.search_params).await.map_err(|e| anyhow::anyhow!("Error running terms query: {e:#}"))?;
        check_timeout(&resp, self.rule.allow_degraded, &self.rule.name)?;
        Ok(resp["aggregations"]["counts"]["buckets"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|b| (b["key"].clone(), b["doc_count"].as_i64().unwrap_or(0)))
            .collect())
    }

    /// Mock data (`test-rule --data`): same time filter as upstream's mock (`start <= ts < end`).
    fn run_mock(&mut self, ctx: &Ctx, start: Ts, end: Ts, matches: &mut Vec<Doc>) -> Result<()> {
        if self.rule.kind == Kind::Correlation {
            bail!("test-rule --data / --use-downloaded cannot replay correlation rules: each leaf is a search of its own");
        }
        if self.aggregating() {
            bail!("test-rule --data / --use-downloaded cannot replay aggregation rule types (metric_aggregation, percentage_match, spike_aggregation)");
        }
        let docs = self.mock.as_ref().expect("checked by caller");
        if self.rule.use_count_query {
            let n = docs.iter().filter(|d| self.in_range(d, start, end)).count();
            self.hits += n as u64;
            self.rtype.add_count(&self.rule, end, n as i64, matches);
            return Ok(());
        }
        if self.rule.use_terms_query {
            let qk = self.rule.query_key.clone().unwrap_or_default();
            let key = qk.strip_suffix(".keyword").or(qk.strip_suffix(".raw")).unwrap_or(&qk).to_string();
            let mut buckets: Vec<(Value, i64)> = Vec::new();
            for d in docs.iter().filter(|d| self.in_range(d, start, end)) {
                let Some(v) = field::lookup(d, &key).cloned() else { continue };
                match buckets.iter_mut().find(|(k, _)| *k == v) {
                    Some(b) => b.1 += 1,
                    None => buckets.push((v, 1)),
                }
            }
            buckets.sort_by(|a, b| b.1.cmp(&a.1));
            self.rtype.add_terms(&self.rule, end, &buckets, matches);
            return Ok(());
        }
        let hits: Vec<Value> = docs
            .iter()
            .filter(|d| self.in_range(d, start, end))
            .map(|d| {
                let mut src = d.clone();
                let id = src.remove("_id").unwrap_or(Value::Null);
                json!({"_id": id, "_source": src})
            })
            .collect();
        self.on_hits(ctx, start, end, hits, false, matches)
    }

    fn in_range(&self, d: &Doc, start: Ts, end: Ts) -> bool {
        field::lookup(d, &self.rule.timestamp_field).and_then(|v| parse_ts(&self.rule, v)).is_some_and(|t| start <= t && t < end)
    }

    async fn scroll_pages(&mut self, ctx: &Ctx, start: Ts, end: Ts, index: &str, body: Value, matches: &mut Vec<Doc>) -> Result<()> {
        let size = self.rule.max_query_size;
        let mut resp = ctx.es.search_scroll(index, &body, size, &ctx.scroll_keepalive, &self.rule.search_params).await?;
        let total = resp["hits"]["total"]["value"].as_u64().or_else(|| resp["hits"]["total"].as_u64()).unwrap_or(0);
        let (mut pages, mut seen_hits) = (0, 0u64);
        loop {
            pages += 1;
            check_shards(&resp, self.rule.allow_degraded, &self.rule.name)?;
            let hits = match resp["hits"]["hits"].take() {
                Value::Array(a) => a,
                _ => Vec::new(),
            };
            seen_hits += hits.len() as u64;
            let empty = hits.is_empty();
            self.on_hits(ctx, start, end, hits, total > size, matches)?;
            let scroll_id = resp["_scroll_id"].as_str().map(String::from);
            let more = !empty && seen_hits < total && (self.rule.max_scrolling_count == 0 || pages < self.rule.max_scrolling_count);
            match (scroll_id, more) {
                (Some(id), true) => resp = ctx.es.scroll(&id, &ctx.scroll_keepalive).await?,
                (Some(id), false) => {
                    ctx.es.clear_scroll(&id).await;
                    return Ok(());
                }
                (None, _) => return Ok(()),
            }
        }
    }

    /// Point in time + `search_after`: no scroll contexts held, no page cap.
    async fn pit_pages(&mut self, ctx: &Ctx, start: Ts, end: Ts, mut body: Value, mut pit: String, matches: &mut Vec<Doc>) -> Result<()> {
        let size = self.rule.max_query_size;
        body["sort"] = json!([{&self.rule.timestamp_field: {"order": "asc"}}, {"_shard_doc": "asc"}]);
        body["size"] = json!(size);
        body["track_total_hits"] = json!(false);
        let mut pages = 0;
        let result = async {
            loop {
                pages += 1;
                body["pit"] = json!({"id": pit, "keep_alive": "1m"});
                let mut resp = ctx.es.pit_search(&body).await?;
                check_shards(&resp, self.rule.allow_degraded, &self.rule.name)?;
                if let Some(p) = resp["pit_id"].as_str() {
                    pit = p.to_string();
                }
                let hits = match resp["hits"]["hits"].take() {
                    Value::Array(a) => a,
                    _ => Vec::new(),
                };
                let n = hits.len() as u64;
                let last = hits.last().and_then(|h| h.get("sort")).cloned();
                self.on_hits(ctx, start, end, hits, pages > 1 || n >= size, matches)?;
                match last {
                    Some(l) if n >= size && (self.rule.max_scrolling_count == 0 || pages < self.rule.max_scrolling_count) => body["search_after"] = l,
                    _ => return Ok::<(), anyhow::Error>(()),
                }
            }
        }
        .await;
        ctx.es.pit_close(&pit).await;
        result
    }

    // ---- limit_execution ----

    /// `limit_execution`: when the run after this one would fall outside the cron window, the time the rule
    /// should wake up at instead. Remembers where to resume when `limit_execution_coverage` is on.
    pub fn limit_check(&mut self, endtime: Ts) -> Option<Ts> {
        self.next_min_start = None;
        let cron = self.rule.limit_execution.as_deref()?.parse::<croner::Cron>().ok()?;
        let next = cron.find_next_occurrence(&chrono::Utc::now(), false).ok()?.timestamp_micros();
        let until = pause_until(next, endtime, self.rule.run_every)?;
        if self.rule.limit_execution_coverage {
            self.next_min_start = Some(until);
        }
        Some(until)
    }

    /// The rule sleeps until `until`; with coverage on, the skipped time is not queried afterwards.
    pub fn pause(&mut self, until: Ts, ts_fmt: Option<&str>) {
        if let Some(t) = self.next_min_start {
            self.minimum_starttime = Some(t);
            self.previous_endtime = Some(t);
        }
        log::info!("Pausing {} until next run at {}", self.rule.name, pretty(until, true, ts_fmt));
    }

    // ---- run position ----

    /// Last `endtime` this rule recorded in the status index, if recent enough.
    async fn last_run_end(&self, ctx: &Ctx) -> Option<Ts> {
        let body = json!({
            "query": {"bool": {"filter": {"term": {"rule_name": self.rule.name}}}},
            "sort": {"@timestamp": {"order": "desc"}},
            "size": 1,
            "_source": ["endtime", "rule_name"],
        });
        let index = ctx.writeback.index_for(Wb::Status);
        match ctx.es.search(&index, &body).await {
            Ok(r) => {
                let end = parse_iso(r["hits"]["hits"][0]["_source"]["endtime"].as_str()?)?;
                if now() - end < ctx.old_query_limit {
                    Some(end)
                } else {
                    log::info!("Found expired previous run for {} at {}", self.rule.name, to_iso(end));
                    None
                }
            }
            Err(e) => {
                ctx.writeback.error(format!("Error querying for last run: {e:#}"), json!({"rule": self.rule.name})).await;
                None
            }
        }
    }

    async fn set_starttime(&mut self, ctx: &Ctx, endtime: Ts) {
        if self.starttime.is_none()
            && !self.rule.scan_entire_timeframe
            && !ctx.debug
            && let Some(last) = self.last_run_end(ctx).await
        {
            self.starttime = Some(self.overlap(last));
            if self.rule.kind.replays_window() {
                // Chains in progress at the last run are rebuilt from the window before it, without alerting twice.
                self.starttime = Some(last - self.rule.timeframe.unwrap_or_default());
                self.rtype.suppress_until(last);
            }
            self.sync_interval();
            self.minimum_starttime = self.starttime;
            return;
        }
        if self.counting() {
            // Count and terms queries read exactly one run_every per run.
            self.starttime = Some(if self.rule.scan_entire_timeframe {
                endtime - self.rule.timeframe.unwrap_or_default()
            } else {
                self.previous_endtime.unwrap_or(endtime - ctx.run_every)
            });
            return;
        }
        let back = if self.rule.scan_entire_timeframe { self.rule.timeframe.unwrap_or_default() } else { self.rule.buffer_time };
        let buffer_delta = endtime - back;
        self.starttime = Some(match (self.minimum_starttime, self.previous_endtime) {
            // Documents carry an ingest time: no need to re-read the overlap, just continue where we stopped.
            _ if self.rule.ingest_field.is_some() && !self.rule.scan_entire_timeframe => self.previous_endtime.or(self.minimum_starttime).unwrap_or(buffer_delta),
            (Some(min), _) if min > buffer_delta => min,
            (_, Some(prev)) if prev < buffer_delta => self.overlap(prev),
            _ => buffer_delta,
        });
        self.sync_interval();
    }

    /// `allow_buffer_time_overlap`: aggregation queries restart `buffer_time - run_every` earlier.
    fn overlap(&self, start: Ts) -> Ts {
        let r = &self.rule;
        if self.aggregating() && r.allow_buffer_time_overlap && !r.use_run_every_query_size && r.buffer_time > r.run_every { start - (r.buffer_time - r.run_every) } else { start }
    }

    /// `bucket_interval`: either snap the start to a bucket boundary (`sync_bucket_interval`) or shift the buckets to it.
    fn sync_interval(&mut self) {
        let (Some((_, interval)), Some(start)) = (&self.rule.bucket_interval, self.starttime) else { return };
        let (secs, step) = (start.div_euclid(SECOND), (interval / SECOND).max(1));
        let offset = secs.rem_euclid(step);
        if self.rule.sync_bucket_interval {
            self.starttime = Some((secs - offset) * SECOND);
        } else {
            self.bucket_offset = offset;
        }
    }

    /// One run over (start, endtime]. Returns the number of matches.
    pub async fn run(&mut self, ctx: &Ctx, endtime: Ts, starttime: Option<Ts>) -> Result<usize> {
        let t0 = std::time::Instant::now();
        if !ctx.debug {
            self.retry_pending(ctx).await;
        }
        self.rtype.init(&self.rule, &ctx.es, starttime).await?;
        match starttime {
            Some(s) => self.starttime = Some(s),
            None => self.set_starttime(ctx, endtime).await,
        }
        let original_start = self.starttime.expect("starttime set above");
        (self.hits, self.dupes) = (0, 0);
        *self.alerts_sent.get_mut() = 0;
        *self.alerts_not_sent.get_mut() = 0;
        if now() <= original_start {
            log::warn!("Attempted to use query start time in the future ({}), sleeping instead", to_iso(original_start));
            return Ok(0);
        }

        // Long ranges are split into segments, like a continuously running instance would see them.
        let agg = self.aggregating();
        let segment = if self.counting() || (agg && self.rule.use_run_every_query_size) { ctx.run_every } else { self.rule.buffer_time }.max(1);
        let mut matches = Vec::new();
        let mut start = original_start;
        while endtime - start > segment {
            let seg_end = start + segment;
            self.run_query(ctx, start, seg_end, &mut matches).await?;
            start = seg_end;
            self.starttime = Some(start);
            self.rtype.garbage_collect(&self.rule, seg_end, &mut matches);
        }
        let mut endtime = endtime;
        if !agg {
            self.run_query(ctx, start, endtime, &mut matches).await?;
            self.rtype.garbage_collect(&self.rule, endtime, &mut matches);
        } else if endtime - start == segment {
            // Aggregations only run over whole segments (like upstream); a shorter rest waits for the next run.
            self.run_query(ctx, start, endtime, &mut matches).await?;
        } else if start == original_start {
            return Ok(0);
        } else {
            endtime = start;
        }
        self.enrich(ctx, &mut matches).await;

        let num_matches = matches.len();
        let mut silenced = 0u64;
        for mut m in matches {
            m.insert("num_hits".into(), json!(self.hits));
            m.insert("num_matches".into(), json!(num_matches));
            if let Some(hours) = &self.rule.active_hours {
                let ts = field::lookup(&m, &self.rule.timestamp_field).and_then(|v| parse_ts(&self.rule, v)).unwrap_or_else(now);
                if !hours.contains(ts) {
                    log::info!("Ignoring match for rule {} outside active_hours", self.rule.name);
                    continue;
                }
            }
            let mut key = self.rule.realert_key.clone();
            let qv = self.rtype.silence_key(&m).or_else(|| self.rule.query_key.as_ref().and_then(|qk| field::lookup(&m, qk)).map(py_str));
            if let Some(qv) = qv {
                key = format!("{key}.{qv}");
            }
            if ctx.silences.is_silenced(&key) || ctx.silences.is_silenced(&format!("{}._silence", self.rule.name)) {
                log::info!("Ignoring match for silenced rule {key}");
                silenced += 1;
                continue;
            }
            if self.rule.realert > 0 {
                let (until, exponent) = self.next_alert_time(ctx, &key, now());
                ctx.silences.set(&key, until, exponent);
                let doc = json!({"exponent": exponent, "rule_name": key, "@timestamp": to_iso(now()), "until": to_iso(until)});
                ctx.writeback.write(Wb::Silence, doc.as_object().cloned().unwrap_or_default()).await;
            }
            // Upstream: run first, a failing enhancement keeps the match, a dropped one is still silenced.
            if self.rule.run_enhancements_first && self.enhance_one(ctx, &mut m).await == Enhanced::Dropped {
                continue;
            }
            if self.rule.aggregation.is_some() {
                self.add_aggregated(ctx, m).await;
            } else {
                self.alert(ctx, vec![m]).await;
            }
        }

        self.previous_endtime = Some(endtime);
        let took = t0.elapsed().as_secs_f64();
        let status = json!({
            "rule_name": self.rule.name,
            "endtime": to_iso(endtime),
            "starttime": to_iso(original_start),
            "matches": num_matches,
            "hits": self.hits,
            "@timestamp": to_iso(now()),
            "time_taken": took,
        });
        ctx.writeback.write(Wb::Status, status.as_object().cloned().unwrap_or_default()).await;
        let (lt, fmt) = (self.rule.use_local_time, ctx.ts_fmt.as_deref());
        let sent = self.alerts_sent.load(Ordering::Relaxed);
        log::info!(
            "Ran {} from {} to {}: {} query hits ({} already seen), {} matches, {} alerts sent",
            self.rule.name,
            pretty(original_start, lt, fmt),
            pretty(endtime, lt, fmt),
            self.hits,
            self.dupes,
            num_matches,
            sent
        );
        ctx.metrics.rule(&self.rule.name, |c| {
            c.scrapes += 1;
            c.hits += self.hits;
            c.matches += num_matches as u64;
            c.time_taken += took;
            c.alerts_sent += sent;
            c.alerts_not_sent += self.alerts_not_sent.load(Ordering::Relaxed);
            c.alerts_silenced += silenced;
            c.last_end = Some(endtime as f64 / SECOND as f64);
            c.last_success = Some(now() as f64 / SECOND as f64);
        });
        Ok(num_matches)
    }

    fn next_alert_time(&self, ctx: &Ctx, key: &str, ts: Ts) -> (Ts, i32) {
        next_alert(self.rule.realert, self.rule.exponential_realert, ctx.silences.get(key), ts)
    }

    // ---- enrichment ----

    /// Matches were built from projected documents; fetch the full `_source` of the few that matched.
    async fn enrich(&self, ctx: &Ctx, matches: &mut [Doc]) {
        if !self.rule.enrich || matches.is_empty() || self.mock.is_some() {
            return;
        }
        fn collect(m: &Doc, out: &mut FxHashSet<(String, String)>) {
            if let (Some(i), Some(d)) = (m.get("_index").and_then(Value::as_str), m.get("_id").and_then(Value::as_str)) {
                out.insert((i.to_string(), d.to_string()));
            }
            for r in m.get("related_events").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_object) {
                collect(r, out);
            }
            for l in m.get("correlation").and_then(|c| c.get("leaves")).and_then(Value::as_object).into_iter().flat_map(Map::values).filter_map(Value::as_object) {
                collect(l, out);
            }
        }
        let mut wanted = FxHashSet::default();
        matches.iter().for_each(|m| collect(m, &mut wanted));
        let wanted: Vec<_> = wanted.into_iter().collect();
        let mut full: FxHashMap<(String, String), Doc> = FxHashMap::default();
        for chunk in wanted.chunks(500) {
            match ctx.es.mget(chunk).await {
                Ok(docs) => {
                    for d in docs {
                        if let (Some(i), Some(id), Some(src)) = (d["_index"].as_str(), d["_id"].as_str(), d["_source"].as_object()) {
                            full.insert((i.to_string(), id.to_string()), src.clone());
                        }
                    }
                }
                Err(e) => log::warn!("rule {}: could not fetch full documents for matches, alerting with partial data: {e:#}", self.rule.name),
            }
        }
        // Fields we asked ES for are replaced by the full values; everything else on the match
        // (num_hits, spike_count, key, ...) was added by the rule and stays.
        let mut tops: FxHashSet<&str> = FxHashSet::default();
        for f in &self.rule.include {
            tops.insert(f.as_str());
            tops.insert(f.split('.').next().unwrap_or(f));
        }
        fn apply(m: &mut Doc, full: &FxHashMap<(String, String), Doc>, tops: &FxHashSet<&str>, ts_field: &str, flat: &[&str]) {
            if let (Some(i), Some(d)) = (m.get("_index").and_then(Value::as_str), m.get("_id").and_then(Value::as_str))
                && let Some(src) = full.get(&(i.to_string(), d.to_string()))
            {
                // Doc values come as flat `a.b` keys; the whole document has them nested.
                for f in flat {
                    m.remove(*f);
                }
                let ts = field::lookup(m, ts_field).cloned();
                for (k, v) in src {
                    if tops.contains(k.as_str()) {
                        m.insert(k.clone(), v.clone());
                    } else {
                        m.entry(k.clone()).or_insert_with(|| v.clone());
                    }
                }
                if let Some(ts) = ts
                    && !field::set(m, ts_field, ts.clone())
                {
                    m.insert(ts_field.to_string(), ts);
                }
            }
            if let Some(Value::Array(rel)) = m.get_mut("related_events") {
                for r in rel.iter_mut().filter_map(Value::as_object_mut) {
                    apply(r, full, tops, ts_field, flat);
                }
            }
            if let Some(Value::Object(leaves)) = m.get_mut("correlation").and_then(|c| c.get_mut("leaves")) {
                for l in leaves.values_mut().filter_map(Value::as_object_mut) {
                    apply(l, full, tops, ts_field, flat);
                }
            }
        }
        let flat: Vec<&str> = if self.rule.read_doc_values { self.rule.include.iter().map(String::as_str).filter(|f| f.contains('.')).collect() } else { vec![] };
        for m in matches.iter_mut() {
            apply(m, &full, &tops, &self.rule.timestamp_field, &flat);
        }
    }

    // ---- top counts ----

    /// `top_events_<key>`: most frequent values of each `top_count_keys` field around the match.
    async fn add_top_counts(&self, ctx: &Ctx, m: &mut Doc) {
        if self.rule.top_count_keys.is_empty() {
            return;
        }
        let Some(ts) = field::lookup(m, &self.rule.timestamp_field).and_then(|v| parse_ts(&self.rule, v)) else { return };
        let timeframe = match (&self.rtype, self.rule.timeframe) {
            (RuleType::Flatline(_), Some(t)) => 2 * t,
            (_, Some(t)) => t,
            (_, None) => 10 * MINUTE,
        };
        let (start, end) = (ts - timeframe, ts + 10 * MINUTE);
        let qk = self.rule.query_key.as_ref().and_then(|q| field::lookup(m, q)).map(py_str);
        let extra = self.query_key_filters(qk.as_deref());
        for key in &self.rule.top_count_keys {
            let counts: Doc = if self.mock.is_some() {
                self.mock_top_counts(key, start, end, qk.as_deref())
            } else {
                let result = match self.index_for(start, end) {
                    Ok(index) => self.terms(ctx, &index, start, end, key.clone(), self.rule.top_count_number, extra.clone()).await,
                    Err(e) => Err(e),
                };
                match result {
                    Ok(b) => b.into_iter().map(|(k, n)| (py_str(&k), json!(n))).collect(),
                    Err(e) => {
                        ctx.writeback.error(format!("{e:#}"), json!({"rule": self.rule.name})).await;
                        Doc::new()
                    }
                }
            };
            m.insert(format!("top_events_{key}"), Value::Object(counts));
        }
    }

    fn mock_top_counts(&self, key: &str, start: Ts, end: Ts, qk: Option<&str>) -> Doc {
        let key = key.strip_suffix(".keyword").or(key.strip_suffix(".raw")).unwrap_or(key);
        let mut counts: Vec<(String, i64)> = Vec::new();
        for d in self.mock.iter().flatten().filter(|d| self.in_range(d, start, end)) {
            if let (Some(q), Some(want)) = (&self.rule.query_key, qk)
                && field::lookup(d, q).map(py_str).as_deref() != Some(want)
            {
                continue;
            }
            let Some(v) = field::lookup(d, key) else { continue };
            let v = py_str(v);
            match counts.iter_mut().find(|(k, _)| *k == v) {
                Some(c) => c.1 += 1,
                None => counts.push((v, 1)),
            }
        }
        counts.sort_by(|a, b| b.1.cmp(&a.1));
        counts.truncate(self.rule.top_count_number as usize);
        counts.into_iter().map(|(k, n)| (k, json!(n))).collect()
    }

    /// Term filters restricting the top counts to the match's `query_key` value(s).
    fn query_key_filters(&self, qk: Option<&str>) -> Vec<Value> {
        let Some(qk) = qk else { return vec![] };
        let values: Vec<&str> = qk.split(',').map(str::trim_start).collect();
        let keys: Vec<String> = if self.rule.compound_query_key.is_empty() { self.rule.query_key.iter().cloned().collect() } else { self.rule.compound_query_key.clone() };
        if values.len() != keys.len() {
            log::warn!("Received {} value(s) for {} key(s). Did '{qk}' have a value with a comma?", values.len(), keys.len());
        }
        let raw = self.rule.raw.get("raw_count_keys").and_then(Value::as_bool).unwrap_or(true);
        keys.into_iter()
            .zip(values)
            .map(|(k, v)| json!({"term": {if raw && !k.ends_with(".keyword") { format!("{k}.keyword") } else { k }: v}}))
            .collect()
    }

    // ---- alerting ----

    /// Runs every alerter not yet done for `p`. Returns true when all succeeded.
    async fn deliver(&self, ctx: &Ctx, p: &mut Pending) -> bool {
        let pipeline = crate::alerters::Pipeline::default();
        pipeline.lock().expect("fresh mutex").insert("alert_time".into(), json!(to_iso(p.alert_time)));
        let mut all = true;
        let labels = self.rule.alert_labels();
        for (i, a) in self.alerters.iter().enumerate() {
            if p.done[i] {
                continue;
            }
            let rule = self.alert_rules[i].as_ref().unwrap_or(&self.rule);
            let view = View { rule, rtype: &self.rtype, ts_fmt: ctx.ts_fmt.as_deref(), pipeline: &pipeline };
            match a.alert(&view, &p.matches).await {
                Ok(()) => {
                    p.done[i] = true;
                    self.alerts_sent.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    all = false;
                    p.exception = format!("{e:#}");
                    self.alerts_not_sent.fetch_add(1, Ordering::Relaxed);
                    ctx.metrics.error();
                    ctx.writeback.error(format!("Error while running alert {}: {e:#}", labels[i]), json!({"rule": self.rule.name})).await;
                }
            }
        }
        all
    }

    /// `add_metadata_alert`: category, description, owner and priority of the rule go into the alert doc.
    fn add_metadata(&self, doc: &mut Doc) {
        if self.rule.raw.get("add_metadata_alert").and_then(Value::as_bool).unwrap_or(false) {
            let text = |k: &str, d: &str| self.rule.raw.get(k).map_or_else(|| d.to_string(), py_str);
            doc.insert("category".into(), json!(text("category", "")));
            doc.insert("description".into(), json!(text("description", "")));
            doc.insert("owner".into(), json!(text("owner", "")));
            doc.insert("priority".into(), json!(text("priority", "2")));
        }
        if let Some(m) = crate::mitre::writeback(&self.rule.mitre_attack) {
            doc.insert("mitre_attack".into(), m);
        }
    }

    /// Writes the alert doc(s) for `p`: one per match, same `_id` every time so updates overwrite.
    /// An aggregated alert is one doc (the first match); the other matches' docs are deleted once it is fully sent.
    async fn write_alert(&self, ctx: &Ctx, p: &mut Pending) {
        let labels = self.rule.alert_labels();
        let sent: Vec<&str> = labels.iter().zip(&p.done).filter(|(_, d)| **d).map(|(l, _)| l.as_str()).collect();
        let complete = p.done.iter().all(|d| *d);
        let grouped = !p.child_ids.is_empty();
        for (n, m) in p.matches.iter().enumerate() {
            if grouped && n > 0 {
                break;
            }
            let mut doc = Map::new();
            if let Some(t) = match_time(&self.rule, m) {
                doc.insert("match_time".into(), t);
            }
            doc.insert("rule_name".into(), json!(self.rule.name));
            doc.insert("alert_info".into(), self.alerters.first().map_or(json!({}), Alerter::info));
            doc.insert("alert_sent".into(), json!(complete));
            doc.insert("alert_time".into(), json!(to_iso(p.alert_time)));
            doc.insert("alerters_sent".into(), json!(sent));
            doc.insert("retry_count".into(), json!(p.attempts));
            if !complete {
                doc.insert("alert_exception".into(), json!(p.exception));
            }
            self.add_metadata(&mut doc);
            doc.insert("match_body".into(), Value::Object(m.clone()));
            let id = if n == 0 { p.id.clone() } else { Writeback::new_id() };
            ctx.writeback.write_id(Wb::Alert, &id, doc).await;
        }
        if complete {
            for id in p.child_ids.drain(..) {
                ctx.writeback.delete_id(Wb::Alert, &id).await;
            }
        }
    }

    /// Runs the enhancements on a match in order; a drop stops the chain.
    async fn enhance_one(&self, ctx: &Ctx, m: &mut Doc) -> Enhanced {
        let mut result = Enhanced::Kept;
        for e in &self.rule.enhancements {
            match e.process(m) {
                Ok(Outcome::Keep) => {}
                Ok(Outcome::Drop) => return Enhanced::Dropped,
                Err(err) => {
                    result = Enhanced::Failed;
                    ctx.metrics.error();
                    ctx.writeback.error(format!("Error running match enhancement: {err:#}"), json!({"rule": self.rule.name})).await;
                }
            }
        }
        result
    }

    /// Everything a match gets right before alerting: top counts, Discover links (on the first match, as upstream)
    /// and, unless `run_enhancements_first`, the enhancements. A match an enhancement fails on is dropped.
    async fn finish(&self, ctx: &Ctx, mut matches: Vec<Doc>) -> Vec<Doc> {
        for m in &mut matches {
            self.add_top_counts(ctx, m).await;
        }
        if let Some(first) = matches.first_mut() {
            if self.rule.kibana_discover
                && let Some(url) = discover::kibana_link(&self.rule, first).await
            {
                first.insert("kibana_discover_url".into(), json!(url));
            }
            if self.rule.opensearch_discover
                && let Some(url) = discover::opensearch_link(&self.rule, first)
            {
                first.insert("opensearch_discover_url".into(), json!(url));
            }
        }
        if !self.rule.run_enhancements_first && !self.rule.enhancements.is_empty() {
            let mut kept = Vec::with_capacity(matches.len());
            for mut m in matches {
                if self.enhance_one(ctx, &mut m).await == Enhanced::Kept {
                    kept.push(m);
                }
            }
            matches = kept;
        }
        matches
    }

    async fn alert(&mut self, ctx: &Ctx, matches: Vec<Doc>) {
        let matches = self.finish(ctx, matches).await;
        if matches.is_empty() {
            return;
        }
        if ctx.debug {
            alert::debug_alert(&self.rule, &self.rtype, &matches, ctx.ts_fmt.as_deref());
            return; // --debug never counts as sent, like upstream
        }
        let p = Pending {
            id: Writeback::new_id(),
            matches,
            done: vec![false; self.alerters.len()],
            attempts: 0,
            next_try: 0,
            alert_time: now(),
            exception: String::new(),
            child_ids: vec![],
        };
        self.send(ctx, p).await;
    }

    async fn send(&mut self, ctx: &Ctx, mut p: Pending) {
        let ok = self.deliver(ctx, &mut p).await;
        if !ok {
            p.attempts += 1;
            p.next_try = now() + backoff(p.attempts);
        }
        self.write_alert(ctx, &mut p).await;
        if !ok {
            self.pending.push(p);
        }
    }

    /// Re-sends alerts whose alerters failed earlier; only the failed alerters are retried.
    async fn retry_pending(&mut self, ctx: &Ctx) {
        let mut pending = std::mem::take(&mut self.pending);
        let mut keep = Vec::new();
        for mut p in pending.drain(..) {
            if now() - p.alert_time > ctx.alert_time_limit {
                log::warn!("Giving up on alert {} of rule {}: older than alert_time_limit", p.id, self.rule.name);
                continue;
            }
            if p.next_try > now() {
                keep.push(p);
                continue;
            }
            let ok = self.deliver(ctx, &mut p).await;
            p.attempts += 1;
            if !ok {
                p.next_try = now() + backoff(p.attempts);
            }
            self.write_alert(ctx, &mut p).await;
            if !ok {
                keep.push(p);
            }
        }
        self.pending = keep;
    }

    /// Puts back an alert that failed before the last shutdown.
    pub fn restore_pending(&mut self, p: Pending) {
        self.pending.push(p);
    }

    // ---- aggregation ----

    fn aggregation_key_value(&self, m: &Doc) -> String {
        match &self.rule.aggregation_key {
            Some(k) => field::lookup(m, k).map_or_else(String::new, py_str),
            None => String::new(),
        }
    }

    fn first_alert_time(&self, m: &Doc) -> Ts {
        match self.rule.aggregation.as_ref() {
            Some(Aggregation::Cron(c)) => c
                .parse::<croner::Cron>()
                .ok()
                .and_then(|cron| cron.find_next_occurrence(&chrono::Utc::now(), false).ok())
                .map_or_else(now, |t| t.timestamp_micros()),
            Some(Aggregation::Timespan(d)) => {
                let base = if self.rule.raw.get("aggregate_by_match_time").and_then(Value::as_bool).unwrap_or(false) {
                    field::lookup(m, &self.rule.timestamp_field).and_then(|v| parse_ts(&self.rule, v)).unwrap_or_else(now)
                } else {
                    now()
                };
                base + d
            }
            None => now(),
        }
    }

    /// Queues a match in its group; the group is sent when its time comes (or at shutdown / replay end).
    async fn add_aggregated(&mut self, ctx: &Ctx, m: Doc) {
        let key = self.aggregation_key_value(&m);
        if self.agg.get(&key).is_some_and(|g| g.alert_time < now()) {
            self.flush_group(ctx, &key).await; // due but not sent yet: send it, then start a new one
        }
        let is_new = !self.agg.contains_key(&key);
        if is_new {
            let alert_time = self.first_alert_time(&m);
            log::info!("New aggregation for {}, aggregation_key: {key}. next alert at {}.", self.rule.name, to_iso(alert_time));
            self.agg.insert(key.clone(), AggGroup { alert_time, head_id: Writeback::new_id(), matches: vec![], child_ids: vec![] });
        }
        let g = self.agg.get_mut(&key).expect("inserted above");
        let (id, alert_time, head_id) = if is_new {
            (g.head_id.clone(), g.alert_time, None)
        } else {
            let id = Writeback::new_id();
            g.child_ids.push(id.clone());
            (id, g.alert_time, Some(g.head_id.clone()))
        };
        g.matches.push(m.clone());
        let mut doc = Map::new();
        if let Some(t) = match_time(&self.rule, &m) {
            doc.insert("match_time".into(), t);
        }
        doc.insert("rule_name".into(), json!(self.rule.name));
        doc.insert("alert_info".into(), self.alerters.first().map_or(json!({}), Alerter::info));
        doc.insert("alert_sent".into(), json!(false));
        doc.insert("alert_time".into(), json!(to_iso(alert_time)));
        if !key.is_empty() {
            doc.insert("aggregation_key".into(), json!(key));
        }
        if let Some(h) = head_id {
            doc.insert("aggregate_id".into(), json!(h));
        }
        self.add_metadata(&mut doc);
        doc.insert("match_body".into(), Value::Object(m));
        if !ctx.debug {
            ctx.writeback.write_id(Wb::Alert, &id, doc).await;
        }
    }

    pub fn next_agg_due(&self) -> Option<Ts> {
        self.agg.values().map(|g| g.alert_time).min()
    }

    async fn flush_group(&mut self, ctx: &Ctx, key: &str) {
        let Some(g) = self.agg.remove(key) else { return };
        log::info!("Sending aggregated alert of {} ({} matches, aggregation_key: {key})", self.rule.name, g.matches.len());
        let matches = self.finish(ctx, g.matches).await;
        if matches.is_empty() {
            // Every match was dropped by an enhancement: the pending docs have nothing left to send.
            for id in g.child_ids.iter().chain([&g.head_id]) {
                ctx.writeback.delete_id(Wb::Alert, id).await;
            }
            return;
        }
        if ctx.debug {
            alert::debug_alert(&self.rule, &self.rtype, &matches, ctx.ts_fmt.as_deref());
            return;
        }
        let p = Pending {
            id: g.head_id,
            matches,
            done: vec![false; self.alerters.len()],
            attempts: 0,
            next_try: 0,
            alert_time: g.alert_time,
            exception: String::new(),
            child_ids: g.child_ids,
        };
        self.send(ctx, p).await;
    }

    /// Sends the groups whose time has come (`all`: every group, used at the end of a replay).
    pub async fn flush_due(&mut self, ctx: &Ctx, all: bool) {
        let t = now();
        let keys: Vec<String> = self.agg.iter().filter(|(_, g)| all || g.alert_time <= t).map(|(k, _)| k.clone()).collect();
        for k in keys {
            self.flush_group(ctx, &k).await;
        }
    }

    /// Rebuilds a group from the pending docs found in ES at startup.
    pub fn restore_group(&mut self, key: String, head_id: String, alert_time: Ts, matches: Vec<Doc>, child_ids: Vec<String>) {
        self.agg.insert(key, AggGroup { alert_time, head_id, matches, child_ids });
    }

    /// Forgets dedup ids older than buffer_time (+ query_delay).
    pub fn forget_old_hits(&mut self) {
        let horizon = now() - self.rule.buffer_time - self.rule.query_delay;
        self.seen.retain(|_, ts| *ts >= horizon);
    }

}

/// Port of `next_alert_time`: with `exponential_realert` the silence doubles while matches keep coming.
/// `cached` is the previous (until, exponent) for the same key.
/// Result of the enhancement chain on one match.
#[derive(PartialEq)]
enum Enhanced {
    Kept,
    Dropped,
    /// An enhancement returned an error (logged).
    Failed,
}

/// Upstream: pause unless the estimated next end time (`end + run_every`) is within a minute of the next cron time.
fn pause_until(exec_next: Ts, endtime: Ts, run_every: Dur) -> Option<Ts> {
    (endtime + run_every < exec_next - 59 * SECOND).then_some(exec_next)
}

fn next_alert(realert: Dur, max: Option<Dur>, cached: Option<(Ts, i32)>, ts: Ts) -> (Ts, i32) {
    let (Some((last_until, mut exponent)), Some(max)) = (cached, max) else {
        return (ts + realert, 0);
    };
    let r = realert as f64 / 1e6;
    let mut diff = (ts - last_until) as f64 / 1e6;
    if diff < r * 2f64.powi(exponent) {
        exponent += 1;
    } else {
        while diff > r * 2f64.powi(exponent) && exponent > 0 {
            diff -= r * 2f64.powi(exponent);
            exponent -= 1;
        }
    }
    let wait = (r * 2f64.powi(exponent) * 1e6) as Dur;
    if wait >= max { (ts + max, exponent - 1) } else { (ts + wait, exponent) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::Leaf;

    fn leaf(name: &str, filter: Value) -> Leaf {
        Leaf { name: name.into(), filter: vec![filter], index: None, query_key: None, num_events: 1 }
    }

    #[test]
    fn doc_values_need_one_aggregatable_type() {
        let caps = json!({"fields": {
            "@timestamp": {"date": {"type": "date", "aggregatable": true}},
            "host.name": {"keyword": {"type": "keyword", "aggregatable": true}},
            "msg": {"text": {"type": "text", "aggregatable": false}},
            "mixed": {"keyword": {"type": "keyword", "aggregatable": true}, "long": {"type": "long", "aggregatable": true}},
        }});
        let list = |f: &[&str]| doc_values_of(&f.iter().map(|s| s.to_string()).collect::<Vec<_>>(), &caps);
        assert_eq!(list(&["@timestamp", "host.name"]).unwrap(), vec![json!({"field": "@timestamp", "format": "strict_date_optional_time"}), json!({"field": "host.name"})]);
        assert!(list(&["msg"]).unwrap_err().contains("text without doc values"));
        assert!(list(&["mixed"]).unwrap_err().contains("several types"));
        assert!(list(&["host"]).unwrap_err().contains("not mapped to a single value type"));
    }

    #[test]
    fn ranges_are_cut_on_a_millisecond() {
        assert_eq!(split_point(0, 4_000), Some(2_000));
        assert_eq!(split_point(1_500, 4_700), Some(3_000));
        assert_eq!(split_point(0, 1_999), None);
        assert_eq!(split_point(1_000, 2_000), None);
        assert_eq!(split_point(1_000, 3_000), Some(2_000));
    }

    #[test]
    fn timed_out_search_is_an_error_unless_degraded_is_allowed() {
        let partial = json!({"timed_out": true, "hits": {"hits": []}});
        assert!(check_timeout(&partial, false, "r").is_err());
        assert!(check_shards(&partial, false, "r").is_err());
        assert!(check_timeout(&partial, true, "r").is_ok());
        assert!(check_timeout(&json!({"timed_out": false}), false, "r").is_ok());
    }

    #[test]
    fn leaves_become_named_alternatives() {
        let leaves = [leaf("a", json!({"term": {"x": 1}})), leaf("b", json!({"query": {"term": {"y": 2}}})), leaf("c", json!({"term": {"z": 3}}))];
        assert_eq!(
            leaves_filter(&leaves, &[0, 2]),
            json!({"bool": {"minimum_should_match": 1, "should": [
                {"bool": {"filter": [{"term": {"x": 1}}], "_name": "ea3_leaf_0"}},
                {"bool": {"filter": [{"term": {"z": 3}}], "_name": "ea3_leaf_2"}},
            ]}})
        );
        // Old-style `query:` entries are unwrapped like the rule's own filter.
        assert_eq!(leaves_filter(&leaves, &[1])["bool"]["should"][0]["bool"]["filter"], json!([{"term": {"y": 2}}]));
    }

    #[test]
    fn hit_says_which_leaves_it_matched() {
        let hit = json!({"matched_queries": ["other", "ea3_leaf_2", "ea3_leaf_0", "ea3_leaf_x"]});
        assert_eq!(matched_leaves(&hit), vec![0, 2]);
        assert_eq!(matched_leaves(&json!({"matched_queries": {"ea3_leaf_1": 0.0}})), vec![1]);
        assert!(matched_leaves(&json!({})).is_empty());
    }

    /// Expected values printed by upstream's `ElastAlerter.next_alert_time` for the same call sequence.
    #[test]
    fn limit_execution_pause_rule() {
        let cron: croner::Cron = "* 10-18 * * 1-5".parse().unwrap();
        let at = |s: &str| chrono::DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&chrono::Utc);
        let next = |now: &str| cron.find_next_occurrence(&at(now), false).unwrap().timestamp_micros();
        let run_every = 5 * MINUTE;
        // Wednesday noon: the next minute is inside the window, keep running.
        let n = at("2026-10-21T12:00:30Z");
        assert_eq!(pause_until(next("2026-10-21T12:00:30Z"), n.timestamp_micros(), run_every), None);
        // Wednesday 18:58: 18:59 is still inside the window, run once more.
        let n = at("2026-10-21T18:58:00Z");
        assert_eq!(pause_until(next("2026-10-21T18:58:00Z"), n.timestamp_micros(), run_every), None);
        // 19:03: the window is over, sleep until Thursday 10:00.
        let n = at("2026-10-21T19:03:00Z");
        assert_eq!(pause_until(next("2026-10-21T19:03:00Z"), n.timestamp_micros(), run_every), Some(at("2026-10-22T10:00:00Z").timestamp_micros()));
        // Friday evening: sleep until Monday morning.
        let n = at("2026-10-23T20:00:00Z");
        assert_eq!(pause_until(next("2026-10-23T20:00:00Z"), n.timestamp_micros(), run_every), Some(at("2026-10-26T10:00:00Z").timestamp_micros()));
    }

    #[test]
    fn exponential_realert_matches_upstream() {
        let (realert, max) = (60 * SECOND, Some(600 * SECOND));
        let mut cache = None;
        let expected = [(0, 60, 0), (10, 130, 1), (140, 380, 2), (400, 880, 3), (900, 1500, 3), (2000, 2240, 2), (2001, 2481, 3), (5000, 5060, 0)];
        for (t, until, exp) in expected {
            let got = next_alert(realert, max, cache, t * SECOND);
            assert_eq!(got, (until * SECOND, exp), "at t={t}");
            cache = Some(got);
        }
    }
}

/// Shard failures stop the rule, unless `allow_queries_on_degraded_indices`: then only query parse errors do.
/// A search stopped by `search_timeout` returns what it had: an error, unless degraded results are allowed.
fn check_timeout(resp: &Value, allow_degraded: bool, rule: &str) -> Result<()> {
    if resp["timed_out"] != json!(true) {
        return Ok(());
    }
    if !allow_degraded {
        bail!("search timed out (search_timeout), the result is partial");
    }
    log::warn!("Rule {rule}: search timed out, continuing with partial results");
    Ok(())
}

fn check_shards(resp: &Value, allow_degraded: bool, rule: &str) -> Result<()> {
    check_timeout(resp, allow_degraded, rule)?;
    let Some(failures) = resp["_shards"]["failures"].as_array().filter(|f| !f.is_empty()) else { return Ok(()) };
    let parse_errors: Vec<&str> = failures.iter().filter_map(|f| f["reason"]["reason"].as_str()).filter(|r| r.contains("Failed to parse")).collect();
    if !parse_errors.is_empty() {
        bail!("{parse_errors:?}");
    }
    if allow_degraded {
        let mut indices: Vec<&str> = failures.iter().filter_map(|f| f["index"].as_str()).collect();
        indices.sort();
        indices.dedup();
        let listed: String = indices.join(", ").chars().take(1024).collect();
        log::warn!("Rule {rule}: {} shard(s) failed, continuing with partial results. Affected indices: {listed}", failures.len());
        return Ok(());
    }
    bail!("shard failures: {}", Value::Array(failures.clone()))
}
