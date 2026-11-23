//! Writeback: every status/alert/silence/error doc goes through one task that sends `_bulk`
//! requests (every second or 500 docs). Ids are generated here, so retries can't duplicate.

use crate::es::Es;
use crate::time::{now, to_iso};
use serde_json::{Map, Value, json};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

const BATCH: usize = 500;
/// Docs kept for retry while ES is unreachable; beyond this the oldest are dropped.
const MAX_BUFFER: usize = 50_000;

#[derive(Clone, Copy)]
pub enum Kind {
    Alert,
    Status,
    Silence,
    Error,
}

#[derive(Clone)]
pub struct Writeback {
    tx: Option<mpsc::Sender<(String, Option<String>, Value)>>,
    index: String,
    /// test-rule: collect what would have been written instead of writing or logging it.
    capture: Option<std::sync::Arc<std::sync::Mutex<Vec<(String, Value)>>>>,
    /// `notify_email` + `notify_all_errors`: every logged error is also mailed.
    notifier: Option<(std::sync::Arc<crate::notify::Notifier>, bool)>,
}

pub type Captured = std::sync::Arc<std::sync::Mutex<Vec<(String, Value)>>>;

impl Writeback {
    /// `es = None` (debug mode) logs the docs instead of writing them.
    pub fn start(es: Option<Es>, index: String) -> (Writeback, Option<JoinHandle<()>>) {
        let Some(es) = es else { return (Writeback { tx: None, index, capture: None, notifier: None }, None) };
        let (tx, rx) = mpsc::channel(10_000);
        let handle = tokio::spawn(run(es, rx));
        (Writeback { tx: Some(tx), index, capture: None, notifier: None }, Some(handle))
    }

    /// Writeback that records docs in memory (`(index, doc)`), for `test-rule`.
    pub fn capturing(index: String) -> (Writeback, Captured) {
        let c: Captured = Default::default();
        (Writeback { tx: None, index, capture: Some(c.clone()), notifier: None }, c)
    }

    /// Deletes the doc with this `_id` (used for the children of a sent aggregated alert).
    pub async fn delete_id(&self, kind: Kind, id: &str) {
        if let Some(tx) = &self.tx {
            let _ = tx.send((self.index_for(kind), Some(id.to_string()), Value::Null)).await;
        }
    }

    pub fn index_for(&self, kind: Kind) -> String {
        let suffix = match kind {
            Kind::Alert => "",
            Kind::Status => "_status",
            Kind::Silence => "_silence",
            Kind::Error => "_error",
        };
        format!("{}{suffix}", self.index)
    }

    pub async fn write(&self, kind: Kind, doc: Map<String, Value>) {
        self.send(kind, None, doc).await
    }

    /// Writes (or overwrites) the doc with this `_id`: used to update pending alerts in place.
    pub async fn write_id(&self, kind: Kind, id: &str, doc: Map<String, Value>) {
        self.send(kind, Some(id.to_string()), doc).await
    }

    /// Client-side id for a new alert doc, so it can be updated later without a round-trip.
    pub fn new_id() -> String {
        uuid::Uuid::now_v7().to_string()
    }

    async fn send(&self, kind: Kind, id: Option<String>, mut doc: Map<String, Value>) {
        doc.entry("@timestamp").or_insert_with(|| json!(to_iso(now())));
        if let Some(c) = &self.capture {
            c.lock().unwrap().push((self.index_for(kind), Value::Object(doc)));
            return;
        }
        match &self.tx {
            None => log::info!("Skipping writing to ES: {}", Value::Object(doc)),
            Some(tx) => {
                let _ = tx.send((self.index_for(kind), id, Value::Object(doc))).await;
            }
        }
    }

    pub fn with_notifier(mut self, notifier: Option<std::sync::Arc<crate::notify::Notifier>>, notify_all_errors: bool) -> Self {
        self.notifier = notifier.map(|n| (n, notify_all_errors));
        self
    }

    /// Logs the error and records it in the `_error` index (and mails it with `notify_all_errors`).
    pub async fn error(&self, message: String, data: Value) {
        self.error_full(message, data, vec![], true).await
    }

    /// `notify`: false when the caller sends its own, more specific notification.
    pub async fn error_full(&self, message: String, data: Value, traceback: Vec<String>, notify: bool) {
        log::error!("{message}");
        if let (true, Some((n, true))) = (notify, &self.notifier) {
            n.send("ElastAlert notification".into(), message.clone(), vec![]);
        }
        let mut doc = Map::new();
        doc.insert("message".into(), json!(message));
        doc.insert("traceback".into(), json!(traceback));
        if !data.is_null() {
            doc.insert("data".into(), data);
        }
        self.write(Kind::Error, doc).await;
    }
}

/// Brings `buf` down to `max` docs: oldest status docs go first, then the oldest of the rest.
/// Returns how many were dropped.
fn shed(buf: &mut Vec<(bool, String)>, max: usize) -> usize {
    let mut excess = buf.len().saturating_sub(max);
    let dropped = excess;
    buf.retain(|(status, _)| !(*status && excess > 0 && { excess -= 1; true }));
    if excess > 0 {
        buf.drain(..excess);
    }
    dropped
}

async fn run(es: Es, mut rx: mpsc::Receiver<(String, Option<String>, Value)>) {
    let mut buf: Vec<(bool, String)> = Vec::new(); // (is a status doc, bulk lines)
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        let open = tokio::select! {
            msg = rx.recv() => match msg {
                Some((index, id, doc)) => {
                    // New docs use `create` so a retried bulk can't duplicate; explicit ids overwrite.
                    let status = index.ends_with("_status");
                    buf.push((status, match (id, doc.is_null()) {
                        (Some(id), true) => format!("{}\n", json!({"delete": {"_index": index, "_id": id}})),
                        (Some(id), false) => format!("{}\n{doc}\n", json!({"index": {"_index": index, "_id": id}})),
                        (None, _) => format!("{}\n{doc}\n", json!({"create": {"_index": index, "_id": uuid::Uuid::now_v7().to_string()}})),
                    }));
                    if buf.len() < BATCH { continue }
                    true
                }
                None => false,
            },
            _ = tick.tick() => true,
        };
        while !buf.is_empty() {
            let n = buf.len().min(BATCH);
            match es.bulk(buf[..n].iter().map(|(_, l)| l.as_str()).collect::<String>()).await {
                Ok(resp) => {
                    if resp["errors"] == json!(true) {
                        let first = resp["items"].as_array().and_then(|items| {
                            items.iter().find_map(|i| i.as_object()?.values().next()?["error"].as_object().filter(|_| i.as_object().and_then(|o| o.values().next()).is_some_and(|v| v["status"] != json!(409) && v["status"] != json!(404))))
                        });
                        if let Some(e) = first {
                            log::error!("Error writing to writeback index: {}", Value::Object(e.clone()));
                        }
                    }
                    buf.drain(..n);
                }
                Err(e) => {
                    log::error!("Error writing to Elasticsearch writeback (will retry): {e:#}");
                    let dropped = shed(&mut buf, MAX_BUFFER);
                    if dropped > 0 {
                        log::error!("Writeback buffer over {MAX_BUFFER} docs while Elasticsearch is unreachable: {dropped} docs dropped (status docs first)");
                    }
                    if open {
                        break;
                    }
                    return; // shutting down and ES is down: give up
                }
            }
        }
        if !open {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shed_drops_status_before_alerts() {
        let mut buf = vec![(false, "a1".to_string()), (true, "s1".into()), (false, "a2".into()), (true, "s2".into())];
        assert_eq!(shed(&mut buf, 3), 1);
        assert_eq!(buf.iter().map(|(_, l)| l.as_str()).collect::<Vec<_>>(), ["a1", "a2", "s2"]);
        assert_eq!(shed(&mut buf, 1), 2);
        assert_eq!(buf, [(false, "a2".to_string())]);
    }
}
