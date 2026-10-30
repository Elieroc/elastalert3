# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

elastalert3 (formerly elastalert-rs): an alerting daemon in Rust that started as a rewrite of the core of ElastAlert 2 (Python) and now adds features of its own (e.g. the `correlation` rule type, `active_hours`). The crate and binary are still named `elastalert`; versions continue from 3.2.0 (1.x was elastalert-rs). Hard contract: existing ElastAlert 2 `config.yaml` and rule files run **unchanged**, and the writeback documents keep upstream's shapes (new fields additive only). Alert text, silence keys, realert timing, the `gt start / lte end` query range and rule-type math must match upstream: parity first, then speed. Any unsupported option must be **rejected at load** with a message (see the `unsupported` list in `src/rule.rs`), never silently run with different behaviour.

## Commands

```sh
cargo build --release                 # target/release/elastalert (fat LTO, slow)
cargo test                            # unit tests, no Elasticsearch needed
cargo test <name_substring>           # single test, e.g. cargo test import_chain
cargo run -- --config tests/parity/config.yaml validate   # load config + all rules, no ES
```

Toolchain: Rust 1.99, edition 2024 (let-chains used).

Integration harnesses need a throwaway Elasticsearch and are not part of `cargo test`:
- `tests/parity/`: `seed.py` loads deterministic data; run Python ElastAlert 2.31.0 and this binary with `--debug --start 2026-10-01T08:00:00Z --end 2026-10-01T10:05:00Z`, then `diff.py py.log rs.log`. The alerts must be identical. Re-run this after any change to rule types, query planning or alert text.
- `tests/sigma/`: `run.py URL` loads 16 events and checks which ones each rule in `rules/` hits against `expected.json` (derived by hand); with pySigma installed it also compares with `sigma convert -t lucene`. `e2e.py URL` runs the daemon over Sigma correlations and a filter in `sigma_folders` (`e2e/`). `corpus.py DIR [--es URL]` converts a SigmaHQ checkout and must not crash. Re-run after any change to `src/sigma/`.
- `tests/beacon/`, `tests/baseline/`, `tests/rare/`, `tests/outlier/`, `tests/risk_ratio/`: hand-made scenarios for `beacon`, `baseline`, `new_term` + `max_occurrences`, `outlier` and `risk` with `risk_ratio` (no Python equivalent). Each `seed.py` header gives the throwaway ES command, the daemon command and the expected matches.
- `tests/alerters/sink.py`: local SMTP + HTTP receiver for the email/slack/post/command alerters and retry behaviour.
- `bench/`: 400k-document dataset, 500-rule folder and correlation rules (`rules-corr`, `config-corr-rs.yaml`) for the performance numbers in `docs/source/differences.rst`.

Unit tests live in `#[cfg(test)] mod tests` at the bottom of each `src/*.rs`. `tests/golden/*.txt` are summary tables printed by upstream, compared byte for byte via `include_str!` in `src/alert.rs`.

## Architecture

Single crate, single binary. Process model:

- `main.rs`: CLI (clap, flag names copied from upstream like `--pin_rules`), startup recovery of pending alerts/aggregations from the writeback index, one tokio task per rule (`rule_task`), hot-reload loop (file hashes of rules + imports; a reloaded rule keeps its state), graceful shutdown (finish running rules, flush writeback, 10 s cap).
- `engine.rs`: one rule run. Plans the time range, queries pages, feeds the rule type, then silence/realert, aggregation groups, enhancement (top counts, `_mget` of the full doc for matches only), and per-alerter delivery with backoff retry. `RuleState` is owned by its task; `Ctx` holds the only shared things: `Es` client, `Silences` (in-memory, refreshed every `run_every`), writeback channel.
- `types.rs`: `RuleType` enum dispatching to per-type structs. Entry points: `add_data` (hits), `add_count` (`use_count_query`), `add_aggregation` (aggregation rule types: `metric_aggregation`, `percentage_match`, `spike_aggregation`, `outlier`; `Kind::is_agg_query`; `outlier` queries the last `timeframe` each run and judges the whole terms population in `add_population`, stateless). `baseline` has its own entry point `add_baseline` (one terms + date_histogram search per bucket, see `baseline_due`); `beacon` and `geo_velocity` work on hits; `new_term` with `max_occurrences` keeps in its `seen` set only the history terms above the limit (no extra state). `Kind::replays_window` marks the types whose state is rebuilt after a restart. `EventWindow` stores compact `(ts, count)` entries, not full docs. Timestamps are `i64` micros UTC (`time.rs`).
- `correlation.rs`: `correlation_query` parser (`AND`/`OR`/`THEN`/`NOT` over `correlation_leaves`, top-level `NOT` split off at load) and `Progress`, the per-chain evaluation used by `types.rs`.
- `exceptions.rs`: rule `exceptions` (Sigma `match` or raw `query`, `expires`) compiled into one `must_not` of the `filter` at load.
- `rule.rs`: YAML loading, `import:` chains, `$key$` references, env expansion, defaults inherited from `config.yaml`, load-time rejection of unsupported options, and per-type field projection (only the fields the type needs are fetched from ES; `fetch_full_source` / `include` opt out).
- `es.rs`: raw REST client over reqwest (no official ES crate) for ES 7.x/8.x and OpenSearch 2.x: PIT + `search_after` when available, scroll fallback, `_bulk`, `_mget`, `--es_debug(_trace)` tracing.
- `writeback.rs`: single bulk-writer task (flush every 1 s or 500 docs), client-side UUIDv7 ids so retries are idempotent.
- `alert.rs`: alert body/subject (Python `str.format` subset, `minijinja` for jinja), summary tables. `alerters/`: one module per alerter (`mod.rs` = enum, option helpers, `View`; `http.rs` = shared webhook client; `testutil` = rule builder + in-process HTTP capture server for tests), all 44 upstream alerters (the `alert:` names) (`debug`, `email`, `slack`, `post`, `command`); any other alerter name is rejected at load.
- `sigma/`: native Sigma rules. `sigma:` in a rule file compiles the Sigma detection into a Query DSL `filter` at load (`mod.rs` = wrapper, metadata and `sigma-convert`; `sigma_folders` plain files are handled in `rule.rs` `read_rule`; `condition.rs`, `modifiers.rs`, `dsl.rs`; `corpus.rs` = multi-document files and the lookup of referenced rules and filters, `corr.rs` = correlation rules as `frequency` / `cardinality` / `correlation`; `pipeline.rs` + `pipelines/*.yml` = field mapping).
- `testrule.rs`: `test-rule` and `validate` subcommands. `setup.rs`: `create-index`, using mappings embedded from `mappings/` (copied from upstream).
- `notify.rs`: `notify_email` operator mails. `metrics.rs`: Prometheus endpoint with upstream metric names.

Error model: ordinary errors (ES down, bad query, alerter failure) are logged and retried next run. Only a panic in a rule task counts as an "uncaught exception": error doc to `_error`, optional notify mail, and with `disable_rules_on_error` the rule is parked until its file changes.

## Project records

- `docs/source/` (Sphinx, published at https://elastalert3.neopipe.fr) is the user-facing coverage contract: the ElastAlert 2 documentation with every difference in a red `.. admonition:: ElastAlert 3` / `:class: ea3` note, and `differences.rst` listing new, changed and unsupported features. Update it when behaviour or coverage changes. Build: `sphinx-build -W -b html docs/source /tmp/html` (requirements in `docs/requirements.txt`); deploy: `docs/compose.yaml`.
- `README.md` stays short: pitch, quick start, links to the docs.
