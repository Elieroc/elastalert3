<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-horizontal-dark.png">
    <img src="docs/assets/logo-horizontal-light.png" alt="elastalert3: alerting for Elasticsearch" width="100%">
  </picture>
</p>

<p align="center">
  <a href="https://elastalert3.neopipe.fr"><img src="https://img.shields.io/badge/docs-elastalert3.neopipe.fr-2980b9" alt="Documentation"></a>
  <img src="https://img.shields.io/badge/version-3.4.0-e5484d" alt="Version 3.4.0">
  <img src="https://img.shields.io/badge/status-beta-orange" alt="Status: beta">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="License: Apache-2.0"></a>
  <img src="https://img.shields.io/badge/rust-1.88%2B%20%C2%B7%20edition%202024-dea584?logo=rust" alt="Rust 1.88+, edition 2024">
  <img src="https://img.shields.io/badge/Elasticsearch-7.x%20%7C%208.x-005571?logo=elasticsearch" alt="Elasticsearch 7.x | 8.x">
  <img src="https://img.shields.io/badge/OpenSearch-2.x-005eb8?logo=opensearch" alt="OpenSearch 2.x">
  <img src="https://img.shields.io/badge/ElastAlert%202-drop--in%20compatible-2ec4b6" alt="ElastAlert 2 drop-in compatible">
</p>

# elastalert3

An alerting daemon for Elasticsearch and OpenSearch, written in Rust. It started as a rewrite of
[ElastAlert 2](https://github.com/jertel/elastalert2), runs **existing ElastAlert 2 `config.yaml` and rule files unchanged**,
writes the same writeback documents, and adds features of its own. It was called elastalert-rs up to 1.2.0.
It is an independent project, not affiliated with Yelp or the ElastAlert 2 maintainers.

**Documentation: https://elastalert3.neopipe.fr**: the ElastAlert 2 documentation, with every difference marked.
Read [Differences from ElastAlert 2](https://elastalert3.neopipe.fr/differences.html) before replacing a production ElastAlert 2.

> **Status: beta.** Alerts are checked against Python ElastAlert 2.31.0 by replaying the same data through both
> (931 + 203 alerts, identical). Nobody runs it in production yet, and TLS, client certificates and degraded clusters
> have never been exercised. Run it next to your current setup with `--debug` first.

## Quick start

```sh
cargo build --release                                        # target/release/elastalert (Rust 1.88+)
elastalert --config config.yaml create-index                 # once
elastalert --config config.yaml validate                     # every rule loads? no Elasticsearch needed
elastalert --config config.yaml test-rule rules/x.yaml --days 1
elastalert --config config.yaml                              # run
```

Docker:

```sh
docker build -t elastalert3 .
docker run -d --name elastalert \
  -v $PWD/config.yaml:/opt/elastalert/config.yaml:ro \
  -v $PWD/rules:/opt/elastalert/rules:ro \
  elastalert3
```

See [Getting Started](https://elastalert3.neopipe.fr/running_elastalert.html).

## What is new

- [`correlation`](https://elastalert3.neopipe.fr/ruletypes.html#correlation) rule type: events of several searches on the same machine, IP or user within a window, including a missing step.
- [`active_hours`](https://elastalert3.neopipe.fr/ruletypes.html#active-hours): ignore matches outside time windows.
- [`ingest_timestamp_field`](https://elastalert3.neopipe.fr/ruletypes.html#ingest-timestamp-field): late documents found exactly once.
- Per-alerter retry, pending alerts kept across restarts, hot reload keeping rule state, `validate` subcommand.
- [Match enhancements in Rust](https://elastalert3.neopipe.fr/enhancements.html) (`rust.add_field`, `rust.drop_if`, `rust.lookup`).
- About 11 times faster, with less than half the memory, on a 400,000-document frequency rule.

Every built-in rule type and all 44 alerters of ElastAlert 2 are supported. Not supported: Python plugins (custom rule
types, alerters, loaders, enhancements, Jinja filters), per-rule Elasticsearch connections, AWS SigV4 signing of
Elasticsearch requests, `notify_alert`, statsd. A rule needing an unsupported option is rejected at load, never run
differently.

## Testing

```sh
cargo test
```

`tests/parity/` replays deterministic data through ElastAlert 2 and elastalert3 and diffs the alerts (needs a throwaway
Elasticsearch), `tests/alerters/` is a local SMTP + HTTP sink, `bench/` holds the performance dataset.

## License

Apache License 2.0, see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
