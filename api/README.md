# elastalert3 API

REST API with Swagger for an elastalert3 daemon. Own crate, own container; the daemon code is untouched.

How it works
- **Rules**: edits the rules folder the daemon hot-reloads. Every write is checked first by the daemon's own loader (`elastalert test-rule --schema-only`), then renamed into place atomically.
- **Alerts, runs, errors, silences**: reads the writeback indices; a silence is the same document as `elastalert --silence`.
- **Test run, Sigma conversion, ATT&CK layer**: calls the `elastalert` binary shipped in the image, so API and daemon never disagree.

Swagger UI: `http://localhost:8080/swagger-ui/` (spec: `/api-docs/openapi.json`).

## Endpoints

| Group | Endpoints | Token |
|---|---|---|
| health | `GET /health` (no token), `GET /status` (rules loaded, lag, errors, ES latency, last run, pending alerts) | read |
| rules | `GET /rules`, `GET/PUT/DELETE /rules/{path}`, `POST /rules/{path}/enable\|disable`, `POST /rules/validate`, `POST /rules/test` | read; write for PUT, DELETE, enable, disable |
| stats | `GET /rules/stats?sort=cpu\|memory\|time\|avg_time\|lag`, `GET /rules/{path}/stats` (+ last runs) | read |
| jobs | `POST /rules/test/jobs`, `GET /jobs`, `GET /jobs/{id}`, `DELETE /jobs/{id}` (cancel) | read |
| alerts | `GET /alerts`, `/alerts/pending`, `/alerts/{id}`, `/runs`, `/errors` | read |
| silences | `GET /silences`, `POST /silences`, `DELETE /silences/{id}` | read; write for POST, DELETE |
| sigma | `POST /sigma/convert`, `GET /mitre/layer`, `GET/PUT/DELETE /sigma/rules[/{path}]` (`sigma_folders`) | read; write for PUT, DELETE |
| rule-types | `GET /rule-types`, `GET /rule-types/{type}` (required and optional options of a type, with descriptions) | read |
| config | `GET /config` (read-only, secrets masked) | read |
| indices | `GET /indices`, `GET /indices/{pattern}/fields`, `POST /indices/{pattern}/search` (read-only, no scripts, max 100 hits) | read |

Rule paths are relative to the rules folder and URL-encoded (`linux%2Fa.yaml`).

How it works
- **Rules**: edits the rules folder the daemon hot-reloads. Every write is checked first by the daemon's own loader (`elastalert test-rule --schema-only`), then renamed into place atomically.
- **Alerts, runs, errors, silences**: reads the writeback indices; a silence is the same document as `elastalert --silence`. Lifting one writes a `lifted: true` marker the daemon reads at its next maintenance tick (needs a daemon built from a version that reads `lifted` markers).
- **Stats and status**: read the daemon's Prometheus endpoint (`ELASTALERT_METRICS_URL`, start the daemon with `--prometheus_port`) and the `_status` index.
- **Test run, Sigma conversion, ATT&CK layer**: calls the `elastalert` binary shipped in the image, so API and daemon never disagree.

## Run

```sh
docker build -t elastalert3 .                             # daemon image, from the repository root
cd api && export API_READ_TOKEN=... API_WRITE_TOKEN=...   # >= 16 chars, different
docker compose up --build
```

Without Docker: `cargo run` with `ELASTALERT_CONFIG`, `ELASTALERT_BIN`, `RULES_DIR`, `ES_URL`.

| Variable | Default | |
|---|---|---|
| `API_READ_TOKEN`, `API_WRITE_TOKEN` | required | Bearer tokens. Read: GET, validate, test, convert. Write: also PUT/DELETE rules, enable/disable, create silences |
| `API_LISTEN` | `0.0.0.0:8080` | |
| `ELASTALERT_CONFIG` | `/opt/elastalert/config.yaml` | `writeback_index` is read from it |
| `RULES_DIR` | `<config dir>/rules` | must be the folder the daemon watches |
| `ELASTALERT_BIN` | `elastalert` | |
| `WRITEBACK_INDEX` | from config | |
| `ES_URL`, `ES_USERNAME`/`ES_PASSWORD`, `ES_API_KEY`, `ES_BEARER`, `ES_INSECURE` | `http://localhost:9200` | |
| `API_TEST_TIMEOUT_SECS` | `120` | synchronous `POST /rules/test` |
| `API_JOB_TIMEOUT_SECS` | `900` | `POST /rules/test/jobs` (4 at once, kept 1 h) |
| `ELASTALERT_METRICS_URL` | unset | e.g. `http://elastalert:9100/metrics`; `/rules/stats` answers 503 without it |
| `SIGMA_DIR` | first `sigma_folders` of the config | |

`rules/` must be writable by the container user (uid 10001, or set `user:` in the compose file).

## Audit

Every request that is not a plain GET, and every 401/403, prints one JSON line on stdout: `{"audit":true,"ts","ip","role","method","path","status"}`. Bodies and tokens are never logged.

## Security notes

A rule can run a command (`command` alerter): the write token is shell access to the daemon's container. Keep it secret, serve the API behind TLS, do not expose it publicly.

## Not in this version

- Several rule folders (`rules_folder` list) or several `sigma_folders`: only the one folder (`RULES_DIR`, first `sigma_folders`).
- Jobs are kept in memory: a restart of the API forgets them.
