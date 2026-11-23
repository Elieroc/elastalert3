.. _api:

REST API
========

.. admonition:: ElastAlert 3
   :class: ea3

   The REST API is new in ElastAlert 3. ElastAlert 2 has no equivalent.

The API manages the rules of an ElastAlert 3 daemon and reads what the daemon writes: alerts, runs, errors and
silences. It is a separate program (``api/`` in the repository) that runs in its own container. The daemon itself is
unchanged, and the API works on the same things the daemon reads:

- **Rules**: it edits the rules folder the daemon hot-reloads. Every write is first loaded by the daemon's own loader
  (``elastalert test-rule --schema-only``), then renamed into place atomically, so the daemon never sees a half-written
  or invalid file.
- **Alerts, runs, errors, silences**: it reads the writeback indices. A silence it creates is the same document as
  ``elastalert --silence``.
- **Stats and status**: it reads the daemon's Prometheus endpoint (``--prometheus_port``) and the ``_status`` index.
- **Test runs, Sigma conversion, ATT&CK layer**: it calls the ``elastalert`` binary shipped in its image, so the API
  and the daemon never disagree.

The Swagger UI is served at ``/swagger-ui/`` and the OpenAPI specification at ``/api-docs/openapi.json``.

Running the API
---------------

Build the daemon image first, then start the daemon and the API side by side with ``api/compose.yaml``. Both
containers share ``config.yaml`` and ``rules/``; only the API mounts ``rules/`` read-write.

.. code-block:: sh

   docker build -t elastalert3 .                             # daemon image, from the repository root
   cd api && export API_READ_TOKEN=... API_WRITE_TOKEN=...   # at least 16 characters, different
   docker compose up --build

Without Docker: ``cargo run`` in ``api/`` with ``ELASTALERT_CONFIG``, ``ELASTALERT_BIN``, ``RULES_DIR`` and ``ES_URL``.

``rules/`` must be writable by the container user (uid 10001, or set ``user:`` in the compose file).

=============================================== ===================================== ==================================================================
Variable                                        Default                               Meaning
=============================================== ===================================== ==================================================================
``API_READ_TOKEN``, ``API_WRITE_TOKEN``         required                              Bearer tokens, at least 16 characters, different (see `Tokens`_)
``API_LISTEN``                                  ``0.0.0.0:8080``                      Listen address
``ELASTALERT_CONFIG``                           ``/opt/elastalert/config.yaml``       The daemon's ``config.yaml``; ``writeback_index`` is read from it
``ELASTALERT_WORKDIR``                          folder of ``ELASTALERT_CONFIG``       Working directory of the ``elastalert`` commands
``RULES_DIR``                                   ``<workdir>/rules``                   Must be the folder the daemon watches
``ELASTALERT_BIN``                              ``elastalert``                        Daemon binary used for validation, tests and conversions
``WRITEBACK_INDEX``                             ``writeback_index`` of the config     Falls back to ``elastalert_status``
``ES_URL``                                      ``http://localhost:9200``             Elasticsearch or OpenSearch
``ES_API_KEY`` | ``ES_BEARER`` |                none                                  Authentication, first one set wins
``ES_USERNAME`` + ``ES_PASSWORD``
``ES_INSECURE``                                 ``false``                             ``true`` skips TLS certificate verification
``ELASTALERT_METRICS_URL``                      unset                                 e.g. ``http://elastalert:9100/metrics``. Needed by ``/rules/stats``
``API_TEST_TIMEOUT_SECS``                       ``120``                               Limit of a synchronous ``POST /rules/test`` and of other commands
``API_JOB_TIMEOUT_SECS``                        ``900``                               Limit of a background test (``POST /rules/test/jobs``)
``SIGMA_DIR``                                   first ``sigma_folders`` of the config Folder of the ``/sigma/rules`` endpoints
=============================================== ===================================== ==================================================================

Tokens
------

Every request carries ``Authorization: Bearer <token>``, except ``GET /health``, ``/swagger-ui/`` and
``/api-docs/``.

- The **read** token gives every ``GET``, and the endpoints that change nothing: ``POST /rules/validate``,
  ``POST /rules/test``, ``POST /rules/test/jobs``, ``DELETE /jobs/{id}``, ``POST /sigma/convert`` and
  ``POST /indices/{pattern}/search``.
- The **write** token gives everything, including the endpoints that change rules or silences. With the read token
  they answer ``403``.

A missing or unknown token answers ``401``. Tokens are compared in constant time.

.. warning::

   A rule can run a command (``command`` alerter), so the write token gives shell access to the daemon's
   container. Keep it secret, serve the API behind TLS and do not expose it publicly.

Audit
-----

Every request that is not a ``GET``, ``HEAD`` or ``OPTIONS``, and every ``401`` or ``403``, prints one JSON line on
stdout (``docker logs``). Request bodies and tokens are never logged.

.. code-block:: json

   {"audit": true, "ts": "2026-11-23T16:20:01.123456+00:00", "ip": "10.0.0.5", "role": "write",
    "method": "PUT", "path": "/rules/linux%2Fssh_bruteforce.yaml", "status": 201}

Conventions
-----------

- **Rule paths** are relative to the rules folder and URL-encoded in the URL: ``linux/ssh.yaml`` is
  ``/rules/linux%2Fssh.yaml``. A path must end in ``.yaml`` or ``.yml`` and must not contain ``..``, an absolute
  path or a hidden component (``400`` otherwise).
- **Errors** are ``{"error": "<message>"}`` with the HTTP status. An Elasticsearch failure, or a disk error, is a
  ``502`` with its cause.
- **Pages** of writeback documents are ``{"total": <n>, "items": [...]}``. The items are the documents as stored in
  Elasticsearch, with ``_id`` added.
- **Times** are ISO 8601, e.g. ``2026-10-01T08:00:00Z``.

In the examples, ``$API`` is the API URL and ``$TOKEN`` a token:

.. code-block:: sh

   export API=http://localhost:8080 TOKEN=...
   alias api='curl -sS -H "Authorization: Bearer $TOKEN"'

Health and status
-----------------

``GET /health``
~~~~~~~~~~~~~~~

No token. ``200`` when Elasticsearch, the writeback index and the rules folder are reachable, ``503`` otherwise.
For load balancer and container health checks.

.. code-block:: json

   {"status": "ok", "api": "0.1.0", "elastalert": "elastalert 3.5.0", "elasticsearch": true,
    "writeback_index": true, "rules_dir": true}

``status`` is ``degraded`` with the ``503``.

``GET /status``
~~~~~~~~~~~~~~~

Read token. The state of the daemon. Works without the metrics endpoint, with only what the writeback index shows
(``metrics_reachable`` is then ``false`` and the per-rule figures are empty).

========================== ===================================================================================
Field                      Meaning
========================== ===================================================================================
``metrics_reachable``      The daemon's Prometheus endpoint answered
``rules_loaded``           Rules the daemon reports metrics for
``errors_total``           Errors the daemon counted since it started
``max_lag_seconds``        Largest gap between now and the end of a rule's last query range
``rules_never_succeeded``  Rules that have not completed a run yet
``cpu_seconds_total``      CPU time of all rule runs since the daemon started
``memory_bytes_total``     Memory held by all rules now
``elasticsearch_requests`` Requests of the daemon by kind (``search``, ``count``, ``bulk``...): ``count``,
                           ``errors``, ``avg_seconds``
``last_run``               Time of the newest document of the ``_status`` index
``pending_alerts``         Alerts not delivered yet (``alert_sent: false``)
``errors_last_hour``       Documents of the ``_error`` index in the last hour
========================== ===================================================================================

Rules
-----

``GET /rules``
~~~~~~~~~~~~~~

Read token. Every ``*.yaml`` / ``*.yml`` file of the rules folder (hidden files and folders skipped), sorted by
path. Query parameters, all optional:

``type``
  Rule type, e.g. ``frequency``.
``enabled``
  ``true`` or ``false`` (``is_enabled``).
``q``
  Substring of the name or the path, case-insensitive.

Each item:

.. code-block:: json

   {"path": "linux/ssh_bruteforce.yaml", "name": "SSH brute force", "type": "frequency",
    "index": "logs-linux-*", "is_enabled": true, "realert_key": "SSH brute force",
    "mitre_attack": ["T1110.001"], "sigma": false, "error": null}

``path`` is the id used by the other endpoints. ``name`` defaults to the file name without extension. ``error`` is
set when the file is not valid YAML. ``import:`` files are listed like rules; the daemon tells them apart, the API
does not.

``GET /rules/{path}``
~~~~~~~~~~~~~~~~~~~~~

Read token. One rule file: ``path``, ``content`` (the raw YAML, comments included) and ``parsed`` (the YAML as
JSON; ``import:`` and ``$key$`` are not resolved). ``404`` if there is no such file.

``PUT /rules/{path}``
~~~~~~~~~~~~~~~~~~~~~

Write token. Creates or replaces a rule. The body is the YAML (``Content-Type: application/yaml``). The folders of
``path`` are created if needed.

The file is written next to its target under a hidden temporary name (so its ``import:`` resolve, and the daemon's
hot reload ignores it), loaded by the daemon's loader, then renamed over the target. The daemon picks it up at its
next reload.

- ``201`` ``{"path": ..., "created": true}``: created. ``200`` with ``created: false``: replaced.
- ``409``: another file already has this rule ``name``.
- ``422``: invalid YAML, not a mapping, or rejected by the daemon's loader; ``error`` holds the loader's message.

.. code-block:: sh

   api -X PUT -H 'Content-Type: application/yaml' --data-binary @ssh_bruteforce.yaml \
       "$API/rules/linux%2Fssh_bruteforce.yaml"

``DELETE /rules/{path}``
~~~~~~~~~~~~~~~~~~~~~~~~

Write token. Deletes the file. ``204``, or ``404`` if there is no such file. The daemon drops the rule at its next
reload.

``POST /rules/{path}/enable`` and ``POST /rules/{path}/disable``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Write token. Sets the top-level ``is_enabled`` line to ``true`` or ``false``, or adds it at the end of the file. A
comment on that line is dropped; the rest of the file is kept as is. The result goes through the same check as
``PUT``. Answers ``200`` ``{"path": ..., "created": false}``, ``404`` or ``422``.

``POST /rules/validate``
~~~~~~~~~~~~~~~~~~~~~~~~

Read token. Loads a YAML draft (body, ``application/yaml``) with the daemon's loader without saving it. Optional
query parameter ``path``: where the rule would live, so its ``import:`` resolve from that folder (default: the rules
folder).

.. code-block:: json

   {"valid": true, "error": null}
   {"valid": false, "error": "<message of the daemon's loader>"}

``POST /rules/test``
~~~~~~~~~~~~~~~~~~~~

Read token. Runs ``elastalert test-rule --formatted-output`` against Elasticsearch, on a rule on disk or on an unsaved
draft. Nothing is alerted or written. JSON body:

``path``
  A rule of the rules folder. With ``content``, only says where the draft's ``import:`` resolve from.
``content``
  An unsaved YAML draft. One of ``path`` and ``content`` is required (``400`` otherwise).
``start``, ``end``
  ISO 8601 range to test.
``days``
  The previous N days (default: the rule's ``timeframe``).
``max_query_size``
  Overrides the rule's ``max_query_size``.

The answer is the ``test-rule`` output: the query, the results and the alerts that would be sent. If the daemon logged
something (e.g. a query refused by Elasticsearch, on which ``test-rule`` still exits 0), it is in ``_log``. ``422``:
invalid rule. ``504``: longer than ``API_TEST_TIMEOUT_SECS``; use a background job for long ranges.

.. code-block:: sh

   api -H 'Content-Type: application/json' \
       -d '{"path": "linux/ssh_bruteforce.yaml", "start": "2026-10-01T08:00:00Z", "end": "2026-10-01T10:00:00Z"}' \
       "$API/rules/test"

Stats
-----

Both endpoints read the daemon's Prometheus endpoint and answer ``503`` when ``ELASTALERT_METRICS_URL`` is not set or
does not answer. Start the daemon with ``--prometheus_port``.

``GET /rules/stats``
~~~~~~~~~~~~~~~~~~~~

Read token. CPU, memory and run time per rule, the most expensive first. Query parameters:

``sort``
  ``cpu`` (default), ``memory``, ``time`` (total run time), ``avg_time``, ``lag``, ``hits``, ``matches``,
  ``alerts``.
``limit``
  Number of rules (default 50, max 1000).

Each item:

======================== ==================================================================================
Field                    Meaning
======================== ==================================================================================
``rule_name``            Rule name
``path``                 Rule file of that name, if any
``cpu_seconds``          CPU time of the rule's runs since the daemon started
``memory_bytes``         Memory the rule holds now, state kept between runs included
``time_taken_seconds``   Total time spent running the rule
``runs``                 Number of runs
``avg_run_seconds``      ``time_taken_seconds / runs``
``hits``, ``matches``    Documents read, matches found
``alerts_sent``,         Alerts by outcome
``alerts_not_sent``,
``alerts_silenced``
``lag_seconds``          Gap between now and the end of the last query range
``last_success``         Unix time of the last run without error
======================== ==================================================================================

.. code-block:: sh

   api "$API/rules/stats?sort=memory&limit=10"

``GET /rules/{path}/stats``
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Read token. The same fields for one rule, plus ``recent_runs``: its last 10 documents of the ``_status`` index
(query range, hits, matches, ``time_taken``). ``404`` if there is no such rule, or if the daemon has no metrics for
it yet (disabled, invalid or not loaded).

Background test jobs
--------------------

For tests longer than ``API_TEST_TIMEOUT_SECS``. Jobs live in the API's memory: a restart of the API forgets them.
At most 4 run at once. A finished job is kept 1 hour, and at most 100 jobs are kept.

``POST /rules/test/jobs``
~~~~~~~~~~~~~~~~~~~~~~~~~

Read token. Same body as ``POST /rules/test``. Starts the test in the background, limited to
``API_JOB_TIMEOUT_SECS``, and answers ``202`` at once with the job. ``429`` when 4 tests are already running.

.. code-block:: json

   {"id": "3f2c...", "status": "running", "path": "linux/ssh_bruteforce.yaml",
    "started": "2026-11-23T16:20:01Z", "finished": null, "error": null, "result": null}

``status`` is ``running``, ``done``, ``failed`` or ``cancelled``.

``GET /jobs``
~~~~~~~~~~~~~

Read token. Every job kept, newest first, without ``result``.

``GET /jobs/{id}``
~~~~~~~~~~~~~~~~~~

Read token. One job. Once ``done``, ``result`` holds the ``test-rule`` output; once ``failed``, ``error`` holds the
reason. ``404`` if unknown.

``DELETE /jobs/{id}``
~~~~~~~~~~~~~~~~~~~~~

Read token. Cancels a running job (its ``elastalert`` process is killed, ``status`` becomes ``cancelled``), or
forgets a finished one. ``404`` if unknown.

Alerts, runs and errors
-----------------------

These endpoints read the writeback indices and answer a page ``{"total", "items"}``, newest first. They take the same
optional query parameters:

``rule``
  Exact rule name.
``since``, ``until``
  ISO 8601 times, ``since`` included, ``until`` excluded.
``sent``
  Alerts only: ``true`` delivered, ``false`` still pending.
``size``, ``offset``
  Page size (default 50, max 1000) and offset.

A missing index gives an empty page, not an error.

``GET /alerts``
~~~~~~~~~~~~~~~

Read token. Alert documents of the writeback index, sorted by ``alert_time``.

.. code-block:: sh

   api "$API/alerts?rule=SSH%20brute%20force&since=2026-11-23T00:00:00Z&size=20"

``GET /alerts/pending``
~~~~~~~~~~~~~~~~~~~~~~~

Read token. Alerts not delivered yet (``alert_sent: false``): waiting for their aggregation window or for a retry.
Same parameters; ``sent`` is forced to ``false``.

``GET /alerts/{id}``
~~~~~~~~~~~~~~~~~~~~

Read token. One document of the writeback index by ``_id``. ``404`` if unknown.

``GET /runs``
~~~~~~~~~~~~~

Read token. One document per rule run, from the ``_status`` index (query range, hits, matches, time taken), sorted by
``@timestamp``.

``GET /errors``
~~~~~~~~~~~~~~~

Read token. Errors the daemon recorded in the ``_error`` index, tracebacks included, sorted by ``@timestamp``.

Silences
--------

``GET /silences``
~~~~~~~~~~~~~~~~~

Read token. Silences still running (``until`` in the future), lift markers excluded, latest ``until`` first, at most
1,000.

``POST /silences``
~~~~~~~~~~~~~~~~~~

Write token. Silences a rule. Writes the same document as ``elastalert --silence`` to the ``_silence`` index; the
daemon reads it at its next maintenance tick (about ``run_every``). JSON body:

``rule``
  Rule name (required). ``404`` if no rule file has this name.
``duration``
  ``--silence`` syntax ``<unit>=<number>``, unit in ``seconds``, ``minutes``, ``hours``, ``days``, ``weeks``. E.g.
  ``hours=2``. At most 366 days. ``400`` otherwise.
``query_key_value``
  Silence only the matches of this ``query_key`` value. The silence key is then ``<realert_key>.<value>``; without it,
  ``<name>._silence``.

Answers ``201`` with the document written.

.. code-block:: sh

   api -H 'Content-Type: application/json' \
       -d '{"rule": "SSH brute force", "duration": "hours=2", "query_key_value": "srv-web-01"}' \
       "$API/silences"

``DELETE /silences/{id}``
~~~~~~~~~~~~~~~~~~~~~~~~~

Write token. Lifts a silence before its end. ``id`` is an ``_id`` from ``GET /silences``. Every running silence
document of the same key (``rule_name``) is deleted, then a ``lifted: true`` marker is written, so the daemon, which
keeps silences in memory, forgets the key at its next maintenance tick (see :doc:`elastalert_status`). A silence set
again after the marker is kept.

.. code-block:: json

   {"rule_name": "SSH brute force.srv-web-01", "deleted": 1}

``404`` if the document is unknown or is itself a lift marker.

Sigma
-----

``POST /sigma/convert``
~~~~~~~~~~~~~~~~~~~~~~~

Read token. Converts a Sigma rule (body, ``application/yaml``) with ``elastalert sigma-convert``. Query parameters:

``pipeline``
  A built-in :ref:`pipeline <sigma_pipelines>`, e.g. ``ecs_windows``.
``dsl``
  ``true``: answer only the search body ``{"query": ...}``.

Without ``dsl``, the answer is ``{"yaml": "<ElastAlert options>"}``. ``422``: the Sigma rule is rejected, with the
reason.

.. code-block:: sh

   api -H 'Content-Type: application/yaml' --data-binary @proc_creation_win_powershell_enc.yml \
       "$API/sigma/convert?pipeline=ecs_windows&dsl=true"

``GET /mitre/layer``
~~~~~~~~~~~~~~~~~~~~

Read token. ATT&CK Navigator layer of the techniques the rules cover (:ref:`mitre_attack <mitre_attack>`), from
``elastalert mitre-layer``. Query parameters: ``name`` (layer name) and ``include_disabled`` (``true``: count the
rules with ``is_enabled: false`` too). Import the JSON in the ATT&CK Navigator.

Sigma files of ``sigma_folders``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

These endpoints work on the plain Sigma files of the first ``sigma_folders`` entry of ``config.yaml`` (or
``SIGMA_DIR``), which the daemon compiles into rules at load. They answer ``404`` when no Sigma folder is configured.
Paths follow the same rules as rule paths.

``GET /sigma/rules``
  Read token. Every Sigma file: ``path``, ``kind`` (``rule``, ``correlation`` or ``filter``, from the first YAML
  document), ``title``, ``id``, ``status``, ``level``, ``tags``, ``logsource``, ``documents`` (a file may hold several
  YAML documents) and ``error`` (invalid YAML).

``GET /sigma/rules/{path}``
  Read token. ``{"path", "content"}``. ``404`` if unknown.

``PUT /sigma/rules/{path}``
  Write token. Creates (``201``) or replaces (``200``) a Sigma file, body ``application/yaml``. It is first checked by
  ``elastalert sigma-convert`` with the folder as context (for correlations and filters that refer to other files),
  then renamed into place. ``422``: invalid YAML or rejected by ``sigma-convert``.

``DELETE /sigma/rules/{path}``
  Write token. ``204``, or ``404``.

Configuration and indices
-------------------------

Helpers to write rules. All read-only.

``GET /config``
~~~~~~~~~~~~~~~

Read token. The daemon's ``config.yaml`` as JSON, with ``path``. The values of keys that look like secrets (names
containing ``password``, ``passwd``, ``secret``, ``token``, ``api_key``, ``apikey``, ``private_key``, ``bearer``,
``webhook``, ``credential`` or ``authorization``) are replaced with ``***``. A change to ``config.yaml`` needs a
restart of the daemon, which the API does not do.

``GET /indices``
~~~~~~~~~~~~~~~~

Read token. Indices matching ``pattern`` (query parameter, default ``*``), hidden ones excluded: ``index``,
``health``, ``status``, ``docs.count``, ``store.size``. A pattern is made of letters, digits and ``. _ - * , :`` and
does not start with ``_`` (``400`` otherwise).

``GET /indices/{pattern}/fields``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Read token. Fields of the matching indices (``_field_caps``), sorted by name: ``name``, ``types`` (more than one
means a mapping conflict between the indices), ``searchable``, ``aggregatable``. Query parameters: ``q`` (substring
of the field name) and ``limit`` (default 500, max 5,000). ``404`` if no index matches.

.. code-block:: sh

   api "$API/indices/logs-windows-*/fields?q=process"

``POST /indices/{pattern}/search``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Read token. A read-only search, to try a filter before putting it in a rule. The body is a Query DSL object with
only ``query``, ``size``, ``from``, ``sort``, ``_source``, ``fields``, ``aggs`` / ``aggregations``; no script anywhere
(``400`` otherwise). ``size`` defaults to 10 and is capped at 100, and the search times out after 10 s. The answer is
the Elasticsearch response, with ``hits.total`` as a number. A query refused by Elasticsearch is a ``400`` with its
reason.

.. code-block:: sh

   api -H 'Content-Type: application/json' \
       -d '{"query": {"query_string": {"query": "event.code:4625"}}, "size": 5}' \
       "$API/indices/logs-windows-*/search"

Limits
------

- One rules folder (``RULES_DIR``) and one Sigma folder: a ``rules_folder`` list or several ``sigma_folders`` are not
  handled.
- Background jobs are kept in memory and lost when the API restarts.
- Symbolic links inside the rules folder are followed: do not mount untrusted links in it.
