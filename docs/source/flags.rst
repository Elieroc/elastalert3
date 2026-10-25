Command Line Flags
******************

ElastAlert 3 accepts several optional command line parameters:

``--config`` will specify the configuration file to use. The default is
``config.yaml``. 

``--debug`` will run ElastAlert 3 in debug mode. This will increase the logging
verboseness, change all alerts to ``DebugAlerter``, which prints alerts and
suppresses their normal action, and skips writing search and alert metadata back
to Elasticsearch. Not compatible with `--verbose`.

``--end <timestamp>`` will force ElastAlert 3 to stop querying after the given
time, instead of the default, querying to the present time. ElastAlert 3 then runs
each rule once and exits; aggregated alerts still open at the end are sent. The timestamp is formatted as
``YYYY-MM-DDTHH:MM:SS`` (UTC) or with timezone ``YYYY-MM-DDTHH:MM:SS-XX:00``
(UTC-XX).

``--es_debug`` will enable logging for all queries made to Elasticsearch.

``--es_debug_trace <trace.log>`` will append every request made to Elasticsearch
to the specified file, as a ``curl`` command followed by its (truncated) response.
The real ``es_host``:``es_port`` is written, credentials never are.

``--patience <unit>=<number>`` will wait up to this long at startup for
Elasticsearch and the writeback index to be reachable, e.g. ``--patience minutes=5``.

``--pin_rules`` will stop ElastAlert 3 from loading, reloading or removing rules
based on changes to their config files.

``--prometheus_port`` exposes ElastAlert 3 `Prometheus metrics <https://elastalert3.neopipe.fr/recipes/exposing_rule_metrics.html>`_ on the specified
port. Prometheus metrics disabled by default.

``--prometheus_addr`` allows you to specify the host address that the Prometheus metrics server will bind to.
The default is ``0.0.0.0``.

``--rule <rule.yaml>`` will only run the given rule. The rule file may be a
complete file path or a filename in ``rules_folder`` or its subdirectories.

``--silence <unit>=<number>`` will silence the alerts for a given rule for a
period of time. A running daemon picks the silence up within one ``run_every``. The rule must be specified using ``--rule``. <unit> is one of
days, weeks, hours, minutes or seconds. <number> is an integer. For example,
``--rule noisy_rule.yaml --silence hours=4`` will stop noisy_rule from
generating any alerts for 4 hours.

``--silence_qk_value <value`` will silence the rule only for the given 
query key value. This parameter is intended to be used with the ``--rule`` 
parameter.

``--start <timestamp>`` will force ElastAlert 3 to begin querying from the given
time, instead of the default, querying from the present. The timestamp should be
ISO8601, e.g.  ``YYYY-MM-DDTHH:MM:SS`` (UTC) or with timezone
``YYYY-MM-DDTHH:MM:SS-08:00`` (PST). Note that if querying over a large date
range, no alerts will be sent until that rule has finished querying over the
entire time period. To force querying from the current time, use "NOW".

``--verbose`` will increase the logging verboseness, which allows you to see
information about the state of queries. Not compatible with `--debug`.

Subcommands
===========

ElastAlert 3 is a single binary. The tools that ElastAlert 2 ships as separate programs are subcommands; ``--config``
applies to them too.

``create-index [--index NAME] [--old-index NAME] [--recreate]`` creates the five writeback indices with the
mappings of ElastAlert 2 (replaces ``elastalert-create-index``).

``validate`` loads the config and every rule, builds the alerters, reports each error and exits with status 1 if
there is any. It does not contact Elasticsearch, so it fits in a CI job.

``validate --es`` also reads the mappings of the indices of each rule (``_field_caps``) and has Elasticsearch parse
each filter (``_validate/query``). It prints warnings, and does not change the exit status. It reports: an index
without any field, a ``timestamp_field`` that is not a date, a filter on a field that is not in the mapping, ``term``,
``terms`` and ``prefix`` on a ``text`` field (with the ``.keyword`` sub-field when there is one), a ``wildcard``
starting with ``*`` or ``?``, a field used for ``query_key`` / ``top_count_keys`` aggregations that cannot be
aggregated, and a filter Elasticsearch cannot parse. A field that no document has yet is only a warning: a new
document may map it later.

``test-rule <rule.yaml> [...]`` runs one rule on past data (replaces ``elastalert-test-rule``). See
:ref:`Testing your rule <testing>`.

Examples::

    elastalert --config config.yaml create-index
    elastalert --config config.yaml validate
    elastalert --config config.yaml test-rule rules/my_rule.yaml --days 1
