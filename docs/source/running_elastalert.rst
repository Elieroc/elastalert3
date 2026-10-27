.. _tutorial:

Getting Started
***************

ElastAlert 3 is a single binary, ``elastalert``. It can be run as :ref:`a Docker container <docker-instructions>`
or directly on your machine :ref:`from a release build <binary-instructions>`.

Requirements
============

- Elasticsearch 7.x or 8.x, or OpenSearch 2.x (tested: Elasticsearch 7.17 and 8.15, OpenSearch 2.17)
- ISO8601 or Unix timestamped data
- To build from source: Rust 1.88 or newer (developed and tested with 1.99)

.. _binary-instructions:

From source
===========

Clone the repository and build the release binary::

    $ git clone https://github.com/Elieroc/elastalert3.git
    $ cd elastalert3
    $ cargo build --release          # binary: target/release/elastalert

Copy ``target/release/elastalert`` anywhere in your ``PATH``. It has no runtime dependency besides the system CA
certificates.

Write a ``config.yaml``. A minimal one is identical to ElastAlert 2's:

.. code-block:: yaml

    rules_folder: rules
    run_every: {minutes: 1}
    buffer_time: {minutes: 15}
    es_host: elasticsearch.example.com
    es_port: 9200
    writeback_index: elastalert_status

See :doc:`configuration` for details on all the configuration options available.

Creating the ElastAlert 3 Indices
---------------------------------

ElastAlert 3 saves information and metadata about its queries and its alerts back
to Elasticsearch. This is useful for auditing, debugging, and it allows
ElastAlert 3 to restart and resume exactly where it left off.

Create the five writeback indices once, with the mappings of ElastAlert 2::

    $ elastalert --config config.yaml create-index

``--index NAME`` picks another name than ``writeback_index``, ``--old-index NAME`` copies an existing index into the
new one and ``--recreate`` deletes and recreates the indices. For information about what data will go here, see
:ref:`ElastAlert 3 Metadata Index <metadata>`.

.. admonition:: ElastAlert 3
   :class: ea3

   ElastAlert 2's separate ``elastalert-create-index`` and ``elastalert-test-rule`` commands are the ``create-index``
   and ``test-rule`` subcommands of the ``elastalert`` binary. ``elastalert-test-rule ARGS`` is also shipped, as a
   small launcher for ``elastalert test-rule ARGS`` (it must sit next to ``elastalert``). ``create-index`` does not
   ask questions.

An existing ElastAlert 2 writeback index can be reused as it is: the documents have the same shape.

Checking and running
--------------------

::

    $ elastalert --config config.yaml validate                              # load every rule, no Elasticsearch needed
    $ elastalert --config config.yaml test-rule rules/my_rule.yaml --days 1  # try a rule on past data, nothing is sent
    $ elastalert --config config.yaml --verbose                             # run the daemon

``validate`` loads the config and every rule, builds the alerters, reports each error and exits with status 1 if
there is any. The argument ``--verbose`` sets it to display INFO level messages; ``--rule example_frequency.yaml``
runs a single rule. See :doc:`flags` and :ref:`Testing your rule <testing>`.

Stop the daemon with ``SIGTERM``: running rules finish and the writeback buffer is flushed (10 seconds limit).

.. _mitre_layer:

ATT&CK Navigator layer
----------------------

.. admonition:: ElastAlert 3
   :class: ea3

   New in ElastAlert 3.

::

    $ elastalert --config config.yaml mitre-layer -o coverage.json

``mitre-layer`` loads every rule, like ``validate``, and writes an `ATT&CK Navigator
<https://mitre-attack.github.io/attack-navigator/>`_ layer (format 4.5) of their :ref:`mitre_attack <mitre_attack>`
techniques. Open the file in Navigator with *Open Existing Layer*. Elasticsearch is not needed.

The layer has one cell per technique and tactic. The cell's score is the number of rules that cover it, and its
comment and metadata name those rules and their files. Rules with ``is_enabled: false`` are left out unless you pass
``--include-disabled``; they are then marked ``(disabled)``. Other options: ``--name`` (the layer name), and no
``-o`` to write to standard output.

.. _docker-instructions:

As a Docker container
=====================

The repository contains a ``Dockerfile`` (Debian slim, non-root user uid 10001, about 140 MB). Build the image::

    $ docker build -t elastalert3 .

- The working directory is ``/opt/elastalert``, so ``rules_folder: rules`` means ``/opt/elastalert/rules``.
- The default command is ``--config /opt/elastalert/config.yaml``. Any other argument replaces it, for example
  ``docker run --rm elastalert3 validate`` or ``... test-rule rules/x.yaml --days 1``.
- ``sh`` is present in the image for the ``command`` alerter.
- The writeback indices are not created automatically: run ``create-index`` once.

The following example assumes an Elasticsearch container has already been started with Docker, on the default Docker
network ``es_default``.

Create a rule directory and rules file in addition to elastalert.yaml, and then mount both into the ElastAlert 3 container:

.. code-block::

    elastalert.yaml
    rules/
      a.yaml

elastalert.yaml

.. code-block:: yaml

    rules_folder: /opt/elastalert/rules

    run_every:
      seconds: 10

    buffer_time:
      minutes: 15

    es_host: elasticsearch
    es_port: 9200

    writeback_index: elastalert_status

    alert_time_limit:
      days: 2

a.yaml

.. code-block:: yaml

    name: "a"
    type: "frequency"
    index: "mariadblog-*"
    is_enabled: true
    num_events: 2
    realert:
      minutes: 5
    terms_size: 50
    timeframe:
      minutes: 5
    timestamp_field: "@timestamp"
    timestamp_type: "iso"
    use_strftime_index: false
    alert_subject: "Test {} 123 aa☃"
    alert_subject_args:
      - "message"
      - "@log_name"
    alert_text: "Test {}  123 bb☃"
    alert_text_args:
      - "message"
    filter:
      - query:
          query_string:
            query: "@timestamp:*"
    alert:
      - "slack"
    slack_webhook_url: 'https://hooks.slack.com/services/xxxxxxxxx'
    slack_channel_override: "#abc"
    slack_emoji_override: ":kissing_cat:"
    slack_msg_color: "warning"
    slack_parse_override: "none"
    slack_username_override: "elastalert"

Create the indices, then start the container:

.. code-block::

    docker run --rm --net=es_default \
    -v $(pwd)/elastalert.yaml:/opt/elastalert/config.yaml:ro \
    elastalert3 --config /opt/elastalert/config.yaml create-index

    docker run --net=es_default -d --name elastalert --restart=always \
    -v $(pwd)/elastalert.yaml:/opt/elastalert/config.yaml:ro \
    -v $(pwd)/rules:/opt/elastalert/rules:ro \
    elastalert3 --config /opt/elastalert/config.yaml --verbose

    docker logs -f elastalert

Environment variables override the connection settings, as in ElastAlert 2: ``ES_HOST``, ``ES_HOSTS``, ``ES_PORT``,
``ES_USERNAME``, ``ES_PASSWORD``, ``ES_API_KEY``, ``ES_BEARER``, ``ES_USE_SSL``, ``ES_URL_PREFIX``. Environment
variables are also expanded inside the YAML files (``$VAR``, ``${VAR}``).

.. _kubernetes-instructions:

As a Kubernetes deployment
==========================

The Docker image can be used directly as a Kubernetes deployment. There is no Helm chart.

.. admonition:: ElastAlert 3
   :class: ea3

   Do not run two instances against the same writeback index: they would alert twice (same as two ElastAlert 2
   instances). Use one replica.

Creating a Rule
===============

Each rule defines a query to perform, parameters on what triggers a match, and a
list of alerts to fire for each match. We are going to use
this frequency rule as a template::

    name: Example rule
    type: frequency
    index: logstash-*
    num_events: 50
    timeframe:
      hours: 4
    filter:
    - term:
        some_field: "some_value"
    alert:
    - "email"
    email:
    - "elastalert@example.com"

``name`` is the unique name for this rule. ElastAlert 3 will not start if two
rules share the same name.

``type``: Each rule has a different type which may take different parameters.
The ``frequency`` type means "Alert when more than ``num_events`` occur within
``timeframe``." For information other types, see :ref:`Rule types <ruletypes>`.

``index``: The name of the index(es) to query. If you are using Logstash, by
default the indexes will match ``"logstash-*"``.

``num_events``: This parameter is specific to ``frequency`` type and is the
threshold for when an alert is triggered.

``timeframe`` is the time period in which ``num_events`` must occur.

``filter`` is a list of Elasticsearch filters that are used to filter results.
Here we have a single term filter for documents with ``some_field`` matching
``some_value``. See :ref:`Writing Filters For Rules <writingfilters>` for more
information. If no filters are desired, it should be specified as an empty list:
``filter: []``

``alert`` is a list of alerts to run on each match. For more information on
alert types, see :ref:`Alert Types <alert_types>`. The email alert requires an SMTP server
for sending mail. By default, it will attempt to use localhost. This can be
changed with the ``smtp_host`` option.

``email`` is a list of addresses to which alerts will be sent.

There are many other optional configuration options, see :ref:`Common
configuration options <commonconfig>`.

.. admonition:: ElastAlert 3
   :class: ea3

   ``es_host`` and ``es_port`` inside a rule must be identical to ``config.yaml``: every rule queries the cluster of
   the global configuration. A rule pointing at another cluster is rejected at load.

All documents must have a timestamp field. ElastAlert 3 will try to use
``@timestamp`` by default, but this can be changed with the ``timestamp_field``
option. By default, ElastAlert 3 uses ISO8601 timestamps, though unix timestamps
are supported by setting ``timestamp_type``.

As is, this rule means "Send an email to elastalert@example.com when there are
more than 50 documents with ``some_field == some_value`` within a 4 hour
period."

See :ref:`the testing section for more details <testing>` on how to test a specific rule file without sending alerts.

Operational Review
==================

When ElastAlert 3 runs with ``--verbose``, the output on standard error will resemble the following::

    INFO:elastalert:Queried rule Example rule from 2026-01-15 14:22 UTC to 2026-01-15 15:07 UTC: 5 hits
    INFO:elastalert:Ran Example rule from 2026-01-15 14:22 UTC to 2026-01-15 15:07 UTC: 5 query hits (0 already seen), 0 matches, 0 alerts sent

Let's break down the response to see what's happening.

``Queried rule Example rule from 2026-01-15 14:22 UTC to 2026-01-15 15:07 UTC: 5 hits``

ElastAlert 3 periodically queries the most recent ``buffer_time`` (default 45
minutes) for data matching the filters. Here we see that it matched 5 hits.

``Ran Example rule from 2026-01-15 14:22 UTC to 2026-01-15 15:07 UTC: 5 query hits (0 already seen), 0 matches, 0 alerts sent``

The line means ElastAlert 3 has finished processing the rule. For large time
periods, sometimes multiple queries may be run, but their data will be processed
together. ``query hits`` is the number of documents that are downloaded from
Elasticsearch, ``already seen`` refers to documents that were already counted in
a previous overlapping query and will be ignored, ``matches`` is the number of
matches the rule type outputted, and ``alerts sent`` is the number of alerts
actually sent. This may differ from ``matches`` because of options like
``realert`` and ``aggregation`` or because of an error.

A status document describing the run is then written to the ``elastalert_status``
index, so that a restart resumes from here.

The default ``run_every`` is 5 minutes, meaning the rule runs again 5 minutes later,
with its time range shifted forward 5 minutes.

.. admonition:: ElastAlert 3
   :class: ea3

   Each rule runs in its own task on its own schedule (``max_threads`` limits how many run at the same time), so
   there is no global ``Sleeping for ... seconds`` line. Writeback documents are sent in one ``_bulk`` request per
   second; use ``--es_debug`` to see every request.

Say, over the next 5 minutes, 46 more matching documents were added to
Elasticsearch::

    INFO:elastalert:Queried rule Example rule from 2026-01-15 14:27 UTC to 2026-01-15 15:12 UTC: 51 hits
    ...
    INFO:elastalert:Sent email to ["elastalert@example.com"]
    ...
    INFO:elastalert:Ran Example rule from 2026-01-15 14:27 UTC to 2026-01-15 15:12 UTC: 51 query hits (5 already seen), 1 matches, 1 alerts sent

The body of the email will contain something like::

    Example rule

    At least 50 events occurred between 2026-01-15 11:12 UTC and 2026-01-15 15:12 UTC

    @timestamp: 2026-01-15T15:12:00Z

If an error occurred, such as an unreachable SMTP server, you will see an
``ERROR:elastalert:Error while running alert email: ...`` line. Only the failed
alerter is retried later.

Note that if you stop ElastAlert 3 and then run it again later, it will look up
``elastalert_status`` and begin querying at the end time of the last query. This
is to prevent duplication or skipping of alerts if ElastAlert 3 is restarted.

By using the ``--debug`` flag instead of ``--verbose``, the body of email will
instead be logged and the email will not be sent. In addition, the queries will
not be saved to ``elastalert_status``.

Disabling a Rule
================

To stop a rule from executing, add or adjust the `is_enabled` option inside the
rule's YAML file to `false`. When ElastAlert 3 reloads the rules it will detect
that the rule has been disabled and prevent it from executing. The rule reload
interval defaults to 5 minutes but can be adjusted via the `run_every`
configuration option.

Optionally, once a rule has been disabled it is safe to remove the rule file, if
there is no intention of re-activating the rule. However, be aware that removing
a rule file without first disabling it will _not_ disable the rule!

.. admonition:: ElastAlert 3
   :class: ea3

   Removing a rule file stops the rule at the next reload. A reloaded rule keeps its state (position, already seen
   documents, pending alerts). ``--pin_rules`` turns reloading off.

