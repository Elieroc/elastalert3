.. _exposingrulemetrics:

Exposing Rule Metrics
=====================

Configuration
-------------
Running ElastAlert with ``--prometheus_port`` configuration flag will expose ElastAlert 3 Prometheus metrics on the specified port. Prometheus metrics are disabled by default.

To expose ElastAlert rule metrics on port ``9979`` run the following command:

.. code-block:: console

    $ elastalert --config config.yaml --prometheus_port 9979 

The ``--prometheus_addr`` configuration flag can also be used to bind the Prometheus metrics server to a different host address.

.. code-block:: console

   $ elastalert --config config.yaml --prometheus_port 9979 --prometheus_addr "::"

Rule Metrics
------------

The metrics being exposed are related to the `ElastAlert 3 metadata indices <https://elastalert3.neopipe.fr/elastalert_status.html>`_. The exposed metrics are in the `Prometheus text-based format <https://prometheus.io/docs/instrumenting/exposition_formats/#text-based-format>`_. Metrics are of the metric type `counter <https://prometheus.io/docs/concepts/metric_types/#counter>`_ or `gauge <https://prometheus.io/docs/concepts/metric_types/#gauge>`_ and follow the `Prometheus metric naming <https://prometheus.io/docs/practices/naming/>`_. 

In the standard metric definition, the metric names are structured as follows:

.. code-block:: console

     elastalert_{metric}_{unit}

Where:

- ``{metric}`` is a unique name of the metric. For example, ``hits``.
- ``{unit}`` is the unit of measurement of the metric value. For example, ``total`` is a counter type metric and ``created`` is a gauge type metric.

All metrics except ``elastalert_errors_{unit}`` have values that apply to a particular rule name. In the exported metrics, these can be identified using the ``rule_name`` `Prometheus label <https://prometheus.io/docs/concepts/data_model/#metric-names-and-labels>`_.

Find below all available metrics:

+---------------------------------------+-----------------+---------------------------+---------------+
|    METRIC                             |  Type           |  Description              |  Label        |
+=======================================+=================+===========================+===============+
| ``elastalert_scrapes_{unit}``         | Counter, Gauge  | Number of scrapes         | ``rule_name`` |
+---------------------------------------+-----------------+---------------------------+---------------+
| ``elastalert_hits_{unit}``            | Counter, Gauge  | Number of hits            | ``rule_name`` |
+---------------------------------------+-----------------+---------------------------+---------------+
| ``elastalert_matches_{unit}``         | Counter, Gauge  | Number of matches         | ``rule_name`` |
+---------------------------------------+-----------------+---------------------------+---------------+
| ``elastalert_time_taken_{unit}``      | Counter, Gauge  | Time taken in seconds     | ``rule_name`` |
+---------------------------------------+-----------------+---------------------------+---------------+
| ``elastalert_alerts_sent_{unit}``     | Counter, Gauge  | Number of alerts sent     | ``rule_name`` |
+---------------------------------------+-----------------+---------------------------+---------------+
| ``elastalert_alerts_not_sent_{unit}`` | Counter, Gauge  | Number of alerts not sent | ``rule_name`` |
+---------------------------------------+-----------------+---------------------------+---------------+
| ``elastalert_alerts_silenced_{unit}`` | Counter, Gauge  | Number of silenced alerts | ``rule_name`` |
+---------------------------------------+-----------------+---------------------------+---------------+
| ``elastalert_errors_{unit}``          | Counter, Gauge  | Number of errors          |               |
+---------------------------------------+-----------------+---------------------------+---------------+

.. admonition:: ElastAlert 3
   :class: ea3

   Only the counters are exposed: ``elastalert_{metric}_total``. The ``_created`` gauges that the Python Prometheus
   client adds are not. The metric names and the ``rule_name`` label are the same, so existing dashboards and alerts
   on the ``_total`` series keep working.

   New in ElastAlert 3, besides the series above:

   - ``elastalert_rule_lag_seconds{rule_name}`` (gauge): seconds between now and the end of the last query range of
     the rule. It keeps growing when a rule stops running, so an alert on it (for example above three times
     ``run_every``) finds rules that are stuck, failing or starved of ``max_threads``.
   - ``elastalert_rule_last_success_timestamp_seconds{rule_name}`` (gauge): Unix time of the last run without error.
     Neither gauge has a sample for a rule until its first successful run.
   - ``elastalert_es_request_duration_seconds{kind}`` (histogram) and ``elastalert_es_request_errors_total{kind}``
     (counter): every request to Elasticsearch, by ``kind`` (``search``, ``scroll``, ``pit``, ``count``, ``mget``,
     ``bulk``, ``eql``, ``esql``, ``validate``, ``field_caps``, ``get``, ``other``). They are not per rule, to keep the
     number of series small with thousands of rules.
