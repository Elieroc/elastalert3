Introduction
************

ElastAlert 3 is a simple framework for alerting on anomalies, spikes, or other patterns of interest from data in `Elasticsearch <https://www.elastic.co/elasticsearch/>`_ and `OpenSearch <https://opensearch.org/>`_.

If you have data being written into Elasticsearch in near real time and want to be alerted when that data matches certain patterns, ElastAlert 3 is the tool for you.

Overview
========

We designed ElastAlert 3 to be :ref:`reliable <reliability>`, highly :ref:`modular <modularity>`, and easy to setup.

It works by combining Elasticsearch with two types of components, rules and alerts.
The datasource, typically Elasticsearch, is periodically queried and the data is passed to the rule type, which determines when
a match is found. When a match occurs, it is given to one or more alerts, which take action based on the match.

This is configured by a set of rules, each of which defines a query, a rule type, and a set of alerts.

Several rule types with common monitoring paradigms are included with ElastAlert 3:

- "Match where there are X events in Y time" (``frequency`` type)
- "Match when the rate of events increases or decreases" (``spike`` type)
- "Match when there are less than X events in Y time" (``flatline`` type)
- "Match when a certain field matches a blacklist/whitelist" (``blacklist`` and ``whitelist`` type)
- "Match on any event matching a given filter" (``any`` type)
- "Match when a field has two different values within some time" (``change`` type)
- "Match when a never before seen term appears in a field" (``new_term`` type)
- "Match when the number of unique values for a field is above or below a threshold" (``cardinality`` type)
- "Match when a metric computed by an Elasticsearch aggregation crosses a threshold" (``metric_aggregation``,
  ``percentage_match`` and ``spike_aggregation`` types)
- "Match when events of several searches happen on the same machine, IP or user within some time" (``correlation`` type,
  new in ElastAlert 3)
- "Match when something moves too far, too fast between two events (impossible travel)" (``geo_velocity`` type, new in
  ElastAlert 3)
- "Match when events come at regular intervals (malware beaconing)" (``beacon`` type, new in ElastAlert 3)
- "Match when the number of events is abnormal for this hour of the week" (``baseline`` type, new in ElastAlert 3)

Currently, we have support built in for these alert types:

- Alerta
- Alertmanager
- AWS SES (Amazon Simple Email Service)
- AWS SNS (Amazon Simple Notification Service)
- AWS SQS (Amazon Simple Queue Service)
- Chatwork
- Command
- Datadog
- Debug
- Dingtalk
- Discord
- Email
- Exotel
- Flashduty
- Gitter
- GoogleChat
- Grafana IRM
- Graylog GELF
- HTTP POST
- HTTP POST 2
- IRIS
- Indexer
- Jira
- Lark
- LINE Messaging API
- Matrix Hookshot
- Mattermost
- Microsoft Power Automate
- OpsGenie
- PagerDuty
- PagerTree
- Rocket.Chat
- Squadcast
- ServiceNow
- Slack
- SMSEagle
- Splunk On-Call (Formerly VictorOps)
- Stomp
- Telegram
- Tencent SMS
- TheHive
- Twilio
- Webex Webhook
- WorkWechat
- YZJ
- Zabbix

The Grafana IRM and Squadcast integrations use the HTTP POST alerter.

.. admonition:: ElastAlert 3
   :class: ea3

   All 44 alerters of ElastAlert 2 are ported. Rule types, alerters, rule loaders and match enhancements are compiled
   into the binary: Python plugins cannot be loaded. See :doc:`extending`.

In addition to this basic usage, there are many other features that make alerts more useful:

- Alerts link to Kibana Discover searches
- Aggregate counts for arbitrary fields
- Combine alerts into periodic reports
- Separate alerts by using a unique key field
- Intercept and enhance match data

To get started, check out :ref:`Running ElastAlert 3 For The First Time <tutorial>`.

.. _reliability:

Reliability
===========

ElastAlert 3 has several features to make it more reliable in the event of restarts or Elasticsearch unavailability:

- ElastAlert 3 :ref:`saves its state to Elasticsearch <metadata>` and, when started, will resume where previously stopped
- If Elasticsearch is unresponsive, ElastAlert 3 will wait until it recovers before continuing
- Alerts which throw errors may be automatically retried for a period of time
- Unsent alerts and open aggregation groups are read back from Elasticsearch at startup
- Each alerter of a rule keeps its own delivery state: if Slack is down and email works, only Slack is retried
- On ``SIGTERM``, running rules finish and pending writes to Elasticsearch are flushed (10 seconds limit)

.. _modularity:

Modularity
==========

ElastAlert 3 has three main components:

Rule types
----------

The rule type is responsible for processing the data returned from Elasticsearch. It is initialized with the rule configuration, passed data
that is returned from querying Elasticsearch with the rule's filters, and outputs matches based on this data. See :ref:`Rule types <ruletypes>`.

Alerts
------

Alerts are responsible for taking action based on a match. A match is generally a dictionary containing values from a document in Elasticsearch,
but may contain arbitrary data added by the rule type. See :ref:`Alerts`.

Enhancements
------------

Enhancements are a way of intercepting an alert and modifying or enhancing it in some way. They are passed the match dictionary before it is given
to the alerter. In ElastAlert 3 they are Rust modules compiled into the binary. See :doc:`enhancements`.

All three are part of the binary. New ones are added in Rust and the binary is rebuilt; see :doc:`extending`.
