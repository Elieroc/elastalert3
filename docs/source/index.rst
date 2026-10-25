ElastAlert 3 - Automated rule-based alerting for Elasticsearch
==============================================================

ElastAlert 3 is an alerting daemon for Elasticsearch and OpenSearch, written in Rust. It started as a rewrite of
the core of `ElastAlert 2 <https://github.com/jertel/elastalert2>`_ and runs existing ElastAlert 2 ``config.yaml``
and rule files unchanged, while adding features of its own such as the :ref:`correlation <correlation>` rule type
and :ref:`active_hours <active_hours>`.

This documentation is based on the ElastAlert 2 documentation. Where ElastAlert 3 behaves differently, or adds
something, the page says so in a red **ElastAlert 3** note. The full list is in :doc:`differences`.

.. admonition:: Status: beta
   :class: warning

   Behaviour is checked against Python ElastAlert 2.31.0 by replaying the same data through both and diffing the
   alerts. It has not been run in production by anyone yet, and several code paths (TLS, client certificates,
   degraded clusters) have never been exercised. Run it next to your current setup with ``--debug`` first.

Contents:

.. toctree::
   :maxdepth: 2

   elastalert
   running_elastalert
   flags
   configuration
   ruletypes
   sigma
   alerts
   enhancements
   differences
   logging
   advanced
   recipes/faq

Indices and Tables
==================

* :ref:`genindex`
* :ref:`search`
