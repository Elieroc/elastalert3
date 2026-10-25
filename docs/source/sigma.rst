.. _sigma:

Sigma rules
===========

.. admonition:: ElastAlert 3
   :class: ea3

   Sigma support is new in ElastAlert 3.4. ElastAlert 2 ignores the ``sigma`` option.

A rule file with ``sigma:`` takes its detection from a `Sigma <https://sigmahq.io>`__ rule file. The Sigma
``detection`` is compiled at load into a Query DSL ``filter``; everything else (``index``, ``alert``, ``realert``,
``type``, ...) is an ordinary rule option.

.. code-block:: yaml

   name: Encoded PowerShell
   sigma: sigma/proc_creation_win_powershell_enc.yml   # relative to this file
   index: logs-windows-*
   alert: [slack]
   realert: {minutes: 10}

The ``type`` defaults to ``any``. Any ``filter`` of the rule is kept, and the Sigma detection is added to it (AND).
A change to the Sigma file reloads the rule.

``sigma_pipeline``
  One :ref:`pipeline <sigma_pipelines>` or a list of them, applied in order.

``sigma_keyword_suffix``
  Text added to every field name after the pipelines, e.g. ``.keyword`` when your text fields have a keyword
  sub-field.

``sigma_rules``
  Files and folders (relative to the rule file) where to look up the rules a correlation refers to, and filters. The
  Sigma file itself and the ``sigma_folders`` are always searched.

``sigma_keyword_fields``
  Fields to search for Sigma keywords (values without a field name). Each keyword is matched as ``contains`` in each
  of them. Without it, a rule with keywords does not load. Can be set in ``config.yaml``.

Metadata
--------

The Sigma file fills in what the rule leaves unset; an option of the rule always wins.

========================= =========================================================================================
Sigma                     ElastAlert rule option
========================= =========================================================================================
``title``                 ``alert_subject``
``description``           ``description`` (written to the alert with ``add_metadata_alert``)
``level``                 ``priority``: ``critical`` 1, ``high`` 2, ``medium`` 3, ``low`` 4, ``informational`` 5
``tags`` ``attack.t1059`` :ref:`mitre_attack <mitre_attack>`
``fields``                ``include``, renamed by the pipelines
========================= =========================================================================================

Only ``attack.tNNNN`` and ``attack.tNNNN.NNN`` tags are used. Tactic, group and software tags are ignored, and so are
techniques unknown to the ATT&CK release in use (with a warning), so a newer Sigma rule never fails on a tag. A technique
counts under every tactic it belongs to. With ``fields``, the matches carry only those fields (and the timestamp).

A ``status`` or ``level`` that Sigma does not define is refused at load.

Sigma folders
-------------

To run a collection of Sigma rules (such as `SigmaHQ <https://github.com/SigmaHQ/sigma>`_) without writing a wrapper per
file, list the folders in ``config.yaml``:

.. code-block:: yaml

   sigma_folders: [/etc/elastalert/sigma/rules/windows]
   sigma_defaults:
     alert: [slack]
     index: logs-windows-*
     sigma_pipeline: ecs_windows
     sigma_keyword_suffix: .keyword
     realert: {minutes: 30}
   skip_invalid: true

Every ``.yml`` / ``.yaml`` file under the folders (subfolders included) is a rule, as if it had a wrapper holding the
``sigma_defaults``. The rule name is the file name without extension, so names must be unique across the folders. The
Sigma file is hot-reloaded like any rule; new and removed files are picked up. With ``sigma_folders`` set, a missing
``rules_folder`` is not an error.

``sigma_defaults`` takes any rule option except ``name``, ``sigma`` and ``import``, and needs an ``alert``. Per-logsource
indices come from a pipeline (``set_index``, see below).

A collection like SigmaHQ contains rules this version refuses (see the end of this page): set ``skip_invalid: true``, or the
daemon stops at the first one. ``elastalert validate`` lists them. Every rule is one search per ``run_every``, so point
``sigma_folders`` at the folders that match your data rather than at the whole repository.

.. _sigma_correlation:

Correlation rules
-----------------

A Sigma file whose first document is a ``correlation`` rule becomes the ElastAlert rule type that counts or correlates
the events of the rules it refers to. Those rules are looked up by ``id`` or ``name`` in the other documents of the file
(``---``), in ``sigma_rules`` and in the ``sigma_folders``. Their pipelines apply, and so do the filters that name them.

========================== ================================ ==========================================================
Sigma                      ElastAlert                       Condition
========================== ================================ ==========================================================
``event_count``            ``frequency``                    ``gte: N`` or ``gt: N``
``value_count``            ``cardinality``                  ``gte: N`` or ``gt: N``, with ``field``
``temporal``               :ref:`correlation <correlation>` all the rules; ``AND``
``temporal_ordered``       :ref:`correlation <correlation>` all the rules, in order; ``THEN``
========================== ================================ ==========================================================

``timespan`` (``30s``, ``10m``, ``1h``, ``1d``) is the ``timeframe``. ``group-by`` is the ``query_key``; ``aliases`` name the
field a group-by value is read from in the events of each rule, and the pipelines rename it. ``level``, ``title`` and the
rest of the metadata work as for other Sigma rules.

.. code-block:: yaml

   title: Many failed logins, then a success
   level: high
   correlation:
     type: temporal_ordered
     rules: [multiple_failed_login, successful_login]
     group-by: [User]
     timespan: 10m
   ---
   name: multiple_failed_login
   correlation:
     type: event_count
     rules: [failed_login]
     group-by: [User]
     timespan: 10m
     condition: {gte: 10}
   ---
   name: failed_login
   logsource: {product: windows, service: security}
   detection: {selection: {EventID: [529, 4625]}, condition: selection}
   ---
   name: successful_login
   logsource: {product: windows, service: security}
   detection: {selection: {EventID: [528, 4624]}, condition: selection}

This is the example of the Sigma specification. It becomes a ``correlation`` rule with two leaves, the first with
``num_events: 10``, joined by ``THEN``.

Things to know:

- A leaf of a ``temporal`` rule can itself be an ``event_count`` correlation of detection rules, as above, if it has the
  same ``timespan`` and ``group-by`` as the rule that uses it. As a leaf, its count is taken inside the window of the
  chain, which starts at the first event of the chain: this is how the ``correlation`` type works, and it is stricter
  than a sliding window of its own.
- ``event_count`` with several rules counts the events of all of them; they must resolve ``group-by`` to the same field
  and ask for the same index. Use ``temporal`` to correlate events carrying the group-by value under different names
  (one ``group-by`` field then).
- The type, ``timeframe``, ``query_key`` and the options that depend on them (``num_events``, ``cardinality_field``,
  ``max_cardinality``, ``correlation_leaves``, ``correlation_query``) come from the correlation: the rule may not set them.
- ``cardinality`` and ``frequency`` alert on each event once the threshold is passed, until ``realert`` (one minute by
  default) silences the key.
- ``generate`` only matters in ``sigma_folders``. With ``false`` (the default) the rules a correlation refers to do not
  run on their own; ``true`` keeps them running too. In a rule with a ``sigma:`` wrapper, ``generate: true`` is refused: write
  a wrapper for each rule you want alerts from.
- Refused at load: ``value_sum``, ``value_avg``, ``value_percentile``, ``lt``, ``lte``, ``eq``, ``neq`` and ranges,
  a ``temporal`` condition that is not "all the rules", a correlation chained deeper than described, and a group-by that
  a pipeline maps to several fields.

.. _sigma_filters:

Filters
-------

A Sigma filter (``filter:`` with ``rules``, ``selection`` and ``condition``) suppresses the matches of the rules it
names: their query becomes ``rule AND NOT filter``. Rules are named by ``id`` or ``name``. The filter is compiled with the
pipelines and the keyword settings of the rule it applies to.

.. code-block:: yaml

   title: Administrator accounts
   filter:
     rules: [6f3e2987-db24-4c78-a860-b4f4095a7095]
     selection: {User|startswith: 'adm_'}
     condition: selection

It is found in the same file (a document after the rule), in ``sigma_rules``, or in the ``sigma_folders``, where a filter
file is not a rule of its own. A filter that names a correlation rule makes it fail to load: name the rules it refers to instead.
Changing a filter reloads the rules it applies to.

Supported
---------

``condition`` with ``and``, ``or``, ``not``, parentheses, ``1 of`` / ``all of`` with ``them`` or a ``name*``
pattern, and a list of conditions (alternatives). Field modifiers: ``contains``, ``startswith``, ``endswith``,
``all``, ``re`` (with ``i``), ``cidr``, ``exists``, ``gt``, ``gte``, ``lt``, ``lte``, ``cased``, ``windash``,
``base64``, ``base64offset``, ``utf16le`` / ``wide``, ``utf16be``, ``utf16``. Wildcards ``*`` and ``?`` with ``\*``,
``\?`` and ``\\`` escapes, ``null`` values, numbers and booleans.

``windash`` writes each ``-`` that starts an argument as ``/``, en dash, em dash and horizontal bar too.

Not supported
-------------

Refused at load, never approximated: aggregation conditions (``| count() ...``), ``timeframe``, ``fieldref``,
``expand``, ``re|m``, wildcards in encoded values, the correlation types listed above, and unknown keys of the Sigma file.
``logsource`` only feeds the pipelines; it does not select the index by itself (see ``set_index``).

Regular expressions
-------------------

A leading ``(?i)`` is read as ``re|i``.

Elasticsearch regular expressions are anchored and have no ``\b``, look-around or lazy quantifiers. ``re`` values are
wrapped in ``.*( ... ).*`` unless they start with ``^`` or end with ``$``, ``\d`` ``\w`` ``\s`` are rewritten as
character classes, and the rest of the unsupported syntax makes the rule fail to load. A pattern whose automaton is
too large for Lucene (many ``.{2,128}`` ranges, for instance) loads but fails at search time with ``Determinizing ...
would require more than 10000 effort``: the rule then logs an error on every run until it is rewritten.

Mappings
--------

Sigma matches case-insensitively, so the queries use ``case_insensitive`` (Elasticsearch 7.10+, OpenSearch 2.x), and
the fields must be mapped as ``keyword`` (or ``wildcard``). A ``cidr`` value needs an ``ip`` field.

.. _sigma_pipelines:

Pipelines
---------

Sigma rules use generic field names (``Image``, ``CommandLine``). A pipeline renames them to the fields of your index,
adds the conditions a logsource implies, and can choose the index. Without one, the names are used as written.

Built-in pipelines, selected by name:

``ecs_windows``
  Windows logs as ECS (Winlogbeat, Elastic Agent): ``Image`` becomes ``process.executable``, and so on. Fields ECS has
  no name for become ``winlog.event_data.<name>``. The ``process_creation``, ``network_connection``, ``file_event`` and
  ``registry_*`` categories add an ``event.category`` condition (``event.type: start`` for process creation).

``sysmon``
  Raw Sysmon events as Winlogbeat ships them: fields under ``winlog.event_data``, and each category adds the Sysmon
  ``winlog.event_id`` and ``winlog.provider_name`` conditions.

``ecs_linux``
  Linux logs as ECS (Auditbeat, Elastic Agent), for process, network and file categories.

These cover the common fields only. Check them against your data, and stack your own pipeline after them for the rest:
``sigma_pipeline: [ecs_windows, pipelines/mine.yml]``.

A pipeline file is a subset of the `pySigma format <https://sigmahq-pysigma.readthedocs.io/>`_. A transformation
outside it makes the rule fail to load.

.. code-block:: yaml

   name: my index
   transformations:
     - type: field_name_mapping
       mapping:
         CommandLine: process.args        # a list maps to several fields, any of which may match
         Image: [process.executable, process.name]
     - type: field_name_suffix            # also: field_name_prefix
       suffix: .keyword
       unmapped: true                     # ElastAlert 3: only fields no earlier mapping renamed
     - type: add_condition                # ANDed with the detection
       rule_conditions: [{type: logsource, category: process_creation, product: windows}]
       conditions: {event.category: process}
     - type: set_index                    # ElastAlert 3: the rule's index, if it sets none
       index: logs-windows-*

``rule_conditions`` can only be ``logsource`` ones (``category``, ``product``, ``service``, compared without regard to
case); all of them must match. A rule's own ``index`` always wins over ``set_index``.

.. _sigma_convert:

Checking a rule: ``sigma-convert``
----------------------------------

``elastalert sigma-convert RULE.yml`` prints what a Sigma rule compiles to (the ``filter``, and the ``alert_subject``,
``priority``, ``mitre_attack``, ``include`` and ``index`` it would give), without Elasticsearch and without a
``config.yaml``. ``-p`` takes a pipeline (repeat it to stack them), ``--keyword-field`` and ``--keyword-suffix`` stand
for ``sigma_keyword_fields`` and ``sigma_keyword_suffix``. ``--dsl`` prints only the search body, ready for Kibana Dev
Tools or ``curl``:

.. code-block:: sh

   elastalert sigma-convert -p ecs_windows rules/proc_creation_win_powershell_enc.yml --dsl

``--rules`` takes the files and folders to look up the rules of a correlation in (``sigma_rules``). A correlation prints
the options of its rule type, not a single query, so ``--dsl`` does not apply to it.

Rules from the SigmaHQ repository
---------------------------------

Of the 3161 rules of SigmaHQ, 3142 (99.4%) convert with the built-in pipelines. The others are refused with a reason:
``fieldref`` (comparing two fields needs a script), regular expressions with ``\b``, lazy quantifiers or anchors inside
the pattern, and one rule that Lucene cannot compile (above).
