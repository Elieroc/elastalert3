Global Configuration
********************

ElastAlert 3 has a global configuration file, ``config.yaml``, which defines several aspects of its operation:

``buffer_time``: ElastAlert 3 will continuously query against a window from the present to ``buffer_time`` ago.
This way, logs can be back filled up to a certain extent and ElastAlert 3 will still process the events. This
may be overridden by individual rules. This option is ignored for rules where ``use_count_query`` or ``use_terms_query``
is set to true. Note that back filled data may not always trigger count based alerts as if it was queried in real time.

``es_host``: The host name of the Elasticsearch cluster where ElastAlert 3 records metadata about its searches.
When ElastAlert 3 is started, it will query for information about the time that it was last run. This way,
even if ElastAlert 3 is stopped and restarted, it will never miss data or look at the same events twice. It will also specify the default cluster for each rule to run on.
The environment variable ``ES_HOST`` will override this field.
For multiple host Elasticsearch clusters see ``es_hosts`` parameter.

``es_port``: The port corresponding to ``es_host``. The environment variable ``ES_PORT`` will override this field.

``es_hosts`` is the list of addresses of the nodes of the Elasticsearch cluster. This
parameter can be used for high availability purposes, but the primary host must also
be specified in the ``es_host`` parameter. The ``es_hosts`` parameter can be overridden 
within each rule. This value can be specified as ``host:port`` if overriding the default port.
The environment variable ``ES_HOSTS`` will override this field, and can be specified as a comma-separated value to denote multiple hosts.

.. admonition:: ElastAlert 3
   :class: ea3

   Failover: on a connection error the next host of the list is tried. ``es_hosts`` cannot be overridden by a rule
   with a different value.


``use_ssl``: Optional; whether or not to connect to ``es_host`` using TLS; set to ``True`` or ``False``.
The environment variable ``ES_USE_SSL`` will override this field.

.. admonition:: ElastAlert 3
   :class: ea3

   TLS, ``verify_certs``, ``ca_certs``, ``client_cert`` and ``client_key`` are implemented but have **never been
   tested against a real TLS endpoint**.


``verify_certs``: Optional; whether or not to verify TLS certificates; set to ``True`` or ``False``. The default is ``True``.

``ssl_show_warn``: Optional; suppress TLS and certificate related warnings; set to ``True`` or ``False``. The default is ``True``.

.. admonition:: ElastAlert 3
   :class: ea3

   Accepted and ignored.


``client_cert``: Optional; path to a PEM certificate to use as the client certificate.

``client_key``: Optional; path to a private key file to use as the client key.

``ca_certs``: Optional; path to a CA cert bundle to use to verify SSL connections

``es_username``: Optional; basic-auth username for connecting to ``es_host``. The environment variable ``ES_USERNAME`` will override this field.

``es_password``: Optional; basic-auth password for connecting to ``es_host``. The environment variable ``ES_PASSWORD`` will override this field.

``es_bearer``: Optional; Bearer token for connecting to ``es_host``. The environment variable ``ES_BEARER`` will override this field. This authentication option will override the password authentication option.

``es_api_key``: Optional; Base64 api-key token for connecting to ``es_host``. The environment variable ``ES_API_KEY`` will override this field. This authentication option will override both the bearer and the password authentication options.

``es_url_prefix``: Optional; URL prefix for the Elasticsearch endpoint.  The environment variable ``ES_URL_PREFIX`` will override this field.

``es_send_get_body_as``: Optional; Method for querying Elasticsearch - ``GET``, ``POST`` or ``source``. The default is ``GET``

.. admonition:: ElastAlert 3
   :class: ea3

   Accepted and ignored: searches are always sent as ``POST`` with a JSON body.


``es_conn_timeout``: Optional; sets timeout for connecting to and reading from ``es_host``; defaults to ``20``.

``rules_loader``: Optional; sets the loader class to be used by ElastAlert 3 to retrieve rules and hashes.
Defaults to ``FileRulesLoader`` if not set.

.. admonition:: ElastAlert 3
   :class: ea3

   Only the built-in file loader exists. Custom Python loaders cannot be loaded.


``rules_folder``: The name of the folder or a list of folders which contains rule configuration files. ElastAlert 3 will load all
files in this folder, and all subdirectories, that end in .yaml. If the contents of this folder change, ElastAlert 3 will load, reload
or remove rules based on their respective config files. (only required when using ``FileRulesLoader``).

.. admonition:: ElastAlert 3
   :class: ea3

   Rule files are checked every ``run_every`` (hash of the rule file and of its ``import`` files). A changed rule
   keeps its state: position, already seen documents and pending alerts. A new or changed file that fails to load is
   reported and the previous version of the rule keeps running.


``scan_subdirectories``: Optional; Sets whether or not ElastAlert 3 should recursively descend the rules directory - ``true`` or ``false``. The default is ``true``

``run_every``: How often ElastAlert 3 should query Elasticsearch. ElastAlert 3 will remember the last time
it ran the query for a given rule, and periodically query from that time until the present. The format of
this field is a nested unit of time, such as ``minutes: 5``. This is how time is defined in every ElastAlert 3
configuration.

``misfire_grace_time``: If the rule scheduler is running behind, due to large numbers of rules or long-running rules, this grace time settings allows a rule to still be executed, provided its next scheduled runt time is no more than this grace period, in seconds, overdue. The default is 5 seconds.

.. admonition:: ElastAlert 3
   :class: ea3

   Accepted and ignored: each rule runs in its own task, there is no shared scheduler to fall behind.


``writeback_index``: The index on ``es_host`` to use.

``max_query_size``: The maximum number of documents that will be downloaded from Elasticsearch in a single query. The
default is 10,000, and if you expect to get near this number, consider using ``use_count_query`` for the rule. If this
limit is reached, ElastAlert 3 will `scroll <https://www.elastic.co/guide/en/elasticsearch/reference/current/search-request-scroll.html>`_
using the size of ``max_query_size`` through the set amount of pages, when ``max_scrolling_count`` is set or until processing all results.

``max_scrolling_count``: The maximum amount of pages to scroll through. The default is ``990``, to avoid a stack overflow error due to Python's stack limit of 1000. For example, if this value is set to ``5`` and the ``max_query_size`` is set to ``10000`` then ``50000`` documents will be downloaded at most.

.. admonition:: ElastAlert 3
   :class: ea3

   Paging uses point in time + ``search_after`` on Elasticsearch 7.12 and newer, scroll otherwise. It is iterative, so
   there is no stack limit and no 990 pages default; the option is honoured when set.


``max_threads``: The maximum number of concurrent threads available to process scheduled rules. Large numbers of long-running rules may require this value be increased, though this could overload the Elasticsearch cluster if too many complex queries are running concurrently. Default is 10.

.. admonition:: ElastAlert 3
   :class: ea3

   Bounds the number of rules that run at the same time. Each rule is a task of its own.


``scroll_keepalive``: The maximum time (formatted in `Time Units <https://www.elastic.co/guide/en/elasticsearch/reference/current/common-options.html#time-units>`_) the scrolling context should be kept alive. Avoid using high values as it abuses resources in Elasticsearch, but be mindful to allow sufficient time to finish processing all the results.

``max_aggregation``: The maximum number of alerts to aggregate together. If a rule has ``aggregation`` set, all
alerts occuring within a timeframe will be sent together. The default is 10,000.

.. admonition:: ElastAlert 3
   :class: ea3

   Accepted and ignored.


``old_query_limit``: The maximum time between queries for ElastAlert 3 to start at the most recently run query.
When ElastAlert 3 starts, for each rule, it will search ``elastalert_metadata`` for the most recently run query and start
from that time, unless it is older than ``old_query_limit``, in which case it will start from the present time. The default is one week.

``disable_rules_on_error``: If true, ElastAlert 3 will disable rules which throw uncaught (not EAException) exceptions. It
will upload a traceback message to ``elastalert_metadata`` and if ``notify_email`` is set, send an email notification. The
rule will no longer be run until either ElastAlert 3 restarts or the rule file has been modified. This defaults to True.

.. admonition:: ElastAlert 3
   :class: ea3

   An "uncaught exception" is a panic in the Rust code. Ordinary errors (Elasticsearch unreachable, bad query,
   missing timestamp field, alerter failure) never disable a rule; the next run retries.


``show_disabled_rules``: If true, ElastAlert 3 show the disable rules' list when finishes the execution. This defaults to True.

.. admonition:: ElastAlert 3
   :class: ea3

   The list is logged every ``run_every``, only when some rules are disabled.


``notify_alert``: List of alerters to execute upon encountering a system error. System errors occur when an unexpected exception is thrown during rule processing. For additional notifications, such as when ElastAlert 3 background tests encounter problems, or when connectivity to the data storage system is lost, enable ``notify_all_errors``. 

.. admonition:: ElastAlert 3
   :class: ea3

   **Not supported**: the option is accepted and ignored. Use ``notify_email``.


See the :ref:`Alerts` section for the list of available alerters and their parameters.

Included fields in a system notification are:

- message: The details about the error
- timestamp: The time that the error occurred
- rule: Rule object if the error occurred during the processing of a rule, otherwise will be empty/None.

The following example shows how all ElastAlert 3 system errors can be delivered to both a Matrix chat server and an email address.

.. code-block:: yaml

    notify_alert:
    - email
    - matrixhookshot

    notify_all_errors: true

    email:
    - jason@some-domain.com
    smtp_host: some-mail-host.com
    from_addr: "ElastAlert 3 <sysadmin@some-server.com>"
    smtp_auth_file: /opt/elastalert2/smtp.auth
    matrixhookshot_webhook_url: https://some-matrix-server/webhook/xyz

``notify_all_errors``: If true, notification emails will be sent on additional system errors. This can cause a large number of emails to be sent when connectivity to Elasticsearch is lost. When set to false, only unexpected, rule-specific errors will be sent.

``notify_email``: (DEPRECATED) An email address, or list of email addresses, to which notification emails will be sent upon encountering an unexpected rule error. The from address, SMTP host, and reply-to header can be set
using ``from_addr``, ``smtp_host``, and ``email_reply_to`` options, respectively. By default, no emails will be sent. NOTE: This is a legacy method with limited email delivery support. Use the newer ``notify_alert`` setting to gain the full flexibility of ElastAlert 3's alerter library for system notifications.

.. admonition:: ElastAlert 3
   :class: ea3

   ``notify_email`` is the way to get error notifications in ElastAlert 3. Operators are mailed when

   - a rule panics (subject ``Uncaught exception in ElastAlert - <rule>``, with the panic location and a backtrace; it
     says whether the rule was disabled);
   - a new or changed rule file fails to load (subject ``Uncaught exception in ElastAlert - <file>``; the previous version
     of the rule keeps running);
   - with ``notify_all_errors: true``, on every logged error (``ElastAlert notification``, the body is the error message).
     This can send one mail per rule per run while Elasticsearch is down.

   Recipients are ``notify_email`` from ``config.yaml`` plus the rule's own ``notify_email`` (de-duplicated). Mail is sent
   through ``smtp_host`` / ``smtp_port`` (default ``localhost:25``, STARTTLS when offered, ``smtp_ssl: true`` for implicit
   TLS, ``smtp_auth_file`` for login). ElastAlert 2 only uses ``smtp_host`` and sends generic error mails with an empty
   body.


single address example::

    notify_email: "one@domain"

or

multiple address example::

    notify_email:
        - "one@domain"
        - "two@domain"

``from_addr``: The address to use as the from header in email notifications.
This value will be used for email alerts as well, unless overwritten in the rule config. The default value
is "ElastAlert".

``smtp_host``: The SMTP host used to send email notifications. This value will be used for email alerts as well,
unless overwritten in the rule config. The default is "localhost".

``email_reply_to``: This sets the Reply-To header in emails. The default is the recipient address.

``aws_region``: This makes ElastAlert 3 to sign HTTP requests when using Amazon OpenSearch Service. It'll use instance role keys to sign the requests.
The environment variable ``AWS_DEFAULT_REGION`` will override this field.

.. admonition:: ElastAlert 3
   :class: ea3

   **Not supported**: AWS SigV4 signing of Elasticsearch requests. (The SNS, SQS and SES alerters sign their own requests.)


``profile``: AWS profile to use when signing requests to Amazon OpenSearch Service, if you don't want to use the instance role keys.
The environment variable ``AWS_DEFAULT_PROFILE`` will override this field.

.. admonition:: ElastAlert 3
   :class: ea3

   **Not supported.**


``replace_dots_in_field_names``: If ``True``, ElastAlert 3 replaces any dots in field names with an underscore before writing documents to Elasticsearch.
The default value is ``False``. Elasticsearch 2.0 - 2.3 does not support dots in field names.

.. admonition:: ElastAlert 3
   :class: ea3

   **Not supported.**


``string_multi_field_name``: If set, the suffix to use for the subfield for string multi-fields in Elasticsearch.
The default value is ``.keyword``.

``add_metadata_alert``: If set, alerts will include metadata described in rules (``category``, ``description``, ``owner`` and ``priority``); set to ``True`` or ``False``. The default is ``False``.

``skip_invalid``: If ``True``, skip invalid files instead of exiting.

``jinja_root_name``: When using a Jinja template, specify the name of the root field name in the template. The default is ``_data``.

``jinja_template_path``: When using a Jinja template, specify relative (based on current working directory) filesystem path to template, this overrides the default behaviour of using alert_text as the template.

``custom_pretty_ts_format``: This option provides a way to define custom format of timestamps printed in log messages and in alert messages.
If this option is not set, default timestamp format ('%Y-%m-%d %H:%M %Z') will be used. (Optional, string, default None)

Example usage and resulting formatted timestamps::

    (not set; default)                               -> '2021-08-16 21:38 JST'
    custom_pretty_ts_format: '%Y-%m-%d %H:%M %z'     -> '2021-08-16 21:38 +0900'
    custom_pretty_ts_format: '%Y-%m-%d %H:%M'        -> '2021-08-16 21:38'

.. _ea3_config:

Options specific to ElastAlert 3
================================

``use_pit``: Use point in time + ``search_after`` to page through results when the cluster supports it
(Elasticsearch 7.12 and newer). Set to ``false`` to always use scroll. (Optional, boolean, default ``true``)

``mitre_attack_data``: Path of an ``enterprise-attack.json`` STIX bundle from
`MITRE <https://github.com/mitre-attack/attack-stix-data>`_. The :ref:`mitre_attack <mitre_attack>` rule option is
checked against this bundle instead of the included copy of Enterprise ATT&CK (v20). (Optional, string, no default)

``sigma_folders``: Folders of plain `Sigma <https://sigmahq.io>`__ rule files, searched with their subfolders. Each file is a rule
of its own, with the options of ``sigma_defaults``. See :ref:`Sigma folders <sigma>`. (Optional, a folder or a list, no default)

``sigma_defaults``: The rule options (``alert``, ``index``, ``sigma_pipeline``, ``realert``, ...) given to every rule of
``sigma_folders``. It needs an ``alert``. (Optional, map, no default)

``statsd_host``, ``statsd_instance_tag``: not supported, ignored. Use the Prometheus endpoint, see
:doc:`recipes/exposing_rule_metrics`.

``logging``: the Python ``dictConfig`` section is not supported. Logs go to standard error; the level is set by
``--verbose`` / ``--debug``. See :doc:`logging`.
