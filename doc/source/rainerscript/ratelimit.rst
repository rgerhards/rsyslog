ratelimit()
===========

The ``ratelimit()`` object defines a reusable rate-limiting
configuration. Once declared, instances can be referenced from inputs,
outputs, or other components via the :literal:`ratelimit.name` parameter.
This makes it trivial to keep rate limiting aligned across multiple
modules.

Examples
--------

Inline definition
~~~~~~~~~~~~~~~~~

.. code-block:: none

   ratelimit(
       name="http_ingest",
       interval="60",
       burst="1200",
       severity="5"
   )

   input(type="imudp"
         port="514"
         ratelimit.name="http_ingest")

   action(type="omhttp"
          server="https://api.example"
          ratelimit.name="http_ingest")

YAML-backed definition
~~~~~~~~~~~~~~~~~~~~~~

Place the reusable limits in a YAML file:

.. code-block:: yaml

   # /etc/rsyslog.d/ratelimits/api_ingest.yml
   interval: 120
   burst: 2000
   severity: 4

Reference the file from the :rainerscript:`ratelimit()` object:

.. code-block:: none

   ratelimit(
       name="api_ingest",
       policy="/etc/rsyslog.d/ratelimits/api_ingest.yml"
   )

   action(type="omhttp"
          server="https://api.example"
          ratelimit.name="api_ingest")

Per-source YAML policy
~~~~~~~~~~~~~~~~~~~~~~

External policies can also describe per-source limits that future inputs may
use to throttle senders individually. The document must provide a ``default``
block containing ``max`` (messages) and ``window`` (seconds) plus an optional
``overrides`` sequence that tweaks specific sender keys:

.. code-block:: yaml

   default:
     max: 1000
     window: 10s      # optional "s" suffix
   overrides:
     - key: "db01.corp.local"
       max: 5000
       window: 10s
     - key: "backup-01"
       max: 20000
       window: 30

The ``window`` value accepts an optional ``s`` suffix for readability (for
example ``5s``). Every override entry must provide ``key``, ``max``, and
``window``. Duplicate keys or missing fields cause configuration validation to
fail with an explanatory error.

Parameters
----------

``name``
   Unique identifier used by :literal:`ratelimit.name`. The object must be
   defined before it is referenced.

``interval``
   Time window, in seconds, that the ratelimiter covers. A value of
   ``0`` disables the limiter.

``burst``
   Number of messages that may pass through the limiter during each
   interval before throttling kicks in.

``severity`` *(optional)*
   Maximum severity level that is subject to rate limiting. Messages with
   a numerically lower severity (e.g. ``emerg``/``alert``) always pass the
   limiter. When omitted, all severities are rate limited.

``policy`` *(optional)*
   Path to a YAML file that defines ``interval``, ``burst``, and optional
   ``severity`` values. When ``policy`` is provided, inline numeric
   parameters must be omitted. The path is resolved relative to the current
   working directory and is stored verbatim in the policy registry so that
   diagnostics can report the source file.

Notes
-----

* Inline ``ratelimit.interval``/``ratelimit.burst`` settings remain
  supported for backward compatibility. When :literal:`ratelimit.name`
  is present, the inline parameters must be omitted.
* ``policy=`` cannot be combined with inline numeric values. For the flat
  schema the YAML file must provide at least ``interval`` and ``burst`` keys.
  Policies that define a ``default`` block (with optional ``overrides``) may
  omit the top-level values. Duplicate keys or unsupported properties cause
  configuration loading to fail with a descriptive error message.
* Policies defining ``default``/``overrides`` may omit the top-level
  ``interval``/``burst`` values. Future per-source features will consume the
  nested configuration while legacy ratelimit consumers continue to use the
  top-level values when present.
* When rsyslog is built without libyaml support the ``policy=`` parameter
  is rejected and the log instructs operators to switch back to the
  traditional inline settings.
* Multiple configuration blocks may reference the same ratelimit object.
  Each consumer keeps its own runtime counters while sharing the immutable
  configuration.
* The optional severity value only takes effect for components that
  support severity-based throttling (currently :doc:`../configuration/modules/imuxsock`).
