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
* ``policy=`` cannot be combined with inline numeric values. The YAML file
  must provide at least ``interval`` and ``burst`` keys. Duplicate keys or
  unsupported properties cause configuration loading to fail with a
  descriptive error message.
* When rsyslog is built without libyaml support the ``policy=`` parameter
  is rejected and the log instructs operators to switch back to the
  traditional inline settings.
* Multiple configuration blocks may reference the same ratelimit object.
  Each consumer keeps its own runtime counters while sharing the immutable
  configuration.
* The optional severity value only takes effect for components that
  support severity-based throttling (currently :doc:`../configuration/modules/imuxsock`).
