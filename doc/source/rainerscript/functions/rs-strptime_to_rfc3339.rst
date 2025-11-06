**********************
strptime_to_rfc3339()
**********************

Purpose
=======

strptime_to_rfc3339(timestamp, format)

Parses ``timestamp`` according to a `strptime(3)` style ``format`` string and
returns the timestamp formatted as an RFC 3339 / ISO 8601 string. The returned
value is a string that can be used in additional template processing or
forwarded to other systems.

If the format string does not contain year information, the current year is
inferred using the same heuristic as :rs:func:`parse_time` for RFC 3164
timestamps. When no time zone is present in the input, ``Z`` (UTC) is used.
When a numeric offset is present and supported (``+HHMM`` or ``+HH:MM``), it is
preserved in the result.

If the input cannot be parsed using the provided format string, an empty string
is returned and :rs:func:`script_error` is set to error state.

Example
=======

Parse a legacy timestamp without a year component:

.. code-block:: none

   strptime_to_rfc3339("Sep 17 13:45:34", "%b %d %H:%M:%S")

might produce (depending on the current year):

.. code-block:: none

   2025-09-17T13:45:34Z

Parse a timestamp with an explicit time zone offset:

.. code-block:: none

   strptime_to_rfc3339("2025-09-17 13:45:34 +02:30", "%Y-%m-%d %H:%M:%S %z")

produces:

.. code-block:: none

   2025-09-17T13:45:34+02:30
