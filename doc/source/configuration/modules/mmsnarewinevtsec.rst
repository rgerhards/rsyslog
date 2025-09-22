SNARE Windows Security Parser Module (mmsnarewinevtsec)
======================================================

.. index:: mmsnarewinevtsec; message modification module

``mmsnarewinevtsec`` parses NXLog SNARE formatted Windows Security events and
stores the extracted data under the ``$!snare`` JSON subtree.  The module
handles both RFC5424 wrapped events (where the SNARE payload starts with
``MSWinEventLog``) and "pure" SNARE payloads where the hostname precedes the
format tag.  After parsing, the fixed SNARE fields are published together with a
structured interpretation of the human readable ``expanded_string`` blob.

Typical Usage
-------------

The module behaves like other message modification modules: load it and add an
``action()`` invocation to transform the message before it reaches later
actions.

.. code-block:: none

   module(load="mmsnarewinevtsec")

   ruleset(name="ingest") {
     action(type="mmsnarewinevtsec"
            mode="lenient"
            parse_time="on"
            default_tz="UTC")
     action(type="omfile" file="/var/log/snare.json"
            template="RSYSLOG_SyslogProtocol23Format")
   }
   input(type="imtcp" port="514" ruleset="ingest")

After execution the ``$!snare`` subtree contains:

* the detected hostname
* the format tag (``MSWinEventLog``)
* integer typed ``criticality``, ``snare_event_counter`` and
  ``event_log_counter``
* ``datetime_str`` and, when enabled, ``datetime_rfc3339``
* identifiers such as ``event_id``, ``source_name`` and ``computer_name``
* the original ``expanded_string`` and a structured
  ``extended_info`` object built from it

Field Mapping
-------------

The table below shows how SNARE fields are mapped.  Index numbers refer to the
fields after the ``MSWinEventLog`` tag.  Pure SNARE payloads provide the
hostname immediately before the tag and are otherwise identical.

==========  ===========================
Index       Output property
==========  ===========================
0           ``criticality``
1           ``log_name``
2           ``snare_event_counter``
3           ``datetime_str`` (and ``datetime_rfc3339`` when enabled)
4           ``event_id`` (omitted if ``N/A``)
5           ``source_name``
6           ``user_name``
7           ``sid_type``
8           ``event_audit_type``
9           ``computer_name``
10          ``category_string``
11          ``data_string``
12          ``expanded_string``
13          ``event_log_counter`` (omitted if ``N/A``)
==========  ===========================

Extended Information Parsing
----------------------------

Security events embed a prose style summary inside ``expanded_string``.  The
module tokenises this string on runs of two or more spaces and interprets tokens
ending in ``:`` as either section headers or field labels.  Values are attached
to the current section and stored beneath ``$!snare!extended_info``.  Before the
first section, leading text is gathered as ``extended_info.intro``.  Integer
values (for example ``Logon Type`` or ``Source Port``) are converted to JSON
numbers, while strings such as SIDs or hexadecimal identifiers remain strings.

Labels that represent lists can be emitted as JSON arrays.  By default
``Privileges`` is split into a list; additional labels can be supplied via the
``list_labels`` parameter.

When fewer than two labels are detected the parser sets
``extended_info.parse_ok`` to ``false``.  The raw ``expanded_string`` is still
exposed, and in debug builds the optional ``debug_raw`` parameter can include a
copy of the original string inside ``extended_info.raw``.

Module Parameters
-----------------

=========================  =====================  =========  ================================================
Parameter                  Type                   Default    Description
=========================  =====================  =========  ================================================
``mode``                   string (``lenient`` | ``strict``)  ``lenient``  ``strict`` enforces the exact field count; ``lenient`` accepts extra trailing fields.
``set_hostname_from_hdr``  binary                 ``on``     When enabled copy the syslog header hostname into ``$!snare!hostname`` for wrapped events.
``parse_time``             binary                 ``off``    Enable conversion of ``datetime_str`` to RFC 3339 (requires ``default_tz``).
``default_tz``             string                 ``UTC``    IANA timezone name or numeric offset used when ``parse_time`` is ``on``.
``max_label_len``          integer                ``64``     Maximum length (in characters) for label detection inside ``expanded_string``.
``list_labels``            string                 ``Privileges``  Comma-separated list of additional labels whose values should be split into arrays.
``debug_raw``              binary                 ``off``    On debug builds add ``extended_info.raw`` containing the unparsed ``expanded_string``.
=========================  =====================  =========  ================================================

Statistics
----------

The module registers the following counters that are visible through
``impstats``:

``parsed_ok``
    Number of messages parsed successfully.
``bad_prefix``
    Messages that did not contain the ``MSWinEventLog`` tag at the expected
    position.
``too_few_fields``
    Messages with insufficient fields (or extra fields when ``mode=strict``).
``time_parse_fail``
    Timestamp conversion failures when ``parse_time=on``.
``expanded_parse_ok`` / ``expanded_parse_fail``
    Success and failure counters for the extended information parser.

See Also
--------

* :doc:`mmleefparse`
* :doc:`mmaudit`
* :doc:`mmnormalize`
