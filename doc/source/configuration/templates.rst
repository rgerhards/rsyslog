Templates
=========

.. _templates.description:

Description
-----------

Templates are a key feature of rsyslog. They define arbitrary output
formats and enable dynamic file name generation. Every output, including
files, user messages, and database writes, relies on templates. When no
explicit template is set, rsyslog uses built-in defaults compatible with
stock syslogd formats. Key elements of templates are rsyslog
properties; see :doc:`rsyslog properties <properties>`.

.. _templates.template-processing:

Template processing
-------------------

When defining a template it should include a `HEADER` as defined in
`RFC5424 <https://datatracker.ietf.org/doc/html/rfc5424>`_. Understanding
:doc:`rsyslog parsing <parser>` is important. For example, if the ``MSG``
field is ``"this:is a message"`` and neither ``HOSTNAME`` nor ``TAG`` are
specified, the outgoing parser splits the message as:

.. code-block:: none

   TAG:this:
   MSG:is a message

.. _templates.template-object:

The ``template()`` object
-------------------------

Templates are defined with the ``template()`` object, which is a static
construct processed when rsyslog reads the configuration. Basic syntax:

.. code-block:: none

   template(parameters)

List templates additionally support an extended syntax:

.. code-block:: none

   template(parameters) { list-descriptions }

Parameters ``name`` and ``type`` select the template name and type. The
name must be unique. See below for available types and statements.

Template parameter: ``format``
------------------------------

The optional ``format`` parameter centralizes default escaping and
framing for templates. It allows new configurations to pick a JSON or SQL
profile in one place while preserving full control over individual
``property()`` statements.

Accepted values (case-insensitive):

.. list-table:: ``format`` values
   :header-rows: 1
   :widths: 25 75

   * - Value
     - Meaning
   * - ``raw``
     - No additional escaping or framing; legacy behaviour.
   * - ``json-quoted``
     - Render the template as a JSON object and quote values as strings
       by default. Equivalent to ``option.json="on"`` together with
       ``option.jsonf="on``.
   * - ``json-canonical``
     - Render the template as a JSON object with automatic typing. Values
       that look like numbers, booleans, or ``null`` remain unquoted,
       while strings are escaped and quoted.
   * - ``sql-mysql``
     - Escape values using MySQL/MariaDB rules (single quotes become
       ``\'`` and backslashes double). Matches ``option.sql``.
   * - ``sql-std``
     - Escape single quotes using SQL-standard doubling (``'`` → ``''``).
       Matches ``option.stdsql``.

Precedence and compatibility notes:

* ``property()`` statements that set their own ``format=`` continue to
  take precedence over template defaults.
* When ``format`` is specified, the legacy ``option.json``,
  ``option.jsonf``, ``option.sql``, and ``option.stdsql`` parameters for
  the same template are ignored and a one-time warning is logged during
  configuration load.
* If ``format`` is omitted, the legacy options behave exactly as before,
  including their mutual exclusion rules and the requirement that SQL
  writers enable either ``option.sql`` or ``option.stdsql`` before they
  start.

Examples:

.. code-block:: none

   template(name="out_json" type="list" format="json-quoted") {
        property(outname="message" name="msg")
   }
   # Result: {"message":" msgnum:00000000:"}

.. code-block:: none

   template(name="out_canon" type="list" format="json-canonical") {
        property(outname="counter" name="$!counter")
        property(outname="rawJSON" name="$!payload" format="jsonfr")
   }
   # Result: {"counter":42, "rawJSON":{"custom":true}}

Migration hints:

.. list-table:: Legacy to ``format`` mapping
   :header-rows: 1
   :widths: 45 55

   * - Legacy setting(s)
     - Preferred ``format`` value
   * - ``option.json`` + ``option.jsonf``
     - ``format="json-quoted"``
   * - ``option.json`` with per-property ``format="jsonf"``
     - ``format="json-quoted"``
   * - Want typed JSON everywhere
     - ``format="json-canonical"``
   * - ``option.sql``
     - ``format="sql-mysql"``
   * - ``option.stdsql``
     - ``format="sql-std"``

.. _templates.types:

Template types
--------------

.. list-table::
   :header-rows: 1
   :widths: 20 80

   * - Topic
     - Summary
   * - :ref:`ref-templates-type-list`
     - .. include:: ../reference/templates/templates-type-list.rst
        :start-after: .. summary-start
        :end-before: .. summary-end

   * - :ref:`ref-templates-type-subtree`
     - .. include:: ../reference/templates/templates-type-subtree.rst
        :start-after: .. summary-start
        :end-before: .. summary-end
   * - :ref:`ref-templates-type-string`
     - .. include:: ../reference/templates/templates-type-string.rst
        :start-after: .. summary-start
        :end-before: .. summary-end
   * - :ref:`ref-templates-type-plugin`
     - .. include:: ../reference/templates/templates-type-plugin.rst
        :start-after: .. summary-start
        :end-before: .. summary-end

.. _templates.statements:

Template statements
-------------------

.. list-table::
   :header-rows: 1
   :widths: 20 80

   * - Topic
     - Summary
   * - :ref:`ref-templates-statement-constant`
     - .. include:: ../reference/templates/templates-statement-constant.rst
        :start-after: .. summary-start
        :end-before: .. summary-end
   * - :ref:`ref-templates-statement-property`
     - .. include:: ../reference/templates/templates-statement-property.rst
        :start-after: .. summary-start
        :end-before: .. summary-end

.. _templates.additional:

Additional topics
-----------------

.. list-table::
   :header-rows: 1
   :widths: 20 80

   * - Topic
     - Summary
   * - :ref:`ref-templates-options`
     - .. include:: ../reference/templates/templates-options.rst
        :start-after: .. summary-start
        :end-before: .. summary-end
   * - :ref:`ref-templates-examples`
     - .. include:: ../reference/templates/templates-examples.rst
        :start-after: .. summary-start
        :end-before: .. summary-end
   * - :ref:`ref-templates-reserved-names`
     - .. include:: ../reference/templates/templates-reserved-names.rst
        :start-after: .. summary-start
        :end-before: .. summary-end
   * - :ref:`ref-templates-legacy`
     - .. include:: ../reference/templates/templates-legacy.rst
        :start-after: .. summary-start
        :end-before: .. summary-end

.. _templates.reserved-table:

Reserved template names overview
--------------------------------

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Name
     - Purpose
   * - RSYSLOG_TraditionalFileFormat
     - Old style log file format
   * - RSYSLOG_FileFormat
     - Modern logfile format with high-precision timestamps
   * - RSYSLOG_TraditionalForwardFormat
     - Traditional forwarding with low-precision timestamps
   * - RSYSLOG_SysklogdFileFormat
     - Sysklogd compatible format
   * - RSYSLOG_ForwardFormat
     - High-precision forwarding format
   * - RSYSLOG_SyslogProtocol23Format
     - Format from IETF draft syslog-protocol-23
   * - RSYSLOG_DebugFormat
     - Troubleshooting format listing all properties
   * - RSYSLOG_WallFmt
     - Host and time followed by tag and message
   * - RSYSLOG_StdUsrMsgFmt
     - Syslogtag followed by the message
   * - RSYSLOG_StdDBFmt
     - Insert command for MariaDB/MySQL
   * - RSYSLOG_StdPgSQLFmt
     - Insert command for PostgreSQL
   * - RSYSLOG_spoofadr
     - Sender IP address only
   * - RSYSLOG_StdJSONFmt
     - JSON structure of message properties

Legacy ``$template`` statement
------------------------------

For historical configurations, the legacy ``$template`` syntax is still
recognized. See :ref:`ref-templates-legacy` for details.

See also
--------

- `How to bind a template <https://www.rsyslog.com/how-to-bind-a-template/>`_
- `Adding the BOM to a message <https://www.rsyslog.com/adding-the-bom-to-a-message/>`_
- `How to separate log files by host name of the sending device <https://www.rsyslog.com/article60/>`_

.. toctree::
   :hidden:

   ../reference/templates/templates-type-list
   ../reference/templates/templates-type-subtree
   ../reference/templates/templates-type-string
   ../reference/templates/templates-type-plugin
   ../reference/templates/templates-statement-constant
   ../reference/templates/templates-statement-property
   ../reference/templates/templates-options
   ../reference/templates/templates-examples
   ../reference/templates/templates-reserved-names
   ../reference/templates/templates-legacy
