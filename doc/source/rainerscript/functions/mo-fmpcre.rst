.. _mod-fmpcre:

.. meta::
   :description: fmpcre adds the pcre_match() RainerScript function for PCRE-based string checks.
   :keywords: rsyslog, fmpcre, pcre_match, function module, regex

.. summary-start

Provides the optional fmpcre function module, which exposes pcre_match() for PCRE-compatible regular expression checks inside RainerScript.

.. summary-end

fmpcre: PCRE Function Module
============================

Overview
--------

The **fmpcre** module exposes the ``pcre_match()`` function to RainerScript so that
configuration logic can check whether a string satisfies a PCRE-compatible regular
expression. Load the module explicitly before calling ``pcre_match()``:

.. code-block:: none

   module(load="fmpcre")

Provided Functions
------------------

``pcre_match(<value>, <regex>)``
    Evaluates ``<value>`` against the supplied regular expression and returns ``1`` when
    the value matches and ``0`` otherwise. The first parameter can be any RainerScript
    expression that yields a string. The second parameter **must** be a constant string
    literal because the module compiles the expression once during configuration loading.

The function compiles the regular expression during configuration processing. If the
pattern is invalid, rsyslog aborts configuration loading and reports the PCRE compiler
error and the failing offset. After the module is unloaded or rsyslog shuts down, the
compiled pattern is released automatically.

Usage Example
-------------

The snippet below creates a helper variable that records whether the message payload
starts with ``foo`` and ends with ``bar``. It uses ``pcre_match()`` to perform the
regular expression check.

.. code-block:: none

   module(load="fmpcre")

   set $.hasFooBar = pcre_match($msg, "^foo.*bar$");
   if $.hasFooBar == 1 then {
       action(type="omfile" file="/var/log/foobar.log")
   }

Error Handling and Performance Notes
------------------------------------

- ``pcre_match()`` returns numeric values (``0`` or ``1``). Use numeric comparisons when
  branching on the result.
- Compiled expressions are cached, so repeated calls within a ruleset do not recompile
  the regex. To change the pattern dynamically, create multiple function calls with
  different constant expressions and guard them with ``if`` statements.
- When the module is not installed on the running system, loading ``fmpcre`` fails with an
  error stating that the module cannot be found.

See Also
--------

- :doc:`idx_module_functions`
- PCRE project documentation: https://www.pcre.org
