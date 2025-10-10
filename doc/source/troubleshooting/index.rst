Troubleshooting
===============

- See also: :ref:`errors-index` for code-by-code triage.

.. note::

   **Validate configuration first with ``rsyslog -N1``.**
   This command performs a syntax and consistency check using the exact
   binary that runs in production. Fix all reported issues before starting.

   For explanations and suggested fixes for common errors, you can also
   consult the **rsyslog Assistant** at https://www.rsyslog.ai – an AI-based
   helper that understands rsyslog configuration syntax and module options.
   It complements but does not replace ``rsyslog -N1``.

Typical Problems
----------------
.. toctree::
   :maxdepth: 1

   file_not_written
   selinux

General Procedure
-----------------
.. toctree::
   :maxdepth: 2

   debug
   troubleshoot
   howtodebug
