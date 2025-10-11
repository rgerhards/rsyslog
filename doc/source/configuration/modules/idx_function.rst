.. _modules-function-index:

.. meta::
   :description: Index of rsyslog function modules that add extra RainerScript capabilities.
   :keywords: rsyslog, function module, rainerscript, pcre, regex

.. summary-start

Index of loadable function modules that extend RainerScript with additional functions.

.. summary-end

Function modules extend RainerScript with additional callable helpers. Load the module
before using the functions it contributes. When multiple modules define the same function
name, the function from the first loaded module is used and a warning is emitted.

.. toctree::
   :glob:
   :maxdepth: 1

   fm*
