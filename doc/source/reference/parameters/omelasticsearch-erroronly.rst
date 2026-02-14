.. _param-omelasticsearch-erroronly:
.. _omelasticsearch.parameter.module.erroronly:

erroronly
=========

.. index::
   single: omelasticsearch; erroronly
   single: erroronly

.. summary-start

Record only failed bulk operations in the configured error file.

.. summary-end

This parameter applies to :doc:`../../configuration/modules/omelasticsearch`.

:Name: erroronly
:Scope: action
:Type: boolean
:Default: action=off
:Required?: no
:Introduced: at least 8.x, possibly earlier

Description
-----------
Enabling ``erroronly`` limits the contents of :ref:`param-omelasticsearch-errorfile`
to bulk requests that Elasticsearch reported as failed. Successful operations are
ignored, keeping the error log focused on actionable records. When combined with
:ref:`param-omelasticsearch-interleaved`, the module still filters for failures
but stores them as request/response pairs.

Action usage
------------
.. _param-omelasticsearch-action-erroronly:
.. _omelasticsearch.parameter.action.erroronly:
.. code-block:: rsyslog

   action(type="omelasticsearch" erroronly="...")

See also
--------
See also :doc:`../../configuration/modules/omelasticsearch`.
