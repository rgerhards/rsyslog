.. _param-omelasticsearch-interleaved:
.. _omelasticsearch.parameter.module.interleaved:

interleaved
===========

.. index::
   single: omelasticsearch; interleaved
   single: interleaved

.. summary-start

Store Elasticsearch bulk requests with their replies as paired entries in the error file.

.. summary-end

This parameter applies to :doc:`../../configuration/modules/omelasticsearch`.

:Name: interleaved
:Scope: action
:Type: boolean
:Default: action=off
:Required?: no
:Introduced: at least 8.x, possibly earlier

Description
-----------
When ``interleaved`` is enabled, :ref:`param-omelasticsearch-errorfile` captures
each processed bulk operation as an object containing both the request payload
and the Elasticsearch reply. With ``erroronly="off"`` every processed request is
logged, providing a complete transcript for troubleshooting. When paired with
:ref:`param-omelasticsearch-erroronly`, only the failed operations are recorded,
but they retain the same request/response pairing.

Action usage
------------
.. _param-omelasticsearch-action-interleaved:
.. _omelasticsearch.parameter.action.interleaved:
.. code-block:: rsyslog

   action(type="omelasticsearch" interleaved="...")

See also
--------
See also :doc:`../../configuration/modules/omelasticsearch`.
