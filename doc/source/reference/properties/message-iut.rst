.. _prop-message-iut:
.. _properties.message.iut:

iut
===

.. index::
   single: properties; iut
   single: iut

.. summary-start

The monitorware infounittype - used when talking to a.

.. summary-end

This property belongs to the **Message Properties** group.

:Name: iut
:Category: Message Properties
:Type: unknown

Description
-----------
  the monitorware InfoUnitType - used when talking to a
  `MonitorWare <https://www.monitorware.com>`_ backend (also for
  `Adiscon LogAnalyzer <https://loganalyzer.adiscon.com/>`_)

Usage
-----
.. _properties.message.iut-usage:

.. code-block:: rsyslog

   template(name="t" type="string" string="%iut%")

See also
--------
See :doc:`../../rainerscript/properties` for the category overview.
