.. _prop-system-time-month:
.. _properties.system-time.month:

$month
======

.. index::
   single: properties; $month
   single: $month

.. summary-start

The current month (2-digit).

.. summary-end

This property belongs to the **Time-Related System Properties** group.

:Name: $month
:Category: Time-Related System Properties
:Type: integer

Description
-----------
  The current month (2-digit)

Usage
-----
.. _properties.system-time.month-usage:

.. code-block:: rsyslog

   template(name="t" type="string" string="%$month%")

See also
--------
See :doc:`../../rainerscript/properties` for the category overview.
