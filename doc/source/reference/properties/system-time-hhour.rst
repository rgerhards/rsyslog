.. _prop-system-time-hhour:
.. _properties.system-time.hhour:

$hhour
======

.. index::
   single: properties; $hhour
   single: $hhour

.. summary-start

The current half hour we are in. from minute 0 to 29, this is always 0.

.. summary-end

This property belongs to the **Time-Related System Properties** group.

:Name: $hhour
:Category: Time-Related System Properties
:Type: integer

Description
-----------
  The current half hour we are in. From minute 0 to 29, this is always 0
  while from 30 to 59 it is always 1.

Usage
-----
.. _properties.system-time.hhour-usage:

.. code-block:: rsyslog

   template(name="t" type="string" string="%$hhour%")

See also
--------
See :doc:`../../rainerscript/properties` for the category overview.
