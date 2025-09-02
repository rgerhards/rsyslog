.. _prop-system-time-year:
.. _properties.system-time.year:

$year
=====

.. index::
   single: properties; $year
   single: $year

.. summary-start

The current year (4-digit).

.. summary-end

This property belongs to the **Time-Related System Properties** group.

:Name: $year
:Category: Time-Related System Properties
:Type: integer

Description
-----------
  The current year (4-digit)

Usage
-----
.. _properties.system-time.year-usage:

.. code-block:: rsyslog

   template(name="t" type="string" string="%$year%")

See also
--------
See :doc:`../../rainerscript/properties` for the category overview.
