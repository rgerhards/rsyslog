.. _prop-system-time-wday:
.. _properties.system-time.wday:

$wday
=====

.. index::
   single: properties; $wday
   single: $wday

.. summary-start

The current week day as defined by 'gmtime()'. 0=sunday, ..., 6=saturday.

.. summary-end

This property belongs to the **Time-Related System Properties** group.

:Name: $wday
:Category: Time-Related System Properties
:Type: integer

Description
-----------
  The current week day as defined by 'gmtime()'. 0=Sunday, ..., 6=Saturday

Usage
-----
.. _properties.system-time.wday-usage:

.. code-block:: rsyslog

   template(name="t" type="string" string="%$wday%")

See also
--------
See :doc:`../../rainerscript/properties` for the category overview.
