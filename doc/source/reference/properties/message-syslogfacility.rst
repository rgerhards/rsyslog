.. _prop-message-syslogfacility:
.. _properties.message.syslogfacility:

syslogfacility
==============

.. index::
   single: properties; syslogfacility
   single: syslogfacility

.. summary-start

The facility from the message - in numerical form.

.. summary-end

This property belongs to the **Message Properties** group.

:Name: syslogfacility
:Category: Message Properties
:Type: unknown

Description
-----------
  the facility from the message - in numerical form

Usage
-----
.. _properties.message.syslogfacility-usage:

.. code-block:: rsyslog

   template(name="t" type="string" string="%syslogfacility%")

See also
--------
See :doc:`../../rainerscript/properties` for the category overview.
