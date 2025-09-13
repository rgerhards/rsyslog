.. _prop-message-syslogfacility-text:
.. _properties.message.syslogfacility-text:

syslogfacility-text
===================

.. index::
   single: properties; syslogfacility-text
   single: syslogfacility-text

.. summary-start

The facility from the message - in text form.

.. summary-end

This property belongs to the **Message Properties** group.

:Name: syslogfacility-text
:Category: Message Properties
:Type: unknown

Description
-----------
  the facility from the message - in text form

Usage
-----
.. _properties.message.syslogfacility-text-usage:

.. code-block:: rsyslog

   template(name="t" type="string" string="%syslogfacility-text%")

See also
--------
See :doc:`../../rainerscript/properties` for the category overview.
