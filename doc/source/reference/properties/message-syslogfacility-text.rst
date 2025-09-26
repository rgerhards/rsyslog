.. _prop-message-syslogfacility-text:
.. _properties.message.syslogfacility-text:

syslogfacility-text
===================

.. index::
   single: properties; syslogfacility-text
   single: syslogfacility-text

.. summary-start

Returns the facility from the message as human-readable text.

.. summary-end

This property belongs to the **Message Properties** group.

:Name: syslogfacility-text
:Category: Message Properties
:Type: string

Description
-----------
The facility from the message - in text form.

Usage
-----
.. _properties.message.syslogfacility-text-usage:

.. code-block:: rsyslog

   template(name="show-syslogfacility-text" type="string" string="%syslogfacility-text%")

See also
--------
See :doc:`../../configuration/properties` for the category overview.
