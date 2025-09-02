.. _prop-message-timegenerated:
.. _properties.message.timegenerated:

timegenerated
=============

.. index::
   single: properties; timegenerated
   single: timegenerated

.. summary-start

Timestamp when the message was received. always in high resolution.

.. summary-end

This property belongs to the **Message Properties** group.

:Name: timegenerated
:Category: Message Properties
:Type: unknown

Description
-----------
  timestamp when the message was RECEIVED. Always in high resolution

Usage
-----
.. _properties.message.timegenerated-usage:

.. code-block:: rsyslog

   template(name="t" type="string" string="%timegenerated%")

See also
--------
See :doc:`../../rainerscript/properties` for the category overview.
