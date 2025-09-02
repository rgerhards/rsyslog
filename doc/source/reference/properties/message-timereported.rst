.. _prop-message-timereported:
.. _properties.message.timereported:
.. _properties.alias.timestamp:

timereported
============

.. index::
   single: properties; timereported
   single: timereported

.. summary-start

Timestamp from the message. resolution depends on what was provided in.

.. summary-end

This property belongs to the **Message Properties** group.

:Name: timereported
:Category: Message Properties
:Type: unknown
:Aliases: timestamp

Description
-----------
  timestamp from the message. Resolution depends on what was provided in
  the message (in most cases, only seconds)

Usage
-----
.. _properties.message.timereported-usage:

.. code-block:: rsyslog

   template(name="t" type="string" string="%timereported%")

Aliases
~~~~~~~
- timestamp — alias for timereported

See also
--------
See :doc:`../../rainerscript/properties` for the category overview.
