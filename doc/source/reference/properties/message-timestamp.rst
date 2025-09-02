.. _prop-message-timestamp:
.. _properties.message.timestamp:

timestamp
=========

.. index::
   single: properties; timestamp
   single: timestamp

.. summary-start

Alias for timereported.

.. summary-end

This property belongs to the **Message Properties** group.

:Name: timestamp
:Category: Message Properties
:Type: unknown
:Aliases: timereported

Description
-----------
  alias for timereported

Usage
-----
.. _properties.message.timestamp-usage:

.. code-block:: rsyslog

   template(name="t" type="string" string="%timestamp%")

Aliases
~~~~~~~
- timereported — alias for timestamp

See also
--------
See :doc:`../../rainerscript/properties` for the category overview.
