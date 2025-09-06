.. _prop-message-hostname:
.. _properties.message.hostname:
.. _properties.alias.source:

hostname
========

.. index::
   single: properties; hostname
   single: hostname

.. summary-start

Hostname from the message.

.. summary-end

This property belongs to the **Message Properties** group.

:Name: hostname
:Category: Message Properties
:Type: unknown
:Aliases: source

Description
-----------
  hostname from the message

Usage
-----
.. _properties.message.hostname-usage:

.. code-block:: rsyslog

   template(name="t" type="string" string="%hostname%")

Aliases
~~~~~~~
- source — alias for hostname

See also
--------
See :doc:`../../rainerscript/properties` for the category overview.
