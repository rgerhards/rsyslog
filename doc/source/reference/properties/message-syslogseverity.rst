.. _prop-message-syslogseverity:
.. _properties.message.syslogseverity:
.. _properties.alias.syslogpriority:

syslogseverity
==============

.. index::
   single: properties; syslogseverity
   single: syslogseverity

.. summary-start

Severity from the message - in numerical form.

.. summary-end

This property belongs to the **Message Properties** group.

:Name: syslogseverity
:Category: Message Properties
:Type: unknown
:Aliases: syslogpriority

Description
-----------
  severity from the message - in numerical form

Usage
-----
.. _properties.message.syslogseverity-usage:

.. code-block:: rsyslog

   template(name="t" type="string" string="%syslogseverity%")

Aliases
~~~~~~~
- syslogpriority — alias for syslogseverity

See also
--------
See :doc:`../../rainerscript/properties` for the category overview.
