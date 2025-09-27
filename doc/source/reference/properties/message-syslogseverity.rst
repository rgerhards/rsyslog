.. _prop-message-syslogseverity:
.. _properties.message.syslogseverity:

syslogseverity
==============

.. index::
   single: properties; syslogseverity
   single: syslogseverity

.. summary-start

Provides the numeric syslog severity extracted from the message.

.. summary-end

This property belongs to the **Message Properties** group.

:Name: syslogseverity
:Category: Message Properties
:Type: integer
:Aliases: syslogpriority

Description
-----------
Severity from the message - in numerical form.

Usage
-----
.. _properties.message.syslogseverity-usage:

.. code-block:: rsyslog

   template(name="example" type="string" string="%syslogseverity%")

Aliases
~~~~~~~
- syslogpriority — alias for syslogseverity

See also
--------
See :doc:`../../rainerscript/properties` for the category overview.
