.. _prop-message-syslogpriority-text:
.. _properties.message.syslogpriority-text:

syslogpriority-text
===================

.. index::
   single: properties; syslogpriority-text
   single: syslogpriority-text

.. summary-start

An alias for syslogseverity-text.

.. summary-end

This property belongs to the **Message Properties** group.

:Name: syslogpriority-text
:Category: Message Properties
:Type: unknown
:Aliases: syslogseverity-text

Description
-----------
  an alias for syslogseverity-text

Usage
-----
.. _properties.message.syslogpriority-text-usage:

.. code-block:: rsyslog

   template(name="t" type="string" string="%syslogpriority-text%")

Aliases
~~~~~~~
- syslogseverity-text — alias for syslogpriority-text

See also
--------
See :doc:`../../rainerscript/properties` for the category overview.
