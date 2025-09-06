.. _prop-message-syslogtag:
.. _properties.message.syslogtag:

syslogtag
=========

.. index::
   single: properties; syslogtag
   single: syslogtag

.. summary-start

Tag from the message.

.. summary-end

This property belongs to the **Message Properties** group.

:Name: syslogtag
:Category: Message Properties
:Type: unknown

Description
-----------
  TAG from the message

Usage
-----
.. _properties.message.syslogtag-usage:

.. code-block:: rsyslog

   template(name="t" type="string" string="%syslogtag%")

See also
--------
See :doc:`../../rainerscript/properties` for the category overview.
