.. _prop-message-syslogtag:
.. _properties.message.syslogtag:

syslogtag
=========

.. index::
   single: properties; syslogtag
   single: syslogtag

.. summary-start

Returns the TAG field from the incoming message header.

.. summary-end

This property belongs to the **Message Properties** group.

:Name: syslogtag
:Category: Message Properties
:Type: string

Description
-----------
TAG from the message.

Usage
-----
.. _properties.message.syslogtag-usage:

.. code-block:: rsyslog

   template(name="show-syslogtag" type="string" string="%syslogtag%")

See also
--------
See :doc:`../../configuration/properties` for the category overview.
