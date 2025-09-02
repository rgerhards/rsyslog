.. _prop-message-app-name:
.. _properties.message.app-name:

app-name
========

.. index::
   single: properties; app-name
   single: app-name

.. summary-start

The contents of the app-name field from ietf draft.

.. summary-end

This property belongs to the **Message Properties** group.

:Name: app-name
:Category: Message Properties
:Type: unknown

Description
-----------
  The contents of the APP-NAME field from IETF draft
  draft-ietf-syslog-protocol

Usage
-----
.. _properties.message.app-name-usage:

.. code-block:: rsyslog

   template(name="t" type="string" string="%app-name%")

See also
--------
See :doc:`../../rainerscript/properties` for the category overview.
