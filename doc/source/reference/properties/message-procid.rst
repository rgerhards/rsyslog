.. _prop-message-procid:
.. _properties.message.procid:

procid
======

.. index::
   single: properties; procid
   single: procid

.. summary-start

The contents of the procid field from ietf draft.

.. summary-end

This property belongs to the **Message Properties** group.

:Name: procid
:Category: Message Properties
:Type: unknown

Description
-----------
  The contents of the PROCID field from IETF draft
  draft-ietf-syslog-protocol

Usage
-----
.. _properties.message.procid-usage:

.. code-block:: rsyslog

   template(name="t" type="string" string="%procid%")

See also
--------
See :doc:`../../rainerscript/properties` for the category overview.
