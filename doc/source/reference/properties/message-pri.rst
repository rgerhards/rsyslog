.. _prop-message-pri:
.. _properties.message.pri:

pri
===

.. index::
   single: properties; pri
   single: pri

.. summary-start

Pri part of the message - undecoded (single value).

.. summary-end

This property belongs to the **Message Properties** group.

:Name: pri
:Category: Message Properties
:Type: unknown

Description
-----------
  PRI part of the message - undecoded (single value)

Usage
-----
.. _properties.message.pri-usage:

.. code-block:: rsyslog

   template(name="t" type="string" string="%pri%")

See also
--------
See :doc:`../../rainerscript/properties` for the category overview.
