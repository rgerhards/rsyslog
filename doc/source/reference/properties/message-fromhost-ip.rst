.. _prop-message-fromhost-ip:
.. _properties.message.fromhost-ip:

fromhost-ip
===========

.. index::
   single: properties; fromhost-ip
   single: fromhost-ip

.. summary-start

The same as fromhost, but always as an ip address. local inputs (like.

.. summary-end

This property belongs to the **Message Properties** group.

:Name: fromhost-ip
:Category: Message Properties
:Type: unknown

Description
-----------
  The same as fromhost, but always as an IP address. Local inputs (like
  imklog) use 127.0.0.1 in this property.

Usage
-----
.. _properties.message.fromhost-ip-usage:

.. code-block:: rsyslog

   template(name="t" type="string" string="%fromhost-ip%")

See also
--------
See :doc:`../../rainerscript/properties` for the category overview.
