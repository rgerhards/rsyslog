.. _prop-message-rawmsg-after-pri:
.. _properties.message.rawmsg-after-pri:

rawmsg-after-pri
================

.. index::
   single: properties; rawmsg-after-pri
   single: rawmsg-after-pri

.. summary-start

Almost the same as **rawmsg**, but the syslog pri is removed.

.. summary-end

This property belongs to the **Message Properties** group.

:Name: rawmsg-after-pri
:Category: Message Properties
:Type: unknown

Description
-----------
  Almost the same as **rawmsg**, but the syslog PRI is removed.
  If no PRI was present, **rawmsg-after-pri** is identical to
  **rawmsg**. Note that the syslog PRI is header field that
  contains information on syslog facility and severity. It is
  enclosed in greater-than and less-than characters, e.g.
  "<191>". This field is often not written to log files, but
  usually needs to be present for the receiver to properly
  classify the message. There are some rare cases where one
  wants the raw message, but not the PRI. You can use this
  property to obtain that. In general, you should know that you
  need this format, otherwise stay away from the property.

Usage
-----
.. _properties.message.rawmsg-after-pri-usage:

.. code-block:: rsyslog

   template(name="t" type="string" string="%rawmsg-after-pri%")

See also
--------
See :doc:`../../rainerscript/properties` for the category overview.
