.. _prop-message-rawmsg:
.. _properties.message.rawmsg:

rawmsg
======

.. index::
   single: properties; rawmsg
   single: rawmsg

.. summary-start

The message "as is".  should be useful for debugging and also if a message.

.. summary-end

This property belongs to the **Message Properties** group.

:Name: rawmsg
:Category: Message Properties
:Type: unknown

Description
-----------
  the message "as is".  Should be useful for debugging and also if a message
  should be forwarded totally unaltered.
  Please notice *EscapecontrolCharactersOnReceive* is enabled by default, so
  it may be different from what was received in the socket.

Usage
-----
.. _properties.message.rawmsg-usage:

.. code-block:: rsyslog

   template(name="t" type="string" string="%rawmsg%")

See also
--------
See :doc:`../../rainerscript/properties` for the category overview.
