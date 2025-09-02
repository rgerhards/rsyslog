.. _prop-message-source:
.. _properties.message.source:

source
======

.. index::
   single: properties; source
   single: source

.. summary-start

Alias for hostname.

.. summary-end

This property belongs to the **Message Properties** group.

:Name: source
:Category: Message Properties
:Type: unknown
:Aliases: HOSTNAME

Description
-----------
  alias for HOSTNAME

Usage
-----
.. _properties.message.source-usage:

.. code-block:: rsyslog

   template(name="t" type="string" string="%source%")

Aliases
~~~~~~~
- HOSTNAME — alias for source

See also
--------
See :doc:`../../rainerscript/properties` for the category overview.
