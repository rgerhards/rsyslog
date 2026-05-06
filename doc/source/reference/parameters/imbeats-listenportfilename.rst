.. _param-imbeats-listenportfilename:
.. _imbeats.parameter.input.listenportfilename:

listenPortFileName
==================

.. meta::
   :description: Port file for dynamic imbeats listeners.
   :keywords: rsyslog, imbeats, listenPortFileName

.. index::
   single: imbeats; listenPortFileName
   single: listenPortFileName

.. summary-start

Write the actual bound port to a file when the imbeats listener uses port ``0``.

.. summary-end

This parameter applies to :doc:`../../configuration/modules/imbeats`.

:Name: listenPortFileName
:Scope: input
:Type: string
:Default: input=none
:Required?: no
:Introduced: 8.2604.0

Description
-----------
Write the actual bound port to a file when the imbeats listener uses port ``0``.

Input usage
-----------
.. _param-imbeats-input-listenportfilename:
.. _imbeats.parameter.input.listenportfilename-usage:

.. code-block:: rsyslog

   input(type="imbeats" port="5044" port="0" listenPortFileName="/tmp/imbeats.port")

See also
--------
See also :doc:`../../configuration/modules/imbeats`.
