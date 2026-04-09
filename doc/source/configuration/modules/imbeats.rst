******************************
imbeats: Beats v2 input module
******************************

.. meta::
   :description: Receive Elastic Beats data in rsyslog via Lumberjack v2 over TCP or TLS.
   :keywords: rsyslog, imbeats, beats, lumberjack, elastic, input, tcp, tls

.. summary-start
imbeats receives Elastic Beats events via Lumberjack protocol v2 over TCP or
TLS, keeps the original JSON payload in ``msg``, maps decoded event fields into
the top-level structured tree ``$!``, and stores transport/protocol metadata
under ``$!metadata!imbeats``.
.. summary-end

===========================  ===========================================================================
**Module Name:**             **imbeats**
**Author:**                  **Adiscon and contributors**
**Available since:**         **8.2604.0**
===========================  ===========================================================================


Purpose
=======

``imbeats`` accepts Elastic Beats traffic that uses the Logstash-style
Lumberjack v2 protocol. The module reuses rsyslog's ``netstrm`` transport
subsystem, so it can listen via plain TCP or the configured TLS stream driver.

The first implementation supports:

- Lumberjack v2 only
- ``W`` window frames
- ``J`` JSON event frames
- ``C`` compressed frames
- cumulative ``A`` acknowledgements

The first implementation intentionally optimizes the internal event shape for
common Elasticsearch-oriented pipelines:

- ``msg`` keeps the original JSON payload
- decoded Beat event fields are added under top-level ``$!``
- transport and protocol metadata is stored under ``$!metadata!imbeats``

This default may be revisited later. A user-selectable representation mode is
not part of the initial release.


Module Parameters
=================

Currently none.


Input Parameters
================

.. list-table::
   :widths: 34 66
   :header-rows: 1

   * - Parameter
     - Summary
   * - :ref:`param-imbeats-address`
     - .. include:: ../../reference/parameters/imbeats-address.rst
        :start-after: .. summary-start
        :end-before: .. summary-end
   * - :ref:`param-imbeats-gnutlsprioritystring`
     - .. include:: ../../reference/parameters/imbeats-gnutlsprioritystring.rst
        :start-after: .. summary-start
        :end-before: .. summary-end
   * - :ref:`param-imbeats-keepalive`
     - .. include:: ../../reference/parameters/imbeats-keepalive.rst
        :start-after: .. summary-start
        :end-before: .. summary-end
   * - :ref:`param-imbeats-keepalive-interval`
     - .. include:: ../../reference/parameters/imbeats-keepalive-interval.rst
        :start-after: .. summary-start
        :end-before: .. summary-end
   * - :ref:`param-imbeats-keepalive-probes`
     - .. include:: ../../reference/parameters/imbeats-keepalive-probes.rst
        :start-after: .. summary-start
        :end-before: .. summary-end
   * - :ref:`param-imbeats-keepalive-time`
     - .. include:: ../../reference/parameters/imbeats-keepalive-time.rst
        :start-after: .. summary-start
        :end-before: .. summary-end
   * - :ref:`param-imbeats-listenportfilename`
     - .. include:: ../../reference/parameters/imbeats-listenportfilename.rst
        :start-after: .. summary-start
        :end-before: .. summary-end
   * - :ref:`param-imbeats-name`
     - .. include:: ../../reference/parameters/imbeats-name.rst
        :start-after: .. summary-start
        :end-before: .. summary-end
   * - :ref:`param-imbeats-networknamespace`
     - .. include:: ../../reference/parameters/imbeats-networknamespace.rst
        :start-after: .. summary-start
        :end-before: .. summary-end
   * - :ref:`param-imbeats-permittedpeer`
     - .. include:: ../../reference/parameters/imbeats-permittedpeer.rst
        :start-after: .. summary-start
        :end-before: .. summary-end
   * - :ref:`param-imbeats-port`
     - .. include:: ../../reference/parameters/imbeats-port.rst
        :start-after: .. summary-start
        :end-before: .. summary-end
   * - :ref:`param-imbeats-ruleset`
     - .. include:: ../../reference/parameters/imbeats-ruleset.rst
        :start-after: .. summary-start
        :end-before: .. summary-end
   * - :ref:`param-imbeats-streamdriver-authmode`
     - .. include:: ../../reference/parameters/imbeats-streamdriver-authmode.rst
        :start-after: .. summary-start
        :end-before: .. summary-end
   * - :ref:`param-imbeats-streamdriver-cafile`
     - .. include:: ../../reference/parameters/imbeats-streamdriver-cafile.rst
        :start-after: .. summary-start
        :end-before: .. summary-end
   * - :ref:`param-imbeats-streamdriver-certfile`
     - .. include:: ../../reference/parameters/imbeats-streamdriver-certfile.rst
        :start-after: .. summary-start
        :end-before: .. summary-end
   * - :ref:`param-imbeats-streamdriver-checkextendedkeypurpose`
     - .. include:: ../../reference/parameters/imbeats-streamdriver-checkextendedkeypurpose.rst
        :start-after: .. summary-start
        :end-before: .. summary-end
   * - :ref:`param-imbeats-streamdriver-crlfile`
     - .. include:: ../../reference/parameters/imbeats-streamdriver-crlfile.rst
        :start-after: .. summary-start
        :end-before: .. summary-end
   * - :ref:`param-imbeats-streamdriver-keyfile`
     - .. include:: ../../reference/parameters/imbeats-streamdriver-keyfile.rst
        :start-after: .. summary-start
        :end-before: .. summary-end
   * - :ref:`param-imbeats-streamdriver-mode`
     - .. include:: ../../reference/parameters/imbeats-streamdriver-mode.rst
        :start-after: .. summary-start
        :end-before: .. summary-end
   * - :ref:`param-imbeats-streamdriver-name`
     - .. include:: ../../reference/parameters/imbeats-streamdriver-name.rst
        :start-after: .. summary-start
        :end-before: .. summary-end
   * - :ref:`param-imbeats-streamdriver-permitexpiredcerts`
     - .. include:: ../../reference/parameters/imbeats-streamdriver-permitexpiredcerts.rst
        :start-after: .. summary-start
        :end-before: .. summary-end
   * - :ref:`param-imbeats-streamdriver-prioritizesan`
     - .. include:: ../../reference/parameters/imbeats-streamdriver-prioritizesan.rst
        :start-after: .. summary-start
        :end-before: .. summary-end
   * - :ref:`param-imbeats-streamdriver-tlsrevocationcheck`
     - .. include:: ../../reference/parameters/imbeats-streamdriver-tlsrevocationcheck.rst
        :start-after: .. summary-start
        :end-before: .. summary-end
   * - :ref:`param-imbeats-streamdriver-tlsverifydepth`
     - .. include:: ../../reference/parameters/imbeats-streamdriver-tlsverifydepth.rst
        :start-after: .. summary-start
        :end-before: .. summary-end


Examples
========

RainerScript
------------

.. code-block:: none

   module(load="imbeats")

   input(type="imbeats"
         port="5044"
         ruleset="beats_to_es"
         streamdriver.name="gtls"
         streamdriver.mode="1"
         streamdriver.authmode="x509/name"
         streamdriver.cafile="/etc/rsyslog.d/ca.pem"
         streamdriver.certfile="/etc/rsyslog.d/server-cert.pem"
         streamdriver.keyfile="/etc/rsyslog.d/server-key.pem")

   ruleset(name="beats_to_es") {
     action(type="omfile" file="/var/log/imbeats-debug.log")
   }

YAML
----

.. code-block:: yaml

   version: 2
   modules:
     - load: imbeats

   inputs:
     - type: imbeats
       port: "5044"
       ruleset: beats_to_es
       streamdriver.name: gtls
       streamdriver.mode: 1
       streamdriver.authmode: x509/name
       streamdriver.cafile: /etc/rsyslog.d/ca.pem
       streamdriver.certfile: /etc/rsyslog.d/server-cert.pem
       streamdriver.keyfile: /etc/rsyslog.d/server-key.pem

   rulesets:
     - name: beats_to_es
       script: |
         action(type="omfile" file="/var/log/imbeats-debug.log")


Statistic Counters
==================

The module exposes these ``impstats`` counters:

- ``connections.accepted``
- ``connections.closed``
- ``protocol_errors``
- ``batches.received``
- ``batches.acked``
- ``events.received``
- ``events.submitted``
- ``events.failed``
- ``compressed_frames``
- ``json_decode_failures``
- ``ack_failures``


.. toctree::
   :hidden:

   ../../reference/parameters/imbeats-address
   ../../reference/parameters/imbeats-gnutlsprioritystring
   ../../reference/parameters/imbeats-keepalive
   ../../reference/parameters/imbeats-keepalive-interval
   ../../reference/parameters/imbeats-keepalive-probes
   ../../reference/parameters/imbeats-keepalive-time
   ../../reference/parameters/imbeats-listenportfilename
   ../../reference/parameters/imbeats-name
   ../../reference/parameters/imbeats-networknamespace
   ../../reference/parameters/imbeats-permittedpeer
   ../../reference/parameters/imbeats-port
   ../../reference/parameters/imbeats-ruleset
   ../../reference/parameters/imbeats-streamdriver-authmode
   ../../reference/parameters/imbeats-streamdriver-cafile
   ../../reference/parameters/imbeats-streamdriver-certfile
   ../../reference/parameters/imbeats-streamdriver-checkextendedkeypurpose
   ../../reference/parameters/imbeats-streamdriver-crlfile
   ../../reference/parameters/imbeats-streamdriver-keyfile
   ../../reference/parameters/imbeats-streamdriver-mode
   ../../reference/parameters/imbeats-streamdriver-name
   ../../reference/parameters/imbeats-streamdriver-permitexpiredcerts
   ../../reference/parameters/imbeats-streamdriver-prioritizesan
   ../../reference/parameters/imbeats-streamdriver-tlsrevocationcheck
   ../../reference/parameters/imbeats-streamdriver-tlsverifydepth
