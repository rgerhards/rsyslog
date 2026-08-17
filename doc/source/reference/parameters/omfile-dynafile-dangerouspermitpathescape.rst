.. _param-omfile-dynafile-dangerouspermitpathescape:
.. _omfile.parameter.action.dynafile-dangerouspermitpathescape:

dynafile.dangerousPermitPathEscape
==================================

.. meta::
   :description: Permit omfile dynafile paths to escape the configured base path.
   :keywords: rsyslog, omfile, dynafile, path traversal, security, dangerous

.. index::
   single: omfile; dynafile.dangerousPermitPathEscape
   single: dynafile.dangerousPermitPathEscape

.. summary-start

Dangerous fallback option that permits rendered dynafile paths to escape
the fixed path prefix configured in the dynafile template.

.. summary-end

This parameter applies to :doc:`../../configuration/modules/omfile`.

:Name: dynafile.dangerousPermitPathEscape
:Scope: action
:Type: boolean
:Default: off
:Required?: no
:Introduced: not specified

Description
-----------

By default, omfile validates rendered :ref:`param-omfile-dynafile` paths
against the fixed path prefix configured in the dynafile template. For
example, a dynafile template that starts with ``/var/log/`` must render
paths below that configured base. Message-derived fields such as
``%HOSTNAME%`` must not use ``..`` components to escape that location.

Set this parameter to ``on`` only as a temporary compatibility fallback
for the one affected action in a trusted legacy configuration. Enabling it allows
message-derived dynafile names to escape the configured path prefix. If
untrusted data can reach the dynafile template, rsyslog may create or
overwrite any file that the rsyslog process user is allowed to write.
Only operating-system permissions, mandatory access controls, mount
options, and similar external controls remain as protection.

This also restores the historical behavior for opaque legacy dynafile
templates that render absolute paths or relative paths containing leading
``..`` components. Without this explicit opt-in, those paths are rejected by
the default fallback guard.

Before enabling this option, reconsider the use case. Prefer changing the
dynafile template so that untrusted fields cannot select parent
directories or absolute paths. For network-sourced fields, keep this
option disabled.

Action usage
------------

.. _param-omfile-action-dynafile-dangerouspermitpathescape:
.. code-block:: rsyslog

   action(type="omfile"
          dynafile="legacyDynFile"
          dynafile.dangerousPermitPathEscape="on")

See also
--------

See also :doc:`../../configuration/modules/omfile`,
:doc:`omfile-dynafile`, and
:doc:`omfile-dynafile-restricttemplatetype`.
