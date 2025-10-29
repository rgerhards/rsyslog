#!/bin/bash
## yaml-basic.sh - basic YAML parser check
##
## Runs rsyslogd with a YAML configuration to ensure that the sample
## file loads a module and adds an input.

set -e
srcdir="$(cd "$(dirname "$0")" && pwd)"
cd "$srcdir"
../tools/rsyslogd -N1 -n -f conf_yaml_poc.yml -i rsyslogd.pid -M../runtime/.libs:../plugins/imtcp/.libs:../.libs >test.log 2>&1 || true
grep -F "yaml: module imtcp loaded" test.log
grep -F "yaml: input imtcp added" test.log
