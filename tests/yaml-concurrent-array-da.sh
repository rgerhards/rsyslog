#!/bin/bash
# Verify YAML configures the same sparseLanes DA parent as RainerScript.  A
# slowed Main consumer forces an automatic segmented child to materialize;
# the marker plus exact unordered IDs prove frontend parity and ownership.
. ${srcdir:=.}/diag.sh init
require_plugin imtcp
require_plugin omtesting
export NUMMESSAGES=128
SPOOL_DIR="${RSYSLOG_DYNNAME}.spool"

generate_conf
add_conf '
include(file="'${TESTCONF_NM}'.yaml")
input(type="imtcp" address="127.0.0.1" port="0" listenPortFileName="'${RSYSLOG_DYNNAME}'.tcpflood_port"
      ruleset="main")
'
add_yaml_conf 'modules:'
add_yaml_conf '  - load: "../plugins/imtcp/.libs/imtcp"'
add_yaml_conf '  - load: "../plugins/omtesting/.libs/omtesting"'
add_yaml_conf 'global:'
add_yaml_conf '  executionEngine: reservedBatch'
add_yaml_conf '  workDirectory: "'${SPOOL_DIR}'"'
add_yaml_conf 'mainqueue:'
add_yaml_conf '  queue.type: ConcurrentArray'
add_yaml_conf '  queue.concurrentCore: sparseLanes'
add_yaml_conf '  queue.filename: yaml-ca'
add_yaml_conf '  queue.size: 32'
add_yaml_conf '  queue.highWatermark: 8'
add_yaml_conf '  queue.lowWatermark: 4'
add_yaml_conf '  queue.dequeueBatchSize: 1'
add_yaml_conf '  queue.diskQueueType: auto'
add_yaml_conf '  queue.diskQueueIdleTimeout: -1'
add_yaml_conf 'templates:'
add_yaml_conf '  - name: outfmt'
add_yaml_conf '    type: string'
add_yaml_conf '    string: "%msg:F,58:2%\n"'
add_yaml_conf 'rulesets:'
add_yaml_conf '  - name: main'
add_yaml_conf '    script: |'
add_yaml_conf '      :omtesting:sleep 0 2000'
add_yaml_conf '      :msg, contains, "msgnum:" action(type="omfile"'
add_yaml_conf '          template="outfmt" file="'${RSYSLOG_OUT_LOG}'")'

startup
tcpflood -m "$NUMMESSAGES"
wait_file_lines "$RSYSLOG_OUT_LOG" "$NUMMESSAGES" 60
[ "$(cat "$SPOOL_DIR/yaml-ca.da-engine")" = "RSYSLOG-DA-ENGINE-V1 segmentedDisk" ] ||
	error_exit 1 "YAML ConcurrentArray DA did not select/materialize segmentedDisk"
shutdown_when_empty
wait_shutdown
sort -n "$RSYSLOG_OUT_LOG" > "${RSYSLOG_OUT_LOG}.sorted"
seq -f '%08g' 0 $((NUMMESSAGES - 1)) > "${RSYSLOG_OUT_LOG}.expected"
diff -u "${RSYSLOG_OUT_LOG}.expected" "${RSYSLOG_OUT_LOG}.sorted" ||
	error_exit 1 "YAML ConcurrentArray DA output set or multiplicity mismatch"
exit_test
