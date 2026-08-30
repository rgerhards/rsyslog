#!/bin/bash
# Verify YAML reaches the same queue parameter backend as RainerScript for an
# opt-in ConcurrentArray Main queue and a reservedBatch queued target. Exact
# sequence output is the runtime oracle; parser-only acceptance would not prove
# that the selected cores ran. A YAML queued-action negative proves that the
# action core cannot be enabled without the reservedBatch execution engine.
. ${srcdir:=.}/diag.sh init
require_plugin imtcp
export NUMMESSAGES=32

generate_conf
add_conf '
include(file="'${TESTCONF_NM}'.yaml")
input(type="imtcp" address="127.0.0.1" port="0" listenPortFileName="'${RSYSLOG_DYNNAME}'.tcpflood_port"
      ruleset="main")
'
rm -f "${TESTCONF_NM}.yaml"
add_yaml_conf 'modules:'
add_yaml_conf '  - load: "../plugins/imtcp/.libs/imtcp"'
add_yaml_conf 'mainqueue:'
add_yaml_conf '  queue.type: ConcurrentArray'
add_yaml_conf '  queue.concurrentCore: sparseLanes'
add_yaml_conf '  queue.workerThreads: 4'
add_yaml_conf 'templates:'
add_yaml_conf '  - name: outfmt'
add_yaml_conf '    type: string'
add_yaml_conf '    string: "%msg:F,58:2%\n"'
add_yaml_conf 'rulesets:'
add_yaml_conf '  - name: main'
add_yaml_conf '    script: |'
add_yaml_conf '      :msg, contains, "msgnum:" action(type="omfile"'
add_yaml_conf '          template="outfmt" file="'${RSYSLOG_OUT_LOG}'")'

startup
tcpflood -m "$NUMMESSAGES"
shutdown_when_empty
wait_shutdown
seq_check 0 31

rm -f "$RSYSLOG_OUT_LOG" "${TESTCONF_NM}.yaml"
export NUMMESSAGES=16
generate_conf
add_conf '
include(file="'${TESTCONF_NM}'.yaml")
input(type="imtcp" address="127.0.0.1" port="0" listenPortFileName="'${RSYSLOG_DYNNAME}'.tcpflood_port"
      ruleset="main")
'
add_yaml_conf 'modules:'
add_yaml_conf '  - load: "../plugins/imtcp/.libs/imtcp"'
add_yaml_conf 'global:'
add_yaml_conf '  executionEngine: reservedBatch'
add_yaml_conf 'mainqueue:'
add_yaml_conf '  queue.type: ConcurrentArray'
add_yaml_conf '  queue.concurrentCore: sparseLanes'
add_yaml_conf '  queue.workerThreads: 2'
add_yaml_conf 'templates:'
add_yaml_conf '  - name: outfmt'
add_yaml_conf '    type: string'
add_yaml_conf '    string: "%msg:F,58:2%\n"'
add_yaml_conf 'rulesets:'
add_yaml_conf '  - name: target'
add_yaml_conf '    queue.type: ConcurrentArray'
add_yaml_conf '    queue.concurrentCore: sparseLanes'
add_yaml_conf '    script: |'
add_yaml_conf '      action(type="omfile" template="outfmt" file="'${RSYSLOG_OUT_LOG}'")'
add_yaml_conf '  - name: main'
add_yaml_conf '    script: |'
add_yaml_conf '      if $msg contains "msgnum:" then call target'
startup
tcpflood -m "$NUMMESSAGES"
shutdown_when_empty
wait_shutdown
seq_check 0 15

rm -f "${TESTCONF_NM}.yaml"
generate_conf
add_conf 'include(file="'${TESTCONF_NM}'.yaml")'
add_yaml_conf 'global:'
add_yaml_conf '  abortOnUncleanConfig: on'
add_yaml_conf 'mainqueue:'
add_yaml_conf '  queue.type: ConcurrentArray'
add_yaml_conf '  queue.concurrentCore: sparseLanes'
add_yaml_conf 'rulesets:'
add_yaml_conf '  - name: main'
add_yaml_conf '    script: |'
add_yaml_conf '      action(type="omfile" file="'${RSYSLOG_OUT_LOG}'" queue.type="ConcurrentArray"'
add_yaml_conf '          queue.concurrentCore="sparseLanes")'
yaml_error="$RSYSLOG_DYNNAME.yaml-action-error.log"
if ../tools/rsyslogd -C -N1 -f"${TESTCONF_NM}.conf" -M"$RSYSLOG_MODDIR" >"$yaml_error" 2>&1; then
	error_exit 1 "YAML ConcurrentArray queued action unexpectedly passed"
fi
grep -Fq "queue.type='ConcurrentArray' requires global executionEngine='reservedBatch'" "$yaml_error" || {
	cat "$yaml_error"
	error_exit 1 "missing YAML ConcurrentArray queued-action diagnostic"
}
exit_test
