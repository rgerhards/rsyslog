#!/bin/bash
# Verify discardMark before the first reservedBatch target binding. A direct
# filler remains in-flight while one source snapshot reaches the marked target;
# exact source completion, exactly one target output (the filler), one discard
# diagnostic, and clean teardown prove the inactive empty wrapper is a no-op
# rather than an INVALID publication/retry loop or stale lifecycle binding.
. ${srcdir:=.}/diag.sh init
CA_CORE=${RSYSLOG_TEST_CA_CORE:-sparseLanes}
require_plugin omtesting

export RS_REDIR=">$RSYSLOG_DYNNAME.rsyslog.log 2>&1"
export RSYSLOG_DEBUG="debug nostdout noprintmutexaction"
export RSYSLOG_DEBUGLOG="$RSYSLOG_DYNNAME.debug.log"
export RSYSLOG_TEST_CA_LIFECYCLE_MARKERS=1
export RSYSLOG_TEST_CA_MULTI_COMMAND_FILE="$RSYSLOG_DYNNAME.ca-multi.commands"
generate_conf
add_conf '
module(load="../plugins/omtesting/.libs/omtesting")
global(executionEngine="reservedBatch")
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="'$CA_CORE'"
           queue.size="16" queue.workerThreads="1" queue.dequeueBatchSize="1")
template(name="outfmt" type="string" string="%msg:F,58:2%\n")
ruleset(name="target" queue.type="ConcurrentArray" queue.concurrentCore="'$CA_CORE'"
        queue.size="8" queue.workerThreads="1" queue.dequeueBatchSize="1"
        queue.discardMark="1" queue.discardSeverity="0") {
  :msg, contains, "00000900" :omtesting:sleep 3 0
  action(type="omfile" file="'$RSYSLOG_OUT_LOG'.target" template="outfmt")
}
if $msg contains "msgnum:" then {
  call target
  action(type="omfile" file="'$RSYSLOG_OUT_LOG'.source" template="outfmt")
}
'
: >"$RSYSLOG_TEST_CA_MULTI_COMMAND_FILE"
printf '900 1 target\n' >>"$RSYSLOG_TEST_CA_MULTI_COMMAND_FILE"
startup
wait_content 'sleep(3, 0)' "$RSYSLOG_DEBUGLOG"
printf 'injectmsg 0 1\n' | $TESTTOOL_DIR/diagtalker -p"$IMDIAG_PORT" >/dev/null || error_exit $?
wait_file_lines "$RSYSLOG_OUT_LOG.source" 1
wait_file_lines "$RSYSLOG_OUT_LOG.target" 1
shutdown_when_empty
wait_shutdown

export EXPECTED=$'00000000'
RSYSLOG_OUT_LOG="$RSYSLOG_OUT_LOG.source" cmp_exact
export EXPECTED=$'00000900'
RSYSLOG_OUT_LOG="$RSYSLOG_OUT_LOG.target" cmp_exact
[ "$(grep -c 'queue nearly full (1 entries), discarded severity' "$RSYSLOG_DEBUGLOG")" -eq 1 ] || \
  error_exit 1 "reserved target discard did not occur exactly once"
content_check 'ConcurrentArray core destruction complete' "$RSYSLOG_DEBUGLOG"
unset EXPECTED RSYSLOG_TEST_CA_LIFECYCLE_MARKERS RSYSLOG_TEST_CA_MULTI_COMMAND_FILE
exit_test
