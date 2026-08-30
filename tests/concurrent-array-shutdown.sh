#!/bin/bash
# Force immediate shutdown after reservedBatch has published its target span
# and purged every target binding, but before direct commit/source completion.
# The default-off pause marker makes the cancellation window deterministic.
# Cleanup must handle PUBLISHED idempotently, return the active source claim,
# unbind its source slot, and destroy both cores without a lifetime warning.
. ${srcdir:=.}/diag.sh init
require_plugin omtesting

export RS_REDIR=">$RSYSLOG_DYNNAME.rsyslog.log 2>&1"
export RSYSLOG_DEBUG="debug nostdout noprintmutexaction"
export RSYSLOG_DEBUGLOG="$RSYSLOG_DYNNAME.debug.log"
export RSYSLOG_TEST_CA_LIFECYCLE_MARKERS=1
export RSYSLOG_TEST_CA_PAUSE_AFTER_EGRESS_PUBLISH_MS=5000
generate_conf
add_conf '
global(executionEngine="reservedBatch")
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="sparseLanes"
	queue.size="128" queue.workerThreads="2" queue.dequeueBatchSize="32"
	queue.timeoutShutdown="1" queue.timeoutActionCompletion="1")
ruleset(name="target" queue.type="ConcurrentArray" queue.concurrentCore="sparseLanes" queue.size="128") {
	action(type="omfile" file="'$RSYSLOG_OUT_LOG'")
}
if $msg contains "msgnum:" then {
	call target
}
'

startup
injectmsg 0 32
# The marker is emitted after publish has purged target bindings and before the
# cancelable pause, so it proves the exact active-claim cancellation window.
wait_content 'reservedBatch test pause after target publication and binding purge' "$RSYSLOG_DEBUGLOG"
shutdown_immediate
wait_shutdown "" 30
check_not_present "Assertion" "$RSYSLOG_DYNNAME.rsyslog.log"
check_not_present "worker not stopped during shutdown" "$RSYSLOG_DYNNAME.rsyslog.log"
content_check 'ConcurrentArray worker lifecycle unbound' "$RSYSLOG_DEBUGLOG"
content_check 'ConcurrentArray core destruction complete' "$RSYSLOG_DEBUGLOG"
unset RSYSLOG_TEST_CA_LIFECYCLE_MARKERS RSYSLOG_TEST_CA_PAUSE_AFTER_EGRESS_PUBLISH_MS
exit_test
