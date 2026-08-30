#!/bin/bash
# Hold an explicit ConcurrentArray action worker only after it owns a real
# claim, then request immediate shutdown. The held marker is the deterministic
# in-flight oracle; the standard proper-termination marker proves cleanup
# returned the claim, unbound the worker, joined it, and destroyed the action
# core without leaving a live binding. A one-second action-completion timeout
# bounds the deliberate blocked callback; no fixed sleep controls the race.
. ${srcdir:=.}/diag.sh init
export RSYSLOG_TEST_CA_ACTION_CLAIM=held-action
export RSYSLOG_TEST_CA_ACTION_CLAIM_GATE="$RSYSLOG_DYNNAME.claim-gate"
export RSYSLOG_TEST_CA_ACTION_CLAIM_HELD="$RSYSLOG_DYNNAME.claim-held"
: > "$RSYSLOG_TEST_CA_ACTION_CLAIM_GATE"

generate_conf
add_conf '
global(executionEngine="reservedBatch")
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="sparseLanes"
           queue.size="16" queue.workerThreads="1" queue.dequeueBatchSize="4")
if $msg contains "msgnum:" then
  action(name="held-action" type="omfile" file="'$RSYSLOG_OUT_LOG'"
         queue.type="ConcurrentArray" queue.concurrentCore="sparseLanes"
         queue.size="16" queue.workerThreads="1" queue.dequeueBatchSize="1"
         queue.timeoutActionCompletion="1000" queue.timeoutShutdown="2000")
'
startup
injectmsg 0 1
wait_file_exists "$RSYSLOG_TEST_CA_ACTION_CLAIM_HELD"
shutdown_immediate
wait_shutdown "" 20
rm -f "$RSYSLOG_TEST_CA_ACTION_CLAIM_GATE" "$RSYSLOG_TEST_CA_ACTION_CLAIM_HELD"
exit_test
