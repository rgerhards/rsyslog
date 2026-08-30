#!/bin/bash
# Force one action-worker failure after a real ConcurrentArray claim. Exact sorted
# IDs 0..3 prove the RDY item remains owned by the action queue, crosses the
# lane-local retry barrier, and is neither lost nor duplicated while later
# claimed elements complete. The hook is one-shot and compiled out without
# ENABLE_IMDIAG, so no timing threshold forms the retry.
. ${srcdir:=.}/diag.sh init
CA_CORE=${RSYSLOG_TEST_CA_CORE:-sparseLanes}
export RSYSLOG_TEST_CA_ACTION_CONSUMER_RETRY=retry-action
export RSYSLOG_TEST_CA_ACTION_CONSUMER_RETRY_MESSAGE=msgnum:00000000

generate_conf
add_conf '
global(executionEngine="reservedBatch")
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="'$CA_CORE'"
           queue.size="32" queue.workerThreads="1" queue.dequeueBatchSize="8")
template(name="outfmt" type="string" string="%msg:F,58:2%\n")
if $msg contains "msgnum:" then
  action(name="retry-action" type="omfile" file="'$RSYSLOG_OUT_LOG'" template="outfmt"
         queue.type="ConcurrentArray" queue.concurrentCore="'$CA_CORE'"
         queue.size="16" queue.workerThreads="1" queue.dequeueBatchSize="4")
'
startup
injectmsg 0 4
wait_file_lines "$RSYSLOG_OUT_LOG" 4
shutdown_when_empty
wait_shutdown
sort "$RSYSLOG_OUT_LOG" > "$RSYSLOG_DYNNAME.sorted"
seq -f '%08g' 0 3 > "$RSYSLOG_DYNNAME.expected"
diff -u "$RSYSLOG_DYNNAME.expected" "$RSYSLOG_DYNNAME.sorted" ||
	error_exit 1 "queued action retry lost or duplicated a claimed ID"
exit_test
