#!/bin/bash
# Force two source WTIs to reserve opposite one-slot ConcurrentArray targets,
# synchronize, and then request the other target. Exact two-message output at
# both targets proves pressure handling publishes every prior local bucket
# before blocking; flushing only the pressured bucket would deadlock or drop.
. ${srcdir:=.}/diag.sh init
generate_conf
add_conf '
global(executionEngine="reservedBatch")
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="sparseLanes"
           queue.size="16" queue.workerThreads="2" queue.workerThreadMinimumMessages="1"
           queue.dequeueBatchSize="1")
module(load="../plugins/omtesting/.libs/omtesting")
template(name="outfmt" type="string" string="%msg:F,58:2%\n")
ruleset(name="barrier") {
  :msg, contains, "msgnum:" :omtesting:barrier_error 2
}
ruleset(name="target_a" queue.type="ConcurrentArray" queue.concurrentCore="sparseLanes"
        queue.size="1" queue.timeoutEnqueue="5000") {
  action(type="omfile" file="'$RSYSLOG_OUT_LOG'.a" template="outfmt")
}
ruleset(name="target_b" queue.type="ConcurrentArray" queue.concurrentCore="sparseLanes"
        queue.size="1" queue.timeoutEnqueue="5000") {
  action(type="omfile" file="'$RSYSLOG_OUT_LOG'.b" template="outfmt")
}
if $msg contains "00000000" then {
  call target_a
  call barrier
  call target_b
} else if $msg contains "00000001" then {
  call target_b
  call barrier
  call target_a
}
'
startup
injectmsg 0 2
shutdown_when_empty
wait_shutdown
content_count_check "000000" 2 "$RSYSLOG_OUT_LOG.a"
content_count_check "000000" 2 "$RSYSLOG_OUT_LOG.b"
printf '00000000\n00000001\n' >"$RSYSLOG_DYNNAME.expected"
sort "$RSYSLOG_OUT_LOG.a" >"$RSYSLOG_DYNNAME.a.sorted"
sort "$RSYSLOG_OUT_LOG.b" >"$RSYSLOG_DYNNAME.b.sorted"
cmp "$RSYSLOG_DYNNAME.expected" "$RSYSLOG_DYNNAME.a.sorted" || error_exit 1 "cross-pressure target A multiplicity"
cmp "$RSYSLOG_DYNNAME.expected" "$RSYSLOG_DYNNAME.b.sorted" || error_exit 1 "cross-pressure target B multiplicity"
exit_test
