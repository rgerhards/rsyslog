#!/bin/bash
# Verify target wrappers are strictly source-batch scoped. Three independently
# drained source batches touch A+B, A-only, then (after HUP) B-only. Exact A
# identities 0,1 and B identities 0,2 prove dormant buckets neither survive
# nor return INVALID, and the HUP boundary exercises callback/reopen cleanup.
. ${srcdir:=.}/diag.sh init
CA_CORE=${RSYSLOG_TEST_CA_CORE:-sparseLanes}

generate_conf
add_conf '
global(executionEngine="reservedBatch")
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="'$CA_CORE'"
           queue.size="16" queue.workerThreads="1" queue.dequeueBatchSize="1")
template(name="outfmt" type="string" string="%msg:F,58:2%\n")
ruleset(name="target_a" queue.type="ConcurrentArray" queue.concurrentCore="'$CA_CORE'" queue.size="16") {
  action(type="omfile" file="'$RSYSLOG_OUT_LOG'.a" template="outfmt")
}
ruleset(name="target_b" queue.type="ConcurrentArray" queue.concurrentCore="'$CA_CORE'" queue.size="16") {
  action(type="omfile" file="'$RSYSLOG_OUT_LOG'.b" template="outfmt")
}
if $msg contains "00000000" then {
  call target_a
  call target_b
} else if $msg contains "00000001" then {
  call target_a
} else if $msg contains "00000002" then {
  call target_b
}
'
startup
injectmsg 0 1
wait_file_lines "$RSYSLOG_OUT_LOG.a" 1
wait_file_lines "$RSYSLOG_OUT_LOG.b" 1
injectmsg 1 1
wait_file_lines "$RSYSLOG_OUT_LOG.a" 2
issue_HUP
injectmsg 2 1
wait_file_lines "$RSYSLOG_OUT_LOG.b" 2
shutdown_when_empty
wait_shutdown
export EXPECTED=$'00000000\n00000001'
RSYSLOG_OUT_LOG="$RSYSLOG_OUT_LOG.a" cmp_exact
export EXPECTED=$'00000000\n00000002'
RSYSLOG_OUT_LOG="$RSYSLOG_OUT_LOG.b" cmp_exact
unset EXPECTED
exit_test
