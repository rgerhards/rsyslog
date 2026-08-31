#!/bin/bash
# Verify a persistent final-publish preparation failure is not normalized into
# source success. The test-only hook rejects both the initial prepare and its
# immediate retry once; the source claim must return RDY, replay, then publish
# exactly one target identity after the hook disarms. One RDY diagnostic and
# exact output prove retryability without ownership loss or duplicate publish.
. ${srcdir:=.}/diag.sh init
CA_CORE=${RSYSLOG_TEST_CA_CORE:-sparseLanes}

export RS_REDIR=">$RSYSLOG_DYNNAME.rsyslog.log 2>&1"
export RSYSLOG_DEBUG="debug nostdout noprintmutexaction"
export RSYSLOG_DEBUGLOG="$RSYSLOG_DYNNAME.debug.log"
export RSYSLOG_TEST_CA_TARGET_FAIL_CHUNK_ON_MESSAGE="msgnum:00000000:"
export RSYSLOG_TEST_CA_TARGET_FAIL_CHUNK_COUNT=2
export RSYSLOG_TEST_CA_LIFECYCLE_MARKERS=1
generate_conf
add_conf '
global(executionEngine="reservedBatch")
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="'$CA_CORE'"
           queue.size="16" queue.workerThreads="1" queue.dequeueBatchSize="1")
template(name="outfmt" type="string" string="%msg:F,58:2%\n")
ruleset(name="target" queue.type="ConcurrentArray" queue.concurrentCore="'$CA_CORE'"
        queue.size="16" queue.workerThreads="1") {
  action(type="omfile" file="'$RSYSLOG_OUT_LOG'" template="outfmt")
}
if $msg contains "msgnum:" then call target
'
startup
injectmsg 0 1
wait_content 'reservedBatch egress error .* restored 1 source messages to RDY' "$RSYSLOG_DEBUGLOG"
issue_HUP
wait_file_lines "$RSYSLOG_OUT_LOG" 1
shutdown_when_empty
wait_shutdown
export EXPECTED=$'00000000'
cmp_exact
[ "$(grep -c 'restored 1 source messages to RDY' "$RSYSLOG_DEBUGLOG")" -eq 1 ] || \
  error_exit 1 "persistent target publication failure did not retry source exactly once"

# Repeat the same persistent failure while flipping the mutable selector after
# ProcessBatch. The batch-local preserve marker must still return the source
# RDY; the replay may use the newly selected engine but cannot lose the branch.
rm -f "$RSYSLOG_OUT_LOG" "$RSYSLOG_DEBUGLOG"
export RSYSLOG_TEST_CA_TARGET_FAIL_CHUNK_ON_MESSAGE="msgnum:00000001:"
export RSYSLOG_TEST_CA_FLIP_ENGINE_AFTER_BATCH_MESSAGE="msgnum:00000001:"
export RSYSLOG_TEST_CA_FLIP_ENGINE_AFTER_BATCH_VALUE=0
generate_conf
add_conf '
global(executionEngine="reservedBatch")
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="'$CA_CORE'"
           queue.size="16" queue.workerThreads="1" queue.dequeueBatchSize="1")
template(name="outfmt" type="string" string="%msg:F,58:2%\n")
ruleset(name="target" queue.type="ConcurrentArray" queue.concurrentCore="'$CA_CORE'"
        queue.size="16" queue.workerThreads="1") {
  action(type="omfile" file="'$RSYSLOG_OUT_LOG'" template="outfmt")
}
if $msg contains "msgnum:" then call target
'
startup
injectmsg 1 1
wait_content 'reservedBatch egress error .* restored 1 source messages to RDY' "$RSYSLOG_DEBUGLOG"
wait_content 'changed mutable executionEngine to 0 after batch; captured completion policy 1' "$RSYSLOG_DEBUGLOG"
issue_HUP
wait_file_lines "$RSYSLOG_OUT_LOG" 1
shutdown_when_empty
wait_shutdown
export EXPECTED=$'00000001'
cmp_exact

# Inverse race: a legacy invocation keeps its legacy blanket-completion policy
# even when the mutable selector changes to reservedBatch after ProcessBatch.
rm -f "$RSYSLOG_OUT_LOG" "$RSYSLOG_DEBUGLOG"
unset RSYSLOG_TEST_CA_TARGET_FAIL_CHUNK_ON_MESSAGE RSYSLOG_TEST_CA_TARGET_FAIL_CHUNK_COUNT
export RSYSLOG_TEST_CA_FLIP_ENGINE_AFTER_BATCH_MESSAGE="msgnum:00000003:"
export RSYSLOG_TEST_CA_FLIP_ENGINE_AFTER_BATCH_VALUE=1
generate_conf
add_conf '
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="'$CA_CORE'"
           queue.size="16" queue.workerThreads="1" queue.dequeueBatchSize="1")
template(name="outfmt" type="string" string="%msg:F,58:2%\n")
if $msg contains "msgnum:" then action(type="omfile" file="'$RSYSLOG_OUT_LOG'" template="outfmt")
'
startup
injectmsg 3 1
wait_content 'changed mutable executionEngine to 1 after batch; captured completion policy 0' "$RSYSLOG_DEBUGLOG"
issue_HUP
wait_file_lines "$RSYSLOG_OUT_LOG" 1
shutdown_when_empty
wait_shutdown
export EXPECTED=$'00000003'
cmp_exact

# Normal reserved control flow is terminal, not retryable. `call target; stop`
# must publish one branch and commit the source once instead of replaying it.
rm -f "$RSYSLOG_OUT_LOG" "$RSYSLOG_DEBUGLOG"
unset RSYSLOG_TEST_CA_FLIP_ENGINE_AFTER_BATCH_MESSAGE RSYSLOG_TEST_CA_FLIP_ENGINE_AFTER_BATCH_VALUE
generate_conf
add_conf '
global(executionEngine="reservedBatch")
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="'$CA_CORE'"
           queue.size="16" queue.workerThreads="1" queue.dequeueBatchSize="1")
template(name="outfmt" type="string" string="%msg:F,58:2%\n")
ruleset(name="target" queue.type="ConcurrentArray" queue.concurrentCore="'$CA_CORE'"
        queue.size="16" queue.workerThreads="1") {
  action(type="omfile" file="'$RSYSLOG_OUT_LOG'" template="outfmt")
}
if $msg contains "msgnum:" then {
  call target
  stop
}
'
startup
injectmsg 4 1
wait_file_lines "$RSYSLOG_OUT_LOG" 1
shutdown_when_empty
wait_shutdown
export EXPECTED=$'00000004'
cmp_exact

# Conversely, legacy execution keeps historical blanket source completion on
# a genuine non-suspended script error. The unresolved lookup-table reload
# returns RS_RET_NONE at runtime; the direct output before it must appear once,
# even when the mutable selector flips after the batch. The captured-policy
# diagnostic and exact one output prove that a marker regression cannot replay
# the legacy source.
rm -f "$RSYSLOG_OUT_LOG" "$RSYSLOG_DEBUGLOG"
export RSYSLOG_TEST_CA_FLIP_ENGINE_AFTER_BATCH_MESSAGE="msgnum:00000005:"
export RSYSLOG_TEST_CA_FLIP_ENGINE_AFTER_BATCH_VALUE=1
generate_conf
add_conf '
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="'$CA_CORE'"
           queue.size="16" queue.workerThreads="1" queue.dequeueBatchSize="1")
template(name="outfmt" type="string" string="%msg:F,58:2%\n")
if $msg contains "msgnum:" then {
  action(type="omfile" file="'$RSYSLOG_OUT_LOG'" template="outfmt")
  reload_lookup_table("does-not-exist");
}
'
startup
injectmsg 5 1
wait_content 'changed mutable executionEngine to 1 after batch; captured completion policy 0' "$RSYSLOG_DEBUGLOG"
wait_file_lines "$RSYSLOG_OUT_LOG" 1
shutdown_when_empty
wait_shutdown
export EXPECTED=$'00000005'
cmp_exact

unset EXPECTED RSYSLOG_TEST_CA_FLIP_ENGINE_AFTER_BATCH_MESSAGE RSYSLOG_TEST_CA_FLIP_ENGINE_AFTER_BATCH_VALUE \
  RSYSLOG_TEST_CA_LIFECYCLE_MARKERS RSYSLOG_TEST_CA_TARGET_FAIL_CHUNK_ON_MESSAGE \
  RSYSLOG_TEST_CA_TARGET_FAIL_CHUNK_COUNT
exit_test
