#!/bin/bash
# Verify reservedBatch dynamic routing across three ConcurrentArray queues.
# Each input touches target A twice around a mutation and target B indirectly;
# exact snapshot counts and values prove target-local accumulation, repeated
# target reuse, indirect destination lookup, and ownership transfer. A one-shot
# target preparation OOM on ID 1 must replay the still-reserved builder and
# retain every exact output. Shutdown success additionally proves every
# batch-scoped target binding was released before the source WTI became idle.
. ${srcdir:=.}/diag.sh init
CA_CORE=${RSYSLOG_TEST_CA_CORE:-sparseLanes}
export RSYSLOG_TEST_CA_TARGET_FAIL_CHUNK_ON_MESSAGE="msgnum:00000001:"
generate_conf
add_conf '
global(executionEngine="reservedBatch")
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="'$CA_CORE'"
           queue.size="256" queue.workerThreads="2" queue.workerThreadMinimumMessages="1")
template(name="snap" type="string" string="%msg:F,58:2%|%$!snap%\n")
ruleset(name="target_a" queue.type="ConcurrentArray" queue.concurrentCore="'$CA_CORE'"
        queue.size="128" queue.workerThreads="2" queue.workerThreadMinimumMessages="1") {
  action(type="omfile" file="'$RSYSLOG_OUT_LOG'.a" template="snap")
}
ruleset(name="target_b" queue.type="ConcurrentArray" queue.concurrentCore="'$CA_CORE'"
        queue.size="128" queue.workerThreads="2" queue.workerThreadMinimumMessages="1") {
  action(type="omfile" file="'$RSYSLOG_OUT_LOG'.b" template="snap")
}
if $msg contains "msgnum:" then {
  set $!snap = "first";
  call target_a
  set $!snap = "second";
  call target_a
  set $.target = "target_b";
  call_indirect $.target;
  action(type="omfile" file="'$RSYSLOG_OUT_LOG'.c" template="snap")
}
'
startup
injectmsg 0 7
wait_file_lines "$RSYSLOG_OUT_LOG.a" 14
issue_HUP
injectmsg 7 7
shutdown_when_empty
wait_shutdown
: >"$RSYSLOG_DYNNAME.expected.a"
: >"$RSYSLOG_DYNNAME.expected.second"
for id in $(seq 0 13); do
	printf '%08d|first\n%08d|second\n' "$id" "$id" >>"$RSYSLOG_DYNNAME.expected.a"
	printf '%08d|second\n' "$id" >>"$RSYSLOG_DYNNAME.expected.second"
done
sort "$RSYSLOG_DYNNAME.expected.a" >"$RSYSLOG_DYNNAME.expected.a.sorted"
sort "$RSYSLOG_DYNNAME.expected.second" >"$RSYSLOG_DYNNAME.expected.second.sorted"
sort "$RSYSLOG_OUT_LOG.a" >"$RSYSLOG_DYNNAME.actual.a.sorted"
sort "$RSYSLOG_OUT_LOG.b" >"$RSYSLOG_DYNNAME.actual.b.sorted"
sort "$RSYSLOG_OUT_LOG.c" >"$RSYSLOG_DYNNAME.actual.c.sorted"
cmp "$RSYSLOG_DYNNAME.expected.a.sorted" "$RSYSLOG_DYNNAME.actual.a.sorted" || \
	error_exit 1 "target A per-ID snapshot multiplicity mismatch"
cmp "$RSYSLOG_DYNNAME.expected.second.sorted" "$RSYSLOG_DYNNAME.actual.b.sorted" || \
	error_exit 1 "target B per-ID snapshot multiplicity mismatch"
cmp "$RSYSLOG_DYNNAME.expected.second.sorted" "$RSYSLOG_DYNNAME.actual.c.sorted" || \
	error_exit 1 "direct action C per-ID snapshot multiplicity mismatch"
unset RSYSLOG_TEST_CA_TARGET_FAIL_CHUNK_ON_MESSAGE
exit_test
