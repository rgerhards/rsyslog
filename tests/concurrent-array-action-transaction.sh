#!/bin/bash
# Form one exact named-source claim behind a compiled-out worker-advice gate, then
# verify one independent transactional queued-action callback stream for 8192
# and 65536 messages. The helper validates every contiguous ID and emits a
# compact exact BEGIN/message/COMMIT/EOF summary, avoiding a 65K-line oracle.
# A final three-message case requires the queued action's core-publication
# marker to exist when the Direct transaction commits, proving target
# publication precedes Direct commit. File waits are failure guards only; the
# worker gate and an impstats enqueue-count predicate, never time, form each
# batch. The 30-second polling bound only guards a stalled daemon on a loaded
# test host.
if [ "$1" != "--case" ]; then
	for count in 8192 65536; do
		RSTB_CA_ACTION_TX_COUNT=$count "$0" --case || exit $?
	done
	RSTB_CA_ACTION_TX_MODE=ordering "$0" --case || exit $?
	exit 0
fi
. ${srcdir:=.}/diag.sh init
CA_CORE=${RSYSLOG_TEST_CA_CORE:-sparseLanes}
require_plugin omprog
count=${RSTB_CA_ACTION_TX_COUNT:-3}
export RSYSLOG_TEST_CA_WORKER_GATE_QUEUE=source
export RSYSLOG_TEST_CA_WORKER_GATE="$RSYSLOG_DYNNAME.worker-gate"
export RSYSLOG_TEST_CA_WORKER_GATE_COUNT=$count
export RSYSLOG_CA_ACTION_TX_RESULT="$PWD/$RSYSLOG_DYNNAME.tx-result"
export RSYSLOG_CA_ACTION_TX_SUMMARY="$PWD/$RSYSLOG_DYNNAME.tx-summary"
export STATSFILE="$RSYSLOG_DYNNAME.stats"
: > "$RSYSLOG_TEST_CA_WORKER_GATE"

if [ "$RSTB_CA_ACTION_TX_MODE" = ordering ]; then
	export RSYSLOG_CA_ACTION_TX_TRANSCRIPT="$PWD/$RSYSLOG_DYNNAME.tx-transcript"
	export RSYSLOG_TEST_CA_ACTION_PUBLICATION_ACTION=queued-before-direct
	export RSYSLOG_TEST_CA_ACTION_PUBLICATION_MARK="$PWD/$RSYSLOG_DYNNAME.action-published"
	queued_action='action(name="queued-before-direct" type="omfile" file="'$RSYSLOG_OUT_LOG'" template="outfmt"
         queue.type="ConcurrentArray" queue.concurrentCore="'$CA_CORE'"
         queue.size="16" queue.workerThreads="1" queue.dequeueBatchSize="3")'
	expected_transcript='BEGIN
MSG msgnum:00000000:
MSG msgnum:00000001:
MSG msgnum:00000002:
COMMIT publication=present'
else
	queued_action='action(name="tx-action" type="omprog"
         binary="'$srcdir'/testsuites/concurrent-array-action-transaction-bin.py"
         template="outfmt" confirmMessages="on" useTransactions="on"
         beginTransactionMark="BEGIN TRANSACTION" commitTransactionMark="COMMIT TRANSACTION"
         queue.type="ConcurrentArray" queue.concurrentCore="'$CA_CORE'"
         queue.size="'$count'" queue.workerThreads="1" queue.dequeueBatchSize="'$count'")'
fi

generate_conf
add_conf '
global(executionEngine="reservedBatch")
module(load="../plugins/omprog/.libs/omprog")
module(load="../plugins/impstats/.libs/impstats" interval="1" log.syslog="off"
       resetCounters="off" log.file="'$STATSFILE'")
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="'$CA_CORE'"
           queue.size="'$((count + 1))'" queue.workerThreads="1" queue.dequeueBatchSize="'$count'")
template(name="outfmt" type="string" string="%msg%\n")
ruleset(name="source" queue.type="ConcurrentArray" queue.concurrentCore="'$CA_CORE'"
        queue.size="'$((count + 1))'" queue.workerThreads="1" queue.dequeueBatchSize="'$count'") {
  if $msg contains "msgnum:0" then {
    '"$queued_action"'
'"$([ "$RSTB_CA_ACTION_TX_MODE" = ordering ] && printf '%s' '
    action(name="direct-transaction" type="omprog"
           binary="'"$srcdir"'/testsuites/concurrent-array-action-transaction-bin.py"
           template="outfmt" confirmMessages="on" useTransactions="on"
           beginTransactionMark="BEGIN TRANSACTION" commitTransactionMark="COMMIT TRANSACTION"
           queue.type="Direct")')"'
  }
}
if $msg contains "msgnum:" then call source
'
startup
injectmsg 0 "$count"
attempt=0
while ! grep -E "source: origin=core.queue .*enqueued=${count} " "$STATSFILE" >/dev/null 2>&1; do
	attempt=$((attempt + 1))
	[ "$attempt" -lt 300 ] || error_exit 1 "named source did not enqueue the exact gated batch"
	"$TESTTOOL_DIR/msleep" 100
done
rm -f "$RSYSLOG_TEST_CA_WORKER_GATE"
wait_content "^${count}$" "$RSYSLOG_CA_ACTION_TX_RESULT"
if [ "$RSTB_CA_ACTION_TX_MODE" = ordering ]; then wait_file_lines "$RSYSLOG_OUT_LOG" 3; fi
shutdown_when_empty
wait_shutdown

expected_count=${RSTB_CA_ACTION_TX_COUNT:-3}
printf '%s\n' "$expected_count" > "$RSYSLOG_DYNNAME.expected-result"
diff -u "$RSYSLOG_DYNNAME.expected-result" "$RSYSLOG_CA_ACTION_TX_RESULT" ||
	error_exit 1 "queued action transaction count was not exact"
printf 'BEGIN=1 MSG=%s COMMIT=1 ERRORS=0 SEQUENCE=contiguous-zero-based EOF_IN_TX=no\n' "$expected_count" \
	> "$RSYSLOG_DYNNAME.expected-summary"
diff -u "$RSYSLOG_DYNNAME.expected-summary" "$RSYSLOG_CA_ACTION_TX_SUMMARY" ||
	error_exit 1 "queued action transaction callback summary was not exact"
if [ "$RSTB_CA_ACTION_TX_MODE" = ordering ]; then
	printf '%s\n' "$expected_transcript" > "$RSYSLOG_DYNNAME.expected-transcript"
	diff -u "$RSYSLOG_DYNNAME.expected-transcript" "$RSYSLOG_CA_ACTION_TX_TRANSCRIPT" ||
		error_exit 1 "queued publication did not precede Direct transaction commit"
fi
exit_test
