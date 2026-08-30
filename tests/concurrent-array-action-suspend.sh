#!/bin/bash
# Exercise action suspension/recovery in fast-first and slow-first branch order.
# A Direct omprog fsyncs every accepted ID before ACK; a sparseLanes omfile
# action is suspended by a missing parent directory until impstats reports a
# real retry. After creating the directory, every durably accepted ID must be
# present in the recovered output and no unaccepted/malformed ID may appear.
# Fast-first additionally snapshots a nonempty Direct acceptance ledger before
# recovery, proving that the earlier branch made durable progress while the
# queued action was suspended. Raw-line counts and anchored formats are checked
# before IDs are extracted, so malformed or extra action output cannot hide.
# The 30-second state and 60-second delivery bounds only guard loaded CI hosts;
# the resumed counter and exact set comparison are the synchronization oracles.
# The background injector is explicitly awaited after recovery; exit_test owns
# the daemon lifecycle and cleanup after both exact output sets are complete.
if [ "$1" != "--case" ]; then
	for order in fast-first slow-first; do
		RSTB_CA_ACTION_ORDER=$order "$0" --case || exit $?
	done
	exit 0
fi
. ${srcdir:=.}/diag.sh init
require_plugin omprog
export NUMMESSAGES=32
export STATSFILE="$RSYSLOG_DYNNAME.stats"
export RSYSLOG_CA_ACTION_ACCEPTED="$PWD/$RSYSLOG_DYNNAME.accepted"
missing_dir="$PWD/$RSYSLOG_DYNNAME.missing"
slow_output="$missing_dir/slow.log"

accept_action='action(name="accept" type="omprog"
       binary="'$srcdir'/testsuites/concurrent-array-action-accept-bin.py"
       template="outfmt" confirmMessages="on" queue.type="Direct")'
slow_action='action(name="slow" type="omfile" file="'$slow_output'" template="outfmt" createDirs="off"
       action.resumeRetryCount="-1" action.resumeInterval="1"
       queue.type="ConcurrentArray" queue.concurrentCore="sparseLanes"
       queue.size="8" queue.dequeueBatchSize="4" queue.workerThreads="1"
       queue.timeoutEnqueue="30000")'
if [ "$RSTB_CA_ACTION_ORDER" = fast-first ]; then
	actions="$accept_action
  $slow_action"
else
	actions="$slow_action
  $accept_action"
fi

generate_conf
add_conf '
global(executionEngine="reservedBatch")
module(load="../plugins/omprog/.libs/omprog")
module(load="../plugins/impstats/.libs/impstats" interval="1" log.syslog="off"
       resetCounters="off" log.file="'$STATSFILE'")
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="sparseLanes"
           queue.size="64" queue.workerThreads="1" queue.dequeueBatchSize="8")
template(name="outfmt" type="string" string="%msg%\n")
ruleset(name="source" queue.type="ConcurrentArray" queue.concurrentCore="sparseLanes"
        queue.size="64" queue.workerThreads="1" queue.dequeueBatchSize="8") {
  if $msg contains "msgnum:" then {
    '"$actions"'
  }
}
if $msg contains "msgnum:" then call source
'
startup
injectmsg 0 "$NUMMESSAGES" &
inject_pid=$!
deadline=$((SECONDS + 30))
while ! grep -E 'slow: origin=core.action .*resumed=[1-9][0-9]* ' "$STATSFILE" >/dev/null 2>&1; do
	[ "$SECONDS" -lt "$deadline" ] || error_exit 1 "queued omfile did not enter observable suspension/retry"
	"$TESTTOOL_DIR/msleep" 100
done
if [ "$RSTB_CA_ACTION_ORDER" = fast-first ]; then
	test -s "$RSYSLOG_CA_ACTION_ACCEPTED" ||
		error_exit 1 "Direct fast-first action made no durable progress before recovery"
	cp "$RSYSLOG_CA_ACTION_ACCEPTED" "$RSYSLOG_DYNNAME.accepted-before-recovery"
	pre_recovery_count=$(wc -l < "$RSYSLOG_DYNNAME.accepted-before-recovery")
	pre_recovery_valid=$(grep -Ec '^msgnum:[0-9]{8}:$' "$RSYSLOG_DYNNAME.accepted-before-recovery" || true)
	[ "$pre_recovery_count" -eq "$pre_recovery_valid" ] ||
		error_exit 1 "fast-first pre-recovery acceptance snapshot contained malformed rows"
fi
mkdir "$missing_dir"
wait "$inject_pid" || error_exit 1 "background imdiag injection failed"
wait_file_lines "$RSYSLOG_CA_ACTION_ACCEPTED" "$NUMMESSAGES" 60
wait_file_lines "$slow_output" "$NUMMESSAGES" 60
shutdown_when_empty
wait_shutdown

accepted_raw_count=$(wc -l < "$RSYSLOG_CA_ACTION_ACCEPTED")
accepted_valid_count=$(grep -Ec '^msgnum:[0-9]{8}:$' "$RSYSLOG_CA_ACTION_ACCEPTED" || true)
[ "$accepted_raw_count" -eq "$NUMMESSAGES" ] ||
	error_exit 1 "Direct acceptance ledger had an unexpected raw row count"
[ "$accepted_valid_count" -eq "$NUMMESSAGES" ] ||
	error_exit 1 "Direct acceptance ledger contained malformed rows"
slow_raw_count=$(wc -l < "$slow_output")
slow_valid_count=$(grep -Ec '^ ?msgnum:[0-9]{8}:$' "$slow_output" || true)
[ "$slow_raw_count" -eq "$NUMMESSAGES" ] ||
	error_exit 1 "recovered queued action had an unexpected raw row count"
[ "$slow_valid_count" -eq "$NUMMESSAGES" ] ||
	error_exit 1 "recovered queued action contained malformed rows"
sort -u "$RSYSLOG_CA_ACTION_ACCEPTED" > "$RSYSLOG_DYNNAME.accepted.unique"
sed -n 's/.*\(msgnum:[0-9]\{8\}:\).*/\1/p' "$slow_output" | sort -u > "$RSYSLOG_DYNNAME.slow.unique"
seq -f 'msgnum:%08g:' 0 $((NUMMESSAGES - 1)) > "$RSYSLOG_DYNNAME.expected"
diff -u "$RSYSLOG_DYNNAME.expected" "$RSYSLOG_DYNNAME.accepted.unique" ||
	error_exit 1 "Direct accepted set was incomplete"
diff -u "$RSYSLOG_DYNNAME.accepted.unique" "$RSYSLOG_DYNNAME.slow.unique" ||
	error_exit 1 "recovered queued action lost accepted IDs or emitted unaccepted IDs"
exit_test
