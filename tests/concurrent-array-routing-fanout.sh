#!/bin/bash
# Verify small exact reservedBatch fanout over three and six ConcurrentArray
# targets. Four source IDs call target 1 twice and every other target once.
# Per-target exact files are the oracle: target 1 contains each ID twice,
# every other target contains each ID once, and no branch is lost or duplicated.
. ${srcdir:=.}/diag.sh init
CA_CORE=${RSYSLOG_TEST_CA_CORE:-sparseLanes}
export RS_REDIR=">$RSYSLOG_DYNNAME.rsyslog.log 2>&1"

for fanout in 3 6; do
	generate_conf
	conf='global(executionEngine="reservedBatch")
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="'$CA_CORE'"
           queue.size="64" queue.workerThreads="1" queue.dequeueBatchSize="8")
template(name="outfmt" type="string" string="%msg:F,58:2%\n")
'
	calls=''
	for target in $(seq 1 "$fanout"); do
		conf="$conf
ruleset(name=\"target${target}\" queue.type=\"ConcurrentArray\" queue.concurrentCore=\"${CA_CORE}\"
        queue.size=\"32\" queue.workerThreads=\"1\") {
  action(type=\"omfile\" file=\"${RSYSLOG_OUT_LOG}.${target}\" template=\"outfmt\")
}"
		calls="$calls
  call target${target}"
	done
	# Repeated target 1 must share its target-local builder and retain both
	# snapshots rather than replacing the first staged call.
	calls="$calls
  call target1"
	conf="$conf
if \$msg contains \"msgnum:\" then {
$calls
}"
	add_conf "$conf"
	startup
	injectmsg 0 4
	for target in $(seq 1 "$fanout"); do
		lines=4
		[ "$target" -ne 1 ] || lines=8
		wait_file_lines "${RSYSLOG_OUT_LOG}.${target}" "$lines"
	done
	shutdown_when_empty
	wait_shutdown
	if grep -Fq 'invalid character' "$RSYSLOG_DYNNAME.rsyslog.log"; then
		error_exit 1 "fanout $fanout generated invalid RainerScript syntax"
	fi

	expected_once=$(for id in 0 1 2 3; do printf '%08d\n' "$id"; done)
	expected_twice=$(for id in 0 1 2 3; do printf '%08d\n%08d\n' "$id" "$id"; done)
	for target in $(seq 1 "$fanout"); do
		expected="$expected_once"
		[ "$target" -ne 1 ] || expected="$expected_twice"
		printf '%s\n' "$expected" >"${RSYSLOG_OUT_LOG}.expected"
		cmp "${RSYSLOG_OUT_LOG}.expected" "${RSYSLOG_OUT_LOG}.${target}" ||
			error_exit 1 "fanout $fanout target $target identity/multiplicity mismatch"
	done
	rm -f "${RSYSLOG_OUT_LOG}".*
done

unset RS_REDIR
exit_test
