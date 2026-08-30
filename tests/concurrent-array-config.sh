#!/bin/bash
# Verify the modern ConcurrentArray configuration contract. The positive
# oracle is -N1 acceptance for explicit Main and named ruleset queues plus the
# unchanged FixedArray/LinkedList defaults. Missing/unknown cores and currently
# unsupported disk/watermark, sampling, and minimum-dequeue combinations must
# fail under abortOnUncleanConfig with their precise diagnostics. Separate
# no-abort validation cases prove Main's late queue construction propagates
# the same errors rather than silently selecting sparseLanes.
. ${srcdir:=.}/diag.sh init

validate_ok() {
	local label="$1"
	local out="${RSYSLOG_DYNNAME}.${label}.log"
	if ! ../tools/rsyslogd -C -N1 -f"${TESTCONF_NM}.conf" -M../runtime/.libs:../.libs >"$out" 2>&1; then
		cat "$out"
		error_exit 1 "expected $label configuration to pass"
	fi
}

validate_error() {
	local label="$1"
	local diagnostic="$2"
	local out="${RSYSLOG_DYNNAME}.${label}.log"
	if ../tools/rsyslogd -C -N1 -f"${TESTCONF_NM}.conf" -M../runtime/.libs:../.libs >"$out" 2>&1; then
		error_exit 1 "expected $label configuration to fail"
	fi
	grep -Fq "$diagnostic" "$out" || {
		cat "$out"
		error_exit 1 "missing $label diagnostic: $diagnostic"
	}
}

reserved_start_error() {
	local label="$1"
	local diagnostic="$2"
	local out="${RSYSLOG_DYNNAME}.${label}.startup.log"
	local startup_conf="${RSYSLOG_DYNNAME}.${label}.startup.conf"
	# This is an actual activation check, not -N1: remove imdiag so the only
	# shutdown boundary under test is the injected CA worker-start failure.
	sed '1,10d' "${TESTCONF_NM}.conf" >"$startup_conf"
	timeout 5s ../tools/rsyslogd -C -n -iNONE -f"$startup_conf" -M"$RSYSLOG_MODDIR" >"$out" 2>&1
	local status=$?
	[ "$status" -ne 0 ] || error_exit 1 "$label reservedBatch startup unexpectedly succeeded"
	[ "$status" -ne 124 ] || error_exit 1 "$label reservedBatch startup left a mismatched queue topology running"
	grep -Fq "$diagnostic" "$out" || {
		cat "$out"
		error_exit 1 "missing $label startup diagnostic: $diagnostic"
	}
}

generate_conf
add_conf '
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="SpArSeLaNeS" queue.workerThreads="16")
ruleset(name="queued" queue.type="ConcurrentArray" queue.concurrentCore="sparseLanes") {
	action(type="omfile" file="'$RSYSLOG_OUT_LOG'")
}
'
validate_ok positive

generate_conf
add_conf '
main_queue(queue.type="FixedArray")
ruleset(name="legacy-memory" queue.type="LinkedList") {
	action(type="omfile" file="'$RSYSLOG_OUT_LOG'")
}
'
validate_ok legacy-memory

generate_conf
add_conf '
global(executionEngine="reservedBatch")
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="sparseLanes")
ruleset(name="reserved-target" queue.type="ConcurrentArray" queue.concurrentCore="sparseLanes") {
	action(type="omfile" file="'$RSYSLOG_OUT_LOG'")
}
'
validate_ok reserved-batch

generate_conf
add_conf '
global(abortOnUncleanConfig="on" executionEngine="reservedBatch")
main_queue(queue.type="FixedArray")
'
validate_error reserved-main "executionEngine=reservedBatch requires the Main queue to use queue.type='ConcurrentArray'"

generate_conf
add_conf '
global(abortOnUncleanConfig="on" executionEngine="reservedBatch")
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="sparseLanes")
ruleset(name="bad-target" queue.type="LinkedList") {
	action(type="omfile" file="'$RSYSLOG_OUT_LOG'")
}
'
validate_error reserved-target "executionEngine=reservedBatch requires queued targets to use queue.type='ConcurrentArray'"

generate_conf
add_conf '
global(abortOnUncleanConfig="on" executionEngine="reservedBatch")
action(type="omfile" file="'$RSYSLOG_OUT_LOG'" queue.type="LinkedList")
'
validate_error reserved-action "executionEngine=reservedBatch requires queued actions to use queue.type='ConcurrentArray'"

generate_conf
add_conf '
global(abortOnUncleanConfig="on" executionEngine="notAnEngine")
'
validate_error reserved-engine "invalid global executionEngine 'notAnEngine'"

generate_conf
add_conf '
global(abortOnUncleanConfig="on")
main_queue(queue.type="ConcurrentArray")
'
validate_error missing-core 'requires queue.concurrentCore="sparseLanes"'

generate_conf
add_conf '
global(abortOnUncleanConfig="on")
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="bbq")
'
validate_error unknown-core "unsupported ConcurrentArray core 'bbq'"

generate_conf
add_conf '
global(abortOnUncleanConfig="on")
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="sparseLanes" queue.filename="not-supported")
'
validate_error disk 'do not yet support disk assistance'

generate_conf
add_conf '
global(abortOnUncleanConfig="on")
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="sparseLanes"
           queue.highWatermark="8" queue.lowWatermark="4")
'
validate_error watermarks 'do not yet support disk assistance'

generate_conf
add_conf '
global(abortOnUncleanConfig="on")
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="sparseLanes" queue.samplingInterval="2")
'
validate_error sampling 'do not yet support queue.samplingInterval'

generate_conf
add_conf '
global(abortOnUncleanConfig="on")
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="sparseLanes" queue.minDequeueBatchSize="2")
'
validate_error minimum-dequeue 'do not yet support queue.minDequeueBatchSize'

generate_conf
add_conf '
global(abortOnUncleanConfig="on")
action(type="omfile" file="'$RSYSLOG_OUT_LOG'" queue.type="ConcurrentArray"
       queue.concurrentCore="sparseLanes")
'
validate_error concurrent-action "queue.type='ConcurrentArray' requires global executionEngine='reservedBatch'"

generate_conf
add_conf '
global(executionEngine="reservedBatch")
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="sparseLanes")
action(type="omfile" file="'$RSYSLOG_OUT_LOG'" queue.type="ConcurrentArray"
       queue.concurrentCore="sparseLanes")
'
validate_ok concurrent-action-reserved

generate_conf
add_conf '
main_queue(queue.type="ConcurrentArray")
'
validate_error missing-core-no-abort 'requires queue.concurrentCore="sparseLanes"'

generate_conf
add_conf '
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="bbq")
'
validate_error unknown-core-no-abort "unsupported ConcurrentArray core 'bbq'"

generate_conf
add_conf '
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="sparseLanes" queue.filename="not-supported")
'
validate_error unsupported-no-abort 'do not yet support disk assistance'

# A CA worker-start failure may fall back to Direct in the legacy engine, but
# reservedBatch requires the validated Main/target topology to remain exact.
# Both actual activation failures must terminate rather than run a Direct queue
# behind compiled asynchronous calls and retry the source forever.
generate_conf
add_conf '
global(executionEngine="reservedBatch")
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="sparseLanes" queue.workerThreads="2")
'
export RSYSLOG_TEST_FAIL_CA_WORKER_PREALLOC=1
reserved_start_error reserved-main-start 'reservedBatch ConcurrentArray queue startup failed'
unset RSYSLOG_TEST_FAIL_CA_WORKER_PREALLOC

generate_conf
add_conf '
global(executionEngine="reservedBatch")
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="sparseLanes" queue.workerThreads="2")
ruleset(name="target" queue.type="ConcurrentArray" queue.concurrentCore="sparseLanes" queue.workerThreads="2") {
	action(type="omfile" file="'$RSYSLOG_OUT_LOG'")
}
'
export RSYSLOG_TEST_FAIL_CA_WORKER_PREALLOC_QUEUE=target
reserved_start_error reserved-target-start 'reservedBatch ConcurrentArray queue startup failed'
unset RSYSLOG_TEST_FAIL_CA_WORKER_PREALLOC_QUEUE

# Worker claim buffers must be prepared while the WTP is constructed, before
# the queue can admit work. Injected failure must transactionally destroy the
# partial core/pool before rsyslog's intentional Direct fallback starts. Exact
# fallback output plus lifecycle markers prove both halves of that contract.
generate_conf
add_conf '
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="sparseLanes" queue.workerThreads="16")
template(name="outfmt" type="string" string="%msg:F,58:2%\n")
:msg, contains, "msgnum:" action(type="omfile" file="'$RSYSLOG_OUT_LOG'" template="outfmt")
'
prealloc_out="${RSYSLOG_DYNNAME}.worker-prealloc.log"
export RS_REDIR=">$prealloc_out 2>&1"
export RSYSLOG_DEBUG="debug nostdout"
export RSYSLOG_DEBUGLOG="$RSYSLOG_DYNNAME.prealloc.debug.log"
export RSYSLOG_TEST_FAIL_CA_WORKER_PREALLOC=1
export RSYSLOG_TEST_CA_LIFECYCLE_MARKERS=1
startup
content_check 'injected ConcurrentArray worker preallocation failure before queue admission' "$prealloc_out"
content_check 'could not start (ruleset) main message queue' "$prealloc_out"
content_check 'ConcurrentArray core destruction complete' "$RSYSLOG_DEBUGLOG"
content_check 'ConcurrentArray startup rollback complete' "$RSYSLOG_DEBUGLOG"
check_not_present 'ConcurrentArray queue start complete' "$RSYSLOG_DEBUGLOG"
injectmsg 0 1
wait_file_lines "$RSYSLOG_OUT_LOG" 1
shutdown_immediate
wait_shutdown
seq_check 0 0
unset RS_REDIR RSYSLOG_DEBUG RSYSLOG_DEBUGLOG RSYSLOG_TEST_FAIL_CA_WORKER_PREALLOC RSYSLOG_TEST_CA_LIFECYCLE_MARKERS

# Fail before the WTP worker-pointer array exists. The rollback destructor must
# tolerate pWrkr == NULL, destroy the CA core, and leave the same queue object
# reusable by the intentional Direct fallback. Exact ID 1 proves that fallback
# accepted and drained work after the earlier allocation boundary failed.
generate_conf
add_conf '
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="sparseLanes" queue.workerThreads="16")
template(name="outfmt" type="string" string="%msg:F,58:2%\n")
:msg, contains, "msgnum:" action(type="omfile" file="'$RSYSLOG_OUT_LOG'" template="outfmt")
'
array_alloc_out="${RSYSLOG_DYNNAME}.worker-array-alloc.log"
export RS_REDIR=">$array_alloc_out 2>&1"
export RSYSLOG_DEBUG="debug nostdout"
export RSYSLOG_DEBUGLOG="$RSYSLOG_DYNNAME.worker-array-alloc.debug.log"
export RSYSLOG_TEST_FAIL_CA_WTP_ARRAY_ALLOC=1
export RSYSLOG_TEST_CA_LIFECYCLE_MARKERS=1
startup
content_check 'injected ConcurrentArray WTP worker-array allocation failure before queue admission' "$array_alloc_out"
content_check 'could not start (ruleset) main message queue' "$array_alloc_out"
content_check 'ConcurrentArray core destruction complete' "$RSYSLOG_DEBUGLOG"
content_check 'ConcurrentArray startup rollback complete' "$RSYSLOG_DEBUGLOG"
check_not_present 'ConcurrentArray queue start complete' "$RSYSLOG_DEBUGLOG"
injectmsg 1 1
wait_file_lines "$RSYSLOG_OUT_LOG" 2
shutdown_immediate
wait_shutdown
seq_check 0 1
unset RS_REDIR RSYSLOG_DEBUG RSYSLOG_DEBUGLOG RSYSLOG_TEST_FAIL_CA_WTP_ARRAY_ALLOC RSYSLOG_TEST_CA_LIFECYCLE_MARKERS

exit_test
