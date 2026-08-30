#!/bin/bash
# Verify the opt-in ConcurrentArray main queue with one, eight, and sixteen
# workers. Each cycle publishes a burst, waits until it is fully observed, then
# publishes one independent tail message after the workers have gone idle. The
# oracle begins with exact unsorted single-submit and MultiEnq sequences, then
# checks one duplicate-free identity set across all cycles; this catches
# producer-lane reordering, lost ready tokens, multiplicity errors, and an
# empty-to-nonempty lost wake.
. ${srcdir:=.}/diag.sh init
require_plugin imtcp
require_plugin omtesting

# Intent/oracle: single-enqueue dispatch is bound at queue start, so the public
# compatibility wrapper must contain no per-message qType selector. The raw CA
# qAdd entry must also remain a hard accounting boundary and never submit to
# the core directly; terminal disposal would otherwise underflow its mirrors.
single_enq_body=$(sed -n '/^rsRetVal qqueueEnqMsg(qqueue_t .* {$/,/^}/p' ../runtime/queue.c)
if printf '%s\n' "$single_enq_body" | grep -q 'qType'; then
	error_exit 'qqueueEnqMsg contains a queue-type selector on the single-message hot path'
fi
if ! printf '%s\n' "$single_enq_body" | grep -q 'pThis->SingleEnq'; then
	error_exit 'qqueueEnqMsg does not use its startup-bound single-enqueue dispatch'
fi
qadd_ca_body=$(sed -n '/^static rsRetVal qAddConcurrentArray(qqueue_t .* {$/,/^}/p' ../runtime/queue.c)
if printf '%s\n' "$qadd_ca_body" | grep -q 'ca_submit_'; then
	error_exit 'qAddConcurrentArray bypasses accounted ConcurrentArray admission'
fi

# Hold the first claim while seven later single-submit calls enter the queue.
# Every call from the input stream resolves to one stable producer identity and
# lane, so exact recovered sequence 0..7 proves per-producer append/claim order
# rather than merely exact multiplicity.
export RSYSLOG_DEBUG="debug nostdout noprintmutexaction"
export RSYSLOG_DEBUGLOG="$RSYSLOG_DYNNAME.debug.log"
generate_conf
add_conf '
module(load="../plugins/omtesting/.libs/omtesting")
module(load="../plugins/imtcp/.libs/imtcp")
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="sparseLanes"
	queue.size="128" queue.workerThreads="1" queue.dequeueBatchSize="128")
template(name="outfmt" type="string" string="%msg:F,58:2%\n")
:msg, contains, "msgnum:00000000:" :omtesting:sleep 1 0
:msg, contains, "msgnum:" action(type="omfile" file="'$RSYSLOG_OUT_LOG'" template="outfmt")
input(type="imtcp" port="0" listenPortFileName="'$RSYSLOG_DYNNAME'.tcpflood_port")
'
startup
injectmsg 0 1
wait_content 'sleep(1, 0)' "$RSYSLOG_DEBUGLOG"
injectmsg 1 7
wait_file_lines "$RSYSLOG_OUT_LOG" 8
export EXPECTED=$'00000000\n00000001\n00000002\n00000003\n00000004\n00000005\n00000006\n00000007'
cmp_exact
tcpflood -m8 -i8
wait_file_lines "$RSYSLOG_OUT_LOG" 16
export EXPECTED=$'00000000\n00000001\n00000002\n00000003\n00000004\n00000005\n00000006\n00000007\n00000008\n00000009\n00000010\n00000011\n00000012\n00000013\n00000014\n00000015'
cmp_exact
shutdown_when_empty
wait_shutdown
unset EXPECTED
unset RSYSLOG_DEBUG RSYSLOG_DEBUGLOG

# The qqueue pre-registers the core's complete bounded producer shape: 16
# dedicated plus two fallback handles for C=1. The default-off startup oracle
# resolves enough synthetic identities to fill all dedicated slots and reach
# both fallback handles. The following real submitter must therefore remain on
# the fallback path while preserving its exact append order.
export RSYSLOG_DEBUG="debug nostdout"
export RSYSLOG_DEBUGLOG="$RSYSLOG_DYNNAME.fallback.debug.log"
export RSYSLOG_TEST_CA_LIFECYCLE_MARKERS=1
export RSYSLOG_TEST_CA_MULTI_COMMAND_FILE="$RSYSLOG_DYNNAME.ca-producer-map.commands"
printf 'map 10000 4096\n' >"$RSYSLOG_TEST_CA_MULTI_COMMAND_FILE"
generate_conf
add_conf '
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="sparseLanes"
	queue.size="128" queue.workerThreads="1" queue.dequeueBatchSize="32")
template(name="outfmt" type="string" string="%msg:F,58:2%\n")
:msg, contains, "msgnum:" action(type="omfile" file="'$RSYSLOG_OUT_LOG'" template="outfmt")
'
startup
injectmsg 16 8
wait_file_lines "$RSYSLOG_OUT_LOG" 24
EXPECTED=$(for id in $(seq 0 23); do printf '%08d\n' "$id"; done)
export EXPECTED
cmp_exact
shutdown_when_empty
wait_shutdown
content_check 'ConcurrentArray registered 16 dedicated and 2 fallback producer handles' "$RSYSLOG_DEBUGLOG"
content_check 'CA test producer map target=main dedicated=16/16 fallback=2/2' "$RSYSLOG_DEBUGLOG"
content_check 'ConcurrentArray published via fallback producer lane' "$RSYSLOG_DEBUGLOG"
unset EXPECTED RSYSLOG_DEBUG RSYSLOG_DEBUGLOG RSYSLOG_TEST_CA_LIFECYCLE_MARKERS \
	RSYSLOG_TEST_CA_MULTI_COMMAND_FILE

start=24
expected=24
for workers in 1 8 16; do
	generate_conf
	add_conf '
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="sparseLanes"
	queue.size="4096" queue.dequeueBatchSize="128"
	queue.workerThreads="'$workers'" queue.workerThreadMinimumMessages="1")

template(name="outfmt" type="string" string="%msg:F,58:2%\n")
:msg, contains, "msgnum:" action(type="omfile" file="'$RSYSLOG_OUT_LOG'" template="outfmt")
'
	startup
	injectmsg "$start" 511
	expected=$((expected + 511))
	wait_file_lines "$RSYSLOG_OUT_LOG" "$expected"
	# The tail is deliberately submitted only after the burst drained. Success
	# requires the sleeping worker path to observe a fresh ready transition.
	injectmsg $((start + 511)) 1
	expected=$((expected + 1))
	wait_file_lines "$RSYSLOG_OUT_LOG" "$expected"
	shutdown_when_empty
	wait_shutdown
	start=$((start + 512))
done

# Exercise the same core as a named ruleset queue while an explicit Main queue
# is also present. TCP binding is the routing oracle: all 128 identities must
# traverse the named queue exactly once.
generate_conf
add_conf '
module(load="../plugins/imtcp/.libs/imtcp")
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="sparseLanes")
template(name="outfmt" type="string" string="%msg:F,58:2%\n")
ruleset(name="named" queue.type="ConcurrentArray" queue.concurrentCore="sparseLanes"
	queue.workerThreads="8" queue.workerThreadMinimumMessages="1") {
	action(type="omfile" file="'$RSYSLOG_OUT_LOG'" template="outfmt")
}
input(type="imtcp" port="0" listenPortFileName="'$RSYSLOG_DYNNAME'.tcpflood_port" ruleset="named")
'
startup
tcpflood -m128 -i"$start"
expected=$((expected + 128))
wait_file_lines "$RSYSLOG_OUT_LOG" "$expected"
shutdown_when_empty
wait_shutdown
start=$((start + 128))

# These two small cycles are regression sentinels for the unchanged legacy
# worker/mutex branch. Their exact adjacent ranges prove that opting in to the
# new WTP mode did not alter FixedArray or LinkedList defaults.
for queue_type in FixedArray LinkedList; do
	generate_conf
	add_conf '
main_queue(queue.type="'$queue_type'" queue.size="128")
template(name="outfmt" type="string" string="%msg:F,58:2%\n")
:msg, contains, "msgnum:" action(type="omfile" file="'$RSYSLOG_OUT_LOG'" template="outfmt")
'
	startup
	injectmsg "$start" 16
	expected=$((expected + 16))
	wait_file_lines "$RSYSLOG_OUT_LOG" "$expected"
	shutdown_when_empty
	wait_shutdown
	start=$((start + 16))
done

seq_check 0 1719
exit_test
