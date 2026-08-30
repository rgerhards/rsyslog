#!/bin/bash
# Verify that the qqueue ConcurrentArray adapter preserves one exact public
# MultiSubmit boundary in roomy capacity. The ENABLE_IMDIAG-only rsyslogd
# startup command-file hook reports adapter counters after the call; one
# reservation/publication/advice and exact published N are the roomy oracle.
# Later phases require exact partial-prefix progress beyond a dequeue ceiling,
# timeout and discard ownership, and current-size discard decisions across a
# forced full/drain transition. Exact adapter counters and output identities,
# rather than timing, prove every accepted item is published once and every
# rejected item transfers ownership once.
. ${srcdir:=.}/diag.sh init

export RS_REDIR=">$RSYSLOG_DYNNAME.rsyslog.log 2>&1"
export RSYSLOG_DEBUG="debug nostdout noprintmutexaction"
export RSYSLOG_DEBUGLOG="$RSYSLOG_DYNNAME.debug.log"
export RSYSLOG_TEST_CA_MULTI_COMMAND_FILE="$RSYSLOG_DYNNAME.ca-multi.commands"

generate_conf
add_conf '
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="sparseLanes"
	queue.size="65536" queue.workerThreads="1" queue.dequeueBatchSize="7")
template(name="outfmt" type="string" string="%msg:F,58:2%\n")
:msg, contains, "msgnum:" action(type="omfile" file="'$RSYSLOG_OUT_LOG'" template="outfmt")
'

total=0
: >"$RSYSLOG_TEST_CA_MULTI_COMMAND_FILE"
for count in 1 2 7 128 1000 4096 8192 16384 32767; do
	printf '%d %d\n' "$total" "$count" >>"$RSYSLOG_TEST_CA_MULTI_COMMAND_FILE"
	total=$((total + count))
done
startup
total=0
for count in 1 2 7 128 1000 4096 8192 16384 32767; do
	expected="CA test MultiSubmit first=$total count=$count target=main reservations=1 publications=1 published=$count advice=1"
	content_check "$expected" "$RSYSLOG_DEBUGLOG"
	total=$((total + count))
done
wait_file_lines "$RSYSLOG_OUT_LOG" "$total"
shutdown_when_empty
wait_shutdown
seq_check 0 $((total - 1))

rm -f "$RSYSLOG_OUT_LOG"
generate_conf
add_conf '
module(load="../plugins/omtesting/.libs/omtesting")
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="sparseLanes"
	queue.size="7" queue.workerThreads="1" queue.dequeueBatchSize="1" queue.timeoutEnqueue="30000")
template(name="outfmt" type="string" string="%msg:F,58:2%\n")
:msg, contains, "msgnum:" :omtesting:sleep 0 2000
:msg, contains, "msgnum:" action(type="omfile" file="'$RSYSLOG_OUT_LOG'" template="outfmt")
'
: >"$RSYSLOG_TEST_CA_MULTI_COMMAND_FILE"
printf '0 128\n' >>"$RSYSLOG_TEST_CA_MULTI_COMMAND_FILE"
startup
response=$(grep 'CA test MultiSubmit first=0 count=128 target=main' "$RSYSLOG_DEBUGLOG" | tail -n1)
reservations=${response#*reservations=}
reservations=${reservations%% *}
publications=${response#*publications=}
publications=${publications%% *}
published=${response#*published=}
published=${published%% *}
advice=${response#*advice=}
[ "$reservations" -gt 1 ] || error_exit 1 "partial MultiSubmit did not retry admission: '$response'"
[ "$publications" -gt 1 ] || error_exit 1 "partial MultiSubmit did not split publication: '$response'"
[ "$published" -eq 128 ] || error_exit 1 "partial MultiSubmit ownership mismatch: '$response'"
[ "$advice" -gt 1 ] || error_exit 1 "partial MultiSubmit did not advise under pressure: '$response'"
wait_file_lines "$RSYSLOG_OUT_LOG" 128
shutdown_when_empty
wait_shutdown
seq_check 0 127

# Timeout ownership: one startup MultiSubmit publishes ID 900 into the sole
# capacity credit. Its action holds the active claim while IDs 901..903 time
# out, proving exact suffix ownership without an external producer command.
rm -f "$RSYSLOG_OUT_LOG"
export RS_REDIR=">$RSYSLOG_DYNNAME.rsyslog.log 2>&1"
export RSYSLOG_DEBUG="debug nostdout noprintmutexaction"
export RSYSLOG_DEBUGLOG="$RSYSLOG_DYNNAME.debug.log"
generate_conf
add_conf '
module(load="../plugins/omtesting/.libs/omtesting")
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="sparseLanes"
	queue.size="1" queue.workerThreads="1" queue.dequeueBatchSize="1" queue.timeoutEnqueue="100")
template(name="outfmt" type="string" string="%msg:F,58:2%\n")
:msg, contains, "00000900" :omtesting:sleep 2 0
:msg, contains, "msgnum:" action(type="omfile" file="'$RSYSLOG_OUT_LOG'" template="outfmt")
'
: >"$RSYSLOG_TEST_CA_MULTI_COMMAND_FILE"
printf '900 4\n' >>"$RSYSLOG_TEST_CA_MULTI_COMMAND_FILE"
startup
response=$(grep 'CA test MultiSubmit first=900 count=4 target=main' "$RSYSLOG_DEBUGLOG" | tail -n1)
case "$response" in
  *'reservations=4 publications=1 published=1 advice=4') ;;
  *) error_exit 1 "native MultiSubmit timeout ownership counters: '$response'" ;;
esac
wait_file_lines "$RSYSLOG_OUT_LOG" 1
shutdown_when_empty
wait_shutdown
export EXPECTED=$'00000900'
cmp_exact

# discardMark ownership: the first startup-span item is eligible at size zero;
# the following seven see the target at its mark and must be destroyed before
# admission, leaving one publication and seven exact discards.
rm -f "$RSYSLOG_OUT_LOG" "$RSYSLOG_DEBUGLOG"
generate_conf
add_conf '
module(load="../plugins/omtesting/.libs/omtesting")
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="sparseLanes"
	queue.size="8" queue.workerThreads="1" queue.dequeueBatchSize="1"
	queue.discardMark="1" queue.discardSeverity="0")
template(name="outfmt" type="string" string="%msg:F,58:2%\n")
:msg, contains, "00000900" :omtesting:sleep 2 0
:msg, contains, "msgnum:" action(type="omfile" file="'$RSYSLOG_OUT_LOG'" template="outfmt")
'
: >"$RSYSLOG_TEST_CA_MULTI_COMMAND_FILE"
printf '900 8\n' >>"$RSYSLOG_TEST_CA_MULTI_COMMAND_FILE"
startup
response=$(grep 'CA test MultiSubmit first=900 count=8 target=main' "$RSYSLOG_DEBUGLOG" | tail -n1)
case "$response" in
  *'reservations=1 publications=1 published=1 advice=1') ;;
  *) error_exit 1 "native MultiSubmit discard ownership counters: '$response'" ;;
esac
wait_file_lines "$RSYSLOG_OUT_LOG" 1
shutdown_when_empty
wait_shutdown
cmp_exact
[ "$(grep -c 'queue nearly full (1 entries), discarded severity 7 message' "$RSYSLOG_DEBUGLOG")" -eq 7 ] || \
	error_exit 1 "native MultiSubmit discardMark did not discard seven exact messages"

# Current-size discard transition: with no worker initially active, the first
# two severity-7 items fill capacity. The third severity-0 item is not eligible
# for discard, hits FULL, and starts/waits for a worker that drains both items
# in one claim. The fourth severity-7 item must re-read the resulting size one
# and be admitted. Exact four outputs and five size-one reservations prove the
# adapter did not pre-discard it using speculative earlier eligibility.
rm -f "$RSYSLOG_OUT_LOG" "$RSYSLOG_DEBUGLOG"
generate_conf
add_conf '
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="sparseLanes"
	queue.size="2" queue.workerThreads="1" queue.dequeueBatchSize="2"
	queue.timeoutEnqueue="5000" queue.discardMark="2" queue.discardSeverity="4")
template(name="outfmt" type="string" string="%msg:F,58:2%\n")
:msg, contains, "msgnum:" action(type="omfile" file="'$RSYSLOG_OUT_LOG'" template="outfmt")
'
: >"$RSYSLOG_TEST_CA_MULTI_COMMAND_FILE"
printf '900 4 - discard-transition\n' >>"$RSYSLOG_TEST_CA_MULTI_COMMAND_FILE"
startup
response=$(grep 'CA test MultiSubmit first=900 count=4 target=main' "$RSYSLOG_DEBUGLOG" | tail -n1)
case "$response" in
  *'reservations=5 publications=4 published=4 advice=2') ;;
  *) error_exit 1 "native MultiSubmit discard transition counters: '$response'" ;;
esac
wait_file_lines "$RSYSLOG_OUT_LOG" 4
shutdown_when_empty
wait_shutdown
export EXPECTED=$'00000900\n00000901\n00000902\n00000903'
cmp_exact

unset EXPECTED RS_REDIR RSYSLOG_DEBUG RSYSLOG_DEBUGLOG RSYSLOG_TEST_CA_MULTI_COMMAND_FILE

exit_test
