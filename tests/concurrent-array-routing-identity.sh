#!/bin/bash
# Verify that native MultiSubmit and a reservedBatch source WTI use distinct
# process-wide producer identities while targeting one ConcurrentArray queue.
# native 128-item span is injected by the imdiag-compiled, startup-only tool
# hook; the routed source then uses its independently allocated WTI identity.
# The first phase uses one target worker, so exact order within each producer
# range is a valid oracle.
# The second uses two target workers and checks exact sorted multiplicity only:
# concurrent claims may complete out of order. Distinct dedicated-lane markers
# and clean teardown are checked in both phases; waits observe debug events,
# not elapsed time.
. ${srcdir:=.}/diag.sh init
CA_CORE=${RSYSLOG_TEST_CA_CORE:-sparseLanes}
require_plugin omtesting

export RS_REDIR=">$RSYSLOG_DYNNAME.rsyslog.log 2>&1"
export RSYSLOG_DEBUG="debug nostdout noprintmutexaction"
export RSYSLOG_DEBUGLOG="$RSYSLOG_DYNNAME.debug.log"
export RSYSLOG_TEST_CA_LIFECYCLE_MARKERS=1
export RSYSLOG_TEST_CA_MULTI_COMMAND_FILE="$RSYSLOG_DYNNAME.ca-multi.commands"
generate_conf
add_conf '
module(load="../plugins/omtesting/.libs/omtesting")
global(executionEngine="reservedBatch")
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="'$CA_CORE'"
           queue.size="512" queue.workerThreads="1" queue.dequeueBatchSize="32")
template(name="outfmt" type="string" string="%msg:F,58:2%\n")
ruleset(name="target" queue.type="ConcurrentArray" queue.concurrentCore="'$CA_CORE'"
        queue.size="512" queue.workerThreads="1" queue.dequeueBatchSize="17") {
  action(type="omfile" file="'$RSYSLOG_OUT_LOG'" template="outfmt")
}
if $msg contains "msgnum:" then {
  call target
  :msg, contains, "msgnum:" :omtesting:sleep 0 200000
}
'
: >"$RSYSLOG_TEST_CA_MULTI_COMMAND_FILE"
printf '1000 128 target\n' >>"$RSYSLOG_TEST_CA_MULTI_COMMAND_FILE"
startup

printf 'injectmsg 0 7\n' | $TESTTOOL_DIR/diagtalker -p"$IMDIAG_PORT" >/dev/null || error_exit $?
wait_content 'reservedBatch target producer identity' "$RSYSLOG_DEBUGLOG"
wait_file_lines "$RSYSLOG_OUT_LOG" 135
shutdown_when_empty
wait_shutdown

awk '{ print $1 + 0 }' "$RSYSLOG_OUT_LOG" | sort -n >"$RSYSLOG_DYNNAME.sorted"
{
  seq 0 6
  seq 1000 1127
} >"$RSYSLOG_DYNNAME.expected"
cmp "$RSYSLOG_DYNNAME.expected" "$RSYSLOG_DYNNAME.sorted" || error_exit 1 "routed/native identity multiplicity mismatch"
awk '$1 + 0 < 1000 { print $1 + 0 }' "$RSYSLOG_OUT_LOG" >"$RSYSLOG_DYNNAME.source"
awk '$1 + 0 >= 1000 { print $1 + 0 }' "$RSYSLOG_OUT_LOG" >"$RSYSLOG_DYNNAME.native"
cmp <(seq 0 6) "$RSYSLOG_DYNNAME.source" || error_exit 1 "routed producer order mismatch"
cmp <(seq 1000 1127) "$RSYSLOG_DYNNAME.native" || error_exit 1 "native producer order mismatch"

routed_identity=$(sed -n 's/.*reservedBatch target producer identity \([0-9][0-9]*\) uses dedicated lane.*/\1/p' \
  "$RSYSLOG_DEBUGLOG" | head -n1)
native_identity=$(sed -n 's/.*native MultiSubmit producer identity \([0-9][0-9]*\) published 128 messages via dedicated lane.*/\1/p' \
  "$RSYSLOG_DEBUGLOG" | head -n1)
[ -n "$routed_identity" ] || error_exit 1 "missing routed dedicated identity marker"
[ -n "$native_identity" ] || error_exit 1 "missing native target dedicated identity marker"
[ "$routed_identity" != "$native_identity" ] || error_exit 1 "native and routed producers reused identity $routed_identity"
content_check 'ConcurrentArray core destruction complete' "$RSYSLOG_DEBUGLOG"

# Repeat with two target workers. Exact identity/multiplicity remains required,
# but output order is deliberately not asserted because independent claims can
# execute and reach omfile in either order.
rm -f "$RSYSLOG_OUT_LOG" "$RSYSLOG_DEBUGLOG"
generate_conf
add_conf '
module(load="../plugins/omtesting/.libs/omtesting")
global(executionEngine="reservedBatch")
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="'$CA_CORE'"
           queue.size="512" queue.workerThreads="1" queue.dequeueBatchSize="32")
template(name="outfmt" type="string" string="%msg:F,58:2%\n")
ruleset(name="target" queue.type="ConcurrentArray" queue.concurrentCore="'$CA_CORE'"
        queue.size="512" queue.workerThreads="2" queue.dequeueBatchSize="17") {
  action(type="omfile" file="'$RSYSLOG_OUT_LOG'" template="outfmt")
}
if $msg contains "msgnum:" then {
  call target
  :msg, contains, "msgnum:" :omtesting:sleep 0 200000
}
'
: >"$RSYSLOG_TEST_CA_MULTI_COMMAND_FILE"
printf '3000 128 target\n' >>"$RSYSLOG_TEST_CA_MULTI_COMMAND_FILE"
startup

printf 'injectmsg 2000 7\n' | $TESTTOOL_DIR/diagtalker -p"$IMDIAG_PORT" >/dev/null || error_exit $?
wait_content 'reservedBatch target producer identity' "$RSYSLOG_DEBUGLOG"
wait_file_lines "$RSYSLOG_OUT_LOG" 135
shutdown_when_empty
wait_shutdown

awk '{ print $1 + 0 }' "$RSYSLOG_OUT_LOG" | sort -n >"$RSYSLOG_DYNNAME.sorted"
{
  seq 2000 2006
  seq 3000 3127
} >"$RSYSLOG_DYNNAME.expected"
cmp "$RSYSLOG_DYNNAME.expected" "$RSYSLOG_DYNNAME.sorted" || \
  error_exit 1 "two-worker routed/native identity multiplicity mismatch"

routed_identity=$(sed -n 's/.*reservedBatch target producer identity \([0-9][0-9]*\) uses dedicated lane.*/\1/p' \
  "$RSYSLOG_DEBUGLOG" | head -n1)
native_identity=$(sed -n 's/.*native MultiSubmit producer identity \([0-9][0-9]*\) published 128 messages via dedicated lane.*/\1/p' \
  "$RSYSLOG_DEBUGLOG" | head -n1)
[ -n "$routed_identity" ] || error_exit 1 "missing two-worker routed dedicated identity marker"
[ -n "$native_identity" ] || error_exit 1 "missing two-worker native target dedicated identity marker"
[ "$routed_identity" != "$native_identity" ] || \
  error_exit 1 "two-worker native and routed producers reused identity $routed_identity"
content_check 'ConcurrentArray core destruction complete' "$RSYSLOG_DEBUGLOG"
unset RSYSLOG_TEST_CA_LIFECYCLE_MARKERS RSYSLOG_TEST_CA_MULTI_COMMAND_FILE
exit_test
