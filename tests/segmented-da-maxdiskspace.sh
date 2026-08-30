#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# Copyright 2026 Rainer Gerhards and Adiscon GmbH.
#
# Fill a 64 KiB segmented DA child while a slow consumer keeps the 50-record
# memory tier above its high watermark, drain it, and repeat. Exact delivery
# proves producer backpressure without loss and reuse after segment reclamation;
# impstats permits only the current-record/topology overshoot used by the pure
# segmented store test.
. ${srcdir:=.}/diag.sh init
require_plugin impstats
export NUMMESSAGES=2000
DA_QUEUE_TYPE=${DA_QUEUE_TYPE:-LinkedList}
STATS_FILE="$PWD/${RSYSLOG_DYNNAME}.stats.log"
if [ "$DA_QUEUE_TYPE" = ConcurrentArray ]; then
	CA_CORE='queue.concurrentCore="sparseLanes"'
	CA_ENGINE=' executionEngine="reservedBatch"'
else
	CA_CORE=
	CA_ENGINE=
fi

generate_conf
add_conf '
module(load="../plugins/omtesting/.libs/omtesting")
module(load="../plugins/impstats/.libs/impstats" log.file="'"$STATS_FILE"'" interval="1")
module(load="../plugins/imtcp/.libs/imtcp")
input(type="imtcp" address="127.0.0.1" port="0"
	listenPortFileName="'"$RSYSLOG_DYNNAME"'.tcpflood_port")
global(workDirectory="'${RSYSLOG_DYNNAME}'.spool"'"$CA_ENGINE"')
main_queue(queue.type="'"$DA_QUEUE_TYPE"'" queue.filename="mainq"
	'"$CA_CORE"'
	queue.size="50" queue.highWatermark="10" queue.lowWatermark="5"
	queue.maxDiskSpace="64k" queue.maxFileSize="8k"
	queue.timeoutEnqueue="300000" queue.dequeueBatchSize="16"
	queue.diskQueueType="auto" queue.diskQueueIdleTimeout="-1")
template(name="outfmt" type="string" string="%msg:F,58:2%\n")
:msg, contains, "msgnum:" :omtesting:sleep 0 1000
if ($msg contains "msgnum:") then
	action(type="omfile" file="'"$RSYSLOG_OUT_LOG"'" template="outfmt")
'

startup
tcpflood -p"$TCPFLOOD_PORT" -m1000 -i0
wait_file_lines "$RSYSLOG_OUT_LOG" 1000
if [ "$DA_QUEUE_TYPE" = ConcurrentArray ]; then
	# Reload at a drained spill boundary proves the reused memory parent keeps
	# its DA child and worker bindings valid for the next pressure cycle.
	issue_HUP
fi
tcpflood -p"$TCPFLOOD_PORT" -m1000 -i1000
wait_file_lines "$RSYSLOG_OUT_LOG" "$NUMMESSAGES"
shutdown_when_empty
wait_shutdown
if [ "$DA_QUEUE_TYPE" = ConcurrentArray ]; then
	sort -n "$RSYSLOG_OUT_LOG" > "${RSYSLOG_OUT_LOG}.sorted"
	seq -f '%08g' 0 $((NUMMESSAGES - 1)) > "${RSYSLOG_OUT_LOG}.expected"
	diff -u "${RSYSLOG_OUT_LOG}.expected" "${RSYSLOG_OUT_LOG}.sorted" ||
		error_exit 1 "ConcurrentArray constrained DA child lost or duplicated accepted work"
else
	seq_check
fi
max_usage=$(grep 'disk.usage=' "$STATS_FILE" | sed -E 's/.*disk\.usage=([0-9]+).*/\1/' |
	sort -n | tail -n 1)
if [ "${max_usage:-0}" -gt 66560 ]; then
	printf 'FAIL: segmented DA sampled usage %s exceeds the 64 KiB limit plus one record\n' "$max_usage"
	cat "$STATS_FILE"
	error_exit 1
fi
rm -rf "${RSYSLOG_DYNNAME}.spool"
exit_test
