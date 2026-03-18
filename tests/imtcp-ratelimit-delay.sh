#!/bin/bash
# Validate ratelimit exceedAction=delay keeps messages and emits delay stats.

. ${srcdir:=.}/diag.sh init
export NUMMESSAGES=40
export QUEUE_EMPTY_CHECK_FUNC=wait_file_lines
export STATSFILE="$RSYSLOG_DYNNAME.stats"

wait_for_stats_metric() {
    local pattern="$1"
    local file="$2"
    local timeout_ms="${3:-30000}"
    local interval_ms=100
    local waited_ms=0

    while true; do
        if [ -f "$file" ] && grep -q "$pattern" "$file"; then
            return 0
        fi

        if [ "$waited_ms" -ge "$timeout_ms" ]; then
            echo "FAIL: stats metric pattern '$pattern' not found in '$file' within ${timeout_ms}ms"
            if [ -f "$file" ]; then
                echo "stats file contents:"
                cat "$file"
            fi
            error_exit 1
        fi

        $TESTTOOL_DIR/msleep $interval_ms
        waited_ms=$((waited_ms + interval_ms))
    done
}

wait_for_exceeded_delayed_gt_zero() {
    local file="$1"
    local timeout_ms="${2:-30000}"
    local interval_ms=100
    local waited_ms=0
    local delayed

    while true; do
        delayed=$(awk -F'[:= ]+' '/ratelimit.rl_delay:/ {for(i=1;i<=NF;i++) if($i=="exceeded_delayed") v=$(i+1)} END{print v+0}' "$file" 2>/dev/null)
        if [ "$delayed" -gt 0 ]; then
            return 0
        fi

        if [ "$waited_ms" -ge "$timeout_ms" ]; then
            echo "FAIL: exceeded_delayed did not become > 0 within ${timeout_ms}ms"
            if [ -f "$file" ]; then
                echo "stats file contents:"
                cat "$file"
            fi
            error_exit 1
        fi

        $TESTTOOL_DIR/msleep $interval_ms
        waited_ms=$((waited_ms + interval_ms))
    done
}

generate_conf
add_conf '
module(load="../plugins/imtcp/.libs/imtcp")
module(load="../plugins/impstats/.libs/impstats" interval="1" log.file="'$STATSFILE'")

main_queue(queue.size="1000")

ratelimit(name="rl_delay"
          interval="60"
          burst="1"
          exceedAction="delay"
          delayQueueFillPercent="95"
          delayUsec="5000")

input(type="imtcp" port="0" listenPortFileName="'$RSYSLOG_DYNNAME'.tcp.port" ratelimit.name="rl_delay")

template(name="outfmt" type="string" string="%msg%\n")
if $msg contains "msgnum:" then action(type="omfile" file="'$RSYSLOG_OUT_LOG'" template="outfmt")
'

startup
./tcpflood -p"$(cat $RSYSLOG_DYNNAME.tcp.port)" -m "$NUMMESSAGES"
wait_for_stats_metric "ratelimit.rl_delay:" "$STATSFILE"
wait_for_exceeded_delayed_gt_zero "$STATSFILE"
shutdown_when_empty
wait_shutdown

content_count=$(grep -c "msgnum:" "$RSYSLOG_OUT_LOG")
if [ "$content_count" -ne "$NUMMESSAGES" ]; then
    echo "FAIL: expected $NUMMESSAGES messages, got $content_count"
    error_exit 1
fi

delayed=$(awk -F'[:= ]+' '/ratelimit.rl_delay:/ {for(i=1;i<=NF;i++) if($i=="exceeded_delayed") v=$(i+1)} END{print v}' "$STATSFILE")
dropped=$(awk -F'[:= ]+' '/ratelimit.rl_delay:/ {for(i=1;i<=NF;i++) if($i=="exceeded_dropped") v=$(i+1)} END{print v}' "$STATSFILE")

delayed=${delayed:-0}
dropped=${dropped:-0}

echo "delayed=$delayed dropped=$dropped"
if [ "$delayed" -le 0 ]; then
    echo "FAIL: expected exceeded_delayed > 0"
    error_exit 1
fi
if [ "$dropped" -ne 0 ]; then
    echo "FAIL: expected exceeded_dropped == 0"
    error_exit 1
fi

exit_test
