#!/bin/bash
# This is not a real test, but a script to stop clickhouse. It is
# implemented as test so that we can stop clickhouse at the time we need
# it (do so via Makefile.am).
# Copyright (C) 2018 Pascal Withopf and Adiscon GmbH
# Released under ASL 2.0
. ${srcdir:=.}/diag.sh init

clickhouse_clear_marker

if ! clickhouse_query "SELECT 1" >/dev/null 2>&1; then
        printf 'ClickHouse not reachable, nothing to stop.\n'
        exit_test
fi

clickhouse_query "DROP DATABASE IF EXISTS rsyslog" >/dev/null 2>&1
sleep 1
if [ -n "$CLICKHOUSE_STOP_CMD" ]; then
        printf 'stopping clickhouse...\n'
        #$SUDO sed -n -r 's/PID: ([0-9]+\.*)/\1/p' /var/lib/clickhouse/status > /tmp/clickhouse-server.pid
        #$SUDO kill $($SUDO sed -n -r 's/PID: ([0-9]+\.*)/\1/p' /var/lib/clickhouse/status)
        eval "$CLICKHOUSE_STOP_CMD"
        sleep 1 # cosmetic: give clickhouse a chance to emit shutdown message
else
        printf 'CLICKHOUSE_STOP_CMD not set, leaving external instance running.\n'
fi
exit_test
