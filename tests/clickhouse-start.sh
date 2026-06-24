#!/bin/bash
# This is not a real test, but a script to start clickhouse. It is
# implemented as test so that we can start clickhouse at the time we need
# it (do so via Makefile.am).
# Copyright (C) 2018 Pascal Withopf and Adiscon GmbH
# Released under ASL 2.0
. ${srcdir:=.}/diag.sh init
set -x

clickhouse_clear_marker

test_error_exit_handler() {
        printf 'clickhouse startup failed, log is:\n'
        $SUDO cat /var/log/clickhouse-server/clickhouse-server.err.log
}

started_locally=0
if [ -n "$CLICKHOUSE_START_CMD" ]; then
        started_locally=1
        printf 'starting clickhouse...\n'
        eval "$CLICKHOUSE_START_CMD" &
fi

printf 'waiting for clickhouse to become ready...\n'
if ! clickhouse_wait_ready 30 2; then
        if [ $started_locally -eq 1 ]; then
                printf 'clickhouse failed to start within timeout\n'
                error_exit 100
        fi
        printf 'no reachable clickhouse instance, skipping server-backed tests\n'
        clickhouse_mark_unavailable
        exit_test
fi

printf 'preparing clickhouse for testbench use...\n'
prepare_cmd=(env "CLICKHOUSE_CLIENT=$CLICKHOUSE_CLIENT")
prepare_cmd+=("${srcdir}/../devtools/prepare_clickhouse.sh")
if [ -n "$SUDO" ]; then
        if ! $SUDO "${prepare_cmd[@]}"; then
                printf 'clickhouse preparation failed\n'
                error_exit 100
        fi
else
        if ! "${prepare_cmd[@]}"; then
                printf 'clickhouse preparation failed\n'
                error_exit 100
        fi
fi

clickhouse_mark_available
printf 'done, clickhouse ready for testbench\n'
exit_test
