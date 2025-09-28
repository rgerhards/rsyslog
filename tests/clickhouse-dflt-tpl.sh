#!/bin/bash
# add 2018-12-07 by Pascal Withopf, released under ASL 2.0
. ${srcdir:=.}/diag.sh init
export NUMMESSAGES=1
generate_conf
add_conf "module(load=\"../plugins/omclickhouse/.libs/omclickhouse\")

:syslogtag, contains, \"tag\" action(type=\"omclickhouse\" $(clickhouse_action_params) bulkmode=\"off\"
                                        user=\"default\" pwd=\"\")
"

clickhouse_query "CREATE TABLE IF NOT EXISTS rsyslog.SystemEvents ( severity Int8, facility Int8, timestamp DateTime, hostname String, tag String, message String ) ENGINE = MergeTree() PARTITION BY severity order by tuple()"

startup
injectmsg
shutdown_when_empty
wait_shutdown
clickhouse_query "SELECT * FROM rsyslog.SystemEvents FORMAT CSV" > $RSYSLOG_OUT_LOG

clickhouse_query "DROP TABLE rsyslog.SystemEvents"
content_check --regex '7,20,"20..-03-01 01:00:00","192.0.2.8","tag"," msgnum:00000000:"'

exit_test
