#!/bin/bash
# add 2018-12-19 by Pascal Withopf, released under ASL 2.0
. ${srcdir:=.}/diag.sh init
generate_conf
add_conf "module(load=\"../plugins/imtcp/.libs/imtcp\")
module(load=\"../plugins/omclickhouse/.libs/omclickhouse\")
input(type=\"imtcp\" port=\"0\" listenPortFileName=\"${RSYSLOG_DYNNAME}.tcpflood_port\")

template(name=\"outfmt\" option.stdsql=\"on\" type=\"string\" string=\"INSERT INTO rsyslog.quotation (id, severity, message) VALUES ( 1, %syslogseverity%, '%msg%')\")

:syslogtag, contains, \"tag\" action(type=\"omclickhouse\" $(clickhouse_action_params)
                                        bulkmode=\"off\"
                                        user=\"default\" pwd=\"\" template=\"outfmt\")
"

clickhouse_query "CREATE TABLE IF NOT EXISTS rsyslog.quotation ( id Int32, severity Int8, message String ) ENGINE = MergeTree() PARTITION BY severity Order By id"

startup
tcpflood -m1 -M "\"<130>Mar 10 01:00:00 172.20.245.8 tag:it's a test\""
shutdown_when_empty
wait_shutdown
clickhouse_query "SELECT id, severity, message FROM rsyslog.quotation" > $RSYSLOG_OUT_LOG

## Verified against ClickHouse 25.9 TabSeparated output (clickhouse local 25.9.2.1).
export EXPECTED="1	2	it\\'s a test"
cmp_exact $RSYSLOG_OUT_LOG

clickhouse_query "DROP TABLE rsyslog.quotation"
exit_test
