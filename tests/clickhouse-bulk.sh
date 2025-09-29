#!/bin/bash
# add 2018-12-07 by Pascal Withopf, released under ASL 2.0
. ${srcdir:=.}/diag.sh init
export NUMMESSAGES=10
generate_conf
add_conf "module(load=\"../plugins/omclickhouse/.libs/omclickhouse\")

template(name=\"outfmt\" option.stdsql=\"on\" type=\"string\" string=\"INSERT INTO rsyslog.bulk (id, severity, facility, timestamp, ipaddress, tag, message) VALUES (%msg:F,58:2%, %syslogseverity%, %syslogfacility%, '%timereported:::date-unixtimestamp%', '%fromhost-ip%', '%syslogtag%', '%msg%')\")

:syslogtag, contains, \"tag\" action(type=\"omclickhouse\" $(clickhouse_action_params)
                                        user=\"default\" pwd=\"\" template=\"outfmt\")
"

clickhouse_query "CREATE TABLE IF NOT EXISTS rsyslog.bulk ( id Int32, severity Int8, facility Int8, timestamp DateTime, ipaddress String, tag String, message String ) ENGINE = MergeTree() PARTITION BY severity Order By id"

startup
injectmsg
shutdown_when_empty
wait_shutdown
clickhouse_query "SELECT id, severity, facility, ipaddress, tag, message FROM rsyslog.bulk ORDER BY id" > $RSYSLOG_OUT_LOG

## Verified against ClickHouse 25.9 TabSeparated output (clickhouse local 25.9.2.1).
export EXPECTED='0	7	20	127.0.0.1	tag	 msgnum:00000000:
1	7	20	127.0.0.1	tag	 msgnum:00000001:
2	7	20	127.0.0.1	tag	 msgnum:00000002:
3	7	20	127.0.0.1	tag	 msgnum:00000003:
4	7	20	127.0.0.1	tag	 msgnum:00000004:
5	7	20	127.0.0.1	tag	 msgnum:00000005:
6	7	20	127.0.0.1	tag	 msgnum:00000006:
7	7	20	127.0.0.1	tag	 msgnum:00000007:
8	7	20	127.0.0.1	tag	 msgnum:00000008:
9	7	20	127.0.0.1	tag	 msgnum:00000009:'
cmp_exact $RSYSLOG_OUT_LOG

clickhouse_query "DROP TABLE rsyslog.bulk"
exit_test
