#!/bin/bash
# add 2018-12-07 by Pascal Withopf, released under ASL 2.0
. ${srcdir:=.}/diag.sh init
echo looks like clickhouse does no longer generate exceptions on error - skip until investigated
exit 77
export NUMMESSAGES=1
generate_conf
cat <<'RSYSLOG_CONF' >> ${TESTCONF_NM}.conf
module(load="../plugins/omclickhouse/.libs/omclickhouse")

template(name="outfmt" option.stdsql="on" type="string" string="INSERT INTO rsyslog.wrongInsertSyntax (id, severity, facility, timestamp, ipaddress, tag, message) VLUES (%msg:F,58:2%, %syslogseverity%, %syslogfacility%, '%timereported:::date-unixtimestamp%', '%fromhost-ip%', '%syslogtag%', '%msg%')")
RSYSLOG_CONF

add_conf "
:syslogtag, contains, \"tag\" action(type=\"omclickhouse\" $(clickhouse_action_params)
                                        user=\"default\" pwd=\"\" template=\"outfmt\"
                                        bulkmode=\"off\" errorfile=\"$RSYSLOG_OUT_LOG\")
"

clickhouse_query "CREATE TABLE IF NOT EXISTS rsyslog.wrongInsertSyntax ( id Int32, severity Int8, facility Int8, timestamp DateTime, ipaddress String, tag String, message String ) ENGINE = MergeTree() PARTITION BY severity Order By id"

startup
injectmsg
shutdown_when_empty
wait_shutdown

clickhouse_query "DROP TABLE rsyslog.wrongInsertSyntax"
content_check "DB::Exception: Syntax error"
exit_test
