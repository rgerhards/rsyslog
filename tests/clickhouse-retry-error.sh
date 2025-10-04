#!/bin/bash
# add 2018-12-31 by Pascal Withopf, released under ASL 2.0
. ${srcdir:=.}/diag.sh init
export NUMMESSAGES=1
generate_conf
add_conf "module(load=\"../plugins/omclickhouse/.libs/omclickhouse\")

template(name=\"outfmt\" option.stdsql=\"on\" type=\"string\" string=\"INSERT INTO rsyslog.retryerror (id, severity, message) VALUES (%msg:F,58:2%, %syslogseverity%, '%msg%')\")

:syslogtag, contains, \"tag\" action(type=\"omclickhouse\" $(clickhouse_action_params \"off\" 65535)
                                        bulkmode=\"off\" user=\"default\" pwd=\"\"
                                        template=\"outfmt\")

action(type=\"omfile\" file=\"$RSYSLOG_OUT_LOG\")
"

startup
injectmsg
shutdown_when_empty
wait_shutdown

content_check "omclickhouse: checkConn failed."

exit_test
