#!/bin/bash
## tpl-format-json-quoted-basic.sh
## Validate format="json-quoted" default escaping and quoting.
. ${srcdir:=.}/diag.sh init

generate_conf
add_conf '
set $!text = "Hello \"world\"";
set $!number = "42";

template(name="quoted" type="list" format="json-quoted") {
        property(outname="text" name="$!text")
        property(outname="number" name="$!number")
}

:msg, contains, "msgnum:" action(type="omfile" file="'${RSYSLOG_OUT_LOG}'" template="quoted")
'

startup
injectmsg 0 1
shutdown_when_empty
wait_shutdown

export EXPECTED='{"text":"Hello \"world\"", "number":"42"}'
cmp_exact $RSYSLOG_OUT_LOG
exit_test
