#!/bin/bash
## tpl-format-json-canonical-basic.sh
## Validate format="json-canonical" default typing and escaping.
. ${srcdir:=.}/diag.sh init

generate_conf
add_conf '
set $!string = "Line \"one\"";
set $!integer = "-42";
set $!decimal = "3.14";
set $!boolTrue = "true";
set $!boolFalse = "false";
set $!null = "null";

template(name="canon" type="list" format="json-canonical") {
        property(outname="string" name="$!string")
        property(outname="integer" name="$!integer")
        property(outname="decimal" name="$!decimal")
        property(outname="boolTrue" name="$!boolTrue")
        property(outname="boolFalse" name="$!boolFalse")
        property(outname="nullField" name="$!null")
}

:msg, contains, "msgnum:" action(type="omfile" file="'${RSYSLOG_OUT_LOG}'" template="canon")
'

startup
injectmsg 0 1
shutdown_when_empty
wait_shutdown

export EXPECTED='{"string":"Line \"one\"", "integer":-42, "decimal":3.14, "booltrue":true, "boolfalse":false, "nullfield":null}'
cmp_exact $RSYSLOG_OUT_LOG
exit_test
