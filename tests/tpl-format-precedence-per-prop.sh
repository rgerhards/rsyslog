#!/bin/bash
## tpl-format-precedence-per-prop.sh
## Verify per-property format overrides template defaults.
. ${srcdir:=.}/diag.sh init

generate_conf
add_conf '
set $!default = "123";
set $!override = "{\"explicit\":true}";
set $!text = "value";

template(name="precedence" type="list" format="json-canonical") {
        property(outname="default" name="$!default")
        property(outname="override" name="$!override" format="jsonfr")
        property(outname="text" name="$!text")
}

:msg, contains, "msgnum:" action(type="omfile" file="'${RSYSLOG_OUT_LOG}'" template="precedence")
'

startup
injectmsg 0 1
shutdown_when_empty
wait_shutdown

export EXPECTED='{"default":123, "override":{"explicit":true}, "text":"value"}'
cmp_exact $RSYSLOG_OUT_LOG
exit_test
