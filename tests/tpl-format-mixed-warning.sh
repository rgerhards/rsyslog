#!/bin/bash
## tpl-format-mixed-warning.sh
## Mixing format= with legacy JSON options should warn once and ignore legacy settings.
. ${srcdir:=.}/diag.sh init

export RS_REDIR=">rsyslog.log 2>&1"

generate_conf
add_conf '
template(name="mixed" type="list" format="json-quoted" option.json="on") {
        property(outname="message" name="msg")
}

:msg, contains, "msgnum:" action(type="omfile" file="'${RSYSLOG_OUT_LOG}'" template="mixed")
'

startup
injectmsg 0 1
shutdown_when_empty
wait_shutdown

export EXPECTED='{"message":" msgnum:00000000:"}'
cmp_exact $RSYSLOG_OUT_LOG

WARN="template 'mixed': legacy JSON/SQL options are ignored because 'format' is set; behavior is controlled by 'format'"
if [ "$(grep -F "$WARN" rsyslog.log | wc -l)" -ne 1 ]; then
        echo "FAIL: expected warning not emitted exactly once"
        cat rsyslog.log
        exit 1
fi

exit_test
