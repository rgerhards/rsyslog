#!/bin/bash
## tpl-format-legacy-fallback.sh
## Ensure legacy option.json/option.jsonf behavior remains unchanged.
. ${srcdir:=.}/diag.sh init

generate_conf
add_conf '
template(name="legacy" type="list" option.json="on" option.jsonf="on") {
        property(outname="message" name="msg" format="jsonf")
        constant(outname="@version" value="1" format="jsonf")
}

:msg, contains, "msgnum:" action(type="omfile" file="'${RSYSLOG_OUT_LOG}'" template="legacy")
'

startup
injectmsg 0 1
shutdown_when_empty
wait_shutdown

export EXPECTED='\"message\":\" msgnum:00000000:\""@version": "1"'
printf '%s' "$EXPECTED" >"${RSYSLOG_OUT_LOG}.expected"
if ! cmp -s "${RSYSLOG_OUT_LOG}.expected" "$RSYSLOG_OUT_LOG"; then
        echo "invalid response generated"
        echo "################# $RSYSLOG_OUT_LOG is:"
        cat -n "$RSYSLOG_OUT_LOG"
        echo "################# EXPECTED was:"
        cat -n "${RSYSLOG_OUT_LOG}.expected"
        echo
        echo "#################### diff is:"
        diff -u "${RSYSLOG_OUT_LOG}.expected" "$RSYSLOG_OUT_LOG"
        exit 1
fi
rm -f "${RSYSLOG_OUT_LOG}.expected"
exit_test
