#!/bin/bash
## tpl-format-sql-std.sh
## format="sql-std" must match legacy option.stdsql escaping.
. ${srcdir:=.}/diag.sh init

generate_conf
add_conf "
set \$!value = \"O\\'Reilly \\\\ path\";

template(name=\"sqlstd_new\" type=\"list\" format=\"sql-std\") {
        constant(value=\"INSERT '\")
        property(name=\"\$!value\")
        constant(value=\"'\\n\")
}

template(name=\"sqlstd_legacy\" type=\"list\" option.stdsql=\"on\") {
        constant(value=\"INSERT '\")
        property(name=\"\$!value\")
        constant(value=\"'\\n\")
}

:msg, contains, \"msgnum:\" action(type=\"omfile\" file=\"${RSYSLOG_OUT_LOG}\" template=\"sqlstd_new\")
:msg, contains, \"msgnum:\" action(type=\"omfile\" file=\"${RSYSLOG_OUT_LOG}_legacy\" template=\"sqlstd_legacy\")
"

startup
injectmsg 0 1
shutdown_when_empty
wait_shutdown

export EXPECTED="INSERT 'O''Reilly \ path'"
cmp_exact $RSYSLOG_OUT_LOG

if ! cmp -s "$RSYSLOG_OUT_LOG" "${RSYSLOG_OUT_LOG}_legacy"; then
        echo "FAIL: sql-std format differs from legacy option.stdsql"
        echo '--- new ---'
        cat -n "$RSYSLOG_OUT_LOG"
        echo '--- legacy ---'
        cat -n "${RSYSLOG_OUT_LOG}_legacy"
        exit 1
fi

exit_test
