#!/bin/bash
## tpl-format-sql-mysql.sh
## format="sql-mysql" must match legacy option.sql escaping.
. ${srcdir:=.}/diag.sh init

generate_conf
add_conf "
set \$!value = \"O\\'Reilly \\\\ path\";

template(name=\"sql_new\" type=\"list\" format=\"sql-mysql\") {
        constant(value=\"INSERT '\")
        property(name=\"\$!value\")
        constant(value=\"'\\n\")
}

template(name=\"sql_legacy\" type=\"list\" option.sql=\"on\") {
        constant(value=\"INSERT '\")
        property(name=\"\$!value\")
        constant(value=\"'\\n\")
}

:msg, contains, \"msgnum:\" action(type=\"omfile\" file=\"${RSYSLOG_OUT_LOG}\" template=\"sql_new\")
:msg, contains, \"msgnum:\" action(type=\"omfile\" file=\"${RSYSLOG_OUT_LOG}_legacy\" template=\"sql_legacy\")
"

startup
injectmsg 0 1
shutdown_when_empty
wait_shutdown

export EXPECTED="INSERT 'O\\'Reilly \\\\ path'"
cmp_exact $RSYSLOG_OUT_LOG

if ! cmp -s "$RSYSLOG_OUT_LOG" "${RSYSLOG_OUT_LOG}_legacy"; then
        echo "FAIL: sql-mysql format differs from legacy option.sql"
        echo '--- new ---'
        cat -n "$RSYSLOG_OUT_LOG"
        echo '--- legacy ---'
        cat -n "${RSYSLOG_OUT_LOG}_legacy"
        exit 1
fi

exit_test
