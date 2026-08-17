#!/bin/bash
# Ensure strict dynafile template-type mode rejects templates that cannot be inspected.
. ${srcdir:=.}/diag.sh init

generate_conf
add_conf '
module(load="builtin:omfile" dynafile.restrictTemplateType="on")

template(name="dynfile" type="subtree" subtree="$!dynfile")
template(name="outfmt" type="string" string="%msg:F,58:2%\n")

if $msg contains "msgnum:" then {
	set $!dynfile = "'$RSYSLOG_OUT_LOG'";
	action(type="omfile" dynafile="dynfile" template="outfmt")
}
'

../tools/rsyslogd -C -N1 -M"$RSYSLOG_MODDIR" -f"${TESTCONF_NM}.conf" \
	>"${RSYSLOG_DYNNAME}.log" 2>&1
if [ $? -ne 1 ]; then
	echo "FAIL: expected config validation failure for subtree dynafile template"
	cat "${RSYSLOG_DYNNAME}.log"
	error_exit 1
fi

grep -F "dynafile template 'dynfile' uses a template type that cannot be safely inspected" \
	"${RSYSLOG_DYNNAME}.log" >/dev/null || {
	echo "FAIL: expected dynafile template type validation error"
	cat "${RSYSLOG_DYNNAME}.log"
	error_exit 1
}

exit_test
