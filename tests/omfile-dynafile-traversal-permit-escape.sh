#!/bin/bash
# Ensure the dangerous dynafile path escape override is explicit.
. ${srcdir:=.}/diag.sh init
require_plugin imtcp

export TRAVERSAL_APP="${RSYSLOG_DYNNAME}-omfile-permit-path-escape"
export TRAVERSAL_ROOT="${RSYSLOG_DYNNAME}.jail"
export TRAVERSAL_OUT="${TRAVERSAL_ROOT}/escape/${TRAVERSAL_APP}.log"
export PROTECTED_OUT="${TRAVERSAL_ROOT}/escape/${TRAVERSAL_APP}.protected.log"
rm -rf "$TRAVERSAL_ROOT"
mkdir -p "${TRAVERSAL_ROOT}/base" "${TRAVERSAL_ROOT}/base-protected" "${TRAVERSAL_ROOT}/escape"

generate_conf
add_conf '
module(load="builtin:omfile")
module(load="../plugins/imtcp/.libs/imtcp")
input(type="imtcp" port="0" listenPortFileName="'$RSYSLOG_DYNNAME'.tcpflood_port")
template(name="dynfile" type="string" string="'$TRAVERSAL_ROOT'/base/%HOSTNAME%/%APP-NAME%.log")
template(name="dynfile_protected" type="string" string="'$TRAVERSAL_ROOT'/base-protected/%HOSTNAME%/%APP-NAME%.protected.log")
template(name="outfmt" type="string" string="%msg%\n")

$rulesetparser rsyslog.rfc5424
local4.debug action(type="omfile" dynafile="dynfile" template="outfmt"
                    dynafile.dangerousPermitPathEscape="on")
local4.debug action(type="omfile" dynafile="dynfile_protected" template="outfmt")
'

../tools/rsyslogd -C -N1 -M"$RSYSLOG_MODDIR" -f"${TESTCONF_NM}.conf" \
	>"${RSYSLOG_DYNNAME}.log" 2>&1
if [ $? -ne 0 ]; then
	echo "FAIL: action-level dangerous dynafile path escape warning rejected the configuration"
	cat "${RSYSLOG_DYNNAME}.log"
	error_exit 1
fi

startup
printf '<167>1 2003-03-01T01:00:00.000Z ../escape %s - - - permit-path-escape\n' \
	"$TRAVERSAL_APP" > "${RSYSLOG_DYNNAME}.input"
tcpflood -B -I "${RSYSLOG_DYNNAME}.input"
shutdown_when_empty
wait_shutdown

if [ ! -f "$TRAVERSAL_OUT" ]; then
	echo "FAIL: dangerous dynafile path escape override did not create $TRAVERSAL_OUT"
	error_exit 1
fi

if [ -f "$PROTECTED_OUT" ]; then
	echo "FAIL: per-action dangerous dynafile path escape leaked into protected action: $PROTECTED_OUT"
	error_exit 1
fi

rm -rf "$TRAVERSAL_ROOT"
exit_test
