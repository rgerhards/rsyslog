#!/bin/bash
# Validate imptcp MaxSessions rejects non-positive values
# added 2026-04-16 by AI-Agent
#
# This file is part of the rsyslog project, released  under GPLv3
. ${srcdir:=.}/diag.sh init
export RS_REDIR=">${RSYSLOG_DYNNAME}.rsyslog.log 2>&1"
LOGFILE="${RSYSLOG_DYNNAME}.rsyslog.log"

check_invalid_maxsessions() {
	local expected="$1"

	rm -rf "${RSYSLOG_DYNNAME}.spool"
	if rsyslogd_config_check; then
		echo "Expected configuration failure for maxsessions=\"$expected\""
		exit 1
	fi

	content_check "parameter 'maxsessions' cannot be less than one" "$LOGFILE"
	rm -f "$LOGFILE"
}

generate_conf
add_conf '
module(load="../plugins/imptcp/.libs/imptcp" maxsessions="0")
input(type="imptcp" port="514")
'
check_invalid_maxsessions "0"

generate_conf
add_conf '
module(load="../plugins/imptcp/.libs/imptcp")
input(type="imptcp" port="514" maxsessions="-1")
'
check_invalid_maxsessions "-1"

exit_test
