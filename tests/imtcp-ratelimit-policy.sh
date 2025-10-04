#!/bin/bash
# Validate imtcp with a YAML-backed ratelimit() policy configuration.
# Added 2025-10-01, released under ASL 2.0.

. ${srcdir:=.}/diag.sh init

export NUMMESSAGES=200
export BURST=5
export RATELIMIT_EXPECTED_LINES=$BURST
export RATELIMIT_OUTPUT_FILE="$RSYSLOG_OUT_LOG"
export RATELIMIT_WAIT_GRACE_SECS=5
export RATELIMIT_SETTLE_SECS=1
export QUEUE_EMPTY_CHECK_FUNC=wait_ratelimit_lines
export RATELIMIT_BURST_LIMIT=$BURST
export RATELIMIT_LOG="$RSYSLOG_DYNNAME.ratelimit.log"

policy_file="$RSYSLOG_DYNNAME.policy.yml"
cat >"$policy_file" <<EOF_POLICY
interval: 10
burst: $BURST
severity: 5
EOF_POLICY

generate_conf
add_conf "
ratelimit(name=\"tcp_yaml\" policy=\"${policy_file}\")

module(load=\"../plugins/imtcp/.libs/imtcp\")

input(type=\"imtcp\" name=\"tcp-yaml\" port=\"0\"
        listenPortFileName=\"'${RSYSLOG_DYNNAME}'.tcpflood_port\"
        ratelimit.name=\"tcp_yaml\")

template(name=\"outfmt\" type=\"string\" string=\"%msg:F,58:2%\\n\")

:msg, contains, \"msgnum:\" action(type=\"omfile\" template=\"outfmt\"
                                 file=\"'${RSYSLOG_OUT_LOG}'\")

:msg, contains, \"begin to drop messages due to rate-limiting\" action(type=\"omfile\"
                                 file=\"'${RATELIMIT_LOG}'\")
"

# Validate configuration before running so we can skip gracefully if libyaml is missing.
verify_log="$RSYSLOG_DYNNAME.verify.log"
if ! ../tools/rsyslogd -N1 -f${TESTCONF_NM}.conf -M../runtime/.libs:../.libs >"$verify_log" 2>&1; then
    if grep -q "libyaml support" "$verify_log"; then
        cat "$verify_log"
        echo "Skipping test because rsyslogd lacks libyaml support"
        skip_test
    fi
    cat "$verify_log"
    error_exit 1
fi
rm -f "$verify_log"

startup
tcpflood -m $NUMMESSAGES
shutdown_when_empty
wait_shutdown

assert_ratelimit_delivery

content_check --regex "tcp-yaml from <.*>: begin to drop messages due to rate-limiting" "$RATELIMIT_LOG"

exit_test
