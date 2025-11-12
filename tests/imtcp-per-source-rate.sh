#!/bin/bash
# Validate imtcp per-source rate limiting via YAML policy.
# Added 2025-10-01, released under ASL 2.0.

. ${srcdir:=.}/diag.sh init

# Override get_free_port since python/perl sockets are blocked in this environment.
get_free_port() {
	for _ in $(seq 1 50); do
		port=$(( (RANDOM % 20000) + 25000 ))
		nc -z 127.0.0.1 "$port" >/dev/null 2>&1 || { echo "$port"; return 0; }
	done
	echo 25000
	return 0
}

export QUIET_HOST="quiet-host.test"
export NOISY_HOST="noisy-host.test"
export QUIET_MESSAGES=5
export NOISY_MESSAGES=20
export NOISY_LIMIT=5
export RATELIMIT_LOG="$RSYSLOG_DYNNAME.persource.drop.log"
export QUIET_OUT="$RSYSLOG_DYNNAME.quiet.log"
export NOISY_OUT="$RSYSLOG_DYNNAME.noisy.log"

policy_file="$RSYSLOG_DYNNAME.per_source.yml"
cat >"$policy_file" <<EOF_POLICY
default:
  max: 100
  window: 10s
overrides:
  - key: "$NOISY_HOST"
    max: $NOISY_LIMIT
    window: 10s
EOF_POLICY

generate_conf
add_conf '
module(load="../plugins/imtcp/.libs/imtcp")

input(type="imtcp" name="tcp-per-source" port="0"
	listenPortFileName="'${RSYSLOG_DYNNAME}'.tcpflood_port"
	perSourceRate="on"
	perSourcePolicyFile="'${policy_file}'"
	perSourceKeyTpl=" RSYSLOG_ImtcpPerSourceKey")

template(name="outfmt" type="string" string="%hostname%:%msg:F,58:2%\n")

if $hostname == "'${QUIET_HOST}'" then {
	action(type="omfile" template="outfmt"
	       file="'${QUIET_OUT}'")
	stop
}

if $hostname == "'${NOISY_HOST}'" then {
	action(type="omfile" template="outfmt"
	       file="'${NOISY_OUT}'")
	stop
}

:msg, contains, "per-source key" action(type="omfile"
			         file="'${RATELIMIT_LOG}'")
'

startup
tcpflood -m $QUIET_MESSAGES -h $QUIET_HOST
tcpflood -m $NOISY_MESSAGES -h $NOISY_HOST
shutdown_when_empty
wait_shutdown

quiet_count=$(grep -c "$QUIET_HOST" "$QUIET_OUT")
echo "Quiet host delivered $quiet_count messages"
if [ "$quiet_count" -ne "$QUIET_MESSAGES" ]; then
	echo "Expected $QUIET_MESSAGES quiet messages, got $quiet_count"
	error_exit 1
fi

noisy_count=$(grep -c "$NOISY_HOST" "$NOISY_OUT")
echo "Noisy host delivered $noisy_count messages"
if [ "$noisy_count" -ne "$NOISY_LIMIT" ]; then
	echo "Expected $NOISY_LIMIT noisy messages due to per-source limiter, got $noisy_count"
	error_exit 1
fi

content_check --regex "per-source key '${NOISY_HOST}'.*: begin to drop messages due to rate-limiting" "$RATELIMIT_LOG"

exit_test
