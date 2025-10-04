#!/bin/bash
## @brief Exercise the omhttp test server's HEC validation helpers
# This file is part of the rsyslog project, released under ASL 2.0

. ${srcdir:=.}/diag.sh init

hec_endpoint="services/collector/event"

# Enable HEC validation and force a deterministic retry failure after the first success
omhttp_start_server 0 \
    --validate-hec \
    --hec-fail-after 1 \
    --hec-fail-message 'intentional hec validation failure'

send_hec_request() {
    local body="$1"
    local outfile="$2"
    curl -s -o "$outfile" -w "%{http_code}" \
        -H 'Content-Type: application/json' \
        --data "$body" \
        "http://localhost:${omhttp_server_lstnport}/${hec_endpoint}"
}

valid_payload_one='{"event":{"msgnum":"0"},"host":"testbench"}'
valid_payload_two='{"event":{"msgnum":"1"},"host":"testbench"}'
invalid_payload='{"host":"testbench"}'

response_file="$RSYSLOG_DYNNAME/hec-response.json"
mkdir -p "$RSYSLOG_DYNNAME"

status=$(send_hec_request "$valid_payload_one" "$response_file")
if [ "$status" != "200" ]; then
    echo "expected first payload to succeed, got HTTP $status"
    cat "$response_file"
    error_exit 1
fi

status=$(send_hec_request "$valid_payload_two" "$response_file")
if [ "$status" != "400" ]; then
    echo "expected second payload to fail with simulated validation error, got HTTP $status"
    cat "$response_file"
    error_exit 1
fi
if ! grep -q 'intentional hec validation failure' "$response_file"; then
    echo "missing simulated failure message in response"
    cat "$response_file"
    error_exit 1
fi

status=$(send_hec_request "$invalid_payload" "$response_file")
if [ "$status" != "400" ]; then
    echo "expected malformed payload to fail validation, got HTTP $status"
    cat "$response_file"
    error_exit 1
fi
if ! grep -q 'missing required "event" field' "$response_file"; then
    echo "validation error response did not mention missing event"
    cat "$response_file"
    error_exit 1
fi

# Only the first, valid payload should be stored.
omhttp_get_data "$omhttp_server_lstnport" "$hec_endpoint" hec
EXPECTED="0"
cmp_exact "$RSYSLOG_OUT_LOG"

omhttp_stop_server
exit_test
