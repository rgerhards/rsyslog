#!/bin/bash
##
## run-omhttp-hec-smoketest.sh
## ---------------------------
## Execute a minimal omhttp-to-Splunk HEC smoke test inside the dev container.
##
## The script builds rsyslog with the contrib/omhttp module enabled, starts a
## transient rsyslogd instance that tails a temporary file via imfile, forwards a
## sample message to the configured Splunk HTTP Event Collector endpoint, and
## shuts down again. The Splunk host, port, scheme and HEC token are read from
## environment variables so the surrounding CI job can inject its runtime
## configuration.
##
## Required environment variables:
##   * SPLUNK_HEC_TOKEN  – authentication token to place in the Authorization
##                          header (required)
##
## Optional environment variables:
##   * SPLUNK_HEC_HOST         – hostname or IP of the HEC endpoint (default 127.0.0.1)
##   * SPLUNK_HEC_PORT         – TCP port of the HEC endpoint (default 8088)
##   * SPLUNK_HEC_SCHEME       – either "https" or "http" (default https)
##   * SPLUNK_HEC_ALLOW_UNSIGNED – set to "on" to skip TLS verification when
##                                  using https (default on)
##   * OMHTTP_HEC_TEST_MESSAGE – payload string to send (default omhttp-hec-smoke)
##
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
TOKEN=${SPLUNK_HEC_TOKEN:?SPLUNK_HEC_TOKEN must be set}
HEC_HOST=${SPLUNK_HEC_HOST:-127.0.0.1}
HEC_PORT=${SPLUNK_HEC_PORT:-8088}
HEC_SCHEME=${SPLUNK_HEC_SCHEME:-https}
HEC_ALLOW_UNSIGNED=${SPLUNK_HEC_ALLOW_UNSIGNED:-on}
TEST_MESSAGE=${OMHTTP_HEC_TEST_MESSAGE:-omhttp-hec-smoke}

if [ -n "${LD_LIBRARY_PATH:-}" ]; then
    export LD_LIBRARY_PATH="${ROOT_DIR}/runtime/.libs:${ROOT_DIR}/.libs:${LD_LIBRARY_PATH}"
else
    export LD_LIBRARY_PATH="${ROOT_DIR}/runtime/.libs:${ROOT_DIR}/.libs"
fi

cd "$ROOT_DIR"

if [ ! -x configure ]; then
    ./autogen.sh
fi

./configure --enable-omhttp
make -j"$(nproc)"

WORK_DIR=$(mktemp -d)
CONF_FILE="${WORK_DIR}/rsyslog-hec.conf"
INPUT_FILE="${WORK_DIR}/hec-input.log"
PID_FILE="${WORK_DIR}/rsyslog.pid"
STATE_FILE="${WORK_DIR}/hec-input.state"

cat <<CFG >"$CONF_FILE"
module(load="${ROOT_DIR}/plugins/imfile/.libs/imfile")
module(load="${ROOT_DIR}/contrib/omhttp/.libs/omhttp")

global(
    workDirectory="${WORK_DIR}"
)

template(name="splunk-hec-jsonf" type="list" subtype="jsonf") {
    property(outname="event" name="msg")
    property(outname="host" name="hostname")
    property(outname="time" name="timereported" dateFormat="unixtimestamp")
    property(outname="severity" name="syslogseverity-text")
    property(outname="facility" name="syslogfacility-text")
    property(outname="app" name="app-name")
}

input(
    type="imfile"
    File="${INPUT_FILE}"
    Tag="hec-smoke"
    PersistStateInterval="1"
    statefile="${STATE_FILE}"
)

action(
    type="omhttp"
    name="send_to_splunk_hec"
    server="${HEC_HOST}"
    serverport="${HEC_PORT}"
    restpath="services/collector/event"
    template="splunk-hec-jsonf"
    batch="off"
    action.resumeRetryCount="-1"
    httpheaderkey="Authorization"
    httpheadervalue="Splunk ${TOKEN}"
CFG

if [ "$HEC_SCHEME" = "https" ]; then
    cat <<CFG >>"$CONF_FILE"
    usehttps="on"
    allowunsignedcerts="${HEC_ALLOW_UNSIGNED}"
CFG
else
    cat <<CFG >>"$CONF_FILE"
    usehttps="off"
CFG
fi

cat <<'CFG' >>"$CONF_FILE"
)
CFG

: >"$INPUT_FILE"

./tools/rsyslogd -N1 -f "$CONF_FILE"
./tools/rsyslogd -n -f "$CONF_FILE" -i "$PID_FILE" &
RSYSLOG_PID=$!
trap 'kill "$RSYSLOG_PID" 2>/dev/null || true' EXIT

sleep 3
echo "$TEST_MESSAGE" >>"$INPUT_FILE"

for _ in {1..30}; do
    if ! kill -0 "$RSYSLOG_PID" 2>/dev/null; then
        break
    fi
    sleep 1
done

if kill -0 "$RSYSLOG_PID" 2>/dev/null; then
    kill "$RSYSLOG_PID"
fi

set +e
wait "$RSYSLOG_PID"
STATUS=$?
set -e
trap - EXIT

if [ "$STATUS" -ne 0 ] && [ "$STATUS" -ne 143 ]; then
    exit "$STATUS"
fi

rm -rf "$WORK_DIR"
