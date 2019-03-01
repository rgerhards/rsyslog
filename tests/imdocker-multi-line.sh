#!/bin/bash
# This is part of the rsyslog testbench, licensed under ASL 2.0

# imdocker unit tests are enabled with --enable-imdocker-tests
. ${srcdir:=.}/diag.sh init

generate_conf
add_conf '
template(name="outfmt" type="string" string="%$!metadata!Names% %msg%\n")

module(load="../contrib/imdocker/.libs/imdocker" PollingInterval="1"
        GetContainerLogOptions="timestamps=0&follow=1&stdout=1&stderr=0")

if $inputname == "imdocker" then {
  action(type="omfile" template="outfmt"  file="'$RSYSLOG_OUT_LOG'")
}
'

#export RS_REDIR=-d
startup
NUM_ITEMS=1000
# launch a docker runtime to generate some logs.
# These logs started after start-up should get from beginning

docker run \
  --name $RSYSLOG_DYNNAME \
  --rm \
  -e num_items=$NUM_ITEMS \
  -l imdocker.startregex=^multi-line: \
  alpine \
  /bin/sh -c \
  'for i in `seq 1 $num_items`; do printf "multi-line: $i\n line2....\n line3....\n"; sleep .01; done' > /dev/null

NUM_EXPECTED=$((NUM_ITEMS - 1))
echo "expected: $NUM_EXPECTED"

content_check_with_count "$RSYSLOG_DYNNAME multi-line:" $NUM_EXPECTED
## check if all the data we expect to get in the file is there
for i in $(seq 1 $NUM_EXPECTED); do
  grep "$RSYSLOG_DYNNAME multi-line: $i#012 line2....#012 line3...." $RSYSLOG_OUT_LOG > /dev/null 2>&1
  if [ ! $? -eq 0 ]; then
    echo "ERROR: expecting the string $RSYSLOG_DYNNAME multi-line: item '$i', it's not there"
    exit 1
  fi
done

echo "file name: $RSYSLOG_OUT_LOG"
shutdown_immediate
exit_test

