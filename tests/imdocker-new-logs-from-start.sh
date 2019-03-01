#!/bin/bash
# This is part of the rsyslog testbench, licensed under ASL 2.0
# imdocker unit tests are enabled with --enable-imdocker-tests
. ${srcdir:=.}/diag.sh init
#export RS_REDIR=-d
generate_conf
add_conf '
#template(name="template_msg_only" type="string" string="%msg%\n")
template(name="outfmt" type="string" string="%$!metadata!Names% %msg%\n")
module(load="../contrib/imdocker/.libs/imdocker" PollingInterval="1"
        GetContainerLogOptions="tail=1&timestamps=0&follow=1&stdout=1&stderr=0&tail=1"
        RetrieveNewLogsFromStart="on"
        )
action(type="omfile" template="outfmt"  file="'$RSYSLOG_OUT_LOG'")
'

#NUM_ITEMS=1000
# launch a docker runtime to generate some logs.
# these log items should be tailed.
docker run \
   --rm \
   -e seq_start=101 \
   -e seq_end=200 \
   alpine \
   /bin/sh -c 'for i in `seq $seq_start $seq_end`; do echo "tailed item $i"; sleep .01; done' > /dev/null &

sleep 1

startup
NUMMESSAGES=1000
# launch a docker runtime to generate some logs.
# These logs started after start-up should get from beginning
docker run \
   --name $RSYSLOG_DYNNAME \
   --rm \
   -e NUMMESSAGES=$NUMMESSAGES \
   alpine \
   /bin/sh -c 'for i in `seq 1 $NUMMESSAGES`; do echo "log item $i"; sleep .01; done' > /dev/null

content_check_with_count "$RSYSLOG_DYNNAME log item" $NUMMESSAGES
echo "file name: $RSYSLOG_OUT_LOG"
echo "\"tailed item\" occured: $(grep -c 'tailed item ' $RSYSLOG_OUT_LOG)/100 (expect less)."
shutdown_immediate
exit_test

