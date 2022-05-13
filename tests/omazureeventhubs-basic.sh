#!/bin/bash
# added 2017-05-03 by alorbach
# This file is part of the rsyslog project, released under ASL 2.0
. ${srcdir:=.}/diag.sh init

export TESTMESSAGES=10000
export TESTMESSAGESFULL=$TESTMESSAGES

# REQUIRES EXTERNAL ENVIRONMENT VARIABLES
if [[ -z "${AZURE_HOST}" ]]; then
	echo "FATAL ERROR: AZURE_HOST environment variable not SET! Example: <yourname>.servicebus.windows.net - SKIPPING"
	exit 77
fi
if [[ -z "${AZURE_PORT}" ]]; then
	echo "FATAL ERROR: AZURE_PORT environment variable not SET! Example: 5671 - SKIPPING"
	exit 77
fi
if [[ -z "${AZURE_KEY_NAME}" ]]; then
	echo "FATAL ERROR: AZURE_KEY_NAME environment variable not SET! Example: <yourkeyname> - SKIPPING"
	exit 77
fi
if [[ -z "${AZURE_KEY}" ]]; then
	echo "FATAL ERROR: AZURE_KEY environment variable not SET! Example: <yourlongkey> - SKIPPING"
	exit 77
fi
if [[ -z "${AZURE_NAME}" ]]; then
	echo "FATAL ERROR: AZURE_NAME environment variable not SET! Example: <youreventhubsname> - SKIPPING"
	exit 77
fi
export AZURE_ENDPOINT="Endpoint=sb://$AZURE_HOST/;SharedAccessKeyName=$AZURE_KEY_NAME;SharedAccessKey=$AZURE_KEY;EntityPath=$AZURE_NAME"
export CONTAINERNAME="rsyslogd-omazureeventhubs"

# --- Create/Start omazureeventhubs sender config 
export RSYSLOG_DEBUG="debug nostdout noprintmutexaction"
export RSYSLOG_DEBUGLOG="$RSYSLOG_DYNNAME.debuglog"
generate_conf
add_conf '
# impstats in order to gain insight into error cases
module(load="../plugins/impstats/.libs/impstats"
	log.file="'$RSYSLOG_DYNNAME.pstats'"
	interval="1" log.syslog="off")
main_queue(queue.timeoutactioncompletion="60000" queue.timeoutshutdown="60000")
$imdiagInjectDelayMode full

# module(load="../contrib/omamqp1/.libs/omamqp1")
module(load="../plugins/omazureeventhubs/.libs/omazureeventhubs")
template(name="outfmt" type="string" string="%msg:F,58:2%\n")

local4.* {
	action(	name="omazureeventhubs"
	type="omazureeventhubs"
	azurehost="'$AZURE_HOST'"
	azureport="'$AZURE_PORT'"
	azure_key_name="'$AZURE_KEY_NAME'"
	azure_key="'$AZURE_KEY'"
	container="'$CONTAINERNAME'"
#	amqp_address="amqps://'$AZURE_KEY_NAME':'$AZURE_KEY'@'$AZURE_HOST'/'$AZURE_NAME'"
	instance="'$AZURE_NAME'"
	template="outfmt"
	failedMsgFile="'$RSYSLOG_OUT_LOG'-failed-'$AZURE_NAME'.data"
#	action.resumeInterval="1"
#	action.resumeRetryCount="2"
	queue.saveonshutdown="on"
	)

	action( type="omfile" file="'$RSYSLOG_OUT_LOG'")
	stop
}

action( type="omfile" file="'$RSYSLOG_DYNNAME.othermsg'")
'
echo Starting sender instance [omazureeventhubs]
startup

echo Inject messages into rsyslog sender instance  
injectmsg 1 $TESTMESSAGES

wait_file_lines $RSYSLOG_OUT_LOG $TESTMESSAGESFULL 100

# experimental: wait until kafkacat receives everything
timeoutend=10
timecounter=0

echo "CHECK $RSYSLOG_DYNNAME.pstats"
while [ $timecounter -lt $timeoutend ]; do
	(( timecounter++ ))

	# Read IMPSTATS for verification
	IMPSTATSLINE=`cat $RSYSLOG_DYNNAME.pstats | grep "origin\=omazureeventhubs" | tail -1 | cut -d: -f5`
	SUBMITTED_MSG=`echo $IMPSTATSLINE | grep "submitted" | cut -d" " -f2 | cut -d"=" -f2`
	FAILED_MSG=`echo $IMPSTATSLINE | grep "failures" | cut -d" " -f3 | cut -d"=" -f2`
	ACCEPTED_MSG=`echo $IMPSTATSLINE | grep "accepted" | cut -d" " -f4 | cut -d"=" -f2`

	if ! [[ $SUBMITTED_MSG =~ $re ]] ; then
		echo "**** omazureeventhubs WAITING FOR IMPSTATS"
	else
		if [ "$SUBMITTED_MSG" -eq "$TESTMESSAGESFULL" ]; then
			if [ "$ACCEPTED_MSG" -eq "$TESTMESSAGESFULL" ]; then
				echo "**** omazureeventhubs SUCCESS: SUBMITTED_MSG:$SUBMITTED_MSG, ACCEPTED_MSG: $ACCEPTED_MSG, FAILED_MSG: $FAILED_MSG"
				shutdown_when_empty
				wait_shutdown
				exit_test
			else
				echo "**** omazureeventhubs SUBMITTED/WAITING: SUBMITTED_MSG:$SUBMITTED_MSG, ACCEPTED_MSG: $ACCEPTED_MSG, FAILED_MSG: $FAILED_MSG"
			fi
		else
			echo "**** omazureeventhubs WAITING: SUBMITTED_MSG:$SUBMITTED_MSG, ACCEPTED_MSG: $ACCEPTED_MSG, FAILED_MSG: $FAILED_MSG"
		fi
	fi
	$TESTTOOL_DIR/msleep 1000
done
unset count

shutdown_when_empty
wait_shutdown
error_exit 1
