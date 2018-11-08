#!/bin/bash
# This file is part of the rsyslog project, released under ASL 2.0
. ${srcdir:=.}/diag.sh init
export ES_DOWNLOAD=elasticsearch-6.0.0.tar.gz
export ES_PORT=19200
prepare_elasticsearch
start_elasticsearch

init_elasticsearch
generate_conf
add_conf '
template(name="tpl" type="string"
	 string="{\"msgnum\":\"%msg:F,58:2%\"}")

module(load="../plugins/omelasticsearch/.libs/omelasticsearch")
:msg, contains, "msgnum:" action(type="omelasticsearch"
				 template="tpl"
				 serverport=`echo $ES_PORT`
				 searchIndex="rsyslog_testbench"
				 errorFile="./'${RSYSLOG_DYNNAME}.errorfile'")
'
startup
injectmsg  0 10000
shutdown_when_empty
wait_shutdown 
es_getdata 10000 $ES_PORT
if [ -f ${RSYSLOG_DYNNAME}.errorfile ]; then
    echo "error: error file exists!"
    error_exit 1
fi
seq_check  0 9999
cleanup_elasticsearch
exit_test
