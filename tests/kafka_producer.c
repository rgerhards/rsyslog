/* a simple (librd)kafka producer
 *
 * Copyright 2017 Rainer Gerhards and Adiscon GmbH.
 *
 * This file is part of the rsyslog project.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *       -or-
 *       see COPYING.ASL20 in the source distribution
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <librdkafka/rdkafka.h>
#include <unistd.h>

static void
errout(char *reason)
{
	perror(reason);
	exit(1);
}

static void
usage(void)
{
	fprintf(stderr, "usage: kafka_producer \n");
	exit (1);
}


static void
produce(void)
{
	char *msg ="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
	char errstr[1024];
	rd_kafka_resp_err_t msg_kafka_response;
	rd_kafka_t *rk;
	rd_kafka_topic_t *rkt = NULL;
	rd_kafka_conf_t *const conf = rd_kafka_conf_new();
	if(rd_kafka_conf_set(conf, "compression.codec" , "snappy", errstr, sizeof(errstr))
		!= RD_KAFKA_CONF_OK) {
		errout("errpr setting compression.codec");
	}
	rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
	if(rk == NULL)
		errout("rk==NULL");
	rd_kafka_topic_conf_t *const topicconf = rd_kafka_topic_conf_new();
	rkt = rd_kafka_topic_new(rk, "static", topicconf);

	printf("Connected to Kafka, begin produce\n");
	for(int i = 0 ; i < 10000 ; ++i) {
		msg_kafka_response = rd_kafka_producev(rk,
						RD_KAFKA_V_RKT(rkt),
						//RD_KAFKA_V_PARTITION(partition),
						RD_KAFKA_V_VALUE(msg, strlen((char*)msg)),
						RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY|RD_KAFKA_MSG_F_FREE),
						//RD_KAFKA_V_TIMESTAMP(ttMsgTimestamp),
						RD_KAFKA_V_END);
		const int cnt = rd_kafka_poll(rk, 0);
		if(cnt > 0)
			printf("poll returned %d\n", cnt);
	}
	printf("done produce\n");
	int queuedCount = rd_kafka_outq_len(rk);
	printf("outq len: %d\n", queuedCount);
	sleep(1);
	printf("past sleep\n");
	const int flushStatus = rd_kafka_flush(rk, 10000);
	printf("flush status: %d\n", flushStatus);
	if (flushStatus != RD_KAFKA_RESP_ERR_NO_ERROR) {
		printf("flush failed: %s\n", rd_kafka_err2str(flushStatus));
		//exit(1);
	}
	queuedCount = rd_kafka_outq_len(rk);
	printf("destroy (outq left: ~ %d)\n", queuedCount);
	rd_kafka_destroy(rk);
}

int
main(int argc, char *argv[])
{
	int fds;
	int fdc;
	int fdf = -1;
	char wrkBuf[4096];
	ssize_t nRead;
	int opt;
	int sleeptime = 0;
	char *targetIP = NULL;
	int targetPort = -1;

#if 0
	while((opt = getopt(argc, argv, "t:p:f:s:")) != -1) {
		switch (opt) {
		case 's':
			sleeptime = atoi(optarg);
			break;
		case 't':
			targetIP = optarg;
			break;
		case 'p':
			targetPort = atoi(optarg);
			break;
		case 'f':
			if(!strcmp(optarg, "-")) {
				fdf = 1;
			} else {
				fdf = open(optarg, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR|S_IWUSR);
				if(fdf == -1) errout(argv[3]);
			}
			break;
		default:
			fprintf(stderr, "invalid option '%c' or value missing - terminating...\n", opt);
			usage();
			break;
		}
	}

	if(targetIP == NULL) {
		fprintf(stderr, "-t parameter missing -- terminating\n");
		usage();
	}
	if(targetPort == -1) {
		fprintf(stderr, "-p parameter missing -- terminating\n");
		usage();
	}
	if(fdf == -1) {
		fprintf(stderr, "-f parameter missing -- terminating\n");
		usage();
	}

	if(sleeptime) {
		printf("minitcpsrv: deliberate sleep of %d seconds\n", sleeptime);
		sleep(sleeptime);
		printf("minitcpsrv: end sleep\n");
	}
#endif

	produce();

	/* let the OS do the cleanup */
	return 0;
}
