/* omazureeventhubs.c
 * This output plugin make rsyslog talk to Azure EventHubs.
 *
 * Copyright 2014-2017 by Adiscon GmbH.
 *
 * This file is part of rsyslog.
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
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/uio.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <math.h>
#ifdef HAVE_SYS_STAT_H
#	include <sys/stat.h>
#endif
#include <unistd.h>

// Include Proton headers
#include <proton/connection.h>
#include <proton/condition.h>
#include <proton/delivery.h>
#include <proton/link.h>
#include <proton/message.h>
#include <proton/proactor.h>
#include <proton/handlers.h>
#include <proton/session.h>
#include <proton/sasl.h>
#include <proton/ssl.h>
#include <proton/transport.h>

// Include rsyslog headers
#include "rsyslog.h"
#include "syslogd-types.h"
#include "srUtils.h"
#include "template.h"
#include "module-template.h"
#include "errmsg.h"
#include "atomic.h"
#include "statsobj.h"
#include "unicode-helper.h"
#include "datetime.h"
#include "glbl.h"

MODULE_TYPE_OUTPUT
MODULE_TYPE_NOKEEP
MODULE_CNFNAME("omazureeventhubs")

/* internal structures
 */
DEF_OMOD_STATIC_DATA
DEFobjCurrIf(datetime)
DEFobjCurrIf(strm)
DEFobjCurrIf(statsobj)
DEFobjCurrIf(glbl)

statsobj_t *azureStats;
STATSCOUNTER_DEF(ctrMessageSubmit, mutCtrMessageSubmit);
STATSCOUNTER_DEF(ctrAzureFail, mutCtrAzureFail);
STATSCOUNTER_DEF(ctrCacheMiss, mutCtrCacheMiss);
STATSCOUNTER_DEF(ctrCacheEvict, mutCtrCacheEvict);
STATSCOUNTER_DEF(ctrCacheSkip, mutCtrCacheSkip);
STATSCOUNTER_DEF(ctrAzureAck, mutCtrAzureAck);
STATSCOUNTER_DEF(ctrAzureMsgTooLarge, mutCtrAzureMsgTooLarge);
STATSCOUNTER_DEF(ctrAzureQueueFull, mutCtrAzureQueueFull);
STATSCOUNTER_DEF(ctrAzureOtherErrors, mutCtrAzureOtherErrors);
STATSCOUNTER_DEF(ctrAzureRespTimedOut, mutCtrAzureRespTimedOut);
STATSCOUNTER_DEF(ctrAzureRespTransport, mutCtrAzureRespTransport);
STATSCOUNTER_DEF(ctrAzureRespBrokerDown, mutCtrAzureRespBrokerDown);
STATSCOUNTER_DEF(ctrAzureRespAuth, mutCtrAzureRespAuth);
STATSCOUNTER_DEF(ctrAzureRespSSL, mutCtrAzureRespSSL);
STATSCOUNTER_DEF(ctrAzureRespOther, mutCtrAzureRespOther);

#define MAX_ERRMSG 1024 /* max size of error messages that we support */

#ifndef SLIST_INIT
#define SLIST_INIT(head) do {           \
	(head)->slh_first = NULL;        \
} while (/*CONSTCOND*/0)
#endif

#ifndef SLIST_ENTRY
#define SLIST_ENTRY(type)           \
	struct {                \
		struct type *sle_next;  /* next element */      \
	}
#endif

#ifndef SLIST_HEAD
#define SLIST_HEAD(name, type)            \
struct name {               \
	struct type *slh_first; /* first element */     \
}
#endif

#ifndef SLIST_INSERT_HEAD
#define SLIST_INSERT_HEAD(head, elm, field) do {      \
	(elm)->field.sle_next = (head)->slh_first;      \
	(head)->slh_first = (elm);          \
} while (/*CONSTCOND*/0)
#endif

#ifndef SLIST_REMOVE_HEAD
#define SLIST_REMOVE_HEAD(head, field) do {       \
	(head)->slh_first = (head)->slh_first->field.sle_next;    \
} while (/*CONSTCOND*/0)
#endif

#ifndef SLIST_FIRST
#define SLIST_FIRST(head) ((head)->slh_first)
#endif

#ifndef SLIST_NEXT
#define SLIST_NEXT(elm, field)  ((elm)->field.sle_next)
#endif

#ifndef SLIST_EMPTY
#define SLIST_EMPTY(head) ((head)->slh_first == NULL)
#endif

#ifndef SLIST_REMOVE
#define SLIST_REMOVE(head, elm, type, field) do {     \
		if ((head)->slh_first == (elm)) {       \
			SLIST_REMOVE_HEAD((head), field);     \
		}               \
	else {                \
		struct type *curelm = (head)->slh_first;    \
		while(curelm->field.sle_next != (elm))      \
			curelm = curelm->field.sle_next;    \
		curelm->field.sle_next = curelm->field.sle_next->field.sle_next;   \
	}               \
} while (/*CONSTCOND*/0)
#endif

#define NO_FIXED_PARTITION -1	/* signifies that no fixed partition config exists */

struct azure_params {
	const char *name;
	const char *val;
};

#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif

/* flags for writeAzure: shall we resubmit a failed message? */
#define RESUBMIT	1
#define NO_RESUBMIT	0

#if 0
	#ifdef HAVE_ATOMIC_BUILTINS64
	static uint64 clockTopicAccess = 0;
	#else
	static unsigned clockTopicAccess = 0;
	#endif
#endif

/* !!! MAY Needed for AZure */
#define AZURE_TimeStamp "\"%timestamp:::date-unixtimestamp%\""

static int closeTimeout = 1000;
static pthread_mutex_t closeTimeoutMut = PTHREAD_MUTEX_INITIALIZER;

/* Struct for Proton Messages Listitems */
struct s_protonmsg_entry {
	uchar* payload;
	size_t payload_len;
	uchar* MsgID;
	size_t MsgID_len;

	uchar* instance;
	sbool submitted;
	SLIST_ENTRY(s_protonmsg_entry) entries;	/*	List. */
} ;
typedef struct s_protonmsg_entry protonmsg_entry;

typedef struct _instanceData {
	uchar *amqp_address;
	uchar *azurehost;
	uchar *azureport;
	uchar *azure_key_name;
	uchar *azure_key;
	uchar *instance;
	uchar *container;

	int bReportErrs;
	uchar *errorFile;

	uchar *tplName;		/* assigned output template */
	int bResubmitOnFailure;	/* Resubmit failed messages into azure queue*/
	int bKeepFailedMessages;/* Keep Failed messages in memory,
							only works if bResubmitOnFailure is enabled */
	uchar *failedMsgFile;	/* file in which failed messages are being stored on
							shutdown and loaded on startup */

	int fdErrFile;		/* error file fd or -1 if not open */
	pthread_mutex_t mutErrFile;
	uchar *statsFile;
	int fdStatsFile;        /* stats file fd or -1 if not open */
	pthread_mutex_t mutStatsFile;
	int bIsOpen;
	int bIsSuspended;	/* when broker fail, we need to suspend the action */
	pthread_rwlock_t pnLock;
	pthread_mutex_t mut_doAction; /* make sure one wrkr instance max in parallel */
	// PROTON 
// 	pn_reactor_t *pnReactor;
//	pn_handler_t *pnHandler;
	pn_proactor_t *pnProactor;
	pn_transport_t *pnTransport;
	pn_connection_t *pnConn;
	pn_link_t* pnSender;

	pn_rwbytes_t pnMessageBuffer;
	int pnStatus;
	int iMsgSeq;

	int closeTimeout;
	SLIST_HEAD(submittedmsg_listhead, s_protonmsg_entry) submittedmsg_head;
	SLIST_HEAD(failedmsg_listhead, s_protonmsg_entry) failedmsg_head;

	uchar *statsName;
	statsobj_t *stats;
	STATSCOUNTER_DEF(ctrMessageSubmit, mutCtrMessageSubmit);
	STATSCOUNTER_DEF(ctrAzureFail, mutCtrAzureFail);
	STATSCOUNTER_DEF(ctrAzureAck, mutCtrAzureAck);
	STATSCOUNTER_DEF(ctrAzureOtherErrors, mutCtrAzureOtherErrors);
	
} instanceData;

typedef struct wrkrInstanceData {
	instanceData *pData;
} wrkrInstanceData_t;

/* The following structure controls the worker threads. Global data is
 * needed for their access.
 */
static struct protonWrkrInfo_s {
	sbool bThreadRunning;
	pthread_t tid;		/* the worker's thread ID */
	instanceData *pInstData;	/* Pointer to omazureeventhubs instance */
} *protonWrkrInfo;

#define INST_STATSCOUNTER_INC(inst, ctr, mut) \
	do { \
		if (inst->stats) { STATSCOUNTER_INC(ctr, mut); } \
	} while(0);

// QPID Proton Handler functions
static rsRetVal proton_run_thread(instanceData *pData);
static rsRetVal proton_shutdown_thread(instanceData *pData);
static void * proton_thread(void *myInfo);
static void handleProton(instanceData *const pData, pn_event_t *event);

/* tables for interfacing with the v6 config system */
/* action (instance) parameters */
static struct cnfparamdescr actpdescr[] = {
	{ "azurehost", eCmdHdlrString, CNFPARAM_REQUIRED },
	{ "azureport", eCmdHdlrString, CNFPARAM_REQUIRED },
	{ "azure_key_name", eCmdHdlrString, CNFPARAM_REQUIRED },
	{ "azure_key", eCmdHdlrString, CNFPARAM_REQUIRED },
	{ "amqp_address", eCmdHdlrString, 0 },
	{ "instance", eCmdHdlrString, CNFPARAM_REQUIRED },
	{ "container", eCmdHdlrString, 0 },

	{ "errorfile", eCmdHdlrGetWord, 0 },
	{ "statsfile", eCmdHdlrGetWord, 0 },
	{ "msgkey", eCmdHdlrGetWord, 0 },
	{ "template", eCmdHdlrGetWord, 0 },
	{ "closetimeout", eCmdHdlrPositiveInt, 0 },
	{ "resubmitonfailure", eCmdHdlrBinary, 0 },	/* Resubmit message into kafaj queue on failure */
	{ "keepfailedmessages", eCmdHdlrBinary, 0 },
	{ "failedmsgfile", eCmdHdlrGetWord, 0 },
	{ "statsname", eCmdHdlrGetWord, 0 }
};
static struct cnfparamblk actpblk =
	{ CNFPARAMBLK_VERSION,
	  sizeof(actpdescr)/sizeof(struct cnfparamdescr),
	  actpdescr
	};

BEGINinitConfVars		/* (re)set config variables to default values */
CODESTARTinitConfVars
ENDinitConfVars

static void ATTR_NONNULL(1)
protonmsg_entry_destruct(protonmsg_entry *const __restrict__ fmsgEntry) {
	free(fmsgEntry->MsgID);
	free(fmsgEntry->payload);
	free(fmsgEntry->instance);
	free(fmsgEntry);
}

/* note: we need the length of message as we need to deal with
 * non-NUL terminated strings under some circumstances.
 */
static protonmsg_entry * ATTR_NONNULL(1,3)
protonmsg_entry_construct(	const char *const MsgID, const size_t msgidlen, 
				const char *const msg, const size_t msglen, 
				const char *const instance)
{
	protonmsg_entry *etry = NULL;

	if((etry = malloc(sizeof(struct s_protonmsg_entry))) == NULL) {
		return NULL;
	}
	etry->submitted = 0; /* NOT SUBMITTED  */
	
	etry->MsgID_len = msgidlen;
	if((etry->MsgID = (uchar*)malloc(msgidlen+1)) == NULL) {
		free(etry);
		return NULL;
	}
	memcpy(etry->MsgID, MsgID, msgidlen);
	etry->MsgID[msgidlen] = '\0';

	etry->payload_len = msglen;
	if((etry->payload = (uchar*)malloc(msglen+1)) == NULL) {
		free(etry->MsgID);
		free(etry);
		return NULL;
	}
	memcpy(etry->payload, msg, msglen);
	etry->payload[msglen] = '\0';

	if((etry->instance = (uchar*)strdup(instance)) == NULL) {
		free(etry->MsgID);
		free(etry->payload);
		free(etry);
		return NULL;
	}
	return etry;
}

/* Create a message with a map { "sequence" : number } encode it and return the encoded buffer. */
static pn_bytes_t proton_encode_message(instanceData *const pData, protonmsg_entry* pMsgEntry) {
	/* Construct a message with the map */
	pn_message_t* message = pn_message();
	pn_data_t* body = pn_message_body(message);
//	pn_string_t* pnStrMsgID = pn_string((char*)pMsgEntry->MsgID);
	pn_message_set_id(message, (pn_atom_t){
						.type=PN_STRING, 
						.u.as_bytes.start = (char*)pMsgEntry->MsgID,
						.u.as_bytes.size = pMsgEntry->MsgID_len
					});
	pn_data_put_map(body);
	pn_data_enter(body);
	pn_data_put_string(body, pn_bytes(pMsgEntry->payload_len-1, (char*)pMsgEntry->payload));
	//  pn_data_put_int(body, pData->sent); /* The sequence number */
	pn_data_exit(body);

	/* encode the message, expanding the encode buffer as needed */
	if (pData->pnMessageBuffer.start == NULL) {
		static const size_t initial_size = 1024;
		pData->pnMessageBuffer = pn_rwbytes(initial_size, (char*)malloc(initial_size));
	}
	/* app->pnMessageBuffer is the total buffer space available. */
	/* mbuf wil point at just the portion used by the encoded message */
	pn_rwbytes_t mbuf = pn_rwbytes(pData->pnMessageBuffer.size, pData->pnMessageBuffer.start);
	int status = 0;
	while ((status = pn_message_encode(message, mbuf.start, &mbuf.size)) == PN_OVERFLOW) {
		pData->pnMessageBuffer.size *= 2;
		pData->pnMessageBuffer.start = 
				(char*)realloc(pData->pnMessageBuffer.start, pData->pnMessageBuffer.size);
		mbuf.size = pData->pnMessageBuffer.size;
		mbuf.start = pData->pnMessageBuffer.start;
	}
	pn_message_free(message);
	return pn_bytes(mbuf.size, mbuf.start);
}

static sbool proton_check_condition(pn_event_t *event, pn_condition_t *cond, const char * pszReason) {
	if (pn_condition_is_set(cond)) {
		DBGPRINTF("proton_check_condition: %s %s: %s: %s",
			pszReason,
			pn_event_type_name(pn_event_type(event)),
			pn_condition_get_name(cond),
			pn_condition_get_description(cond));
		LogError(0, RS_RET_ERR, "omazureeventhubs: %s %s: %s: %s",
			pszReason,
			pn_event_type_name(pn_event_type(event)),
			pn_condition_get_name(cond),
			pn_condition_get_description(cond));
		pn_connection_close(pn_event_connection(event));
		return 0;
	} else {
		return 1;
	}
}

/*	Start PROTON Handling Thread
*/
static rsRetVal proton_run_thread(instanceData *pData)
{
	DEFiRet;
	int iErr = 0;
	if (	protonWrkrInfo == NULL ||
		!protonWrkrInfo->bThreadRunning) {
		DBGPRINTF("Create Proton Protocol Thread for %p\n", pData);
		protonWrkrInfo = calloc(1, sizeof(struct protonWrkrInfo_s));
		if (protonWrkrInfo == NULL) {
			LogError(errno, RS_RET_OUT_OF_MEMORY, "omazureeventhubs: proton_run_thread allocation failed.");
			ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
		}

		/* init worker info structure! */
		protonWrkrInfo->pInstData = pData; /* Set reference pointer */
		do {
			iErr = pthread_create(&protonWrkrInfo->tid, NULL, proton_thread, &(protonWrkrInfo));
			if (!iErr) {
				protonWrkrInfo->bThreadRunning = 1;
				FINALIZE;
			}
		} while (iErr == EAGAIN);
	} else {
		DBGPRINTF("Proton Protocol Thread (tid %d) already running\n", protonWrkrInfo->bThreadRunning);
	}
finalize_it:
	if (iRet != RS_RET_OK) {
		LogError(0, RS_RET_SYS_ERR, "omazureeventhubs: proton_run_thread thread create failed with error: %d", 
			iErr);
	}
	RETiRet;
}
/*	Stop PROTON Handling Thread
*/
static rsRetVal 
proton_shutdown_thread(instanceData *pData)
{
	DEFiRet;
	if (	protonWrkrInfo != NULL && 
		protonWrkrInfo->bThreadRunning) {
		DBGPRINTF("STOPPING Proton Protocol Thread for %p\n", pData);
		int r = pthread_cancel(protonWrkrInfo->tid);
		if(r == 0) {
			pthread_join(protonWrkrInfo->tid, NULL);
		}
		DBGPRINTF("STOPPED Proton Protocol Thread for %p\n", pData);
		free(protonWrkrInfo);
		protonWrkrInfo = NULL;
	}
	FINALIZE;
finalize_it:
	RETiRet;
}

/*
*	Workerthread function for a single ProActor Handler
 */
static void *
proton_thread(void __attribute__((unused)) *myInfo)
{
	// protonWrkrInfo_s *thisWrkrInfo = (struct protonWrkrInfo*) myInfo;
	instanceData *const pData = (instanceData *const) protonWrkrInfo->pInstData;

	DBGPRINTF("proton_thread started protocol workerthread for %p:%s:%s/%s\n", 
		pData, pData->azurehost, pData->azureport, pData->instance); 

	do {
		if (	pData->pnProactor != NULL) {
			// Process Protocol events
			pn_event_batch_t *events = pn_proactor_wait(pData->pnProactor);
			pn_event_t *event;
			for (event = pn_event_batch_next(events); event; event = pn_event_batch_next(events)) {
				handleProton(pData, event);
			}
			pn_proactor_done(pData->pnProactor, events);
		}

		if(glbl.GetGlobalInputTermState() == 1)
			break; /* terminate input! */

		/* Note: the additional 10000ns wait is vitally important. It guards rsyslog
		 * against totally hogging the CPU if the users selects a polling interval
		 * of 0 seconds. It doesn't hurt any other valid scenario. So do not remove.
		 * rgerhards, 2008-02-14
		 */
		if(glbl.GetGlobalInputTermState() == 0)
			srSleep(0, 100000);
	} while(glbl.GetGlobalInputTermState() == 0);
	
	DBGPRINTF("proton_thread stopped protocol workerthread\n");
	return NULL;
}

/*	Handles PROTON Communication
*/
#pragma GCC diagnostic ignored "-Wswitch"
static void 
handleProton(instanceData *const pData, pn_event_t *event) {
//handleProton(pn_handler_t *handler, pn_event_t *event) { //, pn_event_type_t type) {
//	instanceData **ppData = (instanceData **) pn_handler_mem(handler);
//	instanceData *const pData = (instanceData *) *ppData;
//	int pnErr = PN_OK;
//	switch (type) {
	switch (pn_event_type(event)) {
		case PN_CONNECTION_BOUND: {
			DBGPRINTF("handleProton: PN_CONNECTION_BOUND to %s:%s/%s\n", 
				pData->azurehost, pData->azureport, pData->instance);
			break;
		}
		case PN_SESSION_INIT : {
			DBGPRINTF("handleProton: PN_SESSION_INIT  to %s:%s/%s\n", 
				pData->azurehost, pData->azureport, pData->instance);
			break;
		}
		case PN_LINK_INIT: {
			DBGPRINTF("handleProton: PN_LINK_INIT to %s:%s/%s\n",
				pData->azurehost, pData->azureport, pData->instance);
			break;
		}
		case PN_LINK_REMOTE_OPEN: {
			DBGPRINTF("handleProton: PN_LINK_REMOTE_OPEN to %s:%s/%s\n", 
				pData->azurehost, pData->azureport, pData->instance);
			break;
		}
		case PN_CONNECTION_WAKE: { 
			DBGPRINTF("handleProton: PN_CONNECTION_WAKE to %s:%s/%s\n", 
				pData->azurehost, pData->azureport, pData->instance);
			break;
		}
		case PN_CONNECTION_INIT: {
			DBGPRINTF("handleProton: PN_CONNECTION_INIT to %s:%s/%s\n", 
				pData->azurehost, pData->azureport, pData->instance);
			pData->pnStatus = PN_CONNECTION_INIT;
			pData->pnConn = pn_event_connection(event); // Get Connection

			if (pData->container == NULL) {
				// Use default name
				pn_connection_set_container(pData->pnConn, "rsyslogd-omazureeventhubs");
			} else {
				// Use custom container name
				pn_connection_set_container(pData->pnConn, (const char *) pData->container);
			}
			pn_connection_set_hostname(pData->pnConn, (const char *) pData->azurehost);
			pn_connection_set_user(pData->pnConn, (const char *) pData->azure_key_name);
			pn_connection_set_password(pData->pnConn, (const char *) pData->azure_key);

			const char *targetAddress = (char *)pData->instance;
			pn_connection_open(pData->pnConn); // Open Connection
			pn_session_t* pnSession = pn_session(pData->pnConn); // Create Session
			pn_session_open(pnSession); // Open Session
			pData->pnSender = pn_sender(pnSession, "rsyslogd"); // Create Link
			pn_link_set_snd_settle_mode(pData->pnSender, PN_SND_UNSETTLED);
			
			if(pData->amqp_address != NULL) {
				DBGPRINTF("handleProton: PN_CONNECTION_INIT with amqp address: %s\n", 
					pData->amqp_address);
				pn_terminus_set_address(pn_link_target(pData->pnSender), (const char *) pData->amqp_address);
			} else {
				DBGPRINTF("handleProton: PN_CONNECTION_INIT with target: %s\n", 
					targetAddress);
				pn_terminus_set_address(pn_link_target(pData->pnSender), (const char *) targetAddress);
				pn_terminus_set_address(pn_link_source(pData->pnSender), (const char *) targetAddress);
			}
			pn_link_open(pData->pnSender);
			break;
		}
		case PN_CONNECTION_REMOTE_OPEN: {
			DBGPRINTF("handleProton: PN_CONNECTION_REMOTE_OPEN to %s:%s/%s\n", 
				pData->azurehost, 
				pData->azureport, 
				pData->instance);
			pData->pnStatus = PN_CONNECTION_REMOTE_OPEN;
			pn_ssl_t *ssl = pn_ssl(pn_event_transport(event));
			if (ssl) {
				char name[1024];
				pn_ssl_get_protocol_name(ssl, name, sizeof(name));
				{
					const char *subject = pn_ssl_get_remote_subject(ssl);
					if (subject) {
						DBGPRINTF("handleProton: handleProton secure connection: to %s using %s\n", subject, name);
					} else {
						DBGPRINTF("handleProton: handleProton anonymous connection: using %s\n", name);
					}
					fflush(stdout);
				}
			}
			break;
		}
		case PN_LINK_FLOW: {
			pData->pnStatus = PN_LINK_FLOW;
			/* The peer has given us some credit, now we can send messages */
			pData->pnSender = pn_event_link(event);
			/* Process messages from LIST*/
			protonmsg_entry* pMsgEntry = SLIST_FIRST(&pData->submittedmsg_head);
			while (pMsgEntry != NULL) {
				// Process Unsubmitted messages only
				if (pMsgEntry->submitted == 0) {
					if (pn_link_credit(pData->pnSender) > 0) {
						DBGPRINTF(
						"handleProton: PN_LINK_FLOW deliver '%s' @ %s:%s/%s, msg:'%s'\n",
							pMsgEntry->MsgID, 
							pData->azurehost, 
							pData->azureport, 
							pData->instance, 
							pMsgEntry->payload);

						/* Use sent counter as unique delivery tag. */
						pn_delivery(pData->pnSender, pn_dtag((const char *)pMsgEntry->MsgID, 
							pMsgEntry->MsgID_len));
						
						pn_bytes_t msgbuf = proton_encode_message(pData, pMsgEntry);
						pn_link_send(pData->pnSender, msgbuf.start, msgbuf.size);
						pn_link_advance(pData->pnSender);

						STATSCOUNTER_INC(ctrMessageSubmit, mutCtrMessageSubmit);
						INST_STATSCOUNTER_INC(	pData, 
									pData->ctrMessageSubmit, 
									pData->mutCtrMessageSubmit);
						pMsgEntry->submitted = 1;
					} else {
						// TODO: HANDLE
						LogMsg(0, NO_ERRCODE, LOG_INFO, 
							"handleProton: sender credit balance reached ZERO. "
							"We need to try later");
						break;
					}
				}
				// Next Message
				pMsgEntry = SLIST_NEXT(pMsgEntry, entries);
			}
			break;
		}
		case PN_DELIVERY: {
		pData->pnStatus = PN_DELIVERY;
		/* We received acknowledgement from the peer that a message was delivered. */
		pn_delivery_t* pDeliveryStatus = pn_event_delivery(event);
		pn_delivery_tag_t pnTag = pn_delivery_tag(pDeliveryStatus);

		// Search message in submitted list
		sbool bFoundMessage = 0;
		protonmsg_entry* pMsgEntry = SLIST_FIRST(&pData->submittedmsg_head);
		while (pMsgEntry != NULL) {
			// Process submitted messages only
			if (pMsgEntry->submitted == 1) {
				if (	pnTag.start != NULL && 
					memcmp(pnTag.start, pMsgEntry->MsgID, pMsgEntry->MsgID_len) == 0 ) {
				bFoundMessage = 1;
				// Break LOOP
				break; 
				}
			}
			// Next Message
			pMsgEntry = SLIST_NEXT(pMsgEntry, entries);
		}

		if (bFoundMessage == 1) {
			if (pn_delivery_remote_state(pDeliveryStatus) == PN_ACCEPTED) {
				DBGPRINTF("handleProton: PN_DELIVERY SUCCESS for MSG '%s' @%s:%s/%s\n",
					(pnTag.start != NULL ? (char*) pnTag.start : "NULL"),
					pData->azurehost, 
					pData->azureport, 
					pData->instance);
				// Remove from SUBMITTEDLIST
				SLIST_REMOVE(&pData->submittedmsg_head, pMsgEntry, s_protonmsg_entry, entries);
				// Destroy
				protonmsg_entry_destruct(pMsgEntry);
				// Increment Stats Counter
				STATSCOUNTER_INC(ctrAzureAck, mutCtrAzureAck);
				INST_STATSCOUNTER_INC(pData, pData->ctrAzureAck, pData->mutCtrAzureAck);
			} else if (pn_delivery_remote_state(pDeliveryStatus) == PN_REJECTED) {
				LogError(0, RS_RET_ERR, 
						"omazureeventhubs: PN_DELIVERY REJECTED for MSG '%s' Retry=%s"
						" - @%s:%s/%s\n",
						(pnTag.start != NULL ? (char*) pnTag.start : "NULL"),
						(pData->bResubmitOnFailure ? "YES" : "NO"),
						pData->azurehost,
						pData->azureport,
						pData->instance);

				// Remove from SUBMITTED LIST
				SLIST_REMOVE(&pData->submittedmsg_head, pMsgEntry, s_protonmsg_entry, entries);
				if (pData->bResubmitOnFailure) {
					// Add to failed message list
					SLIST_INSERT_HEAD(&pData->failedmsg_head, pMsgEntry, entries);
				} else {
					// Destroy
					protonmsg_entry_destruct(pMsgEntry);
				}
				// Increment Stats Counter
				STATSCOUNTER_INC(ctrAzureFail, mutCtrAzureFail);
				INST_STATSCOUNTER_INC(pData, pData->ctrAzureFail, pData->mutCtrAzureFail);
				// TODO HANDLE CONNECTION TERMINATION OR NOT?!
				// pn_connection_close(pn_event_connection(event));
			} else {
				LogError(0, RS_RET_ERR, 
						"omazureeventhubs: PN_DELIVERY UNKNOWN state %d for MSG '%s' Retry=%s"
						" - @%s:%s/%s\n",
						(int)pn_delivery_remote_state(pDeliveryStatus),
						(pnTag.start != NULL ? (char*) pnTag.start : "NULL"),
						(pData->bResubmitOnFailure ? "YES" : "NO"),
						pData->azurehost,
						pData->azureport,
						pData->instance);
				// Remove from SUBMITTED LIST
				SLIST_REMOVE(&pData->submittedmsg_head, pMsgEntry, s_protonmsg_entry, entries);
				if (pData->bResubmitOnFailure) {
					// Add to failed message list
					SLIST_INSERT_HEAD(&pData->failedmsg_head, pMsgEntry, entries);
				} else {
					// Destroy
					protonmsg_entry_destruct(pMsgEntry);
				}
				// TODO HANDLE CONNECTION TERMINATION OR NOT?!
				// pn_connection_close(pn_event_connection(event));
			}
		} else {
			DBGPRINTF("omazureeventhubs: PN_DELIVERY MISSING MSG '%s' in SUBMITTED Messages - @%s:%s/%s\n",
				(pnTag.start != NULL ? (char*) pnTag.start : "NULL"),
				pData->azurehost,
				pData->azureport,
				pData->instance);
			// Increment Stats Counter
			STATSCOUNTER_INC(ctrAzureOtherErrors, mutCtrAzureOtherErrors);
			INST_STATSCOUNTER_INC(pData, pData->ctrAzureOtherErrors, pData->mutCtrAzureOtherErrors);
		}
		break;
		}
		case PN_TRANSPORT_CLOSED:
			DBGPRINTF("handleProton: transport closed for %s\n",
				pData->azurehost);
			proton_check_condition(event, pn_transport_condition(pn_event_transport(event)), 
				"transport closed");
			// Disconnected
			pData->bIsOpen = 0;
			break;
		case PN_CONNECTION_REMOTE_CLOSE:
			DBGPRINTF("handleProton: connection closed for %s\n", 
				pData->azurehost);
			proton_check_condition(event, pn_connection_remote_condition(pn_event_connection(event)), 
				"connection closed");
			break;
		case PN_SESSION_REMOTE_CLOSE:
			DBGPRINTF("handleProton: remote session closed for %s\n", 
				pData->azurehost);
			proton_check_condition(event, pn_session_remote_condition(pn_event_session(event)), 
				"remote session closed");
			break;
		case PN_LINK_REMOTE_CLOSE:
		case PN_LINK_REMOTE_DETACH:
			DBGPRINTF("handleProton: remote link closed for %s\n", 
				pData->azurehost);
			proton_check_condition(event, pn_link_remote_condition(pn_event_link(event)), 
				"remote link closed");
			break;
		case PN_PROACTOR_INACTIVE:
			DBGPRINTF("handleProton: INAKTIVE for %s\n", 
				pData->azurehost);
			break;
#ifdef __GNU_C
		default: 
			DBGPRINTF("handleProton: UNHANDELED EVENT %d for %s\n", 
				pn_event_type(event), pData->azurehost);
			break;
#endif
	}
}

#if 0
static void 
handleProtonDel(pn_handler_t *handler) {
// TODO
	DBGPRINTF("handleProtonDel: handleProtonDel handler called for %p\n", handler);
	return;
}
#endif

#if 0
/**
 * This function looks for a json object that corresponds to the
 * passed name and returns it is found. Otherwise returns NULL.
 * It will be used for processing stats callback json object.
 */
static struct fjson_object *
get_object(struct fjson_object *fj_obj, const char * name) {
	struct fjson_object_iterator it = fjson_object_iter_begin(fj_obj);
	struct fjson_object_iterator itEnd = fjson_object_iter_end(fj_obj);
	while (!fjson_object_iter_equal (&it, &itEnd)) {
		const char * key = fjson_object_iter_peek_name (&it);
		struct fjson_object * val = fjson_object_iter_peek_value(&it);
		if(!strncmp(key, name, strlen(name))){
			return val;
		}
		fjson_object_iter_next (&it);
	}

	return NULL;
}

/**
 * This function performs a two level search in stats callback json
 * object. It iterates over broker objects and for each broker object
 * returns desired level2 value (such as avg/min/max) for specified
 * level1 window statistic (such as rtt/throttle/int_latency). Threshold
 * allows skipping values that are too small, so that they don't
 * impact on aggregate averaged value that is returned.
 */
static uint64
jsonExtractWindoStats(struct fjson_object * stats_object,
	const char * level1_obj_name, const char * level2_obj_name,
	unsigned long skip_threshold) {
	uint64 level2_val;
	uint64 agg_val = 0;
	uint64 ret_val = 0;
	int active_brokers = 0;

	struct fjson_object * brokers_obj = get_object(stats_object, "brokers");
	if (brokers_obj == NULL) {
		LogMsg(0, NO_ERRCODE, LOG_ERR, "jsonExtractWindowStat: failed to find brokers object");
		return ret_val;
	}

	/* iterate over borkers to get level1 window objects at level2 (min, max, avg, etc.) */
	struct fjson_object_iterator it = fjson_object_iter_begin(brokers_obj);
	struct fjson_object_iterator itEnd = fjson_object_iter_end(brokers_obj);
	while (!fjson_object_iter_equal (&it, &itEnd)) {
		struct fjson_object * val = fjson_object_iter_peek_value(&it);
		struct fjson_object * level1_obj = get_object(val, level1_obj_name);
		if(level1_obj == NULL)
			return ret_val;

		struct fjson_object * level2_obj = get_object(level1_obj, level2_obj_name);
		if(level2_obj == NULL)
			return ret_val;

		level2_val = fjson_object_get_int64(level2_obj);
		if (level2_val > skip_threshold) {
			agg_val += level2_val;
			active_brokers++;
		}
		fjson_object_iter_next (&it);
	}
	if(active_brokers > 0) {
		ret_val = agg_val/active_brokers;
	}

	return ret_val;
}
#endif

/* should be called with write(pnLock) */
static rsRetVal
closeProton(instanceData *const __restrict__ pData)
{
	DEFiRet;
DBGPRINTF("closeProton: ENTER\n");
	if (pData->pnSender) {
		pn_link_close(pData->pnSender);
		pn_session_close(pn_link_session(pData->pnSender));
		DBGPRINTF("closeProton pn_link_close/pn_session_close Session\n");
	}
	if (pData->pnConn) {
		DBGPRINTF("closeProton pn_connection_close connection\n");
		pn_connection_close(pData->pnConn);
	}

	pData->bIsOpen = 0;
	pData->pnStatus = PN_EVENT_NONE;

	pData->pnSender = NULL;
	pData->pnConn = NULL;
	pData->iMsgSeq = 0;

	FINALIZE;
finalize_it:
	RETiRet;

}

/* should be called with write(pnLock) */
static rsRetVal
openProton(instanceData *const __restrict__ pData)
{
	DEFiRet;
	int pnErr = PN_OK;
//	char errstr[MAX_ERRMSG];
	char szAddr[PN_MAX_ADDR];
DBGPRINTF("openProton: ENTER\n");

	if(pData->bIsOpen)
		FINALIZE;

	pData->pnStatus = PN_EVENT_NONE;
/*
	// Create Connection
	pData->pnConn = pn_reactor_connection_to_host(	pData->pnReactor,
							(const char *) pData->azurehost,
							(const char *) pData->azureport,
							pData->pnHandler);
	pn_reactor_connection(pData->pnReactor,pData->pnHandler);
	pn_connection_open(pData->pnConn);
//pn_reactor_connection(pData->pnReactor, sh);
	pn_reactor_run(pData->pnReactor);
*/
	pn_proactor_addr(szAddr, sizeof(szAddr), (const char *) pData->azurehost, (const char *) pData->azureport);
	// Configure a transport for SSL. The transport will be freed by the proactor.
	pData->pnTransport = pn_transport();
	DBGPRINTF("openProton: create transport to '%s:%s'\n", pData->azurehost, pData->azureport);

	pn_ssl_t* pnSsl = pn_ssl(pData->pnTransport);
	if (pnSsl != NULL) {
		pn_ssl_domain_t* pnDomain = pn_ssl_domain(PN_SSL_MODE_CLIENT);
		if (pData->azure_key_name != NULL && pData->azure_key != NULL) {
			pnErr =  pn_ssl_init(pnSsl, pnDomain, NULL);
			if (pnErr) {
				DBGPRINTF("openProton: pn_ssl_init failed for '%s:%s' with error %d: %s\n", 
					pData->azurehost, pData->azureport,
					pnErr, pn_code(pnErr));
			}
			pn_sasl_allowed_mechs(pn_sasl(pData->pnTransport), "PLAIN");
		} else {
			pnErr = pn_ssl_domain_set_peer_authentication(pnDomain, PN_SSL_ANONYMOUS_PEER, NULL);
			if (!pnErr) {
				pnErr = pn_ssl_init(pnSsl, pnDomain, NULL);
			} else {
				DBGPRINTF("openProton: pn_ssl_domain_set_peer_authentication failed with '%d'\n", pnErr);
			}
		}
		pn_ssl_domain_free(pnDomain);
	} else {
		LogError(0, RS_RET_ERR, "openProton: openProton pn_ssl_init NULL");
	}
	
	// Handle ERROR Output
	if (pnErr) {
		LogError(0, RS_RET_IO_ERROR, "openProton: creating transport to '%s:%s' "
			"failed with error %d: %s\n",
			pData->azurehost, pData->azureport,
			pnErr, pn_code(pnErr));
		ABORT_FINALIZE(RS_RET_IO_ERROR);
	}

	// Connect to Azure Event Hubs
	pn_proactor_connect2(pData->pnProactor, NULL, pData->pnTransport, szAddr);

	// Successfully connected
 	pData->bIsOpen = 1;
finalize_it:
	if(iRet == RS_RET_OK) {
		pData->bReportErrs = 1;
	} else {
		pData->bReportErrs = 0;
		closeProton(pData); // Make sure to free ressources
	}
	RETiRet;
}

static rsRetVal
setupProtonHandle(instanceData *const __restrict__ pData, int recreate)
{
	DEFiRet;
DBGPRINTF("setupProtonHandle: ENTER\n");

	pthread_rwlock_wrlock(&pData->pnLock);
	if (recreate) {
		closeProton(pData);
	}
	CHKiRet(openProton(pData));
finalize_it:
	if (iRet != RS_RET_OK) {
		/* Parameter Error's cannot be resumed, so we need to disable the action */
		if (iRet == RS_RET_PARAM_ERROR) {
			iRet = RS_RET_DISABLE_ACTION;
			LogError(0, iRet, "omazureeventhubs: action will be disabled due invalid "
				"configuration parameters\n");
		}
	}
	pthread_rwlock_unlock(&pData->pnLock);
	RETiRet;
}

static rsRetVal
writeProton(instanceData *const __restrict__ pData, const char* pszMsg, size_t tzLen)
{
	DEFiRet;
	protonmsg_entry* fmsgEntry;

	// Increment Message sequence number
	pData->iMsgSeq++;

	// Create Unqiue Message ID
	char szMsgID[64];
	sprintf(szMsgID, "%d", pData->iMsgSeq);
	// Add message to LIST for sending
	CHKmalloc(fmsgEntry = protonmsg_entry_construct(
		szMsgID, sizeof(szMsgID),
		(const char*)pszMsg, tzLen, 
		(const char*)pData->instance));
	SLIST_INSERT_HEAD(&pData->submittedmsg_head, fmsgEntry, entries);

finalize_it:
	RETiRet;
}

static rsRetVal
checkFailedMessages(instanceData *const __restrict__ pData)
{
	protonmsg_entry* fmsgEntry;
	DEFiRet;

	/* Loop through failed messages, reprocess them first! */
	while (!SLIST_EMPTY(&pData->failedmsg_head)) {
		fmsgEntry = SLIST_FIRST(&pData->failedmsg_head);
		assert(fmsgEntry != NULL);

		/* Put back into Proton! */
		iRet = writeProton(pData, (const char*) fmsgEntry->payload, fmsgEntry->payload_len);

		if(iRet != RS_RET_OK) {
			LogMsg(0, RS_RET_SUSPENDED, LOG_WARNING,
				"omazureeventhubs: checkFailedMessages failed to deliver failed msg '%.*s' "
				"with status %d. - suspending AGAIN!",
				(int)(strlen((char*)fmsgEntry->payload)-1),
				(char*)fmsgEntry->payload, iRet);
			ABORT_FINALIZE(RS_RET_SUSPENDED);
		} else {
			DBGPRINTF("checkFailedMessages successfully delivered failed msg '%.*s'.\n",
				(int)(strlen((char*)fmsgEntry->payload)-1),
				(char*)fmsgEntry->payload);
			/* Note: we can use SLIST even though it is o(n), because the element
			 * in question is always either the root or the next element and
			 * SLIST_REMOVE iterates only until the element to be deleted is found.
			 * We cannot use SLIST_REMOVE_HEAD() as new elements may have been
			 * added in the delivery callback!
			 * TODO: sounds like bad logic -- why do we add and remove, just simply
			 * keep it in queue?
			 */
			SLIST_REMOVE(&pData->failedmsg_head, fmsgEntry, s_protonmsg_entry, entries);
			protonmsg_entry_destruct(fmsgEntry);
		}
	}
finalize_it:
	RETiRet;
}

/* This function persists failed messages into a data file, so they can
 * be resend on next startup.
 * alorbach, 2017-06-02
 */
static rsRetVal ATTR_NONNULL(1)
persistFailedMsgs(instanceData *const __restrict__ pData)
{
	DEFiRet;
	int fdMsgFile = -1;
	ssize_t nwritten;
DBGPRINTF("persistFailedMsgs: ENTER\n");

	if(SLIST_EMPTY(&pData->failedmsg_head)) {
		DBGPRINTF("omazureeventhubs: persistFailedMsgs: We do not need to persist failed messages.\n");
		FINALIZE;
	}

	fdMsgFile = open((char*)pData->failedMsgFile,
				O_WRONLY|O_CREAT|O_APPEND|O_LARGEFILE|O_CLOEXEC,
				S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);
	if(fdMsgFile == -1) {
		LogError(errno, RS_RET_ERR, "omazureeventhubs: persistFailedMsgs error opening failed msg file %s",
			pData->failedMsgFile);
		ABORT_FINALIZE(RS_RET_ERR);
	}

	while (!SLIST_EMPTY(&pData->failedmsg_head)) {
		protonmsg_entry* fmsgEntry = SLIST_FIRST(&pData->failedmsg_head);
		assert(fmsgEntry != NULL);
		nwritten = write(fdMsgFile, fmsgEntry->instance, ustrlen(fmsgEntry->instance) );
		if(nwritten != -1)
			nwritten = write(fdMsgFile, "\t", 1);
		if(nwritten != -1)
			nwritten = write(fdMsgFile, fmsgEntry->payload, ustrlen(fmsgEntry->payload) );
		if(nwritten == -1) {
			LogError(errno, RS_RET_ERR, "omazureeventhubs: persistFailedMsgs error writing failed msg file");
			ABORT_FINALIZE(RS_RET_ERR);
		} else {
			DBGPRINTF("omazureeventhubs: persistFailedMsgs successfully written loaded msg '%.*s' for "
				"instance '%s'\n", (int)(strlen((char*)fmsgEntry->payload)-1),
				fmsgEntry->payload, fmsgEntry->instance);
		}
		SLIST_REMOVE_HEAD(&pData->failedmsg_head, entries);
		protonmsg_entry_destruct(fmsgEntry);
	}

finalize_it:
	if(fdMsgFile != -1) {
		close(fdMsgFile);
	}
	if(iRet != RS_RET_OK) {
		LogError(0, iRet, "omazureeventhubs: could not persist failed messages "
			"file %s - failed messages will be lost.",
			(char*)pData->failedMsgFile);
	}
	RETiRet;
}

/* This function loads failed messages from a data file, so they can
 * be resend after action startup.
 * alorbach, 2017-06-06
 */
static rsRetVal
loadFailedMsgs(instanceData *const __restrict__ pData)
{
	DEFiRet;
	struct stat stat_buf;
	protonmsg_entry* pMsgEntry;
	strm_t *pstrmFMSG = NULL;
	cstr_t *pCStr = NULL;
	uchar *puInstanceStr;
	char *pStrTabPos;
DBGPRINTF("loadFailedMsgs: ENTER\n");

	assert(pData->failedMsgFile != NULL);

	/* check if the file exists */
	if(stat((char*) pData->failedMsgFile, &stat_buf) == -1) {
		if(errno == ENOENT) {
			DBGPRINTF("omazureeventhubs: loadFailedMsgs failed messages file %s wasn't found, "
				"continue startup\n", pData->failedMsgFile);
			ABORT_FINALIZE(RS_RET_FILE_NOT_FOUND);
		} else {
			LogError(errno, RS_RET_IO_ERROR,
				"omazureeventhubs: loadFailedMsgs could not open failed messages file %s",
				pData->failedMsgFile);
			ABORT_FINALIZE(RS_RET_IO_ERROR);
		}
	} else {
		DBGPRINTF("omazureeventhubs: loadFailedMsgs found failed message file %s.\n",
			pData->failedMsgFile);
	}

	/* File exists, we can load and process it */
	CHKiRet(strm.Construct(&pstrmFMSG));
	CHKiRet(strm.SettOperationsMode(pstrmFMSG, STREAMMODE_READ));
	CHKiRet(strm.SetsType(pstrmFMSG, STREAMTYPE_FILE_SINGLE));
	CHKiRet(strm.SetFName(pstrmFMSG, pData->failedMsgFile, ustrlen(pData->failedMsgFile)));
	CHKiRet(strm.ConstructFinalize(pstrmFMSG));

	while(strm.ReadLine(pstrmFMSG, &pCStr, 0, 0, NULL, 0, NULL) == RS_RET_OK) {
		if(rsCStrLen(pCStr) == 0) {
			/* we do not process empty lines */
			DBGPRINTF("omazureeventhubs: loadFailedMsgs msg was empty!");
		} else {
			puInstanceStr = rsCStrGetSzStrNoNULL(pCStr); //instance
			pStrTabPos = index((char*)puInstanceStr, '\t');  //instance
			if ((pStrTabPos != NULL)) {
				*pStrTabPos = '\0'; /* split string into two */
				DBGPRINTF("omazureeventhubs: loadFailedMsgs successfully loaded msg '%s' for "
					"instance '%s' \n",
					pStrTabPos+1, (char*)puInstanceStr);
				if (strlen(pStrTabPos+1)) {
					// Increment Message sequence number
					pData->iMsgSeq++;
					// Create Unqiue Message ID
					char szMsgID[64];
					sprintf(szMsgID, "%d", pData->iMsgSeq);
					// Create Message Entry
					CHKmalloc(pMsgEntry = protonmsg_entry_construct(szMsgID, sizeof(szMsgID),
						pStrTabPos+1,strlen(pStrTabPos+1),
						(char*)puInstanceStr));
				} else {
					LogError(0, RS_RET_ERR, 
						"omazureeventhubs: loadFailedMsgs dropping invalid msg found: %s",
						(char*)rsCStrGetSzStrNoNULL(pCStr));
				}
				SLIST_INSERT_HEAD(&pData->failedmsg_head, pMsgEntry, entries);
			} else {
				LogError(0, RS_RET_ERR, 
					"omazureeventhubs: loadFailedMsgs dropping invalid msg found: %s",
					(char*)rsCStrGetSzStrNoNULL(pCStr));
			}
		}

		rsCStrDestruct(&pCStr); /* discard string (must be done by us!) */
	}
finalize_it:
	if(pstrmFMSG != NULL) {
		strm.Destruct(&pstrmFMSG);
	}

	if(iRet != RS_RET_OK) {
		/* We ignore FILE NOT FOUND here */
		if (iRet != RS_RET_FILE_NOT_FOUND) {
			LogError(0, iRet, "omazureeventhubs: could not load failed messages "
			"from file %s error %d - failed messages will not be resend.",
			(char*)pData->failedMsgFile, iRet);
		}
	} else {
		DBGPRINTF("loadFailedMsgs unlinking '%s'\n", (char*)pData->failedMsgFile);
		/* Delete file if still exists! */
		const int r = unlink((char*)pData->failedMsgFile);
		if(r != 0 && r != ENOENT) {
			LogError(errno, RS_RET_ERR, "omazureeventhubs: loadFailedMsgs failed to remove "
				"file \"%s\"", (char*)pData->failedMsgFile);
		}
	}

	RETiRet;
}

BEGINdoHUP
CODESTARTdoHUP
DBGPRINTF("doHUP: ENTER\n");
	pthread_mutex_lock(&pData->mutErrFile);
	if(pData->fdErrFile != -1) {
		close(pData->fdErrFile);
		pData->fdErrFile = -1;
	}
	pthread_mutex_unlock(&pData->mutErrFile);
	pthread_mutex_lock(&pData->mutStatsFile);
	if(pData->fdStatsFile != -1) {
		close(pData->fdStatsFile);
		pData->fdStatsFile = -1;
	}
	pthread_mutex_unlock(&pData->mutStatsFile);

#if 0
// TODO CHECK?!
	if (pData->bReopenOnHup) {
		CHKiRet(setupKafkaHandle(pData, 1));
	} else {
		/* Optional */
		const int callbacksCalled = rd_kafka_poll(pData->rk, 0); /* call callbacks */
		LogMsg(0, NO_ERRCODE, LOG_INFO, "omazureeventhubs: doHUP kafka - '%s' outqueue length: %d,"
			"callbacks called %d\n", pData->tplName,
			rd_kafka_outq_len(pData->rk), callbacksCalled);
	}
finalize_it:
#endif
ENDdoHUP

BEGINcreateInstance
CODESTARTcreateInstance
DBGPRINTF("createInstance: ENTER\n");
	pData->amqp_address = NULL;
	pData->azurehost = NULL;
	pData->azureport = NULL;
	pData->azure_key_name = NULL;
	pData->azure_key = NULL;
	pData->instance = NULL;
	pData->container = NULL;

	pData->bIsOpen = 0;
	pData->bIsSuspended = 0;

	pData->pnProactor = NULL;
	pData->pnConn = NULL;
	pData->pnTransport = NULL;
	pData->pnSender = NULL;

	pData->iMsgSeq = 0;
	pData->pnMessageBuffer.start = NULL;

	pData->fdErrFile = -1;
	pData->fdStatsFile = -1;
	pData->bReportErrs = 1;
	pData->bResubmitOnFailure = 0;
	pData->bKeepFailedMessages = 0;
	pData->failedMsgFile = NULL;
	SLIST_INIT(&pData->submittedmsg_head);
	SLIST_INIT(&pData->failedmsg_head);

	CHKiRet(pthread_mutex_init(&pData->mut_doAction, NULL));
	CHKiRet(pthread_mutex_init(&pData->mutErrFile, NULL));
	CHKiRet(pthread_mutex_init(&pData->mutStatsFile, NULL));
	CHKiRet(pthread_rwlock_init(&pData->pnLock, NULL));
//	CHKiRet(pthread_mutex_init(&pData->mutDynCache, NULL));
	INIT_ATOMIC_HELPER_MUT(pData->mutCurrPartition);

	proton_run_thread(pData);
finalize_it:
ENDcreateInstance


BEGINcreateWrkrInstance
CODESTARTcreateWrkrInstance
ENDcreateWrkrInstance


BEGINisCompatibleWithFeature
CODESTARTisCompatibleWithFeature
ENDisCompatibleWithFeature


BEGINfreeInstance
CODESTARTfreeInstance
DBGPRINTF("freeInstance: ENTER\n");
	/* Helpers for Failed Msg List */
	protonmsg_entry* fmsgEntry1;
	protonmsg_entry* fmsgEntry2;
	if(pData->fdErrFile != -1)
		close(pData->fdErrFile);
	if(pData->fdStatsFile != -1)
		close(pData->fdStatsFile);
	/* Closing azure first! */
	pthread_rwlock_wrlock(&pData->pnLock);

	// Free Proton Ressources
	closeProton(pData);
	if (pData->pnProactor != NULL) {
		DBGPRINTF("freeInstance FREE proactor\n");
		pn_proactor_free(pData->pnProactor);
		pData->pnProactor = NULL;
	}
	free(pData->pnMessageBuffer.start);
	
	// Stop Proton Handle Thread
	proton_shutdown_thread(pData);

	/* Persist failed messages */
	if (pData->bResubmitOnFailure && pData->bKeepFailedMessages && pData->failedMsgFile != NULL) {
		persistFailedMsgs(pData);
	}
	pthread_rwlock_unlock(&pData->pnLock);

	if (pData->stats) {
		statsobj.Destruct(&pData->stats);
	}

	/* Delete Linked List for submitted msgs */
	fmsgEntry1 = SLIST_FIRST(&pData->submittedmsg_head);
	while (fmsgEntry1 != NULL)	{
		fmsgEntry2 = SLIST_NEXT(fmsgEntry1, entries);
		protonmsg_entry_destruct(fmsgEntry1);
		fmsgEntry1 = fmsgEntry2;
	}
	SLIST_INIT(&pData->submittedmsg_head);
	/* Delete Linked List for failed msgs */
	fmsgEntry1 = SLIST_FIRST(&pData->failedmsg_head);
	while (fmsgEntry1 != NULL)	{
		fmsgEntry2 = SLIST_NEXT(fmsgEntry1, entries);
		protonmsg_entry_destruct(fmsgEntry1);
		fmsgEntry1 = fmsgEntry2;
	}
	SLIST_INIT(&pData->failedmsg_head);
	free(pData->errorFile);
	free(pData->statsFile);
	free(pData->failedMsgFile);

	/* Free other mem */
	free(pData->amqp_address);
	free(pData->azurehost);
	free(pData->azureport);
	free(pData->azure_key_name);
	free(pData->azure_key);
	free(pData->instance);
	free(pData->container);

	free(pData->tplName);
	free(pData->statsName);

	DESTROY_ATOMIC_HELPER_MUT(pData->mutCurrPartition);
	pthread_rwlock_destroy(&pData->pnLock);
	pthread_mutex_destroy(&pData->mut_doAction);
	pthread_mutex_destroy(&pData->mutErrFile);
	pthread_mutex_destroy(&pData->mutStatsFile);
ENDfreeInstance

BEGINfreeWrkrInstance
CODESTARTfreeWrkrInstance
ENDfreeWrkrInstance


BEGINdbgPrintInstInfo
CODESTARTdbgPrintInstInfo
ENDdbgPrintInstInfo

BEGINtryResume
	instanceData *const pData = pWrkrData->pData;
	int need_unlock = 0;
CODESTARTtryResume
DBGPRINTF("tryResume: ENTER\n");
	pthread_mutex_lock(&pData->mut_doAction);
	if (!pData->bIsOpen) {
		CHKiRet(setupProtonHandle(pData, 0));
	}

	/* Lock here to prevent msg loss */
	pthread_rwlock_rdlock(&pData->pnLock);
	need_unlock = 1;

// TODO CHECK IF Connection was sudcessful!
finalize_it:
	if(need_unlock) {
		pthread_rwlock_unlock(&pData->pnLock);
	}

	pthread_mutex_unlock(&pData->mut_doAction); /* see doAction header comment! */
	DBGPRINTF("omazureeventhubs: tryResume returned %d\n", iRet);
ENDtryResume

/* 
 *
 */
BEGINdoAction
CODESTARTdoAction
	//protonmsg_entry* fmsgEntry;
	instanceData *const pData = pWrkrData->pData;
	int need_unlock = 0;
// DBGPRINTF("omazureeventhubs: doAction for pData %p ENTER\n", pData);

	pthread_mutex_lock(&pData->mut_doAction);
	if (!pData->bIsOpen) {
		CHKiRet(setupProtonHandle(pData, 0));
	}

	/* Lock here to prevent msg loss */
	pthread_rwlock_rdlock(&pData->pnLock);
	need_unlock = 1;

	/* Reprocess failed messages! */
	if (pData->bResubmitOnFailure) {
		iRet = checkFailedMessages(pData);
		if(iRet != RS_RET_OK) {
			DBGPRINTF("doAction: FAILED to submit FAILED messages with status %d\n", iRet);
			ABORT_FINALIZE(iRet);
		} else {
			DBGPRINTF("doAction: SUCCESSFULLY processed FAILED messages with status\n");
		}
	}

	// Send Message to Proton 
	writeProton(pData, (const char*)ppString[0], strlen((char*)ppString[0]));
finalize_it:
	if(need_unlock) {
		pthread_rwlock_unlock(&pData->pnLock);
	}

	if(iRet != RS_RET_OK) {
		DBGPRINTF("omazureeventhubs: doAction failed with status %d\n", iRet);
	}

	/* Suspend Action if broker problems were reported in error callback */
	if (pData->bIsSuspended) {
		DBGPRINTF("omazureeventhubs: doAction broker failure detected, suspending action\n");
		iRet = RS_RET_SUSPENDED;
	}
	pthread_mutex_unlock(&pData->mut_doAction); /* must be after last pData access! */
ENDdoAction


static void
setInstParamDefaults(instanceData *pData) {
DBGPRINTF("setInstParamDefaults: ENTER\n");
	pData->amqp_address = NULL;
	pData->azurehost = NULL;
	pData->azureport = NULL;
	pData->azure_key_name = NULL;
	pData->azure_key = NULL;
	pData->instance = NULL;
	pData->container = NULL;

	pData->closeTimeout = 2000;
	pData->bReportErrs = 1;
	pData->errorFile = NULL;
	pData->statsFile = NULL;
	pData->failedMsgFile = NULL;
}

BEGINnewActInst
	struct cnfparamvals *pvals;
	int i;
	int iNumTpls;
//	instanceData **ppInstanceData;
DBGPRINTF("newActInst: ENTER\n");

CODESTARTnewActInst
	if((pvals = nvlstGetParams(lst, &actpblk, NULL)) == NULL) {
		ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
	}

	CHKiRet(createInstance(&pData));
	setInstParamDefaults(pData);

	for(i = 0 ; i < actpblk.nParams ; ++i) {
		if(!pvals[i].bUsed)
			continue;
		if(!strcmp(actpblk.descr[i].name, "amqp_address")) {
			pData->amqp_address = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
		} else if(!strcmp(actpblk.descr[i].name, "azurehost")) {
			pData->azurehost = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
		} else if(!strcmp(actpblk.descr[i].name, "azureport")) {
			pData->azureport = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
		} else if(!strcmp(actpblk.descr[i].name, "azure_key_name")) {
			pData->azure_key_name = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
		} else if(!strcmp(actpblk.descr[i].name, "azure_key")) {
			pData->azure_key = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
		} else if(!strcmp(actpblk.descr[i].name, "instance")) {
			pData->instance = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
		} else if(!strcmp(actpblk.descr[i].name, "container")) {
			pData->container = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
		} else if(!strcmp(actpblk.descr[i].name, "closetimeout")) {
			pData->closeTimeout = pvals[i].val.d.n;
		} else if(!strcmp(actpblk.descr[i].name, "errorfile")) {
			pData->errorFile = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
		} else if(!strcmp(actpblk.descr[i].name, "statsfile")) {
			pData->statsFile = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
		} else if(!strcmp(actpblk.descr[i].name, "template")) {
			pData->tplName = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
		} else if(!strcmp(actpblk.descr[i].name, "resubmitonfailure")) {
			pData->bResubmitOnFailure = pvals[i].val.d.n;
		} else if(!strcmp(actpblk.descr[i].name, "keepfailedmessages")) {
			pData->bKeepFailedMessages = pvals[i].val.d.n;
		} else if(!strcmp(actpblk.descr[i].name, "failedmsgfile")) {
			pData->failedMsgFile = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
		} else if(!strcmp(actpblk.descr[i].name, "statsname")) {
			pData->statsName = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
		} else {
			LogError(0, RS_RET_INTERNAL_ERROR,
				"omazureeventhubs: program error, non-handled param '%s'\n", actpblk.descr[i].name);
		}
	}

	if(pData->amqp_address == NULL) {
		if(pData->azurehost == NULL) {
			LogMsg(0, NO_ERRCODE, LOG_INFO, "omazureeventhubs: \"azurehost\" parameter not specified "
				"(youreventhubinstance.servicebus.windows.net- action definition invalid!");
			ABORT_FINALIZE(RS_RET_CONFIG_ERROR);
		}
		if(pData->azureport== NULL) {
			// Set default
			CHKmalloc(pData->azureport = (uchar *) strdup("amqps"));
		}
	}

	if(pData->azure_key_name == NULL || pData->azure_key == NULL) {
		LogError(0, RS_RET_CONFIG_ERROR,
			"omazureeventhubs: azure_key_name and azure_key are requires to access azure eventhubs"
			" - action definition invalid");
		ABORT_FINALIZE(RS_RET_CONFIG_ERROR);
	}

	if(pData->instance == NULL) {
		LogError(0, RS_RET_CONFIG_ERROR,
			"omazureeventhubs: Event Hubs \"instance\" parameter not specified "
			" - action definition invalid");
		ABORT_FINALIZE(RS_RET_CONFIG_ERROR);
	}

	iNumTpls = 2;
//	if(pData->dynaKey) ++iNumTpls;
//	if(pData->dynaTopic) ++iNumTpls;
	CODE_STD_STRING_REQUESTnewActInst(iNumTpls);

	CHKiRet(OMSRsetEntry(*ppOMSR, 0, (uchar*)strdup((pData->tplName == NULL) ?
						"RSYSLOG_FileFormat" : (char*)pData->tplName),
						OMSR_NO_RQD_TPL_OPTS));

	CHKiRet(OMSRsetEntry(*ppOMSR, 1, (uchar*)strdup(" AZURE_TimeStamp"),
						OMSR_NO_RQD_TPL_OPTS));

	pthread_mutex_lock(&closeTimeoutMut);
	if (closeTimeout < pData->closeTimeout) {
		closeTimeout = pData->closeTimeout;
	}
	pthread_mutex_unlock(&closeTimeoutMut);

	/* Load failed messages here (If enabled), do NOT check for IRET!*/
	if (pData->bKeepFailedMessages && pData->failedMsgFile != NULL) {
		loadFailedMsgs(pData);
	}

	if (pData->statsName) {
		CHKiRet(statsobj.Construct(&pData->stats));
		CHKiRet(statsobj.SetName(pData->stats, (uchar *)pData->statsName));
		CHKiRet(statsobj.SetOrigin(pData->stats, (uchar *)"omazureeventhubs"));

		/* Track following stats */
		STATSCOUNTER_INIT(pData->ctrMessageSubmit, pData->mutCtrMessageSubmit);
		CHKiRet(statsobj.AddCounter(pData->stats, (uchar *)"submitted",
			ctrType_IntCtr, CTR_FLAG_RESETTABLE, &pData->ctrMessageSubmit));
		STATSCOUNTER_INIT(pData->ctrAzureFail, pData->mutCtrAzureFail);
		CHKiRet(statsobj.AddCounter(pData->stats, (uchar *)"failures",
			ctrType_IntCtr, CTR_FLAG_RESETTABLE, &pData->ctrAzureFail));
		STATSCOUNTER_INIT(pData->ctrAzureAck, pData->mutCtrAzureAck);
		CHKiRet(statsobj.AddCounter(pData->stats, (uchar *)"accepted",
			ctrType_IntCtr, CTR_FLAG_RESETTABLE, &pData->ctrAzureAck));
		STATSCOUNTER_INIT(pData->ctrAzureOtherErrors, pData->mutCtrAzureOtherErrors);
		CHKiRet(statsobj.AddCounter(pData->stats, (uchar *)"othererrors",
			ctrType_IntCtr, CTR_FLAG_RESETTABLE, &pData->ctrAzureOtherErrors));
		CHKiRet(statsobj.ConstructFinalize(pData->stats));
	}

	// --- Create PROTON Handler, assign own instanceData 
	DBGPRINTF("CREATE NEW PROACTOR\n");
	pData->pnProactor= pn_proactor();
/*
//	pData->pnReactor = pn_reactor();
DBGPRINTF("pn_handler_new: CREATE HANDLER\n");
	pData->pnHandler = pn_handler_new(handleProton, sizeof(instanceData), handleProtonDel);
	ppInstanceData = (instanceData **) pn_handler_mem(pData->pnHandler);
	*ppInstanceData = pData;

	pn_handler_add(pData->pnHandler, pn_handshaker());
*/
	// --- 

CODE_STD_FINALIZERnewActInst
	cnfparamvalsDestruct(pvals, &actpblk);
ENDnewActInst


BEGINmodExit
CODESTARTmodExit
DBGPRINTF("modExit: ENTER\n");
	statsobj.Destruct(&azureStats);
	CHKiRet(objRelease(statsobj, CORE_COMPONENT));
	DESTROY_ATOMIC_HELPER_MUT(mutClock);

	pthread_mutex_lock(&closeTimeoutMut);
//	int timeout = closeTimeout;
	pthread_mutex_unlock(&closeTimeoutMut);
	pthread_mutex_destroy(&closeTimeoutMut);

	objRelease(glbl, CORE_COMPONENT);
finalize_it:
ENDmodExit


NO_LEGACY_CONF_parseSelectorAct
BEGINqueryEtryPt
CODESTARTqueryEtryPt
CODEqueryEtryPt_STD_OMOD_QUERIES
CODEqueryEtryPt_STD_OMOD8_QUERIES
CODEqueryEtryPt_STD_CONF2_CNFNAME_QUERIES
CODEqueryEtryPt_STD_CONF2_OMOD_QUERIES
CODEqueryEtryPt_doHUP
ENDqueryEtryPt


BEGINmodInit()
CODESTARTmodInit
	uchar *pTmp;
DBGPRINTF("modInit: ENTER\n");
INITLegCnfVars
	*ipIFVersProvided = CURR_MOD_IF_VERSION;
CODEmodInit_QueryRegCFSLineHdlr
	/* request objects we use */
	CHKiRet(objUse(glbl, CORE_COMPONENT));
	CHKiRet(objUse(datetime, CORE_COMPONENT));
	CHKiRet(objUse(strm, CORE_COMPONENT));
	CHKiRet(objUse(statsobj, CORE_COMPONENT));

//	INIT_ATOMIC_HELPER_MUT(mutClock);

	DBGPRINTF("omazureeventhubs %s using libuampq library %s, 0x%x\n",
	          VERSION, "TODO", 1/*UAMQP_VERSION*/);

	CHKiRet(statsobj.Construct(&azureStats));
	CHKiRet(statsobj.SetName(azureStats, (uchar *)"omazureeventhubs"));
	CHKiRet(statsobj.SetOrigin(azureStats, (uchar*)"omazureeventhubs"));
	STATSCOUNTER_INIT(ctrMessageSubmit, mutCtrMessageSubmit);
	CHKiRet(statsobj.AddCounter(azureStats, (uchar *)"submitted",
		ctrType_IntCtr, CTR_FLAG_RESETTABLE, &ctrMessageSubmit));
	STATSCOUNTER_INIT(ctrAzureFail, mutCtrAzureFail);
	CHKiRet(statsobj.AddCounter(azureStats, (uchar *)"failures",
		ctrType_IntCtr, CTR_FLAG_RESETTABLE, &ctrAzureFail));
	STATSCOUNTER_INIT(ctrAzureAck, mutCtrAzureAck);
	CHKiRet(statsobj.AddCounter(azureStats, (uchar *)"accepted",
		ctrType_IntCtr, CTR_FLAG_RESETTABLE, &ctrAzureAck));
	STATSCOUNTER_INIT(ctrAzureOtherErrors, mutCtrAzureOtherErrors);
	CHKiRet(statsobj.AddCounter(azureStats, (uchar *)"failures_other",
		ctrType_IntCtr, CTR_FLAG_RESETTABLE, &ctrAzureOtherErrors));
	CHKiRet(statsobj.ConstructFinalize(azureStats));

	DBGPRINTF("omazureeventhubs: Add AZURE_TimeStamp to template system ONCE\n");
	pTmp = (uchar*) AZURE_TimeStamp;
	tplAddLine(ourConf, " AZURE_TimeStamp", &pTmp);

	protonWrkrInfo = NULL;
ENDmodInit
