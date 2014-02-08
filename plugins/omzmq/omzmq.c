/* omzmq.c
 * Copyright 2014 Brian Knox
*
* This program is free software: you can redistribute it and/or
* modify it under the terms of the GNU Lesser General Public License
* as published by the Free Software Foundation, either version 3 of
* the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful, but
* WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public
* License along with this program. If not, see
* <http://www.gnu.org/licenses/>.
*
* Author: Brian Knox
* <taotetek@gmail.com>
*/


#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <time.h>
#include <hiredis/hiredis.h>
#include <czmq.h>

#include "rsyslog.h"
#include "conf.h"
#include "syslogd-types.h"
#include "srUtils.h"
#include "template.h"
#include "module-template.h"
#include "errmsg.h"
#include "cfsysline.h"

MODULE_TYPE_OUTPUT
MODULE_TYPE_NOKEEP
MODULE_CNFNAME("omzmq")
/* internal structures
 */
DEF_OMOD_STATIC_DATA
DEFobjCurrIf(errmsg)

/*  our instance data.
 *  this will be accessable 
 *  via pData */
typedef struct _instanceData {
    zctx_t *ctx; /* zeromq context */
	const char *endPoint; /*  zeromq endpoint */
	int socketType; /*  zeromq socket type */
	uchar *tplName; /*  template name */
} instanceData;

typedef struct wrkrInstanceData {
	instanceData *pData;
    void *zocket; /* zeromq socket */
} wrkrInstanceData_t;

static struct cnfparamdescr actpdescr[] = {
	{ "endpoint", eCmdHdlrGetWord, 0 },
	{ "sockettype", eCmdHdlrInt, 0 },
	{ "template", eCmdHdlrGetWord, 1 }
};
static struct cnfparamblk actpblk = {
	CNFPARAMBLK_VERSION,
	sizeof(actpdescr)/sizeof(struct cnfparamdescr),
	actpdescr
};

BEGINcreateInstance
CODESTARTcreateInstance
ENDcreateInstance

BEGINcreateWrkrInstance
CODESTARTcreateWrkrInstance
	pWrkrData->zocket = NULL; /* Connect later */
ENDcreateWrkrInstance

BEGINisCompatibleWithFeature
CODESTARTisCompatibleWithFeature
	if(eFeat == sFEATURERepeatedMsgReduction)
		iRet = RS_RET_OK;
ENDisCompatibleWithFeature

/*  called when closing */
static void closeZMQ (wrkrInstanceData_t *pWrkrData)
{
	if(pWrkrData->zocket != NULL) {
        zsocket_destroy (pWrkrData->pData->ctx, pWrkrData->zocket);
		pWrkrData->zocket = NULL;
	}
}

/*  Free our instance data.
 *  TODO: free **replies */
BEGINfreeInstance
CODESTARTfreeInstance
	if (pData->ctx != NULL) {
        zctx_destroy (&pData->ctx);
	}
ENDfreeInstance

BEGINfreeWrkrInstance
CODESTARTfreeWrkrInstance
	closeZMQ(pWrkrData);
ENDfreeWrkrInstance

BEGINdbgPrintInstInfo
CODESTARTdbgPrintInstInfo
	/* nothing special here */
ENDdbgPrintInstInfo

/*  establish our connection to redis */
static rsRetVal initZMQ(wrkrInstanceData_t *pWrkrData, int bSilent)
{
	const char *endpoint;
    DEFiRet;

	endpoint = (pWrkrData->pData->endPoint == NULL) ? "ipc:///tmp/test" : 
			(char*) pWrkrData->pData->endPoint;
	DBGPRINTF("omzmq: trying connect to '%s'", endpoint);
	
    pWrkrData->zocket = zsocket_new (pWrkrData->pData->ctx, pWrkrData->pData->socketType);
    int rc = zsocket_connect (pWrkrData->zocket, endpoint);
	if (rc == -1) {
		if(!bSilent)
			errmsg.LogError(0, RS_RET_SUSPENDED,
				"can not initialize zeromq socket");
		ABORT_FINALIZE(RS_RET_SUSPENDED);
	}
finalize_it:
	RETiRet;
}

rsRetVal writeZMQ(uchar *message, wrkrInstanceData_t *pWrkrData)
{
	DEFiRet;

	/*  if we do not have a zeromq connection, call
	 *  initZMQ and try to establish one */
	if(pWrkrData->zocket == NULL)
		CHKiRet(initZMQ(pWrkrData, 0));

    /* try to send the message */
    zmsg_t *msg = zmsg_new ();
    zmsg_addstr (msg, "%s", (char*)message);
    int rc = zmsg_send (&msg, pWrkrData->zocket); 
	if (rc == -1) {
		errmsg.LogError(0, NO_ERRCODE, "omzmq: error sending message");
		dbgprintf("omzmq: error sending message");
		ABORT_FINALIZE(RS_RET_ERR);
	} 
finalize_it:
	RETiRet;
}

/*  called when resuming from suspended state. */
BEGINtryResume
CODESTARTtryResume
	if(pWrkrData->zocket == NULL)
		iRet = initZMQ(pWrkrData, 0);
ENDtryResume

/*  call writeHiredis for this log line,
 *  which appends it as a command to the
 *  current pipeline */
BEGINdoAction
CODESTARTdoAction
	CHKiRet(writeZMQ(ppString[0], pWrkrData));
	iRet = RS_RET_DEFER_COMMIT;
finalize_it:
ENDdoAction

/*  set defaults. note server is set to NULL 
 *  and is set to a default in initHiredis if 
 *  it is still null when it's called - I should
 *  probable just set the default here instead */
static inline void
setInstParamDefaults(instanceData *pData)
{
    pData->ctx = zctx_new ();
	pData->endPoint = NULL;
	pData->socketType = 1;
	pData->tplName = NULL;
}

/*  here is where the work to set up a new instance
 *  is done.  this reads the config options from 
 *  the rsyslog conf and takes appropriate setup
 *  actions. */
BEGINnewActInst
	struct cnfparamvals *pvals;
	int i;
CODESTARTnewActInst
	if((pvals = nvlstGetParams(lst, &actpblk, NULL)) == NULL)
		ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);

	CHKiRet(createInstance(&pData));
	setInstParamDefaults(pData);

	CODE_STD_STRING_REQUESTnewActInst(1)
	for(i = 0 ; i < actpblk.nParams ; ++i) {
		if(!pvals[i].bUsed)
			continue;
	
		if(!strcmp(actpblk.descr[i].name, "endpoint")) {
			pData->endPoint = (const char*)es_str2cstr(pvals[i].val.d.estr, NULL);
		} else if(!strcmp(actpblk.descr[i].name, "sockettype")) {
			pData->socketType = (int) pvals[i].val.d.n;
		} else if(!strcmp(actpblk.descr[i].name, "template")) {
			pData->tplName = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
		} else {
			dbgprintf("omzmq: program error, non-handled "
				"param '%s'\n", actpblk.descr[i].name);
		}
	}

	if(pData->tplName == NULL) {
		dbgprintf("omzmq: action requires a template name");
		ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
	}

	/* template string 0 is just a regular string */
	OMSRsetEntry(*ppOMSR, 0,(uchar*)pData->tplName, OMSR_NO_RQD_TPL_OPTS);

CODE_STD_FINALIZERnewActInst
	cnfparamvalsDestruct(pvals, &actpblk);
ENDnewActInst


BEGINparseSelectorAct
CODESTARTparseSelectorAct

/* tell the engine we only want one template string */
CODE_STD_STRING_REQUESTparseSelectorAct(1)
	if(!strncmp((char*) p, ":omzmq:", sizeof(":omzmq:") - 1)) 
		errmsg.LogError(0, RS_RET_LEGA_ACT_NOT_SUPPORTED,
			"omzmq supports only v6 config format, use: "
			"action(type=\"omzmq\" endpoint=...)");
	ABORT_FINALIZE(RS_RET_CONFLINE_UNPROCESSED);
CODE_STD_FINALIZERparseSelectorAct
ENDparseSelectorAct


BEGINmodExit
CODESTARTmodExit
ENDmodExit

/*  register our plugin entry points
 *  with the rsyslog core engine */
BEGINqueryEtryPt
CODESTARTqueryEtryPt
CODEqueryEtryPt_STD_OMOD_QUERIES
CODEqueryEtryPt_STD_OMOD8_QUERIES
CODEqueryEtryPt_STD_CONF2_OMOD_QUERIES
ENDqueryEtryPt

/*  note we do not support rsyslog v5 syntax */
BEGINmodInit()
CODESTARTmodInit
	*ipIFVersProvided = CURR_MOD_IF_VERSION; /* only supports rsyslog 6 configs */
CODEmodInit_QueryRegCFSLineHdlr
	CHKiRet(objUse(errmsg, CORE_COMPONENT));
	INITChkCoreFeature(bCoreSupportsBatching, CORE_FEATURE_BATCHING);
	if (!bCoreSupportsBatching) {
		errmsg.LogError(0, NO_ERRCODE, "omzmq: rsyslog core does not support batching - abort");
		ABORT_FINALIZE(RS_RET_ERR);
	}
	DBGPRINTF("omzmq: module compiled with rsyslog version %s.\n", VERSION);
ENDmodInit
