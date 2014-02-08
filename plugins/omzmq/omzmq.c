/* omzmq.c
 * Copyright 2014 Brian Knox
 * Using the czmq interface to zeromq, we output
 * to a zmq socket.


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
#include "rsyslog.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include "conf.h"
#include "syslogd-types.h"
#include "srUtils.h"
#include "template.h"
#include "module-template.h"
#include "errmsg.h"
#include "cfsysline.h"

#include <czmq.h>

MODULE_TYPE_OUTPUT
MODULE_TYPE_NOKEEP
MODULE_CNFNAME("omzmq")

static rsRetVal resetConfigVariables (uchar __attribute__((unused)) *pp, void __attribute__((unused)) *pVal);

DEF_OMOD_STATIC_DATA
DEFobjCurrIf(errmsg)

typedef struct _instanceData {
    zctx_t *ctx;
	uchar*  endpoint;
    int     socktype;
    uchar*  tplName;
} instanceData;

typedef struct wrkrInstanceData {
    instanceData *pData;
    void *zocket;
}

static struct cnfparamdescr actpdescr[] = {
	{ "endpoint",            eCmdHdlrGetWord, 0 },
    { "socktype",                eCmdHdlrGetWord, 0 },
    { "action",              eCmdHdlrGetWord, 0 },
    { "template",            eCmdHdlrGetWord, 1 }
};

static struct cnfparamblk actpblk = {
	CNFPARAMBLK_VERSION,
	sizeof(actpdescr)/sizeof(struct cnfparamdescr),
	actpdescr
};

BEGINinitConfVars
CODESTARTinitConfVars
    resetConfigVariables (NULL, NULL);
ENDinitConfVars

BEGINcreateInstance
CODESTARTcreateInstance
ENDcreateInstance

BEGINcreateWrkrInstance
CODESTARTcreateWrkrInstance
ENDcreateWrkrInstance

BEGINisCompatibleWithFeature
CODESTARTisCompatibleWithFeature
	if(eFeat == sFEATURERepeatedMsgReduction)
		iRet = RS_RET_OK;
ENDisCompatibleWithFeature

BEGINfreeInstance
CODESTARTfreeInstance
	free(pData->tplName);
ENDfreeInstance

BEGINfreeWrkrInstance
CODESTARTfreeWrkrInstance
	closeMySQL(pWrkrData);
ENDfreeWrkrInstance

BEGINdbgPrintInstInfo
CODESTARTdbgPrintInstInfo
	/* nothing special here */
ENDdbgPrintInstInfo

static rsRetVal initZMQ (wrkrInstanceData_t *pWrkData, int bSilent)
{
    instanceData *pData;
    DEFiRet;

    ASSERT (pWrkrData->zocket == NULL);
    pData = pWrkrData->pData;
    
    // TODO: initialize socket
finalize_it:
    RETiRet;
}

rsRetVal writeZMQ (wrkrInstanceData_t *pWrkrData, uchar *psz)
{
    DEFiRet;

    if (pWrkrData->zocket == NULL) {
        CHKiRet (initZMQ (pWrkrData, 0));
    }

    // TODO: write to socket
finalize_it:
    RETiRet;
}

BEGINtryResume
CODESTARTtryResume
	if(pWrkrData->zocket == NULL) {
		iRet = initZMQ(pWrkrData, 1);
	}
ENDtryResume

static inline void
setInstParamDefaults(instanceData *pData)
{
	pData->tplName = NULL;
}

BEGINcreateInstance
CODESTARTcreateInstance
ENDcreateInstance

BEGINisCompatibleWithFeature
CODESTARTisCompatibleWithFeature
	if(eFeat == sFEATURERepeatedMsgReduction)
		iRet = RS_RET_OK;
ENDisCompatibleWithFeature


BEGINdbgPrintInstInfo
CODESTARTdbgPrintInstInfo
ENDdbgPrintInstInfo

BEGINfreeInstance
CODESTARTfreeInstance
	closeZMQ(pData);
	free(pData->endpoint);
	free(pData->tplName);
ENDfreeInstance

BEGINtryResume
CODESTARTtryResume
	if(NULL == pData->socket)
		iRet = initZMQ(pData);
ENDtryResume

BEGINdoAction
CODESTARTdoAction
iRet = writeZMQ(ppString[0], pData);
ENDdoAction


BEGINnewActInst
    struct cnfparamvals *pvals;
    int i;
CODESTARTnewActInst
    if ((pvals = nvlstGetParams(lst, &actpblk, NULL)) == NULL) {
        ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
    }

CHKiRet(createInstance(&pData));
setInstParamDefaults(pData);

CODE_STD_STRING_REQUESTnewActInst(1)
    for (i = 0; i < actpblk.nParams; ++i) {
        if (!pvals[i].bUsed)
            continue;
        if (!strcmp(actpblk.descr[i].name, "endpoint")) {
            pData->description = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
        } else if (!strcmp(actpblk.descr[i].name, "template")) {
            pData->tplName = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
        } else if (!strcmp(actpblk.descr[i].name, "socktype")){
            pData->type = getSocketType(es_str2cstr(pvals[i].val.d.estr, NULL));
        } else {
            errmsg.LogError(0, NO_ERRCODE, "omzmq: program error, non-handled "
        }
    }

    if (pData->tplName == NULL) {
        CHKiRet(OMSRsetEntry(*ppOMSR, 0, (uchar*)strdup("RSYSLOG_ForwardFormat"), OMSR_NO_RQD_TPL_OPTS));
    } else {
        CHKiRet(OMSRsetEntry(*ppOMSR, 0, (uchar*)pData->tplName, OMSR_NO_RQD_TPL_OPTS));
    }
    if (NULL == pData->endpoint) {
        errmsg.LogError(0, RS_RET_CONFIG_ERROR, "omzmq: endpoint is required");
        ABORT_FINALIZE(RS_RET_CONFIG_ERROR);
    }
    if (pData->type == -1) {
        errmsg.LogError(0, RS_RET_CONFIG_ERROR, "omzmq: invalid socket type.");
        ABORT_FINALIZE(RS_RET_CONFIG_ERROR);
    }

CODE_STD_FINALIZERnewActInst
    cnfparamvalsDestruct(pvals, &actpblk);
ENDnewActInst

BEGINparseSelectorAct
CODESTARTparseSelectorAct

CODE_STD_STRING_REQUESTparseSelectorAct(1)
	if(!strncmp((char*) p, ":omzmq:", sizeof(":omzmq:") - 1)) 
		errmsg.LogError(0, RS_RET_LEGA_ACT_NOT_SUPPORTED,
			"omzmq supports only v6 config format, use: "
			"action(type=\"omzmq\" socktype=...)");
	ABORT_FINALIZE(RS_RET_CONFLINE_UNPROCESSED);
CODE_STD_FINALIZERparseSelectorAct
ENDparseSelectorAct

BEGINinitConfVars /* (re)set config variables to defaults */
CODESTARTinitConfVars
ENDinitConfVars

BEGINmodExit
CODESTARTmodExit
    if (NULL != s_context) {
        zctx_destroy(&s_context);
        s_context=NULL;
    }
ENDmodExit


BEGINqueryEtryPt
CODESTARTqueryEtryPt
CODEqueryEtryPt_STD_OMOD_QUERIES
CODEqueryEtryPt_STD_CONF2_OMOD_QUERIES
ENDqueryEtryPt

BEGINmodInit()
CODESTARTmodInit
	*ipIFVersProvided = CURR_MOD_IF_VERSION; /* only supports rsyslog 6 configs */
CODEmodInit_QueryRegCFSLineHdlr
	CHKiRet(objUse(errmsg, CORE_COMPONENT));
	INITChkCoreFeature(bCoreSupportsBatching, CORE_FEATURE_BATCHING);
	DBGPRINTF("omzmq3: module compiled with rsyslog version %s.\n", VERSION);

INITLegCnfVars
CHKiRet(omsdRegCFSLineHdlr((uchar *)"omzmqworkerthreads", 0, eCmdHdlrInt, NULL, &s_workerThreads, STD_LOADABLE_MODULE_ID));
ENDmodInit



