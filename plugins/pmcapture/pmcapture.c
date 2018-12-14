/* pmcapture.c
 *
 * This is a parser intended to work in coordination with impcap.
 * This module gets data from the impcap module, and follow streams
 * to capture relevant data, such as files, from packets.
 *
 * File begun on 2018-11-13
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
 #include <stdlib.h>
 #include <assert.h>
 #include <string.h>
 #include <errno.h>
 #include <unistd.h>
 #include <stdarg.h>
 #include <ctype.h>
 #include <json.h>
 #include <sys/types.h>    
 #include <sys/stat.h>

 #include "rsyslog.h"
 #include "errmsg.h"
 #include "unicode-helper.h"
 #include "module-template.h"
 #include "rainerscript.h"
 #include "rsconf.h"

MODULE_TYPE_PARSER
MODULE_TYPE_NOKEEP
MODULE_CNFNAME("pmcapture")

PARSER_NAME("pmcapture")

/* static data */
DEF_IMOD_STATIC_DATA
#define FOLDERNAME "pmcapture_files"
/* conf structures */

struct instanceConf_s {
  struct instanceConf_s *next;
};

struct modConfData_s {
  rsconf_t *pConf;
  instanceConf_t *root, *tail;
};

static modConfData_t *loadModConf = NULL;/* modConf ptr to use for the current load process */

/* input instance parameters */
static struct cnfparamdescr inppdescr[] = {
	{ "interface", eCmdHdlrString, 0 }
};
static struct cnfparamblk inppblk =
	{ CNFPARAMBLK_VERSION,
	  sizeof(inppdescr)/sizeof(struct cnfparamdescr),
	  inppdescr
	};

/* module-global parameters */
static struct cnfparamdescr modpdescr[] = {
	{ "snap_length", eCmdHdlrPositiveInt, 0 }
};
static struct cnfparamblk modpblk =
	{ CNFPARAMBLK_VERSION,
	  sizeof(modpdescr)/sizeof(struct cnfparamdescr),
	  modpdescr
	};

/* create parser instance, set default parameters, and
 * add it to the list of instances.
 */
static rsRetVal
createInstance(instanceConf_t **pinst)
{
	instanceConf_t *inst;
	DEFiRet;
	CHKmalloc(inst = malloc(sizeof(instanceConf_t)));

	/* node created, let's add to global config */
	if(loadModConf->tail == NULL) {
		loadModConf->tail = loadModConf->root = inst;
	} else {
		loadModConf->tail->next = inst;
		loadModConf->tail = inst;
	}

	*pinst = inst;
finalize_it:
	RETiRet;
}

/* parser instances */

BEGINnewParserInst
  struct cnfparamvals *pvals;
  int i;
CODESTARTnewParserInst
  pvals = nvlstGetParams(lst, &inppblk, NULL);

  if(pvals == NULL) {
    LogError(0, RS_RET_MISSING_CNFPARAMS,
              "pmcapture: required parameters are missing\n");
    ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
  }

  CHKiRet(createInstance(&inst));

  for(i = 0 ; i < inppblk.nParams ; ++i) {
    if(!pvals[i].bUsed)
      continue;
    // if(!strcmp(inppblk.descr[i].name, "interface")) {
    //   inst->interface = (uchar*) es_str2cstr(pvals[i].val.d.estr, NULL);
    // }
    // else {
    //   dbgprintf("pmcapture: non-handled param %s in beginCnfLoad\n", inppblk.descr[i].name);
    // }
  }

finalize_it:
CODE_STD_FINALIZERnewParserInst
  cnfparamvalsDestruct(pvals, &inppblk);
ENDnewParserInst

BEGINfreeParserInst
CODESTARTfreeParserInst
ENDfreeParserInst

/* global mod conf (v2 system) */

BEGINsetModCnf
  struct cnfparamvals *pvals = NULL;
  int i;
CODESTARTsetModCnf

  pvals = nvlstGetParams(lst, &modpblk, NULL);

  for(i = 0 ; i < modpblk.nParams ; ++i) {
    if(!pvals[i].bUsed)
      continue;
    // if(!strcmp(modpblk.descr[i].name, "snap_length")) {
    //   loadModConf->snap_length = (int) pvals[i].val.d.n;
    // }
    // else {
    //   dbgprintf("pmcapture: non-handled param %s in beginSetModCnf\n", modpblk.descr[i].name);
    // }
  }
ENDsetModCnf

/* config v2 system */

BEGINbeginCnfLoad
CODESTARTbeginCnfLoad
  loadModConf = pModConf;
  loadModConf->pConf = pConf;
ENDbeginCnfLoad

BEGINendCnfLoad
CODESTARTendCnfLoad
ENDendCnfLoad

BEGINcheckCnf
  instanceConf_t *inst;
CODESTARTcheckCnf
  if(pModConf->root == NULL) {
    LogError(0, RS_RET_NO_LISTNERS , "pmcapture: module loaded, but "
        "no interface defined - no input will be gathered");
    iRet = RS_RET_NO_LISTNERS;
  }

  for(inst = loadModConf->root ; inst != NULL ; inst = inst->next) {
    // add conditions if necessary
  }
ENDcheckCnf

BEGINactivateCnf
  instanceConf_t *inst;
CODESTARTactivateCnf
  loadModConf = pModConf;

  for(inst = loadModConf->root ; inst != NULL ; inst = inst->next) {
    // add activation actions
  }

finalize_it:
ENDactivateCnf

BEGINfreeCnf
CODESTARTfreeCnf
ENDfreeCnf

/* runtime functions */

int createfolder(char* folder){
    struct stat file_stat;
    char index[512]="";
    strcat(index,folder);
    strcat(index,"/");
    strcat(index,FOLDERNAME);

    ret = stat(index, &file_stat);
    if(ret<0)
    {
        if(errno == ENOENT)
        {
            ret = mkdir(index, 0775);
            if(ret < 0)
            {
		return 1;
            }
        }
    }
    return 0;
}


BEGINparse2
CODESTARTparse2
ENDparse2

BEGINmodExit
CODESTARTmodExit
ENDmodExit

/* declaration of functions */

BEGINqueryEtryPt
CODESTARTqueryEtryPt
CODEqueryEtryPt_STD_MOD_QUERIES
CODEqueryEtryPt_STD_CONF2_QUERIES
CODEqueryEtryPt_STD_PMOD2_QUERIES
CODEqueryEtryPt_STD_CONF2_setModCnf_QUERIES
ENDqueryEtryPt

BEGINmodInit()
CODESTARTmodInit
  *ipIFVersProvided = CURR_MOD_IF_VERSION;
ENDmodInit
