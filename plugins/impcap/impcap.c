/* impcap.c
 *
 * This is an input module using libpcap, a
 * portable C/C++ library for network traffic capture.
 * This module reads packets received from a network interface
 * using libpcap, to extract information such as IP addresses, ports,
 * protocols, etc... and make it available to rsyslog and other modules.
 *
 * File begun on 2018-11-13
 *
 * Created by:
 *  - François Bernard (francois.bernard@isen.yncrea.fr)
 *  - Théo Bertin (theo.bertin@isen.yncrea.fr)
 *  - Tianyu Geng (tianyu.geng@isen.yncrea.fr)
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

 #include <pcap.h>

 #include "rsyslog.h"
 #include "prop.h"
 #include "ruleset.h"

 #include "errmsg.h"
 #include "unicode-helper.h"
 #include "module-template.h"
 #include "rainerscript.h"
 #include "rsconf.h"
 #include "glbl.h"

 #include "parser.h"


MODULE_TYPE_INPUT
MODULE_TYPE_NOKEEP
MODULE_CNFNAME("impcap")

#define JSON_LOOKUP_NAME "!impcap"
#define JSON_DATA_NAME "!data"


/* static data */
DEF_IMOD_STATIC_DATA
DEFobjCurrIf(glbl)
DEFobjCurrIf(prop)
DEFobjCurrIf(ruleset)

static prop_t *pInputName = NULL;

/* --- init prototypes --- */
void init_eth_proto_handlers();
void init_ip_proto_handlers();

/* conf structures */

struct instanceConf_s {
  uchar *interface;
  uchar *filePath;
  pcap_t *device;
  uchar *filter;
  uchar *tag;
  uint8_t promiscuous;
  uint8_t immediateMode;
  uint32_t bufSize;
  uint8_t bufTimeout;
  uint8_t pktBatchCnt;
  pthread_t tid;
  uchar *pszBindRuleset;		/* name of ruleset to bind to */
  ruleset_t *pBindRuleset;	/* ruleset to bind listener to (use system default if unspecified) */
  struct instanceConf_s *next;
};

struct modConfData_s {
  rsconf_t *pConf;
  instanceConf_t *root, *tail;
  uint16_t snap_length;
  uint8_t metadataOnly;
};

static modConfData_t *loadModConf = NULL;/* modConf ptr to use for the current load process */

/* input instance parameters */
static struct cnfparamdescr inppdescr[] = {
	{ "interface", eCmdHdlrString, 0 },
  { "file", eCmdHdlrString, 0},
  { "promiscuous", eCmdHdlrBinary, 0 },
  { "filter", eCmdHdlrString, 0 },
  { "tag", eCmdHdlrString, 0 },
  { "ruleset", eCmdHdlrString, 0 },
  { "no_buffer", eCmdHdlrBinary, 0 },
  { "buffer_size", eCmdHdlrPositiveInt, 0 },
  { "buffer_timeout", eCmdHdlrPositiveInt, 0 },
  { "packet_count", eCmdHdlrPositiveInt, 0 }
};
static struct cnfparamblk inppblk =
	{ CNFPARAMBLK_VERSION,
	  sizeof(inppdescr)/sizeof(struct cnfparamdescr),
	  inppdescr
	};

/* module-global parameters */
static struct cnfparamdescr modpdescr[] = {
	{ "snap_length", eCmdHdlrPositiveInt, 0 },
  { "metadata_only", eCmdHdlrBinary, 0 }
};
static struct cnfparamblk modpblk =
	{ CNFPARAMBLK_VERSION,
	  sizeof(modpdescr)/sizeof(struct cnfparamdescr),
	  modpdescr
	};

 #include "im-helper.h"

/*
 * create input instance, set default parameters, and
 * add it to the list of instances.
 */
static rsRetVal
createInstance(instanceConf_t **pinst)
{
	instanceConf_t *inst;
	DEFiRet;
	CHKmalloc(inst = malloc(sizeof(instanceConf_t)));
	inst->next = NULL;
  	inst->interface = NULL;
  	inst->filePath = NULL;
  	inst->device = NULL;
  	inst->promiscuous = 0;
  	inst->filter = NULL;
  	inst->tag = NULL;
  	inst->pszBindRuleset = NULL;
  	inst->immediateMode = 0;
  	inst->bufTimeout = 10;
  	inst->bufSize = 1024 * 1024 * 15;   /* should be enough for up to 10Gb interface*/
  	inst->pktBatchCnt = 5;

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

/* input instances */

BEGINnewInpInst
  struct cnfparamvals *pvals;
  instanceConf_t *inst;
  int i;
CODESTARTnewInpInst
  pvals = nvlstGetParams(lst, &inppblk, NULL);

  if(pvals == NULL) {
    LogError(0, RS_RET_MISSING_CNFPARAMS,
              "impcap: required parameters are missing\n");
    ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
  }

  CHKiRet(createInstance(&inst));

  for(i = 0 ; i < inppblk.nParams ; ++i) {
    if(!pvals[i].bUsed)
      continue;
    if(!strcmp(inppblk.descr[i].name, "interface")) {
      inst->interface = (uchar*) es_str2cstr(pvals[i].val.d.estr, NULL);
    }
    else if(!strcmp(inppblk.descr[i].name, "file")) {
      inst->filePath = (uchar*) es_str2cstr(pvals[i].val.d.estr, NULL);
    }
    else if(!strcmp(inppblk.descr[i].name, "promiscuous")) {
      inst->promiscuous = (uint8_t) pvals[i].val.d.n;
    }
    else if(!strcmp(inppblk.descr[i].name, "filter")) {
      inst->filter = (uchar*) es_str2cstr(pvals[i].val.d.estr, NULL);
    }
    else if(!strcmp(inppblk.descr[i].name, "tag")) {
      inst->tag = (uchar*) es_str2cstr(pvals[i].val.d.estr, NULL);
    }
    else if(!strcmp(inppblk.descr[i].name, "ruleset")) {
      inst->pszBindRuleset = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
    }
    else if(!strcmp(inppblk.descr[i].name, "no_buffer")) {
      inst->immediateMode = (uint8_t) pvals[i].val.d.n;
    }
    else if(!strcmp(inppblk.descr[i].name, "buffer_size")) {
      inst->bufSize = (uint32_t) pvals[i].val.d.n;
    }
    else if(!strcmp(inppblk.descr[i].name, "buffer_timeout")) {
      inst->bufTimeout = (uint8_t) pvals[i].val.d.n;
    }
    else if(!strcmp(inppblk.descr[i].name, "packet_count")) {
      inst->pktBatchCnt = (uint8_t) pvals[i].val.d.n;
    }
    else {
      dbgprintf("impcap: non-handled param %s in beginCnfLoad\n", inppblk.descr[i].name);
    }
  }

finalize_it:
CODE_STD_FINALIZERnewInpInst
  cnfparamvalsDestruct(pvals, &inppblk);
ENDnewInpInst

/* global mod conf (v2 system) */

BEGINsetModCnf
  struct cnfparamvals *pvals = NULL;
  int i;
CODESTARTsetModCnf

  /* TODO: find a better place for this */
  init_ip_proto_handlers();
  init_eth_proto_handlers();

  pvals = nvlstGetParams(lst, &modpblk, NULL);

  for(i = 0 ; i < modpblk.nParams ; ++i) {
    if(!pvals[i].bUsed)
      continue;
    if(!strcmp(modpblk.descr[i].name, "snap_length")) {
      loadModConf->snap_length = (int) pvals[i].val.d.n;
    }
    else if(!strcmp(modpblk.descr[i].name, "metadata_only")) {
      loadModConf->metadataOnly = (uint8_t) pvals[i].val.d.n;
    }
    else {
      dbgprintf("impcap: non-handled param %s in beginSetModCnf\n", modpblk.descr[i].name);
    }
  }
ENDsetModCnf

/* config v2 system */

BEGINbeginCnfLoad
CODESTARTbeginCnfLoad
  loadModConf = pModConf;
  loadModConf->pConf = pConf;
  loadModConf->metadataOnly = 0;
  loadModConf->snap_length = 65535;
ENDbeginCnfLoad

BEGINendCnfLoad
CODESTARTendCnfLoad
ENDendCnfLoad


/* function to generate error message if framework does not find requested ruleset */
static inline void
std_checkRuleset_genErrMsg(__attribute__((unused)) modConfData_t *modConf, instanceConf_t *inst)
{
	LogError(0, NO_ERRCODE, "impcap: ruleset '%s' for interface %s not found - "
			"using default ruleset instead", inst->pszBindRuleset,
			inst->interface);
}

BEGINcheckCnf
  instanceConf_t *inst;
CODESTARTcheckCnf
  if(pModConf->root == NULL) {
    LogError(0, RS_RET_NO_LISTNERS , "impcap: module loaded, but "
        "no interface defined - no input will be gathered");
    iRet = RS_RET_NO_LISTNERS;
  }

  if(loadModConf->metadataOnly) {   /* if metadata_only is "on", snap_length is overwritten */
    loadModConf->snap_length = 100; /* arbitrary value, but should be enough for most protocols */
  }

  for(inst = loadModConf->root ; inst != NULL ; inst = inst->next) {
    std_checkRuleset(pModConf, inst);
    if(inst->interface == NULL && inst->filePath == NULL) {
      iRet = RS_RET_INVALID_PARAMS;
      LogError(0, RS_RET_LOAD_ERROR, "impcap: 'interface' or 'file' must be specified");
      break;
    }
    if(inst->interface != NULL && inst->filePath != NULL) {
      iRet = RS_RET_INVALID_PARAMS;
      LogError(0, RS_RET_LOAD_ERROR, "impcap: either 'interface' or 'file' must be specified");
      break;
    }
  }

ENDcheckCnf

BEGINactivateCnfPrePrivDrop
CODESTARTactivateCnfPrePrivDrop
ENDactivateCnfPrePrivDrop

BEGINactivateCnf
  instanceConf_t *inst;
  pcap_t *dev;
  struct bpf_program filter_program;
  bpf_u_int32 SubNet,NetMask;
  char errBuf[PCAP_ERRBUF_SIZE];
  uint8_t retCode = 0;
CODESTARTactivateCnf
  loadModConf = pModConf;

  for(inst = loadModConf->root ; inst != NULL ; inst = inst->next) {
    if(inst->filePath != NULL) {
      dev = pcap_open_offline((const char *)inst->filePath, errBuf);
      if(dev == NULL) {
        LogError(0, RS_RET_LOAD_ERROR, "pcap: error while opening capture file: '%s'", errBuf);
        ABORT_FINALIZE(RS_RET_LOAD_ERROR);
      }
    }
    else if(inst->interface != NULL) {
      dev = pcap_create((const char *)inst->interface, errBuf);
      if(dev == NULL) {
        LogError(0, RS_RET_LOAD_ERROR, "pcap: error while creating packet capture: '%s'", errBuf);
        ABORT_FINALIZE(RS_RET_LOAD_ERROR);
      }

      DBGPRINTF("setting snap_length %d\n", loadModConf->snap_length);
      if(pcap_set_snaplen(dev, loadModConf->snap_length)) {
        LogError(0, RS_RET_LOAD_ERROR, "pcap: error while setting snap length: '%s'", pcap_geterr(dev));
        ABORT_FINALIZE(RS_RET_LOAD_ERROR);
      }

      DBGPRINTF("setting promiscuous %d\n", inst->promiscuous);
      if(pcap_set_promisc(dev, inst->promiscuous)) {
        LogError(0, RS_RET_LOAD_ERROR, "pcap: error while setting promiscuous mode: '%s'", pcap_geterr(dev));
        ABORT_FINALIZE(RS_RET_LOAD_ERROR);
      }

      if(inst->immediateMode) {
        DBGPRINTF("setting immediate mode %d\n", inst->immediateMode);
        retCode = pcap_set_immediate_mode(dev, inst->immediateMode);
        if(retCode) {
          LogError(0, RS_RET_LOAD_ERROR, "pcap: error while setting immediate mode: '%s',"
            " using buffer instead\n", pcap_geterr(dev));
        }
      }

      if(!inst->immediateMode || retCode){
        DBGPRINTF("setting buffer size %lu\n", inst->bufSize);
        if(pcap_set_buffer_size(dev, inst->bufSize)) {
          LogError(0, RS_RET_LOAD_ERROR, "pcap: error while setting buffer size: '%s'", pcap_geterr(dev));
          ABORT_FINALIZE(RS_RET_LOAD_ERROR);
        }
        DBGPRINTF("setting buffer timeout %dms\n", inst->bufTimeout);
        if(pcap_set_timeout(dev, inst->bufTimeout)) {
          LogError(0, RS_RET_LOAD_ERROR, "pcap: error while setting buffer timeout: '%s'", pcap_geterr(dev));
          ABORT_FINALIZE(RS_RET_LOAD_ERROR);
        }
      }

      switch(pcap_activate(dev)) {
        case PCAP_WARNING_PROMISC_NOTSUP:
            LogError(0, NO_ERRCODE, "interface doesn't support promiscuous mode");
        case PCAP_WARNING_TSTAMP_TYPE_NOTSUP:
            LogError(0, NO_ERRCODE, "timestamp type is not supported");
        case PCAP_WARNING:
            LogError(0, NO_ERRCODE, "pcap: %s", pcap_geterr(dev));
            break;

        case PCAP_ERROR_ACTIVATED:
            LogError(0, RS_RET_LOAD_ERROR, "already activated");
        case PCAP_ERROR_NO_SUCH_DEVICE:
            LogError(0, RS_RET_LOAD_ERROR, "device doesn't exist");
        case PCAP_ERROR_PERM_DENIED:
            LogError(0, RS_RET_LOAD_ERROR, "elevated privilege needed to open capture interface");
        case PCAP_ERROR_PROMISC_PERM_DENIED:
            LogError(0, RS_RET_LOAD_ERROR, "elevated privilege needed to put interface in promiscuous mode");
        case PCAP_ERROR_RFMON_NOTSUP:
            LogError(0, RS_RET_LOAD_ERROR, "interface doesn't support monitor mode");
        case PCAP_ERROR_IFACE_NOT_UP:
            LogError(0, RS_RET_LOAD_ERROR, "interface is not up");
        case PCAP_ERROR:
            LogError(0, RS_RET_LOAD_ERROR, "pcap: %s", pcap_geterr(dev));
            ABORT_FINALIZE(RS_RET_LOAD_ERROR);
      }

      if(inst->filter != NULL) {
        DBGPRINTF("getting submask on %s\n", inst->interface);
        //obtain the subnet
        if(pcap_lookupnet(inst->interface, &SubNet, &NetMask, errBuf)){
          DBGPRINTF("Unable to obtain the netmask: '%s'", errBuf);
          ABORT_FINALIZE(RS_RET_LOAD_ERROR);
        }
        DBGPRINTF("setting filter %s\n", inst->filter);
        /* Compile the filter */
        if(pcap_compile(dev, &filter_program, inst->filter, 1, NetMask)) {
          LogError(0, RS_RET_LOAD_ERROR, "pcap: error while compiling filter: '%s'", pcap_geterr(dev));
          ABORT_FINALIZE(RS_RET_LOAD_ERROR);
        } else if(pcap_setfilter(dev, &filter_program)) {
          LogError(0, RS_RET_LOAD_ERROR, "pcap: error while setting filter: '%s'", pcap_geterr(dev));
          ABORT_FINALIZE(RS_RET_LOAD_ERROR);
        }
      }

      if(pcap_set_datalink(dev, DLT_EN10MB)) {
        LogError(0, RS_RET_LOAD_ERROR, "pcap: error while setting datalink type: '%s'", pcap_geterr(dev));
        ABORT_FINALIZE(RS_RET_LOAD_ERROR);
      }
    } /* inst->interface != NULL */
    else {
      LogError(0, RS_RET_LOAD_ERROR, "impcap: no capture method specified, "
          "please specify either 'interface' or 'file' in config");
      ABORT_FINALIZE(RS_RET_LOAD_ERROR);
    }

    inst->device = dev;
  }

finalize_it:
ENDactivateCnf

BEGINfreeCnf
CODESTARTfreeCnf
ENDfreeCnf

/* runtime functions */

/*
 *  Mock function to do no parsing when protocol is not a valid number
*/
data_ret_t* dont_parse(const uchar *packet, int pktSize, struct json_object *jparent) {
  DBGPRINTF("protocol not handled\n");
  RETURN_DATA_AFTER(0)
}

/*
 *  Initializes the function pointers' list for handled protocols
 *  contained within Ethernet II
*/
void init_eth_proto_handlers() {
  DBGPRINTF("begining init eth handlers\n");
  // set all to blank function
  for(int i = 0; i < ETH_PROTO_NUM; ++i) {
    ethProtoHandlers[i] = dont_parse;
  }

  ethProtoHandlers[ETHERTYPE_IP] = ipv4_parse;
  ethProtoHandlers[ETHERTYPE_ARP] = arp_parse;
  ethProtoHandlers[ETHERTYPE_REVARP] = rarp_parse;
  ethProtoHandlers[ETHERTYPE_IPV6] = ipv6_parse;
  ethProtoHandlers[ETHERTYPE_IPX] = ipx_parse;

}

/*
 *  Initializes the function pointers' list for handled protocols
 *  contained within IP
*/
void init_ip_proto_handlers() {
  DBGPRINTF("begining init ip handlers\n");
  // set all to blank function
  for(int i = 0; i < IP_PROTO_NUM; ++i) {
    ipProtoHandlers[i] = dont_parse;
  }

  ipProtoHandlers[IPPROTO_ICMP] = icmp_parse;
  ipProtoHandlers[IPPROTO_TCP] = tcp_parse;
  ipProtoHandlers[IPPROTO_UDP] = udp_parse;
}

/*
 *  Converts a list of bytes to their hexadecimal representation in ASCII
 *
 *  Gets the list of bytes and the length as parameters
 *
 *  Returns a pointer on the new list, being a string of ASCII characters
 *  representing hexadecimal values, in the form "A5B34C65..."
 *  its size is twice length parameter + 1
*/
char* stringToHex(char* string, size_t length) {
  const char *hexChar = "0123456789ABCDEF";
  char *retBuf;
  uint16_t i;

  retBuf = malloc((2*length+1)*sizeof(char));
  for(i = 0; i < length; ++i) {
    retBuf[2*i] = hexChar[(string[i] & 0xF0) >> 4];
    retBuf[2*i+1] = hexChar[string[i] & 0x0F];
  }
  retBuf[2*length] = '\0';

  return retBuf;
}

/*
 *  This method parses every packet received by libpcap, and is called by it
 *  It creates the message for Rsyslog, calls the parsers and add all necessary information
 *  in the message
*/
void packet_parse(uchar *arg, const struct pcap_pkthdr *pkthdr, const uchar *packet) {
  DBGPRINTF("impcap : entered packet_parse\n");
  smsg_t *pMsg;

  int * id = (int *)arg;
  msgConstruct(&pMsg);

  MsgSetInputName(pMsg, pInputName);
  //search inst in loadmodconf,and check if there is tag. if so set tag in msg.
  pthread_t ctid = pthread_self();
  instanceConf_t *inst;
  for(inst = loadModConf->root ; inst != NULL ; inst = inst->next) {
    if(pthread_equal(ctid, inst->tid)) {
      if(inst->pBindRuleset != NULL){
        MsgSetRuleset(pMsg, inst->pBindRuleset);
      }
      if(inst->tag != NULL){
        MsgSetTAG(pMsg,inst->tag,strlen(inst->tag));
      }
    }
  }


  struct json_object *jown = json_object_new_object();
  json_object_object_add(jown, "ID", json_object_new_int(++(*id)));
  json_object_object_add(jown, "net_bytes_total", json_object_new_int(pkthdr->len));

  data_ret_t *dataLeft = eth_parse(packet, pkthdr->caplen, jown);

  json_object_object_add(jown, "net_bytes_data", json_object_new_int(dataLeft->size));
  char *dataHex = stringToHex(dataLeft->pData, dataLeft->size);
  if(dataHex != NULL) {
    struct json_object *jadd = json_object_new_object();
    json_object_object_add(jadd, "length", json_object_new_int(strlen(dataHex)));
    json_object_object_add(jadd, "content", json_object_new_string(dataHex));
    msgAddJSON(pMsg, JSON_DATA_NAME, jadd, 0, 0);
    free(dataHex);
  }
  free(dataLeft);

  msgAddJSON(pMsg, JSON_LOOKUP_NAME, jown, 0, 0);
  submitMsg2(pMsg);
}

/*
 *  This is the main function for each thread
 *  taking care of a specified network interface
*/
void* startCaptureThread(void *instanceConf) {
  int id = 0;
  instanceConf_t *inst = (instanceConf_t *)instanceConf;
  while(glbl.GetGlobalInputTermState() == 0) {
    pcap_dispatch(inst->device, inst->pktBatchCnt, packet_parse, (uchar *)&id);
  }
  pthread_exit(0);
}

BEGINrunInput
  instanceConf_t *inst;
  int ret = 0;
CODESTARTrunInput
  for(inst = loadModConf->root ; inst != NULL ; inst = inst->next) {
    /* creates a thread and starts capturing on the interface */
    ret = pthread_create(&inst->tid, NULL, startCaptureThread, inst);
    if(ret) {
      LogError(0, RS_RET_NO_RUN, "impcap: error while creating threads\n");
    }
  }

  // will block as long as created threads don't return
  pthread_exit(0);
ENDrunInput

BEGINwillRun
CODESTARTwillRun
	/* we need to create the inputName property (only once during our lifetime) */
	CHKiRet(prop.Construct(&pInputName));
	CHKiRet(prop.SetString(pInputName, UCHAR_CONSTANT("impcap"), sizeof("impcap") - 1));
	CHKiRet(prop.ConstructFinalize(pInputName));
finalize_it:
ENDwillRun

BEGINafterRun
  instanceConf_t *inst;
CODESTARTafterRun
  for(inst = loadModConf->root ; inst != NULL; inst = inst->next) {
    pcap_close(inst->device);
  }
  if(pInputName != NULL){
    prop.Destruct(&pInputName);
  }
ENDafterRun

BEGINmodExit
CODESTARTmodExit
objRelease(glbl, CORE_COMPONENT);
objRelease(prop, CORE_COMPONENT);
objRelease(ruleset, CORE_COMPONENT);
ENDmodExit

/* declaration of functions */

BEGINqueryEtryPt
CODESTARTqueryEtryPt
CODEqueryEtryPt_STD_IMOD_QUERIES
CODEqueryEtryPt_STD_CONF2_QUERIES
CODEqueryEtryPt_STD_CONF2_setModCnf_QUERIES
CODEqueryEtryPt_STD_CONF2_IMOD_QUERIES
CODEqueryEtryPt_STD_CONF2_PREPRIVDROP_QUERIES /* might need it */
ENDqueryEtryPt

BEGINmodInit()
CODESTARTmodInit
  *ipIFVersProvided = CURR_MOD_IF_VERSION;
  CHKiRet(objUse(glbl, CORE_COMPONENT));
  CHKiRet(objUse(ruleset, CORE_COMPONENT));
  CHKiRet(objUse(prop, CORE_COMPONENT));
ENDmodInit
