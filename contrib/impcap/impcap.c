/* impcap.c
 *
 * This is a first implementation of an input module using libpcap, a
 * portable C/C++ library for network traffic capture.
 * This module aims to read packets received from a network interface
 * using libpcap to extract information, such as IP addresses, ports,
 * protocols, etc... and make it available to rsyslog and its modules.
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
 #include <pcap.h>

 #include <json.h>

 #include "rsyslog.h"
 #include "errmsg.h"
 #include "unicode-helper.h"
 #include "module-template.h"
 #include "rainerscript.h"
 #include "rsconf.h"
 #include "dirty.h"
 #include "msg.h"

 #include <netinet/ether.h>
 // #include <netinet/in.h>
 #include <netinet/ip.h>
 #include <netinet/ip6.h>
 #include <net/ethernet.h>
 #include <netinet/if_ether.h>  /* arp structure */
 #include <arpa/inet.h>   /* IP address extraction */

 typedef struct ether_header    eth_header_t;
 typedef struct ip              ipv4_header_t;
 typedef struct ether_arp       arp_header_t;
 typedef struct ip6_hdr        ipv6_header_t;
 #define ip6_addr_sub16 __in6_u.__u6_addr16

MODULE_TYPE_INPUT
MODULE_TYPE_NOKEEP
MODULE_CNFNAME("impcap")

/* static data */
DEF_IMOD_STATIC_DATA

static rsRetVal resetConfigVariables(uchar __attribute__((unused)) *pp, void __attribute__((unused)) *pVal);

/* conf structures */

struct instanceConf_s {
  uchar *interface;
  pcap_t *device;
  struct instanceConf_s *next;
};

struct modConfData_s {
  rsconf_t *pConf;
  instanceConf_t *root, *tail;
  uint16_t snap_length;
};



static modConfData_t *loadModConf = NULL;/* modConf ptr to use for the current load process */

/* input instance parameters */
static struct cnfparamdescr inppdescr[] = {
	{ "interface", eCmdHdlrString, CNFPARAM_REQUIRED }
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

/* --- prototypes --- */
void handle_packet(uchar *arg, const struct pcap_pkthdr *pkthdr, const uchar *packet);
void handle_eth_header(const uchar *packet, size_t pktSize, struct json_object *jparent);
void handle_ipv4_header(const uchar *packet, size_t pktSize, struct json_object *jparent);
void handle_ipv6_header(const uchar *packet, size_t pktSize, struct json_object *jparent);
void handle_arp_header(const uchar *packet, size_t pktSize, struct json_object *jparent);

/* create input instance, set default parameters, and
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
  inst->device = NULL;

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
              "impcap: required parameter are missing\n");
    ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
  }

  CHKiRet(createInstance(&inst));

  for(i = 0 ; i < inppblk.nParams ; ++i) {
    if(!pvals[i].bUsed)
      continue;
    if(!strcmp(inppblk.descr[i].name, "interface")) {
      inst->interface = (uchar*) es_str2cstr(pvals[i].val.d.estr, NULL);
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
  pvals = nvlstGetParams(lst, &modpblk, NULL);

  for(i = 0 ; i < modpblk.nParams ; ++i) {
    if(!pvals[i].bUsed)
      continue;
    if(!strcmp(modpblk.descr[i].name, "snap_length")) {
      loadModConf->snap_length = (int) pvals[i].val.d.n;
    }
    else {
      dbgprintf("impcap: non-handled param %s in beginCnfLoad\n", modpblk.descr[i].name);
    }
  }
ENDsetModCnf

/* config v2 system */

BEGINbeginCnfLoad
CODESTARTbeginCnfLoad
  loadModConf = pModConf;
  loadModConf->pConf = pConf;
  loadModConf->snap_length = 65535;
ENDbeginCnfLoad

BEGINendCnfLoad
CODESTARTendCnfLoad
ENDendCnfLoad

BEGINcheckCnf
  instanceConf_t *inst;
CODESTARTcheckCnf
  if(pModConf->root == NULL) {
    LogError(0, RS_RET_NO_LISTNERS , "impcap: module loaded, but "
        "no interface defined - no input will be gathered");
    iRet = RS_RET_NO_LISTNERS;
  }

  for(inst = loadModConf->root ; inst != NULL ; inst = inst->next) {
    if(inst->interface == NULL || !strcmp((char *)inst->interface, "")) {
      iRet = RS_RET_INVALID_PARAMS;
      LogError(0, RS_RET_LOAD_ERROR, "impcap: interface parameter "
          "invalid: %s", inst->interface);
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
  char errBuf[PCAP_ERRBUF_SIZE];
CODESTARTactivateCnf
  loadModConf = pModConf;

  for(inst = loadModConf->root ; inst != NULL ; inst = inst->next) {
    dev = pcap_open_live((const char *)inst->interface, loadModConf->snap_length, 0, 0, errBuf);
    if(dev == NULL) {
      LogError(0, RS_RET_LOAD_ERROR, "impcap: error while opening interface using pcap");
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

BEGINrunInput
  instanceConf_t *inst;
  int id = 0;
CODESTARTrunInput
inst = loadModConf->root; /* only start first instance for now */
  pcap_loop(inst->device, -1, handle_packet, (uchar *)&id);
ENDrunInput

BEGINwillRun
CODESTARTwillRun
ENDwillRun

BEGINafterRun
  instanceConf_t *inst;
CODESTARTafterRun
  for(inst = loadModConf->root ; inst != NULL; inst = inst->next) {
    pcap_close(inst->device);
  }
ENDafterRun

BEGINmodExit
CODESTARTmodExit
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
ENDmodInit


/* ---message handling functions --- */

/* callback for packet received from pcap_loop */
void handle_packet(uchar *arg, const struct pcap_pkthdr *pkthdr, const uchar *packet) {
  DBGPRINTF("impcap : entered handle_packet\n");

  smsg_t *pMsg;
  DEFiRet;
  char tag[20];
  int length;

  msgConstruct(&pMsg);
  
	struct json_object *jchild;
	struct json_object *jparent;
	jparent = json_object_new_object();
	jchild = json_object_new_object();
	//jval = json_object_new_string((char*)"a");
	
	
	
  // /* ----- DEBUG REMOVE ----- */
  // /* give the raw packet to rsyslog */
  // char rawMsg[1600] = {0};
  // for(int i = 0; i < pkthdr->len; ++i) {
  //   char hexPart[4];
  //
  //   snprintf(hexPart, 4, " %02X", packet[i]);
  //   strncat(rawMsg, hexPart, 4);
  // }
  // DBGPRINTF("raw message is %s\n", rawMsg);
  // DBGPRINTF("message length is %d\n", pkthdr->len);
  // DBGPRINTF("min length is %d\n", ETHER_MIN_LEN);
  // DBGPRINTF("max length is %d\n", ETHER_MAX_LEN);
  //
  // MsgSetRawMsg(pMsg, rawMsg, 1600);
  // /* ----- DEBUG REMOVE ----- */

  if(pkthdr->len >= 40 && pkthdr->len <= 1514) {
    handle_eth_header(packet,pkthdr->len, jchild);
    json_object_object_add(jparent, "eth", jchild);
  }
  else {
    DBGPRINTF("bad packet length, discarded\n");
    msgDestruct(&pMsg);
    return;
  }
  
  msgAddJSON(pMsg, "!impcap", jparent, 0, 0);
  submitMsg2(pMsg);
}

void handle_eth_header(const uchar *packet, size_t pktSize, struct json_object *jparent) {
  DBGPRINTF("entered handle_eth_header\n");
  if (pktSize <= 14) {  /* too short for eth header + data */
    DBGPRINTF("ETH packet too small : %d\n", pktSize);
    return;
  struct json_object *jchild;
  jchild = json_object_new_object();
  struct json_object *jvar;
  eth_header_t *eth_header = (eth_header_t *)packet;

  char *ethMacSrc = ether_ntoa((struct eth_addr *)eth_header->ether_shost);
  char *ethMacDst = ether_ntoa((struct eth_addr *)eth_header->ether_dhost);
  uint16_t ethType = ntohs(eth_header->ether_type);
  char errMsg[50];

  DBGPRINTF("MAC destination : %s\n", ethMacDst);
  DBGPRINTF("MAC source : %s\n", ethMacSrc);
  DBGPRINTF("ether type : %04X\n", ethType);

  jvar = json_object_new_string((char*)ethMacSrc);
  json_object_object_add(jparent, "ETH_src", jvar);
  jvar = json_object_new_string((char*)ethMacDst);
  json_object_object_add(jparent, "ETH_dst", jvar);
  //msgAddMetadata(pMsg, "ETH_src", ethMacSrc);
  //msgAddMetadata(pMsg, "ETH_dst", ethMacDst);

  //msgSetJSONFromVar(pMsg,"ETH_src",creatsvar_char(ethMacSrc),0);
  //msgSetJSONFromVar(pMsg,"ETH_dst",creatsvar_char(ethMacDst),0);

  switch(ethType) {
    case ETHERTYPE_IP:
	jvar = json_object_new_string((char*)"IPV4");
	json_object_object_add(jparent, "ETH_type", jvar);
        //msgAddMetadata(pMsg, "ETH_type", "IPV4");
        handle_ipv4_header((uchar *)(packet + sizeof(eth_header_t)), (pktSize - sizeof(ethHeader_t)), jchild);
	json_object_object_add(jparent, "IPV4", jchild);
        break;
    case ETHERTYPE_IPV6:
	jvar = json_object_new_string((char*)"IPV6");
	json_object_object_add(jparent, "ETH_type", jvar);
        //msgAddMetadata(pMsg, "ETH_type", "IPV6");
        handle_ipv6_header((uchar *)(packet + sizeof(eth_header_t)), (pktSize - sizeof(eth_header_t)), jchild);
	json_object_object_add(jparent, "IPV6", jchild);
        break;
    case ETHERTYPE_ARP:
	jvar = json_object_new_string((char*)"ARP");
	json_object_object_add(jparent, "ETH_type", jvar);
        //msgAddMetadata(pMsg, "ETH_type", "ARP");
        handle_arp_header((uchar *)(packet + sizeof(eth_header_t)), (pktSize - sizeof(eth_header_t)), jchild);
	json_object_object_add(jparent, "ARP", jchild);
        break;
    case ETHERTYPE_REVARP:
	jvar = json_object_new_string((char*)"RARP");
	json_object_object_add(jparent, "ETH_type", jvar);
      	//msgAddMetadata(pMsg, "ETH_type", "RARP");
      	break;
    case ETHERTYPE_PUP:
	jvar = json_object_new_string((char*)"PUP");
	json_object_object_add(jparent, "ETH_type", jvar);
      	//msgAddMetadata(pMsg, "ETH_type", "PUP");
      	break;
    case ETHERTYPE_SPRITE:
	jvar = json_object_new_string((char*)"SPRITE");
	json_object_object_add(jparent, "ETH_type", jvar);
      	//msgAddMetadata(pMsg, "ETH_type", "SPRITE");
      	break;
    case ETHERTYPE_AT:
	jvar = json_object_new_string((char*)"AT");
	json_object_object_add(jparent, "ETH_type", jvar);
      	//msgAddMetadata(pMsg, "ETH_type", "AT");
      	break;
    case ETHERTYPE_AARP:
	jvar = json_object_new_string((char*)"AARP");
	json_object_object_add(jparent, "ETH_type", jvar);
      	//msgAddMetadata(pMsg, "ETH_type", "AARP");
      	break;
    case ETHERTYPE_VLAN:
	jvar = json_object_new_string((char*)"VLAN");
	json_object_object_add(jparent, "ETH_type", jvar);
      	//msgAddMetadata(pMsg, "ETH_type", "VLAN");
      	break;
    case ETHERTYPE_IPX:
	jvar = json_object_new_string((char*)"IPX");
	json_object_object_add(jparent, "ETH_type", jvar);
      	//msgAddMetadata(pMsg, "ETH_type", "IPX");
      	break;
    case ETHERTYPE_LOOPBACK:
	jvar = json_object_new_string((char*)"LOOPBACK");
	json_object_object_add(jparent, "ETH_type", jvar);
      	//msgAddMetadata(pMsg, "ETH_type", "LOOPBACK");
      	break;
    default:
      	snprintf(errMsg, 50, "ETH type unknown: 0x%X", ethType);
      	DBGPRINTF("no match to ethernet type\n");
	jvar = json_object_new_string((char*)errMsg);
	json_object_object_add(jparent, "ETH_err", jvar);
      	//msgAddMetadata(pMsg, "ETH_err", errMsg);
  }
}

void handle_ipv4_header(const uchar *packet, size_t pktSize, struct json_object *jparent) {
  struct json_object *jchild;
  jchild = json_object_new_object();
  struct json_object *jvar;
  DBGPRINTF("handle_ipv4_header\n");

  if(pktSize <= 20) { /* too small for IPv4 header + data (header might be longer)*/
    DBGPRINTF("IPv4 packet too small : %d\n", pktSize);
    return;
  }

	ipv4_header_t *ipv4_header = (ipv4_header_t *)packet;

  char addrSrc[20], addrDst[20], hdrLen[2];

  inet_ntop(AF_INET, (void *)&ipv4_header->ip_src, addrSrc, 20);
  inet_ntop(AF_INET, (void *)&ipv4_header->ip_dst, addrDst, 20);
  snprintf(hdrLen, 2, "%d", ipv4_header->ip_hl);

  DBGPRINTF("IP destination : %s\n", addrDst);
  DBGPRINTF("IP source : %s\n", addrSrc);
  DBGPRINTF("IHL : %s\n", hdrLen);

  jvar = json_object_new_string((char*)addrDst);
  json_object_object_add(jparent, "IP_dest", jvar);
  jvar = json_object_new_string((char*)addrSrc);
  json_object_object_add(jparent, "IP_src", jvar);
  jvar = json_object_new_string((char*)hdrLen);
  json_object_object_add(jparent, "IP_ihl", jvar);
  //msgAddMetadata(pMsg, "IP_dest", addrDst);
  //msgAddMetadata(pMsg, "IP_src", addrSrc);
  //msgAddMetadata(pMsg, "IP_ihl", hdrLen);
}

void handle_ipv6_header(const uchar *packet, size_t pktSize, struct json_object *jparent) {
  struct json_object *jchild;
  jchild = json_object_new_object();
  struct json_object *jvar;
  DBGPRINTF("handle_ipv6_header\n");

  if(pktSize <= 40) { /* too small for IPv6 header + data (header might be longer)*/
    DBGPRINTF("IPv6 packet too small : %d\n", pktSize);
    return;
  }

	ipv6_header_t *ipv6_header = (ipv6_header_t *)packet;

  char addrSrc[40], addrDst[40];

  inet_ntop(AF_INET6, (void *)&ipv6_header->ip6_src, addrSrc, 40);
  inet_ntop(AF_INET6, (void *)&ipv6_header->ip6_dst, addrDst, 40);
  DBGPRINTF("IP6 source : %s\n", addrSrc);
  DBGPRINTF("IP6 destination : %s\n", addrDst);

  jvar = json_object_new_string((char*)addrDst);
  json_object_object_add(jparent, "IP6_dest", jvar);
  jvar = json_object_new_string((char*)addrSrc);
  json_object_object_add(jparent, "IP6_src", jvar);
  //msgAddMetadata(pMsg, "IP6_dest", addrDst);
  //msgAddMetadata(pMsg, "IP6_src", addrSrc);
}

void handle_arp_header(const uchar *packet, size_t pktSize, struct json_object *jparent) {
  struct json_object *jchild;
  jchild = json_object_new_object();
  struct json_object *jvar;
  DBGPRINTF("handle_arp_header\n");

  if(pktSize <= 27) { /* too small for ARP header*/
    DBGPRINTF("ARP packet too small : %d\n", pktSize);
    return;
  }

	arp_header_t *arp_header = (arp_header_t *)packet;

  char hwType[5], pType[5], op[5], pAddrSrc[20], pAddrDst[20];
  snprintf(hwType, 5, "%04X", ntohs(arp_header->arp_hrd));
  snprintf(pType, 5, "%04X", ntohs(arp_header->arp_pro));
  snprintf(op, 5, "%04X", ntohs(arp_header->arp_op));

  DBGPRINTF("ARP hardware type : %s\n", hwType);
  DBGPRINTF("ARP proto type : %s\n", pType);
  DBGPRINTF("ARP operation : %s\n", op);

  jvar = json_object_new_string((char*)hwType);
  json_object_object_add(jparent, "ARP_hwType", jvar);
  jvar = json_object_new_string((char*)pType);
  json_object_object_add(jparent, "ARP_pType", jvar);
  jvar = json_object_new_string((char*)op);
  json_object_object_add(jparent, "ARP_op", jvar);
  //msgAddMetadata(pMsg, "ARP_hwType", hwType);
  //msgAddMetadata(pMsg, "ARP_pType", pType);
  //msgAddMetadata(pMsg, "ARP_op", op);

  if(ntohs(arp_header->arp_hrd) == 1) { /* ethernet addresses */
    char *hwAddrSrc = ether_ntoa((struct eth_addr *)arp_header->arp_sha);
    char *hwAddrDst = ether_ntoa((struct eth_addr *)arp_header->arp_tha);

    jvar = json_object_new_string((char*)hwAddrSrc);
    json_object_object_add(jparent, "ARP_hwSrc", jvar);
    jvar = json_object_new_string((char*)hwAddrDst);
    json_object_object_add(jparent, "ARP_hwDst", jvar);
    //msgAddMetadata(pMsg, "ARP_hwSrc", hwAddrSrc);
    //msgAddMetadata(pMsg, "ARP_hwDst", hwAddrDst);
  }

  if(ntohs(arp_header->arp_pro) == ETHERTYPE_IP) {
    inet_ntop(AF_INET, (void *)&arp_header->arp_spa, pAddrSrc, 20);
    inet_ntop(AF_INET, (void *)&arp_header->arp_tpa, pAddrDst, 20);

    jvar = json_object_new_string((char*)pAddrSrc);
    json_object_object_add(jparent, "ARP_pSrc", jvar);
    jvar = json_object_new_string((char*)pAddrDst);
    json_object_object_add(jparent, "ARP_pDst", jvar);
    //msgAddMetadata(pMsg, "ARP_pSrc", pAddrSrc);
    //msgAddMetadata(pMsg, "ARP_pDst", pAddrDst);
  }
}
