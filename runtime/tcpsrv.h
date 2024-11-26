/* Definitions for tcpsrv class.
 *
 * Copyright 2008-2024 Adiscon GmbH.
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
#ifndef INCLUDED_TCPSRV_H
#define INCLUDED_TCPSRV_H

#include "obj.h"
#include "prop.h"
#include "net.h"
#include "tcps_sess.h"
#include "statsobj.h"

/* support for framing anomalies */
typedef enum ETCPsyslogFramingAnomaly {
	frame_normal = 0,
	frame_NetScreen = 1,
	frame_CiscoIOS = 2
} eTCPsyslogFramingAnomaly;


/* config parameters for TCP listeners */
struct tcpLstnParams_s {
	const uchar *pszPort;			/**< the ports the listener shall listen on */
	const uchar *pszAddr;                 /**< the addrs the listener shall listen on */
	sbool bSuppOctetFram;	/**< do we support octect-counted framing? (if no->legay only!)*/
	sbool bSPFramingFix;	/**< support work-around for broken Cisco ASA framing? */
	sbool bPreserveCase;			/**< preserve case in fromhost */
	const uchar *pszLstnPortFileName;	/**< File in which the dynamic port is written */
	uchar *pszStrmDrvrName;			/**< stream driver to use */
	uchar *pszInputName;			/**< value to be used as input name */
	prop_t *pInputName;
	ruleset_t *pRuleset;			/**< associated ruleset */
	uchar dfltTZ[8];			/**< default TZ if none in timestamp; '\0' =No Default */
};

/* list of tcp listen ports */
struct tcpLstnPortList_s {
	tcpLstnParams_t *cnf_params;	/**< listener config parameters */
	tcpsrv_t *pSrv;			/**< pointer to higher-level server instance */
	statsobj_t *stats;		/**< associated stats object */
	ratelimit_t *ratelimiter;
	STATSCOUNTER_DEF(ctrSubmit, mutCtrSubmit)
	tcpLstnPortList_t *pNext;	/**< next port or NULL */
};

struct tcpsrv_wrkrInfo_s {
	pthread_t tid;	/* the worker's thread ID */
	pthread_cond_t run;
	int idx;
	tcpsrv_t *pSrv; /* pSrv == NULL -> idle */
	nspoll_t *pPoll;
	void *pUsr;
	sbool enabled;
	long long unsigned numCalled;	/* how often was this called */
	tcpsrv_t *mySrv;
};

#define TCPSRV_NO_ADDTL_DELIMITER -1 /* specifies that no additional delimiter is to be used in TCP framing */

/* the tcpsrv object */
struct tcpsrv_s {
	BEGINobjInstance;	/**< Data to implement generic object - MUST be the first data element! */
	int bUseKeepAlive;	/**< use socket layer KEEPALIVE handling? */
	int iKeepAliveIntvl;	/**< socket layer KEEPALIVE interval */
	int iKeepAliveProbes;	/**< socket layer KEEPALIVE probes */
	int iKeepAliveTime;	/**< socket layer KEEPALIVE timeout */
	netstrms_t *pNS;	/**< pointer to network stream subsystem */
	int iDrvrMode;		/**< mode of the stream driver to use */
	int DrvrChkExtendedKeyUsage;		/**< if true, verify extended key usage in certs */
	int DrvrPrioritizeSan;		/**< if true, perform stricter checking of names in certs */
	int DrvrTlsVerifyDepth;		/**< Verify Depth for certificate chains */
	uchar *gnutlsPriorityString;	/**< priority string for gnutls */
	uchar *pszLstnPortFileName;	/**< File in which the dynamic port is written */
	uchar *pszDrvrAuthMode;	/**< auth mode of the stream driver to use */
	uchar *pszDrvrPermitExpiredCerts;/**< current driver setting for handlign expired certs */
	uchar *pszDrvrCAFile;
	uchar *pszDrvrCRLFile;
	uchar *pszDrvrKeyFile;
	uchar *pszDrvrCertFile;
	uchar *pszDrvrName;	/**< name of stream driver to use */
	uchar *pszInputName;	/**< value to be used as input name */ // TODO: REMOVE ME!!!!
	uchar *pszOrigin;		/**< module to be used as "origin" (e.g. for pstats) */
	ruleset_t *pRuleset;	/**< ruleset to bind to */
	permittedPeers_t *pPermPeers;/**< driver's permitted peers */
	sbool bEmitMsgOnClose;	/**< emit an informational message when the remote peer closes connection */
	sbool bEmitMsgOnOpen;
	sbool bUsingEPoll;	/**< are we in epoll mode (means we do not need to keep track of sessions!) */
	sbool bUseFlowControl;	/**< use flow control (make light delayable) */
	sbool bSPFramingFix;	/**< support work-around for broken Cisco ASA framing? */
	int iLstnCurr;		/**< max nbr of listeners currently supported */
	netstrm_t **ppLstn;	/**< our netstream listeners */
	tcpLstnPortList_t **ppLstnPort; /**< pointer to relevant listen port description */
	int iLstnMax;		/**< max number of listeners supported */
	int iSessMax;		/**< max number of sessions supported */
	uchar dfltTZ[8];	/**< default TZ if none in timestamp; '\0' =No Default */
	tcpLstnPortList_t *pLstnPorts;	/**< head pointer for listen ports */

	int addtlFrameDelim;	/**< additional frame delimiter for plain TCP syslog
					framing (e.g. to handle NetScreen) */
	int maxFrameSize;	/**< max frame size for octet counted*/
	int bDisableLFDelim;	/**< if 1, standard LF frame delimiter is disabled (*very dangerous*) */
	int discardTruncatedMsg;/**< discard msg part that has been truncated*/
	sbool bPreserveCase;	/**< preserve case in fromhost */
	unsigned int ratelimitInterval;
	unsigned int ratelimitBurst;
	tcps_sess_t **pSessions;/**< array of all of our sessions */
	void *pUsr;		/**< a user-settable pointer (provides extensibility for "derived classes")*/
	/* callbacks */
	int      (*pIsPermittedHost)(struct sockaddr *addr, char *fromHostFQDN, void*pUsrSrv, void*pUsrSess);
	rsRetVal (*pRcvData)(tcps_sess_t*, char*, size_t, ssize_t *, int*);
	rsRetVal (*OpenLstnSocks)(struct tcpsrv_s*);
	rsRetVal (*pOnListenDeinit)(void*);
	rsRetVal (*OnDestruct)(void*);
	rsRetVal (*pOnRegularClose)(tcps_sess_t *pSess);
	rsRetVal (*pOnErrClose)(tcps_sess_t *pSess);
	/* session specific callbacks */
	rsRetVal (*pOnSessAccept)(tcpsrv_t *, tcps_sess_t*);
	rsRetVal (*OnSessConstructFinalize)(void*);
	rsRetVal (*pOnSessDestruct)(void*);
	pthread_t tid;	/* the worker's thread ID */
	rsRetVal (*OnMsgReceive)(tcps_sess_t *, uchar *pszMsg, int iLenMsg); /* submit message callback */

	/* support for multiple workers */
	pthread_t main_tid;	/* thread ID of module main worker thread */
	sbool bWrkrRunning; /* are the worker threads running? */
	pthread_mutex_t wrkrMut;
	pthread_cond_t wrkrIdle;
	int wrkrMax;
	int wrkrRunning;
	struct tcpsrv_wrkrInfo_s wrkrInfo[4];

	/* self-pipe trick for synchronization */
	int selfpipe_fds[2];
};


/**
 * The following structure is a set of descriptors that need to be processed.
 * This set will be the result of the epoll or select call and be used
 * in the actual request processing stage. It serves as a basis
 * to run multiple request by concurrent threads. -- rgerhards, 2011-01-24
 */
struct tcpsrv_workset_s {
	int idx;	/**< index into session table (or -1 if listener) */
	void *pUsr;
};


/* interfaces */
BEGINinterface(tcpsrv) /* name must also be changed in ENDinterface macro! */
	INTERFACEObjDebugPrint(tcpsrv);
	rsRetVal (*Construct)(tcpsrv_t **ppThis);
	rsRetVal (*ConstructFinalize)(tcpsrv_t __attribute__((unused)) *pThis);
	rsRetVal (*Destruct)(tcpsrv_t **ppThis);
	rsRetVal (*ATTR_NONNULL(1,2) configureTCPListen)(tcpsrv_t*, tcpLstnParams_t *const cnf_params);
	rsRetVal (*create_tcp_socket)(tcpsrv_t *pThis);
	rsRetVal (*Run)(tcpsrv_t *pThis);
	/* set methods */
	rsRetVal (*SetAddtlFrameDelim)(tcpsrv_t*, int);
	rsRetVal (*SetMaxFrameSize)(tcpsrv_t*, int);
	rsRetVal (*SetInputName)(tcpsrv_t *const pThis,tcpLstnParams_t *const cnf_params, const uchar *const name);
	rsRetVal (*SetUsrP)(tcpsrv_t*, void*);
	rsRetVal (*SetCBIsPermittedHost)(tcpsrv_t*, int (*) (struct sockaddr *addr, char*, void*, void*));
	rsRetVal (*SetCBOpenLstnSocks)(tcpsrv_t *, rsRetVal (*)(tcpsrv_t*));
	rsRetVal (*SetCBRcvData)(tcpsrv_t *pThis, rsRetVal (*pRcvData)(tcps_sess_t*, char*, size_t, ssize_t*, int*));
	rsRetVal (*SetCBOnListenDeinit)(tcpsrv_t*, rsRetVal (*)(void*));
	rsRetVal (*SetCBOnDestruct)(tcpsrv_t*, rsRetVal (*) (void*));
	rsRetVal (*SetCBOnRegularClose)(tcpsrv_t*, rsRetVal (*) (tcps_sess_t*));
	rsRetVal (*SetCBOnErrClose)(tcpsrv_t*, rsRetVal (*) (tcps_sess_t*));
	rsRetVal (*SetDrvrMode)(tcpsrv_t *pThis, int iMode);
	rsRetVal (*SetDrvrAuthMode)(tcpsrv_t *pThis, uchar *pszMode);
	rsRetVal (*SetDrvrPermitExpiredCerts)(tcpsrv_t *pThis, uchar *pszMode);
	rsRetVal (*SetDrvrPermPeers)(tcpsrv_t *pThis, permittedPeers_t*);
	/* session specifics */
	rsRetVal (*SetCBOnSessAccept)(tcpsrv_t*, rsRetVal (*) (tcpsrv_t*, tcps_sess_t*));
	rsRetVal (*SetCBOnSessDestruct)(tcpsrv_t*, rsRetVal (*) (void*));
	rsRetVal (*SetCBOnSessConstructFinalize)(tcpsrv_t*, rsRetVal (*) (void*));
	/* added v5 */
	rsRetVal (*SetSessMax)(tcpsrv_t *pThis, int iMaxSess);	/* 2009-04-09 */
	/* added v6 */
	rsRetVal (*SetOnMsgReceive)(tcpsrv_t *pThis,
		rsRetVal (*OnMsgReceive)(tcps_sess_t*, uchar*, int)); /* 2009-05-24 */
	rsRetVal (*SetRuleset)(tcpsrv_t *pThis, ruleset_t*); /* 2009-06-12 */
	/* added v7 (accidently named v8!) */
	rsRetVal (*SetLstnMax)(tcpsrv_t *pThis, int iMaxLstn);	/* 2009-08-17 */
	rsRetVal (*SetNotificationOnRemoteClose)(tcpsrv_t *pThis, int bNewVal); /* 2009-10-01 */
	rsRetVal (*SetNotificationOnRemoteOpen)(tcpsrv_t *pThis, int bNewVal); /* 2022-08-23 */
	/* added v9 -- rgerhards, 2010-03-01 */
	rsRetVal (*SetbDisableLFDelim)(tcpsrv_t*, int);
	/* added v10 -- rgerhards, 2011-04-01 */
	rsRetVal (*SetDiscardTruncatedMsg)(tcpsrv_t*, int);
	rsRetVal (*SetUseFlowControl)(tcpsrv_t*, int);
	/* added v11 -- rgerhards, 2011-05-09 */
	rsRetVal (*SetKeepAlive)(tcpsrv_t*, int);
	/* added v13 -- rgerhards, 2012-10-15 */
	rsRetVal (*SetLinuxLikeRatelimiters)(tcpsrv_t *pThis, unsigned int interval, unsigned int burst);
	/* added v14 -- rgerhards, 2013-07-28 */
	rsRetVal (*SetDfltTZ)(tcpsrv_t *pThis, uchar *dfltTZ);
	/* added v15 -- rgerhards, 2013-09-17 */
	rsRetVal (*SetDrvrName)(tcpsrv_t *pThis, uchar *pszName);
	/* added v16 -- rgerhards, 2014-09-08 */
	rsRetVal (*SetOrigin)(tcpsrv_t*, uchar*);
	/* added v17 */
	rsRetVal (*SetKeepAliveIntvl)(tcpsrv_t*, int);
	rsRetVal (*SetKeepAliveProbes)(tcpsrv_t*, int);
	rsRetVal (*SetKeepAliveTime)(tcpsrv_t*, int);
	/* added v18 */
	rsRetVal (*SetbSPFramingFix)(tcpsrv_t*, sbool);
	/* added v19 -- PascalWithopf, 2017-08-08 */
	rsRetVal (*SetGnutlsPriorityString)(tcpsrv_t*, uchar*);
	/* added v21 -- Preserve case in fromhost, 2018-08-16 */
	rsRetVal (*SetPreserveCase)(tcpsrv_t *pThis, int bPreserveCase);
	/* added v23 -- Options for stricter driver behavior, 2019-08-16 */
	rsRetVal (*SetDrvrCheckExtendedKeyUsage)(tcpsrv_t *pThis, int ChkExtendedKeyUsage);
	rsRetVal (*SetDrvrPrioritizeSAN)(tcpsrv_t *pThis, int prioritizeSan);
	/* added v24 -- Options for TLS verify depth driver behavior, 2019-12-20 */
	rsRetVal (*SetDrvrTlsVerifyDepth)(tcpsrv_t *pThis, int verifyDepth);
	/* added v25 -- Options for TLS certificates, 2021-07-19 */
	rsRetVal (*SetDrvrCAFile)(tcpsrv_t *pThis, uchar *pszMode);
	rsRetVal (*SetDrvrKeyFile)(tcpsrv_t *pThis, uchar *pszMode);
	rsRetVal (*SetDrvrCertFile)(tcpsrv_t *pThis, uchar *pszMode);
	/* added v26 -- Options for TLS CRL file */
	rsRetVal (*SetDrvrCRLFile)(tcpsrv_t *pThis, uchar *pszMode);
ENDinterface(tcpsrv)
#define tcpsrvCURR_IF_VERSION 26 /* increment whenever you change the interface structure! */
/* change for v4:
 * - SetAddtlFrameDelim() added -- rgerhards, 2008-12-10
 * - SetInputName() added -- rgerhards, 2008-12-10
 * change for v5 and up: see above
 * for v12: param bSuppOctetFram added to configureTCPListen
 * for v20: add oserr to setCBRcvData signature -- rgerhards, 2017-09-04
 */


/* prototypes */
PROTOTYPEObj(tcpsrv);

/* the name of our library binary */
#define LM_TCPSRV_FILENAME "lmtcpsrv"

#endif /* #ifndef INCLUDED_TCPSRV_H */
