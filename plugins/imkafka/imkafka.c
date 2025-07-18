/* imkafka.c
 *
 * This input plugin is a consumer for Apache Kafka.
 *
 * File begun on 2017-04-25 by alorbach
 *
 * Copyright 2008-2017 Adiscon GmbH.
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
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/uio.h>
#include <librdkafka/rdkafka.h>

#include "rsyslog.h"
#include "conf.h"
#include "syslogd-types.h"
#include "srUtils.h"
#include "template.h"
#include "module-template.h"
#include "errmsg.h"
#include "atomic.h"
#include "statsobj.h"
#include "unicode-helper.h"
#include "prop.h"
#include "ruleset.h"
#include "glbl.h"
#include "cfsysline.h"
#include "msg.h"
#include "dirty.h"

MODULE_TYPE_INPUT;
MODULE_TYPE_NOKEEP;
MODULE_CNFNAME("imkafka")

/* static data */
DEF_IMOD_STATIC_DATA;
DEFobjCurrIf(prop) DEFobjCurrIf(ruleset) DEFobjCurrIf(glbl) DEFobjCurrIf(statsobj)

    /* forward references */
    static void *imkafkawrkr(void *myself);


struct kafka_params {
    const char *name;
    const char *val;
};

/* Module static data */
static struct configSettings_s {
    uchar *topic;
    uchar *consumergroup;
    char *brokers;
    uchar *pszBindRuleset;
    int nConfParams;
    struct kafka_params *confParams;
} cs;

struct instanceConf_s {
    uchar *topic;
    uchar *consumergroup;
    char *brokers;
    int64_t offset;
    ruleset_t *pBindRuleset; /* ruleset to bind listener to (use system default if unspecified) */
    uchar *pszBindRuleset; /* default name of Ruleset to bind to */
    int bReportErrs;
    int nConfParams;
    struct kafka_params *confParams;
    int bIsConnected;
    rd_kafka_conf_t *conf;
    rd_kafka_t *rk;
    rd_kafka_topic_conf_t *topic_conf;
    int partition;
    int bIsSubscribed;
    int nMsgParsingFlags;

    struct instanceConf_s *next;
};


struct modConfData_s {
    rsconf_t *pConf; /* our overall config object */
    uchar *topic;
    uchar *consumergroup;
    char *brokers;
    instanceConf_t *root, *tail;
    ruleset_t *pBindRuleset; /* ruleset to bind listener to (use system default if unspecified) */
    uchar *pszBindRuleset; /* default name of Ruleset to bind to */
};

/* global data */
pthread_attr_t wrkrThrdAttr; /* Attribute for worker threads ; read only after startup */
static int activeKafkaworkers = 0;
/* The following structure controls the worker threads. Global data is
 * needed for their access.
 */
static struct kafkaWrkrInfo_s {
    pthread_t tid; /* the worker's thread ID */
    instanceConf_t *inst; /* Pointer to imkafka instance */
} *kafkaWrkrInfo;

static modConfData_t *loadModConf = NULL; /* modConf ptr to use for the current load process */
static modConfData_t *runModConf = NULL; /* modConf ptr to use for the current load process */

static prop_t *pInputName = NULL;
/* there is only one global inputName for all messages generated by this input */

/* module-global parameters */
static struct cnfparamdescr modpdescr[] = {
    {"ruleset", eCmdHdlrGetWord, 0},
};
static struct cnfparamblk modpblk = {CNFPARAMBLK_VERSION, sizeof(modpdescr) / sizeof(struct cnfparamdescr), modpdescr};

/* input instance parameters */
static struct cnfparamdescr inppdescr[] = {
    {"topic", eCmdHdlrString, CNFPARAM_REQUIRED}, {"broker", eCmdHdlrArray, 0},   {"confparam", eCmdHdlrArray, 0},
    {"consumergroup", eCmdHdlrString, 0},         {"ruleset", eCmdHdlrString, 0}, {"parsehostname", eCmdHdlrBinary, 0},
};
static struct cnfparamblk inppblk = {CNFPARAMBLK_VERSION, sizeof(inppdescr) / sizeof(struct cnfparamdescr), inppdescr};

#include "im-helper.h" /* must be included AFTER the type definitions! */

/* ------------------------------ callbacks ------------------------------ */


/* ------------------------------ end callbacks ------------------------------ */

static void kafkaLogger(const rd_kafka_t __attribute__((unused)) * rk, int level, const char *fac, const char *buf) {
    DBGPRINTF("imkafka: kafka log message [%d,%s]: %s\n", level, fac, buf);
}


/* enqueue the kafka message. The provided string is
 * not freed - thuis must be done by the caller.
 */
static rsRetVal enqMsg(instanceConf_t *const __restrict__ inst, rd_kafka_message_t *const __restrict__ rkmessage) {
    DEFiRet;
    smsg_t *pMsg;

    if ((int)rkmessage->len == 0) {
        /* we do not process empty lines */
        FINALIZE;
    }

    DBGPRINTF("imkafka: enqMsg: Msg: %.*s\n", (int)rkmessage->len, (char *)rkmessage->payload);

    CHKiRet(msgConstruct(&pMsg));
    MsgSetInputName(pMsg, pInputName);
    MsgSetRawMsg(pMsg, (char *)rkmessage->payload, (int)rkmessage->len);
    MsgSetFlowControlType(pMsg, eFLOWCTL_LIGHT_DELAY);
    MsgSetRuleset(pMsg, inst->pBindRuleset);
    pMsg->msgFlags = inst->nMsgParsingFlags;
    /* Optional Fields */
    if (rkmessage->key_len) {
        DBGPRINTF("imkafka: enqMsg: Key: %.*s\n", (int)rkmessage->key_len, (char *)rkmessage->key);
        MsgSetTAG(pMsg, (const uchar *)rkmessage->key, (int)rkmessage->key_len);
    }
    MsgSetMSGoffs(pMsg, 0); /* we do not have a header... */

    CHKiRet(submitMsg2(pMsg));

finalize_it:
    RETiRet;
}

/**
 * Handle Kafka Consumer Loop until all msgs are processed
 */
static void msgConsume(instanceConf_t *inst) {
    rd_kafka_message_t *rkmessage = NULL;

    do { /* Consume messages */
        rkmessage = rd_kafka_consumer_poll(inst->rk, 1000); /* Block for 1000 ms max */
        if (rkmessage == NULL) {
            DBGPRINTF("imkafka: msgConsume EMPTY Loop on %s/%s/%s\n", inst->topic, inst->consumergroup, inst->brokers);
            goto done;
        }

        if (rkmessage->err) {
            if (rkmessage->err == RD_KAFKA_RESP_ERR__PARTITION_EOF) {
                /* not an error, just a regular status! */
                DBGPRINTF(
                    "imkafka: Consumer "
                    "reached end of topic \"%s\" [%" PRId32
                    "]"
                    "message queue offset %" PRId64 "\n",
                    rd_kafka_topic_name(rkmessage->rkt), rkmessage->partition, rkmessage->offset);
                goto done;
            }
            if (rkmessage->rkt) {
                LogError(0, RS_RET_KAFKA_ERROR,
                         "imkafka: Consumer error for topic \"%s\" [%" PRId32
                         "]"
                         "message queue offset %" PRId64 ": %s\n",
                         rd_kafka_topic_name(rkmessage->rkt), rkmessage->partition, rkmessage->offset,
                         rd_kafka_message_errstr(rkmessage));
            } else {
                LogError(0, RS_RET_KAFKA_ERROR, "imkafka: Consumer error for topic \"%s\": \"%s\"\n",
                         rd_kafka_err2str(rkmessage->err), rd_kafka_message_errstr(rkmessage));
            }
            goto done;
        }

        DBGPRINTF("imkafka: msgConsume Loop on %s/%s/%s: [%" PRId32
                  "], "
                  "offset %" PRId64 ", %zd bytes):\n",
                  rd_kafka_topic_name(rkmessage->rkt) /*inst->topic*/, inst->consumergroup, inst->brokers,
                  rkmessage->partition, rkmessage->offset, rkmessage->len);
        enqMsg(inst, rkmessage);
        /* Destroy message and continue */
        rd_kafka_message_destroy(rkmessage);
        rkmessage = NULL;
    } while (1); /* loop broken inside */
done:
    /* Destroy message in case rkmessage->err was set */
    if (rkmessage != NULL) {
        rd_kafka_message_destroy(rkmessage);
    }
    return;
}


/* create input instance, set default parameters, and
 * add it to the list of instances.
 */
static rsRetVal createInstance(instanceConf_t **pinst) {
    instanceConf_t *inst;
    DEFiRet;
    CHKmalloc(inst = malloc(sizeof(instanceConf_t)));
    inst->next = NULL;

    inst->brokers = NULL;
    inst->topic = NULL;
    inst->consumergroup = NULL;
    inst->pszBindRuleset = NULL;
    inst->nConfParams = 0;
    inst->confParams = NULL;
    inst->pBindRuleset = NULL;
    inst->bReportErrs = 1; /* Fixed for now */
    inst->nMsgParsingFlags = NEEDS_PARSING;
    inst->bIsConnected = 0;
    inst->bIsSubscribed = 0;
    /* Kafka objects */
    inst->conf = NULL;
    inst->rk = NULL;
    inst->topic_conf = NULL;
    inst->partition = RD_KAFKA_PARTITION_UA;

    /* node created, let's add to config */
    if (loadModConf->tail == NULL) {
        loadModConf->tail = loadModConf->root = inst;
    } else {
        loadModConf->tail->next = inst;
        loadModConf->tail = inst;
    }

    *pinst = inst;
finalize_it:
    RETiRet;
}

/* this function checks instance parameters and does some required pre-processing
 */
static rsRetVal ATTR_NONNULL() checkInstance(instanceConf_t *const inst) {
    DEFiRet;
    char kafkaErrMsg[1024];

    /* main kafka conf */
    inst->conf = rd_kafka_conf_new();
    if (inst->conf == NULL) {
        if (inst->bReportErrs) {
            LogError(0, RS_RET_KAFKA_ERROR, "imkafka: error creating kafka conf obj: %s\n",
                     rd_kafka_err2str(rd_kafka_last_error()));
        }
        ABORT_FINALIZE(RS_RET_KAFKA_ERROR);
    }

#ifdef DEBUG
    /* enable kafka debug output */
    if (rd_kafka_conf_set(inst->conf, "debug", RD_KAFKA_DEBUG_CONTEXTS, kafkaErrMsg, sizeof(kafkaErrMsg)) !=
        RD_KAFKA_CONF_OK) {
        LogError(0, RS_RET_KAFKA_ERROR, "imkafka: error setting kafka debug option: %s\n", kafkaErrMsg);
        /* DO NOT ABORT IN THIS CASE! */
    }
#endif

    /* Set custom configuration parameters */
    for (int i = 0; i < inst->nConfParams; ++i) {
        assert(inst->confParams + i != NULL); /* invariant: nConfParams MUST exist! */
        DBGPRINTF("imkafka: setting custom configuration parameter: %s:%s\n", inst->confParams[i].name,
                  inst->confParams[i].val);
        if (rd_kafka_conf_set(inst->conf, inst->confParams[i].name, inst->confParams[i].val, kafkaErrMsg,
                              sizeof(kafkaErrMsg)) != RD_KAFKA_CONF_OK) {
            if (inst->bReportErrs) {
                LogError(0, RS_RET_PARAM_ERROR,
                         "error setting custom configuration "
                         "parameter '%s=%s': %s",
                         inst->confParams[i].name, inst->confParams[i].val, kafkaErrMsg);
            } else {
                DBGPRINTF("imkafka: error setting custom configuration parameter '%s=%s': %s", inst->confParams[i].name,
                          inst->confParams[i].val, kafkaErrMsg);
            }
            ABORT_FINALIZE(RS_RET_PARAM_ERROR);
        }
    }

    /* Topic configuration */
    inst->topic_conf = rd_kafka_topic_conf_new();

    /* Assign kafka group id */
    if (inst->consumergroup != NULL) {
        DBGPRINTF("imkafka: setting consumergroup: '%s'\n", inst->consumergroup);
        if (rd_kafka_conf_set(inst->conf, "group.id", (char *)inst->consumergroup, kafkaErrMsg, sizeof(kafkaErrMsg)) !=
            RD_KAFKA_CONF_OK) {
            if (inst->bReportErrs) {
                LogError(0, RS_RET_KAFKA_ERROR,
                         "imkafka: error assigning consumergroup %s to "
                         "kafka config: %s\n",
                         inst->consumergroup, kafkaErrMsg);
            }
            ABORT_FINALIZE(RS_RET_KAFKA_ERROR);
        }


        /* Set default for auto offset reset */
        if (rd_kafka_topic_conf_set(inst->topic_conf, "auto.offset.reset", "smallest", kafkaErrMsg,
                                    sizeof(kafkaErrMsg)) != RD_KAFKA_CONF_OK) {
            if (inst->bReportErrs) {
                LogError(0, RS_RET_KAFKA_ERROR, "imkafka: error setting kafka auto.offset.reset on %s: %s\n",
                         inst->consumergroup, kafkaErrMsg);
            }
            ABORT_FINALIZE(RS_RET_KAFKA_ERROR);
        }
        /* Consumer groups always use broker based offset storage */
        if (rd_kafka_topic_conf_set(inst->topic_conf, "offset.store.method", "broker", kafkaErrMsg,
                                    sizeof(kafkaErrMsg)) != RD_KAFKA_CONF_OK) {
            if (inst->bReportErrs) {
                LogError(0, RS_RET_KAFKA_ERROR, "imkafka: error setting kafka offset.store.method on %s: %s\n",
                         inst->consumergroup, kafkaErrMsg);
            }
            ABORT_FINALIZE(RS_RET_KAFKA_ERROR);
        }

        /* Set default topic config for pattern-matched topics. */
        rd_kafka_conf_set_default_topic_conf(inst->conf, inst->topic_conf);
    }

#if RD_KAFKA_VERSION >= 0x00090001
    rd_kafka_conf_set_log_cb(inst->conf, kafkaLogger);
#endif

    /* Create Kafka Consumer */
    inst->rk = rd_kafka_new(RD_KAFKA_CONSUMER, inst->conf, kafkaErrMsg, sizeof(kafkaErrMsg));
    if (inst->rk == NULL) {
        if (inst->bReportErrs) {
            LogError(0, RS_RET_KAFKA_ERROR, "imkafka: error creating kafka handle: %s\n", kafkaErrMsg);
        }
        ABORT_FINALIZE(RS_RET_KAFKA_ERROR);
    }
#if RD_KAFKA_VERSION < 0x00090001
    rd_kafka_set_logger(inst->rk, kafkaLogger);
#endif

    DBGPRINTF("imkafka: setting brokers: '%s'\n", inst->brokers);
    if (rd_kafka_brokers_add(inst->rk, (char *)inst->brokers) == 0) {
        if (inst->bReportErrs) {
            LogError(0, RS_RET_KAFKA_NO_VALID_BROKERS, "imkafka: no valid brokers specified: %s", inst->brokers);
        }
        ABORT_FINALIZE(RS_RET_KAFKA_NO_VALID_BROKERS);
    }

    /* Kafka Consumer is opened */
    inst->bIsConnected = 1;

finalize_it:
    if (iRet != RS_RET_OK) {
        if (inst->rk == NULL) {
            if (inst->conf != NULL) {
                rd_kafka_conf_destroy(inst->conf);
                inst->conf = NULL;
            }
        } else { /* inst->rk != NULL ! */
            rd_kafka_destroy(inst->rk);
            inst->rk = NULL;
        }
    }

    RETiRet;
}

/* function to generate an error message if the ruleset cannot be found */
static inline void std_checkRuleset_genErrMsg(__attribute__((unused)) modConfData_t *modConf, instanceConf_t *inst) {
    if (inst->bReportErrs) {
        LogError(0, NO_ERRCODE,
                 "imkafka: ruleset '%s' not found - "
                 "using default ruleset instead",
                 inst->pszBindRuleset);
    }
}


static rsRetVal ATTR_NONNULL(2) addConsumer(modConfData_t __attribute__((unused)) * modConf, instanceConf_t *inst) {
    DEFiRet;
    rd_kafka_resp_err_t err;

    assert(inst != NULL);

    rd_kafka_topic_partition_list_t *topics = NULL;
    DBGPRINTF("imkafka: creating kafka consumer on %s/%s/%s\n", inst->topic, inst->consumergroup, inst->brokers);

    /* Redirect rd_kafka_poll() to consumer_poll() */
    rd_kafka_poll_set_consumer(inst->rk);

    topics = rd_kafka_topic_partition_list_new(1);
    rd_kafka_topic_partition_list_add(topics, (const char *)inst->topic, inst->partition);
    DBGPRINTF("imkafka: Created topics(%d) for %s)\n", topics->cnt, inst->topic);
    if ((err = rd_kafka_subscribe(inst->rk, topics))) {
        /* Subscription failed */
        inst->bIsSubscribed = 0;
        LogError(0, RS_RET_KAFKA_ERROR,
                 "imkafka: Failed to start consuming "
                 "topics: %s\n",
                 rd_kafka_err2str(err));
        ABORT_FINALIZE(RS_RET_KAFKA_ERROR);
    } else {
        DBGPRINTF("imkafka: Successfully subscribed to %s/%s/%s\n", inst->topic, inst->consumergroup, inst->brokers);
        /* Subscription is working */
        inst->bIsSubscribed = 1;
    }
finalize_it:
    if (topics != NULL) rd_kafka_topic_partition_list_destroy(topics);
    RETiRet;
}

static rsRetVal ATTR_NONNULL()
    processKafkaParam(char *const param, const char **const name, const char **const paramval) {
    DEFiRet;
    char *val = strstr(param, "=");
    if (val == NULL) {
        LogError(0, RS_RET_PARAM_ERROR,
                 "missing equal sign in "
                 "parameter '%s'",
                 param);
        ABORT_FINALIZE(RS_RET_PARAM_ERROR);
    }
    *val = '\0'; /* terminates name */
    ++val; /* now points to begin of value */
    CHKmalloc(*name = strdup(param));
    CHKmalloc(*paramval = strdup(val));
finalize_it:
    RETiRet;
}

BEGINnewInpInst
    struct cnfparamvals *pvals;
    instanceConf_t *inst;
    int i;
    CODESTARTnewInpInst;
    DBGPRINTF("newInpInst (imkafka)\n");

    if ((pvals = nvlstGetParams(lst, &inppblk, NULL)) == NULL) {
        ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
    }

    if (Debug) {
        dbgprintf("input param blk in imkafka:\n");
        cnfparamsPrint(&inppblk, pvals);
    }

    CHKiRet(createInstance(&inst));

    for (i = 0; i < inppblk.nParams; ++i) {
        if (!pvals[i].bUsed) continue;
        if (!strcmp(inppblk.descr[i].name, "broker")) {
            es_str_t *es = es_newStr(128);
            int bNeedComma = 0;
            for (int j = 0; j < pvals[i].val.d.ar->nmemb; ++j) {
                if (bNeedComma) es_addChar(&es, ',');
                es_addStr(&es, pvals[i].val.d.ar->arr[j]);
                bNeedComma = 1;
            }
            inst->brokers = es_str2cstr(es, NULL);
            es_deleteStr(es);
        } else if (!strcmp(inppblk.descr[i].name, "confparam")) {
            inst->nConfParams = pvals[i].val.d.ar->nmemb;
            CHKmalloc(inst->confParams = malloc(sizeof(struct kafka_params) * inst->nConfParams));
            for (int j = 0; j < inst->nConfParams; j++) {
                char *cstr = es_str2cstr(pvals[i].val.d.ar->arr[j], NULL);
                CHKiRet(processKafkaParam(cstr, &inst->confParams[j].name, &inst->confParams[j].val));
                free(cstr);
            }
        } else if (!strcmp(inppblk.descr[i].name, "topic")) {
            inst->topic = (uchar *)es_str2cstr(pvals[i].val.d.estr, NULL);
        } else if (!strcmp(inppblk.descr[i].name, "consumergroup")) {
            inst->consumergroup = (uchar *)es_str2cstr(pvals[i].val.d.estr, NULL);
        } else if (!strcmp(inppblk.descr[i].name, "ruleset")) {
            inst->pszBindRuleset = (uchar *)es_str2cstr(pvals[i].val.d.estr, NULL);
        } else if (!strcmp(inppblk.descr[i].name, "parsehostname")) {
            if (pvals[i].val.d.n) {
                inst->nMsgParsingFlags = NEEDS_PARSING | PARSE_HOSTNAME;
            } else {
                inst->nMsgParsingFlags = NEEDS_PARSING;
            }
        } else {
            dbgprintf(
                "imkafka: program error, non-handled "
                "param '%s'\n",
                inppblk.descr[i].name);
        }
    }

    if (inst->brokers == NULL) {
        CHKmalloc(inst->brokers = strdup("localhost:9092"));
        LogMsg(0, NO_ERRCODE, LOG_INFO,
               "imkafka: \"broker\" parameter not specified "
               "using default of localhost:9092 -- this may not be what you want!");
    }

    DBGPRINTF("imkafka: newInpIns brokers=%s, topic=%s, consumergroup=%s\n", inst->brokers, inst->topic,
              inst->consumergroup);

finalize_it:
    CODE_STD_FINALIZERnewInpInst cnfparamvalsDestruct(pvals, &inppblk);
ENDnewInpInst


BEGINbeginCnfLoad
    CODESTARTbeginCnfLoad;
    loadModConf = pModConf;
    pModConf->pConf = pConf;
    pModConf->pszBindRuleset = NULL;
ENDbeginCnfLoad


BEGINsetModCnf
    struct cnfparamvals *pvals = NULL;
    int i;
    CODESTARTsetModCnf;
    pvals = nvlstGetParams(lst, &modpblk, NULL);
    if (pvals == NULL) {
        LogError(0, RS_RET_MISSING_CNFPARAMS,
                 "imkafka: error processing module "
                 "config parameters [module(...)]");
        ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
    }

    if (Debug) {
        dbgprintf("module (global) param blk for imkafka:\n");
        cnfparamsPrint(&modpblk, pvals);
    }

    for (i = 0; i < modpblk.nParams; ++i) {
        if (!pvals[i].bUsed) continue;
        if (!strcmp(modpblk.descr[i].name, "ruleset")) {
            loadModConf->pszBindRuleset = (uchar *)es_str2cstr(pvals[i].val.d.estr, NULL);
        } else {
            dbgprintf(
                "imkafka: program error, non-handled "
                "param '%s' in beginCnfLoad\n",
                modpblk.descr[i].name);
        }
    }
finalize_it:
    if (pvals != NULL) cnfparamvalsDestruct(pvals, &modpblk);
ENDsetModCnf

BEGINendCnfLoad
    CODESTARTendCnfLoad;
    if (loadModConf->pszBindRuleset == NULL) {
        if ((cs.pszBindRuleset == NULL) || (cs.pszBindRuleset[0] == '\0')) {
            loadModConf->pszBindRuleset = NULL;
        } else {
            CHKmalloc(loadModConf->pszBindRuleset = ustrdup(cs.pszBindRuleset));
        }
    }
finalize_it:
    free(cs.pszBindRuleset);
    cs.pszBindRuleset = NULL;
    loadModConf = NULL; /* done loading */
ENDendCnfLoad

BEGINcheckCnf
    instanceConf_t *inst;
    CODESTARTcheckCnf;
    for (inst = pModConf->root; inst != NULL; inst = inst->next) {
        if (inst->pszBindRuleset == NULL && pModConf->pszBindRuleset != NULL) {
            CHKmalloc(inst->pszBindRuleset = ustrdup(pModConf->pszBindRuleset));
        }
        std_checkRuleset(pModConf, inst);
    }
finalize_it:
ENDcheckCnf


BEGINactivateCnfPrePrivDrop
    CODESTARTactivateCnfPrePrivDrop;
    runModConf = pModConf;
ENDactivateCnfPrePrivDrop

BEGINactivateCnf
    CODESTARTactivateCnf;
    for (instanceConf_t *inst = pModConf->root; inst != NULL; inst = inst->next) {
        iRet = checkInstance(inst);
    }
ENDactivateCnf


BEGINfreeCnf
    instanceConf_t *inst, *del;
    CODESTARTfreeCnf;
    for (inst = pModConf->root; inst != NULL;) {
        free(inst->topic);
        free(inst->consumergroup);
        free(inst->brokers);
        free(inst->pszBindRuleset);
        for (int i = 0; i < inst->nConfParams; i++) {
            free((void *)inst->confParams[i].name);
            free((void *)inst->confParams[i].val);
        }
        free((void *)inst->confParams);
        del = inst;
        inst = inst->next;
        free(del);
    }
    free(pModConf->pszBindRuleset);
ENDfreeCnf


/* Cleanup imkafka worker threads */
static void shutdownKafkaWorkers(void) {
    int i;
    instanceConf_t *inst;

    assert(kafkaWrkrInfo != NULL);

    DBGPRINTF("imkafka: waiting on imkafka workerthread termination\n");
    for (i = 0; i < activeKafkaworkers; ++i) {
        pthread_join(kafkaWrkrInfo[i].tid, NULL);
        DBGPRINTF("imkafka: Stopped worker %d\n", i);
    }
    free(kafkaWrkrInfo);
    kafkaWrkrInfo = NULL;

    for (inst = runModConf->root; inst != NULL; inst = inst->next) {
        DBGPRINTF("imkafka: stop consuming %s/%s/%s\n", inst->topic, inst->consumergroup, inst->brokers);
        rd_kafka_consumer_close(inst->rk); /* Close the consumer, committing final offsets, etc. */
        rd_kafka_destroy(inst->rk); /* Destroy handle object */
        DBGPRINTF("imkafka: stopped consuming %s/%s/%s\n", inst->topic, inst->consumergroup, inst->brokers);

#if RD_KAFKA_VERSION < 0x00090001
        /* Wait for kafka being destroyed in old API */
        if (rd_kafka_wait_destroyed(10000) < 0) {
            DBGPRINTF(
                "imkafka: error, rd_kafka_destroy did not finish after grace "
                "timeout (10s)!\n");
        } else {
            DBGPRINTF("imkafka: rd_kafka_destroy successfully finished\n");
        }
#endif
    }
}


/* This function is called to gather input.  */
BEGINrunInput
    int i;
    instanceConf_t *inst;
    CODESTARTrunInput;
    DBGPRINTF("imkafka: runInput loop started ...\n");
    activeKafkaworkers = 0;
    for (inst = runModConf->root; inst != NULL; inst = inst->next) {
        if (inst->rk != NULL) {
            ++activeKafkaworkers;
        }
    }

    if (activeKafkaworkers == 0) {
        LogError(0, RS_RET_ERR,
                 "imkafka: no active inputs, input does "
                 "not run - there should have been additional error "
                 "messages given previously");
        ABORT_FINALIZE(RS_RET_ERR);
    }


    DBGPRINTF("imkafka: Starting %d imkafka workerthreads\n", activeKafkaworkers);
    kafkaWrkrInfo = calloc(activeKafkaworkers, sizeof(struct kafkaWrkrInfo_s));
    if (kafkaWrkrInfo == NULL) {
        LogError(errno, RS_RET_OUT_OF_MEMORY, "imkafka: worker-info array allocation failed.");
        ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
    }

    /* Start worker threads for each imkafka input source
     */
    i = 0;
    for (inst = runModConf->root; inst != NULL; inst = inst->next) {
        /* init worker info structure! */
        kafkaWrkrInfo[i].inst = inst; /* Set reference pointer */
        pthread_create(&kafkaWrkrInfo[i].tid, &wrkrThrdAttr, imkafkawrkr, &(kafkaWrkrInfo[i]));
        i++;
    }

    while (glbl.GetGlobalInputTermState() == 0) {
        /* Note: the additional 10000ns wait is vitally important. It guards rsyslog
         * against totally hogging the CPU if the users selects a polling interval
         * of 0 seconds. It doesn't hurt any other valid scenario. So do not remove.
         */
        if (glbl.GetGlobalInputTermState() == 0) srSleep(0, 100000);
    }
    DBGPRINTF("imkafka: terminating upon request of rsyslog core\n");

    /* we need to shutdown kafak worker threads here because this operation can
     * potentially block (e.g. when no kafka broker is available!). If this
     * happens in runInput, the rsyslog core can cancel our thread. However,
     * in afterRun this is not possible, because the core does not assume it
     * can block there. -- rgerhards, 2018-10-23
     */
    shutdownKafkaWorkers();
finalize_it:
ENDrunInput


BEGINwillRun
    CODESTARTwillRun;
    /* we need to create the inputName property (only once during our lifetime) */
    CHKiRet(prop.Construct(&pInputName));
    CHKiRet(prop.SetString(pInputName, UCHAR_CONSTANT("imkafka"), sizeof("imkafka") - 1));
    CHKiRet(prop.ConstructFinalize(pInputName));
finalize_it:
ENDwillRun


BEGINafterRun
    CODESTARTafterRun;
    if (pInputName != NULL) prop.Destruct(&pInputName);

ENDafterRun


BEGINmodExit
    CODESTARTmodExit;
    pthread_attr_destroy(&wrkrThrdAttr);
    /* release objects we used */
    objRelease(statsobj, CORE_COMPONENT);
    objRelease(ruleset, CORE_COMPONENT);
    objRelease(glbl, CORE_COMPONENT);
    objRelease(prop, CORE_COMPONENT);
ENDmodExit


BEGINisCompatibleWithFeature
    CODESTARTisCompatibleWithFeature;
    if (eFeat == sFEATURENonCancelInputTermination) iRet = RS_RET_OK;
ENDisCompatibleWithFeature


BEGINqueryEtryPt
    CODESTARTqueryEtryPt;
    CODEqueryEtryPt_STD_IMOD_QUERIES;
    CODEqueryEtryPt_STD_CONF2_QUERIES;
    CODEqueryEtryPt_STD_CONF2_PREPRIVDROP_QUERIES;
    CODEqueryEtryPt_STD_CONF2_IMOD_QUERIES;
    CODEqueryEtryPt_STD_CONF2_setModCnf_QUERIES;
    CODEqueryEtryPt_IsCompatibleWithFeature_IF_OMOD_QUERIES;
ENDqueryEtryPt


BEGINmodInit()
    CODESTARTmodInit;
    *ipIFVersProvided = CURR_MOD_IF_VERSION;
    CODEmodInit_QueryRegCFSLineHdlr
        /* request objects we use */
        CHKiRet(objUse(glbl, CORE_COMPONENT));
    CHKiRet(objUse(prop, CORE_COMPONENT));
    CHKiRet(objUse(ruleset, CORE_COMPONENT));
    CHKiRet(objUse(statsobj, CORE_COMPONENT));

    /* initialize "read-only" thread attributes */
    pthread_attr_init(&wrkrThrdAttr);
    pthread_attr_setstacksize(&wrkrThrdAttr, 4096 * 1024);

    DBGPRINTF("imkafka %s using librdkafka version %s, 0x%x\n", VERSION, rd_kafka_version_str(), rd_kafka_version());
ENDmodInit

/*
 *	Workerthread function for a single kafka consomer
 */
static void *imkafkawrkr(void *myself) {
    struct kafkaWrkrInfo_s *me = (struct kafkaWrkrInfo_s *)myself;
    DBGPRINTF("imkafka: started kafka consumer workerthread on %s/%s/%s\n", me->inst->topic, me->inst->consumergroup,
              me->inst->brokers);

    do {
        if (glbl.GetGlobalInputTermState() == 1) break; /* terminate input! */

        if (me->inst->rk == NULL) {
            continue;
        }

        // Try to add consumer only if connected! */
        if (me->inst->bIsConnected == 1 && me->inst->bIsSubscribed == 0) {
            addConsumer(runModConf, me->inst);
        }
        if (me->inst->bIsSubscribed == 1) {
            msgConsume(me->inst);
        }
        /* Note: the additional 10000ns wait is vitally important. It guards rsyslog
         * against totally hogging the CPU if the users selects a polling interval
         * of 0 seconds. It doesn't hurt any other valid scenario. So do not remove.
         * rgerhards, 2008-02-14
         */
        if (glbl.GetGlobalInputTermState() == 0) srSleep(0, 100000);
    } while (glbl.GetGlobalInputTermState() == 0);

    DBGPRINTF("imkafka: stopped kafka consumer workerthread on %s/%s/%s\n", me->inst->topic, me->inst->consumergroup,
              me->inst->brokers);
    return NULL;
}
