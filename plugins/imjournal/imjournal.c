/* The systemd journal import module
 *
 * To test under Linux:
 * emmit log message into systemd journal
 *
 * Copyright (C) 2008-2019 Adiscon GmbH
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
#include "rsyslog.h"
#include <stdio.h>
#include <dirent.h>
#include <assert.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <stdlib.h>
#include <time.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <systemd/sd-journal.h>
#include <fcntl.h>

#include "dirty.h"
#include "cfsysline.h"
#include "obj.h"
#include "msg.h"
#include "module-template.h"
#include "datetime.h"
#include "net.h"
#include "glbl.h"
#include "statsobj.h"
#include "ruleset.h"
#include "parser.h"
#include "prop.h"
#include "errmsg.h"
#include "srUtils.h"
#include "unicode-helper.h"
#include "ratelimit.h"


MODULE_TYPE_INPUT;
MODULE_TYPE_NOKEEP;
MODULE_CNFNAME("imjournal")

/* Module static data */
DEF_IMOD_STATIC_DATA;
DEFobjCurrIf(datetime) DEFobjCurrIf(glbl) DEFobjCurrIf(parser) DEFobjCurrIf(prop) DEFobjCurrIf(net)
    DEFobjCurrIf(ruleset) DEFobjCurrIf(statsobj)

    /* Module static data */
    typedef struct journal_etry_s {
    pthread_t tid; /* the worker's thread ID */
    ruleset_t *pBindRuleset;
    char *stateFile;
    struct journalContext_s *journalContext;
    struct journal_etry_s *next;
} journal_etry_t;
static journal_etry_t *journal_root = NULL;
static int n_journal = 0;

struct modConfData_s {
    rsconf_t *pConf;
    instanceConf_t *root, *tail;
};

static struct configSettings_s {
    char *stateFile;
    int fCreateMode; /* default mode to use when creating new files, e.g. stateFile */
    int iPersistStateInterval;
    unsigned int ratelimitInterval;
    unsigned int ratelimitBurst;
    int bIgnorePrevious;
    int bIgnoreNonValidStatefile;
    int iDfltSeverity;
    int iDfltFacility;
    int bUseJnlPID;
    char *usePid;
    int bWorkAroundJournalBug; /* deprecated, left for backwards compatibility only */
    int bFsync;
    int bRemote;
    char *dfltTag;
} cs;

static rsRetVal facilityHdlr(uchar **pp, void *pVal);

/* module-global parameters */
static struct cnfparamdescr modpdescr[] = {{"statefile", eCmdHdlrGetWord, 0},
                                           {"filecreatemode", eCmdHdlrFileCreateMode, 0},
                                           {"ratelimit.interval", eCmdHdlrInt, 0},
                                           {"ratelimit.burst", eCmdHdlrInt, 0},
                                           {"persiststateinterval", eCmdHdlrInt, 0},
                                           {"ignorepreviousmessages", eCmdHdlrBinary, 0},
                                           {"ignorenonvalidstatefile", eCmdHdlrBinary, 0},
                                           {"defaultseverity", eCmdHdlrSeverity, 0},
                                           {"defaultfacility", eCmdHdlrString, 0},
                                           {"usepidfromsystem", eCmdHdlrBinary, 0},
                                           {"usepid", eCmdHdlrString, 0},
                                           {"workaroundjournalbug", eCmdHdlrBinary, 0},
                                           {"fsync", eCmdHdlrBinary, 0},
                                           {"remote", eCmdHdlrBinary, 0},
                                           {"defaulttag", eCmdHdlrGetWord, 0}};
static struct cnfparamblk modpblk = {CNFPARAMBLK_VERSION, sizeof(modpdescr) / sizeof(struct cnfparamdescr), modpdescr};

/* input instance parameters */
static struct cnfparamdescr inppdescr[] = {
    {"ruleset", eCmdHdlrString, 0},
    {"main", eCmdHdlrBinary, 0},
};
static struct cnfparamblk inppblk = {CNFPARAMBLK_VERSION, sizeof(inppdescr) / sizeof(struct cnfparamdescr), inppdescr};

struct instanceConf_s {
    struct instanceConf_s *next;
    char *stateFile;
    uchar *pszBindRuleset;
    ruleset_t *pBindRuleset; /* ruleset to bind listener to (use system default if unspecified) */
    int bMain;
};

#include "im-helper.h" /* must be included AFTER the type definitions! */

#define DFLT_persiststateinterval 10
#define DFLT_SEVERITY pri2sev(LOG_NOTICE)
#define DFLT_FACILITY pri2fac(LOG_USER)
#define DFLT_TAG "journal"

static int bLegacyCnfModGlobalsPermitted = 1; /* are legacy module-global config parameters permitted? */

static prop_t *pInputName = NULL;
/* there is only one global inputName for all messages generated by this module */
static prop_t *pLocalHostIP = NULL; /* a pseudo-constant propterty for 127.0.0.1 */
static const char *pidFieldName; /* read-only after startup */
static int bPidFallBack;
static ratelimit_t *ratelimiter = NULL;
static struct {
    statsobj_t *stats;
    STATSCOUNTER_DEF(ctrSubmitted, mutCtrSubmitted)
    STATSCOUNTER_DEF(ctrRead, mutCtrRead);
    STATSCOUNTER_DEF(ctrDiscarded, mutCtrDiscarded);
    STATSCOUNTER_DEF(ctrFailed, mutCtrFailed);
    STATSCOUNTER_DEF(ctrPollFailed, mutCtrPollFailed);
    STATSCOUNTER_DEF(ctrRotations, mutCtrRotations);
    STATSCOUNTER_DEF(ctrRecoveryAttempts, mutCtrRecoveryAttempts);
    uint64 ratelimitDiscardedInInterval;
    uint64 diskUsageBytes;
} statsCounter;
struct journalContext_s { /* structure encapsulating all the journald_API-related stuff  */
    sd_journal *j; /* main object encapsulating journal for us, has to be used in every sd_journal*() call */
    sbool reloaded; /* we have reloaded journal after detecting rotation */
    sbool atHead; /* true if we are at start of journal (no seek was done) */
    char *cursor; /* should point to last valid journald entry we processed */
};

#define MAX_JOURNAL 8
static struct journalContext_s journalContextArray[MAX_JOURNAL] = {
    {NULL, 0, 1, NULL}, {NULL, 0, 1, NULL}, {NULL, 0, 1, NULL}, {NULL, 0, 1, NULL},
    {NULL, 0, 1, NULL}, {NULL, 0, 1, NULL}, {NULL, 0, 1, NULL}, {NULL, 0, 1, NULL},
};
static modConfData_t *loadModConf = NULL; /* modConf ptr to use for the current load process */
static modConfData_t *runModConf = NULL; /* modConf ptr to use for run process */

#define J_PROCESS_PERIOD 1024 /* Call sd_journal_process() every 1,024 records */

static rsRetVal persistJournalState(struct journalContext_s *journalContext, char *stateFile);
static rsRetVal loadJournalState(struct journalContext_s *journalContext, char *stateFile);

static rsRetVal openJournal(struct journalContext_s *journalContext) {
    int r;
    DEFiRet;

    if (journalContext->j) {
        LogMsg(0, RS_RET_OK_WARN, LOG_WARNING, "imjournal: opening journal when already opened.\n");
    }
    if ((r = sd_journal_open(&journalContext->j, cs.bRemote ? 0 : SD_JOURNAL_LOCAL_ONLY)) < 0) {
        LogError(-r, RS_RET_IO_ERROR, "imjournal: sd_journal_open() failed");
        iRet = RS_RET_IO_ERROR;
    }
    if ((r = sd_journal_set_data_threshold(journalContext->j, glbl.GetMaxLine(runModConf->pConf))) < 0) {
        LogError(-r, RS_RET_IO_ERROR, "imjournal: sd_journal_set_data_threshold() failed");
        iRet = RS_RET_IO_ERROR;
    }
    journalContext->atHead = 1;
    RETiRet;
}

/* trySave shoulod only be true if there is no journald error preceeding this call */
static void closeJournal(struct journalContext_s *journalContext) {
    if (!journalContext->j) {
        LogMsg(0, RS_RET_OK_WARN, LOG_WARNING, "imjournal: closing NULL journal.\n");
    }
    sd_journal_close(journalContext->j);
    journalContext->j = NULL; /* setting to NULL here as journald API will not do that for us... */
}

static int journalGetData(struct journalContext_s *journalContext,
                          const char *field,
                          const void **data,
                          size_t *length) {
    int ret;

    ret = sd_journal_get_data(journalContext->j, field, data, length);
    if (ret == -EADDRNOTAVAIL) {
        LogError(-ret, RS_RET_ERR, "imjournal: Tried to get data without a 'next' call.\n");
        if ((ret = sd_journal_next(journalContext->j)) < 0) {
            LogError(-ret, RS_RET_ERR, "imjournal: sd_journal_next() failed\n");
        } else {
            ret = sd_journal_get_data(journalContext->j, field, data, length);
        }
    }

    return ret;
}


/* ugly workaround to handle facility numbers; values
 * derived from names need to be eight times smaller,
 * i.e.: 0..23
 */
static rsRetVal facilityHdlr(uchar **pp, void *pVal) {
    DEFiRet;
    char *p;

    skipWhiteSpace(pp);
    p = (char *)*pp;

    if (isdigit((int)*p)) {
        *((int *)pVal) = (int)strtol(p, (char **)pp, 10);
    } else {
        int len;
        syslogName_t *c;

        for (len = 0; p[len] && !isspace((int)p[len]); len++) /* noop */
            ;
        for (c = syslogFacNames; c->c_name; c++) {
            if (!strncasecmp(p, (char *)c->c_name, len)) {
                *((int *)pVal) = pri2fac(c->c_val);
                break;
            }
        }
        *pp += len;
    }

    RETiRet;
}


/* Currently just replaces '\0' with ' '. Not doing so would cause
 * the value to be truncated. New space is allocated for the resulting
 * string.
 */
static rsRetVal sanitizeValue(const char *in, size_t len, char **out) {
    char *buf, *p;
    DEFiRet;

    CHKmalloc(p = buf = malloc(len + 1));
    memcpy(buf, in, len);
    buf[len] = '\0';

    while ((p = memchr(p, '\0', len + buf - p)) != NULL) {
        *p++ = ' ';
    }

    *out = buf;

finalize_it:
    RETiRet;
}


/* Read JSON part of single journald message and return it as JSON object
 */
static rsRetVal readJSONfromJournalMsg(struct journalContext_s *journalContext, struct fjson_object **json) {
    DEFiRet;
    const void *get;
    const void *equal_sign;
    struct fjson_object *jval;
    size_t l;
    long prefixlen = 0;

    CHKmalloc(*json = fjson_object_new_object());

    SD_JOURNAL_FOREACH_DATA(journalContext->j, get, l) {
        char *data;
        char *name;

        /* locate equal sign, this is always present */
        equal_sign = memchr(get, '=', l);

        /* ... but we know better than to trust the specs */
        if (equal_sign == NULL) {
            LogError(0, RS_RET_ERR,
                     "SD_JOURNAL_FOREACH_DATA()"
                     "returned a malformed field (has no '='): '%s'",
                     (char *)get);
            continue; /* skip the entry */
        }

        /* get length of journal data prefix */
        prefixlen = ((char *)equal_sign - (char *)get);

        CHKmalloc(name = strndup(get, prefixlen));

        prefixlen++; /* remove '=' */

        CHKiRet_Hdlr(sanitizeValue(((const char *)get) + prefixlen, l - prefixlen, &data)) {
            free(name);
            FINALIZE;
        }

        /* and save them to json object */
        jval = fjson_object_new_string((char *)data);
        fjson_object_object_add(*json, name, jval);
        free(data);
        free(name);
    }
finalize_it:
    RETiRet;
}


/* Try to obtain current journald cursor and save it to journalContext struct.
 */
static rsRetVal updateJournalCursor(struct journalContext_s *journalContext) {
    DEFiRet;
    char *c = NULL;
    int r;

    if ((r = sd_journal_get_cursor(journalContext->j, &c)) < 0) {
        LogError(-r, RS_RET_ERR, "imjournal: Could not get journald cursor!\n");
        ABORT_FINALIZE(RS_RET_ERR);
    }
    /* save journal cursor (at this point we can be sure it is valid) */
    free(journalContext->cursor);
    journalContext->cursor = c;
finalize_it:
    RETiRet;
}


/* enqueue the the journal message into the message queue.
 * The provided msg string is not freed - thus must be done
 * by the caller.
 */
static rsRetVal enqMsg(uchar *msg,
                       uchar *pszTag,
                       int iFacility,
                       int iSeverity,
                       struct timeval *tp,
                       struct fjson_object *json,
                       int sharedJsonProperties,
                       ruleset_t *pBindRuleset) {
    struct syslogTime st;
    smsg_t *pMsg;
    size_t len;
    DEFiRet;

    assert(msg != NULL);
    assert(pszTag != NULL);

    if (tp == NULL) {
        CHKiRet(msgConstruct(&pMsg));
    } else {
        datetime.timeval2syslogTime(tp, &st, TIME_IN_LOCALTIME);
        CHKiRet(msgConstructWithTime(&pMsg, &st, tp->tv_sec));
    }
    MsgSetFlowControlType(pMsg, eFLOWCTL_LIGHT_DELAY);
    MsgSetInputName(pMsg, pInputName);
    len = strlen((char *)msg);
    MsgSetRawMsg(pMsg, (char *)msg, len);
    if (len > 0) parser.SanitizeMsg(pMsg);
    MsgSetMSGoffs(pMsg, 0); /* we do not have a header... */
    MsgSetRcvFrom(pMsg, glbl.GetLocalHostNameProp());
    MsgSetRcvFromIP(pMsg, pLocalHostIP);
    MsgSetHOSTNAME(pMsg, glbl.GetLocalHostName(), ustrlen(glbl.GetLocalHostName()));
    MsgSetTAG(pMsg, pszTag, ustrlen(pszTag));
    if (pBindRuleset != NULL) {
        MsgSetRuleset(pMsg, pBindRuleset);
    }
    pMsg->iFacility = iFacility;
    pMsg->iSeverity = iSeverity;

    if (json != NULL) {
        msgAddJSON(pMsg, (uchar *)"!", json, 0, sharedJsonProperties);
    }

    CHKiRet(ratelimitAddMsg(ratelimiter, NULL, pMsg));
    STATSCOUNTER_INC(statsCounter.ctrSubmitted, statsCounter.mutCtrSubmitted);

finalize_it:
    if (iRet == RS_RET_DISCARDMSG) {
        STATSCOUNTER_INC(statsCounter.ctrDiscarded, statsCounter.mutCtrDiscarded);
    } else if (iRet != RS_RET_OK) {
        LogError(0, RS_RET_ERR, "imjournal: error during enqMsg().\n");
    }

    RETiRet;
}


/* Read journal log while data are available, each read() reads one journald record.
 */
static rsRetVal readjournal(struct journalContext_s *journalContext, ruleset_t *pBindRuleset) {
    DEFiRet;

    struct timeval tv;
    uint64_t timestamp;

    struct fjson_object *json = NULL;
    int r;

    /* Information from messages */
    char *message = NULL;
    char *sys_iden;
    char *sys_iden_help = NULL;

    const void *get;
    const void *pidget;
    size_t length;
    size_t pidlength;

    int severity = cs.iDfltSeverity;
    int facility = cs.iDfltFacility;

    /* Get message text */
    if (journalGetData(journalContext, "MESSAGE", &get, &length) < 0) {
        CHKmalloc(message = strdup(""));
    } else {
        CHKiRet(sanitizeValue(((const char *)get) + 8, length - 8, &message));
    }
    STATSCOUNTER_INC(statsCounter.ctrRead, statsCounter.mutCtrRead);

    /* Get message severity ("priority" in journald's terminology) */
    if (journalGetData(journalContext, "PRIORITY", &get, &length) >= 0) {
        if (length == 10) {
            severity = ((char *)get)[9] - '0';
            if (severity < 0 || 7 < severity) {
                LogError(0, RS_RET_ERR,
                         "imjournal: the value of the 'PRIORITY' field is "
                         "out of bounds: %d, resetting",
                         severity);
                severity = cs.iDfltSeverity;
            }
        } else {
            LogError(0, RS_RET_ERR,
                     "The value of the 'PRIORITY' field has an "
                     "unexpected length: %zu\n",
                     length);
        }
    }

    /* Get syslog facility */
    if (journalGetData(journalContext, "SYSLOG_FACILITY", &get, &length) >= 0) {
        // Note: the journal frequently contains invalid facilities!
        if (length == 17 || length == 18) {
            facility = ((char *)get)[16] - '0';
            if (length == 18) {
                facility *= 10;
                facility += ((char *)get)[17] - '0';
            }
            if (facility < 0 || 23 < facility) {
                DBGPRINTF(
                    "The value of the 'FACILITY' field is "
                    "out of bounds: %d, resetting\n",
                    facility);
                facility = cs.iDfltFacility;
            }
        } else {
            DBGPRINTF(
                "The value of the 'FACILITY' field has an "
                "unexpected length: %zu value: '%s'\n",
                length, (const char *)get);
        }
    }

    /* Get message identifier, client pid and add ':' */
    if (journalGetData(journalContext, "SYSLOG_IDENTIFIER", &get, &length) >= 0) {
        CHKiRet(sanitizeValue(((const char *)get) + 18, length - 18, &sys_iden));
    } else if (journalGetData(journalContext, "_COMM", &get, &length) >= 0) {
        CHKiRet(sanitizeValue(((const char *)get) + 6, length - 6, &sys_iden));
    } else {
        CHKmalloc(sys_iden = strdup(cs.dfltTag));
    }

    /* trying to get PID, default is "SYSLOG_PID" property */
    if (journalGetData(journalContext, pidFieldName, &pidget, &pidlength) >= 0) {
        char *sys_pid;
        int val_ofs;

        val_ofs = strlen(pidFieldName) + 1; /* name + '=' */
        CHKiRet_Hdlr(sanitizeValue(((const char *)pidget) + val_ofs, pidlength - val_ofs, &sys_pid)) {
            free(sys_iden);
            FINALIZE;
        }
        r = asprintf(&sys_iden_help, "%s[%s]:", sys_iden, sys_pid);
        free(sys_pid);
    } else {
        /* this is fallback, "SYSLOG_PID" doesn't exist so trying to get "_PID" property */
        if (bPidFallBack && journalGetData(journalContext, "_PID", &pidget, &pidlength) >= 0) {
            char *sys_pid;
            int val_ofs;

            val_ofs = strlen("_PID") + 1; /* name + '=' */
            CHKiRet_Hdlr(sanitizeValue(((const char *)pidget) + val_ofs, pidlength - val_ofs, &sys_pid)) {
                free(sys_iden);
                FINALIZE;
            }
            r = asprintf(&sys_iden_help, "%s[%s]:", sys_iden, sys_pid);
            free(sys_pid);
        } else {
            /* there is no PID property available */
            r = asprintf(&sys_iden_help, "%s:", sys_iden);
        }
    }

    free(sys_iden);

    if (-1 == r) {
        STATSCOUNTER_INC(statsCounter.ctrFailed, statsCounter.mutCtrFailed);
        ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
    }

    CHKiRet(readJSONfromJournalMsg(journalContext, &json));

    /* calculate timestamp */
    if (sd_journal_get_realtime_usec(journalContext->j, &timestamp) >= 0) {
        tv.tv_sec = timestamp / 1000000;
        tv.tv_usec = timestamp % 1000000;
    }

    iRet = updateJournalCursor(journalContext);

    /* submit message */
    enqMsg((uchar *)message, (uchar *)sys_iden_help, facility, severity, &tv, json, 0, pBindRuleset);

finalize_it:
    free(sys_iden_help);
    free(message);
    RETiRet;
}


/* This function saves journal cursor into state file.
 * It must be checked that stateFile is configured prior to calling this.
 */
static rsRetVal persistJournalState(struct journalContext_s *journalContext, char *stateFile) {
    DEFiRet;
    char tmp_sf[MAXFNAME];
    int fd = -1;
    size_t len;
    ssize_t wr_ret;

    DBGPRINTF("Persisting journal position, cursor: %s, at head? %d\n", journalContext->cursor, journalContext->atHead);

    /* first check that we have valid cursor */
    if (!journalContext->cursor) {
        DBGPRINTF("Journal cursor is not valid, ok...\n");
        ABORT_FINALIZE(RS_RET_OK);
    }

    /* we create a temporary name by adding a ".tmp"
     * suffix to the end of our state file's name
     *
     * we use snprintf() to safely honor the boundaries
     * of the temporary state file name buffer by using
     * a precision specifier, which will limit the number
     * of bytes taken from stateFile to what will fit
     *
     * TODO: figure out a better way to avoid the PATH_MAX
     * problem. The truncated stateFile with .tmp at the
     * end is not optimal
     */
#define IM_SF_TMP_SUFFIX ".tmp"
    snprintf(tmp_sf, sizeof(tmp_sf), "%.*s%s",
             /* this calculates the max size for state file name, note that
              * sizeof() NOT -1 is intentional - it reserves spaces for the
              * NUL terminator.
              */
             (int)(sizeof(tmp_sf) - sizeof(IM_SF_TMP_SUFFIX)), stateFile, IM_SF_TMP_SUFFIX);

    fd = open((char *)tmp_sf, O_WRONLY | O_CREAT | O_CLOEXEC, cs.fCreateMode);
    if (fd == -1) {
        LogError(errno, RS_RET_FILE_OPEN_ERROR, "imjournal: open() failed for path: '%s'", tmp_sf);
        ABORT_FINALIZE(RS_RET_FILE_OPEN_ERROR);
    }

    len = strlen(journalContext->cursor);
    wr_ret = write(fd, journalContext->cursor, len);
    if (wr_ret != (ssize_t)len) {
        LogError(errno, RS_RET_IO_ERROR,
                 "imjournal: failed to save cursor to: '%s',"
                 "write returned %zd, expected %zu",
                 cs.stateFile, wr_ret, len);
        ABORT_FINALIZE(RS_RET_IO_ERROR);
    }

    /* change the name of the file to the configured one */
    if (rename(tmp_sf, stateFile) < 0) {
        LogError(errno, iRet, "imjournal: rename() failed for new path: '%s'", stateFile);
        ABORT_FINALIZE(RS_RET_IO_ERROR);
    }

    if (cs.bFsync) {
        if (fsync(fd) != 0) {
            LogError(errno, RS_RET_IO_ERROR, "imjournal: fsync on '%s' failed", stateFile);
            ABORT_FINALIZE(RS_RET_IO_ERROR);
        }
        /* In order to guarantee physical write we need to force parent sync as well */
        DIR *wd;
        if (!(wd = opendir((char *)glbl.GetWorkDir(runModConf->pConf)))) {
            LogError(errno, RS_RET_IO_ERROR, "imjournal: failed to open '%s' directory",
                     glbl.GetWorkDir(runModConf->pConf));
            ABORT_FINALIZE(RS_RET_IO_ERROR);
        }
        if (fsync(dirfd(wd)) != 0) {
            LogError(errno, RS_RET_IO_ERROR, "imjournal: fsync on '%s' failed", glbl.GetWorkDir(runModConf->pConf));
            ABORT_FINALIZE(RS_RET_IO_ERROR);
        }

        closedir(wd);
    }

    DBGPRINTF("Persisted journal to '%s'\n", stateFile);

finalize_it:
    if (fd != -1) {
        if (close(fd) == -1) {
            LogError(errno, RS_RET_IO_ERROR, "imjournal: close() failed for path: '%s'", tmp_sf);
            iRet = RS_RET_IO_ERROR;
        }
    }
    RETiRet;
}


static rsRetVal skipOldMessages(struct journalContext_s *journalContext);

static rsRetVal handleRotation(struct journalContext_s *journalContext, char *stateFile) {
    DEFiRet;

    LogMsg(0, RS_RET_OK, LOG_NOTICE, "imjournal: journal files changed, reloading...\n");
    STATSCOUNTER_INC(statsCounter.ctrRotations, statsCounter.mutCtrRotations);

    /* outside error scenarios we should always have a cursor available at this point */
    if (!journalContext->cursor) {
        if (stateFile) {
            iRet = loadJournalState(journalContext, stateFile);
        } else if (cs.bIgnorePrevious) {
            /* Seek to the very end of the journal and ignore all older messages. */
            iRet = skipOldMessages(journalContext);
        }
        FINALIZE;
    }

    if (sd_journal_seek_cursor(journalContext->j, journalContext->cursor) != 0) {
        LogError(0, RS_RET_ERR,
                 "imjournal: "
                 "couldn't seek to cursor `%s'\n",
                 journalContext->cursor);
        iRet = RS_RET_ERR;
    }
    journalContext->atHead = 0;

finalize_it:
    RETiRet;
}

#define POLL_TIMEOUT 900000 /* timeout for poll is 900ms */

static rsRetVal pollJournal(struct journalContext_s *journalContext, char *stateFile) {
    DEFiRet;
    int err;

    err = sd_journal_wait(journalContext->j, POLL_TIMEOUT);
    if (err == SD_JOURNAL_INVALIDATE) {
        CHKiRet(handleRotation(journalContext, stateFile));
    }

finalize_it:
    RETiRet;
}


static rsRetVal skipOldMessages(struct journalContext_s *journalContext) {
    int r;
    DEFiRet;

    if ((r = sd_journal_seek_tail(journalContext->j)) < 0) {
        LogError(-r, RS_RET_ERR, "imjournal: sd_journal_seek_tail() failed");
        ABORT_FINALIZE(RS_RET_ERR);
    }
    journalContext->atHead = 0;
    if ((r = sd_journal_previous(journalContext->j)) < 0) {
        LogError(-r, RS_RET_ERR, "imjournal: sd_journal_previous() failed");
        ABORT_FINALIZE(RS_RET_ERR);
    }

finalize_it:
    RETiRet;
}

/* This function loads a journal cursor from the state file.
 */
static rsRetVal loadJournalState(struct journalContext_s *journalContext, char *stateFile) {
    DEFiRet;
    int r;
    FILE *r_sf;

    DBGPRINTF("Loading journal position, at head? %d, reloaded? %d\n", journalContext->atHead,
              journalContext->reloaded);

    /* if state file not exists (on very first run), skip */
    if (access(stateFile, F_OK | R_OK) == -1 && errno == ENOENT) {
        if (cs.bIgnorePrevious) {
            /* Seek to the very end of the journal and ignore all older messages. */
            skipOldMessages(journalContext);
        }
        LogMsg(errno, RS_RET_FILE_NOT_FOUND, LOG_NOTICE,
               "imjournal: No statefile exists, "
               "%s will be created (ignore if this is first run)",
               stateFile);
        FINALIZE;
    }

    if ((r_sf = fopen(stateFile, "rb")) != NULL) {
        char readCursor[128 + 1];
        if (fscanf(r_sf, "%128s\n", readCursor) != EOF) {
            if (sd_journal_seek_cursor(journalContext->j, readCursor) != 0) {
                LogError(0, RS_RET_ERR,
                         "imjournal: "
                         "couldn't seek to cursor `%s'\n",
                         readCursor);
                iRet = RS_RET_ERR;
            } else {
                journalContext->atHead = 0;
                char *tmp_cursor = NULL;
                sd_journal_next(journalContext->j);
                /*
                * This is resolving the situation when system is after reboot and boot_id
                * doesn't match so cursor pointing into "future".
                * Usually sd_journal_next jump to head of journal due to journal aproximation,
                * but when system time goes backwards and cursor is still
                  invalid, rsyslog stops logging.
                * We use sd_journal_get_cursor to validate our cursor.
                * When cursor is invalid we are trying to jump to the head of journal
                * This problem with time should not affect persistent journal,
                * but if cursor has been intentionally compromised it could stop logging even
                * with persistent journal.
                * */
                if ((r = sd_journal_get_cursor(journalContext->j, &tmp_cursor)) < 0) {
                    LogError(-r, RS_RET_IO_ERROR,
                             "imjournal: "
                             "loaded invalid cursor, seeking to the head of journal\n");
                    if ((r = sd_journal_seek_head(journalContext->j)) < 0) {
                        LogError(-r, RS_RET_ERR,
                                 "imjournal: "
                                 "sd_journal_seek_head() failed, when cursor is invalid\n");
                        iRet = RS_RET_ERR;
                    }
                    journalContext->atHead = 1;
                }
                free(tmp_cursor);
            }
        } else {
            LogError(0, RS_RET_IO_ERROR,
                     "imjournal: "
                     "fscanf on state file `%s' failed\n",
                     stateFile);
            iRet = RS_RET_IO_ERROR;
        }

        fclose(r_sf);

        if (iRet != RS_RET_OK && cs.bIgnoreNonValidStatefile) {
            /* ignore state file errors */
            iRet = RS_RET_OK;
            LogError(0, NO_ERRCODE, "imjournal: ignoring invalid state file %s", stateFile);
            if (cs.bIgnorePrevious) {
                skipOldMessages(journalContext);
            }
        }
    } else {
        LogError(0, RS_RET_FOPEN_FAILURE, "imjournal: open on state file `%s' failed\n", stateFile);
        if (cs.bIgnorePrevious) {
            /* Seek to the very end of the journal and ignore all older messages. */
            skipOldMessages(journalContext);
        }
    }

finalize_it:
    RETiRet;
}

static void tryRecover(struct journalContext_s *journalContext) {
    LogMsg(0, RS_RET_OK, LOG_INFO, "imjournal: trying to recover from journal error");
    STATSCOUNTER_INC(statsCounter.ctrRecoveryAttempts, statsCounter.mutCtrRecoveryAttempts);
    closeJournal(journalContext);
    srSleep(0, 200000);  // do not hammer machine with too-frequent retries
    openJournal(journalContext);
}

static rsRetVal addListner(instanceConf_t *inst, u_int8_t index) {
    DEFiRet;
    if (index >= MAX_JOURNAL) {
        iRet = RS_RET_NO_MORE_DATA;
        RETiRet;
    }

    journal_etry_t *etry;
    CHKmalloc(etry = (journal_etry_t *)calloc(1, sizeof(journal_etry_t)));
    etry->journalContext = &journalContextArray[index];
    if (inst) {
        etry->pBindRuleset = inst->pBindRuleset;
        etry->stateFile = inst->stateFile;
    }
    etry->next = journal_root;
    journal_root = etry;
    ++n_journal;

finalize_it:
    if (iRet != RS_RET_OK) {
        LogError(0, NO_ERRCODE, "imjournal: error %d trying to add listener", iRet);
        free(etry);
    }
    RETiRet;
}


static rsRetVal doRun(journal_etry_t const *etry) {
    DEFiRet;
    uint64_t count = 0;
    char *stateFile = cs.stateFile;
    if (etry->stateFile) {
        stateFile = etry->stateFile;
    }

    if (stateFile) {
        /* Load our position in the journal from the state file. */
        CHKiRet(loadJournalState(etry->journalContext, stateFile));
    } else if (cs.bIgnorePrevious) {
        /* Seek to the very end of the journal and ignore all older messages. */
        skipOldMessages(etry->journalContext);
    }

    if (cs.dfltTag == NULL) {
        cs.dfltTag = strdup(DFLT_TAG);
    }

    if (cs.usePid && (strcmp(cs.usePid, "system") == 0)) {
        pidFieldName = "_PID";
        bPidFallBack = 0;
    } else if (cs.usePid && (strcmp(cs.usePid, "syslog") == 0)) {
        pidFieldName = "SYSLOG_PID";
        bPidFallBack = 0;
    } else {
        pidFieldName = "SYSLOG_PID";
        bPidFallBack = 1;
        if (cs.usePid && (strcmp(cs.usePid, "both") != 0)) {
            LogError(0, RS_RET_OK,
                     "option \"usepid\""
                     " should contain one of system|syslog|both and no '%s'",
                     cs.usePid);
        }
    }

    /* this is an endless loop - it is terminated when the thread is
     * signalled to do so. This, however, is handled by the framework.
     */
    while (glbl.GetGlobalInputTermState() == 0) {
        int r;

        /* read journal entries until we are at the end of the journal */
        while ((r = sd_journal_next(etry->journalContext->j)) > 0 && glbl.GetGlobalInputTermState() == 0) {
            /* We use sd_journal_next to move the read pointer forward by one entry.
             * However, this does not always ensure that the cursor advances to the next
             * entry, particularly after a journal rotation. If sd_journal_test_cursor()
             * returns 1, indicating the current entry matches the specified cursor,
             * we need to manually advance the cursor. This is because, after calling sd_journal_next,
             * the cursor should point to a new entry; otherwise, we read the same entry twice.
             */
            int test = sd_journal_test_cursor(etry->journalContext->j, etry->journalContext->cursor);
            if (test == 1) {
                DBGPRINTF("sd_journal_next did not move cursor, skipping message\n");
                continue;
            }

            /*
             * update journal disk usage before reading the new message.
             */
            const int e = sd_journal_get_usage(etry->journalContext->j, (uint64_t *)&statsCounter.diskUsageBytes);
            if (e < 0) {
                LogError(-e, RS_RET_ERR, "imjournal: sd_get_usage() failed");
            }

            if (readjournal(etry->journalContext, etry->pBindRuleset) != RS_RET_OK) {
                tryRecover(etry->journalContext);
                continue;
            }

            count++;
            etry->journalContext->atHead = 0;
            if (stateFile) {
                /* TODO: This could use some finer metric. */
                if ((count % cs.iPersistStateInterval) == 0) {
                    persistJournalState(etry->journalContext, stateFile);
                }
            }
        }

        if (r < 0) {
            LogError(-r, RS_RET_ERR, "imjournal: sd_journal_next() failed");
            tryRecover(etry->journalContext);
            continue;
        }

        /* At this point r == 0, which means no new messages are available. */
        if (etry->journalContext->atHead) {
            LogMsg(0, RS_RET_OK, LOG_WARNING,
                   "imjournal: "
                   "Journal indicates no msgs when positioned at head.\n");
        }

        /* No new messages, wait for activity. */
        if (pollJournal(etry->journalContext, stateFile) != RS_RET_OK) {
            tryRecover(etry->journalContext);
        }
    }
finalize_it:
    RETiRet;
}

static void *RunServerThread(void *myself) {
    DEFiRet;
    journal_etry_t *const etry = (journal_etry_t *)myself;
    iRet = doRun(etry);
    if (iRet != RS_RET_OK) {
        LogError(0, iRet,
                 "imjournal: error while stopping journal processing; "
                 "rsyslog may hang on shutdown");
    }
    return NULL;
}

/* support for running multiple servers on multiple threads (one server per thread) */
static void startSrvWrkr(journal_etry_t *const etry) {
    int r;
    pthread_attr_t sessThrdAttr;

    /* We need to temporarily block all signals because the new thread
     * inherits our signal mask. There is a race if we do not block them
     * now, and we have seen in practice that this race causes grief.
     * So we 1. save the current set, 2. block evertyhing, 3. start
     * threads, and 4 reset the current set to saved state.
     * rgerhards, 2019-08-16
     */
    sigset_t sigSet, sigSetSave;
    sigfillset(&sigSet);
    /* enable signals we still need */
    sigdelset(&sigSet, SIGTTIN);
    sigdelset(&sigSet, SIGSEGV);
    pthread_sigmask(SIG_SETMASK, &sigSet, &sigSetSave);

    pthread_attr_init(&sessThrdAttr);
    pthread_attr_setstacksize(&sessThrdAttr, 4096 * 1024);
    r = pthread_create(&etry->tid, &sessThrdAttr, RunServerThread, etry);
    if (r != 0) {
        LogError(r, NO_ERRCODE, "imjournal: error creating imjournal thread");
        /* we do NOT abort, as other servers may run - after all, we logged an error */
    }
    pthread_attr_destroy(&sessThrdAttr);
    pthread_sigmask(SIG_SETMASK, &sigSetSave, NULL);
}

/* stop server worker thread
 */
static void stopSrvWrkr(journal_etry_t *const etry) {
    DBGPRINTF("Wait for thread shutdown etry %p\n", etry);
    pthread_kill(etry->tid, SIGTTIN);
    pthread_join(etry->tid, NULL);
    DBGPRINTF("input %p terminated\n", etry);
}

BEGINrunInput
    CODESTARTrunInput;
    CHKiRet(ratelimitNew(&ratelimiter, "imjournal", NULL));
    dbgprintf("imjournal: ratelimiting burst %u, interval %u\n", cs.ratelimitBurst, cs.ratelimitInterval);
    ratelimitSetLinuxLike(ratelimiter, cs.ratelimitInterval, cs.ratelimitBurst);
    ratelimitSetNoTimeCache(ratelimiter);

    /* handling old "usepidfromsystem" option */
    if (cs.bUseJnlPID != -1) {
        free(cs.usePid);
        cs.usePid = strdup("system");
        LogError(0, RS_RET_DEPRECATED, "\"usepidfromsystem\" is deprecated, use \"usepid\" instead");
    }

    journal_etry_t *etry = journal_root->next;
    while (etry != NULL) {
        startSrvWrkr(etry);
        etry = etry->next;
    }

    CHKiRet(doRun(journal_root));

    etry = journal_root->next;
    while (etry != NULL) {
        stopSrvWrkr(etry);
        etry = etry->next;
    }

finalize_it:
ENDrunInput


BEGINbeginCnfLoad
    CODESTARTbeginCnfLoad;
    loadModConf = pModConf;
    pModConf->pConf = pConf;
    bLegacyCnfModGlobalsPermitted = 1;

    cs.bIgnoreNonValidStatefile = 1;
    cs.iPersistStateInterval = DFLT_persiststateinterval;
    cs.stateFile = NULL;
    cs.fCreateMode = 0644;
    cs.ratelimitBurst = 20000;
    cs.ratelimitInterval = 600;
    cs.iDfltSeverity = DFLT_SEVERITY;
    cs.iDfltFacility = DFLT_FACILITY;
    cs.bUseJnlPID = -1;
    cs.usePid = NULL;
    cs.bWorkAroundJournalBug = 1;
    cs.bFsync = 0;
    cs.bRemote = 0;
    cs.dfltTag = NULL;
ENDbeginCnfLoad


BEGINendCnfLoad
    CODESTARTendCnfLoad;
    /* bad trick to handle old and new style config all in old-style var */
    if (cs.stateFile != NULL && cs.stateFile[0] != '/') {
        char *new_stateFile;
        if (-1 == asprintf(&new_stateFile, "%s/%s", (char *)glbl.GetWorkDir(loadModConf->pConf), cs.stateFile)) {
            LogError(0, RS_RET_OUT_OF_MEMORY, "imjournal: asprintf failed\n");
            ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
        }
        free(cs.stateFile);
        cs.stateFile = new_stateFile;
    }
finalize_it:
ENDendCnfLoad


BEGINcheckCnf
    instanceConf_t *inst;
    CODESTARTcheckCnf;
    for (inst = pModConf->root; inst != NULL; inst = inst->next) {
        std_checkRuleset(pModConf, inst);
    }
ENDcheckCnf


BEGINactivateCnf
    instanceConf_t *inst;
    instanceConf_t *root_inst = NULL;
    u_int8_t index = 0;
    CODESTARTactivateCnf;
    runModConf = pModConf;

    /* support statistic gathering */
    CHKiRet(statsobj.Construct(&(statsCounter.stats)));
    CHKiRet(statsobj.SetName(statsCounter.stats, (uchar *)"imjournal"));
    CHKiRet(statsobj.SetOrigin(statsCounter.stats, (uchar *)"imjournal"));
    STATSCOUNTER_INIT(statsCounter.ctrSubmitted, statsCounter.mutCtrSubmitted);
    CHKiRet(statsobj.AddCounter(statsCounter.stats, UCHAR_CONSTANT("submitted"), ctrType_IntCtr, CTR_FLAG_RESETTABLE,
                                &(statsCounter.ctrSubmitted)));
    STATSCOUNTER_INIT(statsCounter.ctrRead, statsCounter.mutCtrRead);
    CHKiRet(statsobj.AddCounter(statsCounter.stats, UCHAR_CONSTANT("read"), ctrType_IntCtr, CTR_FLAG_RESETTABLE,
                                &(statsCounter.ctrRead)));
    STATSCOUNTER_INIT(statsCounter.ctrDiscarded, statsCounter.mutCtrDiscarded);
    CHKiRet(statsobj.AddCounter(statsCounter.stats, UCHAR_CONSTANT("discarded"), ctrType_IntCtr, CTR_FLAG_RESETTABLE,
                                &(statsCounter.ctrDiscarded)));
    STATSCOUNTER_INIT(statsCounter.ctrFailed, statsCounter.mutCtrFailed);
    CHKiRet(statsobj.AddCounter(statsCounter.stats, UCHAR_CONSTANT("failed"), ctrType_IntCtr, CTR_FLAG_RESETTABLE,
                                &(statsCounter.ctrFailed)));
    STATSCOUNTER_INIT(statsCounter.ctrPollFailed, statsCounter.mutCtrPollFailed);
    CHKiRet(statsobj.AddCounter(statsCounter.stats, UCHAR_CONSTANT("poll_failed"), ctrType_IntCtr, CTR_FLAG_RESETTABLE,
                                &(statsCounter.ctrPollFailed)));
    STATSCOUNTER_INIT(statsCounter.ctrRotations, statsCounter.mutCtrRotations);
    CHKiRet(statsobj.AddCounter(statsCounter.stats, UCHAR_CONSTANT("rotations"), ctrType_IntCtr, CTR_FLAG_RESETTABLE,
                                &(statsCounter.ctrRotations)));
    STATSCOUNTER_INIT(statsCounter.ctrRecoveryAttempts, statsCounter.mutCtrRecoveryAttempts);
    CHKiRet(statsobj.AddCounter(statsCounter.stats, UCHAR_CONSTANT("recovery_attempts"), ctrType_IntCtr,
                                CTR_FLAG_RESETTABLE, &(statsCounter.ctrRecoveryAttempts)));
    CHKiRet(statsobj.AddCounter(statsCounter.stats, UCHAR_CONSTANT("ratelimit_discarded_in_interval"), ctrType_Int,
                                CTR_FLAG_NONE, &(statsCounter.ratelimitDiscardedInInterval)));
    CHKiRet(statsobj.AddCounter(statsCounter.stats, UCHAR_CONSTANT("disk_usage_bytes"), ctrType_Int, CTR_FLAG_NONE,
                                &(statsCounter.diskUsageBytes)));
    CHKiRet(statsobj.ConstructFinalize(statsCounter.stats));
    /* end stats counter */

    for (inst = runModConf->root; inst != NULL; inst = inst->next) {
        if (cs.stateFile) {
            char *new_stateFile;
            if (-1 == asprintf(&new_stateFile, "%s/%s", cs.stateFile, inst->pszBindRuleset)) {
                LogError(0, RS_RET_OUT_OF_MEMORY, "imjournal: asprintf failed\n");
                ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
            }
            free(inst->stateFile);
            inst->stateFile = new_stateFile;
            ;
        }

        // Only the first input module with main enabled will be treated as
        // the main process.
        if (inst->bMain && root_inst == NULL) {
            root_inst = inst;
        } else {
            if (addListner(inst, index++) != RS_RET_OK) {
                LogError(0, RS_RET_NO_MORE_DATA, "imjournal: Can only support up to %i journals\n", MAX_JOURNAL);
                ABORT_FINALIZE(RS_RET_NO_MORE_DATA);
            }
        }
    }

    // Add all state files as a subfile of original cs.stateFile.
    if (runModConf->root != NULL && cs.stateFile) {
        char *new_stateFile;
        if (-1 == asprintf(&new_stateFile, "%s/default", cs.stateFile)) {
            LogError(0, RS_RET_OUT_OF_MEMORY, "imjournal: asprintf failed\n");
            ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
        }

        // TODO(need to delete old state file and create the folder.
        DIR *stateDir;
        if (!(stateDir = opendir(cs.stateFile))) {
            remove(cs.stateFile);
            mkdir(cs.stateFile, 0700);
        } else {
            closedir(stateDir);
        }

        free(cs.stateFile);
        cs.stateFile = new_stateFile;
        ;
    }

    // Default Handlers. Will be used as the main process if no `main`
    // property is set in the input modules.
    if (addListner(NULL, index++) != RS_RET_OK) {
        LogError(0, RS_RET_NO_MORE_DATA, "imjournal: Can only support up to %i journals\n", MAX_JOURNAL);
        ABORT_FINALIZE(RS_RET_NO_MORE_DATA);
    }

    // Main process will be the top of journal_root.
    if (root_inst != NULL) {
        if (addListner(root_inst, index++) != RS_RET_OK) {
            LogError(0, RS_RET_NO_MORE_DATA, "imjournal: Can only support up to %i journals\n", MAX_JOURNAL);
            ABORT_FINALIZE(RS_RET_NO_MORE_DATA);
        }
    }

finalize_it:
ENDactivateCnf


BEGINfreeCnf
    instanceConf_t *inst, *del;
    CODESTARTfreeCnf;
    for (inst = pModConf->root; inst != NULL;) {
        free(inst->pszBindRuleset);
        free(inst->stateFile);
        del = inst;
        inst = inst->next;
        free(del);
    }
    free(cs.stateFile);
    free(cs.usePid);
    free(cs.dfltTag);
    statsobj.Destruct(&(statsCounter.stats));
ENDfreeCnf

/* open journal */
BEGINwillRun
    journal_etry_t *etry = journal_root;
    CODESTARTwillRun;
    while (etry != NULL) {
        CHKiRet(openJournal(etry->journalContext));
        etry = etry->next;
    }
finalize_it:
ENDwillRun

/* close journal */
BEGINafterRun
    journal_etry_t *etry = journal_root;
    journal_etry_t *del;
    CODESTARTafterRun;
    while (etry != NULL) {
        char *stateFile = cs.stateFile;
        if (etry->stateFile) {
            stateFile = etry->stateFile;
        }
        if (stateFile) { /* can't persist without a state file */
            persistJournalState(etry->journalContext, stateFile);
        }
        closeJournal(etry->journalContext);
        free(etry->journalContext->cursor);
        // TODO: check iRet, reprot error
        del = etry;
        etry = etry->next;
        free(del);
    }

    if (ratelimiter) {
        ratelimitDestruct(ratelimiter);
    }
ENDafterRun


BEGINmodExit
    CODESTARTmodExit;
    if (pInputName != NULL) prop.Destruct(&pInputName);
    if (pLocalHostIP != NULL) prop.Destruct(&pLocalHostIP);

    /* release objects we used */
    objRelease(statsobj, CORE_COMPONENT);
    objRelease(glbl, CORE_COMPONENT);
    objRelease(net, CORE_COMPONENT);
    objRelease(datetime, CORE_COMPONENT);
    objRelease(parser, CORE_COMPONENT);
    objRelease(prop, CORE_COMPONENT);
    objRelease(ruleset, CORE_COMPONENT);
ENDmodExit


BEGINsetModCnf
    struct cnfparamvals *pvals = NULL;
    int i;
    CODESTARTsetModCnf;
    pvals = nvlstGetParams(lst, &modpblk, NULL);
    if (pvals == NULL) {
        LogError(0, RS_RET_MISSING_CNFPARAMS,
                 "error processing module "
                 "config parameters [module(...)]");
        ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
    }

    if (Debug) {
        dbgprintf("module (global) param blk for imjournal:\n");
        cnfparamsPrint(&modpblk, pvals);
    }

    for (i = 0; i < modpblk.nParams; ++i) {
        if (!pvals[i].bUsed) continue;
        if (!strcmp(modpblk.descr[i].name, "persiststateinterval")) {
            cs.iPersistStateInterval = (int)pvals[i].val.d.n;
        } else if (!strcmp(modpblk.descr[i].name, "statefile")) {
            cs.stateFile = (char *)es_str2cstr(pvals[i].val.d.estr, NULL);
        } else if (!strcmp(modpblk.descr[i].name, "filecreatemode")) {
            cs.fCreateMode = (int)pvals[i].val.d.n;
        } else if (!strcmp(modpblk.descr[i].name, "ratelimit.burst")) {
            cs.ratelimitBurst = (unsigned int)pvals[i].val.d.n;
        } else if (!strcmp(modpblk.descr[i].name, "ratelimit.interval")) {
            cs.ratelimitInterval = (unsigned int)pvals[i].val.d.n;
        } else if (!strcmp(modpblk.descr[i].name, "ignorepreviousmessages")) {
            cs.bIgnorePrevious = (int)pvals[i].val.d.n;
        } else if (!strcmp(modpblk.descr[i].name, "ignorenonvalidstatefile")) {
            cs.bIgnoreNonValidStatefile = (int)pvals[i].val.d.n;
        } else if (!strcmp(modpblk.descr[i].name, "defaultseverity")) {
            cs.iDfltSeverity = (int)pvals[i].val.d.n;
        } else if (!strcmp(modpblk.descr[i].name, "defaultfacility")) {
            /* ugly workaround to handle facility numbers; values
               derived from names need to be eight times smaller */

            char *fac, *p;

            fac = p = es_str2cstr(pvals[i].val.d.estr, NULL);
            facilityHdlr((uchar **)&p, (void *)&cs.iDfltFacility);
            free(fac);
        } else if (!strcmp(modpblk.descr[i].name, "usepidfromsystem")) {
            cs.bUseJnlPID = (int)pvals[i].val.d.n;
        } else if (!strcmp(modpblk.descr[i].name, "usepid")) {
            cs.usePid = (char *)es_str2cstr(pvals[i].val.d.estr, NULL);
        } else if (!strcmp(modpblk.descr[i].name, "workaroundjournalbug")) {
            cs.bWorkAroundJournalBug = (int)pvals[i].val.d.n;
        } else if (!strcmp(modpblk.descr[i].name, "fsync")) {
            cs.bFsync = (int)pvals[i].val.d.n;
        } else if (!strcmp(modpblk.descr[i].name, "remote")) {
            cs.bRemote = (int)pvals[i].val.d.n;
        } else if (!strcmp(modpblk.descr[i].name, "defaulttag")) {
            cs.dfltTag = (char *)es_str2cstr(pvals[i].val.d.estr, NULL);
        } else {
            dbgprintf(
                "imjournal: program error, non-handled "
                "param '%s' in beginCnfLoad\n",
                modpblk.descr[i].name);
        }
    }

finalize_it:
    if (pvals != NULL) cnfparamvalsDestruct(pvals, &modpblk);
ENDsetModCnf

/* create input instance, set default parameters, and
 * add it to the list of instances.
 */
static rsRetVal ATTR_NONNULL(1) createInstance(instanceConf_t **const pinst) {
    instanceConf_t *inst;
    DEFiRet;
    CHKmalloc(inst = malloc(sizeof(instanceConf_t)));
    inst->next = NULL;
    inst->pBindRuleset = NULL;
    inst->pszBindRuleset = NULL;

    /* node created, let's add to config */
    if (loadModConf->tail == NULL) {
        loadModConf->tail = loadModConf->root = inst;
    } else {
        loadModConf->tail->next = inst;
        loadModConf->tail = inst;
    }

    *pinst = inst;
finalize_it:
    if (iRet != RS_RET_OK) {
        free(inst);
    }
    RETiRet;
}


BEGINnewInpInst
    struct cnfparamvals *pvals;
    instanceConf_t *inst;
    int i;
    CODESTARTnewInpInst;
    DBGPRINTF("newInpInst (imjournal)\n");

    pvals = nvlstGetParams(lst, &inppblk, NULL);
    if (pvals == NULL) {
        ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
    }

    if (Debug) {
        DBGPRINTF("input param blk in imjournal:\n");
        cnfparamsPrint(&inppblk, pvals);
    }

    CHKiRet(createInstance(&inst));

    for (i = 0; i < inppblk.nParams; ++i) {
        if (!pvals[i].bUsed) continue;
        if (!strcmp(inppblk.descr[i].name, "ruleset")) {
            inst->pszBindRuleset = (uchar *)es_str2cstr(pvals[i].val.d.estr, NULL);
        } else if (!strcmp(inppblk.descr[i].name, "main")) {
            inst->bMain = (int)pvals[i].val.d.n;
        } else {
            DBGPRINTF(
                "program error, non-handled "
                "param '%s'\n",
                inppblk.descr[i].name);
        }
    }
finalize_it:
    CODE_STD_FINALIZERnewInpInst if (pvals != NULL) cnfparamvalsDestruct(pvals, &inppblk);
ENDnewInpInst


BEGINisCompatibleWithFeature
    CODESTARTisCompatibleWithFeature;
    if (eFeat == sFEATURENonCancelInputTermination) iRet = RS_RET_OK;
ENDisCompatibleWithFeature


BEGINqueryEtryPt
    CODESTARTqueryEtryPt;
    CODEqueryEtryPt_STD_IMOD_QUERIES;
    CODEqueryEtryPt_STD_CONF2_QUERIES;
    CODEqueryEtryPt_STD_CONF2_setModCnf_QUERIES;
    CODEqueryEtryPt_STD_CONF2_IMOD_QUERIES;
    CODEqueryEtryPt_IsCompatibleWithFeature_IF_OMOD_QUERIES;
ENDqueryEtryPt


static inline void std_checkRuleset_genErrMsg(__attribute__((unused)) modConfData_t *modConf, instanceConf_t *inst) {
    LogError(0, NO_ERRCODE,
             "imjournal: ruleset '%s' not found - "
             "using default ruleset instead",
             inst->pszBindRuleset);
}

BEGINmodInit()
    CODESTARTmodInit;
    *ipIFVersProvided = CURR_MOD_IF_VERSION; /* we only support the current interface specification */
    CODEmodInit_QueryRegCFSLineHdlr CHKiRet(objUse(datetime, CORE_COMPONENT));
    CHKiRet(objUse(glbl, CORE_COMPONENT));
    CHKiRet(objUse(parser, CORE_COMPONENT));
    CHKiRet(objUse(prop, CORE_COMPONENT));
    CHKiRet(objUse(net, CORE_COMPONENT));
    CHKiRet(objUse(statsobj, CORE_COMPONENT));
    CHKiRet(objUse(ruleset, CORE_COMPONENT));

    /* we need to create the inputName property (only once during our lifetime) */
    CHKiRet(prop.CreateStringProp(&pInputName, UCHAR_CONSTANT("imjournal"), sizeof("imjournal") - 1));
    CHKiRet(prop.CreateStringProp(&pLocalHostIP, UCHAR_CONSTANT("127.0.0.1"), sizeof("127.0.0.1") - 1));

    CHKiRet(omsdRegCFSLineHdlr((uchar *)"imjournalpersiststateinterval", 0, eCmdHdlrInt, NULL,
                               &cs.iPersistStateInterval, STD_LOADABLE_MODULE_ID));
    CHKiRet(omsdRegCFSLineHdlr((uchar *)"imjournalratelimitinterval", 0, eCmdHdlrInt, NULL, &cs.ratelimitInterval,
                               STD_LOADABLE_MODULE_ID));
    CHKiRet(omsdRegCFSLineHdlr((uchar *)"imjournalratelimitburst", 0, eCmdHdlrInt, NULL, &cs.ratelimitBurst,
                               STD_LOADABLE_MODULE_ID));
    CHKiRet(omsdRegCFSLineHdlr((uchar *)"imjournalstatefile", 0, eCmdHdlrGetWord, NULL, &cs.stateFile,
                               STD_LOADABLE_MODULE_ID));
    CHKiRet(omsdRegCFSLineHdlr((uchar *)"imjournalignorepreviousmessages", 0, eCmdHdlrBinary, NULL, &cs.bIgnorePrevious,
                               STD_LOADABLE_MODULE_ID));
    CHKiRet(omsdRegCFSLineHdlr((uchar *)"imjournaldefaultseverity", 0, eCmdHdlrSeverity, NULL, &cs.iDfltSeverity,
                               STD_LOADABLE_MODULE_ID));
    CHKiRet(omsdRegCFSLineHdlr((uchar *)"imjournaldefaultfacility", 0, eCmdHdlrCustomHandler, facilityHdlr,
                               &cs.iDfltFacility, STD_LOADABLE_MODULE_ID));
    CHKiRet(omsdRegCFSLineHdlr((uchar *)"imjournalusepidfromsystem", 0, eCmdHdlrBinary, NULL, &cs.bUseJnlPID,
                               STD_LOADABLE_MODULE_ID));
ENDmodInit
/* vim:set ai:
 */
