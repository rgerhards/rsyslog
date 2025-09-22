/* mmsnarewinevtsec.c
 * Message modification module that parses NXLog SNARE formatted Windows
 * Security events and exposes structured content under the $!snare subtree.
 *
 * Copyright (C) 2025 by Rainer Gerhards and Adiscon GmbH.
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

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <json.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "rsyslog.h"
#include "conf.h"
#include "syslogd-types.h"
#include "template.h"
#include "module-template.h"
#include "errmsg.h"
#include "cfsysline.h"
#include "parserif.h"
#include "dirty.h"
#include "datetime.h"
#include "statsobj.h"
#include "msg.h"
#include "timezones.h"

#include "mmsnarewinevtsec.h"

MODULE_TYPE_OUTPUT;
MODULE_TYPE_NOKEEP;
MODULE_CNFNAME("mmsnarewinevtsec")

/** @file
 *  @brief mmsnarewinevtsec parses NXLog SNARE formatted Windows Security
 *         events and stores the parsed result under the $!snare JSON subtree.
 */

/** @brief mmsnarewinevtsec action parameters.
 *  @param mode                 Controls field validation strictness. Either
 *                              "lenient" (default) or "strict".
 *  @param set_hostname_from_hdr When "on" (default), copy the syslog header
 *                              hostname into $!snare!hostname when not present.
 *  @param parse_time           When "on", datetime_str is converted to
 *                              RFC3339 using default_tz and emitted as
 *                              datetime_rfc3339.
 *  @param default_tz           IANA timezone name or numeric offset used
 *                              together with parse_time. Defaults to "UTC".
 *  @param max_label_len        Maximum label length accepted inside the
 *                              expanded_info parser. Defaults to 64.
 *  @param list_labels          Comma separated list of additional labels whose
 *                              values should be split into arrays.
 *  @param debug_raw            When enabled (only meaningful on debug builds),
 *                              include the unparsed expanded string under
 *                              extended_info.raw.
 */
static struct cnfparamdescr actpdescr[] = {
    {"mode", eCmdHdlrString, 0},       {"set_hostname_from_hdr", eCmdHdlrBinary, 0},
    {"parse_time", eCmdHdlrBinary, 0}, {"default_tz", eCmdHdlrString, 0},
    {"max_label_len", eCmdHdlrInt, 0}, {"list_labels", eCmdHdlrString, 0},
    {"debug_raw", eCmdHdlrBinary, 0}};
static struct cnfparamblk actpblk = {CNFPARAMBLK_VERSION, sizeof(actpdescr) / sizeof(struct cnfparamdescr), actpdescr};

/* static data */

/* internal structures */
DEF_OMOD_STATIC_DATA;
DEFobjCurrIf(datetime) DEFobjCurrIf(statsobj)

    typedef enum {
        SNARE_MODE_LENIENT = 0,
        SNARE_MODE_STRICT = 1
    } snare_mode_t;

typedef struct {
    const char *ptr;
    size_t len;
} strfrag_t;

typedef struct {
    snare_mode_t mode;
    sbool set_hostname_from_hdr;
    sbool parse_time;
    sbool debug_raw;
    char *default_tz;
    int max_label_len;
    char **list_labels;
    size_t list_label_count;
    sbool tz_offset_valid;
    int tz_offset_minutes;
} instanceData;

typedef struct wrkrInstanceData {
    instanceData *pData;
} wrkrInstanceData_t;

struct modConfData_s {
    rsconf_t *pConf;
};
static modConfData_t *loadModConf = NULL;
static modConfData_t *runModConf = NULL;

STATSCOUNTER_DEF(ctrParsedOk, mutCtrParsedOk);
STATSCOUNTER_DEF(ctrBadPrefix, mutCtrBadPrefix);
STATSCOUNTER_DEF(ctrTooFewFields, mutCtrTooFewFields);
STATSCOUNTER_DEF(ctrTimeParseFail, mutCtrTimeParseFail);
STATSCOUNTER_DEF(ctrExpandedParseOk, mutCtrExpandedParseOk);
STATSCOUNTER_DEF(ctrExpandedParseFail, mutCtrExpandedParseFail);
static statsobj_t *snareStats = NULL;

static inline void to_lowercase(char *s) {
    if (s == NULL) return;
    for (; *s != '\0'; ++s) *s = (char)tolower((unsigned char)*s);
}

static inline void free_list_labels(instanceData *pData) {
    if (pData->list_labels != NULL) {
        for (size_t i = 0; i < pData->list_label_count; ++i) free(pData->list_labels[i]);
        free(pData->list_labels);
        pData->list_labels = NULL;
    }
    pData->list_label_count = 0;
}

static rsRetVal add_list_label(instanceData *pData, const char *start, size_t len) {
    DEFiRet;
    char *label = NULL;
    size_t trimmed_len = len;

    while (trimmed_len > 0 && isspace((unsigned char)start[0])) {
        ++start;
        --trimmed_len;
    }
    while (trimmed_len > 0 && isspace((unsigned char)start[trimmed_len - 1])) --trimmed_len;
    if (trimmed_len == 0) RETiRet;

    for (size_t i = 0; i < pData->list_label_count; ++i) {
        if (strncmp(pData->list_labels[i], start, trimmed_len) == 0 && pData->list_labels[i][trimmed_len] == '\0') {
            RETiRet;
        }
    }

    CHKmalloc(label = malloc(trimmed_len + 1));
    memcpy(label, start, trimmed_len);
    label[trimmed_len] = '\0';

    char **newarr = realloc(pData->list_labels, (pData->list_label_count + 1) * sizeof(char *));
    if (newarr == NULL) {
        free(label);
        ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
    }
    pData->list_labels = newarr;
    pData->list_labels[pData->list_label_count++] = label;

finalize_it:
    RETiRet;
}

static void setInstParamDefaults(instanceData *pData) {
    pData->mode = SNARE_MODE_LENIENT;
    pData->set_hostname_from_hdr = 1;
    pData->parse_time = 0;
    pData->debug_raw = 0;
    pData->default_tz = strdup("UTC");
    pData->max_label_len = 64;
    pData->list_labels = NULL;
    pData->list_label_count = 0;
    pData->tz_offset_valid = 1;
    pData->tz_offset_minutes = 0;
    if (pData->default_tz == NULL) pData->tz_offset_valid = 0;
    if (add_list_label(pData, "Privileges", strlen("Privileges")) != RS_RET_OK) {
        free_list_labels(pData);
    }
}

static inline sbool is_list_label(const instanceData *pData, const char *label) {
    for (size_t i = 0; i < pData->list_label_count; ++i) {
        if (!strcmp(pData->list_labels[i], label)) return 1;
    }
    return 0;
}

static sbool strfrag_case_equals(const strfrag_t *frag, const char *cmp) {
    size_t cmplen = strlen(cmp);
    if (frag->len != cmplen) return 0;
    for (size_t i = 0; i < cmplen; ++i) {
        if (tolower((unsigned char)frag->ptr[i]) != tolower((unsigned char)cmp[i])) return 0;
    }
    return 1;
}

static sbool parse_int64(const strfrag_t *frag, long long *val) {
    if (frag->len == 0 || frag->len >= 64) return 0;
    char buf[64];
    memcpy(buf, frag->ptr, frag->len);
    buf[frag->len] = '\0';
    char *end = NULL;
    errno = 0;
    long long tmp = strtoll(buf, &end, 10);
    if (errno != 0 || end == buf || *end != '\0') return 0;
    *val = tmp;
    return 1;
}

static sbool parse_uint64(const strfrag_t *frag, unsigned long long *val) {
    if (frag->len == 0 || frag->len >= 64) return 0;
    char buf[64];
    memcpy(buf, frag->ptr, frag->len);
    buf[frag->len] = '\0';
    char *end = NULL;
    errno = 0;
    unsigned long long tmp = strtoull(buf, &end, 10);
    if (errno != 0 || end == buf || *end != '\0') return 0;
    *val = tmp;
    return 1;
}

static sbool parse_numeric_tz(const char *tz, int *offset_minutes) {
    if (tz == NULL) return 0;
    if (tz[0] == '\0') return 0;
    if (!strcmp(tz, "UTC") || !strcmp(tz, "utc") || !strcmp(tz, "Z") || !strcmp(tz, "z")) {
        *offset_minutes = 0;
        return 1;
    }

    int sign = 1;
    size_t pos = 0;
    if (tz[0] == '+') {
        sign = 1;
        pos = 1;
    } else if (tz[0] == '-') {
        sign = -1;
        pos = 1;
    }

    if (!isdigit((unsigned char)tz[pos])) return 0;

    int hour = 0;
    int minute = 0;
    if (isdigit((unsigned char)tz[pos]) && isdigit((unsigned char)tz[pos + 1])) {
        hour = (tz[pos] - '0') * 10 + (tz[pos + 1] - '0');
        pos += 2;
    } else {
        return 0;
    }

    if (tz[pos] == ':') {
        ++pos;
        if (!isdigit((unsigned char)tz[pos]) || !isdigit((unsigned char)tz[pos + 1])) return 0;
        minute = (tz[pos] - '0') * 10 + (tz[pos + 1] - '0');
        pos += 2;
    } else if (isdigit((unsigned char)tz[pos]) && isdigit((unsigned char)tz[pos + 1])) {
        minute = (tz[pos] - '0') * 10 + (tz[pos + 1] - '0');
        pos += 2;
    }

    if (tz[pos] != '\0') return 0;
    if (hour > 23 || minute > 59) return 0;

    *offset_minutes = sign * (hour * 60 + minute);
    return 1;
}

static void set_timezone_offset(instanceData *pData) {
    pData->tz_offset_valid = 0;
    pData->tz_offset_minutes = 0;
    if (pData->default_tz == NULL) return;

    if (parse_numeric_tz(pData->default_tz, &pData->tz_offset_minutes)) {
        pData->tz_offset_valid = 1;
        return;
    }

    if (runModConf != NULL && runModConf->pConf != NULL) {
        tzinfo_t *tzinfo = glblFindTimezone(runModConf->pConf, pData->default_tz);
        if (tzinfo != NULL) {
            int minutes = tzinfo->offsHour * 60 + tzinfo->offsMin;
            if (tzinfo->offsMode == '-') minutes = -minutes;
            pData->tz_offset_minutes = minutes;
            pData->tz_offset_valid = 1;
            return;
        }
    }

    if (loadModConf != NULL && loadModConf->pConf != NULL) {
        tzinfo_t *tzinfo = glblFindTimezone(loadModConf->pConf, pData->default_tz);
        if (tzinfo != NULL) {
            int minutes = tzinfo->offsHour * 60 + tzinfo->offsMin;
            if (tzinfo->offsMode == '-') minutes = -minutes;
            pData->tz_offset_minutes = minutes;
            pData->tz_offset_valid = 1;
            return;
        }
    }
}

typedef struct {
    char *buf;
    size_t len;
    size_t cap;
} strbuilder_t;

static void sb_destroy(strbuilder_t *sb) {
    free(sb->buf);
    sb->buf = NULL;
    sb->len = sb->cap = 0;
}

static rsRetVal sb_append(strbuilder_t *sb, const strfrag_t *frag) {
    DEFiRet;
    if (frag->len == 0) RETiRet;
    size_t need = sb->len + (sb->len ? 1 : 0) + frag->len + 1;
    if (need > sb->cap) {
        size_t newcap = sb->cap == 0 ? 64 : sb->cap;
        while (newcap < need) newcap *= 2;
        char *tmp = realloc(sb->buf, newcap);
        if (tmp == NULL) ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
        sb->buf = tmp;
        sb->cap = newcap;
    }
    if (sb->len) sb->buf[sb->len++] = ' ';
    memcpy(sb->buf + sb->len, frag->ptr, frag->len);
    sb->len += frag->len;
    sb->buf[sb->len] = '\0';
finalize_it:
    RETiRet;
}

typedef struct {
    const char *ptr;
    size_t len;
} token_t;

static rsRetVal tokenize_expanded(const char *str, size_t len, token_t **out_tokens, size_t *out_count) {
    DEFiRet;
    token_t *tokens = NULL;
    size_t count = 0;
    size_t cap = 0;
    size_t i = 0;
    sbool in_token = 0;
    size_t start = 0;

    while (i < len) {
        if (str[i] == ' ') {
            size_t j = i;
            while (j < len && str[j] == ' ') ++j;
            size_t spaces = j - i;
            if (spaces >= 2) {
                if (in_token) {
                    if (count == cap) {
                        size_t newcap = cap == 0 ? 16 : cap * 2;
                        token_t *tmp = realloc(tokens, newcap * sizeof(token_t));
                        if (tmp == NULL) ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
                        tokens = tmp;
                        cap = newcap;
                    }
                    tokens[count].ptr = str + start;
                    tokens[count].len = i - start;
                    ++count;
                    in_token = 0;
                }
                i = j;
                continue;
            } else {
                if (!in_token) {
                    start = i;
                    in_token = 1;
                }
                i = j;
                continue;
            }
        } else {
            if (!in_token) {
                start = i;
                in_token = 1;
            }
            ++i;
        }
    }

    if (in_token) {
        if (count == cap) {
            size_t newcap = cap == 0 ? 16 : cap * 2;
            token_t *tmp = realloc(tokens, newcap * sizeof(token_t));
            if (tmp == NULL) ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
            tokens = tmp;
            cap = newcap;
        }
        tokens[count].ptr = str + start;
        tokens[count].len = len - start;
        ++count;
    }

    *out_tokens = tokens;
    *out_count = count;
    RETiRet;
finalize_it:
    if (iRet != RS_RET_OK) free(tokens);
    RETiRet;
}

static sbool is_label_token(const token_t *tok, int max_len) {
    if (tok->len < 2) return 0;
    if (tok->ptr[tok->len - 1] != ':') return 0;
    size_t base_len = tok->len - 1;
    if (base_len > (size_t)max_len) return 0;
    for (size_t i = 0; i < base_len; ++i) {
        unsigned char c = (unsigned char)tok->ptr[i];
        if (!(isalnum(c) || c == ' ' || c == '(' || c == ')' || c == '-' || c == '/' || c == '%')) return 0;
    }
    return 1;
}

static rsRetVal split_list_value(const char *ptr, size_t len, struct json_object *array) {
    DEFiRet;
    size_t i = 0;
    sbool in_token = 0;
    size_t start = 0;
    while (i < len) {
        if (ptr[i] == ' ') {
            size_t j = i;
            while (j < len && ptr[j] == ' ') ++j;
            size_t spaces = j - i;
            if (spaces >= 2) {
                if (in_token) {
                    json_object_array_add(array, json_object_new_string_len(ptr + start, (int)(i - start)));
                    in_token = 0;
                }
                i = j;
                continue;
            } else {
                if (!in_token) {
                    start = i;
                    in_token = 1;
                }
                i = j;
                continue;
            }
        } else {
            if (!in_token) {
                start = i;
                in_token = 1;
            }
            ++i;
        }
    }
    if (in_token) json_object_array_add(array, json_object_new_string_len(ptr + start, (int)(len - start)));
    RETiRet;
}

static rsRetVal parse_extended_info(const instanceData *pData,
                                    const strfrag_t *expanded,
                                    struct json_object **extended,
                                    sbool *parse_ok) {
    DEFiRet;
    token_t *tokens = NULL;
    size_t token_count = 0;
    size_t labels = 0;
    struct json_object *ext = NULL;
    struct json_object *current_section = NULL;
    struct json_object *root = NULL;
    strbuilder_t intro = {.buf = NULL, .len = 0, .cap = 0};
    sbool have_section = 0;

    *parse_ok = 0;

    if (expanded->len == 0) {
        ext = json_object_new_object();
        if (ext == NULL) ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
        json_object_object_add(ext, "parse_ok", json_object_new_boolean(0));
        goto finalize_success;
    }

    CHKiRet(tokenize_expanded(expanded->ptr, expanded->len, &tokens, &token_count));

    ext = json_object_new_object();
    if (ext == NULL) ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);

    for (size_t i = 0; i < token_count;) {
        if (is_label_token(&tokens[i], pData->max_label_len)) {
            ++labels;
            size_t label_len = tokens[i].len - 1;
            char keybuf[128];
            if (label_len >= sizeof(keybuf)) label_len = sizeof(keybuf) - 1;
            memcpy(keybuf, tokens[i].ptr, label_len);
            keybuf[label_len] = '\0';

            if (i + 1 < token_count && !is_label_token(&tokens[i + 1], pData->max_label_len)) {
                struct json_object *target;
                if (current_section != NULL)
                    target = current_section;
                else {
                    if (root == NULL) {
                        root = json_object_new_object();
                        if (root == NULL) ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
                        json_object_object_add(ext, "root", root);
                    }
                    target = root;
                }

                struct json_object *val;
                if (is_list_label(pData, keybuf)) {
                    val = json_object_new_array();
                    if (val == NULL) ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
                    CHKiRet(split_list_value(tokens[i + 1].ptr, tokens[i + 1].len, val));
                } else {
                    strfrag_t value_frag = {tokens[i + 1].ptr, tokens[i + 1].len};
                    val = json_new_string_or_int(&value_frag);
                    if (val == NULL) ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
                }
                json_object_object_add(target, keybuf, val);
                i += 2;
            } else {
                struct json_object *section;
                if (!json_object_object_get_ex(ext, keybuf, &section)) {
                    section = json_object_new_object();
                    if (section == NULL) ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
                    json_object_object_add(ext, keybuf, section);
                }
                current_section = section;
                have_section = 1;
                ++i;
            }
        } else {
            if (!have_section && tokens[i].len > 0) {
                strfrag_t frag = {tokens[i].ptr, tokens[i].len};
                CHKiRet(sb_append(&intro, &frag));
            }
            ++i;
        }
    }

    if (intro.len > 0) {
        struct json_object *introVal = json_object_new_string_len(intro.buf, (int)intro.len);
        if (introVal == NULL) ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
        json_object_object_add(ext, "intro", introVal);
    }

    if (labels >= 2) {
        json_object_object_add(ext, "parse_ok", json_object_new_boolean(1));
        *parse_ok = 1;
    } else {
        json_object_put(ext);
        ext = json_object_new_object();
        if (ext == NULL) ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
        json_object_object_add(ext, "parse_ok", json_object_new_boolean(0));
        *parse_ok = 0;
    }

finalize_success:
    *extended = ext;

finalize_it:
    free(tokens);
    sb_destroy(&intro);
    RETiRet;
}

static int month_from_str(const char *s) {
    static const char *months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    for (int i = 0; i < 12; ++i) {
        if (!strcasecmp(s, months[i])) return i + 1;
    }
    return 0;
}

static sbool format_datetime_rfc3339(const instanceData *pData,
                                     const strfrag_t *datetime_str,
                                     char *buf,
                                     size_t bufsz) {
    if (!pData->parse_time || !pData->tz_offset_valid) return 0;
    if (datetime_str->len == 0 || datetime_str->len >= 128) return 0;

    char tmp[128];
    memcpy(tmp, datetime_str->ptr, datetime_str->len);
    tmp[datetime_str->len] = '\0';

    char weekday[8];
    char month[8];
    int day, hour, minute, second, year;

    if (sscanf(tmp, "%7s %7s %d %d:%d:%d %d", weekday, month, &day, &hour, &minute, &second, &year) != 7) return 0;
    int month_idx = month_from_str(month);
    if (month_idx == 0) return 0;
    if (day < 1 || day > 31 || hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 60)
        return 0;

    struct syslogTime ts;
    memset(&ts, 0, sizeof(ts));
    ts.timeType = TIME_TYPE_RFC5424;
    ts.year = (short)year;
    ts.month = (intTiny)month_idx;
    ts.day = (intTiny)day;
    ts.hour = (intTiny)hour;
    ts.minute = (intTiny)minute;
    ts.second = (intTiny)second;
    ts.secfracPrecision = 0;
    ts.secfrac = 0;
    ts.inUTC = 0;

    int offset = pData->tz_offset_minutes;
    if (offset < 0) {
        ts.OffsetMode = '-';
        offset = -offset;
    } else {
        ts.OffsetMode = '+';
    }
    ts.OffsetHour = (intTiny)(offset / 60);
    ts.OffsetMinute = (intTiny)(offset % 60);

    if (datetime.formatTimestamp3339(&ts, buf) <= 0) return 0;
    return 1;
}

static struct json_object *json_add_string(struct json_object *parent, const char *key, const strfrag_t *frag) {
    struct json_object *val = json_object_new_string_len(frag->ptr, (int)frag->len);
    if (val == NULL) return NULL;
    json_object_object_add(parent, key, val);
    return val;
}

static struct json_object *json_new_string_or_int(const strfrag_t *frag) {
    long long val;
    if (parse_int64(frag, &val)) {
        return json_object_new_int64(val);
    }
    return json_object_new_string_len(frag->ptr, (int)frag->len);
}

#define SNARE_MAX_FIELDS 32

enum snare_field_index {
    FIELD_CRITICALITY = 0,
    FIELD_LOG_NAME,
    FIELD_SNARE_COUNTER,
    FIELD_DATETIME,
    FIELD_EVENT_ID,
    FIELD_SOURCE_NAME,
    FIELD_USER_NAME,
    FIELD_SID_TYPE,
    FIELD_EVENT_AUDIT_TYPE,
    FIELD_COMPUTER_NAME,
    FIELD_CATEGORY_STRING,
    FIELD_DATA_STRING,
    FIELD_EXPANDED_STRING,
    FIELD_EVENT_LOG_COUNTER,
    FIELD_COUNT_EXPECTED
};

static rsRetVal parse_message(wrkrInstanceData_t *pWrkrData, smsg_t *pMsg) {
    DEFiRet;
    instanceData *pData = pWrkrData->pData;
    const char *payload = (const char *)getMSG(pMsg);
    if (payload == NULL) RETiRet;

    size_t payload_len = strlen(payload);
    const char *tag = strstr(payload, MMSNAREWINEVTSEC_FORMAT_TAG);
    if (tag == NULL) {
        STATSCOUNTER_INC(ctrBadPrefix, mutCtrBadPrefix);
        RETiRet;
    }

    size_t tag_len = strlen(MMSNAREWINEVTSEC_FORMAT_TAG);
    if ((size_t)(tag - payload) + tag_len >= payload_len) {
        STATSCOUNTER_INC(ctrTooFewFields, mutCtrTooFewFields);
        RETiRet;
    }
    char delim = tag[tag_len];
    if (delim == '\0') {
        STATSCOUNTER_INC(ctrTooFewFields, mutCtrTooFewFields);
        RETiRet;
    }

    sbool is_pure = 0;
    strfrag_t host_field = {NULL, 0};
    if (tag != payload) {
        if (tag > payload && tag[-1] == delim) {
            host_field.ptr = payload;
            host_field.len = (size_t)(tag - payload - 1);
            while (host_field.len > 0 && isspace((unsigned char)host_field.ptr[0])) {
                ++host_field.ptr;
                --host_field.len;
            }
            while (host_field.len > 0 && isspace((unsigned char)host_field.ptr[host_field.len - 1])) --host_field.len;
            is_pure = 1;
        } else {
            STATSCOUNTER_INC(ctrBadPrefix, mutCtrBadPrefix);
            RETiRet;
        }
    }

    const char *field_cursor = tag + tag_len + 1;
    size_t remaining = payload_len - (size_t)(field_cursor - payload);
    strfrag_t fields[SNARE_MAX_FIELDS];
    size_t field_count = 0;

    while (remaining > 0 && field_count < SNARE_MAX_FIELDS) {
        const char *next = memchr(field_cursor, delim, remaining);
        if (next == NULL) {
            fields[field_count].ptr = field_cursor;
            fields[field_count].len = remaining;
            ++field_count;
            break;
        }
        fields[field_count].ptr = field_cursor;
        fields[field_count].len = (size_t)(next - field_cursor);
        ++field_count;
        remaining -= (size_t)(next - field_cursor) + 1;
        field_cursor = next + 1;
    }

    size_t expected_fields = MMSNAREWINEVTSEC_EXPECTED_WRAPPED_FIELDS;
    if (field_count < expected_fields) {
        STATSCOUNTER_INC(ctrTooFewFields, mutCtrTooFewFields);
        RETiRet;
    }

    if (pData->mode == SNARE_MODE_STRICT) {
        size_t required_fields = expected_fields;
        if (is_pure) required_fields = MMSNAREWINEVTSEC_EXPECTED_PURE_FIELDS - 1;
        if (field_count != required_fields) {
            STATSCOUNTER_INC(ctrTooFewFields, mutCtrTooFewFields);
            RETiRet;
        }
    }

    struct json_object *snare = json_object_new_object();
    if (snare == NULL) ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);

    if (is_pure) {
        json_object_object_add(snare, "hostname", json_object_new_string_len(host_field.ptr, (int)host_field.len));
    } else if (pData->set_hostname_from_hdr) {
        const char *hdrHost = getHOSTNAME(pMsg);
        if (hdrHost != NULL && hdrHost[0] != '\0')
            json_object_object_add(snare, "hostname", json_object_new_string(hdrHost));
    }

    json_object_object_add(snare, "format_tag", json_object_new_string(MMSNAREWINEVTSEC_FORMAT_TAG));

    long long criticality;
    if (parse_int64(&fields[FIELD_CRITICALITY], &criticality))
        json_object_object_add(snare, "criticality", json_object_new_int64(criticality));
    else
        json_add_string(snare, "criticality", &fields[FIELD_CRITICALITY]);

    json_add_string(snare, "log_name", &fields[FIELD_LOG_NAME]);

    unsigned long long snare_counter;
    if (parse_uint64(&fields[FIELD_SNARE_COUNTER], &snare_counter))
        json_object_object_add(snare, "snare_event_counter", json_object_new_int64((long long)snare_counter));
    else
        json_add_string(snare, "snare_event_counter", &fields[FIELD_SNARE_COUNTER]);

    json_add_string(snare, "datetime_str", &fields[FIELD_DATETIME]);

    char tsbuf[64];
    if (format_datetime_rfc3339(pData, &fields[FIELD_DATETIME], tsbuf, sizeof(tsbuf))) {
        json_object_object_add(snare, "datetime_rfc3339", json_object_new_string(tsbuf));
    } else if (pData->parse_time && fields[FIELD_DATETIME].len > 0) {
        STATSCOUNTER_INC(ctrTimeParseFail, mutCtrTimeParseFail);
    }

    if (!strfrag_case_equals(&fields[FIELD_EVENT_ID], "N/A")) {
        long long event_id;
        if (parse_int64(&fields[FIELD_EVENT_ID], &event_id))
            json_object_object_add(snare, "event_id", json_object_new_int64(event_id));
        else
            json_add_string(snare, "event_id", &fields[FIELD_EVENT_ID]);
    }

    json_add_string(snare, "source_name", &fields[FIELD_SOURCE_NAME]);
    json_add_string(snare, "user_name", &fields[FIELD_USER_NAME]);
    json_add_string(snare, "sid_type", &fields[FIELD_SID_TYPE]);
    json_add_string(snare, "event_audit_type", &fields[FIELD_EVENT_AUDIT_TYPE]);
    json_add_string(snare, "computer_name", &fields[FIELD_COMPUTER_NAME]);
    json_add_string(snare, "category_string", &fields[FIELD_CATEGORY_STRING]);
    json_add_string(snare, "data_string", &fields[FIELD_DATA_STRING]);
    json_add_string(snare, "expanded_string", &fields[FIELD_EXPANDED_STRING]);

    if (!strfrag_case_equals(&fields[FIELD_EVENT_LOG_COUNTER], "N/A")) {
        long long counter;
        if (parse_int64(&fields[FIELD_EVENT_LOG_COUNTER], &counter))
            json_object_object_add(snare, "event_log_counter", json_object_new_int64(counter));
        else
            json_add_string(snare, "event_log_counter", &fields[FIELD_EVENT_LOG_COUNTER]);
    }

    struct json_object *extended = NULL;
    sbool ext_ok = 0;
    CHKiRet(parse_extended_info(pData, &fields[FIELD_EXPANDED_STRING], &extended, &ext_ok));

#ifdef RSYSLOG_DEBUG
    if (pData->debug_raw) {
        json_object_object_add(
            extended, "raw",
            json_object_new_string_len(fields[FIELD_EXPANDED_STRING].ptr, (int)fields[FIELD_EXPANDED_STRING].len));
    }
#endif

    if (ext_ok)
        STATSCOUNTER_INC(ctrExpandedParseOk, mutCtrExpandedParseOk);
    else
        STATSCOUNTER_INC(ctrExpandedParseFail, mutCtrExpandedParseFail);

    json_object_object_add(snare, "extended_info", extended);

    CHKiRet(msgAddJSON(pMsg, (uchar *)"!snare", snare, 0, 0));
    STATSCOUNTER_INC(ctrParsedOk, mutCtrParsedOk);

finalize_it:
    if (iRet != RS_RET_OK && snare != NULL) json_object_put(snare);
    RETiRet;
}

BEGINdoAction_NoStrings
    smsg_t **ppMsg = (smsg_t **)pMsgData;
    smsg_t *pMsg = ppMsg[0];
    int bSuccess = 0;
    CODESTARTdoAction;

    CHKiRet(parse_message(pWrkrData, pMsg));
    bSuccess = 1;

finalize_it:
    MsgSetParseSuccess(pMsg, bSuccess);
ENDdoAction

BEGINbeginCnfLoad
    CODESTARTbeginCnfLoad;
    loadModConf = pModConf;
    pModConf->pConf = pConf;
ENDbeginCnfLoad

BEGINendCnfLoad
    CODESTARTendCnfLoad;
    loadModConf = NULL;
ENDendCnfLoad

BEGINactivateCnf
    CODESTARTactivateCnf;
    runModConf = pModConf;
ENDactivateCnf

BEGINcreateInstance
    CODESTARTcreateInstance;
    setInstParamDefaults(pData);
finalize_it:
ENDcreateInstance

BEGINfreeInstance
    CODESTARTfreeInstance;
    if (pData != NULL) {
        free(pData->default_tz);
        free_list_labels(pData);
    }
ENDfreeInstance

BEGINcreateWrkrInstance
    CODESTARTcreateWrkrInstance;
ENDcreateWrkrInstance

BEGINfreeWrkrInstance
    CODESTARTfreeWrkrInstance;
ENDfreeWrkrInstance

BEGINisCompatibleWithFeature
    CODESTARTisCompatibleWithFeature;
ENDisCompatibleWithFeature

BEGINdbgPrintInstInfo
    CODESTARTdbgPrintInstInfo;
    DBGPRINTF("mmsnarewinevtsec\n");
ENDdbgPrintInstInfo

BEGINtryResume
    CODESTARTtryResume;
ENDtryResume

BEGINnewActInst
    struct cnfparamvals *pvals;
    instanceData *pData = NULL;
    int i;
    CODESTARTnewActInst;

    if ((pvals = nvlstGetParams(lst, &actpblk, NULL)) == NULL) {
        ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
    }

    CHKiRet(OMSRsetEntry(*ppOMSR, 0, NULL, OMSR_TPL_AS_MSG));
    CHKiRet(createInstance(&pData));

    for (i = 0; i < actpblk.nParams; ++i) {
        if (!pvals[i].bUsed) continue;
        if (!strcmp(actpblk.descr[i].name, "mode")) {
            char *val = es_str2cstr(pvals[i].val.d.estr, NULL);
            if (val == NULL) ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
            to_lowercase(val);
            if (!strcmp(val, "strict"))
                pData->mode = SNARE_MODE_STRICT;
            else if (!strcmp(val, "lenient"))
                pData->mode = SNARE_MODE_LENIENT;
            else {
                parser_errmsg("mmsnarewinevtsec: invalid mode '%s'", val);
                free(val);
                ABORT_FINALIZE(RS_RET_INVALID_VALUE);
            }
            free(val);
        } else if (!strcmp(actpblk.descr[i].name, "set_hostname_from_hdr")) {
            pData->set_hostname_from_hdr = (int)pvals[i].val.d.n;
        } else if (!strcmp(actpblk.descr[i].name, "parse_time")) {
            pData->parse_time = (int)pvals[i].val.d.n;
        } else if (!strcmp(actpblk.descr[i].name, "default_tz")) {
            free(pData->default_tz);
            pData->default_tz = es_str2cstr(pvals[i].val.d.estr, NULL);
            if (pData->default_tz == NULL) ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
        } else if (!strcmp(actpblk.descr[i].name, "max_label_len")) {
            int len = (int)pvals[i].val.d.n;
            if (len <= 0) {
                parser_errmsg("mmsnarewinevtsec: max_label_len must be positive");
                ABORT_FINALIZE(RS_RET_INVALID_VALUE);
            }
            pData->max_label_len = len;
        } else if (!strcmp(actpblk.descr[i].name, "list_labels")) {
            char *list = es_str2cstr(pvals[i].val.d.estr, NULL);
            if (list == NULL) ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
            char *cur = list;
            while (*cur != '\0') {
                char *comma = strchr(cur, ',');
                if (comma != NULL) *comma = '\0';
                size_t len = strlen(cur);
                if (len > 0) CHKiRet(add_list_label(pData, cur, len));
                if (comma == NULL) break;
                cur = comma + 1;
            }
            free(list);
        } else if (!strcmp(actpblk.descr[i].name, "debug_raw")) {
            pData->debug_raw = (int)pvals[i].val.d.n;
        }
    }

    set_timezone_offset(pData);

    CODE_STD_FINALIZERnewActInst;
    cnfparamvalsDestruct(pvals, &actpblk);
ENDnewActInst

BEGINmodInit()
    CODESTARTmodInit;
    *ipIFVersProvided = CURR_MOD_IF_VERSION;
    CODEmodInit_QueryRegCFSLineHdlr CHKiRet(objUse(statsobj, CORE_COMPONENT));
    CHKiRet(objUse(datetime, CORE_COMPONENT));

    CHKiRet(statsobj.Construct(&snareStats));
    CHKiRet(statsobj.SetName(snareStats, (uchar *)"mmsnarewinevtsec"));
    CHKiRet(statsobj.SetOrigin(snareStats, (uchar *)"mmsnarewinevtsec"));

    STATSCOUNTER_INIT(ctrParsedOk, mutCtrParsedOk);
    CHKiRet(statsobj.AddCounter(snareStats, (uchar *)"parsed_ok", ctrType_IntCtr, CTR_FLAG_RESETTABLE, &ctrParsedOk));
    STATSCOUNTER_INIT(ctrBadPrefix, mutCtrBadPrefix);
    CHKiRet(statsobj.AddCounter(snareStats, (uchar *)"bad_prefix", ctrType_IntCtr, CTR_FLAG_RESETTABLE, &ctrBadPrefix));
    STATSCOUNTER_INIT(ctrTooFewFields, mutCtrTooFewFields);
    CHKiRet(statsobj.AddCounter(snareStats, (uchar *)"too_few_fields", ctrType_IntCtr, CTR_FLAG_RESETTABLE,
                                &ctrTooFewFields));
    STATSCOUNTER_INIT(ctrTimeParseFail, mutCtrTimeParseFail);
    CHKiRet(statsobj.AddCounter(snareStats, (uchar *)"time_parse_fail", ctrType_IntCtr, CTR_FLAG_RESETTABLE,
                                &ctrTimeParseFail));
    STATSCOUNTER_INIT(ctrExpandedParseOk, mutCtrExpandedParseOk);
    CHKiRet(statsobj.AddCounter(snareStats, (uchar *)"expanded_parse_ok", ctrType_IntCtr, CTR_FLAG_RESETTABLE,
                                &ctrExpandedParseOk));
    STATSCOUNTER_INIT(ctrExpandedParseFail, mutCtrExpandedParseFail);
    CHKiRet(statsobj.AddCounter(snareStats, (uchar *)"expanded_parse_fail", ctrType_IntCtr, CTR_FLAG_RESETTABLE,
                                &ctrExpandedParseFail));

    CHKiRet(statsobj.ConstructFinalize(snareStats));
ENDmodInit

BEGINmodExit
    CODESTARTmodExit;
    statsobj.Destruct(&snareStats);
    objRelease(datetime, CORE_COMPONENT);
    objRelease(statsobj, CORE_COMPONENT);
ENDmodExit

BEGINqueryEtryPt
    CODESTARTqueryEtryPt;
    CODEqueryEtryPt_STD_OMOD_QUERIES;
    CODEqueryEtryPt_STD_OMOD8_QUERIES;
    CODEqueryEtryPt_STD_CONF2_OMOD_QUERIES;
    CODEqueryEtryPt_STD_CONF2_QUERIES;
ENDqueryEtryPt
