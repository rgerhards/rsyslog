/* ratelimit.c
 * support for rate-limiting sources, including "last message
 * repeated n times" processing.
 *
 * Copyright 2012-2020 Rainer Gerhards and Adiscon GmbH.
 *
 * This file is part of the rsyslog runtime library.
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
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>

#include "rsyslog.h"
#include "errmsg.h"
#include "ratelimit.h"
#include "rainerscript.h"
#include "datetime.h"
#include "parser.h"
#include "unicode-helper.h"
#include "msg.h"
#include "rsconf.h"
#include "dirty.h"

#ifdef HAVE_LIBYAML
#    include <yaml.h>
#endif

/**
 * @brief Overview of the ratelimit architecture.
 *
 * The ratelimit subsystem is structured into distinct layers so that
 * configuration parsing, registry management, and runtime enforcement remain
 * loosely coupled:
 * - During configuration loading the ratelimit() object handler stores each
 *   named policy in the per-configuration registry (a linked list of
 *   ::ratelimit_config_s entries owned by ::rsconf_s). Inline `ratelimit.*`
 *   parameters are promoted to ad-hoc entries in the same registry so they can
 *   be referenced later.
 * - Modules call ::ratelimitResolveFromValues (or ::ratelimitResolveConfig)
 *   whenever they need ratelimit settings. The helper enforces the "shared OR
 *   inline" contract, returning a pointer to the immutable configuration node.
 *   Whenever an ::rsconf_t is available, callers should prefer this path so
 *   the shared registry is populated for future reuse.
 * - At activation time workers create runtime instances via
 *   ::ratelimitNewFromConfig (shared/ad-hoc) when a configuration entry is
 *   available, or via ::ratelimitNew when no registry context exists (for
 *   example during bootstrap or in tooling). The runtime structure keeps the
 *   mutable counters, mutex state, and repeat suppression data while
 *   referencing the registry entry for the immutable parameters whenever
 *   possible.
 *
 * This file implements all three layers: registry maintenance, object parsing
 * and promotion, plus the actual rate-checking and repeat-suppression logic.
 */

/* Implementation note: the public API is documented in ratelimit.h. */

/* definitions for objects we access */
DEFobjStaticHelpers;
DEFobjCurrIf(glbl);
DEFobjCurrIf(datetime);
DEFobjCurrIf(parser);

/**
 * Immutable configuration entry stored inside the per-configuration
 * ratelimit registry. Each node captures the shared interval, burst, and
 * severity settings associated with a named ratelimit() object so runtime
 * instances can reference them by name.
 */
struct ratelimit_config_s {
    char *name;
    unsigned int interval;
    unsigned int burst;
    intTiny severity;
    char *policy_path;
    ratelimit_per_source_policy_t *per_source;
    ratelimit_config_t *next;
    sbool isAdHoc;
};

struct ratelimit_registry_entry_s {
    ratelimit_config_t *cfg;
    const rsconf_t *owner;
    struct ratelimit_registry_entry_s *next;
};
typedef struct ratelimit_registry_entry_s ratelimit_registry_entry_t;

static ratelimit_registry_entry_t *ratelimit_registry_head;

static ratelimit_config_t *ratelimitFindConfig(const rsconf_t *cnf, const char *name);
static rsRetVal ratelimitConfigValidateSpec(const ratelimit_config_spec_t *spec);
static char *ratelimitBuildInstanceName(const ratelimit_config_t *cfg, const char *instance_name);
static void ratelimitDropSuppressedIfAny(ratelimit_t *ratelimit);
static smsg_t *ratelimitGenRepMsg(ratelimit_t *ratelimit);
static ratelimit_registry_entry_t *ratelimitRegistryFindEntry(const rsconf_t *owner, const char *name);
static rsRetVal ratelimitRegistryAppend(rsconf_t *owner, ratelimit_config_t *cfg);
static void ratelimitRegistryRemove(const rsconf_t *owner, const ratelimit_config_t *cfg);
static void ratelimitRegistryRemoveOwner(const rsconf_t *owner);
static rsRetVal ratelimitPolicyLoadFromYaml(const char *path, ratelimit_config_spec_t *spec);
static void ratelimitPerSourceOverridesFree(ratelimit_per_source_override_t *head);
static void ratelimitPerSourcePolicyFree(ratelimit_per_source_policy_t *policy);
static rsRetVal ratelimitPerSourcePolicyClone(const ratelimit_per_source_policy_t *src,
                                              ratelimit_per_source_policy_t **dst);
static rsRetVal ratelimitParseUnsigned(const char *path, const char *key, const char *value, unsigned int *out);
static rsRetVal ratelimitParseWindow(const char *path, const char *key, const char *value, unsigned int *out);
#ifdef HAVE_LIBYAML
static rsRetVal ratelimitYamlScalarDup(const yaml_node_t *node, char **str_out);
#endif

static struct cnfparamdescr ratelimitpdescr[] = {
    {"name", eCmdHdlrString, CNFPARAM_REQUIRED},
    {"interval", eCmdHdlrInt, 0},
    {"burst", eCmdHdlrInt, 0},
    {"severity", eCmdHdlrInt, 0},
    {"policy", eCmdHdlrString, 0},
};
static struct cnfparamblk ratelimitpblk = {CNFPARAMBLK_VERSION, sizeof(ratelimitpdescr) / sizeof(struct cnfparamdescr),
                                           ratelimitpdescr};

/* static data */

/**
 * @brief Implementation of ::ratelimitConfigSpecInit().
 * @see ratelimit.h for the caller contract.
 *
 * Resets the structure to a disabled limiter so callers can selectively
 * override fields without worrying about stale state.
 */
void ratelimitConfigSpecInit(ratelimit_config_spec_t *const spec) {
    if (spec == NULL) return;
    spec->interval = 0;
    spec->burst = 0;
    spec->severity = RATELIMIT_SEVERITY_UNSET;
    spec->policy_path = NULL;
    spec->per_source = NULL;
}

static ratelimit_config_t *ratelimitFindConfig(const rsconf_t *const cnf, const char *const name) {
    ratelimit_config_t *cfg;

    if (cnf == NULL || name == NULL) return NULL;

    for (cfg = cnf->ratelimits.head; cfg != NULL; cfg = cfg->next) {
        if (!strcmp(cfg->name, name)) {
            return cfg;
        }
    }

    return NULL;
}

static rsRetVal ratelimitConfigValidateSpec(const ratelimit_config_spec_t *const spec) {
    DEFiRet;

    if (spec == NULL) {
        ABORT_FINALIZE(RS_RET_INVALID_PARAMS);
    }

    const sbool has_per_source = (spec->per_source != NULL);

    if (spec->policy_path != NULL && spec->interval == 0 && spec->burst == 0 && !has_per_source) {
        LogError(0, RS_RET_INVALID_VALUE,
                 "ratelimit: YAML policy '%s' did not define interval/burst values", spec->policy_path);
        ABORT_FINALIZE(RS_RET_INVALID_VALUE);
    }

    if (spec->interval == 0) {
        /* burst has no meaning when interval is disabled, but zero is fine */
        FINALIZE;
    }

    if (spec->burst == 0) {
        LogError(0, RS_RET_INVALID_VALUE, "ratelimit: burst must be > 0 when interval is enabled");
        ABORT_FINALIZE(RS_RET_INVALID_VALUE);
    }

    if (has_per_source) {
        if (spec->per_source->def_window == 0 || spec->per_source->def_max == 0) {
            LogError(0, RS_RET_INVALID_VALUE,
                     "ratelimit: per-source policy requires non-zero default max/window values");
            ABORT_FINALIZE(RS_RET_INVALID_VALUE);
        }
        for (ratelimit_per_source_override_t *ovr = spec->per_source->overrides; ovr != NULL; ovr = ovr->next) {
            if (ovr->key == NULL || *ovr->key == '\0') {
                LogError(0, RS_RET_INVALID_VALUE,
                         "ratelimit: per-source policy override must define a non-empty key");
                ABORT_FINALIZE(RS_RET_INVALID_VALUE);
            }
            if (ovr->window == 0 || ovr->max == 0) {
                LogError(0, RS_RET_INVALID_VALUE,
                         "ratelimit: per-source policy override for '%s' requires non-zero max/window", ovr->key);
                ABORT_FINALIZE(RS_RET_INVALID_VALUE);
            }
        }
    }

finalize_it:
    RETiRet;
}

/**
 * @brief Implementation of ::ratelimitStoreInit().
 * @see ratelimit.h for semantics.
 *
 * Sets up the per-configuration linked list so lookups and registrations
 * can operate in O(1) append time.
 */
void ratelimitStoreInit(rsconf_t *const cnf) {
    if (cnf == NULL) return;
    ratelimitRegistryRemoveOwner(cnf);
    cnf->ratelimits.head = NULL;
    cnf->ratelimits.tail = NULL;
    cnf->ratelimits.next_auto_id = 1;
}

/**
 * @brief Implementation of ::ratelimitStoreDestruct().
 *
 * Walks the store and releases all configuration entries so that a
 * configuration teardown or reload does not leak memory.
 */
void ratelimitStoreDestruct(rsconf_t *const cnf) {
    ratelimit_config_t *cfg;
    ratelimit_config_t *nxt;

    if (cnf == NULL) return;

    cfg = cnf->ratelimits.head;
    while (cfg != NULL) {
        nxt = cfg->next;
        ratelimitRegistryRemove(cnf, cfg);
        free(cfg->name);
        free(cfg->policy_path);
        ratelimitPerSourcePolicyFree(cfg->per_source);
        free(cfg);
        cfg = nxt;
    }

    cnf->ratelimits.head = NULL;
    cnf->ratelimits.tail = NULL;
    cnf->ratelimits.next_auto_id = 1;
}

static ratelimit_config_t *ratelimitConfigAlloc(const ratelimit_config_spec_t *const spec) {
    ratelimit_config_t *cfg = calloc(1, sizeof(*cfg));
    if (cfg == NULL) return NULL;

    cfg->interval = spec->interval;
    cfg->burst = spec->burst;
    cfg->severity = (spec->severity == RATELIMIT_SEVERITY_UNSET) ? 0 : (intTiny)spec->severity;
    if (spec->policy_path != NULL) {
        cfg->policy_path = strdup(spec->policy_path);
        if (cfg->policy_path == NULL) {
            goto fail;
        }
    }
    cfg->isAdHoc = 0;
    if (spec->per_source != NULL) {
        if (ratelimitPerSourcePolicyClone(spec->per_source, &cfg->per_source) != RS_RET_OK) {
            goto fail;
        }
    }
    return cfg;

fail:
    free(cfg->policy_path);
    ratelimitPerSourcePolicyFree(cfg->per_source);
    free(cfg);
    return NULL;
}

static rsRetVal ratelimitConfigRegister(rsconf_t *const cnf, ratelimit_config_t *const cfg) {
    DEFiRet;

    CHKiRet(ratelimitRegistryAppend(cnf, cfg));

    if (cnf->ratelimits.tail == NULL) {
        cnf->ratelimits.head = cfg;
    } else {
        cnf->ratelimits.tail->next = cfg;
    }
    cnf->ratelimits.tail = cfg;

finalize_it:
    if (iRet != RS_RET_OK) {
        ratelimitRegistryRemove(cnf, cfg);
    }
    RETiRet;
}

/**
 * @brief Implementation of ::ratelimitConfigCreateNamed().
 *
 * Performs duplicate checking and list registration before returning the
 * immutable configuration to callers.
 */
rsRetVal ratelimitConfigCreateNamed(rsconf_t *const cnf,
                                    const char *const name,
                                    const ratelimit_config_spec_t *const spec,
                                    ratelimit_config_t **const cfg_out) {
    ratelimit_config_t *cfg = NULL;
    DEFiRet;

    if (cnf == NULL || name == NULL || spec == NULL || cfg_out == NULL) {
        ABORT_FINALIZE(RS_RET_INVALID_PARAMS);
    }

    CHKiRet(ratelimitConfigValidateSpec(spec));

    if (ratelimitFindConfig(cnf, name) != NULL) {
        LogError(0, RS_RET_INVALID_VALUE, "ratelimit '%s' is defined more than once", name);
        ABORT_FINALIZE(RS_RET_INVALID_VALUE);
    }

    CHKmalloc(cfg = ratelimitConfigAlloc(spec));
    CHKmalloc(cfg->name = strdup(name));

    CHKiRet(ratelimitConfigRegister(cnf, cfg));

    *cfg_out = cfg;
    cfg = NULL;

finalize_it:
    if (cfg != NULL) {
        free(cfg->name);
        free(cfg->policy_path);
        ratelimitPerSourcePolicyFree(cfg->per_source);
        free(cfg);
    }
    RETiRet;
}

static void ratelimitSanitizeHint(const char *const hint, char *buf, const size_t buflen) {
    size_t len = 0;
    const char *src = hint;

    if (buflen == 0) return;

    if (src == NULL || *src == '\0') {
        if (buflen > 1) {
            buf[0] = 'r';
            buf[1] = '\0';
        } else {
            buf[0] = '\0';
        }
        return;
    }

    while (*src != '\0' && len + 1 < buflen) {
        unsigned char ch = (unsigned char)*src;
        if (isalnum(ch) || ch == '-' || ch == '_') {
            buf[len++] = (char)tolower(ch);
        } else {
            buf[len++] = '_';
        }
        ++src;
    }
    buf[len] = '\0';
    if (len == 0 && buflen > 1) {
        buf[0] = 'r';
        buf[1] = '\0';
    }
}

/**
 * @brief Implementation of ::ratelimitConfigCreateAdHoc().
 *
 * Synthesises a unique name while reusing the same allocation path as
 * explicitly named objects.
 */
rsRetVal ratelimitConfigCreateAdHoc(rsconf_t *const cnf,
                                    const char *const hint,
                                    const ratelimit_config_spec_t *const spec,
                                    ratelimit_config_t **const cfg_out) {
    char namebuf[256];
    char sanitized[128];
    ratelimit_config_t *cfg = NULL;
    DEFiRet;

    if (cnf == NULL || spec == NULL || cfg_out == NULL) {
        ABORT_FINALIZE(RS_RET_INVALID_PARAMS);
    }

    CHKiRet(ratelimitConfigValidateSpec(spec));

    ratelimitSanitizeHint(hint, sanitized, sizeof(sanitized));
    snprintf(namebuf, sizeof(namebuf), "adhoc.%s.%llu", sanitized, (unsigned long long)cnf->ratelimits.next_auto_id++);

    CHKiRet(ratelimitConfigCreateNamed(cnf, namebuf, spec, &cfg));
    cfg->isAdHoc = 1;
    *cfg_out = cfg;

finalize_it:
    RETiRet;
}

/**
 * @brief Implementation of ::ratelimitConfigLookup().
 *
 * Provides a NULL-safe wrapper around the linear search through the
 * configuration list.
 */
rsRetVal ratelimitConfigLookup(const rsconf_t *const cnf, const char *const name, ratelimit_config_t **const cfg) {
    ratelimit_config_t *found;
    DEFiRet;

    if (cfg == NULL) {
        ABORT_FINALIZE(RS_RET_INVALID_PARAMS);
    }

    *cfg = NULL;

    if (cnf == NULL || name == NULL) {
        ABORT_FINALIZE(RS_RET_NOT_FOUND);
    }

    found = ratelimitFindConfig(cnf, name);
    if (found == NULL) {
        ABORT_FINALIZE(RS_RET_NOT_FOUND);
    }

    *cfg = found;

finalize_it:
    RETiRet;
}

static ratelimit_registry_entry_t *ratelimitRegistryFindEntry(const rsconf_t *const owner, const char *const name) {
    ratelimit_registry_entry_t *entry;

    if (name == NULL || *name == '\0') return NULL;

    for (entry = ratelimit_registry_head; entry != NULL; entry = entry->next) {
        if (entry->cfg == NULL || entry->cfg->name == NULL) continue;
        if (owner != NULL && entry->owner != owner) continue;
        if (!strcmp(entry->cfg->name, name)) {
            return entry;
        }
    }

    return NULL;
}

static rsRetVal ratelimitRegistryAppend(rsconf_t *const owner, ratelimit_config_t *const cfg) {
    ratelimit_registry_entry_t *entry = NULL;
    DEFiRet;

    if (cfg == NULL || cfg->name == NULL) {
        ABORT_FINALIZE(RS_RET_INVALID_PARAMS);
    }

    if (ratelimitRegistryFindEntry(owner, cfg->name) != NULL) {
        ABORT_FINALIZE(RS_RET_INVALID_VALUE);
    }

    CHKmalloc(entry = calloc(1, sizeof(*entry)));
    entry->cfg = cfg;
    entry->owner = owner;
    entry->next = ratelimit_registry_head;
    ratelimit_registry_head = entry;
    entry = NULL;

finalize_it:
    free(entry);
    RETiRet;
}

static void ratelimitRegistryRemove(const rsconf_t *const owner, const ratelimit_config_t *const cfg) {
    ratelimit_registry_entry_t **link = &ratelimit_registry_head;

    while (*link != NULL) {
        ratelimit_registry_entry_t *const entry = *link;
        if (entry->cfg == cfg && entry->owner == owner) {
            *link = entry->next;
            free(entry);
            return;
        }
        link = &entry->next;
    }
}

static void ratelimitRegistryRemoveOwner(const rsconf_t *const owner) {
    ratelimit_registry_entry_t **link = &ratelimit_registry_head;

    while (*link != NULL) {
        ratelimit_registry_entry_t *const entry = *link;
        if (entry->owner == owner) {
            *link = entry->next;
            free(entry);
            continue;
        }
        link = &entry->next;
    }
}

static void ratelimitPerSourceOverridesFree(ratelimit_per_source_override_t *head) {
    while (head != NULL) {
        ratelimit_per_source_override_t *next = head->next;
        free(head->key);
        free(head);
        head = next;
    }
}

static void ratelimitPerSourcePolicyFree(ratelimit_per_source_policy_t *const policy) {
    if (policy == NULL) return;
    ratelimitPerSourceOverridesFree(policy->overrides);
    free(policy);
}

static rsRetVal ratelimitPerSourcePolicyClone(const ratelimit_per_source_policy_t *const src,
                                              ratelimit_per_source_policy_t **const dst) {
    ratelimit_per_source_policy_t *copy = NULL;
    ratelimit_per_source_override_t **tail = NULL;

    if (dst == NULL) return RS_RET_INVALID_PARAMS;
    *dst = NULL;
    if (src == NULL) return RS_RET_OK;

    copy = calloc(1, sizeof(*copy));
    if (copy == NULL) return RS_RET_OUT_OF_MEMORY;
    copy->def_max = src->def_max;
    copy->def_window = src->def_window;
    copy->override_count = src->override_count;
    tail = &copy->overrides;

    for (const ratelimit_per_source_override_t *node = src->overrides; node != NULL; node = node->next) {
        ratelimit_per_source_override_t *ovr = calloc(1, sizeof(*ovr));
        if (ovr == NULL) goto fail;
        if (node->key != NULL) {
            ovr->key = strdup(node->key);
            if (ovr->key == NULL) {
                free(ovr);
                goto fail;
            }
        }
        ovr->max = node->max;
        ovr->window = node->window;
        *tail = ovr;
        tail = &ovr->next;
    }

    *dst = copy;
    return RS_RET_OK;

fail:
    ratelimitPerSourcePolicyFree(copy);
    return RS_RET_OUT_OF_MEMORY;
}

static inline void ratelimitSkipTrailingWhitespace(char **cursor) {
    if (cursor == NULL || *cursor == NULL) return;
    while (**cursor != '\0' && isspace((unsigned char)**cursor)) {
        (*cursor)++;
    }
}

static rsRetVal ratelimitParseUnsigned(const char *const path,
                                       const char *const key,
                                       const char *const value,
                                       unsigned int *const out) {
    char *endptr = NULL;
    long long parsed;

    if (value == NULL || out == NULL || key == NULL) return RS_RET_INVALID_PARAMS;

    errno = 0;
    parsed = strtoll(value, &endptr, 10);
    if (errno != 0 || endptr == value) goto invalid;
    ratelimitSkipTrailingWhitespace(&endptr);
    if (endptr != NULL && *endptr != '\0') goto invalid;
    if (parsed < 0 || (unsigned long long)parsed > UINT_MAX) goto invalid;
    *out = (unsigned int)parsed;
    return RS_RET_OK;

invalid:
    LogError(0, RS_RET_INVALID_VALUE,
             "ratelimit: YAML policy '%s' has invalid numeric value '%s' for key '%s'", path, value, key);
    return RS_RET_INVALID_VALUE;
}

static rsRetVal ratelimitParseWindow(const char *const path,
                                     const char *const key,
                                     const char *const value,
                                     unsigned int *const out) {
    char *endptr = NULL;
    long long parsed;

    if (value == NULL || out == NULL || key == NULL) return RS_RET_INVALID_PARAMS;

    errno = 0;
    parsed = strtoll(value, &endptr, 10);
    if (errno != 0 || endptr == value) goto invalid;

    ratelimitSkipTrailingWhitespace(&endptr);
    if (endptr != NULL && (*endptr == 's' || *endptr == 'S')) {
        ++endptr;
        ratelimitSkipTrailingWhitespace(&endptr);
    }
    if (endptr != NULL && *endptr != '\0') goto invalid;
    if (parsed <= 0 || (unsigned long long)parsed > UINT_MAX) goto invalid;
    *out = (unsigned int)parsed;
    return RS_RET_OK;

invalid:
    LogError(0, RS_RET_INVALID_VALUE,
             "ratelimit: YAML policy '%s' has invalid window value '%s' for key '%s'", path, value, key);
    return RS_RET_INVALID_VALUE;
}

#ifdef HAVE_LIBYAML
static rsRetVal ratelimitYamlScalarDup(const yaml_node_t *const node, char **const str_out) {
    if (str_out == NULL) return RS_RET_INVALID_PARAMS;
    *str_out = NULL;
    if (node == NULL || node->type != YAML_SCALAR_NODE) {
        return RS_RET_INVALID_VALUE;
    }

    const size_t len = node->data.scalar.length;
    char *copy = malloc(len + 1);
    if (copy == NULL) {
        return RS_RET_OUT_OF_MEMORY;
    }
    if (len > 0) {
        memcpy(copy, node->data.scalar.value, len);
    }
    copy[len] = '\0';
    *str_out = copy;
    return RS_RET_OK;
}
#endif

static rsRetVal ratelimitPolicyLoadFromYaml(const char *const path, ratelimit_config_spec_t *const spec) {
#ifndef HAVE_LIBYAML
    if (spec != NULL) {
        free(spec->policy_path);
        spec->policy_path = NULL;
        spec->interval = 0;
        spec->burst = 0;
        spec->severity = RATELIMIT_SEVERITY_UNSET;
        ratelimitPerSourcePolicyFree(spec->per_source);
        spec->per_source = NULL;
    }
    if (path == NULL) {
        LogError(0, RS_RET_NOT_IMPLEMENTED,
                 "ratelimit: YAML policy requested but rsyslogd was built without libyaml support; use inline ratelimit.* parameters instead");
    } else {
        LogError(0, RS_RET_NOT_IMPLEMENTED,
                 "ratelimit: policy='%s' requested but rsyslogd was built without libyaml support; use inline ratelimit.* parameters instead",
                 path);
    }
    return RS_RET_NOT_IMPLEMENTED;
#else
    FILE *fp = NULL;
    yaml_parser_t yaml_parser;
    yaml_document_t document;
    sbool parser_initialised = 0;
   sbool document_loaded = 0;
    sbool interval_seen = 0;
    sbool burst_seen = 0;
    sbool severity_seen = 0;
    sbool default_seen = 0;
    DEFiRet;
    ratelimit_per_source_policy_t *parsed_policy = NULL;

    if (spec == NULL || path == NULL || *path == '\0') {
        LogError(0, RS_RET_INVALID_VALUE, "ratelimit: policy path must be specified");
        ABORT_FINALIZE(RS_RET_INVALID_VALUE);
    }

    free(spec->policy_path);
    spec->policy_path = NULL;
    spec->interval = 0;
    spec->burst = 0;
    spec->severity = RATELIMIT_SEVERITY_UNSET;
    ratelimitPerSourcePolicyFree(spec->per_source);
    spec->per_source = NULL;

    fp = fopen(path, "rb");
    if (fp == NULL) {
        LogError(errno, RS_RET_NO_FILE_ACCESS, "ratelimit: could not open policy file '%s': %s", path, strerror(errno));
        ABORT_FINALIZE(RS_RET_NO_FILE_ACCESS);
    }

    if (!yaml_parser_initialize(&yaml_parser)) {
        LogError(0, RS_RET_INTERNAL_ERROR, "ratelimit: failed to initialise YAML parser for '%s'", path);
        ABORT_FINALIZE(RS_RET_INTERNAL_ERROR);
    }
    parser_initialised = 1;
    yaml_parser_set_input_file(&yaml_parser, fp);

    if (!yaml_parser_load(&yaml_parser, &document)) {
        const char *problem =
            (yaml_parser.problem != NULL && *yaml_parser.problem != '\0') ? yaml_parser.problem : "unknown error";
        LogError(0, RS_RET_INVALID_VALUE,
                 "ratelimit: failed to parse YAML policy '%s': %s at line %zu column %zu", path, problem,
                 (size_t)(yaml_parser.problem_mark.line + 1), (size_t)(yaml_parser.problem_mark.column + 1));
        ABORT_FINALIZE(RS_RET_INVALID_VALUE);
    }
    document_loaded = 1;

    yaml_node_t *const root = yaml_document_get_root_node(&document);
    if (root == NULL) {
        LogError(0, RS_RET_INVALID_VALUE, "ratelimit: YAML policy '%s' is empty", path);
        ABORT_FINALIZE(RS_RET_INVALID_VALUE);
    }
    if (root->type != YAML_MAPPING_NODE) {
        LogError(0, RS_RET_INVALID_VALUE, "ratelimit: YAML policy '%s' must contain a mapping at the top level", path);
        ABORT_FINALIZE(RS_RET_INVALID_VALUE);
    }

    for (yaml_node_pair_t *pair = root->data.mapping.pairs.start; pair < root->data.mapping.pairs.top; ++pair) {
        yaml_node_t *const key_node = yaml_document_get_node(&document, pair->key);
        yaml_node_t *const value_node = yaml_document_get_node(&document, pair->value);
        if (key_node == NULL || key_node->type != YAML_SCALAR_NODE || value_node == NULL) {
            LogError(0, RS_RET_INVALID_VALUE,
                     "ratelimit: YAML policy '%s' must use scalar keys", path);
            ABORT_FINALIZE(RS_RET_INVALID_VALUE);
        }

        char *key = NULL;
        rsRetVal pairRet = ratelimitYamlScalarDup(key_node, &key);
        if (pairRet != RS_RET_OK) {
            LogError(0, pairRet, "ratelimit: failed to copy YAML key while parsing policy '%s'", path);
            free(key);
            iRet = pairRet;
            ABORT_FINALIZE(iRet);
        }

        if (!strcmp(key, "interval") || !strcmp(key, "burst") || !strcmp(key, "severity")) {
            if (value_node->type != YAML_SCALAR_NODE) {
                LogError(0, RS_RET_INVALID_VALUE,
                         "ratelimit: YAML policy '%s' expects scalar for key '%s'", path, key);
                free(key);
                ABORT_FINALIZE(RS_RET_INVALID_VALUE);
            }
            char *value = NULL;
            pairRet = ratelimitYamlScalarDup(value_node, &value);
            if (pairRet != RS_RET_OK) {
                LogError(0, pairRet, "ratelimit: failed to copy YAML value for key '%s' in policy '%s'", key, path);
                free(value);
                free(key);
                iRet = pairRet;
                ABORT_FINALIZE(iRet);
            }

            if (!strcmp(key, "interval")) {
                if (interval_seen) {
                    LogError(0, RS_RET_INVALID_VALUE,
                             "ratelimit: YAML policy '%s' defines 'interval' more than once", path);
                    pairRet = RS_RET_INVALID_VALUE;
                } else {
                    pairRet = ratelimitParseUnsigned(path, "interval", value, &spec->interval);
                    if (pairRet == RS_RET_OK) interval_seen = 1;
                }
            } else if (!strcmp(key, "burst")) {
                if (burst_seen) {
                    LogError(0, RS_RET_INVALID_VALUE,
                             "ratelimit: YAML policy '%s' defines 'burst' more than once", path);
                    pairRet = RS_RET_INVALID_VALUE;
                } else {
                    pairRet = ratelimitParseUnsigned(path, "burst", value, &spec->burst);
                    if (pairRet == RS_RET_OK) burst_seen = 1;
                }
            } else { /* severity */
                if (severity_seen) {
                    LogError(0, RS_RET_INVALID_VALUE,
                             "ratelimit: YAML policy '%s' defines 'severity' more than once", path);
                    pairRet = RS_RET_INVALID_VALUE;
                } else {
                    unsigned int sev = 0;
                    pairRet = ratelimitParseUnsigned(path, "severity", value, &sev);
                    if (pairRet == RS_RET_OK) {
                        if (sev > 7) {
                            LogError(0, RS_RET_INVALID_VALUE,
                                     "ratelimit: YAML policy '%s' has invalid severity '%s' (expected 0-7)", path, value);
                            pairRet = RS_RET_INVALID_VALUE;
                        } else {
                            spec->severity = (int)sev;
                            severity_seen = 1;
                        }
                    }
                }
            }

            free(value);
            free(key);
            if (pairRet != RS_RET_OK) {
                iRet = pairRet;
                ABORT_FINALIZE(iRet);
            }
            continue;
        }

        if (!strcmp(key, "default")) {
            if (value_node->type != YAML_MAPPING_NODE) {
                LogError(0, RS_RET_INVALID_VALUE,
                         "ratelimit: YAML policy '%s' expects mapping for 'default'", path);
                free(key);
                ABORT_FINALIZE(RS_RET_INVALID_VALUE);
            }
            if (default_seen) {
                LogError(0, RS_RET_INVALID_VALUE,
                         "ratelimit: YAML policy '%s' defines 'default' more than once", path);
                free(key);
                ABORT_FINALIZE(RS_RET_INVALID_VALUE);
            }
            if (parsed_policy == NULL) {
                parsed_policy = calloc(1, sizeof(*parsed_policy));
                if (parsed_policy == NULL) {
                    free(key);
                    ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
                }
            }

            sbool max_seen = 0;
            sbool window_seen = 0;
            for (yaml_node_pair_t *def_pair = value_node->data.mapping.pairs.start;
                 def_pair < value_node->data.mapping.pairs.top; ++def_pair) {
                yaml_node_t *def_key_node = yaml_document_get_node(&document, def_pair->key);
                yaml_node_t *def_value_node = yaml_document_get_node(&document, def_pair->value);
                if (def_key_node == NULL || def_value_node == NULL || def_key_node->type != YAML_SCALAR_NODE ||
                    def_value_node->type != YAML_SCALAR_NODE) {
                    LogError(0, RS_RET_INVALID_VALUE,
                             "ratelimit: YAML policy '%s' default block must use scalar keys/values", path);
                    free(key);
                    ABORT_FINALIZE(RS_RET_INVALID_VALUE);
                }
                char *def_key = NULL;
                char *def_value = NULL;
                pairRet = ratelimitYamlScalarDup(def_key_node, &def_key);
                if (pairRet != RS_RET_OK) {
                    free(def_key);
                    free(def_value);
                    free(key);
                    iRet = pairRet;
                    ABORT_FINALIZE(iRet);
                }
                pairRet = ratelimitYamlScalarDup(def_value_node, &def_value);
                if (pairRet != RS_RET_OK) {
                    LogError(0, pairRet,
                             "ratelimit: failed to copy YAML value for default '%s' in policy '%s'",
                             (def_key != NULL) ? def_key : "(unknown)", path);
                    free(def_key);
                    free(def_value);
                    free(key);
                    iRet = pairRet;
                    ABORT_FINALIZE(iRet);
                }

                if (!strcmp(def_key, "max")) {
                    pairRet = ratelimitParseUnsigned(path, "default.max", def_value, &parsed_policy->def_max);
                    if (pairRet == RS_RET_OK) max_seen = 1;
                } else if (!strcmp(def_key, "window")) {
                    pairRet = ratelimitParseWindow(path, "default.window", def_value, &parsed_policy->def_window);
                    if (pairRet == RS_RET_OK) window_seen = 1;
                } else {
                    LogError(0, RS_RET_INVALID_VALUE,
                             "ratelimit: YAML policy '%s' default block contains unsupported key '%s'", path, def_key);
                    pairRet = RS_RET_INVALID_VALUE;
                }

                free(def_key);
                free(def_value);
                if (pairRet != RS_RET_OK) {
                    free(key);
                    iRet = pairRet;
                    ABORT_FINALIZE(iRet);
                }
            }

            if (!max_seen || !window_seen) {
                LogError(0, RS_RET_INVALID_VALUE,
                         "ratelimit: YAML policy '%s' default block must define both max and window", path);
                free(key);
                ABORT_FINALIZE(RS_RET_INVALID_VALUE);
            }

            default_seen = 1;
            free(key);
            continue;
        }

        if (!strcmp(key, "overrides")) {
            if (value_node->type != YAML_SEQUENCE_NODE) {
                LogError(0, RS_RET_INVALID_VALUE,
                         "ratelimit: YAML policy '%s' expects a sequence for 'overrides'", path);
                free(key);
                ABORT_FINALIZE(RS_RET_INVALID_VALUE);
            }
            if (parsed_policy == NULL) {
                parsed_policy = calloc(1, sizeof(*parsed_policy));
                if (parsed_policy == NULL) {
                    free(key);
                    ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
                }
            }

            for (yaml_node_item_t *item = value_node->data.sequence.items.start;
                 item < value_node->data.sequence.items.top; ++item) {
                yaml_node_t *ovr_node = yaml_document_get_node(&document, *item);
                if (ovr_node == NULL || ovr_node->type != YAML_MAPPING_NODE) {
                    LogError(0, RS_RET_INVALID_VALUE,
                             "ratelimit: YAML policy '%s' overrides entries must be mappings", path);
                    free(key);
                    ABORT_FINALIZE(RS_RET_INVALID_VALUE);
                }

                char *override_key = NULL;
                unsigned int override_max = 0;
                unsigned int override_window = 0;
                sbool override_key_seen = 0;
                sbool override_max_seen = 0;
                sbool override_window_seen = 0;

                for (yaml_node_pair_t *ovr_pair = ovr_node->data.mapping.pairs.start;
                     ovr_pair < ovr_node->data.mapping.pairs.top; ++ovr_pair) {
                    yaml_node_t *ovr_key_node = yaml_document_get_node(&document, ovr_pair->key);
                    yaml_node_t *ovr_value_node = yaml_document_get_node(&document, ovr_pair->value);
                    if (ovr_key_node == NULL || ovr_value_node == NULL || ovr_key_node->type != YAML_SCALAR_NODE ||
                        ovr_value_node->type != YAML_SCALAR_NODE) {
                        LogError(0, RS_RET_INVALID_VALUE,
                                 "ratelimit: YAML policy '%s' overrides must use scalar keys/values", path);
                        free(override_key);
                        free(key);
                        ABORT_FINALIZE(RS_RET_INVALID_VALUE);
                    }
                    char *ovr_key = NULL;
                    char *ovr_value = NULL;
                    pairRet = ratelimitYamlScalarDup(ovr_key_node, &ovr_key);
                    if (pairRet != RS_RET_OK) {
                        free(ovr_key);
                        free(ovr_value);
                        free(override_key);
                        free(key);
                        iRet = pairRet;
                        ABORT_FINALIZE(iRet);
                    }
                    pairRet = ratelimitYamlScalarDup(ovr_value_node, &ovr_value);
                    if (pairRet != RS_RET_OK) {
                        LogError(0, pairRet,
                                 "ratelimit: failed to copy YAML override value for key '%s' in policy '%s'",
                                 (ovr_key != NULL) ? ovr_key : "(unknown)", path);
                        free(ovr_key);
                        free(ovr_value);
                        free(override_key);
                        free(key);
                        iRet = pairRet;
                        ABORT_FINALIZE(iRet);
                    }

                    if (!strcmp(ovr_key, "key")) {
                        free(override_key);
                        override_key = strdup(ovr_value);
                        if (override_key == NULL) {
                            free(ovr_key);
                            free(ovr_value);
                            free(key);
                            ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
                        }
                        override_key_seen = 1;
                    } else if (!strcmp(ovr_key, "max")) {
                        pairRet = ratelimitParseUnsigned(path, "overrides[].max", ovr_value, &override_max);
                        if (pairRet == RS_RET_OK) override_max_seen = 1;
                    } else if (!strcmp(ovr_key, "window")) {
                        pairRet = ratelimitParseWindow(path, "overrides[].window", ovr_value, &override_window);
                        if (pairRet == RS_RET_OK) override_window_seen = 1;
                    } else {
                        LogError(0, RS_RET_INVALID_VALUE,
                                 "ratelimit: YAML policy '%s' override contains unsupported key '%s'", path, ovr_key);
                        pairRet = RS_RET_INVALID_VALUE;
                    }

                    free(ovr_key);
                    free(ovr_value);
                    if (pairRet != RS_RET_OK) {
                        free(override_key);
                        free(key);
                        iRet = pairRet;
                        ABORT_FINALIZE(iRet);
                    }
                }

                if (!override_key_seen || !override_max_seen || !override_window_seen) {
                    LogError(0, RS_RET_INVALID_VALUE,
                             "ratelimit: YAML policy '%s' overrides must define key/max/window", path);
                    free(override_key);
                    free(key);
                    ABORT_FINALIZE(RS_RET_INVALID_VALUE);
                }

                for (ratelimit_per_source_override_t *existing = parsed_policy->overrides; existing != NULL;
                     existing = existing->next) {
                    if (existing->key != NULL && override_key != NULL && !strcmp(existing->key, override_key)) {
                        LogError(0, RS_RET_INVALID_VALUE,
                                 "ratelimit: YAML policy '%s' defines override for key '%s' more than once", path,
                                 override_key);
                        free(override_key);
                        free(key);
                        ABORT_FINALIZE(RS_RET_INVALID_VALUE);
                    }
                }

                ratelimit_per_source_override_t *ovr = calloc(1, sizeof(*ovr));
                if (ovr == NULL) {
                    free(override_key);
                    free(key);
                    ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
                }
                ovr->key = override_key;
                ovr->max = override_max;
                ovr->window = override_window;
                ovr->next = NULL;

                if (parsed_policy->overrides == NULL) {
                    parsed_policy->overrides = ovr;
                } else {
                    ratelimit_per_source_override_t *tail = parsed_policy->overrides;
                    while (tail->next != NULL) tail = tail->next;
                    tail->next = ovr;
                }
                parsed_policy->override_count++;
            }

            free(key);
            continue;
        }

        LogError(0, RS_RET_INVALID_VALUE, "ratelimit: YAML policy '%s' contains unsupported key '%s'", path, key);
        free(key);
        ABORT_FINALIZE(RS_RET_INVALID_VALUE);
    }

    if (parsed_policy != NULL) {
        if (!default_seen) {
            LogError(0, RS_RET_INVALID_VALUE,
                     "ratelimit: YAML policy '%s' overrides require a default block", path);
            ABORT_FINALIZE(RS_RET_INVALID_VALUE);
        }
        spec->per_source = parsed_policy;
        parsed_policy = NULL;
    }

    if (spec->per_source == NULL) {
        if (!interval_seen) {
            LogError(0, RS_RET_INVALID_VALUE, "ratelimit: YAML policy '%s' must define an interval", path);
            ABORT_FINALIZE(RS_RET_INVALID_VALUE);
        }
        if (!burst_seen) {
            LogError(0, RS_RET_INVALID_VALUE, "ratelimit: YAML policy '%s' must define a burst", path);
            ABORT_FINALIZE(RS_RET_INVALID_VALUE);
        }
    }

    char *resolved = realpath(path, NULL);
    if (resolved != NULL) {
        spec->policy_path = resolved;
    } else {
        spec->policy_path = strdup(path);
        if (spec->policy_path == NULL) {
            LogError(0, RS_RET_OUT_OF_MEMORY, "ratelimit: failed to duplicate policy path '%s'", path);
            ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
        }
    }

finalize_it:
    if (document_loaded) yaml_document_delete(&document);
    if (parser_initialised) yaml_parser_delete(&yaml_parser);
    if (fp != NULL) fclose(fp);
    if (parsed_policy != NULL) ratelimitPerSourcePolicyFree(parsed_policy);
    if (iRet != RS_RET_OK) {
        free(spec->policy_path);
        spec->policy_path = NULL;
        spec->interval = 0;
        spec->burst = 0;
        spec->severity = RATELIMIT_SEVERITY_UNSET;
        ratelimitPerSourcePolicyFree(spec->per_source);
        spec->per_source = NULL;
    }
    RETiRet;
#endif
}

rsRetVal ratelimitRegistryLookup(const rsconf_t *const cnf, const char *const name, ratelimit_config_t **const cfg_out) {
    ratelimit_registry_entry_t *entry;
    DEFiRet;

    if (cfg_out == NULL) {
        ABORT_FINALIZE(RS_RET_INVALID_PARAMS);
    }

    *cfg_out = NULL;

    if (name == NULL || *name == '\0') {
        ABORT_FINALIZE(RS_RET_INVALID_PARAMS);
    }

    entry = ratelimitRegistryFindEntry(cnf, name);
    if (entry == NULL) {
        ABORT_FINALIZE(RS_RET_NOT_FOUND);
    }

    *cfg_out = entry->cfg;

finalize_it:
    RETiRet;
}

/**
 * @brief Implementation of ::ratelimitConfigName().
 *
 * Returns the stored identifier so diagnostics can mention the
 * configuration that was used.
 */
const char *ratelimitConfigName(const ratelimit_config_t *const cfg) {
    return (cfg == NULL) ? NULL : cfg->name;
}

/**
 * @brief Implementation of ::ratelimitConfigGetInterval().
 *
 * Provides callers with the resolved interval while gracefully handling
 * NULL configuration pointers.
 */
unsigned int ratelimitConfigGetInterval(const ratelimit_config_t *const cfg) {
    return (cfg == NULL) ? 0 : cfg->interval;
}

/**
 * @brief Implementation of ::ratelimitConfigGetBurst().
 *
 * Mirrors ::ratelimitConfigGetInterval() for the burst field.
 */
unsigned int ratelimitConfigGetBurst(const ratelimit_config_t *const cfg) {
    return (cfg == NULL) ? 0 : cfg->burst;
}

/**
 * @brief Implementation of ::ratelimitConfigGetSeverity().
 *
 * Exposes the stored severity threshold while defaulting to zero when no
 * configuration is supplied.
 */
int ratelimitConfigGetSeverity(const ratelimit_config_t *const cfg) {
    return (cfg == NULL) ? 0 : cfg->severity;
}

const char *ratelimitConfigGetPolicyPath(const ratelimit_config_t *const cfg) {
    return (cfg == NULL) ? NULL : cfg->policy_path;
}

const ratelimit_per_source_policy_t *ratelimitConfigGetPerSourcePolicy(const ratelimit_config_t *const cfg) {
    return (cfg == NULL) ? NULL : cfg->per_source;
}

unsigned int ratelimitPerSourcePolicyGetDefaultMax(const ratelimit_per_source_policy_t *const policy) {
    return (policy == NULL) ? 0 : policy->def_max;
}

unsigned int ratelimitPerSourcePolicyGetDefaultWindow(const ratelimit_per_source_policy_t *const policy) {
    return (policy == NULL) ? 0 : policy->def_window;
}

size_t ratelimitPerSourcePolicyGetOverrideCount(const ratelimit_per_source_policy_t *const policy) {
    return (policy == NULL) ? 0 : policy->override_count;
}

const ratelimit_per_source_override_t *
ratelimitPerSourcePolicyGetOverrides(const ratelimit_per_source_policy_t *const policy) {
    return (policy == NULL) ? NULL : policy->overrides;
}

const char *ratelimitPerSourceOverrideGetKey(const ratelimit_per_source_override_t *const override) {
    return (override == NULL) ? NULL : override->key;
}

unsigned int ratelimitPerSourceOverrideGetMax(const ratelimit_per_source_override_t *const override) {
    return (override == NULL) ? 0 : override->max;
}

unsigned int ratelimitPerSourceOverrideGetWindow(const ratelimit_per_source_override_t *const override) {
    return (override == NULL) ? 0 : override->window;
}

/**
 * @brief Implementation of ::ratelimitResolveConfig().
 *
 * Centralises the legacy-parameter guard rails so all call sites get
 * consistent error reporting.
 */
rsRetVal ratelimitResolveConfig(rsconf_t *const cnf,
                                const char *const hint,
                                const char *const name,
                                const sbool legacyParamsSpecified,
                                const ratelimit_config_spec_t *const spec,
                                ratelimit_config_t **const cfg_out) {
    DEFiRet;

    if (cfg_out == NULL || cnf == NULL || spec == NULL) {
        ABORT_FINALIZE(RS_RET_INVALID_PARAMS);
    }

    if (name != NULL && *name != '\0') {
        if (legacyParamsSpecified) {
            LogError(0, RS_RET_INVALID_VALUE,
                     "ratelimit '%s': ratelimit.name cannot be combined with inline ratelimit.* parameters", name);
            ABORT_FINALIZE(RS_RET_INVALID_VALUE);
        }
        CHKiRet(ratelimitConfigLookup(cnf, name, cfg_out));
    } else {
        CHKiRet(ratelimitConfigCreateAdHoc(cnf, hint, spec, cfg_out));
    }

finalize_it:
    RETiRet;
}

/**
 * @brief Implementation of ::ratelimitResolveFromValues().
 *
 * Promotes inline parameters to shared configurations so dynamically
 * created instances can reuse the same immutable spec.
 */
rsRetVal ratelimitResolveFromValues(rsconf_t *const cnf,
                                    const char *const hint,
                                    const char *const name,
                                    const sbool legacyParamsSpecified,
                                    unsigned int *const interval,
                                    unsigned int *const burst,
                                    int *const severity,
                                    ratelimit_config_t **const cfg_out) {
    ratelimit_config_spec_t spec = {0};
    DEFiRet;

    if (interval == NULL || burst == NULL) {
        ABORT_FINALIZE(RS_RET_INVALID_PARAMS);
    }

    ratelimitConfigSpecInit(&spec);
    spec.interval = *interval;
    spec.burst = *burst;
    if (severity != NULL) spec.severity = (*severity < 0) ? RATELIMIT_SEVERITY_UNSET : *severity;

    CHKiRet(ratelimitResolveConfig(cnf, hint, name, legacyParamsSpecified, &spec, cfg_out));

    *interval = ratelimitConfigGetInterval(*cfg_out);
    *burst = ratelimitConfigGetBurst(*cfg_out);
    if (severity != NULL) *severity = ratelimitConfigGetSeverity(*cfg_out);

finalize_it:
    RETiRet;
}

static char *ratelimitBuildInstanceName(const ratelimit_config_t *const cfg, const char *const instance_name) {
    if (instance_name != NULL && *instance_name != '\0') {
        return strdup(instance_name);
    }
    if (cfg != NULL && cfg->name != NULL) {
        return strdup(cfg->name);
    }
    return strdup("ratelimit");
}

static void ratelimitDropSuppressedIfAny(ratelimit_t *const ratelimit) {
    if (ratelimit->pMsg != NULL) {
        if (ratelimit->nsupp > 0) {
            smsg_t *rep = ratelimitGenRepMsg(ratelimit);
            if (rep != NULL) submitMsg2(rep);
        }
        msgDestruct(&ratelimit->pMsg);
    }
}

static inline unsigned int ratelimitEffectiveInterval(const ratelimit_t *const ratelimit) {
    if (ratelimit->has_override) {
        return ratelimit->interval_override;
    }
    return (ratelimit->cfg != NULL) ? ratelimit->cfg->interval : 0;
}

static inline unsigned int ratelimitEffectiveBurst(const ratelimit_t *const ratelimit) {
    if (ratelimit->has_override) {
        return ratelimit->burst_override;
    }
    return (ratelimit->cfg != NULL) ? ratelimit->cfg->burst : 0;
}

static inline intTiny ratelimitEffectiveSeverity(const ratelimit_t *const ratelimit) {
    if (ratelimit->has_override) {
        return ratelimit->severity_override;
    }
    return (ratelimit->cfg != NULL) ? ratelimit->cfg->severity : 0;
}

/**
 * @brief Implementation of ::ratelimitProcessCnf().
 *
 * Parses the RainerScript object definition and feeds the resulting spec
 * into the configuration store.
 */
rsRetVal ratelimitProcessCnf(struct cnfobj *const o) {
    struct cnfparamvals *pvals = NULL;
    ratelimit_config_spec_t spec = {0};
    ratelimit_config_t *cfg = NULL;
    char *name = NULL;
    char *policy_param = NULL;
    sbool interval_seen = 0;
    sbool burst_seen = 0;
    sbool severity_seen = 0;
    DEFiRet;

    if (o == NULL) {
        ABORT_FINALIZE(RS_RET_INVALID_PARAMS);
    }

    ratelimitConfigSpecInit(&spec);

    pvals = nvlstGetParams(o->nvlst, &ratelimitpblk, NULL);
    if (pvals == NULL) {
        ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
    }

    for (short i = 0; i < ratelimitpblk.nParams; ++i) {
        if (!pvals[i].bUsed) continue;
        const char *const pname = ratelimitpblk.descr[i].name;
        if (!strcmp(pname, "name")) {
            free(name);
            name = es_str2cstr(pvals[i].val.d.estr, NULL);
        } else if (!strcmp(pname, "interval")) {
            const long long val = pvals[i].val.d.n;
            if (val < 0) {
                LogError(0, RS_RET_INVALID_VALUE, "ratelimit: interval must be >= 0");
                ABORT_FINALIZE(RS_RET_INVALID_VALUE);
            }
            spec.interval = (unsigned int)val;
            interval_seen = 1;
        } else if (!strcmp(pname, "burst")) {
            const long long val = pvals[i].val.d.n;
            if (val < 0) {
                LogError(0, RS_RET_INVALID_VALUE, "ratelimit: burst must be >= 0");
                ABORT_FINALIZE(RS_RET_INVALID_VALUE);
            }
            spec.burst = (unsigned int)val;
            burst_seen = 1;
        } else if (!strcmp(pname, "severity")) {
            const long long val = pvals[i].val.d.n;
            if (val < 0 || val > 7) {
                LogError(0, RS_RET_INVALID_VALUE, "ratelimit: severity must be between 0 and 7");
                ABORT_FINALIZE(RS_RET_INVALID_VALUE);
            }
            spec.severity = (int)val;
            severity_seen = 1;
        } else if (!strcmp(pname, "policy")) {
            free(policy_param);
            policy_param = es_str2cstr(pvals[i].val.d.estr, NULL);
        }
    }

    if (name == NULL) {
        LogError(0, RS_RET_INVALID_VALUE, "ratelimit: name parameter is required");
        ABORT_FINALIZE(RS_RET_INVALID_VALUE);
    }

    if (policy_param != NULL) {
        if (interval_seen || burst_seen || severity_seen) {
            LogError(0, RS_RET_INVALID_VALUE,
                     "ratelimit '%s': policy= cannot be combined with inline interval/burst/severity values", name);
            ABORT_FINALIZE(RS_RET_INVALID_VALUE);
        }
        CHKiRet(ratelimitPolicyLoadFromYaml(policy_param, &spec));
    } else {
        if (!interval_seen || !burst_seen) {
            LogError(0, RS_RET_INVALID_VALUE,
                     "ratelimit '%s': interval and burst must be provided when policy= is not used", name);
            ABORT_FINALIZE(RS_RET_INVALID_VALUE);
        }
    }

    CHKiRet(ratelimitConfigCreateNamed(loadConf, name, &spec, &cfg));
    cfg = NULL;

finalize_it:
    free(spec.policy_path);
    ratelimitPerSourcePolicyFree(spec.per_source);
    free(name);
    free(policy_param);
    cnfparamvalsDestruct(pvals, &ratelimitpblk);
    RETiRet;
}

/* generate a "repeated n times" message */
static smsg_t *ratelimitGenRepMsg(ratelimit_t *ratelimit) {
    smsg_t *repMsg;
    size_t lenRepMsg;
    uchar szRepMsg[1024];

    if (ratelimit->nsupp == 1) { /* we simply use the original message! */
        repMsg = MsgAddRef(ratelimit->pMsg);
    } else { /* we need to duplicate, original message may still be in use in other
              * parts of the system!  */
        if ((repMsg = MsgDup(ratelimit->pMsg)) == NULL) {
            DBGPRINTF("Message duplication failed, dropping repeat message.\n");
            goto done;
        }
        lenRepMsg = snprintf((char *)szRepMsg, sizeof(szRepMsg), " message repeated %d times: [%.800s]",
                             ratelimit->nsupp, getMSG(ratelimit->pMsg));
        MsgReplaceMSG(repMsg, szRepMsg, lenRepMsg);
    }

done:
    return repMsg;
}

static rsRetVal doLastMessageRepeatedNTimes(ratelimit_t *ratelimit, smsg_t *pMsg, smsg_t **ppRepMsg) {
    int bNeedUnlockMutex = 0;
    DEFiRet;

    if (ratelimit->bThreadSafe) {
        pthread_mutex_lock(&ratelimit->mut);
        bNeedUnlockMutex = 1;
    }

    if (ratelimit->pMsg != NULL && getMSGLen(pMsg) == getMSGLen(ratelimit->pMsg) &&
        !ustrcmp(getMSG(pMsg), getMSG(ratelimit->pMsg)) && !strcmp(getHOSTNAME(pMsg), getHOSTNAME(ratelimit->pMsg)) &&
        !strcmp(getPROCID(pMsg, LOCK_MUTEX), getPROCID(ratelimit->pMsg, LOCK_MUTEX)) &&
        !strcmp(getAPPNAME(pMsg, LOCK_MUTEX), getAPPNAME(ratelimit->pMsg, LOCK_MUTEX))) {
        ratelimit->nsupp++;
        DBGPRINTF("msg repeated %d times\n", ratelimit->nsupp);
        /* use current message, so we have the new timestamp
         * (means we need to discard previous one) */
        msgDestruct(&ratelimit->pMsg);
        ratelimit->pMsg = pMsg;
        ABORT_FINALIZE(RS_RET_DISCARDMSG);
    } else { /* new message, do "repeat processing" & save it */
        if (ratelimit->pMsg != NULL) {
            if (ratelimit->nsupp > 0) {
                *ppRepMsg = ratelimitGenRepMsg(ratelimit);
                ratelimit->nsupp = 0;
            }
            msgDestruct(&ratelimit->pMsg);
        }
        ratelimit->pMsg = MsgAddRef(pMsg);
    }

finalize_it:
    if (bNeedUnlockMutex) pthread_mutex_unlock(&ratelimit->mut);
    RETiRet;
}


/* helper: tell how many messages we lost due to linux-like ratelimiting */
static void tellLostCnt(ratelimit_t *const ratelimit) {
    uchar msgbuf[1024];
    if (ratelimit->missed) {
        const unsigned int burst = ratelimitEffectiveBurst(ratelimit);
        const unsigned int interval = ratelimitEffectiveInterval(ratelimit);
        snprintf((char *)msgbuf, sizeof(msgbuf),
                 "%s: %u messages lost due to rate-limiting (%u allowed within %u seconds)", ratelimit->name,
                 ratelimit->missed, burst, interval);
        ratelimit->missed = 0;
        logmsgInternal(RS_RET_RATE_LIMITED, LOG_SYSLOG | LOG_INFO, msgbuf, 0);
    }
}

/* Linux-like ratelimiting, modelled after the linux kernel
 * returns 1 if message is within rate limit and shall be
 * processed, 0 otherwise.
 * This implementation is NOT THREAD-SAFE and must not
 * be called concurrently.
 */
static int ATTR_NONNULL()
    withinRatelimit(ratelimit_t *__restrict__ const ratelimit, time_t tt, const char *const appname) {
    int ret;
    uchar msgbuf[1024];
    const unsigned int interval = ratelimitEffectiveInterval(ratelimit);
    const unsigned int burst = ratelimitEffectiveBurst(ratelimit);

    if (ratelimit->bThreadSafe) {
        pthread_mutex_lock(&ratelimit->mut);
    }

    if (interval == 0) {
        ret = 1;
        goto finalize_it;
    }

    /* we primarily need "NoTimeCache" mode for imjournal, as it
     * sets the message generation time to the journal timestamp.
     * As such, we do not get a proper indication of the actual
     * message rate. To prevent this, we need to query local
     * system time ourselvs.
     */
    if (ratelimit->bNoTimeCache) tt = time(NULL);

    assert(burst != 0);

    if (ratelimit->begin == 0) ratelimit->begin = tt;

    /* resume if we go out of time window or if time has gone backwards */
    if ((tt > (time_t)(ratelimit->begin + interval)) || (tt < ratelimit->begin)) {
        ratelimit->begin = 0;
        ratelimit->done = 0;
        tellLostCnt(ratelimit);
    }

    /* do actual limit check */
    if (burst > ratelimit->done) {
        ratelimit->done++;
        ret = 1;
    } else {
        ratelimit->missed++;
        if (ratelimit->missed == 1) {
            snprintf((char *)msgbuf, sizeof(msgbuf), "%s from <%s>: begin to drop messages due to rate-limiting",
                     ratelimit->name, appname);
            logmsgInternal(RS_RET_RATE_LIMITED, LOG_SYSLOG | LOG_INFO, msgbuf, 0);
        }
        ret = 0;
    }

finalize_it:
    if (ratelimit->bThreadSafe) {
        pthread_mutex_unlock(&ratelimit->mut);
    }
    return ret;
}

/* ratelimit a message based on message count
 * - handles only rate-limiting
 * This function returns RS_RET_OK, if the caller shall process
 * the message regularly and RS_RET_DISCARD if the caller must
 * discard the message. The caller should also discard the message
 * if another return status occurs.
 */
/**
 * @brief Implementation of ::ratelimitMsgCount().
 *
 * Separates the pure rate-limit code path from the repeat-message logic so
 * callers that do not need suppression can still share the limiter core.
 */
rsRetVal ratelimitMsgCount(ratelimit_t *__restrict__ const ratelimit, time_t tt, const char *const appname) {
    DEFiRet;
    if (ratelimitEffectiveInterval(ratelimit)) {
        if (withinRatelimit(ratelimit, tt, appname) == 0) {
            ABORT_FINALIZE(RS_RET_DISCARDMSG);
        }
    }
finalize_it:
    if (Debug) {
        if (iRet == RS_RET_DISCARDMSG) DBGPRINTF("message discarded by ratelimiting\n");
    }
    RETiRet;
}

/* ratelimit a message, that means:
 * - handle "last message repeated n times" logic
 * - handle actual (discarding) rate-limiting
 * This function returns RS_RET_OK, if the caller shall process
 * the message regularly and RS_RET_DISCARD if the caller must
 * discard the message. The caller should also discard the message
 * if another return status occurs. This places some burden on the
 * caller logic, but provides best performance. Demanding this
 * cooperative mode can enable a faulty caller to thrash up part
 * of the system, but we accept that risk (a faulty caller can
 * always do all sorts of evil, so...)
 * If *ppRepMsg != NULL on return, the caller must enqueue that
 * message before the original message.
 */
/**
 * @brief Implementation of ::ratelimitMsg().
 *
 * Applies both counting and repeat suppression while honouring the
 * severity threshold documented in the header.
 */
rsRetVal ratelimitMsg(ratelimit_t *__restrict__ const ratelimit, smsg_t *pMsg, smsg_t **ppRepMsg) {
    DEFiRet;
    rsRetVal localRet;
    int severity = 0;
    const intTiny severityThreshold = ratelimitEffectiveSeverity(ratelimit);
    const unsigned int interval = ratelimitEffectiveInterval(ratelimit);

    *ppRepMsg = NULL;

    if (runConf->globals.bReduceRepeatMsgs || severityThreshold > 0) {
        /* consider early parsing only if really needed */
        if ((pMsg->msgFlags & NEEDS_PARSING) != 0) {
            if ((localRet = parser.ParseMsg(pMsg)) != RS_RET_OK) {
                DBGPRINTF("Message discarded, parsing error %d\n", localRet);
                ABORT_FINALIZE(RS_RET_DISCARDMSG);
            }
        }
        severity = pMsg->iSeverity;
    }

    /* Only the messages having severity level at or below the
     * treshold (the value is >=) are subject to ratelimiting. */
    if (interval && (severity >= severityThreshold)) {
        char namebuf[512]; /* 256 for FGDN adn 256 for APPNAME should be enough */
        snprintf(namebuf, sizeof namebuf, "%s:%s", getHOSTNAME(pMsg), getAPPNAME(pMsg, 0));
        if (withinRatelimit(ratelimit, pMsg->ttGenTime, namebuf) == 0) {
            msgDestruct(&pMsg);
            ABORT_FINALIZE(RS_RET_DISCARDMSG);
        }
    }
    if (runConf->globals.bReduceRepeatMsgs) {
        CHKiRet(doLastMessageRepeatedNTimes(ratelimit, pMsg, ppRepMsg));
    }
finalize_it:
    if (Debug) {
        if (iRet == RS_RET_DISCARDMSG) DBGPRINTF("message discarded by ratelimiting\n");
    }
    RETiRet;
}

/**
 * @brief Implementation of ::ratelimitChecked().
 */
int ratelimitChecked(ratelimit_t *ratelimit) {
    if (ratelimit == NULL) return 0;
    return ratelimitEffectiveInterval(ratelimit) || runConf->globals.bReduceRepeatMsgs;
}


/* add a message to a ratelimiter/multisubmit structure.
 * ratelimiting is automatically handled according to the ratelimit
 * settings.
 * if pMultiSub == NULL, a single-message enqueue happens (under reconsideration)
 */
/**
 * @brief Implementation of ::ratelimitAddMsg().
 *
 * Bridges the limiter with the multi-submit batching helper while keeping
 * the caller oblivious to repeat messages.
 */
rsRetVal ratelimitAddMsg(ratelimit_t *ratelimit, multi_submit_t *pMultiSub, smsg_t *pMsg) {
    rsRetVal localRet;
    smsg_t *repMsg;
    DEFiRet;

    localRet = ratelimitMsg(ratelimit, pMsg, &repMsg);
    if (pMultiSub == NULL) {
        if (repMsg != NULL) CHKiRet(submitMsg2(repMsg));
        CHKiRet(localRet);
        CHKiRet(submitMsg2(pMsg));
    } else {
        if (repMsg != NULL) {
            pMultiSub->ppMsgs[pMultiSub->nElem++] = repMsg;
            if (pMultiSub->nElem == pMultiSub->maxElem) CHKiRet(multiSubmitMsg2(pMultiSub));
        }
        CHKiRet(localRet);
        if (pMsg->iLenRawMsg > glblGetMaxLine(runConf)) {
            /* oversize message needs special processing. We keep
             * at least the previous batch as batch...
             */
            if (pMultiSub->nElem > 0) {
                CHKiRet(multiSubmitMsg2(pMultiSub));
            }
            CHKiRet(submitMsg2(pMsg));
            FINALIZE;
        }
        pMultiSub->ppMsgs[pMultiSub->nElem++] = pMsg;
        if (pMultiSub->nElem == pMultiSub->maxElem) CHKiRet(multiSubmitMsg2(pMultiSub));
    }

finalize_it:
    RETiRet;
}


/**
 * @brief Implementation of ::ratelimitNew().
 *
 * Constructs a legacy inline-configured limiter with a human-readable
 * diagnostic name.
 */
rsRetVal ratelimitNew(ratelimit_t **ppThis, const char *modname, const char *dynname) {
    ratelimit_t *pThis = NULL;
    char namebuf[256];
    DEFiRet;

    if (ppThis == NULL) {
        ABORT_FINALIZE(RS_RET_INVALID_PARAMS);
    }

    CHKmalloc(pThis = calloc(1, sizeof(*pThis)));
    pThis->cfg = NULL;
    pThis->interval_override = 0;
    pThis->burst_override = 0;
    pThis->severity_override = 0;
    pThis->has_override = 0;

    if (modname == NULL) modname = "*ERROR:MODULE NAME MISSING*";

    if (dynname == NULL) {
        CHKmalloc(pThis->name = strdup(modname));
    } else {
        snprintf(namebuf, sizeof(namebuf), "%s[%s]", modname, dynname);
        namebuf[sizeof(namebuf) - 1] = '\0';
        CHKmalloc(pThis->name = strdup(namebuf));
    }

    DBGPRINTF("ratelimit:%s:new ratelimiter\n", pThis->name);
    *ppThis = pThis;
    pThis = NULL;

finalize_it:
    if (pThis != NULL) {
        free(pThis->name);
        free(pThis);
    }
    RETiRet;
}
/**
 * @brief Implementation of ::ratelimitNewFromConfig().
 *
 * Binds a freshly allocated limiter to an immutable configuration entry
 * and gives it a meaningful diagnostic name.
 */
rsRetVal ratelimitNewFromConfig(ratelimit_t **ppThis,
                                const ratelimit_config_t *const cfg,
                                const char *const instance_name) {
    ratelimit_t *pThis = NULL;
    char *name = NULL;
    DEFiRet;

    if (ppThis == NULL || cfg == NULL) {
        ABORT_FINALIZE(RS_RET_INVALID_PARAMS);
    }

    CHKmalloc(pThis = calloc(1, sizeof(*pThis)));
    pThis->cfg = cfg;
    pThis->interval_override = 0;
    pThis->burst_override = 0;
    pThis->severity_override = 0;
    pThis->has_override = 0;

    name = ratelimitBuildInstanceName(cfg, instance_name);
    if (name == NULL) {
        ABORT_FINALIZE(RS_RET_OUT_OF_MEMORY);
    }
    pThis->name = name;
    name = NULL;

    DBGPRINTF("ratelimit:%s:new ratelimiter\n", pThis->name);
    *ppThis = pThis;
    pThis = NULL;

finalize_it:
    free(name);
    if (pThis != NULL) {
        free(pThis->name);
        free(pThis);
    }
    RETiRet;
}


/* enable thread-safe operations mode. This make sure that
 * a single ratelimiter can be called from multiple threads. As
 * this causes some overhead and is not always required, it needs
 * to be explicitely enabled. This operation cannot be undone
 * (think: why should one do that???)
 */
/**
 * @brief Implementation of ::ratelimitSetThreadSafe().
 *
 * Initialises the mutex that protects shared counters so a single limiter
 * instance can be shared across worker threads.
 */
void ratelimitSetThreadSafe(ratelimit_t *ratelimit) {
    ratelimit->bThreadSafe = 1;
    pthread_mutex_init(&ratelimit->mut, NULL);
}
/**
 * @brief Implementation of ::ratelimitSetLinuxLike().
 *
 * Reconfigures the limiter with inline interval/burst values emulating the
 * kernel rate-limiter defaults.
 */
void ratelimitSetLinuxLike(ratelimit_t *ratelimit, unsigned int interval, unsigned int burst) {
    if (ratelimit == NULL) return;
    ratelimit->cfg = NULL;
    ratelimit->interval_override = interval;
    ratelimit->burst_override = burst;
    ratelimit->done = 0;
    ratelimit->missed = 0;
    ratelimit->begin = 0;
    ratelimit->has_override = 1;
}
/**
 * @brief Implementation of ::ratelimitSetNoTimeCache().
 *
 * Enables source-provided timestamps by forcing real-time queries instead
 * of relying on cached dispatcher time.
 */
void ratelimitSetNoTimeCache(ratelimit_t *ratelimit) {
    ratelimit->bNoTimeCache = 1;
    pthread_mutex_init(&ratelimit->mut, NULL);
}
/**
 * @brief Implementation of ::ratelimitSetSeverity().
 *
 * Stores the legacy inline severity override and marks the instance as
 * detached from shared configuration state.
 */
void ratelimitSetSeverity(ratelimit_t *ratelimit, intTiny severity) {
    if (ratelimit == NULL) return;
    ratelimit->cfg = NULL;
    ratelimit->severity_override = severity;
    ratelimit->has_override = 1;
}

/**
 * @brief Implementation of ::ratelimitDestruct().
 *
 * Ensures any pending repeat message summary is flushed before freeing
 * the limiter state.
 */
void ratelimitDestruct(ratelimit_t *ratelimit) {
    if (ratelimit == NULL) return;
    ratelimitDropSuppressedIfAny(ratelimit);
    tellLostCnt(ratelimit);
    if (ratelimit->bThreadSafe) pthread_mutex_destroy(&ratelimit->mut);
    free(ratelimit->name);
    free(ratelimit);
}

/**
 * @brief Implementation of ::ratelimitModExit().
 *
 * Releases the shared interfaces acquired in ::ratelimitModInit().
 */
void ratelimitModExit(void) {
    objRelease(datetime, CORE_COMPONENT);
    objRelease(glbl, CORE_COMPONENT);
    objRelease(parser, CORE_COMPONENT);
}

/**
 * @brief Implementation of ::ratelimitModInit().
 *
 * Registers the helper interfaces required during runtime operation so the
 * limiter can parse messages and write diagnostics.
 */
rsRetVal ratelimitModInit(void) {
    DEFiRet;
    CHKiRet(objGetObjInterface(&obj));
    CHKiRet(objUse(glbl, CORE_COMPONENT));
    CHKiRet(objUse(datetime, CORE_COMPONENT));
    CHKiRet(objUse(parser, CORE_COMPONENT));
finalize_it:
    RETiRet;
}
