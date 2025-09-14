/**
 * @file conf_yaml_poc.c
 * @brief Proof-of-concept YAML configuration parser.
 *
 * This prototype reads `modules` and `inputs` sections from a YAML file
 * and converts them into `struct cnfobj` entries processed via
 * ::cnfDoObj.  It is part of the rsyslog project and released under
 * the terms of the Apache License 2.0.
 */
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yaml.h>
#include <libestr.h>
#include "grammar/rainerscript.h"
#include "grammar/parserif.h"
#include "rsyslog.h"

/**
 * @brief Append a key/value pair to a name-value list.
 *
 * @param lst Existing list or NULL.
 * @param name Key name to insert.
 * @param val Value associated with @p name.
 * @return Head of the updated list.
 */
static struct nvlst *add_kv(struct nvlst *lst, const char *name, const char *val) {
    struct nvlst *n = nvlstNewStr(es_newStrFromCStr(val, strlen(val)));
    if (n == NULL) {
        return lst;
    }
    n->name = es_newStrFromCStr(name, strlen(name));
    n->next = NULL;
    if (lst == NULL) {
        return n;
    }
    struct nvlst *p = lst;
    while (p->next != NULL) {
        p = p->next;
    }
    p->next = n;
    return lst;
}

/**
 * @brief Create a configuration object that loads a module.
 *
 * @param name Module name as specified in the YAML file.
 */
static void process_module(const char *name) {
    struct nvlst *lst = NULL;
    lst = add_kv(lst, "load", name);
    struct cnfobj *o = cnfobjNew(CNFOBJ_MODULE, lst);
    cnfDoObj(o);
    cnfobjDestruct(o);
    printf("module %s loaded\n", name);
}

/**
 * @brief Create a configuration object for an input stanza.
 *
 * The input is described by the mapping @p map. Each scalar key/value
 * pair becomes an entry in the ::nvlst list. The resulting object is
 * passed to ::cnfDoObj for further processing.
 *
 * @param doc Parsed YAML document providing node storage.
 * @param map Mapping node describing a single input.
 */
static void process_input(yaml_document_t *doc, yaml_node_t *map) {
    struct nvlst *lst = NULL;
    yaml_node_pair_t *pair;
    const char *type = NULL;
    for (pair = map->data.mapping.pairs.start; pair < map->data.mapping.pairs.top; ++pair) {
        yaml_node_t *key = yaml_document_get_node(doc, pair->key);
        yaml_node_t *val = yaml_document_get_node(doc, pair->value);
        if (key->type != YAML_SCALAR_NODE || val->type != YAML_SCALAR_NODE) {
            continue;
        }
        const char *k = (const char *)key->data.scalar.value;
        const char *v = (const char *)val->data.scalar.value;
        lst = add_kv(lst, k, v);
        if (strcmp(k, "type") == 0) {
            type = v;
        }
    }
    struct cnfobj *o = cnfobjNew(CNFOBJ_INPUT, lst);
    cnfDoObj(o);
    cnfobjDestruct(o);
    if (type != NULL) {
        printf("input %s added\n", type);
    } else {
        printf("input added\n");
    }
}

/**
 * @brief Entry point that drives YAML configuration parsing.
 *
 * @param argc Number of command-line arguments.
 * @param argv Argument vector. Expects a single YAML file path.
 * @retval 0 on success.
 * @retval 1 on failure.
 */
int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <file>\n", argv[0]);
        return 1;
    }

    if (rsrtInit(NULL, NULL) != RS_RET_OK) {
        fprintf(stderr, "runtime init failed\n");
        return 1;
    }

    FILE *fh = fopen(argv[1], "r");
    if (fh == NULL) {
        perror("fopen");
        return 1;
    }

    yaml_parser_t parser;
    yaml_document_t doc;
    if (!yaml_parser_initialize(&parser)) {
        fprintf(stderr, "yaml parser init failed\n");
        fclose(fh);
        return 1;
    }
    yaml_parser_set_input_file(&parser, fh);
    if (!yaml_parser_load(&parser, &doc)) {
        fprintf(stderr, "yaml parse failed\n");
        yaml_parser_delete(&parser);
        fclose(fh);
        return 1;
    }

    yaml_node_t *root = yaml_document_get_root_node(&doc);
    if (root != NULL && root->type == YAML_MAPPING_NODE) {
        yaml_node_pair_t *pair;
        for (pair = root->data.mapping.pairs.start; pair < root->data.mapping.pairs.top; ++pair) {
            yaml_node_t *key = yaml_document_get_node(&doc, pair->key);
            yaml_node_t *val = yaml_document_get_node(&doc, pair->value);
            if (key->type != YAML_SCALAR_NODE) {
                continue;
            }
            const char *k = (const char *)key->data.scalar.value;
            if (strcmp(k, "modules") == 0 && val->type == YAML_SEQUENCE_NODE) {
                yaml_node_item_t *item;
                for (item = val->data.sequence.items.start; item < val->data.sequence.items.top; ++item) {
                    yaml_node_t *mod = yaml_document_get_node(&doc, *item);
                    if (mod->type == YAML_SCALAR_NODE) {
                        process_module((const char *)mod->data.scalar.value);
                    }
                }
            } else if (strcmp(k, "inputs") == 0 && val->type == YAML_SEQUENCE_NODE) {
                yaml_node_item_t *item;
                for (item = val->data.sequence.items.start; item < val->data.sequence.items.top; ++item) {
                    yaml_node_t *inp = yaml_document_get_node(&doc, *item);
                    if (inp->type == YAML_MAPPING_NODE) {
                        process_input(&doc, inp);
                    }
                }
            }
        }
    }

    yaml_document_delete(&doc);
    yaml_parser_delete(&parser);
    fclose(fh);
    rsrtExit();
    return 0;
}
