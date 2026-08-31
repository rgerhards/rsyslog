/*
 * Helpable bounded ready-token queue for the ConcurrentArray prototype.
 *
 * This private interface deliberately carries only integral lane tokens.  It
 * does not expose message, plugin, or public queue ABI types.
 */
#ifndef INCLUDED_CONCURRENT_ARRAY_READY_SCQ_H
#define INCLUDED_CONCURRENT_ARRAY_READY_SCQ_H

#include <stddef.h>
#include <stdint.h>

typedef struct ca_ready_scq_s ca_ready_scq_t;

typedef enum ca_ready_scq_result_e {
    CA_READY_SCQ_OK = 0,
    CA_READY_SCQ_EMPTY,
    CA_READY_SCQ_FULL,
    CA_READY_SCQ_OVERFLOW,
    CA_READY_SCQ_UNSUPPORTED,
    CA_READY_SCQ_BUSY,
    CA_READY_SCQ_INVALID,
    CA_READY_SCQ_NOMEM
} ca_ready_scq_result_t;

/* Creation requires lock-free 64-bit atomics, capacity 1..65535, and tokens
 * no greater than ca_ready_scq_token_max() (currently UINT16_MAX). */
int ca_ready_scq_is_lock_free(void);
uint64_t ca_ready_scq_token_max(void);
ca_ready_scq_result_t ca_ready_scq_create(size_t capacity, ca_ready_scq_t **queue);
ca_ready_scq_result_t ca_ready_scq_try_enqueue(ca_ready_scq_t *queue, uint64_t token);
ca_ready_scq_result_t ca_ready_scq_try_dequeue(ca_ready_scq_t *queue, uint64_t *token);
size_t ca_ready_scq_capacity(const ca_ready_scq_t *queue);
/* Includes admitted/unpublished and out-of-order completed tickets until the
 * contiguous reclaim frontier catches up; it never exceeds capacity. */
size_t ca_ready_scq_reserved(const ca_ready_scq_t *queue);
/* The caller must first stop/join all threads that can enter this object. */
ca_ready_scq_result_t ca_ready_scq_destroy(ca_ready_scq_t *queue);

#ifdef CA_READY_SCQ_TESTING
typedef enum ca_ready_scq_test_point_e {
    CA_READY_SCQ_TEST_ENQUEUE_AFTER_RESERVE = 1,
    CA_READY_SCQ_TEST_ENQUEUE_BEFORE_CELL_LOAD,
    CA_READY_SCQ_TEST_ENQUEUE_BEFORE_PUBLISH_CAS,
    CA_READY_SCQ_TEST_ENQUEUE_AFTER_PUBLISH,
    CA_READY_SCQ_TEST_DEQUEUE_AFTER_CLAIM,
    CA_READY_SCQ_TEST_DEQUEUE_BEFORE_HELP_CAS,
    CA_READY_SCQ_TEST_DEQUEUE_AFTER_HELP
} ca_ready_scq_test_point_t;

typedef void (*ca_ready_scq_test_hook_t)(ca_ready_scq_test_point_t point, uint64_t ticket, void *context);

void ca_ready_scq_test_set_hook(ca_ready_scq_t *queue, ca_ready_scq_test_hook_t hook, void *context);
ca_ready_scq_result_t ca_ready_scq_test_seed_empty(ca_ready_scq_t *queue, uint64_t ticket_base);
uint64_t ca_ready_scq_test_ticket_limit(const ca_ready_scq_t *queue);
#endif

#endif
