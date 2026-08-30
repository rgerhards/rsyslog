/* SPDX-License-Identifier: Apache-2.0 */

#ifndef INCLUDED_CONCURRENT_ARRAY_H
#define INCLUDED_CONCURRENT_ARRAY_H

#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>
#include <time.h>

/*
 * Private prototype API for candidate ConcurrentArray stores.
 *
 * This header is deliberately not installed and does not contain rsyslog
 * message types. The qqueue and execution-engine adapters supply their owned
 * message pointers at this boundary without changing smsg_t or multi_submit_t.
 *
 * Ownership: a successfully published pointer belongs to the queue until a
 * claim is completed with COMMIT or DISCARD.  RETRY keeps queue ownership.
 * Capacity: reservations, unused lease credits, published messages, and
 * claimed messages all consume the exact configured message count.
 */

typedef struct ca_queue ca_queue_t;
typedef struct ca_slot_meta ca_slot_meta_t;

/* Bind one queue-lifetime admission shard to a stable worker thread. Destroy
 * refuses while bindings live, so every worker that may overlap destruction
 * must bind before the queue becomes destroyable and unbind after its last
 * call. Unbound standalone callers use provisional TLS-modulo sharding, are
 * not guaranteed unique slots, and must not overlap ca_destroy(). */
typedef struct ca_lifecycle_binding {
    ca_queue_t *queue;
    size_t slot;
    _Atomic unsigned activations;
    unsigned active : 1;
    unsigned implicit_activation : 1;
} ca_lifecycle_binding_t;

/* A bound worker may temporarily activate another explicitly owned queue
 * binding. Deactivation restores the previous binding, so target operations
 * nest over the source queue without falling back to provisional TLS-modulo
 * slots. Dynamic-routing adapters bind and unbind these scopes within one
 * source batch; the generic core does not retain them. */
typedef struct ca_lifecycle_scope {
    ca_lifecycle_binding_t *binding;
    ca_lifecycle_binding_t *previous;
    unsigned active : 1;
} ca_lifecycle_scope_t;

typedef enum ca_status {
    CA_OK = 0,
    CA_PARTIAL,
    CA_FULL,
    CA_EMPTY,
    CA_CLOSED,
    CA_BUSY,
    CA_TIMED_OUT,
    CA_INVALID,
    CA_NO_MEMORY
} ca_status_t;

typedef enum ca_core_kind { CA_CORE_SPARSE_LANES = 1, CA_CORE_BBQ } ca_core_kind_t;

typedef enum ca_completion_state {
    CA_COMPLETE_COMMIT = 0,
    CA_COMPLETE_RETRY,
    CA_COMPLETE_DISCARD
} ca_completion_state_t;

typedef enum ca_quiesce_mode { CA_QUIESCE_DRAIN = 0, CA_QUIESCE_DISCARD } ca_quiesce_mode_t;

typedef void (*ca_dispose_fn)(void *item, ca_completion_state_t state, void *user);

typedef struct ca_config {
    ca_core_kind_t core;
    size_t capacity;
    unsigned consumers;
    ca_dispose_fn dispose;
    void *dispose_user;
} ca_config_t;

typedef struct ca_producer {
    ca_queue_t *queue;
    /* Candidate-private stable producer identity. */
    void *private_state;
    uint32_t lane_index;
    uint64_t lane_generation;
    _Atomic size_t outstanding;
    unsigned active : 1;
    unsigned fallback : 1;
} ca_producer_t;

typedef struct ca_reservation {
    ca_queue_t *queue;
    ca_producer_t *owner;
    uint32_t lane_index;
    uint64_t lane_generation;
    size_t count;
    void *prepared_chunks;
    size_t prepared_chunk_count;
    unsigned active : 1;
    unsigned prepared : 1;
} ca_reservation_t;

typedef struct ca_credit_lease {
    ca_queue_t *queue;
    ca_producer_t *owner;
    uint32_t lane_index;
    uint64_t lane_generation;
    size_t unused;
    size_t speculative_unused;
    unsigned active : 1;
} ca_credit_lease_t;

typedef struct ca_builder {
    ca_queue_t *queue;
    ca_producer_t *owner;
    uint32_t lane_index;
    uint64_t lane_generation;
    void *inline_item;
    void **items;
    size_t count;
    size_t allocated;
    void *prepared_chunks;
    size_t prepared_chunk_count;
    unsigned active : 1;
    unsigned prepared : 1;
} ca_builder_t;

typedef struct ca_claim_item {
    void *item;
    /* Private fields.  Callers must preserve them until ca_complete(). */
    ca_slot_meta_t *slot;
    uint64_t ordinal;
    unsigned was_retry : 1;
} ca_claim_item_t;

typedef struct ca_claim {
    ca_queue_t *queue;
    ca_claim_item_t *items;
    size_t count;
    size_t capacity;
    uint32_t lane_index;
    uint64_t lane_generation;
    unsigned active : 1;
} ca_claim_t;

typedef struct ca_capacity_snapshot {
    size_t capacity;
    size_t available;
    size_t speculative_unused;
    size_t in_flight;
    uint32_t epoch;
    unsigned accepting : 1;
    unsigned claiming : 1;
} ca_capacity_snapshot_t;

typedef struct ca_diagnostics {
    uint64_t capacity_attempts;
    uint64_t capacity_failures;
    uint64_t cas_retries;
    uint64_t faa_operations;
    uint64_t publish_calls;
    uint64_t published_items;
    uint64_t largest_publication;
    uint64_t claim_calls;
    uint64_t claimed_items;
    uint64_t largest_claim;
    uint64_t ready_enqueues;
    uint64_t ready_dequeues;
    uint64_t ready_retries;
    uint64_t dedicated_publications;
    uint64_t fallback_publications;
    uint64_t chunks_allocated;
    uint64_t chunks_freed;
    uint64_t chunks_live;
    uint64_t chunks_pooled;
    uint64_t wake_requests;
    uint64_t sleeps;
    uint64_t retry_barriers;
} ca_diagnostics_t;

ca_status_t ca_create(const ca_config_t *config, ca_queue_t **queue);
ca_status_t ca_destroy(ca_queue_t *queue);

ca_status_t ca_lifecycle_bind(ca_queue_t *queue, ca_lifecycle_binding_t *binding);
ca_status_t ca_lifecycle_unbind(ca_lifecycle_binding_t *binding);
ca_status_t ca_lifecycle_activate(ca_lifecycle_binding_t *binding, ca_lifecycle_scope_t *scope);
ca_status_t ca_lifecycle_deactivate(ca_lifecycle_scope_t *scope);

ca_status_t ca_producer_register(ca_queue_t *queue, uint64_t stable_key, ca_producer_t *producer);
ca_status_t ca_producer_register_fallback(ca_queue_t *queue, size_t fallback_index, ca_producer_t *producer);
ca_status_t ca_producer_release(ca_producer_t *producer);

ca_status_t ca_reserve(ca_queue_t *queue, ca_producer_t *producer, size_t wanted, ca_reservation_t *reservation);
ca_status_t ca_prepare_reserved(ca_reservation_t *reservation);
ca_status_t ca_commit_prepared(ca_reservation_t *reservation, void *const *items);
ca_status_t ca_publish_reserved(ca_reservation_t *reservation, void *const *items);
void ca_cancel_reservation(ca_reservation_t *reservation);

ca_status_t ca_submit_one(ca_queue_t *queue, ca_producer_t *producer, void *item);
ca_status_t ca_submit_span(
    ca_queue_t *queue, ca_producer_t *producer, void *const *items, size_t count, size_t *accepted);

ca_status_t ca_credit_acquire(ca_queue_t *queue, ca_producer_t *producer, size_t wanted, ca_credit_lease_t *lease);
ca_status_t ca_credit_submit_span(ca_credit_lease_t *lease, void *const *items, size_t count, size_t *accepted);
void ca_credit_release(ca_credit_lease_t *lease);

ca_status_t ca_builder_begin(ca_queue_t *queue, ca_producer_t *producer, ca_builder_t *builder);
ca_status_t ca_builder_append(
    ca_builder_t *builder, ca_credit_lease_t *lease, void *const *items, size_t count, size_t *accepted);
ca_status_t ca_builder_prepare(ca_builder_t *builder);
ca_status_t ca_builder_commit(ca_builder_t *builder);
ca_status_t ca_builder_publish(ca_builder_t *builder);
void ca_builder_cancel(ca_builder_t *builder);

ca_status_t ca_claim_up_to(ca_queue_t *queue, ca_claim_t *claim, ca_claim_item_t *items, size_t maximum);
ca_status_t ca_complete(ca_claim_t *claim, const ca_completion_state_t *states);
/* Claim ownership must end in complete or return_claim. Asynchronous pthread
 * cancellation is prohibited around core calls.  A deferred-cancellation
 * caller must keep cancellation disabled from ca_claim_up_to() until it has
 * installed cleanup that calls ca_return_claim(); this retries every item in
 * original lane order. */
ca_status_t ca_return_claim(ca_claim_t *claim);

void ca_capacity_read(const ca_queue_t *queue, ca_capacity_snapshot_t *snapshot);
uint32_t ca_epoch(const ca_queue_t *queue);
ca_status_t ca_wait_epoch(ca_queue_t *queue, uint32_t observed, const struct timespec *absolute_deadline);
uint32_t ca_capacity_epoch(const ca_queue_t *queue);
ca_status_t ca_wait_capacity_epoch(ca_queue_t *queue, uint32_t observed, const struct timespec *absolute_deadline);
/* Control-plane wake for shutdown/state changes. Normal publication uses the
 * core's proportional wake policy instead. */
void ca_interrupt_waiters(ca_queue_t *queue);
ca_status_t ca_quiesce(ca_queue_t *queue, ca_quiesce_mode_t mode, const struct timespec *absolute_deadline);
void ca_diagnostics_read(const ca_queue_t *queue, ca_diagnostics_t *diagnostics);

/* Standalone shape queries used by deterministic contract tests. */
size_t ca_dedicated_lane_limit(const ca_queue_t *queue);
size_t ca_fallback_lane_count(const ca_queue_t *queue);
size_t ca_ready_ring_capacity(const ca_queue_t *queue);

#if defined(ENABLE_IMDIAG) || defined(CA_TESTING)
/* Compiled-out deterministic fault injection for qqueue ownership tests. It
 * rejects the next count chunk acquisitions, including pool reuse, so the
 * ownership oracle does not depend on earlier lane history. */
void ca_test_fail_next_chunk_allocations(ca_queue_t *queue, size_t count);
#endif

#ifdef CA_TESTING
/* Deterministic white-box pauses used only by the standalone unit target. */
enum {
    CA_TEST_ROLE_HANDLE = 0,
    CA_TEST_ROLE_RESERVE,
    CA_TEST_ROLE_PUBLISH,
    CA_TEST_ROLE_CLAIM,
    CA_TEST_ROLE_COMPLETE,
    CA_TEST_ROLE_WAIT,
    CA_TEST_ROLE_INSPECT
};
void ca_test_pause_role(ca_queue_t *queue, int role);
int ca_test_role_entered(ca_queue_t *queue);
void ca_test_release_role(ca_queue_t *queue);
void ca_test_pause_before_lifecycle_cas(ca_queue_t *queue);
int ca_test_before_lifecycle_cas_entered(ca_queue_t *queue);
void ca_test_release_before_lifecycle_cas(ca_queue_t *queue);
size_t ca_test_waiter_count(ca_queue_t *queue);
size_t ca_test_work_sleepers(ca_queue_t *queue);
size_t ca_test_capacity_sleepers(ca_queue_t *queue);
ca_status_t ca_test_seed_empty_lane(ca_queue_t *queue, ca_producer_t *producer, uint64_t ordinal);
void ca_test_pause_normal_claim(ca_queue_t *queue);
int ca_test_normal_claim_entered(ca_queue_t *queue);
void ca_test_release_normal_claim(ca_queue_t *queue);
void ca_test_fail_chunk_alloc_after(ca_queue_t *queue, size_t successful_allocations);
size_t ca_test_chunks_live(ca_queue_t *queue);
size_t ca_test_chunks_pooled(ca_queue_t *queue);
size_t ca_test_builder_item_allocations(ca_queue_t *queue);
int ca_test_accepting(ca_queue_t *queue);
int ca_test_destroying(ca_queue_t *queue);
size_t ca_test_lifecycle_slot(ca_queue_t *queue);
size_t ca_test_lifecycle_bytes(ca_queue_t *queue);
size_t ca_test_lifecycle_alignment(ca_queue_t *queue);
int ca_test_lifecycle_is_aligned(ca_queue_t *queue);
#endif

#endif
