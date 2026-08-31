/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Sparse-lane ConcurrentArray prototype.
 *
 * Concurrency & locking
 * ---------------------
 * Queue lifecycle admission uses one cache-line-separated slot per worker
 * shard.  A slot's single atomic word packs a closed bit and reader count;
 * quiescence closes every slot and waits its readers before changing selective
 * operation flags. Bound workers provide the queue-storage lifetime contract:
 * destroy refuses while a binding lives. Unbound prototype calls require the
 * caller to exclude destruction. There is no queue-wide pthread storage mutex.
 *
 * Each lane owns an ordinal log.  Ordinal zero uses the embedded singleton;
 * subsequent entries live in lazy, reusable 64-pointer chunks.  One short
 * per-lane atomic-flag section publishes, reserves claims, installs ordered
 * retry barriers, advances the final frontier, and recycles completed chunks.
 * Claims leave that section before executing, so multiple claims from one lane
 * may be in flight concurrently.  Retry is ordered by original lane ordinal
 * and blocks every later normal claim after its linearization point.
 *
 * The ready-token implementation is isolated in concurrent_array_ready_scq;
 * this file does not implement or modify its algorithm.
 */

#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif

#include "concurrent_array_internal.h"
#include "concurrent_array_ready_scq.h"

/* The candidate core is intentionally written as C11. rsyslog's historical
 * warning profile still diagnoses declarations after statements as a C90
 * style error, so keep that style-only warning local to this private source. */
#if defined(__GNUC__)
    #pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
#endif

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <stdalign.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(__linux__) && !defined(CA_FORCE_PTHREAD_WAIT)
    #include <linux/futex.h>
    #include <sys/syscall.h>
    #include <unistd.h>
    #define CA_USE_FUTEX 1
#else
    #define CA_USE_FUTEX 0
#endif

#define CA_CHUNK_ITEMS 64U
#define CA_PRODUCER_CLOSED ((size_t)1 << (sizeof(size_t) * CHAR_BIT - 1))
#define CA_PRODUCER_REF_MASK (CA_PRODUCER_CLOSED - 1)
#define CA_LEASE_MAX 64U
#define CA_LIFECYCLE_CLOSED (UINT64_C(1) << 63)
#define CA_LIFECYCLE_REFS (CA_LIFECYCLE_CLOSED - 1)

enum ca_slot_state { CA_SLOT_UNUSED = 0, CA_SLOT_READY, CA_SLOT_CLAIMED, CA_SLOT_RETRY_READY, CA_SLOT_TERMINAL };

enum ca_lifecycle_role {
    CA_ROLE_HANDLE = 0,
    CA_ROLE_RESERVE,
    CA_ROLE_PUBLISH,
    CA_ROLE_CLAIM,
    CA_ROLE_COMPLETE,
    CA_ROLE_WAIT,
    CA_ROLE_INSPECT,
    CA_ROLE_COUNT
};

struct ca_lane;
struct ca_chunk;

struct ca_slot_meta {
    _Atomic unsigned state;
    uint8_t offset;
    ca_slot_meta_t *retry_next;
};

struct ca_chunk {
    struct ca_chunk *next;
    struct ca_chunk *pool_next;
    uint64_t base;
    uint64_t slab_index;
    uint32_t generation;
    _Atomic unsigned terminal_count;
    void *messages[CA_CHUNK_ITEMS];
    ca_slot_meta_t slots[CA_CHUNK_ITEMS];
};

struct ca_lifecycle_slot {
    alignas(64) _Atomic uint64_t state;
    _Atomic unsigned bound;
    unsigned char padding[64 - sizeof(_Atomic uint64_t) - sizeof(_Atomic unsigned)];
};

_Static_assert(sizeof(struct ca_lifecycle_slot) == 64, "lifecycle slots must occupy one cache line");

enum ca_token_state { CA_TOKEN_ABSENT = 0, CA_TOKEN_QUEUED, CA_TOKEN_OWNED };

struct ca_lane {
    struct sparse_queue *queue;
    uint32_t index;
    uint64_t generation;
    unsigned fallback : 1;
    atomic_flag gate;
    _Atomic unsigned assigned;
    unsigned reuse_pending : 1;
    _Atomic unsigned token_state;
    uint64_t published_tail;
    uint64_t claim_cursor;
    uint64_t final_frontier;
    void *inline_message;
    ca_slot_meta_t inline_slot;
    struct ca_chunk *chunks_head;
    struct ca_chunk *chunks_tail;
    struct ca_chunk *claim_hint;
    struct ca_chunk *chunk_pool;
    ca_slot_meta_t *retry_head;
    size_t retry_pending;
};

#ifdef CA_ENABLE_DIAGNOSTICS
struct ca_diag_atomic {
    _Atomic uint64_t capacity_attempts;
    _Atomic uint64_t capacity_failures;
    _Atomic uint64_t cas_retries;
    _Atomic uint64_t faa_operations;
    _Atomic uint64_t publish_calls;
    _Atomic uint64_t published_items;
    _Atomic uint64_t largest_publication;
    _Atomic uint64_t claim_calls;
    _Atomic uint64_t claimed_items;
    _Atomic uint64_t largest_claim;
    _Atomic uint64_t ready_enqueues;
    _Atomic uint64_t ready_dequeues;
    _Atomic uint64_t ready_retries;
    _Atomic uint64_t dedicated_publications;
    _Atomic uint64_t fallback_publications;
    _Atomic uint64_t chunks_allocated;
    _Atomic uint64_t chunks_freed;
    _Atomic uint64_t chunks_live;
    _Atomic uint64_t chunks_pooled;
    _Atomic uint64_t wake_requests;
    _Atomic uint64_t sleeps;
    _Atomic uint64_t retry_barriers;
};
    #define DIAG_ADD(queue, member, value) \
        atomic_fetch_add_explicit(&(queue)->diag.member, (value), memory_order_relaxed)
    #define DIAG_INC(queue, member) DIAG_ADD(queue, member, 1)
#else
    #define DIAG_ADD(queue, member, value) ((void)(queue), (void)(value))
    #define DIAG_INC(queue, member) ((void)(queue))
#endif

struct sparse_queue {
    ca_queue_t base;
    size_t capacity;
    unsigned consumers;
    size_t dedicated_limit;
    size_t fallback_count;
    size_t lane_count;
    struct ca_lane *lanes;
    _Atomic size_t dedicated_cursor;
    _Atomic size_t anonymous_counter;
    _Atomic uint64_t next_slab_index;
    _Atomic size_t available;
    _Atomic size_t speculative_unused;
    _Atomic size_t in_flight;
    _Atomic size_t live_producers;
    _Atomic size_t live_reservations;
    _Atomic size_t live_leases;
    _Atomic size_t live_builders;
    _Atomic size_t live_claims;
    _Atomic size_t live_waiters;
    _Atomic size_t live_bindings;
    _Atomic size_t chunks_live_count;
    _Atomic size_t chunks_pooled_count;
    struct ca_lifecycle_slot *lifecycle_slots;
    size_t lifecycle_slot_count;
    size_t lifecycle_bytes;
    _Atomic unsigned lifecycle_writer;
    _Atomic unsigned control_owner;
    _Atomic uint64_t epoch;
    _Atomic uint64_t capacity_epoch;
#if CA_USE_FUTEX
    _Atomic uint32_t epoch_futex;
    _Atomic uint32_t capacity_epoch_futex;
#endif
    _Atomic unsigned sleepers;
    _Atomic unsigned capacity_sleepers;
    _Atomic unsigned accepting;
    _Atomic unsigned publishing;
    _Atomic unsigned claiming;
    _Atomic unsigned waiting;
    _Atomic unsigned destroying;
    ca_ready_scq_t *ready;
    ca_dispose_fn dispose;
    void *dispose_user;
#if defined(ENABLE_IMDIAG) || defined(CA_TESTING)
    _Atomic size_t injected_chunk_alloc_failures;
#endif
#if !CA_USE_FUTEX
    pthread_mutex_t wait_mutex;
    pthread_cond_t wait_cond;
    pthread_cond_t capacity_wait_cond;
#endif
#ifdef CA_ENABLE_DIAGNOSTICS
    struct ca_diag_atomic diag;
#endif
#ifdef CA_TESTING
    _Atomic int test_pause_before_lifecycle_cas;
    _Atomic int test_before_lifecycle_cas_entered;
    _Atomic int test_before_lifecycle_cas_release;
    _Atomic int test_pause_role;
    _Atomic int test_role_entered;
    _Atomic int test_role_release;
    _Atomic int test_pause_claim;
    _Atomic int test_claim_entered;
    _Atomic int test_claim_release;
    _Atomic int test_pause_producer_pin;
    _Atomic int test_producer_pin_entered;
    _Atomic int test_producer_pin_release;
    _Atomic int test_pause_before_producer_ref;
    _Atomic int test_before_producer_ref_entered;
    _Atomic int test_before_producer_ref_release;
    _Atomic size_t test_chunk_allocations;
    _Atomic size_t test_chunk_fail_after;
    _Atomic size_t test_builder_item_allocations;
#endif
};

static _Atomic size_t ca_next_thread_slot = 0;
static _Thread_local size_t ca_thread_slot = SIZE_MAX;
static _Thread_local ca_lifecycle_binding_t *ca_bound_lifecycle = NULL;

static size_t lifecycle_slot(const struct sparse_queue *queue) {
    if (ca_bound_lifecycle != NULL && ca_bound_lifecycle->active && ca_bound_lifecycle->queue == &queue->base)
        return ca_bound_lifecycle->slot;
    if (ca_thread_slot == SIZE_MAX)
        ca_thread_slot = atomic_fetch_add_explicit(&ca_next_thread_slot, 1, memory_order_relaxed);
    return ca_thread_slot & (queue->lifecycle_slot_count - 1);
}

static struct sparse_queue *as_sparse(ca_queue_t *queue) {
    return (struct sparse_queue *)queue;
}

static size_t next_power_of_two(size_t value) {
    size_t result = 1;
    while (result < value) {
        if (result > SIZE_MAX / 2) return 0;
        result <<= 1;
    }
    return result;
}

static int checked_add_size(size_t left, size_t right, size_t *result) {
    if (right > SIZE_MAX - left) return 0;
    *result = left + right;
    return 1;
}

static int checked_mul_size(size_t left, size_t right, size_t *result) {
    if (left != 0 && right > SIZE_MAX / left) return 0;
    *result = left * right;
    return 1;
}

#ifdef CA_ENABLE_DIAGNOSTICS
static void diag_max(_Atomic uint64_t *maximum, uint64_t value) {
    uint64_t old = atomic_load_explicit(maximum, memory_order_relaxed);
    while (old < value &&
           !atomic_compare_exchange_weak_explicit(maximum, &old, value, memory_order_relaxed, memory_order_relaxed));
}
#endif

static ca_status_t lifecycle_enter(struct sparse_queue *queue, enum ca_lifecycle_role role) {
    (void)role;
    const size_t slot = lifecycle_slot(queue);
    struct ca_lifecycle_slot *lifecycle = &queue->lifecycle_slots[slot];
    for (;;) {
#ifdef CA_TESTING
        if (atomic_load_explicit(&queue->test_pause_before_lifecycle_cas, memory_order_acquire)) {
            atomic_store_explicit(&queue->test_before_lifecycle_cas_entered, 1, memory_order_release);
            while (!atomic_load_explicit(&queue->test_before_lifecycle_cas_release, memory_order_acquire))
                sched_yield();
        }
#endif
        uint64_t state = atomic_load_explicit(&lifecycle->state, memory_order_acquire);
        while ((state & CA_LIFECYCLE_CLOSED) == 0) {
            if ((state & CA_LIFECYCLE_REFS) == CA_LIFECYCLE_REFS) {
                return CA_BUSY;
            }
            if (atomic_compare_exchange_weak_explicit(&lifecycle->state, &state, state + 1, memory_order_acquire,
                                                      memory_order_relaxed)) {
#ifdef CA_TESTING
                if (atomic_load_explicit(&queue->test_pause_role, memory_order_acquire) == (int)role) {
                    atomic_store_explicit(&queue->test_role_entered, 1, memory_order_release);
                    while (!atomic_load_explicit(&queue->test_role_release, memory_order_acquire)) sched_yield();
                }
#endif
                return CA_OK;
            }
        }
        if ((state & CA_LIFECYCLE_CLOSED) != 0) {
            if (atomic_load_explicit(&queue->destroying, memory_order_acquire)) return CA_CLOSED;
            sched_yield();
        }
    }
}

static void lifecycle_exit(struct sparse_queue *queue, enum ca_lifecycle_role role) {
    (void)role;
    atomic_fetch_sub_explicit(&queue->lifecycle_slots[lifecycle_slot(queue)].state, 1, memory_order_release);
}

static int deadline_expired(const struct timespec *deadline) {
    if (deadline == NULL) return 0;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return now.tv_sec > deadline->tv_sec || (now.tv_sec == deadline->tv_sec && now.tv_nsec >= deadline->tv_nsec);
}

static ca_status_t lifecycle_writer_begin(struct sparse_queue *queue, const struct timespec *deadline) {
    for (;;) {
        unsigned expected = 0;
        if (atomic_compare_exchange_weak_explicit(&queue->lifecycle_writer, &expected, 1, memory_order_acq_rel,
                                                  memory_order_relaxed))
            break;
        if (deadline_expired(deadline)) return CA_TIMED_OUT;
        sched_yield();
    }
    for (size_t i = 0; i < queue->lifecycle_slot_count; ++i)
        atomic_fetch_or_explicit(&queue->lifecycle_slots[i].state, CA_LIFECYCLE_CLOSED, memory_order_acq_rel);
    return CA_OK;
}

static ca_status_t lifecycle_writer_wait(struct sparse_queue *queue, const struct timespec *deadline) {
    for (;;) {
        int occupied = 0;
        for (size_t i = 0; i < queue->lifecycle_slot_count; ++i) {
            struct ca_lifecycle_slot *slot = &queue->lifecycle_slots[i];
            if ((atomic_load_explicit(&slot->state, memory_order_acquire) & CA_LIFECYCLE_REFS) != 0) {
                occupied = 1;
                break;
            }
        }
        if (!occupied) return CA_OK;
        if (deadline_expired(deadline)) return CA_TIMED_OUT;
        sched_yield();
    }
}

static void lifecycle_writer_end(struct sparse_queue *queue) {
    for (size_t i = 0; i < queue->lifecycle_slot_count; ++i)
        atomic_fetch_and_explicit(&queue->lifecycle_slots[i].state, CA_LIFECYCLE_REFS, memory_order_release);
    atomic_store_explicit(&queue->lifecycle_writer, 0, memory_order_release);
}

static int control_enter(struct sparse_queue *queue) {
    unsigned expected = 0;
    return atomic_compare_exchange_strong_explicit(&queue->control_owner, &expected, 1, memory_order_acq_rel,
                                                   memory_order_acquire);
}

static void control_exit(struct sparse_queue *queue) {
    atomic_store_explicit(&queue->control_owner, 0, memory_order_release);
}

static ca_status_t sparse_lifecycle_bind(ca_queue_t *base, ca_lifecycle_binding_t *binding) {
    if (binding == NULL) return CA_INVALID;
    memset(binding, 0, sizeof(*binding));
    struct sparse_queue *queue = as_sparse(base);
    ca_status_t status = lifecycle_enter(queue, CA_ROLE_HANDLE);
    if (status != CA_OK) return status;
    if (!atomic_load_explicit(&queue->accepting, memory_order_acquire)) {
        lifecycle_exit(queue, CA_ROLE_HANDLE);
        return CA_CLOSED;
    }

    size_t slot = queue->lifecycle_slot_count;
    for (size_t i = 0; i < queue->lifecycle_slot_count; ++i) {
        unsigned expected = 0;
        if (atomic_compare_exchange_strong_explicit(&queue->lifecycle_slots[i].bound, &expected, 1,
                                                    memory_order_acq_rel, memory_order_relaxed)) {
            slot = i;
            break;
        }
    }
    if (slot == queue->lifecycle_slot_count) {
        lifecycle_exit(queue, CA_ROLE_HANDLE);
        return CA_BUSY;
    }

    binding->queue = base;
    binding->slot = slot;
    binding->active = 1;
    atomic_init(&binding->activations, 0);
    atomic_fetch_add_explicit(&queue->live_bindings, 1, memory_order_release);
    lifecycle_exit(queue, CA_ROLE_HANDLE);
    /* Preserve the original one-binding convenience for standalone callers.
     * Additional bindings remain dormant until explicitly activated. */
    if (ca_bound_lifecycle == NULL) {
        ca_bound_lifecycle = binding;
        binding->implicit_activation = 1;
        atomic_store_explicit(&binding->activations, 1, memory_order_release);
    }
    return CA_OK;
}

static ca_status_t sparse_lifecycle_unbind(ca_lifecycle_binding_t *binding) {
    if (binding == NULL || !binding->active || binding->queue == NULL) return CA_INVALID;
    struct sparse_queue *queue = as_sparse(binding->queue);
    if (binding->slot >= queue->lifecycle_slot_count) return CA_INVALID;
    unsigned activations = atomic_load_explicit(&binding->activations, memory_order_acquire);
    if (binding->implicit_activation) {
        if (ca_bound_lifecycle != binding || activations != 1) return CA_BUSY;
        ca_bound_lifecycle = NULL;
        binding->implicit_activation = 0;
        atomic_store_explicit(&binding->activations, 0, memory_order_release);
    } else if (activations != 0) {
        return CA_BUSY;
    }
    atomic_store_explicit(&queue->lifecycle_slots[binding->slot].bound, 0, memory_order_release);
    binding->active = 0;
    binding->queue = NULL;
    atomic_fetch_sub_explicit(&queue->live_bindings, 1, memory_order_release);
    return CA_OK;
}

static ca_status_t sparse_lifecycle_activate(ca_lifecycle_binding_t *binding, ca_lifecycle_scope_t *scope) {
    if (binding == NULL || scope == NULL || !binding->active || binding->queue == NULL) return CA_INVALID;
    memset(scope, 0, sizeof(*scope));
    scope->binding = binding;
    scope->previous = ca_bound_lifecycle;
    scope->active = 1;
    atomic_fetch_add_explicit(&binding->activations, 1, memory_order_acq_rel);
    ca_bound_lifecycle = binding;
    return CA_OK;
}

static ca_status_t sparse_lifecycle_deactivate(ca_lifecycle_scope_t *scope) {
    if (scope == NULL || !scope->active || scope->binding == NULL || ca_bound_lifecycle != scope->binding)
        return CA_INVALID;
    ca_bound_lifecycle = scope->previous;
    atomic_fetch_sub_explicit(&scope->binding->activations, 1, memory_order_release);
    memset(scope, 0, sizeof(*scope));
    return CA_OK;
}

static void lane_lock(struct ca_lane *lane) {
    while (atomic_flag_test_and_set_explicit(&lane->gate, memory_order_acquire)) {
        DIAG_INC(lane->queue, cas_retries);
        sched_yield();
    }
}

static void lane_unlock(struct ca_lane *lane) {
    atomic_flag_clear_explicit(&lane->gate, memory_order_release);
}

static uint64_t lane_token(const struct ca_lane *lane) {
    return lane->index;
}

static void event_signal_on(struct sparse_queue *queue,
                            _Atomic uint64_t *epoch,
#if CA_USE_FUTEX
                            _Atomic uint32_t *futex_epoch,
#endif
                            _Atomic unsigned *sleepers,
#if !CA_USE_FUTEX
                            pthread_cond_t *condition,
#endif
                            size_t wake_count) {
#if CA_USE_FUTEX
    atomic_fetch_add_explicit(epoch, 1, memory_order_release);
    atomic_fetch_add_explicit(futex_epoch, 1, memory_order_release);
    const unsigned sleeper_count = atomic_load_explicit(sleepers, memory_order_acquire);
    if (sleeper_count != 0) {
        const int requested = wake_count == SIZE_MAX || wake_count >= (size_t)INT_MAX ? INT_MAX : (int)wake_count;
        DIAG_INC(queue, wake_requests);
        (void)syscall(SYS_futex, futex_epoch, FUTEX_WAKE_PRIVATE, requested, NULL, NULL, 0);
    }
#else
    pthread_mutex_lock(&queue->wait_mutex);
    atomic_fetch_add_explicit(epoch, 1, memory_order_release);
    DIAG_INC(queue, wake_requests);
    if (wake_count == SIZE_MAX) {
        pthread_cond_broadcast(condition);
    } else {
        const unsigned sleeper_count = atomic_load_explicit(sleepers, memory_order_acquire);
        const size_t signals = wake_count < sleeper_count ? wake_count : sleeper_count;
        for (size_t i = 0; i < signals; ++i) pthread_cond_signal(condition);
    }
    pthread_mutex_unlock(&queue->wait_mutex);
#endif
}

static void event_signal(struct sparse_queue *queue, int all) {
    event_signal_on(queue, &queue->epoch,
#if CA_USE_FUTEX
                    &queue->epoch_futex,
#endif
                    &queue->sleepers,
#if !CA_USE_FUTEX
                    &queue->wait_cond,
#endif
                    all ? SIZE_MAX : 1);
}

static void capacity_event_signal(struct sparse_queue *queue, int all) {
    event_signal_on(queue, &queue->capacity_epoch,
#if CA_USE_FUTEX
                    &queue->capacity_epoch_futex,
#endif
                    &queue->capacity_sleepers,
#if !CA_USE_FUTEX
                    &queue->capacity_wait_cond,
#endif
                    all ? SIZE_MAX : 1);
}

static void capacity_event_signal_count(struct sparse_queue *queue, size_t count) {
    event_signal_on(queue, &queue->capacity_epoch,
#if CA_USE_FUTEX
                    &queue->capacity_epoch_futex,
#endif
                    &queue->capacity_sleepers,
#if !CA_USE_FUTEX
                    &queue->capacity_wait_cond,
#endif
                    count);
}

static struct ca_lane *lane_from_handle(struct sparse_queue *queue, uint32_t index, uint64_t generation) {
    if (index >= queue->lane_count) return NULL;
    struct ca_lane *lane = &queue->lanes[index];
    return lane->generation == generation ? lane : NULL;
}

static struct ca_chunk *slot_chunk(ca_slot_meta_t *slot) {
    if (slot->offset == UINT8_MAX) return NULL;
    const uintptr_t chunk_address =
        (uintptr_t)(void *)slot - offsetof(struct ca_chunk, slots) - (size_t)slot->offset * sizeof(ca_slot_meta_t);
    return (struct ca_chunk *)chunk_address;
}

static uint64_t slot_ordinal(ca_slot_meta_t *slot) {
    struct ca_chunk *chunk = slot_chunk(slot);
    return chunk == NULL ? 0 : chunk->base + slot->offset;
}

static int producer_op_enter(struct sparse_queue *queue, ca_producer_t *producer) {
#ifndef CA_TESTING
    (void)queue;
#endif
    size_t state = atomic_load_explicit(&producer->op_state, memory_order_acquire);
    for (;;) {
        if (state & CA_PRODUCER_CLOSED || (state & CA_PRODUCER_REF_MASK) == CA_PRODUCER_REF_MASK) return 0;
#ifdef CA_TESTING
        if (atomic_load_explicit(&queue->test_pause_before_producer_ref, memory_order_acquire)) {
            atomic_store_explicit(&queue->test_before_producer_ref_entered, 1, memory_order_release);
            while (!atomic_load_explicit(&queue->test_before_producer_ref_release, memory_order_acquire)) sched_yield();
        }
#endif
        if (atomic_compare_exchange_weak_explicit(&producer->op_state, &state, state + 1, memory_order_acquire,
                                                  memory_order_acquire))
            return 1;
    }
}

static void producer_op_exit(ca_producer_t *producer) {
    const size_t previous = atomic_fetch_sub_explicit(&producer->op_state, 1, memory_order_release);
    if ((previous & CA_PRODUCER_REF_MASK) == 0) abort();
}

static ca_status_t validate_producer(struct sparse_queue *queue,
                                     ca_producer_t *producer,
                                     struct ca_lane **lane_result) {
    if (producer == NULL) {
        size_t value = atomic_fetch_add_explicit(&queue->anonymous_counter, 1, memory_order_relaxed);
        DIAG_INC(queue, faa_operations);
        *lane_result = &queue->lanes[queue->dedicated_limit + (value & (queue->fallback_count - 1))];
        return CA_OK;
    }
    if (!producer_op_enter(queue, producer)) return CA_INVALID;
#ifdef CA_TESTING
    if (atomic_load_explicit(&queue->test_pause_producer_pin, memory_order_acquire)) {
        atomic_store_explicit(&queue->test_producer_pin_entered, 1, memory_order_release);
        while (!atomic_load_explicit(&queue->test_producer_pin_release, memory_order_acquire)) sched_yield();
    }
#endif
    if (!producer->active || producer->queue != &queue->base) {
        producer_op_exit(producer);
        return CA_INVALID;
    }
    struct ca_lane *lane = lane_from_handle(queue, producer->lane_index, producer->lane_generation);
    if (lane == NULL) {
        producer_op_exit(producer);
        return CA_INVALID;
    }
    *lane_result = lane;
    return CA_OK;
}

static ca_slot_meta_t *lane_slot_locked(struct ca_lane *lane, uint64_t ordinal, void ***message) {
    if (ordinal == 0) {
        if (message != NULL) *message = &lane->inline_message;
        return &lane->inline_slot;
    }
    struct ca_chunk *chunk = lane->claim_hint;
    if (chunk == NULL || ordinal < chunk->base) chunk = lane->chunks_head;
    while (chunk != NULL && (ordinal < chunk->base || ordinal - chunk->base >= CA_CHUNK_ITEMS)) chunk = chunk->next;
    if (chunk == NULL || ordinal < chunk->base) return NULL;
    lane->claim_hint = chunk;
    const size_t index = (size_t)(ordinal - chunk->base);
    if (message != NULL) *message = &chunk->messages[index];
    return &chunk->slots[index];
}

static struct ca_chunk *chunk_take_locked(struct ca_lane *lane, uint64_t base) {
#if defined(ENABLE_IMDIAG) || defined(CA_TESTING)
    size_t injected = atomic_load_explicit(&lane->queue->injected_chunk_alloc_failures, memory_order_relaxed);
    while (injected != 0 &&
           !atomic_compare_exchange_weak_explicit(&lane->queue->injected_chunk_alloc_failures, &injected, injected - 1,
                                                  memory_order_relaxed, memory_order_relaxed));
    if (injected != 0) return NULL;
#endif
    struct ca_chunk *chunk = lane->chunk_pool;
    int fresh = 0;
    if (chunk != NULL) {
        lane->chunk_pool = chunk->pool_next;
        atomic_fetch_sub_explicit(&lane->queue->chunks_pooled_count, 1, memory_order_relaxed);
        DIAG_ADD(lane->queue, chunks_pooled, UINT64_MAX);
        chunk->pool_next = NULL;
        ++chunk->generation;
        if (chunk->generation == 0) chunk->generation = 1;
    } else {
#ifdef CA_TESTING
        const size_t allocation =
            atomic_fetch_add_explicit(&lane->queue->test_chunk_allocations, 1, memory_order_relaxed);
        if (allocation >= atomic_load_explicit(&lane->queue->test_chunk_fail_after, memory_order_relaxed)) return NULL;
#endif
        chunk = calloc(1, sizeof(*chunk));
        if (chunk == NULL) return NULL;
        chunk->slab_index = atomic_fetch_add_explicit(&lane->queue->next_slab_index, 1, memory_order_relaxed);
        chunk->generation = 1;
        fresh = 1;
        atomic_fetch_add_explicit(&lane->queue->chunks_live_count, 1, memory_order_relaxed);
        DIAG_INC(lane->queue, chunks_allocated);
        DIAG_INC(lane->queue, chunks_live);
    }
    chunk->next = NULL;
    chunk->base = base;
    if (fresh)
        atomic_init(&chunk->terminal_count, 0);
    else
        atomic_store_explicit(&chunk->terminal_count, 0, memory_order_relaxed);
    for (size_t i = 0; i < CA_CHUNK_ITEMS; ++i) {
        chunk->messages[i] = NULL;
        chunk->slots[i].offset = (uint8_t)i;
        chunk->slots[i].retry_next = NULL;
        if (fresh)
            atomic_init(&chunk->slots[i].state, CA_SLOT_UNUSED);
        else
            atomic_store_explicit(&chunk->slots[i].state, CA_SLOT_UNUSED, memory_order_relaxed);
    }
    return chunk;
}

static void chunk_return_locked(struct ca_lane *lane, struct ca_chunk *chunk) {
    if (lane->chunk_pool == NULL) {
        chunk->pool_next = NULL;
        lane->chunk_pool = chunk;
        atomic_fetch_add_explicit(&lane->queue->chunks_pooled_count, 1, memory_order_relaxed);
        DIAG_INC(lane->queue, chunks_pooled);
    } else {
        free(chunk);
        atomic_fetch_sub_explicit(&lane->queue->chunks_live_count, 1, memory_order_relaxed);
        DIAG_INC(lane->queue, chunks_freed);
        DIAG_ADD(lane->queue, chunks_live, UINT64_MAX);
    }
}

static void prepared_chunks_return_locked(struct ca_lane *lane, void **head, size_t *count) {
    struct ca_chunk *chunk = *head;
    while (chunk != NULL) {
        struct ca_chunk *const next = chunk->pool_next;
        chunk->pool_next = NULL;
        chunk_return_locked(lane, chunk);
        chunk = next;
    }
    *head = NULL;
    *count = 0;
}

/* Preparation is independent of the lane's current tail.  A producer handle
 * is ordinarily one logical stream, but fallback identities intentionally
 * share a handle and the private API does not forbid overlapping prepared
 * reservations.  Reserve the worst-aligned chunk count so either prepared
 * operation can linearize first at commit without sharing a tail snapshot.
 * The inline singleton remains the actual first storage slot; its unused
 * prepared chunk is returned to the lane-local pool and reused thereafter. */
static ca_status_t prepared_chunks_take_locked(struct ca_lane *lane, size_t items, void **head, size_t *count) {
    if (items == 0 || *head != NULL || *count != 0) return CA_INVALID;
    const size_t remainder = items % CA_CHUNK_ITEMS;
    const size_t needed = items / CA_CHUNK_ITEMS + (remainder <= 1 ? 1 : 2);
    struct ca_chunk *first = NULL;
    size_t taken = 0;
    while (taken < needed) {
        struct ca_chunk *const chunk = chunk_take_locked(lane, 0);
        if (chunk == NULL) {
            prepared_chunks_return_locked(lane, (void **)&first, &taken);
            return CA_NO_MEMORY;
        }
        chunk->pool_next = first;
        first = chunk;
        ++taken;
    }
    *head = first;
    *count = taken;
    return CA_OK;
}

static void ensure_prepared_slot_locked(struct ca_lane *lane,
                                        uint64_t ordinal,
                                        void **prepared_head,
                                        size_t *prepared_count,
                                        ca_slot_meta_t **slot,
                                        void ***message) {
    if (ordinal == 0) {
        *slot = &lane->inline_slot;
        *message = &lane->inline_message;
        return;
    }
    const uint64_t base = 1 + ((ordinal - 1) / CA_CHUNK_ITEMS) * CA_CHUNK_ITEMS;
    if (lane->chunks_tail == NULL || lane->chunks_tail->base < base) {
        struct ca_chunk *chunk = *prepared_head;
        if (chunk == NULL || *prepared_count == 0) abort();
        *prepared_head = chunk->pool_next;
        --*prepared_count;
        chunk->pool_next = NULL;
        chunk->base = base;
        if (lane->chunks_tail == NULL)
            lane->chunks_head = chunk;
        else
            lane->chunks_tail->next = chunk;
        lane->chunks_tail = chunk;
        if (lane->claim_hint == NULL) lane->claim_hint = chunk;
    }
    *slot = &lane->chunks_tail->slots[(size_t)(ordinal - lane->chunks_tail->base)];
    *message = &lane->chunks_tail->messages[(size_t)(ordinal - lane->chunks_tail->base)];
}

static int lane_idle_locked(const struct ca_lane *lane) {
    return lane->published_tail == lane->final_frontier && lane->claim_cursor == lane->published_tail &&
           lane->retry_pending == 0 &&
           atomic_load_explicit(&lane->token_state, memory_order_acquire) == CA_TOKEN_ABSENT;
}

static void reset_dedicated_lane_locked(struct ca_lane *lane) {
    if (lane->fallback || !lane_idle_locked(lane)) return;
    struct ca_chunk *chunk = lane->chunks_head;
    lane->chunks_head = NULL;
    lane->chunks_tail = NULL;
    lane->claim_hint = NULL;
    while (chunk != NULL) {
        struct ca_chunk *next = chunk->next;
        chunk_return_locked(lane, chunk);
        chunk = next;
    }
    lane->published_tail = 0;
    lane->claim_cursor = 0;
    lane->final_frontier = 0;
    lane->inline_message = NULL;
    lane->inline_slot.retry_next = NULL;
    atomic_store_explicit(&lane->inline_slot.state, CA_SLOT_UNUSED, memory_order_relaxed);
    ++lane->generation;
    if (lane->generation == 0) lane->generation = 1;
    lane->reuse_pending = 0;
    atomic_store_explicit(&lane->assigned, 0, memory_order_release);
}

static void reclaim_chunks_locked(struct ca_lane *lane) {
    while (lane->chunks_head != NULL && lane->chunks_head != lane->chunks_tail) {
        struct ca_chunk *chunk = lane->chunks_head;
        if (atomic_load_explicit(&chunk->terminal_count, memory_order_acquire) != CA_CHUNK_ITEMS ||
            chunk->base > UINT64_MAX - CA_CHUNK_ITEMS || lane->claim_cursor < chunk->base + CA_CHUNK_ITEMS ||
            lane->final_frontier < chunk->base + CA_CHUNK_ITEMS)
            break;
        lane->chunks_head = chunk->next;
        if (lane->claim_hint == chunk) lane->claim_hint = lane->chunks_head;
        chunk_return_locked(lane, chunk);
    }
}

static ca_status_t ensure_slot_locked(struct ca_lane *lane, uint64_t ordinal, ca_slot_meta_t **slot, void ***message) {
    if (ordinal == 0) {
        *slot = &lane->inline_slot;
        *message = &lane->inline_message;
        return CA_OK;
    }
    const uint64_t base = 1 + ((ordinal - 1) / CA_CHUNK_ITEMS) * CA_CHUNK_ITEMS;
    if (lane->chunks_tail == NULL || lane->chunks_tail->base < base) {
        struct ca_chunk *chunk = chunk_take_locked(lane, base);
        if (chunk == NULL) return CA_NO_MEMORY;
        if (lane->chunks_tail == NULL)
            lane->chunks_head = chunk;
        else
            lane->chunks_tail->next = chunk;
        lane->chunks_tail = chunk;
        if (lane->claim_hint == NULL) lane->claim_hint = chunk;
    }
    *slot = &lane->chunks_tail->slots[(size_t)(ordinal - lane->chunks_tail->base)];
    *message = &lane->chunks_tail->messages[(size_t)(ordinal - lane->chunks_tail->base)];
    return CA_OK;
}

static int retry_runnable_locked(const struct ca_lane *lane) {
    return lane->retry_pending != 0 && lane->retry_head != NULL &&
           slot_ordinal(lane->retry_head) == lane->final_frontier &&
           atomic_load_explicit(&lane->retry_head->state, memory_order_acquire) == CA_SLOT_RETRY_READY;
}

static int lane_runnable_locked(const struct ca_lane *lane) {
    if (lane->retry_pending != 0) return retry_runnable_locked(lane);
    return lane->claim_cursor < lane->published_tail;
}

/* Enqueue precedes the ABSENT->QUEUED state transition.  A consumer that sees
 * the token in that short window changes ABSENT directly to OWNED.  Thus a
 * stopped producer cannot leave a shared ENQUEUING state which hides work,
 * while the independent SCQ makes its own reserved publication helpable. */
static void lane_enqueue_token_locked(struct ca_lane *lane) {
    ca_ready_scq_result_t result;
    do {
        result = ca_ready_scq_try_enqueue(lane->queue->ready, lane_token(lane));
        if (result == CA_READY_SCQ_FULL) {
            DIAG_INC(lane->queue, ready_retries);
            sched_yield();
        }
    } while (result == CA_READY_SCQ_FULL);
    if (result != CA_READY_SCQ_OK) abort();
    unsigned expected = CA_TOKEN_ABSENT;
    (void)atomic_compare_exchange_strong_explicit(&lane->token_state, &expected, CA_TOKEN_QUEUED, memory_order_release,
                                                  memory_order_acquire);
    if (expected != CA_TOKEN_ABSENT && expected != CA_TOKEN_OWNED) abort();
    DIAG_INC(lane->queue, ready_enqueues);
    event_signal(lane->queue, 0);
}

static void lane_make_ready_locked(struct ca_lane *lane) {
    if (!lane_runnable_locked(lane)) return;
    if (atomic_load_explicit(&lane->token_state, memory_order_acquire) == CA_TOKEN_ABSENT)
        lane_enqueue_token_locked(lane);
}

static void lane_finish_token_locked(struct ca_lane *lane) {
    const int runnable = lane_runnable_locked(lane);
    atomic_store_explicit(&lane->token_state, CA_TOKEN_ABSENT, memory_order_release);
    if (runnable) lane_enqueue_token_locked(lane);
}

static ca_status_t publish_lane(struct sparse_queue *queue, struct ca_lane *lane, void *const *items, size_t count) {
    if (items == NULL || count == 0) return CA_INVALID;
    lane_lock(lane);
    if (count > UINT64_MAX - lane->published_tail) {
        lane_unlock(lane);
        return CA_INVALID;
    }
    const uint64_t start = lane->published_tail;
    struct ca_chunk *const original_head = lane->chunks_head;
    struct ca_chunk *const original_tail = lane->chunks_tail;
    struct ca_chunk *const original_hint = lane->claim_hint;
    size_t prepared = 0;
    ca_status_t status = CA_OK;
    for (; prepared < count; ++prepared) {
        ca_slot_meta_t *slot;
        void **message;
        status = ensure_slot_locked(lane, start + prepared, &slot, &message);
        if (status != CA_OK) break;
        *message = items[prepared];
        slot->retry_next = NULL;
        atomic_store_explicit(&slot->state, CA_SLOT_READY, memory_order_relaxed);
    }
    if (status != CA_OK) {
        for (size_t i = 0; i < prepared; ++i) {
            void **message;
            ca_slot_meta_t *slot = lane_slot_locked(lane, start + i, &message);
            *message = NULL;
            atomic_store_explicit(&slot->state, CA_SLOT_UNUSED, memory_order_relaxed);
        }
        struct ca_chunk *added = original_tail == NULL ? lane->chunks_head : original_tail->next;
        if (original_tail != NULL) original_tail->next = NULL;
        lane->chunks_head = original_head;
        lane->chunks_tail = original_tail;
        lane->claim_hint = original_hint;
        while (added != NULL) {
            struct ca_chunk *next = added->next;
            chunk_return_locked(lane, added);
            added = next;
        }
        lane_unlock(lane);
        return status;
    }
    lane->published_tail += count;
    reclaim_chunks_locked(lane);
    lane_make_ready_locked(lane);
    lane_unlock(lane);
    DIAG_INC(queue, publish_calls);
    DIAG_ADD(queue, published_items, count);
#ifdef CA_ENABLE_DIAGNOSTICS
    diag_max(&queue->diag.largest_publication, count);
#endif
    if (lane->fallback)
        DIAG_INC(queue, fallback_publications);
    else
        DIAG_INC(queue, dedicated_publications);
    return CA_OK;
}

static ca_status_t publish_lane_prepared(struct sparse_queue *queue,
                                         struct ca_lane *lane,
                                         void *const *items,
                                         size_t count,
                                         void **prepared_head,
                                         size_t *prepared_count) {
    if (items == NULL || count == 0 || prepared_head == NULL || prepared_count == NULL) return CA_INVALID;
    lane_lock(lane);
    if (count > UINT64_MAX - lane->published_tail) {
        lane_unlock(lane);
        return CA_INVALID;
    }
    const uint64_t start = lane->published_tail;
    for (size_t i = 0; i < count; ++i) {
        ca_slot_meta_t *slot;
        void **message;
        ensure_prepared_slot_locked(lane, start + i, prepared_head, prepared_count, &slot, &message);
        *message = items[i];
        slot->retry_next = NULL;
        atomic_store_explicit(&slot->state, CA_SLOT_READY, memory_order_relaxed);
    }
    lane->published_tail += count;
    prepared_chunks_return_locked(lane, prepared_head, prepared_count);
    reclaim_chunks_locked(lane);
    lane_make_ready_locked(lane);
    lane_unlock(lane);
    DIAG_INC(queue, publish_calls);
    DIAG_ADD(queue, published_items, count);
#ifdef CA_ENABLE_DIAGNOSTICS
    diag_max(&queue->diag.largest_publication, count);
#endif
    if (lane->fallback)
        DIAG_INC(queue, fallback_publications);
    else
        DIAG_INC(queue, dedicated_publications);
    return CA_OK;
}

static ca_status_t reserve_capacity(struct sparse_queue *queue, size_t wanted, size_t *granted) {
    *granted = 0;
    if (wanted == 0) return CA_INVALID;
    DIAG_INC(queue, capacity_attempts);
    size_t available = atomic_load_explicit(&queue->available, memory_order_relaxed);
    for (;;) {
        if (available == 0) {
            DIAG_INC(queue, capacity_failures);
            return CA_FULL;
        }
        const size_t take = available < wanted ? available : wanted;
        if (atomic_compare_exchange_weak_explicit(&queue->available, &available, available - take, memory_order_acq_rel,
                                                  memory_order_relaxed)) {
            *granted = take;
            return take == wanted ? CA_OK : CA_PARTIAL;
        }
        DIAG_INC(queue, cas_retries);
    }
}

static void capacity_release(struct sparse_queue *queue, size_t count) {
    if (count == 0) return;
    size_t old = atomic_load_explicit(&queue->available, memory_order_relaxed);
    for (;;) {
        if (old > queue->capacity || count > queue->capacity - old) abort();
        if (atomic_compare_exchange_weak_explicit(&queue->available, &old, old + count, memory_order_release,
                                                  memory_order_relaxed))
            break;
        DIAG_INC(queue, cas_retries);
    }
    capacity_event_signal_count(queue, count);
}

static void owner_acquire(ca_producer_t *owner) {
    if (owner != NULL) atomic_fetch_add_explicit(&owner->outstanding, 1, memory_order_relaxed);
}

static void owner_release(ca_producer_t *owner) {
    if (owner != NULL) atomic_fetch_sub_explicit(&owner->outstanding, 1, memory_order_release);
}

static ca_status_t sparse_reserve(ca_queue_t *base,
                                  ca_producer_t *producer,
                                  size_t wanted,
                                  ca_reservation_t *reservation) {
    if (reservation == NULL) return CA_INVALID;
    memset(reservation, 0, sizeof(*reservation));
    struct sparse_queue *queue = as_sparse(base);
    ca_status_t status = lifecycle_enter(queue, CA_ROLE_RESERVE);
    if (status != CA_OK) return status;
    if (!atomic_load_explicit(&queue->accepting, memory_order_acquire)) {
        lifecycle_exit(queue, CA_ROLE_RESERVE);
        return CA_CLOSED;
    }
    struct ca_lane *lane;
    status = validate_producer(queue, producer, &lane);
    const int producer_pinned = status == CA_OK && producer != NULL;
    size_t granted = 0;
    if (status == CA_OK) status = reserve_capacity(queue, wanted, &granted);
    if (status == CA_OK || status == CA_PARTIAL) {
        reservation->queue = base;
        reservation->owner = producer;
        reservation->lane_index = lane->index;
        reservation->lane_generation = lane->generation;
        reservation->count = granted;
        reservation->active = 1;
        owner_acquire(producer);
        atomic_fetch_add_explicit(&queue->live_reservations, 1, memory_order_relaxed);
    }
    if (producer_pinned) producer_op_exit(producer);
    lifecycle_exit(queue, CA_ROLE_RESERVE);
    return status;
}

static void close_reservation(struct sparse_queue *queue, ca_reservation_t *reservation) {
    assert(reservation->prepared_chunks == NULL && reservation->prepared_chunk_count == 0);
    owner_release(reservation->owner);
    atomic_fetch_sub_explicit(&queue->live_reservations, 1, memory_order_release);
    reservation->active = 0;
    reservation->count = 0;
    reservation->queue = NULL;
}

static ca_status_t sparse_prepare_reserved(ca_reservation_t *reservation) {
    if (reservation == NULL || reservation->queue == NULL || !reservation->active || reservation->count == 0 ||
        reservation->prepared)
        return CA_INVALID;
    struct sparse_queue *queue = as_sparse(reservation->queue);
    ca_status_t status = lifecycle_enter(queue, CA_ROLE_PUBLISH);
    if (status != CA_OK) return status;
    if (!atomic_load_explicit(&queue->publishing, memory_order_acquire)) {
        lifecycle_exit(queue, CA_ROLE_PUBLISH);
        return CA_CLOSED;
    }
    struct ca_lane *const lane = lane_from_handle(queue, reservation->lane_index, reservation->lane_generation);
    if (lane == NULL) {
        lifecycle_exit(queue, CA_ROLE_PUBLISH);
        return CA_INVALID;
    }
    lane_lock(lane);
    status = prepared_chunks_take_locked(lane, reservation->count, &reservation->prepared_chunks,
                                         &reservation->prepared_chunk_count);
    lane_unlock(lane);
    if (status == CA_OK) reservation->prepared = 1;
    lifecycle_exit(queue, CA_ROLE_PUBLISH);
    return status;
}

static ca_status_t sparse_commit_prepared(ca_reservation_t *reservation, void *const *items) {
    if (reservation == NULL || reservation->queue == NULL || !reservation->active || !reservation->prepared ||
        reservation->count == 0 || items == NULL)
        return CA_INVALID;
    struct sparse_queue *queue = as_sparse(reservation->queue);
    ca_status_t status = lifecycle_enter(queue, CA_ROLE_PUBLISH);
    if (status != CA_OK) return status;
    if (!atomic_load_explicit(&queue->publishing, memory_order_acquire)) {
        lifecycle_exit(queue, CA_ROLE_PUBLISH);
        return CA_CLOSED;
    }
    struct ca_lane *const lane = lane_from_handle(queue, reservation->lane_index, reservation->lane_generation);
    if (lane == NULL)
        status = CA_INVALID;
    else
        status = publish_lane_prepared(queue, lane, items, reservation->count, &reservation->prepared_chunks,
                                       &reservation->prepared_chunk_count);
    if (status == CA_OK) {
        reservation->prepared = 0;
        close_reservation(queue, reservation);
    }
    lifecycle_exit(queue, CA_ROLE_PUBLISH);
    return status;
}

static ca_status_t sparse_publish_reserved(ca_reservation_t *reservation, void *const *items) {
    if (reservation == NULL || reservation->queue == NULL) return CA_INVALID;
    struct sparse_queue *queue = as_sparse(reservation->queue);
    ca_status_t status = lifecycle_enter(queue, CA_ROLE_PUBLISH);
    if (status != CA_OK) return status;
    if (!atomic_load_explicit(&queue->publishing, memory_order_acquire)) {
        lifecycle_exit(queue, CA_ROLE_PUBLISH);
        return CA_CLOSED;
    }
    struct ca_lane *lane =
        reservation->active ? lane_from_handle(queue, reservation->lane_index, reservation->lane_generation) : NULL;
    if (lane == NULL || items == NULL || reservation->count == 0)
        status = CA_INVALID;
    else if (reservation->prepared)
        status = publish_lane_prepared(queue, lane, items, reservation->count, &reservation->prepared_chunks,
                                       &reservation->prepared_chunk_count);
    else
        status = publish_lane(queue, lane, items, reservation->count);
    if (reservation->active) {
        if (reservation->prepared_chunks != NULL) {
            lane_lock(lane);
            prepared_chunks_return_locked(lane, &reservation->prepared_chunks, &reservation->prepared_chunk_count);
            lane_unlock(lane);
        }
        reservation->prepared = 0;
        if (status != CA_OK) capacity_release(queue, reservation->count);
        close_reservation(queue, reservation);
    }
    lifecycle_exit(queue, CA_ROLE_PUBLISH);
    return status;
}

static void sparse_cancel_reservation(ca_reservation_t *reservation) {
    if (reservation == NULL || reservation->queue == NULL) return;
    struct sparse_queue *queue = as_sparse(reservation->queue);
    /* The live handle is the destruction pin. Drop its release-count only
     * after every queue/lane access, so cleanup cannot fail behind a writer. */
    if (reservation->active) {
        struct ca_lane *const lane = lane_from_handle(queue, reservation->lane_index, reservation->lane_generation);
        if (lane != NULL && reservation->prepared_chunks != NULL) {
            lane_lock(lane);
            prepared_chunks_return_locked(lane, &reservation->prepared_chunks, &reservation->prepared_chunk_count);
            lane_unlock(lane);
        }
        reservation->prepared = 0;
        capacity_release(queue, reservation->count);
        close_reservation(queue, reservation);
    }
}

static ca_status_t sparse_submit_span(
    ca_queue_t *base, ca_producer_t *producer, void *const *items, size_t count, size_t *accepted) {
    if (accepted == NULL || items == NULL || count == 0) return CA_INVALID;
    *accepted = 0;
    struct sparse_queue *queue = as_sparse(base);
    ca_status_t status = lifecycle_enter(queue, CA_ROLE_PUBLISH);
    if (status != CA_OK) return status;
    if (!atomic_load_explicit(&queue->accepting, memory_order_acquire) ||
        !atomic_load_explicit(&queue->publishing, memory_order_acquire)) {
        lifecycle_exit(queue, CA_ROLE_PUBLISH);
        return CA_CLOSED;
    }
    struct ca_lane *lane;
    status = validate_producer(queue, producer, &lane);
    const int producer_pinned = status == CA_OK && producer != NULL;
    size_t granted = 0;
    if (status == CA_OK) status = reserve_capacity(queue, count, &granted);
    if (status == CA_OK || status == CA_PARTIAL) {
        const ca_status_t publish_status = publish_lane(queue, lane, items, granted);
        if (publish_status != CA_OK) {
            capacity_release(queue, granted);
            status = publish_status;
        } else {
            *accepted = granted;
        }
    }
    if (producer_pinned) producer_op_exit(producer);
    lifecycle_exit(queue, CA_ROLE_PUBLISH);
    return status;
}

static ca_status_t sparse_credit_acquire(ca_queue_t *base,
                                         ca_producer_t *producer,
                                         size_t wanted,
                                         ca_credit_lease_t *lease) {
    if (lease == NULL || wanted == 0) return CA_INVALID;
    memset(lease, 0, sizeof(*lease));
    struct sparse_queue *queue = as_sparse(base);
    ca_status_t status = lifecycle_enter(queue, CA_ROLE_RESERVE);
    if (status != CA_OK) return status;
    if (!atomic_load_explicit(&queue->accepting, memory_order_acquire)) {
        lifecycle_exit(queue, CA_ROLE_RESERVE);
        return CA_CLOSED;
    }
    struct ca_lane *lane;
    status = validate_producer(queue, producer, &lane);
    const int producer_pinned = status == CA_OK && producer != NULL;
    if (status != CA_OK) {
        lifecycle_exit(queue, CA_ROLE_RESERVE);
        return status;
    }
    if (wanted > CA_LEASE_MAX) wanted = CA_LEASE_MAX;
    const size_t limit = (queue->capacity - 1) / 2;
    size_t speculative = atomic_load_explicit(&queue->speculative_unused, memory_order_relaxed);
    size_t grant = 0;
    for (;;) {
        size_t extra = speculative < limit ? limit - speculative : 0;
        if (extra > wanted - 1) extra = wanted - 1;
        grant = 1 + extra;
        if (atomic_compare_exchange_weak_explicit(&queue->speculative_unused, &speculative, speculative + extra,
                                                  memory_order_acq_rel, memory_order_relaxed)) {
            size_t capacity_grant;
            status = reserve_capacity(queue, grant, &capacity_grant);
            if (status == CA_FULL || status == CA_INVALID) {
                atomic_fetch_sub_explicit(&queue->speculative_unused, extra, memory_order_release);
                break;
            }
            if (capacity_grant < grant) {
                const size_t actual_extra = capacity_grant > 0 ? capacity_grant - 1 : 0;
                atomic_fetch_sub_explicit(&queue->speculative_unused, extra - actual_extra, memory_order_release);
                extra = actual_extra;
                grant = capacity_grant;
            }
            lease->queue = base;
            lease->owner = producer;
            lease->lane_index = lane->index;
            lease->lane_generation = lane->generation;
            lease->unused = grant;
            lease->speculative_unused = extra;
            lease->active = 1;
            owner_acquire(producer);
            atomic_fetch_add_explicit(&queue->live_leases, 1, memory_order_relaxed);
            status = grant == wanted ? CA_OK : CA_PARTIAL;
            break;
        }
        DIAG_INC(queue, cas_retries);
    }
    if (producer_pinned) producer_op_exit(producer);
    lifecycle_exit(queue, CA_ROLE_RESERVE);
    return status;
}

static void close_lease(struct sparse_queue *queue, ca_credit_lease_t *lease) {
    owner_release(lease->owner);
    atomic_fetch_sub_explicit(&queue->live_leases, 1, memory_order_release);
    lease->active = 0;
    lease->unused = 0;
    lease->speculative_unused = 0;
    lease->queue = NULL;
}

static ca_status_t sparse_credit_submit_span(ca_credit_lease_t *lease,
                                             void *const *items,
                                             size_t count,
                                             size_t *accepted) {
    if (lease == NULL || lease->queue == NULL || accepted == NULL || items == NULL || count == 0) return CA_INVALID;
    *accepted = 0;
    struct sparse_queue *queue = as_sparse(lease->queue);
    ca_status_t status = lifecycle_enter(queue, CA_ROLE_PUBLISH);
    if (status != CA_OK) return status;
    if (!atomic_load_explicit(&queue->publishing, memory_order_acquire)) {
        lifecycle_exit(queue, CA_ROLE_PUBLISH);
        return CA_CLOSED;
    }
    struct ca_lane *lane = lease->active ? lane_from_handle(queue, lease->lane_index, lease->lane_generation) : NULL;
    const size_t publish_count = lease->unused < count ? lease->unused : count;
    if (lane == NULL || publish_count == 0) {
        lifecycle_exit(queue, CA_ROLE_PUBLISH);
        return CA_INVALID;
    }
    status = publish_lane(queue, lane, items, publish_count);
    if (status == CA_OK) {
        const size_t mandatory = lease->unused - lease->speculative_unused;
        const size_t speculative_used = publish_count > mandatory ? publish_count - mandatory : 0;
        lease->unused -= publish_count;
        lease->speculative_unused -= speculative_used;
        atomic_fetch_sub_explicit(&queue->speculative_unused, speculative_used, memory_order_release);
        *accepted = publish_count;
        status = publish_count == count ? CA_OK : CA_PARTIAL;
    }
    lifecycle_exit(queue, CA_ROLE_PUBLISH);
    return status;
}

static void sparse_credit_release(ca_credit_lease_t *lease) {
    if (lease == NULL || lease->queue == NULL) return;
    struct sparse_queue *queue = as_sparse(lease->queue);
    /* See sparse_cancel_reservation: void ownership cleanup is no-fail. */
    if (lease->active) {
        atomic_fetch_sub_explicit(&queue->speculative_unused, lease->speculative_unused, memory_order_release);
        capacity_release(queue, lease->unused);
        close_lease(queue, lease);
    }
}

static ca_status_t sparse_builder_begin(ca_queue_t *base, ca_producer_t *producer, ca_builder_t *builder) {
    if (builder == NULL) return CA_INVALID;
    memset(builder, 0, sizeof(*builder));
    struct sparse_queue *queue = as_sparse(base);
    ca_status_t status = lifecycle_enter(queue, CA_ROLE_RESERVE);
    if (status != CA_OK) return status;
    if (!atomic_load_explicit(&queue->accepting, memory_order_acquire)) {
        lifecycle_exit(queue, CA_ROLE_RESERVE);
        return CA_CLOSED;
    }
    struct ca_lane *lane;
    status = validate_producer(queue, producer, &lane);
    const int producer_pinned = status == CA_OK && producer != NULL;
    if (status == CA_OK) {
        builder->queue = base;
        builder->owner = producer;
        builder->lane_index = lane->index;
        builder->lane_generation = lane->generation;
        builder->items = &builder->inline_item;
        builder->allocated = 1;
        builder->active = 1;
        owner_acquire(producer);
        atomic_fetch_add_explicit(&queue->live_builders, 1, memory_order_relaxed);
    }
    if (producer_pinned) producer_op_exit(producer);
    lifecycle_exit(queue, CA_ROLE_RESERVE);
    return status;
}

static ca_status_t sparse_builder_append(
    ca_builder_t *builder, ca_credit_lease_t *lease, void *const *items, size_t count, size_t *accepted) {
    if (builder == NULL || builder->queue == NULL || lease == NULL || accepted == NULL || items == NULL || count == 0)
        return CA_INVALID;
    *accepted = 0;
    struct sparse_queue *queue = as_sparse(builder->queue);
    ca_status_t status = lifecycle_enter(queue, CA_ROLE_PUBLISH);
    if (status != CA_OK) return status;
    if (!atomic_load_explicit(&queue->publishing, memory_order_acquire)) {
        lifecycle_exit(queue, CA_ROLE_PUBLISH);
        return CA_CLOSED;
    }
    if (!builder->active || builder->prepared || !lease->active || lease->queue != builder->queue ||
        lease->owner != builder->owner || lease->lane_index != builder->lane_index ||
        lease->lane_generation != builder->lane_generation) {
        lifecycle_exit(queue, CA_ROLE_PUBLISH);
        return CA_INVALID;
    }
    size_t take = lease->unused < count ? lease->unused : count;
    size_t needed;
    if (take == 0 || !checked_add_size(builder->count, take, &needed)) {
        lifecycle_exit(queue, CA_ROLE_PUBLISH);
        return take == 0 ? CA_FULL : CA_INVALID;
    }
    if (needed > builder->allocated) {
        size_t allocation = builder->allocated <= 1 ? CA_CHUNK_ITEMS : builder->allocated;
        while (allocation < needed) {
            if (allocation > SIZE_MAX / 2) {
                allocation = needed;
                break;
            }
            allocation *= 2;
        }
        size_t bytes;
        if (!checked_mul_size(allocation, sizeof(*builder->items), &bytes)) {
            lifecycle_exit(queue, CA_ROLE_PUBLISH);
            return CA_INVALID;
        }
        void **grown;
        if (builder->items == &builder->inline_item) {
            grown = malloc(bytes);
            if (grown != NULL) memcpy(grown, builder->items, builder->count * sizeof(*builder->items));
        } else {
            grown = realloc(builder->items, bytes);
        }
        if (grown == NULL) {
            lifecycle_exit(queue, CA_ROLE_PUBLISH);
            return CA_NO_MEMORY;
        }
        builder->items = grown;
        builder->allocated = allocation;
#ifdef CA_TESTING
        atomic_fetch_add_explicit(&queue->test_builder_item_allocations, 1, memory_order_relaxed);
#endif
    }
    memcpy(&builder->items[builder->count], items, take * sizeof(*items));
    builder->count += take;
    const size_t mandatory = lease->unused - lease->speculative_unused;
    const size_t speculative_used = take > mandatory ? take - mandatory : 0;
    lease->unused -= take;
    lease->speculative_unused -= speculative_used;
    atomic_fetch_sub_explicit(&queue->speculative_unused, speculative_used, memory_order_release);
    *accepted = take;
    status = take == count ? CA_OK : CA_PARTIAL;
    lifecycle_exit(queue, CA_ROLE_PUBLISH);
    return status;
}

static void close_builder(struct sparse_queue *queue, ca_builder_t *builder) {
    assert(builder->prepared_chunks == NULL && builder->prepared_chunk_count == 0);
    if (builder->items != &builder->inline_item) free(builder->items);
    owner_release(builder->owner);
    atomic_fetch_sub_explicit(&queue->live_builders, 1, memory_order_release);
    memset(builder, 0, sizeof(*builder));
}

static ca_status_t sparse_builder_prepare(ca_builder_t *builder) {
    if (builder == NULL || builder->queue == NULL || !builder->active || builder->count == 0 || builder->prepared)
        return CA_INVALID;
    struct sparse_queue *queue = as_sparse(builder->queue);
    ca_status_t status = lifecycle_enter(queue, CA_ROLE_PUBLISH);
    if (status != CA_OK) return status;
    if (!atomic_load_explicit(&queue->publishing, memory_order_acquire)) {
        lifecycle_exit(queue, CA_ROLE_PUBLISH);
        return CA_CLOSED;
    }
    struct ca_lane *const lane =
        builder->active ? lane_from_handle(queue, builder->lane_index, builder->lane_generation) : NULL;
    if (lane == NULL) {
        lifecycle_exit(queue, CA_ROLE_PUBLISH);
        return CA_INVALID;
    }
    lane_lock(lane);
    status =
        prepared_chunks_take_locked(lane, builder->count, &builder->prepared_chunks, &builder->prepared_chunk_count);
    lane_unlock(lane);
    if (status == CA_OK) builder->prepared = 1;
    lifecycle_exit(queue, CA_ROLE_PUBLISH);
    return status;
}

static ca_status_t sparse_builder_commit(ca_builder_t *builder) {
    if (builder == NULL || builder->queue == NULL || !builder->active || !builder->prepared || builder->count == 0)
        return CA_INVALID;
    struct sparse_queue *queue = as_sparse(builder->queue);
    ca_status_t status = lifecycle_enter(queue, CA_ROLE_PUBLISH);
    if (status != CA_OK) return status;
    if (!atomic_load_explicit(&queue->publishing, memory_order_acquire)) {
        lifecycle_exit(queue, CA_ROLE_PUBLISH);
        return CA_CLOSED;
    }
    struct ca_lane *const lane = lane_from_handle(queue, builder->lane_index, builder->lane_generation);
    if (lane == NULL)
        status = CA_INVALID;
    else
        status = publish_lane_prepared(queue, lane, builder->items, builder->count, &builder->prepared_chunks,
                                       &builder->prepared_chunk_count);
    if (status == CA_OK) {
        builder->prepared = 0;
        close_builder(queue, builder);
    }
    lifecycle_exit(queue, CA_ROLE_PUBLISH);
    return status;
}

static ca_status_t sparse_builder_publish(ca_builder_t *builder) {
    if (builder == NULL || builder->queue == NULL) return CA_INVALID;
    struct sparse_queue *queue = as_sparse(builder->queue);
    ca_status_t status = lifecycle_enter(queue, CA_ROLE_PUBLISH);
    if (status != CA_OK) return status;
    if (!atomic_load_explicit(&queue->publishing, memory_order_acquire)) {
        lifecycle_exit(queue, CA_ROLE_PUBLISH);
        return CA_CLOSED;
    }
    struct ca_lane *lane =
        builder->active ? lane_from_handle(queue, builder->lane_index, builder->lane_generation) : NULL;
    if (lane == NULL || builder->count == 0)
        status = CA_INVALID;
    else if (builder->prepared)
        status = publish_lane_prepared(queue, lane, builder->items, builder->count, &builder->prepared_chunks,
                                       &builder->prepared_chunk_count);
    else
        status = publish_lane(queue, lane, builder->items, builder->count);
    if (status == CA_OK) {
        builder->prepared = 0;
        close_builder(queue, builder);
    }
    lifecycle_exit(queue, CA_ROLE_PUBLISH);
    return status;
}

static void sparse_builder_cancel(ca_builder_t *builder) {
    if (builder == NULL || builder->queue == NULL) return;
    struct sparse_queue *queue = as_sparse(builder->queue);
    /* Prepared chunks return under the lane lock before the live pin drops. */
    if (builder->active) {
        struct ca_lane *const lane = lane_from_handle(queue, builder->lane_index, builder->lane_generation);
        if (lane != NULL && builder->prepared_chunks != NULL) {
            lane_lock(lane);
            prepared_chunks_return_locked(lane, &builder->prepared_chunks, &builder->prepared_chunk_count);
            lane_unlock(lane);
        }
        builder->prepared = 0;
        capacity_release(queue, builder->count);
        close_builder(queue, builder);
    }
}

static void retry_insert_locked(struct ca_lane *lane, ca_slot_meta_t *slot) {
    ca_slot_meta_t **position = &lane->retry_head;
    while (*position != NULL && slot_ordinal(*position) < slot_ordinal(slot)) position = &(*position)->retry_next;
    slot->retry_next = *position;
    *position = slot;
}

static void advance_frontier_locked(struct ca_lane *lane) {
    while (lane->final_frontier < lane->published_tail) {
        ca_slot_meta_t *slot = lane_slot_locked(lane, lane->final_frontier, NULL);
        if (slot == NULL || atomic_load_explicit(&slot->state, memory_order_acquire) != CA_SLOT_TERMINAL) break;
        ++lane->final_frontier;
    }
}

static size_t claim_retry_locked(struct ca_lane *lane, ca_claim_item_t *items) {
    if (!retry_runnable_locked(lane)) return 0;
    ca_slot_meta_t *slot = lane->retry_head;
    lane->retry_head = slot->retry_next;
    slot->retry_next = NULL;
    atomic_store_explicit(&slot->state, CA_SLOT_CLAIMED, memory_order_release);
    void **message;
    const uint64_t ordinal = slot_ordinal(slot);
    (void)lane_slot_locked(lane, ordinal, &message);
    items[0] = (ca_claim_item_t){.item = *message, .slot = slot, .ordinal = ordinal, .was_retry = 1};
    return 1;
}

static size_t claim_normal_locked(struct ca_lane *lane, ca_claim_item_t *items, size_t maximum) {
    if (lane->retry_pending != 0 || lane->claim_cursor >= lane->published_tail) return 0;
#ifdef CA_TESTING
    if (atomic_load_explicit(&lane->queue->test_pause_claim, memory_order_acquire)) {
        atomic_store_explicit(&lane->queue->test_claim_entered, 1, memory_order_release);
        while (!atomic_load_explicit(&lane->queue->test_claim_release, memory_order_acquire)) sched_yield();
    }
#endif
    uint64_t available = lane->published_tail - lane->claim_cursor;
    size_t count = available < maximum ? (size_t)available : maximum;
    const uint64_t start = lane->claim_cursor;
    lane->claim_cursor += count;
    for (size_t i = 0; i < count; ++i) {
        void **message;
        ca_slot_meta_t *slot = lane_slot_locked(lane, start + i, &message);
        if (slot == NULL || atomic_load_explicit(&slot->state, memory_order_acquire) != CA_SLOT_READY) abort();
        atomic_store_explicit(&slot->state, CA_SLOT_CLAIMED, memory_order_release);
        items[i] = (ca_claim_item_t){.item = *message, .slot = slot, .ordinal = start + i, .was_retry = 0};
    }
    return count;
}

static ca_status_t sparse_claim(ca_queue_t *base, ca_claim_t *claim, ca_claim_item_t *items, size_t maximum) {
    if (claim == NULL || items == NULL || maximum == 0) return CA_INVALID;
    memset(claim, 0, sizeof(*claim));
    struct sparse_queue *queue = as_sparse(base);
    ca_status_t status = lifecycle_enter(queue, CA_ROLE_CLAIM);
    if (status != CA_OK) return status;
    if (!atomic_load_explicit(&queue->claiming, memory_order_acquire)) {
        lifecycle_exit(queue, CA_ROLE_CLAIM);
        return CA_CLOSED;
    }
    int previous_cancel_state;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous_cancel_state) != 0) {
        lifecycle_exit(queue, CA_ROLE_CLAIM);
        return CA_INVALID;
    }
    uint64_t token;
    while (ca_ready_scq_try_dequeue(queue->ready, &token) == CA_READY_SCQ_OK) {
        DIAG_INC(queue, ready_dequeues);
        const uint32_t index = (uint32_t)token;
        if (index >= queue->lane_count) continue;
        struct ca_lane *lane = &queue->lanes[index];
        const uint64_t generation = lane->generation;
        unsigned observed = atomic_load_explicit(&lane->token_state, memory_order_acquire);
        while (observed != CA_TOKEN_OWNED &&
               !atomic_compare_exchange_weak_explicit(&lane->token_state, &observed, CA_TOKEN_OWNED,
                                                      memory_order_acq_rel, memory_order_acquire));
        if (observed == CA_TOKEN_OWNED) continue;
        lane_lock(lane);
        size_t count = claim_retry_locked(lane, items);
        if (count == 0) count = claim_normal_locked(lane, items, maximum);
        lane_finish_token_locked(lane);
        lane_unlock(lane);
        if (count == 0) continue;
        atomic_fetch_add_explicit(&queue->in_flight, count, memory_order_relaxed);
        atomic_fetch_add_explicit(&queue->live_claims, 1, memory_order_relaxed);
        DIAG_INC(queue, claim_calls);
        DIAG_ADD(queue, claimed_items, count);
#ifdef CA_ENABLE_DIAGNOSTICS
        diag_max(&queue->diag.largest_claim, count);
#endif
        claim->queue = base;
        claim->items = items;
        claim->count = count;
        claim->capacity = maximum;
        claim->lane_index = index;
        claim->lane_generation = generation;
        claim->active = 1;
        lifecycle_exit(queue, CA_ROLE_CLAIM);
        (void)pthread_setcancelstate(previous_cancel_state, NULL);
        return CA_OK;
    }
    lifecycle_exit(queue, CA_ROLE_CLAIM);
    (void)pthread_setcancelstate(previous_cancel_state, NULL);
    return CA_EMPTY;
}

static ca_status_t sparse_complete_impl(ca_claim_t *claim, const ca_completion_state_t *states, int return_all) {
    if (claim == NULL || claim->queue == NULL || !claim->active || (!return_all && states == NULL) || claim->count == 0)
        return CA_INVALID;
    if (!return_all) {
        for (size_t i = 0; i < claim->count; ++i) {
            if (states[i] != CA_COMPLETE_COMMIT && states[i] != CA_COMPLETE_RETRY && states[i] != CA_COMPLETE_DISCARD)
                return CA_INVALID;
        }
    }
    struct sparse_queue *queue = as_sparse(claim->queue);
    ca_status_t status = lifecycle_enter(queue, CA_ROLE_COMPLETE);
    if (status != CA_OK) return status;
    struct ca_lane *lane = lane_from_handle(queue, claim->lane_index, claim->lane_generation);
    if (lane == NULL) {
        lifecycle_exit(queue, CA_ROLE_COMPLETE);
        return CA_INVALID;
    }
    size_t final_count = 0;
    lane_lock(lane);
    for (size_t i = 0; i < claim->count; ++i) {
        const ca_claim_item_t *item = &claim->items[i];
        const ca_slot_meta_t *slot = item->slot;
        if (slot == NULL || slot_ordinal((ca_slot_meta_t *)slot) != item->ordinal ||
            atomic_load_explicit(&slot->state, memory_order_acquire) != CA_SLOT_CLAIMED) {
            lane_unlock(lane);
            lifecycle_exit(queue, CA_ROLE_COMPLETE);
            return CA_INVALID;
        }
    }
    for (size_t i = 0; i < claim->count; ++i) {
        ca_claim_item_t *item = &claim->items[i];
        ca_slot_meta_t *slot = item->slot;
        const ca_completion_state_t state = return_all ? CA_COMPLETE_RETRY : states[i];
        if (state == CA_COMPLETE_RETRY) {
            atomic_store_explicit(&slot->state, CA_SLOT_RETRY_READY, memory_order_release);
            if (!item->was_retry) {
                ++lane->retry_pending;
                DIAG_INC(queue, retry_barriers);
            }
            retry_insert_locked(lane, slot);
        } else {
            atomic_store_explicit(&slot->state, CA_SLOT_TERMINAL, memory_order_release);
            struct ca_chunk *chunk = slot_chunk(slot);
            if (chunk != NULL) atomic_fetch_add_explicit(&chunk->terminal_count, 1, memory_order_relaxed);
            if (item->was_retry) --lane->retry_pending;
            ++final_count;
        }
    }
    advance_frontier_locked(lane);
    reclaim_chunks_locked(lane);
    if (lane->reuse_pending && lane_idle_locked(lane))
        reset_dedicated_lane_locked(lane);
    else
        lane_make_ready_locked(lane);
    lane_unlock(lane);

    for (size_t i = 0; i < claim->count; ++i) {
        const ca_completion_state_t state = return_all ? CA_COMPLETE_RETRY : states[i];
        if (state != CA_COMPLETE_RETRY && queue->dispose != NULL)
            queue->dispose(claim->items[i].item, state, queue->dispose_user);
    }
    atomic_fetch_sub_explicit(&queue->in_flight, claim->count, memory_order_release);
    if (final_count != 0) capacity_release(queue, final_count);
    atomic_fetch_sub_explicit(&queue->live_claims, 1, memory_order_release);
    claim->active = 0;
    claim->count = 0;
    claim->queue = NULL;
    lifecycle_exit(queue, CA_ROLE_COMPLETE);
    return CA_OK;
}

static ca_status_t sparse_complete(ca_claim_t *claim, const ca_completion_state_t *states) {
    return sparse_complete_impl(claim, states, 0);
}

static ca_status_t sparse_return_claim(ca_claim_t *claim) {
    return sparse_complete_impl(claim, NULL, 1);
}

static uint64_t
#if defined(__clang__)
    __attribute__((no_sanitize("unsigned-integer-overflow")))
#endif
    sparse_producer_hash(uint64_t key) {
    /* Unsigned wrap is part of this hash's avalanche algorithm. */
    uint64_t mixed = key + UINT64_C(0x9e3779b97f4a7c15);
    mixed = (mixed ^ (mixed >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    mixed = (mixed ^ (mixed >> 27)) * UINT64_C(0x94d049bb133111eb);
    return mixed ^ (mixed >> 31);
}

static ca_status_t sparse_producer_register(ca_queue_t *base, uint64_t key, ca_producer_t *producer) {
    if (producer == NULL) return CA_INVALID;
    memset(producer, 0, sizeof(*producer));
    struct sparse_queue *queue = as_sparse(base);
    ca_status_t status = lifecycle_enter(queue, CA_ROLE_HANDLE);
    if (status != CA_OK) return status;
    if (!atomic_load_explicit(&queue->accepting, memory_order_acquire)) {
        lifecycle_exit(queue, CA_ROLE_HANDLE);
        return CA_CLOSED;
    }
    const size_t start = atomic_fetch_add_explicit(&queue->dedicated_cursor, 1, memory_order_relaxed);
    size_t index = SIZE_MAX;
    for (size_t offset = 0; offset < queue->dedicated_limit; ++offset) {
        const size_t candidate = (start + offset) % queue->dedicated_limit;
        unsigned expected = 0;
        if (atomic_compare_exchange_strong_explicit(&queue->lanes[candidate].assigned, &expected, 1,
                                                    memory_order_acq_rel, memory_order_relaxed)) {
            index = candidate;
            break;
        }
    }
    if (index != SIZE_MAX) {
        producer->fallback = 0;
    } else {
        const uint64_t mixed = sparse_producer_hash(key);
        index = queue->dedicated_limit + ((size_t)mixed & (queue->fallback_count - 1));
        producer->fallback = 1;
    }
    producer->queue = base;
    producer->lane_index = (uint32_t)index;
    producer->lane_generation = queue->lanes[index].generation;
    atomic_init(&producer->outstanding, 0);
    atomic_init(&producer->op_state, 0);
    producer->active = 1;
    atomic_fetch_add_explicit(&queue->live_producers, 1, memory_order_relaxed);
    lifecycle_exit(queue, CA_ROLE_HANDLE);
    return CA_OK;
}

static ca_status_t sparse_producer_register_fallback(ca_queue_t *base, size_t fallback_index, ca_producer_t *producer) {
    if (producer == NULL) return CA_INVALID;
    memset(producer, 0, sizeof(*producer));
    struct sparse_queue *queue = as_sparse(base);
    ca_status_t status = lifecycle_enter(queue, CA_ROLE_HANDLE);
    if (status != CA_OK) return status;
    if (!atomic_load_explicit(&queue->accepting, memory_order_acquire)) {
        status = CA_CLOSED;
    } else if (fallback_index >= queue->fallback_count) {
        status = CA_INVALID;
    } else {
        const size_t index = queue->dedicated_limit + fallback_index;
        producer->queue = base;
        producer->lane_index = (uint32_t)index;
        producer->lane_generation = queue->lanes[index].generation;
        atomic_init(&producer->outstanding, 0);
        atomic_init(&producer->op_state, 0);
        producer->active = 1;
        producer->fallback = 1;
        atomic_fetch_add_explicit(&queue->live_producers, 1, memory_order_relaxed);
        status = CA_OK;
    }
    lifecycle_exit(queue, CA_ROLE_HANDLE);
    return status;
}

static ca_status_t sparse_producer_release(ca_producer_t *producer) {
    if (producer == NULL) return CA_INVALID;
    size_t state = atomic_load_explicit(&producer->op_state, memory_order_acquire);
    for (;;) {
        if (state & CA_PRODUCER_CLOSED) return CA_INVALID;
        if (atomic_compare_exchange_weak_explicit(&producer->op_state, &state, state | CA_PRODUCER_CLOSED,
                                                  memory_order_acq_rel, memory_order_acquire))
            break;
    }
    while ((atomic_load_explicit(&producer->op_state, memory_order_acquire) & CA_PRODUCER_REF_MASK) != 0) sched_yield();
    if (producer->queue == NULL) {
        atomic_store_explicit(&producer->op_state, 0, memory_order_release);
        return CA_INVALID;
    }
    struct sparse_queue *queue = as_sparse(producer->queue);
    ca_status_t status = lifecycle_enter(queue, CA_ROLE_HANDLE);
    if (status != CA_OK) {
        atomic_store_explicit(&producer->op_state, 0, memory_order_release);
        return status;
    }
    if (!producer->active || producer->queue != &queue->base ||
        lane_from_handle(queue, producer->lane_index, producer->lane_generation) == NULL) {
        status = CA_INVALID;
        atomic_store_explicit(&producer->op_state, 0, memory_order_release);
    } else if (atomic_load_explicit(&producer->outstanding, memory_order_acquire) != 0) {
        status = CA_BUSY;
        atomic_store_explicit(&producer->op_state, 0, memory_order_release);
    } else {
        struct ca_lane *lane = &queue->lanes[producer->lane_index];
        if (!lane->fallback) {
            lane_lock(lane);
            lane->reuse_pending = 1;
            if (lane_idle_locked(lane)) reset_dedicated_lane_locked(lane);
            lane_unlock(lane);
        }
        producer->active = 0;
        producer->queue = NULL;
        atomic_fetch_sub_explicit(&queue->live_producers, 1, memory_order_release);
        status = CA_OK;
    }
    lifecycle_exit(queue, CA_ROLE_HANDLE);
    return status;
}

static void sparse_capacity_read(const ca_queue_t *base, ca_capacity_snapshot_t *snapshot) {
    struct sparse_queue *queue = as_sparse((ca_queue_t *)base);
    if (lifecycle_enter(queue, CA_ROLE_INSPECT) != CA_OK) {
        memset(snapshot, 0, sizeof(*snapshot));
        return;
    }
    snapshot->capacity = queue->capacity;
    snapshot->available = atomic_load_explicit(&queue->available, memory_order_acquire);
    snapshot->speculative_unused = atomic_load_explicit(&queue->speculative_unused, memory_order_acquire);
    snapshot->in_flight = atomic_load_explicit(&queue->in_flight, memory_order_acquire);
    snapshot->epoch = atomic_load_explicit(&queue->epoch, memory_order_acquire);
    snapshot->accepting = atomic_load_explicit(&queue->accepting, memory_order_acquire);
    snapshot->claiming = atomic_load_explicit(&queue->claiming, memory_order_acquire);
    lifecycle_exit(queue, CA_ROLE_INSPECT);
}

static uint64_t sparse_epoch(const ca_queue_t *base) {
    struct sparse_queue *queue = as_sparse((ca_queue_t *)base);
    if (lifecycle_enter(queue, CA_ROLE_INSPECT) != CA_OK) return 0;
    const uint64_t epoch = atomic_load_explicit(&queue->epoch, memory_order_acquire);
    lifecycle_exit(queue, CA_ROLE_INSPECT);
    return epoch;
}

#if CA_USE_FUTEX
static int relative_deadline(const struct timespec *deadline, struct timespec *relative) {
    if (deadline == NULL) return 0;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    relative->tv_sec = deadline->tv_sec - now.tv_sec;
    relative->tv_nsec = deadline->tv_nsec - now.tv_nsec;
    if (relative->tv_nsec < 0) {
        --relative->tv_sec;
        relative->tv_nsec += 1000000000L;
    }
    return relative->tv_sec < 0 ? -1 : 1;
}
#else
static void realtime_deadline(const struct timespec *monotonic_deadline, struct timespec *realtime) {
    struct timespec monotonic_now;
    struct timespec realtime_now;
    clock_gettime(CLOCK_MONOTONIC, &monotonic_now);
    clock_gettime(CLOCK_REALTIME, &realtime_now);
    realtime->tv_sec = realtime_now.tv_sec + monotonic_deadline->tv_sec - monotonic_now.tv_sec;
    realtime->tv_nsec = realtime_now.tv_nsec + monotonic_deadline->tv_nsec - monotonic_now.tv_nsec;
    if (realtime->tv_nsec >= 1000000000L) {
        ++realtime->tv_sec;
        realtime->tv_nsec -= 1000000000L;
    } else if (realtime->tv_nsec < 0) {
        --realtime->tv_sec;
        realtime->tv_nsec += 1000000000L;
    }
}

struct wait_cleanup {
    struct sparse_queue *queue;
    _Atomic unsigned *sleepers;
    int mutex_locked;
    int sleeper_registered;
    int lifecycle_registered;
};

static void wait_cancel_cleanup(void *argument) {
    struct wait_cleanup *cleanup = argument;
    if (cleanup->sleeper_registered) {
        atomic_fetch_sub_explicit(cleanup->sleepers, 1, memory_order_release);
        atomic_fetch_sub_explicit(&cleanup->queue->live_waiters, 1, memory_order_release);
    }
    if (cleanup->mutex_locked) pthread_mutex_unlock(&cleanup->queue->wait_mutex);
    if (cleanup->lifecycle_registered) lifecycle_exit(cleanup->queue, CA_ROLE_WAIT);
}
#endif

static ca_status_t sparse_wait_epoch_on(ca_queue_t *base,
                                        uint64_t observed,
                                        const struct timespec *deadline,
                                        _Atomic uint64_t *epoch,
#if CA_USE_FUTEX
                                        _Atomic uint32_t *futex_epoch,
#endif
                                        _Atomic unsigned *sleepers
#if !CA_USE_FUTEX
                                        ,
                                        pthread_cond_t *condition
#endif
) {
    struct sparse_queue *queue = as_sparse(base);
    ca_status_t status = lifecycle_enter(queue, CA_ROLE_WAIT);
    if (status != CA_OK) return status;
    if (!atomic_load_explicit(&queue->waiting, memory_order_acquire)) {
        lifecycle_exit(queue, CA_ROLE_WAIT);
        return CA_CLOSED;
    }
    atomic_fetch_add_explicit(&queue->live_waiters, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(sleepers, 1, memory_order_acq_rel);
    DIAG_INC(queue, sleeps);
#if CA_USE_FUTEX
    const uint32_t futex_observed = atomic_load_explicit(futex_epoch, memory_order_acquire);
    if (atomic_load_explicit(epoch, memory_order_acquire) == observed) {
        struct timespec relative;
        const int deadline_state = relative_deadline(deadline, &relative);
        int result;
        if (deadline_state < 0)
            result = ETIMEDOUT;
        else {
            result = (int)syscall(SYS_futex, futex_epoch, FUTEX_WAIT_PRIVATE, futex_observed,
                                  deadline_state == 0 ? NULL : &relative, NULL, 0);
            result = result == 0 ? 0 : errno;
        }
        if (result == ETIMEDOUT) status = CA_TIMED_OUT;
    }
    atomic_fetch_sub_explicit(sleepers, 1, memory_order_release);
    atomic_fetch_sub_explicit(&queue->live_waiters, 1, memory_order_release);
    lifecycle_exit(queue, CA_ROLE_WAIT);
#else
    struct wait_cleanup cleanup = {
        .queue = queue,
        .sleepers = sleepers,
        .sleeper_registered = 1,
        .lifecycle_registered = 1,
    };
    int result = 0;
    pthread_cleanup_push(wait_cancel_cleanup, &cleanup);
    pthread_mutex_lock(&queue->wait_mutex);
    cleanup.mutex_locked = 1;
    if (atomic_load_explicit(epoch, memory_order_acquire) == observed) {
        if (deadline == NULL)
            result = pthread_cond_wait(condition, &queue->wait_mutex);
        else {
            struct timespec wait_deadline;
            realtime_deadline(deadline, &wait_deadline);
            result = pthread_cond_timedwait(condition, &queue->wait_mutex, &wait_deadline);
        }
    }
    cleanup.mutex_locked = 0;
    pthread_mutex_unlock(&queue->wait_mutex);
    cleanup.sleeper_registered = 0;
    atomic_fetch_sub_explicit(sleepers, 1, memory_order_release);
    atomic_fetch_sub_explicit(&queue->live_waiters, 1, memory_order_release);
    cleanup.lifecycle_registered = 0;
    lifecycle_exit(queue, CA_ROLE_WAIT);
    pthread_cleanup_pop(0);
    if (result == ETIMEDOUT) status = CA_TIMED_OUT;
#endif
    if (status == CA_OK && atomic_load_explicit(epoch, memory_order_acquire) == observed && deadline_expired(deadline))
        status = CA_TIMED_OUT;
    return status;
}

static ca_status_t sparse_wait_epoch(ca_queue_t *base, uint64_t observed, const struct timespec *deadline) {
    struct sparse_queue *queue = as_sparse(base);
    return sparse_wait_epoch_on(base, observed, deadline, &queue->epoch,
#if CA_USE_FUTEX
                                &queue->epoch_futex,
#endif
                                &queue->sleepers
#if !CA_USE_FUTEX
                                ,
                                &queue->wait_cond
#endif
    );
}

static uint64_t sparse_capacity_epoch(const ca_queue_t *base) {
    struct sparse_queue *queue = as_sparse((ca_queue_t *)base);
    if (lifecycle_enter(queue, CA_ROLE_INSPECT) != CA_OK) return 0;
    const uint64_t epoch = atomic_load_explicit(&queue->capacity_epoch, memory_order_acquire);
    lifecycle_exit(queue, CA_ROLE_INSPECT);
    return epoch;
}

static ca_status_t sparse_wait_capacity_epoch(ca_queue_t *base, uint64_t observed, const struct timespec *deadline) {
    struct sparse_queue *queue = as_sparse(base);
    return sparse_wait_epoch_on(base, observed, deadline, &queue->capacity_epoch,
#if CA_USE_FUTEX
                                &queue->capacity_epoch_futex,
#endif
                                &queue->capacity_sleepers
#if !CA_USE_FUTEX
                                ,
                                &queue->capacity_wait_cond
#endif
    );
}

static void sparse_interrupt_waiters(ca_queue_t *base) {
    struct sparse_queue *queue = as_sparse(base);
    event_signal(queue, 1);
    capacity_event_signal(queue, 1);
}

static void discard_lane(struct ca_lane *lane, size_t *discarded) {
    for (uint64_t ordinal = lane->final_frontier; ordinal < lane->published_tail; ++ordinal) {
        lane_lock(lane);
        void **message;
        ca_slot_meta_t *slot = lane_slot_locked(lane, ordinal, &message);
        unsigned state = atomic_load_explicit(&slot->state, memory_order_acquire);
        if (state == CA_SLOT_TERMINAL) {
            lane_unlock(lane);
            continue;
        }
        if (state == CA_SLOT_CLAIMED) abort();
        atomic_store_explicit(&slot->state, CA_SLOT_TERMINAL, memory_order_release);
        struct ca_chunk *chunk = slot_chunk(slot);
        if (chunk != NULL) atomic_fetch_add_explicit(&chunk->terminal_count, 1, memory_order_relaxed);
        void *const item = *message;
        lane_unlock(lane);
        /* Disposal may invoke application code.  The quiesce flags make the
         * lane immutable here, so run it without holding the lane lock and
         * permit a callback to inspect or attempt a closed queue operation. */
        if (lane->queue->dispose != NULL) lane->queue->dispose(item, CA_COMPLETE_DISCARD, lane->queue->dispose_user);
        ++*discarded;
    }
    lane_lock(lane);
    lane->retry_head = NULL;
    lane->retry_pending = 0;
    lane->claim_cursor = lane->published_tail;
    lane->final_frontier = lane->published_tail;
    reclaim_chunks_locked(lane);
    lane_unlock(lane);
}

static ca_status_t sparse_quiesce(ca_queue_t *base, ca_quiesce_mode_t mode, const struct timespec *deadline) {
    struct sparse_queue *queue = as_sparse(base);
    size_t discarded = 0;
    if (!control_enter(queue)) return CA_BUSY;
    ca_status_t status = lifecycle_writer_begin(queue, deadline);
    if (status != CA_OK) {
        control_exit(queue);
        return status;
    }
    const unsigned was_accepting = atomic_load_explicit(&queue->accepting, memory_order_relaxed);
    const unsigned was_publishing = atomic_load_explicit(&queue->publishing, memory_order_relaxed);
    const unsigned was_claiming = atomic_load_explicit(&queue->claiming, memory_order_relaxed);
    const unsigned was_waiting = atomic_load_explicit(&queue->waiting, memory_order_relaxed);
    atomic_store_explicit(&queue->accepting, 0, memory_order_release);
    if (mode == CA_QUIESCE_DISCARD) {
        atomic_store_explicit(&queue->publishing, 0, memory_order_release);
        atomic_store_explicit(&queue->claiming, 0, memory_order_release);
        atomic_store_explicit(&queue->waiting, 0, memory_order_release);
    }
    event_signal(queue, 1);
    capacity_event_signal(queue, 1);
    status = lifecycle_writer_wait(queue, deadline);
    if (status != CA_OK) {
        atomic_store_explicit(&queue->accepting, was_accepting, memory_order_relaxed);
        atomic_store_explicit(&queue->publishing, was_publishing, memory_order_relaxed);
        atomic_store_explicit(&queue->claiming, was_claiming, memory_order_relaxed);
        atomic_store_explicit(&queue->waiting, was_waiting, memory_order_release);
        lifecycle_writer_end(queue);
        event_signal(queue, 1);
        capacity_event_signal(queue, 1);
        control_exit(queue);
        return status;
    }
    lifecycle_writer_end(queue);

    if (mode == CA_QUIESCE_DRAIN) {
        while (atomic_load_explicit(&queue->available, memory_order_acquire) != queue->capacity) {
            if (deadline_expired(deadline)) goto timed_out;
            const uint64_t observed = atomic_load_explicit(&queue->capacity_epoch, memory_order_acquire);
            status = sparse_wait_capacity_epoch(base, observed, deadline);
            if (status == CA_TIMED_OUT) goto timed_out;
        }
        atomic_store_explicit(&queue->publishing, 0, memory_order_release);
        atomic_store_explicit(&queue->claiming, 0, memory_order_release);
        atomic_store_explicit(&queue->waiting, 0, memory_order_release);
        event_signal(queue, 1);
        capacity_event_signal(queue, 1);
        control_exit(queue);
        return CA_OK;
    }

    while (atomic_load_explicit(&queue->live_claims, memory_order_acquire) != 0 ||
           atomic_load_explicit(&queue->in_flight, memory_order_acquire) != 0) {
        if (deadline_expired(deadline)) goto timed_out;
        sched_yield();
    }
    for (size_t i = 0; i < queue->lane_count; ++i) discard_lane(&queue->lanes[i], &discarded);
    uint64_t stale_token;
    while (ca_ready_scq_try_dequeue(queue->ready, &stale_token) == CA_READY_SCQ_OK);
    for (size_t i = 0; i < queue->lane_count; ++i)
        atomic_store_explicit(&queue->lanes[i].token_state, CA_TOKEN_ABSENT, memory_order_release);
    capacity_release(queue, discarded);
    status = atomic_load_explicit(&queue->available, memory_order_acquire) == queue->capacity ? CA_OK : CA_BUSY;
    control_exit(queue);
    return status;

timed_out:
    atomic_store_explicit(&queue->accepting, was_accepting, memory_order_relaxed);
    atomic_store_explicit(&queue->publishing, was_publishing, memory_order_relaxed);
    atomic_store_explicit(&queue->claiming, was_claiming, memory_order_relaxed);
    atomic_store_explicit(&queue->waiting, was_waiting, memory_order_release);
    event_signal(queue, 1);
    capacity_event_signal(queue, 1);
    control_exit(queue);
    return CA_TIMED_OUT;
}

static void free_lane_chunks(struct ca_lane *lane) {
    struct ca_chunk *chunk = lane->chunks_head;
    while (chunk != NULL) {
        struct ca_chunk *next = chunk->next;
        free(chunk);
        chunk = next;
    }
    chunk = lane->chunk_pool;
    while (chunk != NULL) {
        struct ca_chunk *next = chunk->pool_next;
        free(chunk);
        chunk = next;
    }
}

static ca_status_t sparse_destroy(ca_queue_t *base) {
    struct sparse_queue *queue = as_sparse(base);
    if (!control_enter(queue)) return CA_BUSY;
    ca_status_t status = lifecycle_writer_begin(queue, NULL);
    if (status != CA_OK) {
        control_exit(queue);
        return status;
    }
    atomic_store_explicit(&queue->destroying, 1, memory_order_release);
    atomic_store_explicit(&queue->accepting, 0, memory_order_release);
    atomic_store_explicit(&queue->publishing, 0, memory_order_release);
    atomic_store_explicit(&queue->claiming, 0, memory_order_release);
    atomic_store_explicit(&queue->waiting, 0, memory_order_release);
    event_signal(queue, 1);
    capacity_event_signal(queue, 1);
    status = lifecycle_writer_wait(queue, NULL);
    if (status != CA_OK) {
        atomic_store_explicit(&queue->destroying, 0, memory_order_release);
        lifecycle_writer_end(queue);
        control_exit(queue);
        return status;
    }
    const int busy = atomic_load_explicit(&queue->live_producers, memory_order_acquire) != 0 ||
                     atomic_load_explicit(&queue->live_reservations, memory_order_acquire) != 0 ||
                     atomic_load_explicit(&queue->live_leases, memory_order_acquire) != 0 ||
                     atomic_load_explicit(&queue->live_builders, memory_order_acquire) != 0 ||
                     atomic_load_explicit(&queue->live_claims, memory_order_acquire) != 0 ||
                     atomic_load_explicit(&queue->live_waiters, memory_order_acquire) != 0 ||
                     atomic_load_explicit(&queue->live_bindings, memory_order_acquire) != 0 ||
                     ca_ready_scq_reserved(queue->ready) != 0 ||
                     atomic_load_explicit(&queue->available, memory_order_acquire) != queue->capacity;
    if (busy) {
        atomic_store_explicit(&queue->destroying, 0, memory_order_release);
        lifecycle_writer_end(queue);
        control_exit(queue);
        return CA_BUSY;
    }
    if (ca_ready_scq_destroy(queue->ready) != CA_READY_SCQ_OK) abort();
    for (size_t i = 0; i < queue->lane_count; ++i) free_lane_chunks(&queue->lanes[i]);
#if !CA_USE_FUTEX
    pthread_cond_destroy(&queue->capacity_wait_cond);
    pthread_cond_destroy(&queue->wait_cond);
    pthread_mutex_destroy(&queue->wait_mutex);
#endif
    free(queue->lanes);
    free(queue->lifecycle_slots);
    free(queue);
    return CA_OK;
}

static ca_status_t sparse_create(const ca_config_t *config, ca_queue_t **result) {
    size_t dedicated_limit;
    size_t fallback_input;
    if (!checked_mul_size(config->consumers, 4, &dedicated_limit) ||
        !checked_mul_size(config->consumers, 2, &fallback_input))
        return CA_INVALID;
    if (dedicated_limit < 16) dedicated_limit = 16;
    const size_t fallback_count = next_power_of_two(fallback_input);
    size_t lane_count;
    if (fallback_count == 0 || !checked_add_size(dedicated_limit, fallback_count, &lane_count) ||
        lane_count > UINT32_MAX || lane_count - 1 > ca_ready_scq_token_max())
        return CA_INVALID;
    size_t ready_minimum;
    if (!checked_add_size(lane_count, config->consumers, &ready_minimum)) return CA_INVALID;
    const size_t ready_capacity = next_power_of_two(ready_minimum);
    if (ready_capacity == 0) return CA_INVALID;

    struct sparse_queue *queue = calloc(1, sizeof(*queue));
    if (queue == NULL) return CA_NO_MEMORY;
    queue->base.ops = &ca_sparse_lanes_ops;
    queue->capacity = config->capacity;
    queue->consumers = config->consumers;
    queue->dedicated_limit = dedicated_limit;
    queue->fallback_count = fallback_count;
    queue->lane_count = lane_count;
    queue->dispose = config->dispose;
    queue->dispose_user = config->dispose_user;
    queue->lifecycle_slot_count = next_power_of_two(dedicated_limit < 64 ? 64 : dedicated_limit);
    if (queue->lifecycle_slot_count == 0 ||
        !checked_mul_size(queue->lifecycle_slot_count, sizeof(*queue->lifecycle_slots), &queue->lifecycle_bytes)) {
        free(queue);
        return CA_INVALID;
    }
    if (posix_memalign((void **)&queue->lifecycle_slots, 64, queue->lifecycle_bytes) != 0) {
        free(queue);
        return CA_NO_MEMORY;
    }
    memset(queue->lifecycle_slots, 0, queue->lifecycle_bytes);
    queue->lanes = calloc(lane_count, sizeof(*queue->lanes));
    if (queue->lanes == NULL) {
        free(queue->lifecycle_slots);
        free(queue);
        return CA_NO_MEMORY;
    }
    atomic_init(&queue->dedicated_cursor, 0);
    atomic_init(&queue->anonymous_counter, 0);
    atomic_init(&queue->next_slab_index, 1);
    atomic_init(&queue->available, config->capacity);
    atomic_init(&queue->speculative_unused, 0);
    atomic_init(&queue->in_flight, 0);
    atomic_init(&queue->live_producers, 0);
#if defined(ENABLE_IMDIAG) || defined(CA_TESTING)
    atomic_init(&queue->injected_chunk_alloc_failures, 0);
#endif
    atomic_init(&queue->live_reservations, 0);
    atomic_init(&queue->live_leases, 0);
    atomic_init(&queue->live_builders, 0);
    atomic_init(&queue->live_claims, 0);
    atomic_init(&queue->live_waiters, 0);
    atomic_init(&queue->live_bindings, 0);
    atomic_init(&queue->chunks_live_count, 0);
    atomic_init(&queue->chunks_pooled_count, 0);
    atomic_init(&queue->lifecycle_writer, 0);
    atomic_init(&queue->control_owner, 0);
    for (size_t i = 0; i < queue->lifecycle_slot_count; ++i) {
        atomic_init(&queue->lifecycle_slots[i].state, 0);
        atomic_init(&queue->lifecycle_slots[i].bound, 0);
    }
    atomic_init(&queue->epoch, 0);
    atomic_init(&queue->capacity_epoch, 0);
#if CA_USE_FUTEX
    atomic_init(&queue->epoch_futex, 0);
    atomic_init(&queue->capacity_epoch_futex, 0);
#endif
    atomic_init(&queue->sleepers, 0);
    atomic_init(&queue->capacity_sleepers, 0);
    atomic_init(&queue->accepting, 1);
    atomic_init(&queue->publishing, 1);
    atomic_init(&queue->claiming, 1);
    atomic_init(&queue->waiting, 1);
    atomic_init(&queue->destroying, 0);
#ifdef CA_TESTING
    atomic_init(&queue->test_pause_before_lifecycle_cas, 0);
    atomic_init(&queue->test_before_lifecycle_cas_entered, 0);
    atomic_init(&queue->test_before_lifecycle_cas_release, 0);
    atomic_init(&queue->test_pause_role, -1);
    atomic_init(&queue->test_role_entered, 0);
    atomic_init(&queue->test_role_release, 0);
    atomic_init(&queue->test_pause_claim, 0);
    atomic_init(&queue->test_claim_entered, 0);
    atomic_init(&queue->test_claim_release, 0);
    atomic_init(&queue->test_pause_producer_pin, 0);
    atomic_init(&queue->test_producer_pin_entered, 0);
    atomic_init(&queue->test_producer_pin_release, 0);
    atomic_init(&queue->test_pause_before_producer_ref, 0);
    atomic_init(&queue->test_before_producer_ref_entered, 0);
    atomic_init(&queue->test_before_producer_ref_release, 0);
    atomic_init(&queue->test_chunk_allocations, 0);
    atomic_init(&queue->test_chunk_fail_after, SIZE_MAX);
    atomic_init(&queue->test_builder_item_allocations, 0);
#endif
#ifdef CA_ENABLE_DIAGNOSTICS
    #define INIT_DIAG(member) atomic_init(&queue->diag.member, 0)
    INIT_DIAG(capacity_attempts);
    INIT_DIAG(capacity_failures);
    INIT_DIAG(cas_retries);
    INIT_DIAG(faa_operations);
    INIT_DIAG(publish_calls);
    INIT_DIAG(published_items);
    INIT_DIAG(largest_publication);
    INIT_DIAG(claim_calls);
    INIT_DIAG(claimed_items);
    INIT_DIAG(largest_claim);
    INIT_DIAG(ready_enqueues);
    INIT_DIAG(ready_dequeues);
    INIT_DIAG(ready_retries);
    INIT_DIAG(dedicated_publications);
    INIT_DIAG(fallback_publications);
    INIT_DIAG(chunks_allocated);
    INIT_DIAG(chunks_freed);
    INIT_DIAG(chunks_live);
    INIT_DIAG(chunks_pooled);
    INIT_DIAG(wake_requests);
    INIT_DIAG(sleeps);
    INIT_DIAG(retry_barriers);
    #undef INIT_DIAG
#endif
    if (!ca_ready_scq_is_lock_free() || !atomic_is_lock_free(&queue->epoch) ||
        !atomic_is_lock_free(&queue->capacity_epoch) || !atomic_is_lock_free(&queue->lifecycle_slots[0].state) ||
        !atomic_is_lock_free(&queue->available)
#if CA_USE_FUTEX
        || !atomic_is_lock_free(&queue->epoch_futex) || !atomic_is_lock_free(&queue->capacity_epoch_futex) ||
        ((uintptr_t)&queue->epoch_futex % sizeof(uint32_t)) != 0 ||
        ((uintptr_t)&queue->capacity_epoch_futex % sizeof(uint32_t)) != 0
#endif
    ) {
        free(queue->lanes);
        free(queue->lifecycle_slots);
        free(queue);
        return CA_INVALID;
    }
    ca_ready_scq_result_t ready_status = ca_ready_scq_create(ready_capacity, &queue->ready);
    if (ready_status != CA_READY_SCQ_OK) {
        free(queue->lanes);
        free(queue->lifecycle_slots);
        free(queue);
        return ready_status == CA_READY_SCQ_NOMEM ? CA_NO_MEMORY : CA_INVALID;
    }
#if !CA_USE_FUTEX
    if (pthread_mutex_init(&queue->wait_mutex, NULL) != 0) {
        (void)ca_ready_scq_destroy(queue->ready);
        free(queue->lanes);
        free(queue->lifecycle_slots);
        free(queue);
        return CA_INVALID;
    }
    if (pthread_cond_init(&queue->wait_cond, NULL) != 0) {
        pthread_mutex_destroy(&queue->wait_mutex);
        (void)ca_ready_scq_destroy(queue->ready);
        free(queue->lanes);
        free(queue->lifecycle_slots);
        free(queue);
        return CA_INVALID;
    }
    if (pthread_cond_init(&queue->capacity_wait_cond, NULL) != 0) {
        pthread_cond_destroy(&queue->wait_cond);
        pthread_mutex_destroy(&queue->wait_mutex);
        (void)ca_ready_scq_destroy(queue->ready);
        free(queue->lanes);
        free(queue->lifecycle_slots);
        free(queue);
        return CA_INVALID;
    }
#endif
    for (size_t i = 0; i < lane_count; ++i) {
        struct ca_lane *lane = &queue->lanes[i];
        lane->queue = queue;
        lane->index = (uint32_t)i;
        lane->generation = 1;
        lane->fallback = i >= dedicated_limit;
        atomic_flag_clear(&lane->gate);
        atomic_init(&lane->assigned, lane->fallback ? 1U : 0U);
        atomic_init(&lane->token_state, CA_TOKEN_ABSENT);
        lane->inline_slot.offset = UINT8_MAX;
        lane->inline_slot.retry_next = NULL;
        atomic_init(&lane->inline_slot.state, CA_SLOT_UNUSED);
    }
    *result = &queue->base;
    return CA_OK;
}

static void sparse_diagnostics_read(const ca_queue_t *base, ca_diagnostics_t *diagnostics) {
    struct sparse_queue *mutable_queue = as_sparse((ca_queue_t *)base);
    if (lifecycle_enter(mutable_queue, CA_ROLE_INSPECT) != CA_OK) return;
#ifdef CA_ENABLE_DIAGNOSTICS
    const struct sparse_queue *queue = mutable_queue;
    #define LOAD_DIAG(member) diagnostics->member = atomic_load_explicit(&queue->diag.member, memory_order_relaxed)
    LOAD_DIAG(capacity_attempts);
    LOAD_DIAG(capacity_failures);
    LOAD_DIAG(cas_retries);
    LOAD_DIAG(faa_operations);
    LOAD_DIAG(publish_calls);
    LOAD_DIAG(published_items);
    LOAD_DIAG(largest_publication);
    LOAD_DIAG(claim_calls);
    LOAD_DIAG(claimed_items);
    LOAD_DIAG(largest_claim);
    LOAD_DIAG(ready_enqueues);
    LOAD_DIAG(ready_dequeues);
    LOAD_DIAG(ready_retries);
    LOAD_DIAG(dedicated_publications);
    LOAD_DIAG(fallback_publications);
    LOAD_DIAG(chunks_allocated);
    LOAD_DIAG(chunks_freed);
    LOAD_DIAG(chunks_live);
    LOAD_DIAG(chunks_pooled);
    LOAD_DIAG(wake_requests);
    LOAD_DIAG(sleeps);
    LOAD_DIAG(retry_barriers);
    #undef LOAD_DIAG
#else
    (void)base;
    (void)diagnostics;
#endif
    lifecycle_exit(mutable_queue, CA_ROLE_INSPECT);
}

static size_t sparse_dedicated_lane_limit(const ca_queue_t *base) {
    struct sparse_queue *queue = as_sparse((ca_queue_t *)base);
    if (lifecycle_enter(queue, CA_ROLE_INSPECT) != CA_OK) return 0;
    const size_t result = queue->dedicated_limit;
    lifecycle_exit(queue, CA_ROLE_INSPECT);
    return result;
}

static size_t sparse_fallback_lane_count(const ca_queue_t *base) {
    struct sparse_queue *queue = as_sparse((ca_queue_t *)base);
    if (lifecycle_enter(queue, CA_ROLE_INSPECT) != CA_OK) return 0;
    const size_t result = queue->fallback_count;
    lifecycle_exit(queue, CA_ROLE_INSPECT);
    return result;
}

static size_t sparse_ready_ring_capacity(const ca_queue_t *base) {
    struct sparse_queue *queue = as_sparse((ca_queue_t *)base);
    if (lifecycle_enter(queue, CA_ROLE_INSPECT) != CA_OK) return 0;
    const size_t result = ca_ready_scq_capacity(queue->ready);
    lifecycle_exit(queue, CA_ROLE_INSPECT);
    return result;
}

static void sparse_test_fail_next_chunk_allocations(ca_queue_t *base, size_t count) {
    if (base == NULL) return;
#if defined(ENABLE_IMDIAG) || defined(CA_TESTING)
    atomic_store_explicit(&as_sparse(base)->injected_chunk_alloc_failures, count, memory_order_release);
#else
    (void)count;
#endif
}

#ifdef CA_TESTING
void ca_test_pause_role(ca_queue_t *base, int role) {
    struct sparse_queue *queue = as_sparse(base);
    atomic_store_explicit(&queue->test_role_entered, 0, memory_order_relaxed);
    atomic_store_explicit(&queue->test_role_release, 0, memory_order_relaxed);
    atomic_store_explicit(&queue->test_pause_role, role, memory_order_release);
}

int ca_test_role_entered(ca_queue_t *base) {
    return atomic_load_explicit(&as_sparse(base)->test_role_entered, memory_order_acquire);
}

void ca_test_release_role(ca_queue_t *base) {
    struct sparse_queue *queue = as_sparse(base);
    atomic_store_explicit(&queue->test_role_release, 1, memory_order_release);
    atomic_store_explicit(&queue->test_pause_role, -1, memory_order_release);
}

void ca_test_pause_before_lifecycle_cas(ca_queue_t *base) {
    struct sparse_queue *queue = as_sparse(base);
    atomic_store_explicit(&queue->test_before_lifecycle_cas_entered, 0, memory_order_relaxed);
    atomic_store_explicit(&queue->test_before_lifecycle_cas_release, 0, memory_order_relaxed);
    atomic_store_explicit(&queue->test_pause_before_lifecycle_cas, 1, memory_order_release);
}

int ca_test_before_lifecycle_cas_entered(ca_queue_t *base) {
    return atomic_load_explicit(&as_sparse(base)->test_before_lifecycle_cas_entered, memory_order_acquire);
}

void ca_test_release_before_lifecycle_cas(ca_queue_t *base) {
    struct sparse_queue *queue = as_sparse(base);
    atomic_store_explicit(&queue->test_before_lifecycle_cas_release, 1, memory_order_release);
    atomic_store_explicit(&queue->test_pause_before_lifecycle_cas, 0, memory_order_release);
}

size_t ca_test_waiter_count(ca_queue_t *base) {
    return atomic_load_explicit(&as_sparse(base)->live_waiters, memory_order_acquire);
}

size_t ca_test_work_sleepers(ca_queue_t *base) {
    return atomic_load_explicit(&as_sparse(base)->sleepers, memory_order_acquire);
}

size_t ca_test_capacity_sleepers(ca_queue_t *base) {
    return atomic_load_explicit(&as_sparse(base)->capacity_sleepers, memory_order_acquire);
}

ca_status_t ca_test_seed_empty_lane(ca_queue_t *base, ca_producer_t *producer, uint64_t ordinal) {
    struct sparse_queue *queue = as_sparse(base);
    struct ca_lane *lane;
    if (validate_producer(queue, producer, &lane) != CA_OK) return CA_INVALID;
    lane_lock(lane);
    if (lane->published_tail != lane->final_frontier || lane->claim_cursor != lane->published_tail ||
        lane->chunks_head != NULL) {
        lane_unlock(lane);
        producer_op_exit(producer);
        return CA_BUSY;
    }
    lane->published_tail = ordinal;
    lane->claim_cursor = ordinal;
    lane->final_frontier = ordinal;
    lane_unlock(lane);
    producer_op_exit(producer);
    return CA_OK;
}

void ca_test_pause_normal_claim(ca_queue_t *base) {
    struct sparse_queue *queue = as_sparse(base);
    atomic_store_explicit(&queue->test_claim_entered, 0, memory_order_relaxed);
    atomic_store_explicit(&queue->test_claim_release, 0, memory_order_relaxed);
    atomic_store_explicit(&queue->test_pause_claim, 1, memory_order_release);
}

int ca_test_normal_claim_entered(ca_queue_t *base) {
    return atomic_load_explicit(&as_sparse(base)->test_claim_entered, memory_order_acquire);
}

void ca_test_release_normal_claim(ca_queue_t *base) {
    struct sparse_queue *queue = as_sparse(base);
    atomic_store_explicit(&queue->test_claim_release, 1, memory_order_release);
    atomic_store_explicit(&queue->test_pause_claim, 0, memory_order_release);
}

void ca_test_pause_producer_pin(ca_queue_t *base) {
    struct sparse_queue *queue = as_sparse(base);
    atomic_store_explicit(&queue->test_producer_pin_entered, 0, memory_order_relaxed);
    atomic_store_explicit(&queue->test_producer_pin_release, 0, memory_order_relaxed);
    atomic_store_explicit(&queue->test_pause_producer_pin, 1, memory_order_release);
}

int ca_test_producer_pin_entered(ca_queue_t *base) {
    return atomic_load_explicit(&as_sparse(base)->test_producer_pin_entered, memory_order_acquire);
}

void ca_test_release_producer_pin(ca_queue_t *base) {
    struct sparse_queue *queue = as_sparse(base);
    atomic_store_explicit(&queue->test_producer_pin_release, 1, memory_order_release);
    atomic_store_explicit(&queue->test_pause_producer_pin, 0, memory_order_release);
}

void ca_test_pause_before_producer_ref(ca_queue_t *base) {
    struct sparse_queue *queue = as_sparse(base);
    atomic_store_explicit(&queue->test_before_producer_ref_entered, 0, memory_order_relaxed);
    atomic_store_explicit(&queue->test_before_producer_ref_release, 0, memory_order_relaxed);
    atomic_store_explicit(&queue->test_pause_before_producer_ref, 1, memory_order_release);
}

int ca_test_before_producer_ref_entered(ca_queue_t *base) {
    return atomic_load_explicit(&as_sparse(base)->test_before_producer_ref_entered, memory_order_acquire);
}

void ca_test_release_before_producer_ref(ca_queue_t *base) {
    struct sparse_queue *queue = as_sparse(base);
    atomic_store_explicit(&queue->test_before_producer_ref_release, 1, memory_order_release);
    atomic_store_explicit(&queue->test_pause_before_producer_ref, 0, memory_order_release);
}

int ca_test_producer_closed(ca_producer_t *producer) {
    return (atomic_load_explicit(&producer->op_state, memory_order_acquire) & CA_PRODUCER_CLOSED) != 0;
}

void ca_test_seed_epochs(ca_queue_t *base, uint64_t work, uint64_t capacity) {
    struct sparse_queue *queue = as_sparse(base);
    atomic_store_explicit(&queue->epoch, work, memory_order_release);
    atomic_store_explicit(&queue->capacity_epoch, capacity, memory_order_release);
    #if CA_USE_FUTEX
    atomic_store_explicit(&queue->epoch_futex, (uint32_t)work, memory_order_release);
    atomic_store_explicit(&queue->capacity_epoch_futex, (uint32_t)capacity, memory_order_release);
    #endif
}

void ca_test_fail_chunk_alloc_after(ca_queue_t *base, size_t successful_allocations) {
    struct sparse_queue *queue = as_sparse(base);
    atomic_store_explicit(&queue->test_chunk_allocations, 0, memory_order_relaxed);
    atomic_store_explicit(&queue->test_chunk_fail_after, successful_allocations, memory_order_release);
}

size_t ca_test_chunks_live(ca_queue_t *base) {
    return atomic_load_explicit(&as_sparse(base)->chunks_live_count, memory_order_acquire);
}

size_t ca_test_chunks_pooled(ca_queue_t *base) {
    return atomic_load_explicit(&as_sparse(base)->chunks_pooled_count, memory_order_acquire);
}

size_t ca_test_builder_item_allocations(ca_queue_t *base) {
    return atomic_load_explicit(&as_sparse(base)->test_builder_item_allocations, memory_order_acquire);
}

int ca_test_accepting(ca_queue_t *base) {
    return atomic_load_explicit(&as_sparse(base)->accepting, memory_order_acquire);
}

int ca_test_destroying(ca_queue_t *base) {
    return atomic_load_explicit(&as_sparse(base)->destroying, memory_order_acquire);
}

int ca_test_writer_active(ca_queue_t *base) {
    return atomic_load_explicit(&as_sparse(base)->lifecycle_writer, memory_order_acquire);
}

size_t ca_test_lifecycle_slot(ca_queue_t *base) {
    return lifecycle_slot(as_sparse(base));
}

size_t ca_test_lifecycle_bytes(ca_queue_t *base) {
    return as_sparse(base)->lifecycle_bytes;
}

size_t ca_test_lifecycle_alignment(ca_queue_t *base) {
    (void)base;
    return alignof(struct ca_lifecycle_slot);
}

int ca_test_lifecycle_is_aligned(ca_queue_t *base) {
    return (uintptr_t)as_sparse(base)->lifecycle_slots % alignof(struct ca_lifecycle_slot) == 0;
}
#endif

const struct ca_ops ca_sparse_lanes_ops = {
    .create = sparse_create,
    .destroy = sparse_destroy,
    .lifecycle_bind = sparse_lifecycle_bind,
    .lifecycle_unbind = sparse_lifecycle_unbind,
    .lifecycle_activate = sparse_lifecycle_activate,
    .lifecycle_deactivate = sparse_lifecycle_deactivate,
    .producer_register = sparse_producer_register,
    .producer_register_fallback = sparse_producer_register_fallback,
    .producer_release = sparse_producer_release,
    .reserve = sparse_reserve,
    .prepare_reserved = sparse_prepare_reserved,
    .commit_prepared = sparse_commit_prepared,
    .publish_reserved = sparse_publish_reserved,
    .cancel_reservation = sparse_cancel_reservation,
    .submit_span = sparse_submit_span,
    .credit_acquire = sparse_credit_acquire,
    .credit_submit_span = sparse_credit_submit_span,
    .credit_release = sparse_credit_release,
    .builder_begin = sparse_builder_begin,
    .builder_append = sparse_builder_append,
    .builder_prepare = sparse_builder_prepare,
    .builder_commit = sparse_builder_commit,
    .builder_publish = sparse_builder_publish,
    .builder_cancel = sparse_builder_cancel,
    .claim = sparse_claim,
    .complete = sparse_complete,
    .return_claim = sparse_return_claim,
    .capacity_read = sparse_capacity_read,
    .epoch = sparse_epoch,
    .wait_epoch = sparse_wait_epoch,
    .capacity_epoch = sparse_capacity_epoch,
    .wait_capacity_epoch = sparse_wait_capacity_epoch,
    .interrupt_waiters = sparse_interrupt_waiters,
    .quiesce = sparse_quiesce,
    .diagnostics_read = sparse_diagnostics_read,
    .dedicated_lane_limit = sparse_dedicated_lane_limit,
    .fallback_lane_count = sparse_fallback_lane_count,
    .ready_ring_capacity = sparse_ready_ring_capacity,
    .test_fail_next_chunk_allocations = sparse_test_fail_next_chunk_allocations,
};
