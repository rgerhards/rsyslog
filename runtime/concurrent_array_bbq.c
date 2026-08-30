/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Standalone block-based bounded ConcurrentArray candidate.
 *
 * Logical capacity and physical positions are deliberately separate. Exact
 * admission credits remain charged through completion, while claim detaches a
 * logical record from its physical cell immediately. Producers reserve
 * monotonic positions with fetch-add. Each cell control word atomically packs
 * its generation, state, and record-pool index. A consumer may install a
 * tombstone for an empty reserved generation, so a
 * producer stopped between the FAA and publication cannot obstruct the queue;
 * the producer retries the same fully initialized record when it observes
 * that help.
 *
 * The compact control table is checked and calloc-backed so unused pages stay
 * physically lazy. 64-record metadata slabs grow on demand, reuse bitmap
 * indices, and trim excess slabs at quiescence. Normal publication and claim
 * use only per-cell atomics. Per-producer record chains allow normal
 * records to be claimed concurrently. A completion that requests retry adds a
 * producer-local barrier for later records that were not already claimed,
 * while independent producers continue.
 */

#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif

#include "concurrent_array_internal.h"

#if defined(__GNUC__)
    #pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
#endif

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(__linux__) && !defined(CA_FORCE_PTHREAD_WAIT)
    #include <linux/futex.h>
    #include <sys/syscall.h>
    #include <unistd.h>
    #define BBQ_USE_FUTEX 1
#else
    #define BBQ_USE_FUTEX 0
#endif

#define BBQ_BLOCK_ITEMS 64U
#define BBQ_LEASE_MAX 64U
#define BBQ_CELL_STATE_MASK UINT64_C(3)
#define BBQ_CELL_INDEX_SHIFT 2U

enum bbq_cell_state { BBQ_CELL_EMPTY = 0, BBQ_CELL_FULL = 1, BBQ_CELL_TOMBSTONE = 2, BBQ_CELL_CLAIMED = 3 };

enum bbq_phase { BBQ_PHASE_RUNNING = 0, BBQ_PHASE_DRAIN, BBQ_PHASE_DISCARD, BBQ_PHASE_DESTROY };

enum bbq_record_state {
    BBQ_RECORD_NORMAL = 0,
    BBQ_RECORD_RETRY,
    BBQ_RECORD_NORMAL_BLOCKED,
    BBQ_RECORD_RETRY_BLOCKED,
    BBQ_RECORD_CLAIMED_NORMAL,
    BBQ_RECORD_CLAIMED_RETRY,
    BBQ_RECORD_TERMINAL
};

struct bbq_queue;
struct bbq_record;

struct bbq_producer_state {
    struct bbq_queue *queue;
    struct bbq_producer_state *next;
    struct bbq_record *head;
    struct bbq_record *tail;
    uint64_t stable_key;
    uint64_t next_ordinal;
    uint64_t retry_barrier;
    size_t handle_refs;
    size_t active_completions;
    unsigned fallback;
    atomic_flag gate;
};

struct bbq_record {
    struct bbq_producer_state *producer;
    struct bbq_record *previous;
    struct bbq_record *next;
    void *item;
    uint64_t ordinal;
    size_t pool_index;
    _Atomic unsigned state;
};

struct bbq_record_block {
    struct bbq_record records[BBQ_BLOCK_ITEMS];
};

struct bbq_cell {
    uint64_t control;
};

_Static_assert(_Alignof(struct bbq_cell) >= _Alignof(uint64_t), "BBQ control words must be naturally aligned");

struct bbq_queue {
    ca_queue_t base;
    size_t capacity;
    unsigned consumers;
    size_t block_count;
    size_t record_capacity;
    size_t record_block_count;
    unsigned record_index_bits;
    uint64_t record_index_mask;
    uint64_t generation_max;
    struct bbq_cell *cells;
    _Atomic(struct bbq_record_block *) *record_blocks;
    _Atomic uint64_t *record_bitmap;
    _Atomic size_t record_cursor;
    _Atomic uint64_t publish_position;
    _Atomic uint64_t claim_position;
    struct bbq_producer_state anonymous_producer;
    _Atomic(struct bbq_producer_state *) producers;
    atomic_flag producer_registry_gate;
    _Atomic size_t available;
    _Atomic size_t speculative_unused;
    _Atomic size_t in_flight;
    _Atomic size_t active_calls;
    _Atomic unsigned lifecycle_writer;
    _Atomic size_t live_producers;
    _Atomic size_t live_reservations;
    _Atomic size_t live_leases;
    _Atomic size_t live_builders;
    _Atomic size_t live_claims;
    _Atomic size_t live_waiters;
    _Atomic size_t live_bindings;
    _Atomic size_t binding_cursor;
    _Atomic uint32_t epoch;
    _Atomic uint32_t capacity_epoch;
    _Atomic unsigned sleepers;
    _Atomic unsigned capacity_sleepers;
    _Atomic unsigned accepting;
    _Atomic unsigned publishing;
    _Atomic unsigned claiming;
    _Atomic unsigned waiting;
    _Atomic unsigned destroying;
    _Atomic unsigned phase;
#if !BBQ_USE_FUTEX
    pthread_mutex_t wait_mutex;
    pthread_cond_t wait_cond;
    pthread_cond_t capacity_cond;
#endif
    ca_dispose_fn dispose;
    void *dispose_user;
#ifdef CA_ENABLE_DIAGNOSTICS
    _Atomic uint64_t capacity_attempts;
    _Atomic uint64_t capacity_failures;
    _Atomic uint64_t cas_retries;
    _Atomic uint64_t publish_calls;
    _Atomic uint64_t published_items;
    _Atomic uint64_t claim_calls;
    _Atomic uint64_t claimed_items;
    _Atomic uint64_t ready_enqueues;
    _Atomic uint64_t ready_dequeues;
    _Atomic uint64_t wake_requests;
    _Atomic uint64_t sleeps;
    _Atomic uint64_t retry_barriers;
    _Atomic uint64_t largest_publication;
    _Atomic uint64_t largest_claim;
#endif
#ifdef CA_TESTING
    _Atomic int test_pause_after_faa;
    _Atomic int test_after_faa_entered;
    _Atomic int test_after_faa_release;
    _Atomic int test_pause_after_install;
    _Atomic int test_after_install_entered;
    _Atomic int test_after_install_release;
    _Atomic int test_pause_after_claim;
    _Atomic int test_after_claim_entered;
    _Atomic int test_after_claim_release;
    _Atomic int test_pause_after_record_release;
    _Atomic int test_after_record_release_entered;
    _Atomic int test_after_record_release_release;
    _Atomic int test_pause_after_discard_producer;
    _Atomic int test_after_discard_producer_entered;
    _Atomic int test_after_discard_producer_release;
    _Atomic size_t test_record_word_probes;
#endif
};

static _Thread_local ca_lifecycle_binding_t *bbq_active_binding;

#ifdef CA_ENABLE_DIAGNOSTICS
    #define BBQ_DIAG_INC(q, member) atomic_fetch_add_explicit(&(q)->member, 1, memory_order_relaxed)
    #define BBQ_DIAG_ADD(q, member, value) atomic_fetch_add_explicit(&(q)->member, (value), memory_order_relaxed)
static void bbq_diag_max(_Atomic uint64_t *maximum, uint64_t value) {
    uint64_t old = atomic_load_explicit(maximum, memory_order_relaxed);
    while (old < value &&
           !atomic_compare_exchange_weak_explicit(maximum, &old, value, memory_order_relaxed, memory_order_relaxed));
}
#else
    #define BBQ_DIAG_INC(q, member) ((void)(q))
    #define BBQ_DIAG_ADD(q, member, value) ((void)(q), (void)(value))
#endif

static struct bbq_queue *as_bbq(ca_queue_t *base) {
    return (struct bbq_queue *)base;
}

static int checked_mul_size(size_t left, size_t right, size_t *result) {
    if (left != 0 && right > SIZE_MAX / left) return 0;
    *result = left * right;
    return 1;
}

static uint64_t cell_control(const struct bbq_queue *queue,
                             uint64_t generation,
                             enum bbq_cell_state state,
                             size_t record_index) {
    if (generation > queue->generation_max || record_index > queue->record_index_mask) abort();
    return (generation << (BBQ_CELL_INDEX_SHIFT + queue->record_index_bits)) |
           ((uint64_t)record_index << BBQ_CELL_INDEX_SHIFT) | (uint64_t)state;
}

static uint64_t cell_generation(const struct bbq_queue *queue, uint64_t control) {
    return control >> (BBQ_CELL_INDEX_SHIFT + queue->record_index_bits);
}

static enum bbq_cell_state cell_state(uint64_t control) {
    return (enum bbq_cell_state)(control & BBQ_CELL_STATE_MASK);
}

static size_t cell_record_index(const struct bbq_queue *queue, uint64_t control) {
    return (size_t)((control >> BBQ_CELL_INDEX_SHIFT) & queue->record_index_mask);
}

static uint64_t cell_control_load(const struct bbq_cell *cell) {
    return __atomic_load_n(&cell->control, __ATOMIC_ACQUIRE);
}

static int cell_control_cas(struct bbq_cell *cell, uint64_t *expected, uint64_t desired) {
    return __atomic_compare_exchange_n(&cell->control, expected, desired, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
}

static int deadline_expired(const struct timespec *deadline) {
    if (deadline == NULL) return 0;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return now.tv_sec > deadline->tv_sec || (now.tv_sec == deadline->tv_sec && now.tv_nsec >= deadline->tv_nsec);
}

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

#if !BBQ_USE_FUTEX
static void realtime_deadline(const struct timespec *monotonic, struct timespec *realtime) {
    struct timespec mono_now;
    struct timespec real_now;
    clock_gettime(CLOCK_MONOTONIC, &mono_now);
    clock_gettime(CLOCK_REALTIME, &real_now);
    realtime->tv_sec = real_now.tv_sec + monotonic->tv_sec - mono_now.tv_sec;
    realtime->tv_nsec = real_now.tv_nsec + monotonic->tv_nsec - mono_now.tv_nsec;
    if (realtime->tv_nsec >= 1000000000L) {
        ++realtime->tv_sec;
        realtime->tv_nsec -= 1000000000L;
    } else if (realtime->tv_nsec < 0) {
        --realtime->tv_sec;
        realtime->tv_nsec += 1000000000L;
    }
}
#endif

static ca_status_t operation_enter(struct bbq_queue *queue) {
    if (atomic_load_explicit(&queue->destroying, memory_order_acquire) ||
        atomic_load_explicit(&queue->lifecycle_writer, memory_order_acquire))
        return CA_CLOSED;
    atomic_fetch_add_explicit(&queue->active_calls, 1, memory_order_acquire);
    if (atomic_load_explicit(&queue->destroying, memory_order_acquire) ||
        atomic_load_explicit(&queue->lifecycle_writer, memory_order_acquire)) {
        atomic_fetch_sub_explicit(&queue->active_calls, 1, memory_order_release);
        return CA_CLOSED;
    }
    return CA_OK;
}

static void operation_exit(struct bbq_queue *queue) {
    atomic_fetch_sub_explicit(&queue->active_calls, 1, memory_order_release);
}

static ca_status_t writer_begin(struct bbq_queue *queue, const struct timespec *deadline) {
    unsigned expected = 0;
    while (!atomic_compare_exchange_weak_explicit(&queue->lifecycle_writer, &expected, 1, memory_order_acq_rel,
                                                  memory_order_relaxed)) {
        expected = 0;
        if (deadline_expired(deadline)) return CA_TIMED_OUT;
        sched_yield();
    }
    while (atomic_load_explicit(&queue->active_calls, memory_order_acquire) != 0) {
        if (deadline_expired(deadline)) {
            atomic_store_explicit(&queue->lifecycle_writer, 0, memory_order_release);
            return CA_TIMED_OUT;
        }
        sched_yield();
    }
    return CA_OK;
}

static void writer_end(struct bbq_queue *queue) {
    atomic_store_explicit(&queue->lifecycle_writer, 0, memory_order_release);
}

static void producer_lock(struct bbq_producer_state *producer) {
    while (atomic_flag_test_and_set_explicit(&producer->gate, memory_order_acquire)) sched_yield();
}

static void producer_unlock(struct bbq_producer_state *producer) {
    atomic_flag_clear_explicit(&producer->gate, memory_order_release);
}

static void producer_registry_lock(struct bbq_queue *queue) {
    while (atomic_flag_test_and_set_explicit(&queue->producer_registry_gate, memory_order_acquire)) sched_yield();
}

static void producer_registry_unlock(struct bbq_queue *queue) {
    atomic_flag_clear_explicit(&queue->producer_registry_gate, memory_order_release);
}

static void producer_registry_unlink(struct bbq_queue *queue, struct bbq_producer_state *producer) {
    struct bbq_producer_state *previous = NULL;
    struct bbq_producer_state *scan = atomic_load_explicit(&queue->producers, memory_order_relaxed);
    while (scan != NULL && scan != producer) {
        previous = scan;
        scan = scan->next;
    }
    if (scan == NULL) abort();
    if (previous == NULL)
        atomic_store_explicit(&queue->producers, producer->next, memory_order_release);
    else
        previous->next = producer->next;
}

static void producer_completion_exit(struct bbq_queue *queue, struct bbq_producer_state *producer) {
    if (producer == &queue->anonymous_producer) {
        producer_lock(producer);
        if (producer->active_completions == 0) abort();
        --producer->active_completions;
        producer_unlock(producer);
        return;
    }
    producer_registry_lock(queue);
    producer_lock(producer);
    if (producer->active_completions == 0) abort();
    --producer->active_completions;
    const int reclaim = atomic_load_explicit(&queue->phase, memory_order_acquire) == BBQ_PHASE_RUNNING &&
                        producer->handle_refs == 0 && producer->active_completions == 0 && producer->head == NULL;
    if (reclaim) producer_registry_unlink(queue, producer);
    producer_unlock(producer);
    producer_registry_unlock(queue);
    if (reclaim) free(producer);
}

static void event_signal_on(struct bbq_queue *queue,
                            _Atomic uint32_t *epoch,
                            _Atomic unsigned *sleepers,
#if !BBQ_USE_FUTEX
                            pthread_cond_t *condition,
#endif
                            int all) {
#if BBQ_USE_FUTEX
    atomic_fetch_add_explicit(epoch, 1, memory_order_release);
    if (atomic_load_explicit(sleepers, memory_order_acquire) != 0) {
        BBQ_DIAG_INC(queue, wake_requests);
        (void)syscall(SYS_futex, epoch, FUTEX_WAKE_PRIVATE, all ? INT_MAX : 1, NULL, NULL, 0);
    }
#else
    pthread_mutex_lock(&queue->wait_mutex);
    atomic_fetch_add_explicit(epoch, 1, memory_order_release);
    BBQ_DIAG_INC(queue, wake_requests);
    if (all)
        pthread_cond_broadcast(condition);
    else
        pthread_cond_signal(condition);
    pthread_mutex_unlock(&queue->wait_mutex);
#endif
}

static void signal_work(struct bbq_queue *queue, int all) {
    event_signal_on(queue, &queue->epoch, &queue->sleepers,
#if !BBQ_USE_FUTEX
                    &queue->wait_cond,
#endif
                    all);
}

static void signal_capacity(struct bbq_queue *queue, int all) {
    event_signal_on(queue, &queue->capacity_epoch, &queue->capacity_sleepers,
#if !BBQ_USE_FUTEX
                    &queue->capacity_cond,
#endif
                    all);
}

static ca_status_t reserve_capacity(struct bbq_queue *queue, size_t wanted, size_t *granted) {
    *granted = 0;
    if (wanted == 0) return CA_INVALID;
    BBQ_DIAG_INC(queue, capacity_attempts);
    size_t available = atomic_load_explicit(&queue->available, memory_order_relaxed);
    for (;;) {
        if (available == 0) {
            BBQ_DIAG_INC(queue, capacity_failures);
            return CA_FULL;
        }
        const size_t take = available < wanted ? available : wanted;
        if (atomic_compare_exchange_weak_explicit(&queue->available, &available, available - take, memory_order_acq_rel,
                                                  memory_order_relaxed)) {
            *granted = take;
            return take == wanted ? CA_OK : CA_PARTIAL;
        }
        BBQ_DIAG_INC(queue, cas_retries);
    }
}

static void release_capacity(struct bbq_queue *queue, size_t count) {
    if (count == 0) return;
    const size_t old = atomic_fetch_add_explicit(&queue->available, count, memory_order_release);
    if (old > queue->capacity || count > queue->capacity - old) abort();
    signal_capacity(queue, count > 1);
}

static struct bbq_cell *cell_get(struct bbq_queue *queue, uint64_t position) {
    const size_t index = (size_t)(position % queue->capacity);
    return &queue->cells[index];
}

static struct bbq_record_block *record_block_get(struct bbq_queue *queue, size_t block_index) {
    struct bbq_record_block *block = atomic_load_explicit(&queue->record_blocks[block_index], memory_order_acquire);
    if (block != NULL) return block;
    struct bbq_record_block *created = calloc(1, sizeof(*created));
    if (created == NULL) return NULL;
    struct bbq_record_block *expected = NULL;
    if (!atomic_compare_exchange_strong_explicit(&queue->record_blocks[block_index], &expected, created,
                                                 memory_order_release, memory_order_acquire)) {
        free(created);
        block = expected;
    } else {
        block = created;
    }
    return block;
}

static struct bbq_record *record_at(struct bbq_queue *queue, size_t index) {
    if (index >= queue->record_capacity) abort();
    struct bbq_record_block *block =
        atomic_load_explicit(&queue->record_blocks[index / BBQ_BLOCK_ITEMS], memory_order_acquire);
    if (block == NULL) abort();
    return &block->records[index % BBQ_BLOCK_ITEMS];
}

static struct bbq_record *record_acquire(struct bbq_queue *queue) {
    for (;;) {
        const size_t start =
            atomic_fetch_add_explicit(&queue->record_cursor, 1, memory_order_relaxed) % queue->record_block_count;
        for (size_t offset = 0; offset < queue->record_block_count; ++offset) {
            const size_t word_index = (start + offset) % queue->record_block_count;
#ifdef CA_TESTING
            atomic_fetch_add_explicit(&queue->test_record_word_probes, 1, memory_order_relaxed);
#endif
            uint64_t word = atomic_load_explicit(&queue->record_bitmap[word_index], memory_order_relaxed);
            for (;;) {
                uint64_t free_bits = ~word;
                if (word_index + 1 == queue->record_block_count && queue->record_capacity % BBQ_BLOCK_ITEMS != 0)
                    free_bits &= (UINT64_C(1) << (queue->record_capacity % BBQ_BLOCK_ITEMS)) - 1;
                if (free_bits == 0) break;
                const unsigned bit = (unsigned)__builtin_ctzll(free_bits);
                const uint64_t mask = UINT64_C(1) << bit;
                if (atomic_compare_exchange_weak_explicit(&queue->record_bitmap[word_index], &word, word | mask,
                                                          memory_order_acq_rel, memory_order_relaxed)) {
                    struct bbq_record_block *block = record_block_get(queue, word_index);
                    if (block == NULL) {
                        atomic_fetch_and_explicit(&queue->record_bitmap[word_index], ~mask, memory_order_release);
                        atomic_store_explicit(&queue->record_cursor, word_index, memory_order_relaxed);
                        return NULL;
                    }
                    struct bbq_record *record = &block->records[bit];
                    memset(record, 0, sizeof(*record));
                    record->pool_index = word_index * BBQ_BLOCK_ITEMS + bit;
                    return record;
                }
            }
        }
        sched_yield();
    }
}

static void record_release(struct bbq_queue *queue, struct bbq_record *record) {
    const size_t index = record->pool_index;
    memset(record, 0, sizeof(*record));
    atomic_fetch_and_explicit(&queue->record_bitmap[index / BBQ_BLOCK_ITEMS],
                              ~(UINT64_C(1) << (index % BBQ_BLOCK_ITEMS)), memory_order_release);
    atomic_store_explicit(&queue->record_cursor, index / BBQ_BLOCK_ITEMS, memory_order_relaxed);
}

static void record_pool_trim(struct bbq_queue *queue) {
    for (size_t i = 1; i < queue->record_block_count; ++i) {
        if (atomic_load_explicit(&queue->record_bitmap[i], memory_order_acquire) != 0) abort();
        struct bbq_record_block *block = atomic_exchange_explicit(&queue->record_blocks[i], NULL, memory_order_acq_rel);
        free(block);
    }
    atomic_store_explicit(&queue->record_cursor, 0, memory_order_relaxed);
}

static void physical_publish(struct bbq_queue *queue, struct bbq_record *record) {
    for (;;) {
        const uint64_t position = atomic_fetch_add_explicit(&queue->publish_position, 1, memory_order_relaxed);
        const uint64_t generation = position / queue->capacity;
        if (generation >= queue->generation_max) abort();
        struct bbq_cell *cell = cell_get(queue, position);
        uint64_t control;
        do {
            control = cell_control_load(cell);
            if (cell_generation(queue, control) < generation) {
                const enum bbq_cell_state state = cell_state(control);
                if (state == BBQ_CELL_CLAIMED || state == BBQ_CELL_TOMBSTONE) {
                    const uint64_t old_generation = cell_generation(queue, control);
                    (void)cell_control_cas(cell, &control, cell_control(queue, old_generation + 1, BBQ_CELL_EMPTY, 0));
                } else {
                    sched_yield();
                }
            }
        } while (cell_generation(queue, control) < generation);
        if (cell_generation(queue, control) != generation || cell_state(control) != BBQ_CELL_EMPTY) continue;
#ifdef CA_TESTING
        int pause_expected = 1;
        if (atomic_compare_exchange_strong_explicit(&queue->test_pause_after_faa, &pause_expected, 0,
                                                    memory_order_acq_rel, memory_order_acquire)) {
            atomic_store_explicit(&queue->test_after_faa_entered, 1, memory_order_release);
            while (!atomic_load_explicit(&queue->test_after_faa_release, memory_order_acquire)) sched_yield();
        }
#endif
        BBQ_DIAG_INC(queue, ready_enqueues);
        signal_work(queue, 0);
        uint64_t expected_control = cell_control(queue, generation, BBQ_CELL_EMPTY, 0);
        if (!cell_control_cas(cell, &expected_control,
                              cell_control(queue, generation, BBQ_CELL_FULL, record->pool_index)))
            continue;
#ifdef CA_TESTING
        pause_expected = 1;
        if (atomic_compare_exchange_strong_explicit(&queue->test_pause_after_install, &pause_expected, 0,
                                                    memory_order_acq_rel, memory_order_acquire)) {
            atomic_store_explicit(&queue->test_after_install_entered, 1, memory_order_release);
            while (!atomic_load_explicit(&queue->test_after_install_release, memory_order_acquire)) sched_yield();
        }
#endif
        return;
    }
}

static struct bbq_producer_state *producer_state(struct bbq_queue *queue, ca_producer_t *producer) {
    if (producer == NULL) return &queue->anonymous_producer;
    if (!producer->active || producer->queue != &queue->base || producer->private_state == NULL) return NULL;
    struct bbq_producer_state *state = producer->private_state;
    return state->queue == queue ? state : NULL;
}

static ca_status_t publish_items(struct bbq_queue *queue,
                                 struct bbq_producer_state *producer,
                                 void *const *items,
                                 size_t count) {
    if (items == NULL || count == 0 || producer == NULL) return CA_INVALID;
    struct bbq_record *first = NULL;
    struct bbq_record *last = NULL;
    for (size_t i = 0; i < count; ++i) {
        struct bbq_record *record = record_acquire(queue);
        if (record == NULL) {
            while (first != NULL) {
                struct bbq_record *next = first->next;
                record_release(queue, first);
                first = next;
            }
            return CA_NO_MEMORY;
        }
        record->producer = producer;
        record->item = items[i];
        atomic_init(&record->state, BBQ_RECORD_NORMAL);
        if (last == NULL)
            first = record;
        else {
            record->previous = last;
            last->next = record;
        }
        last = record;
    }
    producer_lock(producer);
    if (count > UINT64_MAX - producer->next_ordinal) {
        producer_unlock(producer);
        while (first != NULL) {
            struct bbq_record *next = first->next;
            record_release(queue, first);
            first = next;
        }
        return CA_INVALID;
    }
    uint64_t ordinal = producer->next_ordinal;
    for (struct bbq_record *record = first; record != NULL; record = record->next) record->ordinal = ordinal++;
    producer->next_ordinal = ordinal;
    if (producer->tail == NULL) {
        producer->head = first;
    } else {
        first->previous = producer->tail;
        producer->tail->next = first;
    }
    producer->tail = last;
    producer_unlock(producer);
    for (struct bbq_record *record = first; record != NULL;) {
        struct bbq_record *next = record->next;
        physical_publish(queue, record);
        record = next;
    }
    BBQ_DIAG_INC(queue, publish_calls);
    BBQ_DIAG_ADD(queue, published_items, count);
#ifdef CA_ENABLE_DIAGNOSTICS
    bbq_diag_max(&queue->largest_publication, count);
#endif
    return CA_OK;
}

static int record_try_claim(struct bbq_record *record, int *was_retry) {
    struct bbq_producer_state *producer = record->producer;
    int claimed = 0;
    producer_lock(producer);
    const unsigned state = atomic_load_explicit(&record->state, memory_order_acquire);
    if (state == BBQ_RECORD_NORMAL &&
        (producer->retry_barrier == UINT64_MAX || record->ordinal < producer->retry_barrier)) {
        *was_retry = 0;
        atomic_store_explicit(&record->state, BBQ_RECORD_CLAIMED_NORMAL, memory_order_release);
        claimed = 1;
    } else if (state == BBQ_RECORD_NORMAL) {
        atomic_store_explicit(&record->state, BBQ_RECORD_NORMAL_BLOCKED, memory_order_release);
    } else if (state == BBQ_RECORD_RETRY && producer->head == record) {
        *was_retry = 1;
        atomic_store_explicit(&record->state, BBQ_RECORD_CLAIMED_RETRY, memory_order_release);
        claimed = 1;
    } else if (state == BBQ_RECORD_RETRY) {
        atomic_store_explicit(&record->state, BBQ_RECORD_RETRY_BLOCKED, memory_order_release);
    }
    producer_unlock(producer);
    return claimed;
}

static void cell_finish(struct bbq_queue *queue, struct bbq_cell *cell, uint64_t position, uint64_t expected_control) {
    const uint64_t generation = position / queue->capacity;
    if (!cell_control_cas(cell, &expected_control, cell_control(queue, generation + 1, BBQ_CELL_EMPTY, 0)) &&
        cell_generation(queue, expected_control) <= generation)
        abort();
}

static ca_status_t claim_records(struct bbq_queue *queue,
                                 ca_claim_item_t *items,
                                 size_t maximum,
                                 size_t *claimed_count) {
    size_t count = 0;
    while (count < maximum) {
        uint64_t position = atomic_load_explicit(&queue->claim_position, memory_order_acquire);
        if (position >= atomic_load_explicit(&queue->publish_position, memory_order_acquire)) break;
        if (!atomic_compare_exchange_weak_explicit(&queue->claim_position, &position, position + 1,
                                                   memory_order_acq_rel, memory_order_acquire))
            continue;
        struct bbq_cell *cell = cell_get(queue, position);
        const uint64_t generation = position / queue->capacity;
        uint64_t control;
        do {
            control = cell_control_load(cell);
            if (cell_generation(queue, control) < generation) sched_yield();
        } while (cell_generation(queue, control) < generation);
        if (cell_generation(queue, control) != generation) abort();
        if (cell_state(control) == BBQ_CELL_EMPTY) {
            uint64_t expected_control = cell_control(queue, generation, BBQ_CELL_EMPTY, 0);
            (void)cell_control_cas(cell, &expected_control, cell_control(queue, generation, BBQ_CELL_TOMBSTONE, 0));
            control = cell_control_load(cell);
        }
        if (cell_generation(queue, control) != generation) abort();
        if (cell_state(control) == BBQ_CELL_TOMBSTONE) {
            cell_finish(queue, cell, position, control);
            continue;
        }
        if (cell_state(control) != BBQ_CELL_FULL) abort();
        const size_t record_index = cell_record_index(queue, control);
        uint64_t expected_control = control;
        const uint64_t claimed_control = cell_control(queue, generation, BBQ_CELL_CLAIMED, record_index);
        if (!cell_control_cas(cell, &expected_control, claimed_control)) abort();
#ifdef CA_TESTING
        int pause_expected = 1;
        if (atomic_compare_exchange_strong_explicit(&queue->test_pause_after_claim, &pause_expected, 0,
                                                    memory_order_acq_rel, memory_order_acquire)) {
            atomic_store_explicit(&queue->test_after_claim_entered, 1, memory_order_release);
            while (!atomic_load_explicit(&queue->test_after_claim_release, memory_order_acquire)) sched_yield();
        }
#endif
        struct bbq_record *record = record_at(queue, record_index);
        cell_finish(queue, cell, position, claimed_control);
        int was_retry = 0;
        const int won = record_try_claim(record, &was_retry);
        BBQ_DIAG_INC(queue, ready_dequeues);
        if (!won) continue;
        items[count++] = (ca_claim_item_t){
            .item = record->item, .slot = (ca_slot_meta_t *)record, .ordinal = record->ordinal, .was_retry = was_retry};
    }
    *claimed_count = count;
    return count == 0 ? CA_EMPTY : CA_OK;
}

static ca_status_t bbq_lifecycle_bind(ca_queue_t *base, ca_lifecycle_binding_t *binding) {
    if (binding == NULL) return CA_INVALID;
    struct bbq_queue *queue = as_bbq(base);
    ca_status_t status = operation_enter(queue);
    if (status != CA_OK) return status;
    memset(binding, 0, sizeof(*binding));
    binding->queue = base;
    binding->slot = atomic_fetch_add_explicit(&queue->binding_cursor, 1, memory_order_relaxed);
    atomic_init(&binding->activations, 0);
    binding->active = 1;
    atomic_fetch_add_explicit(&queue->live_bindings, 1, memory_order_relaxed);
    operation_exit(queue);
    return CA_OK;
}

static ca_status_t bbq_lifecycle_unbind(ca_lifecycle_binding_t *binding) {
    if (binding == NULL || binding->queue == NULL || !binding->active) return CA_INVALID;
    struct bbq_queue *queue = as_bbq(binding->queue);
    ca_status_t status = operation_enter(queue);
    if (status != CA_OK) return status;
    if (atomic_load_explicit(&binding->activations, memory_order_acquire) != 0) {
        operation_exit(queue);
        return CA_BUSY;
    }
    binding->active = 0;
    binding->queue = NULL;
    atomic_fetch_sub_explicit(&queue->live_bindings, 1, memory_order_release);
    operation_exit(queue);
    return CA_OK;
}

static ca_status_t bbq_lifecycle_activate(ca_lifecycle_binding_t *binding, ca_lifecycle_scope_t *scope) {
    if (binding == NULL || scope == NULL || binding->queue == NULL || !binding->active) return CA_INVALID;
    struct bbq_queue *queue = as_bbq(binding->queue);
    ca_status_t status = operation_enter(queue);
    if (status != CA_OK) return status;
    memset(scope, 0, sizeof(*scope));
    scope->binding = binding;
    scope->previous = bbq_active_binding;
    scope->active = 1;
    bbq_active_binding = binding;
    atomic_fetch_add_explicit(&binding->activations, 1, memory_order_relaxed);
    operation_exit(queue);
    return CA_OK;
}

static ca_status_t bbq_lifecycle_deactivate(ca_lifecycle_scope_t *scope) {
    if (scope == NULL || !scope->active || scope->binding == NULL || bbq_active_binding != scope->binding)
        return CA_INVALID;
    struct bbq_queue *queue = as_bbq(scope->binding->queue);
    ca_status_t status = operation_enter(queue);
    if (status != CA_OK) return status;
    bbq_active_binding = scope->previous;
    atomic_fetch_sub_explicit(&scope->binding->activations, 1, memory_order_release);
    memset(scope, 0, sizeof(*scope));
    operation_exit(queue);
    return CA_OK;
}

static ca_status_t bbq_producer_register_common(ca_queue_t *base,
                                                uint64_t stable_key,
                                                int fallback,
                                                ca_producer_t *producer) {
    if (producer == NULL) return CA_INVALID;
    struct bbq_queue *queue = as_bbq(base);
    ca_status_t status = operation_enter(queue);
    if (status != CA_OK) return status;
    memset(producer, 0, sizeof(*producer));
    if (!atomic_load_explicit(&queue->accepting, memory_order_acquire)) {
        operation_exit(queue);
        return CA_CLOSED;
    }
    producer_registry_lock(queue);
    struct bbq_producer_state *state = atomic_load_explicit(&queue->producers, memory_order_relaxed);
    while (state != NULL && (state->stable_key != stable_key || state->fallback != (unsigned)fallback))
        state = state->next;
    if (state == NULL) {
        state = calloc(1, sizeof(*state));
        if (state == NULL) {
            producer_registry_unlock(queue);
            operation_exit(queue);
            return CA_NO_MEMORY;
        }
        state->queue = queue;
        state->stable_key = stable_key;
        state->fallback = (unsigned)fallback;
        state->retry_barrier = UINT64_MAX;
        atomic_flag_clear(&state->gate);
        state->next = atomic_load_explicit(&queue->producers, memory_order_relaxed);
        atomic_store_explicit(&queue->producers, state, memory_order_release);
    }
    ++state->handle_refs;
    producer_registry_unlock(queue);
    producer->queue = base;
    producer->private_state = state;
    producer->lane_generation = 1;
    atomic_init(&producer->outstanding, 0);
    producer->active = 1;
    producer->fallback = fallback;
    atomic_fetch_add_explicit(&queue->live_producers, 1, memory_order_relaxed);
    operation_exit(queue);
    return CA_OK;
}

static ca_status_t bbq_producer_register(ca_queue_t *base, uint64_t key, ca_producer_t *producer) {
    return bbq_producer_register_common(base, key, 0, producer);
}

static ca_status_t bbq_producer_register_fallback(ca_queue_t *base, size_t index, ca_producer_t *producer) {
    return bbq_producer_register_common(base, index, 1, producer);
}

static ca_status_t bbq_producer_release(ca_producer_t *producer) {
    if (producer == NULL || producer->queue == NULL || !producer->active) return CA_INVALID;
    struct bbq_queue *queue = as_bbq(producer->queue);
    ca_status_t status = operation_enter(queue);
    if (status != CA_OK) return status;
    if (atomic_load_explicit(&producer->outstanding, memory_order_acquire) != 0) {
        operation_exit(queue);
        return CA_BUSY;
    }
    struct bbq_producer_state *state = producer->private_state;
    producer->active = 0;
    producer->queue = NULL;
    producer->private_state = NULL;
    producer_registry_lock(queue);
    producer_lock(state);
    if (state->handle_refs == 0) abort();
    --state->handle_refs;
    const int reclaim = atomic_load_explicit(&queue->phase, memory_order_acquire) == BBQ_PHASE_RUNNING &&
                        state->handle_refs == 0 && state->active_completions == 0 && state->head == NULL;
    if (reclaim) producer_registry_unlink(queue, state);
    producer_unlock(state);
    producer_registry_unlock(queue);
    if (reclaim) free(state);
    atomic_fetch_sub_explicit(&queue->live_producers, 1, memory_order_release);
    operation_exit(queue);
    return CA_OK;
}

static void owner_acquire(ca_producer_t *owner) {
    if (owner != NULL) atomic_fetch_add_explicit(&owner->outstanding, 1, memory_order_relaxed);
}

static void owner_release(ca_producer_t *owner) {
    if (owner != NULL) atomic_fetch_sub_explicit(&owner->outstanding, 1, memory_order_release);
}

static ca_status_t bbq_reserve(ca_queue_t *base,
                               ca_producer_t *producer,
                               size_t wanted,
                               ca_reservation_t *reservation) {
    if (reservation == NULL) return CA_INVALID;
    struct bbq_queue *queue = as_bbq(base);
    ca_status_t status = operation_enter(queue);
    if (status != CA_OK) return status;
    memset(reservation, 0, sizeof(*reservation));
    struct bbq_producer_state *state = producer_state(queue, producer);
    if (!atomic_load_explicit(&queue->accepting, memory_order_acquire))
        status = CA_CLOSED;
    else if (state == NULL)
        status = CA_INVALID;
    size_t granted = 0;
    if (status == CA_OK) status = reserve_capacity(queue, wanted, &granted);
    if (status == CA_OK || status == CA_PARTIAL) {
        reservation->queue = base;
        reservation->owner = producer;
        reservation->lane_generation = 1;
        reservation->count = granted;
        reservation->active = 1;
        owner_acquire(producer);
        atomic_fetch_add_explicit(&queue->live_reservations, 1, memory_order_relaxed);
    }
    operation_exit(queue);
    return status;
}

static void close_reservation(struct bbq_queue *queue, ca_reservation_t *reservation) {
    owner_release(reservation->owner);
    atomic_fetch_sub_explicit(&queue->live_reservations, 1, memory_order_release);
    memset(reservation, 0, sizeof(*reservation));
}

static ca_status_t bbq_prepare_reserved(ca_reservation_t *reservation) {
    if (reservation == NULL || reservation->queue == NULL || !reservation->active || reservation->prepared ||
        reservation->count == 0)
        return CA_INVALID;
    struct bbq_queue *queue = as_bbq(reservation->queue);
    ca_status_t status = operation_enter(queue);
    if (status != CA_OK) return status;
    if (!atomic_load_explicit(&queue->publishing, memory_order_acquire))
        status = CA_CLOSED;
    else {
        reservation->prepared = 1;
        status = CA_OK;
    }
    operation_exit(queue);
    return status;
}

static ca_status_t publish_reservation(ca_reservation_t *reservation, void *const *items, int prepared) {
    if (reservation == NULL || reservation->queue == NULL || !reservation->active || items == NULL ||
        (prepared && !reservation->prepared))
        return CA_INVALID;
    struct bbq_queue *queue = as_bbq(reservation->queue);
    ca_status_t status = operation_enter(queue);
    if (status != CA_OK) return status;
    struct bbq_producer_state *producer = producer_state(queue, reservation->owner);
    if (!atomic_load_explicit(&queue->publishing, memory_order_acquire))
        status = CA_CLOSED;
    else if (producer == NULL)
        status = CA_INVALID;
    else
        status = publish_items(queue, producer, items, reservation->count);
    if (status == CA_OK) close_reservation(queue, reservation);
    operation_exit(queue);
    return status;
}

static ca_status_t bbq_commit_prepared(ca_reservation_t *reservation, void *const *items) {
    return publish_reservation(reservation, items, 1);
}

static ca_status_t bbq_publish_reserved(ca_reservation_t *reservation, void *const *items) {
    ca_status_t status = publish_reservation(reservation, items, 0);
    if (status != CA_OK && reservation != NULL && reservation->queue != NULL && reservation->active &&
        status != CA_CLOSED) {
        struct bbq_queue *queue = as_bbq(reservation->queue);
        ca_status_t enter = operation_enter(queue);
        if (enter == CA_OK) {
            release_capacity(queue, reservation->count);
            close_reservation(queue, reservation);
            operation_exit(queue);
        }
    }
    return status;
}

static void bbq_cancel_reservation(ca_reservation_t *reservation) {
    if (reservation == NULL || reservation->queue == NULL || !reservation->active) return;
    struct bbq_queue *queue = as_bbq(reservation->queue);
    if (operation_enter(queue) != CA_OK) return;
    release_capacity(queue, reservation->count);
    close_reservation(queue, reservation);
    operation_exit(queue);
}

static ca_status_t bbq_submit_span(
    ca_queue_t *base, ca_producer_t *producer, void *const *items, size_t count, size_t *accepted) {
    if (accepted == NULL || items == NULL || count == 0) return CA_INVALID;
    *accepted = 0;
    ca_reservation_t reservation;
    ca_status_t status = bbq_reserve(base, producer, count, &reservation);
    if (status != CA_OK && status != CA_PARTIAL) return status;
    const ca_status_t reserve_status = status;
    const size_t granted = reservation.count;
    status = bbq_publish_reserved(&reservation, items);
    if (status == CA_OK) *accepted = granted;
    return reserve_status == CA_PARTIAL && status == CA_OK ? CA_PARTIAL : status;
}

static ca_status_t bbq_credit_acquire(ca_queue_t *base,
                                      ca_producer_t *producer,
                                      size_t wanted,
                                      ca_credit_lease_t *lease) {
    if (lease == NULL || wanted == 0) return CA_INVALID;
    struct bbq_queue *queue = as_bbq(base);
    ca_status_t status = operation_enter(queue);
    if (status != CA_OK) return status;
    memset(lease, 0, sizeof(*lease));
    if (!atomic_load_explicit(&queue->accepting, memory_order_acquire) || producer_state(queue, producer) == NULL) {
        operation_exit(queue);
        return CA_CLOSED;
    }
    if (wanted > BBQ_LEASE_MAX) wanted = BBQ_LEASE_MAX;
    const size_t limit = (queue->capacity - 1) / 2;
    size_t speculative = atomic_load_explicit(&queue->speculative_unused, memory_order_relaxed);
    size_t extra;
    for (;;) {
        extra = speculative < limit ? limit - speculative : 0;
        if (extra > wanted - 1) extra = wanted - 1;
        if (atomic_compare_exchange_weak_explicit(&queue->speculative_unused, &speculative, speculative + extra,
                                                  memory_order_acq_rel, memory_order_relaxed))
            break;
    }
    size_t granted = 0;
    status = reserve_capacity(queue, 1 + extra, &granted);
    if (status != CA_OK && status != CA_PARTIAL) {
        atomic_fetch_sub_explicit(&queue->speculative_unused, extra, memory_order_release);
        operation_exit(queue);
        return status;
    }
    const size_t actual_extra = granted - 1;
    if (actual_extra < extra)
        atomic_fetch_sub_explicit(&queue->speculative_unused, extra - actual_extra, memory_order_release);
    lease->queue = base;
    lease->owner = producer;
    lease->lane_generation = 1;
    lease->unused = granted;
    lease->speculative_unused = actual_extra;
    lease->active = 1;
    owner_acquire(producer);
    atomic_fetch_add_explicit(&queue->live_leases, 1, memory_order_relaxed);
    operation_exit(queue);
    return granted == wanted ? CA_OK : CA_PARTIAL;
}

static void close_lease(struct bbq_queue *queue, ca_credit_lease_t *lease) {
    owner_release(lease->owner);
    atomic_fetch_sub_explicit(&queue->live_leases, 1, memory_order_release);
    memset(lease, 0, sizeof(*lease));
}

static ca_status_t bbq_credit_submit_span(ca_credit_lease_t *lease,
                                          void *const *items,
                                          size_t count,
                                          size_t *accepted) {
    if (lease == NULL || lease->queue == NULL || !lease->active || items == NULL || accepted == NULL || count == 0)
        return CA_INVALID;
    *accepted = 0;
    struct bbq_queue *queue = as_bbq(lease->queue);
    ca_status_t status = operation_enter(queue);
    if (status != CA_OK) return status;
    if (!atomic_load_explicit(&queue->publishing, memory_order_acquire)) {
        operation_exit(queue);
        return CA_CLOSED;
    }
    const size_t take = lease->unused < count ? lease->unused : count;
    if (take == 0) {
        operation_exit(queue);
        return CA_FULL;
    }
    struct bbq_producer_state *producer = producer_state(queue, lease->owner);
    status = producer == NULL ? CA_INVALID : publish_items(queue, producer, items, take);
    if (status == CA_OK) {
        const size_t mandatory = lease->unused - lease->speculative_unused;
        const size_t speculative_used = take > mandatory ? take - mandatory : 0;
        lease->unused -= take;
        lease->speculative_unused -= speculative_used;
        atomic_fetch_sub_explicit(&queue->speculative_unused, speculative_used, memory_order_release);
        *accepted = take;
        status = take == count ? CA_OK : CA_PARTIAL;
    }
    operation_exit(queue);
    return status;
}

static void bbq_credit_release(ca_credit_lease_t *lease) {
    if (lease == NULL || lease->queue == NULL || !lease->active) return;
    struct bbq_queue *queue = as_bbq(lease->queue);
    if (operation_enter(queue) != CA_OK) return;
    atomic_fetch_sub_explicit(&queue->speculative_unused, lease->speculative_unused, memory_order_release);
    release_capacity(queue, lease->unused);
    close_lease(queue, lease);
    operation_exit(queue);
}

static ca_status_t bbq_builder_begin(ca_queue_t *base, ca_producer_t *producer, ca_builder_t *builder) {
    if (builder == NULL) return CA_INVALID;
    struct bbq_queue *queue = as_bbq(base);
    ca_status_t status = operation_enter(queue);
    if (status != CA_OK) return status;
    memset(builder, 0, sizeof(*builder));
    if (!atomic_load_explicit(&queue->accepting, memory_order_acquire) || producer_state(queue, producer) == NULL) {
        operation_exit(queue);
        return CA_CLOSED;
    }
    builder->queue = base;
    builder->owner = producer;
    builder->lane_generation = 1;
    builder->items = &builder->inline_item;
    builder->allocated = 1;
    builder->active = 1;
    owner_acquire(producer);
    atomic_fetch_add_explicit(&queue->live_builders, 1, memory_order_relaxed);
    operation_exit(queue);
    return CA_OK;
}

static ca_status_t bbq_builder_append(
    ca_builder_t *builder, ca_credit_lease_t *lease, void *const *items, size_t count, size_t *accepted) {
    if (builder == NULL || builder->queue == NULL || !builder->active || lease == NULL || !lease->active ||
        lease->queue != builder->queue || lease->owner != builder->owner || items == NULL || accepted == NULL ||
        count == 0)
        return CA_INVALID;
    struct bbq_queue *queue = as_bbq(builder->queue);
    ca_status_t status = operation_enter(queue);
    if (status != CA_OK) return status;
    if (!atomic_load_explicit(&queue->publishing, memory_order_acquire)) {
        operation_exit(queue);
        return CA_CLOSED;
    }
    *accepted = 0;
    const size_t take = lease->unused < count ? lease->unused : count;
    if (take == 0 || take > SIZE_MAX - builder->count) {
        operation_exit(queue);
        return take == 0 ? CA_FULL : CA_INVALID;
    }
    const size_t needed = builder->count + take;
    if (needed > builder->allocated) {
        size_t allocation = builder->allocated == 1 ? BBQ_BLOCK_ITEMS : builder->allocated;
        while (allocation < needed) {
            if (allocation > SIZE_MAX / 2) {
                operation_exit(queue);
                return CA_INVALID;
            }
            allocation *= 2;
        }
        size_t bytes;
        if (!checked_mul_size(allocation, sizeof(*builder->items), &bytes)) {
            operation_exit(queue);
            return CA_INVALID;
        }
        void **grown = builder->items == &builder->inline_item ? malloc(bytes) : realloc(builder->items, bytes);
        if (grown == NULL) {
            operation_exit(queue);
            return CA_NO_MEMORY;
        }
        if (builder->items == &builder->inline_item && builder->count != 0) grown[0] = builder->inline_item;
        builder->items = grown;
        builder->allocated = allocation;
    }
    memcpy(&builder->items[builder->count], items, take * sizeof(*items));
    builder->count += take;
    const size_t mandatory = lease->unused - lease->speculative_unused;
    const size_t speculative_used = take > mandatory ? take - mandatory : 0;
    lease->unused -= take;
    lease->speculative_unused -= speculative_used;
    atomic_fetch_sub_explicit(&queue->speculative_unused, speculative_used, memory_order_release);
    *accepted = take;
    operation_exit(queue);
    return take == count ? CA_OK : CA_PARTIAL;
}

static void close_builder(struct bbq_queue *queue, ca_builder_t *builder) {
    if (builder->items != &builder->inline_item) free(builder->items);
    owner_release(builder->owner);
    atomic_fetch_sub_explicit(&queue->live_builders, 1, memory_order_release);
    memset(builder, 0, sizeof(*builder));
}

static ca_status_t bbq_builder_prepare(ca_builder_t *builder) {
    if (builder == NULL || builder->queue == NULL || !builder->active || builder->prepared || builder->count == 0)
        return CA_INVALID;
    struct bbq_queue *queue = as_bbq(builder->queue);
    ca_status_t status = operation_enter(queue);
    if (status != CA_OK) return status;
    if (!atomic_load_explicit(&queue->publishing, memory_order_acquire))
        status = CA_CLOSED;
    else {
        builder->prepared = 1;
        status = CA_OK;
    }
    operation_exit(queue);
    return status;
}

static ca_status_t builder_publish(ca_builder_t *builder, int prepared) {
    if (builder == NULL || builder->queue == NULL || !builder->active || builder->count == 0 ||
        (prepared && !builder->prepared))
        return CA_INVALID;
    struct bbq_queue *queue = as_bbq(builder->queue);
    ca_status_t status = operation_enter(queue);
    if (status != CA_OK) return status;
    struct bbq_producer_state *producer = producer_state(queue, builder->owner);
    if (!atomic_load_explicit(&queue->publishing, memory_order_acquire))
        status = CA_CLOSED;
    else if (producer == NULL)
        status = CA_INVALID;
    else
        status = publish_items(queue, producer, builder->items, builder->count);
    if (status == CA_OK) close_builder(queue, builder);
    operation_exit(queue);
    return status;
}

static ca_status_t bbq_builder_commit(ca_builder_t *builder) {
    return builder_publish(builder, 1);
}

static ca_status_t bbq_builder_publish(ca_builder_t *builder) {
    return builder_publish(builder, 0);
}

static void bbq_builder_cancel(ca_builder_t *builder) {
    if (builder == NULL || builder->queue == NULL || !builder->active) return;
    struct bbq_queue *queue = as_bbq(builder->queue);
    if (operation_enter(queue) != CA_OK) return;
    release_capacity(queue, builder->count);
    close_builder(queue, builder);
    operation_exit(queue);
}

static ca_status_t bbq_claim(ca_queue_t *base, ca_claim_t *claim, ca_claim_item_t *items, size_t maximum) {
    if (claim == NULL || items == NULL || maximum == 0) return CA_INVALID;
    memset(claim, 0, sizeof(*claim));
    struct bbq_queue *queue = as_bbq(base);
    ca_status_t status = operation_enter(queue);
    if (status != CA_OK) return status;
    if (!atomic_load_explicit(&queue->claiming, memory_order_acquire)) {
        operation_exit(queue);
        return CA_CLOSED;
    }
    int old_cancel_state;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old_cancel_state) != 0) {
        operation_exit(queue);
        return CA_INVALID;
    }
    size_t count = 0;
    status = claim_records(queue, items, maximum, &count);
    if (status == CA_OK) {
        atomic_fetch_add_explicit(&queue->in_flight, count, memory_order_relaxed);
        atomic_fetch_add_explicit(&queue->live_claims, 1, memory_order_relaxed);
        claim->queue = base;
        claim->items = items;
        claim->count = count;
        claim->capacity = maximum;
        claim->active = 1;
        BBQ_DIAG_INC(queue, claim_calls);
        BBQ_DIAG_ADD(queue, claimed_items, count);
#ifdef CA_ENABLE_DIAGNOSTICS
        bbq_diag_max(&queue->largest_claim, count);
#endif
    }
    operation_exit(queue);
    (void)pthread_setcancelstate(old_cancel_state, NULL);
    return status;
}

static void republish_unblocked(struct bbq_queue *queue, struct bbq_producer_state *producer) {
    for (;;) {
        struct bbq_record *publish = NULL;
        producer_lock(producer);
        for (struct bbq_record *record = producer->head; record != NULL; record = record->next) {
            const unsigned state = atomic_load_explicit(&record->state, memory_order_acquire);
            if (state == BBQ_RECORD_RETRY_BLOCKED && record == producer->head) {
                atomic_store_explicit(&record->state, BBQ_RECORD_RETRY, memory_order_release);
                publish = record;
                break;
            }
            if (state == BBQ_RECORD_NORMAL_BLOCKED &&
                (producer->retry_barrier == UINT64_MAX || record->ordinal < producer->retry_barrier)) {
                atomic_store_explicit(&record->state, BBQ_RECORD_NORMAL, memory_order_release);
                publish = record;
                break;
            }
        }
        producer_unlock(producer);
        if (publish == NULL) return;
        physical_publish(queue, publish);
    }
}

static ca_status_t complete_record(struct bbq_queue *queue,
                                   struct bbq_record *record,
                                   ca_completion_state_t state,
                                   int was_retry) {
    struct bbq_producer_state *producer = record->producer;
    int publish_retry = 0;
    int barrier_released = 0;
    struct bbq_record *publish_head_retry = NULL;
    producer_lock(producer);
    const unsigned expected_state = was_retry ? BBQ_RECORD_CLAIMED_RETRY : BBQ_RECORD_CLAIMED_NORMAL;
    if (atomic_load_explicit(&record->state, memory_order_acquire) != expected_state) {
        producer_unlock(producer);
        return CA_INVALID;
    }
    ++producer->active_completions;
    if (state == CA_COMPLETE_RETRY) {
        if (record->ordinal < producer->retry_barrier) producer->retry_barrier = record->ordinal;
        publish_retry = producer->head == record;
        atomic_store_explicit(&record->state, publish_retry ? BBQ_RECORD_RETRY : BBQ_RECORD_RETRY_BLOCKED,
                              memory_order_release);
        --producer->active_completions;
        producer_unlock(producer);
        if (!was_retry) BBQ_DIAG_INC(queue, retry_barriers);
        if (publish_retry) physical_publish(queue, record);
        return CA_OK;
    }
    atomic_store_explicit(&record->state, BBQ_RECORD_TERMINAL, memory_order_release);
    if (was_retry && producer->retry_barrier == record->ordinal) {
        barrier_released = 1;
        producer->retry_barrier = UINT64_MAX;
        for (struct bbq_record *scan = producer->head; scan != NULL; scan = scan->next) {
            const unsigned scan_state = atomic_load_explicit(&scan->state, memory_order_acquire);
            if (scan_state == BBQ_RECORD_RETRY || scan_state == BBQ_RECORD_RETRY_BLOCKED) {
                producer->retry_barrier = scan->ordinal;
                break;
            }
        }
    }
    if (record->previous == NULL)
        producer->head = record->next;
    else
        record->previous->next = record->next;
    if (record->next != NULL) record->next->previous = record->previous;
    if (producer->tail == record) producer->tail = record->previous;
    if (producer->head == NULL) producer->tail = NULL;
    if (!barrier_released && producer->head != NULL &&
        atomic_load_explicit(&producer->head->state, memory_order_acquire) == BBQ_RECORD_RETRY_BLOCKED) {
        publish_head_retry = producer->head;
        atomic_store_explicit(&publish_head_retry->state, BBQ_RECORD_RETRY, memory_order_release);
    }
    producer_unlock(producer);
    if (queue->dispose != NULL) queue->dispose(record->item, state, queue->dispose_user);
    record->item = NULL;
    record_release(queue, record);
#ifdef CA_TESTING
    int pause_expected = 1;
    if (atomic_compare_exchange_strong_explicit(&queue->test_pause_after_record_release, &pause_expected, 0,
                                                memory_order_acq_rel, memory_order_acquire)) {
        atomic_store_explicit(&queue->test_after_record_release_entered, 1, memory_order_release);
        while (!atomic_load_explicit(&queue->test_after_record_release_release, memory_order_acquire)) sched_yield();
    }
#endif
    release_capacity(queue, 1);
    if (barrier_released)
        republish_unblocked(queue, producer);
    else if (publish_head_retry != NULL)
        physical_publish(queue, publish_head_retry);
    producer_completion_exit(queue, producer);
    return CA_OK;
}

static ca_status_t bbq_complete_impl(ca_claim_t *claim, const ca_completion_state_t *states, int return_all) {
    if (claim == NULL || claim->queue == NULL || !claim->active || claim->count == 0 || (!return_all && states == NULL))
        return CA_INVALID;
    for (size_t i = 0; !return_all && i < claim->count; ++i)
        if (states[i] != CA_COMPLETE_COMMIT && states[i] != CA_COMPLETE_RETRY && states[i] != CA_COMPLETE_DISCARD)
            return CA_INVALID;
    struct bbq_queue *queue = as_bbq(claim->queue);
    ca_status_t status = operation_enter(queue);
    if (status != CA_OK) return status;
    for (size_t i = 0; i < claim->count; ++i) {
        struct bbq_record *record = (struct bbq_record *)claim->items[i].slot;
        if (record == NULL || record->item != claim->items[i].item || record->ordinal != claim->items[i].ordinal) {
            operation_exit(queue);
            return CA_INVALID;
        }
    }
    for (size_t i = 0; i < claim->count; ++i) {
        const ca_completion_state_t state = return_all ? CA_COMPLETE_RETRY : states[i];
        status = complete_record(queue, (struct bbq_record *)claim->items[i].slot, state, claim->items[i].was_retry);
        if (status != CA_OK) {
            operation_exit(queue);
            return status;
        }
    }
    atomic_fetch_sub_explicit(&queue->in_flight, claim->count, memory_order_release);
    atomic_fetch_sub_explicit(&queue->live_claims, 1, memory_order_release);
    memset(claim, 0, sizeof(*claim));
    operation_exit(queue);
    return CA_OK;
}

static ca_status_t bbq_complete(ca_claim_t *claim, const ca_completion_state_t *states) {
    return bbq_complete_impl(claim, states, 0);
}

static ca_status_t bbq_return_claim(ca_claim_t *claim) {
    return bbq_complete_impl(claim, NULL, 1);
}

static void bbq_capacity_read(const ca_queue_t *base, ca_capacity_snapshot_t *snapshot) {
    struct bbq_queue *queue = as_bbq((ca_queue_t *)base);
    if (operation_enter(queue) != CA_OK) {
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
    operation_exit(queue);
}

static uint32_t bbq_epoch(const ca_queue_t *base) {
    return atomic_load_explicit(&((const struct bbq_queue *)base)->epoch, memory_order_acquire);
}

static uint32_t bbq_capacity_epoch(const ca_queue_t *base) {
    return atomic_load_explicit(&((const struct bbq_queue *)base)->capacity_epoch, memory_order_acquire);
}

#if !BBQ_USE_FUTEX
struct bbq_wait_cleanup {
    struct bbq_queue *queue;
    _Atomic unsigned *sleepers;
    int mutex_locked;
};

static void wait_cancel_cleanup(void *argument) {
    struct bbq_wait_cleanup *cleanup = argument;
    atomic_fetch_sub_explicit(cleanup->sleepers, 1, memory_order_release);
    atomic_fetch_sub_explicit(&cleanup->queue->live_waiters, 1, memory_order_release);
    if (cleanup->mutex_locked) pthread_mutex_unlock(&cleanup->queue->wait_mutex);
}
#endif

static ca_status_t wait_on_epoch(struct bbq_queue *queue,
                                 _Atomic uint32_t *epoch,
                                 _Atomic unsigned *sleepers,
#if !BBQ_USE_FUTEX
                                 pthread_cond_t *condition,
#endif
                                 uint32_t observed,
                                 const struct timespec *deadline) {
    ca_status_t status = operation_enter(queue);
    if (status != CA_OK) return status;
    if (!atomic_load_explicit(&queue->waiting, memory_order_acquire)) {
        operation_exit(queue);
        return CA_CLOSED;
    }
    atomic_fetch_add_explicit(&queue->live_waiters, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(sleepers, 1, memory_order_acq_rel);
    BBQ_DIAG_INC(queue, sleeps);
    /* live_waiters pins queue storage. Lifecycle admission is released before
     * sleeping so a writer can close waiting and wake both adapter classes. */
    operation_exit(queue);
#if BBQ_USE_FUTEX
    if (atomic_load_explicit(epoch, memory_order_acquire) == observed) {
        struct timespec relative;
        const int deadline_state = relative_deadline(deadline, &relative);
        int result = deadline_state < 0 ? ETIMEDOUT
                                        : (int)syscall(SYS_futex, epoch, FUTEX_WAIT_PRIVATE, observed,
                                                       deadline_state == 0 ? NULL : &relative, NULL, 0);
        if (result != 0 && deadline_state >= 0) result = errno;
        if (result == ETIMEDOUT) status = CA_TIMED_OUT;
    }
    atomic_fetch_sub_explicit(sleepers, 1, memory_order_release);
    atomic_fetch_sub_explicit(&queue->live_waiters, 1, memory_order_release);
#else
    struct bbq_wait_cleanup cleanup = {.queue = queue, .sleepers = sleepers};
    int result = 0;
    pthread_cleanup_push(wait_cancel_cleanup, &cleanup);
    pthread_mutex_lock(&queue->wait_mutex);
    cleanup.mutex_locked = 1;
    if (atomic_load_explicit(epoch, memory_order_acquire) == observed) {
        if (deadline == NULL)
            result = pthread_cond_wait(condition, &queue->wait_mutex);
        else {
            struct timespec real_deadline;
            realtime_deadline(deadline, &real_deadline);
            result = pthread_cond_timedwait(condition, &queue->wait_mutex, &real_deadline);
        }
    }
    cleanup.mutex_locked = 0;
    pthread_mutex_unlock(&queue->wait_mutex);
    atomic_fetch_sub_explicit(sleepers, 1, memory_order_release);
    atomic_fetch_sub_explicit(&queue->live_waiters, 1, memory_order_release);
    pthread_cleanup_pop(0);
    if (result == ETIMEDOUT) status = CA_TIMED_OUT;
#endif
    if (status == CA_OK && atomic_load_explicit(epoch, memory_order_acquire) == observed && deadline_expired(deadline))
        status = CA_TIMED_OUT;
    return status;
}

static ca_status_t bbq_wait_epoch(ca_queue_t *base, uint32_t observed, const struct timespec *deadline) {
    struct bbq_queue *queue = as_bbq(base);
    return wait_on_epoch(queue, &queue->epoch, &queue->sleepers,
#if !BBQ_USE_FUTEX
                         &queue->wait_cond,
#endif
                         observed, deadline);
}

static ca_status_t bbq_wait_capacity_epoch(ca_queue_t *base, uint32_t observed, const struct timespec *deadline) {
    struct bbq_queue *queue = as_bbq(base);
    return wait_on_epoch(queue, &queue->capacity_epoch, &queue->capacity_sleepers,
#if !BBQ_USE_FUTEX
                         &queue->capacity_cond,
#endif
                         observed, deadline);
}

static void bbq_interrupt_waiters(ca_queue_t *base) {
    struct bbq_queue *queue = as_bbq(base);
    signal_work(queue, 1);
    signal_capacity(queue, 1);
}

static void physical_discard(struct bbq_queue *queue) {
    for (;;) {
        const uint64_t position = atomic_load_explicit(&queue->claim_position, memory_order_acquire);
        if (position >= atomic_load_explicit(&queue->publish_position, memory_order_acquire)) break;
        struct bbq_cell *cell = cell_get(queue, position);
        const uint64_t generation = position / queue->capacity;
        uint64_t control = cell_control_load(cell);
        if (cell_generation(queue, control) != generation) abort();
        if (cell_state(control) == BBQ_CELL_EMPTY) {
            uint64_t expected_control = cell_control(queue, generation, BBQ_CELL_EMPTY, 0);
            (void)cell_control_cas(cell, &expected_control, cell_control(queue, generation, BBQ_CELL_TOMBSTONE, 0));
            control = cell_control_load(cell);
        }
        cell_finish(queue, cell, position, control);
        atomic_store_explicit(&queue->claim_position, position + 1, memory_order_release);
    }
}

static size_t discard_producer(struct bbq_queue *queue, struct bbq_producer_state *producer) {
    size_t discarded = 0;
    producer_lock(producer);
    struct bbq_record *record = producer->head;
    producer->head = NULL;
    producer->tail = NULL;
    producer_unlock(producer);
    while (record != NULL) {
        struct bbq_record *next = record->next;
        if (queue->dispose != NULL) queue->dispose(record->item, CA_COMPLETE_DISCARD, queue->dispose_user);
        record_release(queue, record);
        ++discarded;
        record = next;
    }
    return discarded;
}

static ca_status_t bbq_quiesce(ca_queue_t *base, ca_quiesce_mode_t mode, const struct timespec *deadline) {
    struct bbq_queue *queue = as_bbq(base);
    ca_status_t status = writer_begin(queue, deadline);
    if (status != CA_OK) return status;
    const unsigned was_accepting = atomic_load_explicit(&queue->accepting, memory_order_relaxed);
    const unsigned was_publishing = atomic_load_explicit(&queue->publishing, memory_order_relaxed);
    const unsigned was_claiming = atomic_load_explicit(&queue->claiming, memory_order_relaxed);
    const unsigned was_waiting = atomic_load_explicit(&queue->waiting, memory_order_relaxed);
    const unsigned was_phase = atomic_load_explicit(&queue->phase, memory_order_relaxed);
    atomic_store_explicit(&queue->phase, mode == CA_QUIESCE_DRAIN ? BBQ_PHASE_DRAIN : BBQ_PHASE_DISCARD,
                          memory_order_release);
    atomic_store_explicit(&queue->accepting, 0, memory_order_release);
    if (mode == CA_QUIESCE_DISCARD) {
        atomic_store_explicit(&queue->publishing, 0, memory_order_release);
        atomic_store_explicit(&queue->claiming, 0, memory_order_release);
        atomic_store_explicit(&queue->waiting, 0, memory_order_release);
    }
    bbq_interrupt_waiters(base);
    writer_end(queue);
    if (mode == CA_QUIESCE_DRAIN) {
        while (atomic_load_explicit(&queue->available, memory_order_acquire) != queue->capacity) {
            if (deadline_expired(deadline)) goto timed_out;
            const uint32_t observed = atomic_load_explicit(&queue->capacity_epoch, memory_order_acquire);
            status = bbq_wait_capacity_epoch(base, observed, deadline);
            if (status == CA_TIMED_OUT) goto timed_out;
        }
        atomic_store_explicit(&queue->publishing, 0, memory_order_release);
        atomic_store_explicit(&queue->claiming, 0, memory_order_release);
        atomic_store_explicit(&queue->waiting, 0, memory_order_release);
        bbq_interrupt_waiters(base);
        record_pool_trim(queue);
        return CA_OK;
    }
    while (atomic_load_explicit(&queue->live_claims, memory_order_acquire) != 0) {
        if (deadline_expired(deadline)) goto timed_out;
        sched_yield();
    }
    physical_discard(queue);
    size_t discarded = discard_producer(queue, &queue->anonymous_producer);
    for (struct bbq_producer_state *producer = atomic_load_explicit(&queue->producers, memory_order_acquire);
         producer != NULL; producer = producer->next) {
        discarded += discard_producer(queue, producer);
#ifdef CA_TESTING
        int pause_expected = 1;
        if (atomic_compare_exchange_strong_explicit(&queue->test_pause_after_discard_producer, &pause_expected, 0,
                                                    memory_order_acq_rel, memory_order_acquire)) {
            atomic_store_explicit(&queue->test_after_discard_producer_entered, 1, memory_order_release);
            while (!atomic_load_explicit(&queue->test_after_discard_producer_release, memory_order_acquire))
                sched_yield();
        }
#endif
    }
    release_capacity(queue, discarded);
    if (atomic_load_explicit(&queue->available, memory_order_acquire) != queue->capacity) return CA_BUSY;
    record_pool_trim(queue);
    return CA_OK;

timed_out:
    atomic_store_explicit(&queue->accepting, was_accepting, memory_order_relaxed);
    atomic_store_explicit(&queue->publishing, was_publishing, memory_order_relaxed);
    atomic_store_explicit(&queue->claiming, was_claiming, memory_order_relaxed);
    atomic_store_explicit(&queue->waiting, was_waiting, memory_order_release);
    atomic_store_explicit(&queue->phase, was_phase, memory_order_release);
    bbq_interrupt_waiters(base);
    return CA_TIMED_OUT;
}

static void free_allocations(struct bbq_queue *queue) {
    for (size_t i = 0; i < queue->record_block_count; ++i) {
        free(atomic_load_explicit(&queue->record_blocks[i], memory_order_relaxed));
    }
    free(queue->cells);
    free(queue->record_blocks);
    free(queue->record_bitmap);
}

static ca_status_t bbq_destroy(ca_queue_t *base) {
    struct bbq_queue *queue = as_bbq(base);
    ca_status_t status = writer_begin(queue, NULL);
    if (status != CA_OK) return status;
    const unsigned was_phase = atomic_load_explicit(&queue->phase, memory_order_relaxed);
    atomic_store_explicit(&queue->destroying, 1, memory_order_release);
    atomic_store_explicit(&queue->phase, BBQ_PHASE_DESTROY, memory_order_release);
    bbq_interrupt_waiters(base);
    if (atomic_load_explicit(&queue->live_producers, memory_order_acquire) != 0 ||
        atomic_load_explicit(&queue->live_reservations, memory_order_acquire) != 0 ||
        atomic_load_explicit(&queue->live_leases, memory_order_acquire) != 0 ||
        atomic_load_explicit(&queue->live_builders, memory_order_acquire) != 0 ||
        atomic_load_explicit(&queue->live_claims, memory_order_acquire) != 0 ||
        atomic_load_explicit(&queue->live_waiters, memory_order_acquire) != 0 ||
        atomic_load_explicit(&queue->live_bindings, memory_order_acquire) != 0 ||
        atomic_load_explicit(&queue->available, memory_order_acquire) != queue->capacity) {
        atomic_store_explicit(&queue->destroying, 0, memory_order_release);
        atomic_store_explicit(&queue->phase, was_phase, memory_order_release);
        writer_end(queue);
        return CA_BUSY;
    }
    struct bbq_producer_state *producer = atomic_load_explicit(&queue->producers, memory_order_relaxed);
    while (producer != NULL) {
        struct bbq_producer_state *next = producer->next;
        free(producer);
        producer = next;
    }
#if !BBQ_USE_FUTEX
    pthread_cond_destroy(&queue->capacity_cond);
    pthread_cond_destroy(&queue->wait_cond);
    pthread_mutex_destroy(&queue->wait_mutex);
#endif
    free_allocations(queue);
    free(queue);
    return CA_OK;
}

static ca_status_t bbq_create(const ca_config_t *config, ca_queue_t **result) {
    if (config->capacity > UINT32_MAX) return CA_INVALID;
    unsigned record_index_bits = 0;
    for (size_t highest_index = config->capacity - 1; highest_index != 0; highest_index >>= 1) ++record_index_bits;
    const uint64_t record_index_mask = record_index_bits == 0 ? 0 : (UINT64_C(1) << record_index_bits) - 1;
    const uint64_t generation_max = UINT64_MAX >> (BBQ_CELL_INDEX_SHIFT + record_index_bits);
    const size_t block_count = (config->capacity - 1) / BBQ_BLOCK_ITEMS + 1;
    const size_t record_capacity = config->capacity;
    const size_t record_block_count = (record_capacity - 1) / BBQ_BLOCK_ITEMS + 1;
    size_t cell_bytes;
    size_t record_pointer_bytes;
    size_t bitmap_bytes;
    if (!checked_mul_size(config->capacity, sizeof(struct bbq_cell), &cell_bytes) ||
        !checked_mul_size(record_block_count, sizeof(_Atomic(struct bbq_record_block *)), &record_pointer_bytes) ||
        !checked_mul_size(record_block_count, sizeof(_Atomic uint64_t), &bitmap_bytes))
        return CA_INVALID;
    struct bbq_queue *queue = calloc(1, sizeof(*queue));
    if (queue == NULL) return CA_NO_MEMORY;
    queue->cells = calloc(1, cell_bytes);
    queue->record_blocks = malloc(record_pointer_bytes);
    queue->record_bitmap = malloc(bitmap_bytes);
    if (queue->cells == NULL || queue->record_blocks == NULL || queue->record_bitmap == NULL) {
        free(queue->cells);
        free(queue->record_blocks);
        free(queue->record_bitmap);
        free(queue);
        return CA_NO_MEMORY;
    }
    queue->base.ops = &ca_bbq_ops;
    queue->capacity = config->capacity;
    queue->consumers = config->consumers;
    queue->block_count = block_count;
    queue->record_capacity = record_capacity;
    queue->record_block_count = record_block_count;
    queue->record_index_bits = record_index_bits;
    queue->record_index_mask = record_index_mask;
    queue->generation_max = generation_max;
    queue->dispose = config->dispose;
    queue->dispose_user = config->dispose_user;
    if (!__atomic_is_lock_free(sizeof(queue->cells[0].control), &queue->cells[0].control)) {
        free(queue->cells);
        free(queue->record_blocks);
        free(queue->record_bitmap);
        free(queue);
        return CA_INVALID;
    }
    for (size_t i = 0; i < record_block_count; ++i) {
        atomic_init(&queue->record_blocks[i], NULL);
        atomic_init(&queue->record_bitmap[i], 0);
    }
    atomic_init(&queue->publish_position, 0);
    atomic_init(&queue->claim_position, 0);
    atomic_init(&queue->record_cursor, 0);
    queue->anonymous_producer.queue = queue;
    queue->anonymous_producer.retry_barrier = UINT64_MAX;
    atomic_flag_clear(&queue->anonymous_producer.gate);
    atomic_init(&queue->producers, NULL);
    atomic_flag_clear(&queue->producer_registry_gate);
    atomic_init(&queue->available, config->capacity);
    atomic_init(&queue->speculative_unused, 0);
    atomic_init(&queue->in_flight, 0);
    atomic_init(&queue->active_calls, 0);
    atomic_init(&queue->lifecycle_writer, 0);
    atomic_init(&queue->live_producers, 0);
    atomic_init(&queue->live_reservations, 0);
    atomic_init(&queue->live_leases, 0);
    atomic_init(&queue->live_builders, 0);
    atomic_init(&queue->live_claims, 0);
    atomic_init(&queue->live_waiters, 0);
    atomic_init(&queue->live_bindings, 0);
    atomic_init(&queue->binding_cursor, 0);
    atomic_init(&queue->epoch, 0);
    atomic_init(&queue->capacity_epoch, 0);
    atomic_init(&queue->sleepers, 0);
    atomic_init(&queue->capacity_sleepers, 0);
    atomic_init(&queue->accepting, 1);
    atomic_init(&queue->publishing, 1);
    atomic_init(&queue->claiming, 1);
    atomic_init(&queue->waiting, 1);
    atomic_init(&queue->destroying, 0);
    atomic_init(&queue->phase, BBQ_PHASE_RUNNING);
#ifdef CA_ENABLE_DIAGNOSTICS
    atomic_init(&queue->capacity_attempts, 0);
    atomic_init(&queue->capacity_failures, 0);
    atomic_init(&queue->cas_retries, 0);
    atomic_init(&queue->publish_calls, 0);
    atomic_init(&queue->published_items, 0);
    atomic_init(&queue->claim_calls, 0);
    atomic_init(&queue->claimed_items, 0);
    atomic_init(&queue->ready_enqueues, 0);
    atomic_init(&queue->ready_dequeues, 0);
    atomic_init(&queue->wake_requests, 0);
    atomic_init(&queue->sleeps, 0);
    atomic_init(&queue->retry_barriers, 0);
    atomic_init(&queue->largest_publication, 0);
    atomic_init(&queue->largest_claim, 0);
#endif
#ifdef CA_TESTING
    atomic_init(&queue->test_pause_after_faa, 0);
    atomic_init(&queue->test_after_faa_entered, 0);
    atomic_init(&queue->test_after_faa_release, 0);
    atomic_init(&queue->test_pause_after_install, 0);
    atomic_init(&queue->test_after_install_entered, 0);
    atomic_init(&queue->test_after_install_release, 0);
    atomic_init(&queue->test_pause_after_claim, 0);
    atomic_init(&queue->test_after_claim_entered, 0);
    atomic_init(&queue->test_after_claim_release, 0);
    atomic_init(&queue->test_pause_after_record_release, 0);
    atomic_init(&queue->test_after_record_release_entered, 0);
    atomic_init(&queue->test_after_record_release_release, 0);
    atomic_init(&queue->test_pause_after_discard_producer, 0);
    atomic_init(&queue->test_after_discard_producer_entered, 0);
    atomic_init(&queue->test_after_discard_producer_release, 0);
    atomic_init(&queue->test_record_word_probes, 0);
#endif
#if !BBQ_USE_FUTEX
    if (pthread_mutex_init(&queue->wait_mutex, NULL) != 0) goto synchronization_error;
    if (pthread_cond_init(&queue->wait_cond, NULL) != 0) {
        pthread_mutex_destroy(&queue->wait_mutex);
        goto synchronization_error;
    }
    if (pthread_cond_init(&queue->capacity_cond, NULL) != 0) {
        pthread_cond_destroy(&queue->wait_cond);
        pthread_mutex_destroy(&queue->wait_mutex);
        goto synchronization_error;
    }
#endif
    *result = &queue->base;
    return CA_OK;

#if !BBQ_USE_FUTEX
synchronization_error:
    free_allocations(queue);
    free(queue);
    return CA_INVALID;
#endif
}

static void bbq_diagnostics_read(const ca_queue_t *base, ca_diagnostics_t *diagnostics) {
#ifdef CA_ENABLE_DIAGNOSTICS
    const struct bbq_queue *queue = (const struct bbq_queue *)base;
    diagnostics->capacity_attempts = atomic_load_explicit(&queue->capacity_attempts, memory_order_relaxed);
    diagnostics->capacity_failures = atomic_load_explicit(&queue->capacity_failures, memory_order_relaxed);
    diagnostics->cas_retries = atomic_load_explicit(&queue->cas_retries, memory_order_relaxed);
    diagnostics->publish_calls = atomic_load_explicit(&queue->publish_calls, memory_order_relaxed);
    diagnostics->published_items = atomic_load_explicit(&queue->published_items, memory_order_relaxed);
    diagnostics->largest_publication = atomic_load_explicit(&queue->largest_publication, memory_order_relaxed);
    diagnostics->claim_calls = atomic_load_explicit(&queue->claim_calls, memory_order_relaxed);
    diagnostics->claimed_items = atomic_load_explicit(&queue->claimed_items, memory_order_relaxed);
    diagnostics->largest_claim = atomic_load_explicit(&queue->largest_claim, memory_order_relaxed);
    diagnostics->ready_enqueues = atomic_load_explicit(&queue->ready_enqueues, memory_order_relaxed);
    diagnostics->ready_dequeues = atomic_load_explicit(&queue->ready_dequeues, memory_order_relaxed);
    diagnostics->wake_requests = atomic_load_explicit(&queue->wake_requests, memory_order_relaxed);
    diagnostics->sleeps = atomic_load_explicit(&queue->sleeps, memory_order_relaxed);
    diagnostics->retry_barriers = atomic_load_explicit(&queue->retry_barriers, memory_order_relaxed);
#else
    (void)base;
    (void)diagnostics;
#endif
}

static size_t bbq_dedicated_lane_limit(const ca_queue_t *base) {
    (void)base;
    return 16;
}

static size_t bbq_fallback_lane_count(const ca_queue_t *base) {
    (void)base;
    return 2;
}

static size_t bbq_ready_ring_capacity(const ca_queue_t *base) {
    return ((const struct bbq_queue *)base)->block_count;
}

#ifdef CA_TESTING
void ca_bbq_test_pause_after_faa(ca_queue_t *base) {
    struct bbq_queue *queue = as_bbq(base);
    atomic_store_explicit(&queue->test_after_faa_entered, 0, memory_order_relaxed);
    atomic_store_explicit(&queue->test_after_faa_release, 0, memory_order_relaxed);
    atomic_store_explicit(&queue->test_pause_after_faa, 1, memory_order_release);
}

int ca_bbq_test_after_faa_entered(ca_queue_t *base) {
    return atomic_load_explicit(&as_bbq(base)->test_after_faa_entered, memory_order_acquire);
}

void ca_bbq_test_release_after_faa(ca_queue_t *base) {
    struct bbq_queue *queue = as_bbq(base);
    atomic_store_explicit(&queue->test_pause_after_faa, 0, memory_order_relaxed);
    atomic_store_explicit(&queue->test_after_faa_release, 1, memory_order_release);
}

void ca_bbq_test_pause_after_install(ca_queue_t *base) {
    struct bbq_queue *queue = as_bbq(base);
    atomic_store_explicit(&queue->test_after_install_entered, 0, memory_order_relaxed);
    atomic_store_explicit(&queue->test_after_install_release, 0, memory_order_relaxed);
    atomic_store_explicit(&queue->test_pause_after_install, 1, memory_order_release);
}

int ca_bbq_test_after_install_entered(ca_queue_t *base) {
    return atomic_load_explicit(&as_bbq(base)->test_after_install_entered, memory_order_acquire);
}

void ca_bbq_test_release_after_install(ca_queue_t *base) {
    struct bbq_queue *queue = as_bbq(base);
    atomic_store_explicit(&queue->test_pause_after_install, 0, memory_order_relaxed);
    atomic_store_explicit(&queue->test_after_install_release, 1, memory_order_release);
}

void ca_bbq_test_pause_after_claim(ca_queue_t *base) {
    struct bbq_queue *queue = as_bbq(base);
    atomic_store_explicit(&queue->test_after_claim_entered, 0, memory_order_relaxed);
    atomic_store_explicit(&queue->test_after_claim_release, 0, memory_order_relaxed);
    atomic_store_explicit(&queue->test_pause_after_claim, 1, memory_order_release);
}

int ca_bbq_test_after_claim_entered(ca_queue_t *base) {
    return atomic_load_explicit(&as_bbq(base)->test_after_claim_entered, memory_order_acquire);
}

void ca_bbq_test_release_after_claim(ca_queue_t *base) {
    struct bbq_queue *queue = as_bbq(base);
    atomic_store_explicit(&queue->test_pause_after_claim, 0, memory_order_relaxed);
    atomic_store_explicit(&queue->test_after_claim_release, 1, memory_order_release);
}

void ca_bbq_test_pause_after_record_release(ca_queue_t *base) {
    struct bbq_queue *queue = as_bbq(base);
    atomic_store_explicit(&queue->test_after_record_release_entered, 0, memory_order_relaxed);
    atomic_store_explicit(&queue->test_after_record_release_release, 0, memory_order_relaxed);
    atomic_store_explicit(&queue->test_pause_after_record_release, 1, memory_order_release);
}

int ca_bbq_test_after_record_release_entered(ca_queue_t *base) {
    return atomic_load_explicit(&as_bbq(base)->test_after_record_release_entered, memory_order_acquire);
}

void ca_bbq_test_release_after_record_release(ca_queue_t *base) {
    struct bbq_queue *queue = as_bbq(base);
    atomic_store_explicit(&queue->test_pause_after_record_release, 0, memory_order_relaxed);
    atomic_store_explicit(&queue->test_after_record_release_release, 1, memory_order_release);
}

void ca_bbq_test_pause_after_discard_producer(ca_queue_t *base) {
    struct bbq_queue *queue = as_bbq(base);
    atomic_store_explicit(&queue->test_after_discard_producer_entered, 0, memory_order_relaxed);
    atomic_store_explicit(&queue->test_after_discard_producer_release, 0, memory_order_relaxed);
    atomic_store_explicit(&queue->test_pause_after_discard_producer, 1, memory_order_release);
}

int ca_bbq_test_after_discard_producer_entered(ca_queue_t *base) {
    return atomic_load_explicit(&as_bbq(base)->test_after_discard_producer_entered, memory_order_acquire);
}

void ca_bbq_test_release_after_discard_producer(ca_queue_t *base) {
    struct bbq_queue *queue = as_bbq(base);
    atomic_store_explicit(&queue->test_pause_after_discard_producer, 0, memory_order_relaxed);
    atomic_store_explicit(&queue->test_after_discard_producer_release, 1, memory_order_release);
}

int ca_bbq_test_uses_futex(void) {
    return BBQ_USE_FUTEX;
}

size_t ca_bbq_test_work_sleepers(ca_queue_t *base) {
    return atomic_load_explicit(&as_bbq(base)->sleepers, memory_order_acquire);
}

size_t ca_bbq_test_capacity_sleepers(ca_queue_t *base) {
    return atomic_load_explicit(&as_bbq(base)->capacity_sleepers, memory_order_acquire);
}

size_t ca_bbq_test_record_blocks(ca_queue_t *base) {
    struct bbq_queue *queue = as_bbq(base);
    size_t allocated = 0;
    for (size_t i = 0; i < queue->record_block_count; ++i)
        if (atomic_load_explicit(&queue->record_blocks[i], memory_order_acquire) != NULL) ++allocated;
    return allocated;
}

void ca_bbq_test_reset_record_word_probes(ca_queue_t *base) {
    atomic_store_explicit(&as_bbq(base)->test_record_word_probes, 0, memory_order_relaxed);
}

size_t ca_bbq_test_record_word_probes(ca_queue_t *base) {
    return atomic_load_explicit(&as_bbq(base)->test_record_word_probes, memory_order_relaxed);
}
#endif

const struct ca_ops ca_bbq_ops = {
    .create = bbq_create,
    .destroy = bbq_destroy,
    .lifecycle_bind = bbq_lifecycle_bind,
    .lifecycle_unbind = bbq_lifecycle_unbind,
    .lifecycle_activate = bbq_lifecycle_activate,
    .lifecycle_deactivate = bbq_lifecycle_deactivate,
    .producer_register = bbq_producer_register,
    .producer_register_fallback = bbq_producer_register_fallback,
    .producer_release = bbq_producer_release,
    .reserve = bbq_reserve,
    .prepare_reserved = bbq_prepare_reserved,
    .commit_prepared = bbq_commit_prepared,
    .publish_reserved = bbq_publish_reserved,
    .cancel_reservation = bbq_cancel_reservation,
    .submit_span = bbq_submit_span,
    .credit_acquire = bbq_credit_acquire,
    .credit_submit_span = bbq_credit_submit_span,
    .credit_release = bbq_credit_release,
    .builder_begin = bbq_builder_begin,
    .builder_append = bbq_builder_append,
    .builder_prepare = bbq_builder_prepare,
    .builder_commit = bbq_builder_commit,
    .builder_publish = bbq_builder_publish,
    .builder_cancel = bbq_builder_cancel,
    .claim = bbq_claim,
    .complete = bbq_complete,
    .return_claim = bbq_return_claim,
    .capacity_read = bbq_capacity_read,
    .epoch = bbq_epoch,
    .wait_epoch = bbq_wait_epoch,
    .capacity_epoch = bbq_capacity_epoch,
    .wait_capacity_epoch = bbq_wait_capacity_epoch,
    .interrupt_waiters = bbq_interrupt_waiters,
    .quiesce = bbq_quiesce,
    .diagnostics_read = bbq_diagnostics_read,
    .dedicated_lane_limit = bbq_dedicated_lane_limit,
    .fallback_lane_count = bbq_fallback_lane_count,
    .ready_ring_capacity = bbq_ready_ring_capacity,
};
