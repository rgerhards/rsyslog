/*
 * Helpable bounded ready-token queue for ConcurrentArray.
 *
 * Concurrency and progress
 * ------------------------
 * The ring is an SCQ-family ticket/cycle queue, but it is not a verbatim
 * Nikolaev SCQ.  Enqueue, dequeue, and contiguous-reclamation tickets are
 * independent lock-free words.  Exact bounded admission uses
 * enqueue_ticket - reclaim_ticket, so choosing a ticket is itself the visible
 * reservation and creates no separate permit-acquisition hole.  Each cell
 * contains a cycle, a token, and a full bit in one lock-free word.
 *
 * A dequeuer owns a monotonically increasing ticket.  If the matching
 * producer stopped after admission but before publication, the dequeuer moves
 * the empty cell to the next cycle and returns that admission credit.  If an
 * earlier dequeuer stopped, a later-cycle dequeuer consumes an older published
 * token or skips all unpublished generations in one compare/exchange.  Any
 * thread may then advance the contiguous reclamation ticket by inspecting the
 * already-advanced cell generations.  This makes completion idempotently
 * helpable too: a consumer stopped after its cell CAS cannot leak capacity.
 * Normal empty checks and publication do not scan lanes or the ring.
 *
 * Unlike SCQ's threshold-based unbounded dequeue-ticket search, dequeue here
 * has an exact finite horizon: the enqueue word exposes the last admitted
 * ticket.  It therefore stops when dequeue_ticket reaches enqueue_ticket and
 * needs no threshold heuristic.  Operations are lock-free as a system, not
 * wait-free individually: an enqueuer whose cell still contains an older
 * token may wait while another consumer completes or helps that cell.
 *
 * The queue deliberately promises exact-once token removal, not global FIFO
 * completion order between concurrent consumers.  The caller's per-lane
 * ready-bit protocol is responsible for allowing at most one live token for a
 * lane.  The successful dequeue cell CAS transfers the token to that caller;
 * asynchronous thread cancellation must remain disabled until the caller has
 * handed the token to its lane logic.  No hazard pointers are needed because
 * token and cycle are stored in the same atomic word.
 *
 * Counter wrap is forbidden rather than silently wrapped.  The last usable
 * full cycle leaves one representable empty generation for safe reclamation.
 */
#include "concurrent_array_ready_scq.h"

#include <limits.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>

#define CA_READY_SCQ_CELL_FULL UINT64_C(1)
#define CA_READY_SCQ_CELL_TOKEN_SHIFT 1U
#define CA_READY_SCQ_CELL_TOKEN_BITS 16U
#define CA_READY_SCQ_CELL_TOKEN_MASK UINT64_C(0xffff)
#define CA_READY_SCQ_CELL_GENERATION_SHIFT (CA_READY_SCQ_CELL_TOKEN_SHIFT + CA_READY_SCQ_CELL_TOKEN_BITS)
#define CA_READY_SCQ_CELL_GENERATION_MAX ((UINT64_C(1) << (64U - CA_READY_SCQ_CELL_GENERATION_SHIFT)) - UINT64_C(1))

typedef struct ca_ready_scq_cell_s {
    _Alignas(8) _Atomic uint64_t state;
} ca_ready_scq_cell_t;

struct ca_ready_scq_s {
    size_t capacity;
    uint64_t ticket_limit;
    _Alignas(8) _Atomic uint64_t enqueue_ticket;
    _Alignas(8) _Atomic uint64_t dequeue_ticket;
    _Alignas(8) _Atomic uint64_t reclaim_ticket;
    ca_ready_scq_cell_t *cells;
#ifdef CA_READY_SCQ_TESTING
    ca_ready_scq_test_hook_t test_hook;
    void *test_hook_context;
#endif
};

static inline uint64_t cell_generation(const uint64_t state) {
    return state >> CA_READY_SCQ_CELL_GENERATION_SHIFT;
}

static inline int cell_is_full(const uint64_t state) {
    return (state & CA_READY_SCQ_CELL_FULL) != 0;
}

static inline uint64_t cell_token(const uint64_t state) {
    return (state >> CA_READY_SCQ_CELL_TOKEN_SHIFT) & CA_READY_SCQ_CELL_TOKEN_MASK;
}

static inline uint64_t empty_cell(const uint64_t generation) {
    return generation << CA_READY_SCQ_CELL_GENERATION_SHIFT;
}

static inline uint64_t full_cell(const uint64_t generation, const uint64_t token) {
    return (generation << CA_READY_SCQ_CELL_GENERATION_SHIFT) | (token << CA_READY_SCQ_CELL_TOKEN_SHIFT) |
           CA_READY_SCQ_CELL_FULL;
}

#ifdef CA_READY_SCQ_TESTING
static inline void test_hook(ca_ready_scq_t *const queue,
                             const ca_ready_scq_test_point_t point,
                             const uint64_t ticket) {
    ca_ready_scq_test_hook_t const hook = queue->test_hook;
    if (hook != NULL) hook(point, ticket, queue->test_hook_context);
}
#else
    #define test_hook(queue, point, ticket) ((void)0)
    #define CA_READY_SCQ_TEST_ENQUEUE_AFTER_RESERVE 0
    #define CA_READY_SCQ_TEST_ENQUEUE_BEFORE_CELL_LOAD 0
    #define CA_READY_SCQ_TEST_ENQUEUE_BEFORE_PUBLISH_CAS 0
    #define CA_READY_SCQ_TEST_ENQUEUE_AFTER_PUBLISH 0
    #define CA_READY_SCQ_TEST_DEQUEUE_AFTER_CLAIM 0
    #define CA_READY_SCQ_TEST_DEQUEUE_BEFORE_HELP_CAS 0
    #define CA_READY_SCQ_TEST_DEQUEUE_AFTER_HELP 0
#endif

static void advance_reclaim(ca_ready_scq_t *const queue) {
    uint64_t reclaim = atomic_load_explicit(&queue->reclaim_ticket, memory_order_acquire);
    for (;;) {
        const uint64_t tail = atomic_load_explicit(&queue->enqueue_ticket, memory_order_acquire);
        uint64_t observed;
        uint64_t generation;
        if (reclaim >= tail) return;
        observed = atomic_load_explicit(&queue->cells[reclaim % queue->capacity].state, memory_order_acquire);
        generation = reclaim / queue->capacity;
        if (cell_generation(observed) <= generation) return;
        atomic_compare_exchange_weak_explicit(&queue->reclaim_ticket, &reclaim, reclaim + 1, memory_order_acq_rel,
                                              memory_order_acquire);
    }
}

int ca_ready_scq_is_lock_free(void) {
    _Atomic uint64_t probe;
    atomic_init(&probe, 0);
    return atomic_is_lock_free(&probe);
}

uint64_t ca_ready_scq_token_max(void) {
    return CA_READY_SCQ_CELL_TOKEN_MASK;
}

ca_ready_scq_result_t ca_ready_scq_create(const size_t capacity, ca_ready_scq_t **const result) {
    ca_ready_scq_t *queue;
    uint64_t generation_limit;

    if (result == NULL || capacity == 0 || capacity > UINT16_MAX) return CA_READY_SCQ_INVALID;
    *result = NULL;
    if (!ca_ready_scq_is_lock_free()) return CA_READY_SCQ_UNSUPPORTED;

    queue = calloc(1, sizeof(*queue));
    if (queue == NULL) return CA_READY_SCQ_NOMEM;
    queue->cells = calloc(capacity, sizeof(*queue->cells));
    if (queue->cells == NULL) {
        free(queue);
        return CA_READY_SCQ_NOMEM;
    }
    queue->capacity = capacity;
    /* Generation MAX is reserved for the final empty/reclaimed marker. */
    generation_limit = CA_READY_SCQ_CELL_GENERATION_MAX * (uint64_t)capacity;
    queue->ticket_limit = generation_limit;
    atomic_init(&queue->enqueue_ticket, 0);
    atomic_init(&queue->dequeue_ticket, 0);
    atomic_init(&queue->reclaim_ticket, 0);
    for (size_t i = 0; i < capacity; ++i) atomic_init(&queue->cells[i].state, empty_cell(0));
#ifdef CA_READY_SCQ_TESTING
    queue->test_hook = NULL;
    queue->test_hook_context = NULL;
#endif
    *result = queue;
    return CA_READY_SCQ_OK;
}

ca_ready_scq_result_t ca_ready_scq_try_enqueue(ca_ready_scq_t *const queue, const uint64_t token) {
    uint64_t ticket;
    uint64_t old_enqueue;
    uint64_t generation;
    uint64_t expected_empty;
    uint64_t observed;
    uint64_t observed_generation;
    uint64_t desired;
    size_t index;
    ca_ready_scq_cell_t *cell;

    if (queue == NULL || token > CA_READY_SCQ_CELL_TOKEN_MASK) return CA_READY_SCQ_INVALID;

retry_admission:
    old_enqueue = atomic_load_explicit(&queue->enqueue_ticket, memory_order_acquire);
    for (;;) {
        uint64_t reclaim = atomic_load_explicit(&queue->reclaim_ticket, memory_order_acquire);
        if (reclaim > old_enqueue) {
            old_enqueue = atomic_load_explicit(&queue->enqueue_ticket, memory_order_acquire);
            continue;
        }
        if (old_enqueue - reclaim >= queue->capacity) {
            advance_reclaim(queue);
            reclaim = atomic_load_explicit(&queue->reclaim_ticket, memory_order_acquire);
            if (reclaim > old_enqueue) {
                old_enqueue = atomic_load_explicit(&queue->enqueue_ticket, memory_order_acquire);
                continue;
            }
            if (old_enqueue - reclaim >= queue->capacity) return CA_READY_SCQ_FULL;
        }
        if (old_enqueue >= queue->ticket_limit) return CA_READY_SCQ_OVERFLOW;
        if (atomic_compare_exchange_weak_explicit(&queue->enqueue_ticket, &old_enqueue, old_enqueue + 1,
                                                  memory_order_acq_rel, memory_order_acquire)) {
            ticket = old_enqueue;
            break;
        }
    }

    test_hook(queue, CA_READY_SCQ_TEST_ENQUEUE_AFTER_RESERVE, ticket);
    index = (size_t)(ticket % queue->capacity);
    generation = ticket / queue->capacity;
    expected_empty = empty_cell(generation);
    cell = &queue->cells[index];

    for (;;) {
        test_hook(queue, CA_READY_SCQ_TEST_ENQUEUE_BEFORE_CELL_LOAD, ticket);
        observed = atomic_load_explicit(&cell->state, memory_order_acquire);
        observed_generation = cell_generation(observed);
        if (observed_generation > generation) goto retry_admission;
        if (observed == expected_empty) {
            desired = full_cell(generation, token);
            test_hook(queue, CA_READY_SCQ_TEST_ENQUEUE_BEFORE_PUBLISH_CAS, ticket);
            if (atomic_compare_exchange_strong_explicit(&cell->state, &observed, desired, memory_order_release,
                                                        memory_order_acquire)) {
                test_hook(queue, CA_READY_SCQ_TEST_ENQUEUE_AFTER_PUBLISH, ticket);
                return CA_READY_SCQ_OK;
            }
            continue;
        }
        /* An earlier claimed dequeue ticket owns the old cell. */
        sched_yield();
    }
}

ca_ready_scq_result_t ca_ready_scq_try_dequeue(ca_ready_scq_t *const queue, uint64_t *const token) {
    uint64_t head;
    uint64_t tail;
    uint64_t ticket;
    uint64_t reclaim;
    uint64_t generation;
    uint64_t observed;
    uint64_t observed_generation;
    uint64_t desired;
    size_t index;
    int full;
    ca_ready_scq_cell_t *cell;

    if (queue == NULL || token == NULL) return CA_READY_SCQ_INVALID;

    for (;;) {
        head = atomic_load_explicit(&queue->dequeue_ticket, memory_order_acquire);
        for (;;) {
            tail = atomic_load_explicit(&queue->enqueue_ticket, memory_order_acquire);
            if (head >= tail) {
                advance_reclaim(queue);
                reclaim = atomic_load_explicit(&queue->reclaim_ticket, memory_order_acquire);
                head = atomic_load_explicit(&queue->dequeue_ticket, memory_order_acquire);
                tail = atomic_load_explicit(&queue->enqueue_ticket, memory_order_acquire);
                if (head < tail) continue;
                if (reclaim >= head) return CA_READY_SCQ_EMPTY;
                /* All tickets are claimed; help the oldest incomplete claim. */
                ticket = reclaim;
                break;
            }
            if (atomic_compare_exchange_weak_explicit(&queue->dequeue_ticket, &head, head + 1, memory_order_acq_rel,
                                                      memory_order_acquire)) {
                ticket = head;
                break;
            }
        }

        index = (size_t)(ticket % queue->capacity);
        generation = ticket / queue->capacity;
        cell = &queue->cells[index];
        test_hook(queue, CA_READY_SCQ_TEST_DEQUEUE_AFTER_CLAIM, ticket);

        for (;;) {
            observed = atomic_load_explicit(&cell->state, memory_order_acquire);
            observed_generation = cell_generation(observed);
            full = cell_is_full(observed);
            if (observed_generation > generation) break;
            desired = empty_cell(generation + 1);
            test_hook(queue, CA_READY_SCQ_TEST_DEQUEUE_BEFORE_HELP_CAS, ticket);
            if (!atomic_compare_exchange_weak_explicit(&cell->state, &observed, desired, memory_order_acq_rel,
                                                       memory_order_acquire))
                continue;
            advance_reclaim(queue);
            test_hook(queue, CA_READY_SCQ_TEST_DEQUEUE_AFTER_HELP, ticket);
            if (full) {
                *token = cell_token(observed);
                return CA_READY_SCQ_OK;
            }
            break;
        }
    }
}

size_t ca_ready_scq_capacity(const ca_ready_scq_t *const queue) {
    return queue == NULL ? 0 : queue->capacity;
}

size_t ca_ready_scq_reserved(const ca_ready_scq_t *const queue) {
    uint64_t tail;
    uint64_t reclaim;
    if (queue == NULL) return 0;
    tail = atomic_load_explicit(&queue->enqueue_ticket, memory_order_acquire);
    reclaim = atomic_load_explicit(&queue->reclaim_ticket, memory_order_acquire);
    while (reclaim > tail) tail = atomic_load_explicit(&queue->enqueue_ticket, memory_order_acquire);
    return (size_t)(tail - reclaim);
}

ca_ready_scq_result_t ca_ready_scq_destroy(ca_ready_scq_t *const queue) {
    uint64_t enqueue;
    if (queue == NULL) return CA_READY_SCQ_INVALID;
    advance_reclaim(queue);
    enqueue = atomic_load_explicit(&queue->enqueue_ticket, memory_order_acquire);
    if (atomic_load_explicit(&queue->reclaim_ticket, memory_order_acquire) != enqueue ||
        atomic_load_explicit(&queue->dequeue_ticket, memory_order_acquire) != enqueue)
        return CA_READY_SCQ_BUSY;
    free(queue->cells);
    free(queue);
    return CA_READY_SCQ_OK;
}

#ifdef CA_READY_SCQ_TESTING
void ca_ready_scq_test_set_hook(ca_ready_scq_t *const queue, ca_ready_scq_test_hook_t hook, void *const context) {
    if (queue != NULL) {
        queue->test_hook = hook;
        queue->test_hook_context = context;
    }
}

ca_ready_scq_result_t ca_ready_scq_test_seed_empty(ca_ready_scq_t *const queue, const uint64_t ticket_base) {
    uint64_t generation;
    if (queue == NULL || ticket_base >= queue->ticket_limit || ticket_base % queue->capacity != 0)
        return CA_READY_SCQ_INVALID;
    if (atomic_load_explicit(&queue->reclaim_ticket, memory_order_acquire) !=
            atomic_load_explicit(&queue->enqueue_ticket, memory_order_acquire) ||
        atomic_load_explicit(&queue->dequeue_ticket, memory_order_acquire) !=
            atomic_load_explicit(&queue->enqueue_ticket, memory_order_acquire))
        return CA_READY_SCQ_BUSY;
    generation = ticket_base / queue->capacity;
    for (size_t i = 0; i < queue->capacity; ++i)
        atomic_store_explicit(&queue->cells[i].state, empty_cell(generation), memory_order_relaxed);
    atomic_store_explicit(&queue->dequeue_ticket, ticket_base, memory_order_relaxed);
    atomic_store_explicit(&queue->reclaim_ticket, ticket_base, memory_order_relaxed);
    atomic_store_explicit(&queue->enqueue_ticket, ticket_base, memory_order_release);
    return CA_READY_SCQ_OK;
}

uint64_t ca_ready_scq_test_ticket_limit(const ca_ready_scq_t *const queue) {
    return queue == NULL ? 0 : queue->ticket_limit;
}
#endif
