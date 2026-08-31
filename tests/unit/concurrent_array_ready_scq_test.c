/*
 * Standalone deterministic tests for the ConcurrentArray ready-token ring.
 *
 * The adversarial cases stop one operation at each publication boundary.  A
 * semaphore is the readiness oracle: once entered is posted, the operation is
 * definitely at the named boundary.  Other producers and consumers must then
 * complete exact token-set work before the stopped operation is released.
 * alarm(60) is hang protection for a broken progress guarantee, not a timing
 * assertion; ordinary runs complete in well under a second.
 */
#define _GNU_SOURCE
#define CA_READY_SCQ_TESTING 1
#include "concurrent_array_ready_scq.h"

#include <pthread.h>
#include <sched.h>
#include <semaphore.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define CHECK(condition)                                                                    \
    do {                                                                                    \
        if (!(condition)) {                                                                 \
            fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #condition); \
            exit(1);                                                                        \
        }                                                                                   \
    } while (0)

typedef struct stop_hook_s {
    ca_ready_scq_test_point_t point;
    uint64_t ticket;
    _Atomic int armed;
    sem_t entered;
    sem_t release;
} stop_hook_t;

typedef struct enqueue_arg_s {
    ca_ready_scq_t *queue;
    uint64_t token;
    ca_ready_scq_result_t result;
} enqueue_arg_t;

typedef struct dequeue_arg_s {
    ca_ready_scq_t *queue;
    uint64_t token;
    ca_ready_scq_result_t result;
} dequeue_arg_t;

static void stop_hook_init(stop_hook_t *const hook, const ca_ready_scq_test_point_t point, const uint64_t ticket) {
    hook->point = point;
    hook->ticket = ticket;
    atomic_init(&hook->armed, 1);
    CHECK(sem_init(&hook->entered, 0, 0) == 0);
    CHECK(sem_init(&hook->release, 0, 0) == 0);
}

static void stop_hook_destroy(stop_hook_t *const hook) {
    CHECK(sem_destroy(&hook->entered) == 0);
    CHECK(sem_destroy(&hook->release) == 0);
}

static void stop_hook_callback(const ca_ready_scq_test_point_t point, const uint64_t ticket, void *const context) {
    stop_hook_t *const hook = context;
    int expected = 1;
    if (point != hook->point || ticket != hook->ticket ||
        !atomic_compare_exchange_strong_explicit(&hook->armed, &expected, 0, memory_order_acq_rel,
                                                 memory_order_acquire))
        return;
    CHECK(sem_post(&hook->entered) == 0);
    while (sem_wait(&hook->release) != 0);
}

static void *enqueue_thread(void *const argument) {
    enqueue_arg_t *const arg = argument;
    do {
        arg->result = ca_ready_scq_try_enqueue(arg->queue, arg->token);
        if (arg->result == CA_READY_SCQ_FULL) sched_yield();
    } while (arg->result == CA_READY_SCQ_FULL);
    return NULL;
}

static void *dequeue_thread(void *const argument) {
    dequeue_arg_t *const arg = argument;
    arg->result = ca_ready_scq_try_dequeue(arg->queue, &arg->token);
    return NULL;
}

static void test_basic_and_wrap(void) {
    ca_ready_scq_t *queue = NULL;
    uint64_t token;
    CHECK(ca_ready_scq_create(7, &queue) == CA_READY_SCQ_OK);
    CHECK(ca_ready_scq_capacity(queue) == 7);
    CHECK(ca_ready_scq_try_dequeue(queue, &token) == CA_READY_SCQ_EMPTY);
    for (uint64_t i = 0; i < 7; ++i) CHECK(ca_ready_scq_try_enqueue(queue, 100 + i) == CA_READY_SCQ_OK);
    CHECK(ca_ready_scq_reserved(queue) == 7);
    CHECK(ca_ready_scq_try_enqueue(queue, 999) == CA_READY_SCQ_FULL);
    for (uint64_t i = 0; i < 7; ++i) {
        CHECK(ca_ready_scq_try_dequeue(queue, &token) == CA_READY_SCQ_OK);
        CHECK(token == 100 + i);
    }
    for (uint64_t cycle = 0; cycle < 10000; ++cycle) {
        CHECK(ca_ready_scq_try_enqueue(queue, cycle) == CA_READY_SCQ_OK);
        CHECK(ca_ready_scq_try_dequeue(queue, &token) == CA_READY_SCQ_OK);
        CHECK(token == cycle);
    }
    CHECK(ca_ready_scq_reserved(queue) == 0);
    CHECK(ca_ready_scq_destroy(queue) == CA_READY_SCQ_OK);
}

static void test_capacity_matrix(void) {
    static const size_t capacities[] = {1, 2, 3, 7, 64, 65, 1000};
    for (size_t c = 0; c < sizeof(capacities) / sizeof(capacities[0]); ++c) {
        ca_ready_scq_t *queue = NULL;
        uint64_t token;
        CHECK(ca_ready_scq_create(capacities[c], &queue) == CA_READY_SCQ_OK);
        for (uint64_t i = 0; i < capacities[c]; ++i) CHECK(ca_ready_scq_try_enqueue(queue, i) == CA_READY_SCQ_OK);
        CHECK(ca_ready_scq_try_enqueue(queue, capacities[c]) == CA_READY_SCQ_FULL);
        for (uint64_t i = 0; i < capacities[c]; ++i) {
            CHECK(ca_ready_scq_try_dequeue(queue, &token) == CA_READY_SCQ_OK);
            CHECK(token == i);
        }
        CHECK(ca_ready_scq_try_dequeue(queue, &token) == CA_READY_SCQ_EMPTY);
        CHECK(ca_ready_scq_destroy(queue) == CA_READY_SCQ_OK);
    }
}

static void test_stopped_publisher(const ca_ready_scq_test_point_t point) {
    ca_ready_scq_t *queue = NULL;
    stop_hook_t hook;
    pthread_t producer;
    enqueue_arg_t blocked = {.token = 10, .result = CA_READY_SCQ_INVALID};
    uint64_t token;
    CHECK(ca_ready_scq_create(4, &queue) == CA_READY_SCQ_OK);
    stop_hook_init(&hook, point, 0);
    ca_ready_scq_test_set_hook(queue, stop_hook_callback, &hook);
    blocked.queue = queue;
    CHECK(pthread_create(&producer, NULL, enqueue_thread, &blocked) == 0);
    CHECK(sem_wait(&hook.entered) == 0);

    if (point == CA_READY_SCQ_TEST_ENQUEUE_AFTER_PUBLISH) {
        CHECK(ca_ready_scq_try_dequeue(queue, &token) == CA_READY_SCQ_OK);
        CHECK(token == 10);
    } else {
        /* Ticket one publishes while ticket zero is an interrupted hole. */
        CHECK(ca_ready_scq_try_enqueue(queue, 11) == CA_READY_SCQ_OK);
        CHECK(ca_ready_scq_try_dequeue(queue, &token) == CA_READY_SCQ_OK);
        CHECK(token == 11);
    }
    CHECK(sem_post(&hook.release) == 0);
    CHECK(pthread_join(producer, NULL) == 0);
    CHECK(blocked.result == CA_READY_SCQ_OK);
    if (point != CA_READY_SCQ_TEST_ENQUEUE_AFTER_PUBLISH) {
        CHECK(ca_ready_scq_try_dequeue(queue, &token) == CA_READY_SCQ_OK);
        CHECK(token == 10);
    }
    CHECK(ca_ready_scq_reserved(queue) == 0);
    ca_ready_scq_test_set_hook(queue, NULL, NULL);
    stop_hook_destroy(&hook);
    CHECK(ca_ready_scq_destroy(queue) == CA_READY_SCQ_OK);
}

static void test_cancelled_publisher(void) {
    ca_ready_scq_t *queue = NULL;
    stop_hook_t hook;
    pthread_t producer;
    enqueue_arg_t blocked = {.token = 20, .result = CA_READY_SCQ_INVALID};
    uint64_t token;
    void *thread_result;
    CHECK(ca_ready_scq_create(2, &queue) == CA_READY_SCQ_OK);
    stop_hook_init(&hook, CA_READY_SCQ_TEST_ENQUEUE_AFTER_RESERVE, 0);
    ca_ready_scq_test_set_hook(queue, stop_hook_callback, &hook);
    blocked.queue = queue;
    CHECK(pthread_create(&producer, NULL, enqueue_thread, &blocked) == 0);
    CHECK(sem_wait(&hook.entered) == 0);
    CHECK(ca_ready_scq_try_enqueue(queue, 21) == CA_READY_SCQ_OK);
    CHECK(ca_ready_scq_try_enqueue(queue, 22) == CA_READY_SCQ_FULL);
    CHECK(pthread_cancel(producer) == 0);
    CHECK(pthread_join(producer, &thread_result) == 0);
    CHECK(thread_result == PTHREAD_CANCELED);
    CHECK(ca_ready_scq_try_dequeue(queue, &token) == CA_READY_SCQ_OK);
    CHECK(token == 21);
    CHECK(ca_ready_scq_reserved(queue) == 0);
    CHECK(ca_ready_scq_try_enqueue(queue, 22) == CA_READY_SCQ_OK);
    CHECK(ca_ready_scq_try_dequeue(queue, &token) == CA_READY_SCQ_OK);
    CHECK(token == 22);
    ca_ready_scq_test_set_hook(queue, NULL, NULL);
    /* No waiter remains, but balance the semaphore before destruction. */
    CHECK(sem_post(&hook.release) == 0);
    stop_hook_destroy(&hook);
    CHECK(ca_ready_scq_destroy(queue) == CA_READY_SCQ_OK);
}

static void test_stopped_consumer_is_helped(const ca_ready_scq_test_point_t point) {
    ca_ready_scq_t *queue = NULL;
    stop_hook_t hook;
    pthread_t consumer;
    pthread_t producer;
    dequeue_arg_t blocked_consumer = {.result = CA_READY_SCQ_INVALID};
    enqueue_arg_t wrapped_producer = {.token = 32, .result = CA_READY_SCQ_INVALID};
    uint64_t token;
    CHECK(ca_ready_scq_create(2, &queue) == CA_READY_SCQ_OK);
    CHECK(ca_ready_scq_try_enqueue(queue, 30) == CA_READY_SCQ_OK);
    CHECK(ca_ready_scq_try_enqueue(queue, 31) == CA_READY_SCQ_OK);
    stop_hook_init(&hook, point, 0);
    ca_ready_scq_test_set_hook(queue, stop_hook_callback, &hook);
    blocked_consumer.queue = queue;
    CHECK(pthread_create(&consumer, NULL, dequeue_thread, &blocked_consumer) == 0);
    CHECK(sem_wait(&hook.entered) == 0);
    CHECK(ca_ready_scq_try_dequeue(queue, &token) == CA_READY_SCQ_OK);
    CHECK(token == 31);

    /* Ticket two is admitted but its cell still holds ticket zero. */
    wrapped_producer.queue = queue;
    CHECK(pthread_create(&producer, NULL, enqueue_thread, &wrapped_producer) == 0);
    while (ca_ready_scq_reserved(queue) != 2) sched_yield();
    /* This dequeue catches up the stopped ticket-zero consumer. */
    CHECK(ca_ready_scq_try_dequeue(queue, &token) == CA_READY_SCQ_OK);
    CHECK(token == 30);
    CHECK(pthread_join(producer, NULL) == 0);
    CHECK(wrapped_producer.result == CA_READY_SCQ_OK);
    CHECK(sem_post(&hook.release) == 0);
    CHECK(pthread_join(consumer, NULL) == 0);
    CHECK(blocked_consumer.result == CA_READY_SCQ_OK);
    CHECK(blocked_consumer.token == 32);
    CHECK(ca_ready_scq_reserved(queue) == 0);
    ca_ready_scq_test_set_hook(queue, NULL, NULL);
    stop_hook_destroy(&hook);
    CHECK(ca_ready_scq_destroy(queue) == CA_READY_SCQ_OK);
}

typedef struct many_state_s {
    ca_ready_scq_t *queue;
    unsigned producer_count;
    unsigned per_producer;
    _Atomic unsigned next_producer;
    _Atomic unsigned consumed;
    _Atomic int failed;
    _Atomic unsigned char *seen;
} many_state_t;

static void *many_producer(void *const argument) {
    many_state_t *const state = argument;
    const unsigned producer = atomic_fetch_add_explicit(&state->next_producer, 1, memory_order_relaxed);
    for (unsigned i = 0; i < state->per_producer; ++i) {
        const uint64_t token = (uint64_t)producer * state->per_producer + i + 1;
        ca_ready_scq_result_t result;
        do {
            result = ca_ready_scq_try_enqueue(state->queue, token);
            if (result == CA_READY_SCQ_FULL) sched_yield();
        } while (result == CA_READY_SCQ_FULL);
        if (result != CA_READY_SCQ_OK) {
            atomic_store_explicit(&state->failed, 1, memory_order_release);
            return NULL;
        }
    }
    return NULL;
}

static void *many_consumer(void *const argument) {
    many_state_t *const state = argument;
    const unsigned total = state->producer_count * state->per_producer;
    while (atomic_load_explicit(&state->consumed, memory_order_acquire) < total) {
        uint64_t token;
        const ca_ready_scq_result_t result = ca_ready_scq_try_dequeue(state->queue, &token);
        if (result == CA_READY_SCQ_EMPTY) {
            sched_yield();
            continue;
        }
        if (result != CA_READY_SCQ_OK || token == 0 || token > total ||
            atomic_fetch_add_explicit(&state->seen[token - 1], 1, memory_order_acq_rel) != 0) {
            atomic_store_explicit(&state->failed, 1, memory_order_release);
            return NULL;
        }
        atomic_fetch_add_explicit(&state->consumed, 1, memory_order_release);
    }
    return NULL;
}

static void test_concurrency(const unsigned producers, const unsigned consumers) {
    const unsigned per_producer = 1000;
    const unsigned total = producers * per_producer;
    ca_ready_scq_t *queue = NULL;
    pthread_t *producer_threads = calloc(producers, sizeof(*producer_threads));
    pthread_t *consumer_threads = calloc(consumers, sizeof(*consumer_threads));
    many_state_t state;
    CHECK(producer_threads != NULL && consumer_threads != NULL);
    CHECK(ca_ready_scq_create(257, &queue) == CA_READY_SCQ_OK);
    state.queue = queue;
    state.producer_count = producers;
    state.per_producer = per_producer;
    atomic_init(&state.next_producer, 0);
    atomic_init(&state.consumed, 0);
    atomic_init(&state.failed, 0);
    state.seen = calloc(total, sizeof(*state.seen));
    CHECK(state.seen != NULL);
    for (unsigned i = 0; i < consumers; ++i)
        CHECK(pthread_create(&consumer_threads[i], NULL, many_consumer, &state) == 0);
    for (unsigned i = 0; i < producers; ++i)
        CHECK(pthread_create(&producer_threads[i], NULL, many_producer, &state) == 0);
    for (unsigned i = 0; i < producers; ++i) CHECK(pthread_join(producer_threads[i], NULL) == 0);
    for (unsigned i = 0; i < consumers; ++i) CHECK(pthread_join(consumer_threads[i], NULL) == 0);
    CHECK(atomic_load_explicit(&state.failed, memory_order_acquire) == 0);
    CHECK(atomic_load_explicit(&state.consumed, memory_order_acquire) == total);
    CHECK(ca_ready_scq_reserved(queue) == 0);
    for (unsigned i = 0; i < total; ++i) CHECK(atomic_load_explicit(&state.seen[i], memory_order_relaxed) == 1);
    free(state.seen);
    free(consumer_threads);
    free(producer_threads);
    CHECK(ca_ready_scq_destroy(queue) == CA_READY_SCQ_OK);
}

static void test_counter_guard(void) {
    ca_ready_scq_t *queue = NULL;
    uint64_t token;
    uint64_t limit;
    CHECK(ca_ready_scq_create(7, &queue) == CA_READY_SCQ_OK);
    limit = ca_ready_scq_test_ticket_limit(queue);
    CHECK(limit > 7 && limit % 7 == 0);
    CHECK(ca_ready_scq_test_seed_empty(queue, limit - 7) == CA_READY_SCQ_OK);
    for (uint64_t i = 0; i < 7; ++i) CHECK(ca_ready_scq_try_enqueue(queue, i) == CA_READY_SCQ_OK);
    for (uint64_t i = 0; i < 7; ++i) CHECK(ca_ready_scq_try_dequeue(queue, &token) == CA_READY_SCQ_OK);
    CHECK(ca_ready_scq_try_enqueue(queue, 8) == CA_READY_SCQ_OVERFLOW);
    CHECK(ca_ready_scq_destroy(queue) == CA_READY_SCQ_OK);
}

/* Intent: cross the former 32-bit-token generation horizon with an admitted,
 * interrupted ticket. The exact 11/10 ordering proves the hole is helped and
 * retried, then repeated exact enqueue/dequeue proves the expanded counter
 * representation continues beyond the old limit without abort or ABA. */
static void test_expanded_lifetime_boundary(void) {
    const size_t capacity = 4;
    const uint64_t base = ((UINT64_C(1) << 31) - 1) * capacity;
    ca_ready_scq_t *queue = NULL;
    stop_hook_t hook;
    pthread_t producer;
    enqueue_arg_t blocked = {.token = 10, .result = CA_READY_SCQ_INVALID};
    uint64_t token;
    CHECK(ca_ready_scq_create(capacity, &queue) == CA_READY_SCQ_OK);
    CHECK(ca_ready_scq_test_ticket_limit(queue) > base + 16);
    CHECK(ca_ready_scq_test_seed_empty(queue, base) == CA_READY_SCQ_OK);
    stop_hook_init(&hook, CA_READY_SCQ_TEST_ENQUEUE_AFTER_RESERVE, base);
    ca_ready_scq_test_set_hook(queue, stop_hook_callback, &hook);
    blocked.queue = queue;
    CHECK(pthread_create(&producer, NULL, enqueue_thread, &blocked) == 0);
    CHECK(sem_wait(&hook.entered) == 0);
    CHECK(ca_ready_scq_try_enqueue(queue, 11) == CA_READY_SCQ_OK);
    CHECK(ca_ready_scq_try_dequeue(queue, &token) == CA_READY_SCQ_OK && token == 11);
    CHECK(sem_post(&hook.release) == 0);
    CHECK(pthread_join(producer, NULL) == 0 && blocked.result == CA_READY_SCQ_OK);
    CHECK(ca_ready_scq_try_dequeue(queue, &token) == CA_READY_SCQ_OK && token == 10);
    ca_ready_scq_test_set_hook(queue, NULL, NULL);
    stop_hook_destroy(&hook);
    for (uint64_t i = 0; i < 16; ++i) {
        CHECK(ca_ready_scq_try_enqueue(queue, 100 + i) == CA_READY_SCQ_OK);
        CHECK(ca_ready_scq_try_dequeue(queue, &token) == CA_READY_SCQ_OK && token == 100 + i);
    }
    CHECK(ca_ready_scq_reserved(queue) == 0);
    CHECK(ca_ready_scq_destroy(queue) == CA_READY_SCQ_OK);
}

static void test_quiescent_destroy(void) {
    ca_ready_scq_t *queue = NULL;
    uint64_t token;
    CHECK(ca_ready_scq_create(0, &queue) == CA_READY_SCQ_INVALID);
    CHECK(ca_ready_scq_create(65536, &queue) == CA_READY_SCQ_INVALID);
    CHECK(ca_ready_scq_create(1, &queue) == CA_READY_SCQ_OK);
    CHECK(ca_ready_scq_try_enqueue(queue, ca_ready_scq_token_max() + 1) == CA_READY_SCQ_INVALID);
    CHECK(ca_ready_scq_try_enqueue(queue, 1) == CA_READY_SCQ_OK);
    CHECK(ca_ready_scq_destroy(queue) == CA_READY_SCQ_BUSY);
    CHECK(ca_ready_scq_try_dequeue(queue, &token) == CA_READY_SCQ_OK);
    CHECK(token == 1);
    CHECK(ca_ready_scq_destroy(queue) == CA_READY_SCQ_OK);
}

int main(void) {
    alarm(60);
    CHECK(ca_ready_scq_is_lock_free());
    CHECK(ca_ready_scq_token_max() == UINT16_MAX);
    test_basic_and_wrap();
    test_capacity_matrix();
    test_stopped_publisher(CA_READY_SCQ_TEST_ENQUEUE_AFTER_RESERVE);
    test_stopped_publisher(CA_READY_SCQ_TEST_ENQUEUE_BEFORE_CELL_LOAD);
    test_stopped_publisher(CA_READY_SCQ_TEST_ENQUEUE_BEFORE_PUBLISH_CAS);
    test_stopped_publisher(CA_READY_SCQ_TEST_ENQUEUE_AFTER_PUBLISH);
    test_cancelled_publisher();
    test_stopped_consumer_is_helped(CA_READY_SCQ_TEST_DEQUEUE_AFTER_CLAIM);
    test_stopped_consumer_is_helped(CA_READY_SCQ_TEST_DEQUEUE_BEFORE_HELP_CAS);
    test_concurrency(1, 1);
    test_concurrency(8, 8);
    test_concurrency(16, 16);
    test_counter_guard();
    test_expanded_lifetime_boundary();
    test_quiescent_destroy();
    puts("concurrent_array_ready_scq_test: PASS");
    return 0;
}
