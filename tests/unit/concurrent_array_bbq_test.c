/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Intent: validate the candidate-neutral ConcurrentArray contract for the
 * standalone BBQ core without enabling it in rsyslog configuration.
 *
 * Exact ownership and capacity are the oracles: every accepted integer is
 * completed once, retry and returned claims reappear, cancelled admission
 * restores every credit, and concurrent identities are neither lost nor
 * duplicated. Five-second deadlines and the process alarm are hang protection,
 * not timing pass criteria.
 */

#include "concurrent_array_internal.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define CHECK(condition)                                                                    \
    do {                                                                                    \
        if (!(condition)) {                                                                 \
            fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, #condition); \
            exit(1);                                                                        \
        }                                                                                   \
    } while (0)

static void *item_id(size_t id) {
    return (void *)(uintptr_t)(id + 1);
}

static size_t id_of(void *item) {
    CHECK(item != NULL);
    return (size_t)(uintptr_t)item - 1;
}

static ca_queue_t *new_queue(size_t capacity, unsigned consumers, ca_dispose_fn dispose, void *user) {
    ca_queue_t *queue = NULL;
    const ca_config_t config = {
        .core = CA_CORE_BBQ,
        .capacity = capacity,
        .consumers = consumers,
        .dispose = dispose,
        .dispose_user = user,
    };
    CHECK(ca_create(&config, &queue) == CA_OK);
    CHECK(queue != NULL);
    return queue;
}

static void count_dispose(void *item, ca_completion_state_t state, void *user) {
    (void)item;
    (void)state;
    atomic_fetch_add_explicit((_Atomic size_t *)user, 1, memory_order_relaxed);
}

static void check_capacity(ca_queue_t *queue, size_t capacity, size_t available) {
    ca_capacity_snapshot_t snapshot;
    ca_capacity_read(queue, &snapshot);
    CHECK(snapshot.capacity == capacity);
    CHECK(snapshot.available == available);
    CHECK(snapshot.available + snapshot.speculative_unused + snapshot.in_flight <= snapshot.capacity);
}

static size_t drain_commit(ca_queue_t *queue, size_t maximum, unsigned char *seen, size_t seen_count) {
    ca_claim_item_t *items = calloc(maximum, sizeof(*items));
    ca_completion_state_t *states = calloc(maximum, sizeof(*states));
    CHECK(items != NULL && states != NULL);
    size_t total = 0;
    for (;;) {
        ca_claim_t claim;
        const ca_status_t status = ca_claim_up_to(queue, &claim, items, maximum);
        if (status == CA_EMPTY) break;
        CHECK(status == CA_OK);
        for (size_t i = 0; i < claim.count; ++i) {
            if (seen != NULL) {
                const size_t id = id_of(items[i].item);
                CHECK(id < seen_count && seen[id] == 0);
                seen[id] = 1;
            }
            states[i] = CA_COMPLETE_COMMIT;
        }
        total += claim.count;
        CHECK(ca_complete(&claim, states) == CA_OK);
    }
    free(states);
    free(items);
    return total;
}

static void drain_expect_order(ca_queue_t *queue, size_t first, size_t count, size_t maximum) {
    ca_claim_item_t *items = calloc(maximum, sizeof(*items));
    ca_completion_state_t *states = calloc(maximum, sizeof(*states));
    CHECK(items != NULL && states != NULL);
    size_t expected = first;
    while (expected < first + count) {
        ca_claim_t claim;
        CHECK(ca_claim_up_to(queue, &claim, items, maximum) == CA_OK);
        for (size_t i = 0; i < claim.count; ++i) {
            CHECK(id_of(items[i].item) == expected++);
            states[i] = CA_COMPLETE_COMMIT;
        }
        CHECK(ca_complete(&claim, states) == CA_OK);
    }
    free(states);
    free(items);
}

static void finish_queue(ca_queue_t *queue) {
    CHECK(ca_quiesce(queue, CA_QUIESCE_DRAIN, NULL) == CA_OK);
    CHECK(ca_destroy(queue) == CA_OK);
}

static void test_capacity_boundaries(void) {
    static const size_t capacities[] = {1, 2, 3, 7, 8, 15, 16, 17, 63, 64, 65};
    void *items[130];
    for (size_t i = 0; i < 130; ++i) items[i] = item_id(i);
    for (size_t c = 0; c < sizeof(capacities) / sizeof(capacities[0]); ++c) {
        const size_t capacity = capacities[c];
        ca_queue_t *queue = new_queue(capacity, 4, NULL, NULL);
        ca_producer_t producer;
        CHECK(ca_producer_register(queue, 11, &producer) == CA_OK);
        size_t accepted = 0;
        CHECK(ca_submit_span(queue, &producer, items, capacity + 1, &accepted) == CA_PARTIAL);
        CHECK(accepted == capacity);
        check_capacity(queue, capacity, 0);
        accepted = 99;
        CHECK(ca_submit_span(queue, &producer, items, 1, &accepted) == CA_FULL);
        CHECK(accepted == 0);
        CHECK(drain_commit(queue, 19, NULL, 0) == capacity);
        check_capacity(queue, capacity, capacity);
        CHECK(ca_submit_one(queue, &producer, item_id(129)) == CA_OK);
        CHECK(drain_commit(queue, 1, NULL, 0) == 1);
        CHECK(ca_producer_release(&producer) == CA_OK);
        finish_queue(queue);
    }
}

static void test_large_span_and_wrap(void) {
    static const size_t sizes[] = {127, 128, 129, 1000, 4096, 8192, 65536};
    for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); ++s) {
        const size_t count = sizes[s];
        ca_queue_t *queue = new_queue(count, 16, NULL, NULL);
        ca_producer_t producer;
        CHECK(ca_producer_register(queue, 20 + s, &producer) == CA_OK);
        void **items = calloc(count, sizeof(*items));
        CHECK(items != NULL);
        for (size_t i = 0; i < count; ++i) items[i] = item_id(i);
        if (count == 65536) ca_bbq_test_reset_record_word_probes(queue);
        size_t accepted = 0;
        CHECK(ca_submit_span(queue, &producer, items, count, &accepted) == CA_OK);
        CHECK(accepted == count);
        if (count == 65536) {
            /* The rotating record-word cursor gives every item in this exact
             * 1024-word full-capacity span a non-full starting word. One probe
             * per record is the oracle against restarting at word zero. */
            CHECK(ca_bbq_test_record_word_probes(queue) == count);
        }
        drain_expect_order(queue, 0, count, 17);
        for (size_t cycle = 0; cycle < 2000; ++cycle) {
            CHECK(ca_submit_one(queue, &producer, item_id(cycle % count)) == CA_OK);
            CHECK(drain_commit(queue, 1, NULL, 0) == 1);
        }
        CHECK(ca_producer_release(&producer) == CA_OK);
        finish_queue(queue);
        free(items);
    }
}

static void test_control_word_wrap_integrity(void) {
    enum { CAPACITY = 65, CYCLES = 1024 };
    ca_queue_t *queue = new_queue(CAPACITY, 1, NULL, NULL);
    ca_producer_t producer;
    CHECK(ca_producer_register(queue, 29, &producer) == CA_OK);
    void *items[CAPACITY];

    /* Each cycle crosses the 64-cell block boundary and reuses every cell in
     * its next generation. Exact count and order detect a stale control word,
     * an early generation reuse, or a duplicate record-pool index. */
    for (size_t cycle = 0; cycle < CYCLES; ++cycle) {
        const size_t first = cycle * CAPACITY;
        for (size_t i = 0; i < CAPACITY; ++i) items[i] = item_id(first + i);
        size_t accepted = 0;
        CHECK(ca_submit_span(queue, &producer, items, CAPACITY, &accepted) == CA_OK);
        CHECK(accepted == CAPACITY);
        drain_expect_order(queue, first, CAPACITY, 13);
        check_capacity(queue, CAPACITY, CAPACITY);
    }

    CHECK(ca_producer_release(&producer) == CA_OK);
    finish_queue(queue);
}

static void test_reservation_credit_and_builder(void) {
    ca_queue_t *queue = new_queue(128, 2, NULL, NULL);
    ca_producer_t producer;
    CHECK(ca_producer_register(queue, 1, &producer) == CA_OK);
    ca_reservation_t reservation;
    CHECK(ca_reserve(queue, &producer, 128, &reservation) == CA_OK);
    check_capacity(queue, 128, 0);
    ca_cancel_reservation(&reservation);
    check_capacity(queue, 128, 128);

    /* A logical reservation creates no physical hole: independently
     * published work remains immediately claimable, and cancelling the held
     * reservation returns its credit exactly once. */
    CHECK(ca_reserve(queue, &producer, 127, &reservation) == CA_OK);
    CHECK(ca_submit_one(queue, &producer, item_id(127)) == CA_OK);
    CHECK(drain_commit(queue, 1, NULL, 0) == 1);
    ca_cancel_reservation(&reservation);
    check_capacity(queue, 128, 128);

    ca_builder_t cancelled;
    CHECK(ca_builder_begin(queue, &producer, &cancelled) == CA_OK);
    ca_credit_lease_t cancelled_lease;
    CHECK(ca_credit_acquire(queue, &producer, 1, &cancelled_lease) == CA_OK);
    void *cancelled_item = item_id(127);
    size_t cancelled_accepted = 0;
    CHECK(ca_builder_append(&cancelled, &cancelled_lease, &cancelled_item, 1, &cancelled_accepted) == CA_OK);
    CHECK(cancelled_accepted == 1);
    ca_credit_release(&cancelled_lease);
    ca_builder_cancel(&cancelled);
    check_capacity(queue, 128, 128);

    ca_builder_t builder;
    CHECK(ca_builder_begin(queue, &producer, &builder) == CA_OK);
    void *items[128];
    for (size_t i = 0; i < 128; ++i) items[i] = item_id(i);
    for (size_t offset = 0; offset < 128; offset += 64) {
        ca_credit_lease_t lease;
        CHECK(ca_credit_acquire(queue, &producer, 64, &lease) == CA_OK);
        size_t accepted = 0;
        CHECK(ca_builder_append(&builder, &lease, &items[offset], 64, &accepted) == CA_OK);
        CHECK(accepted == 64 && lease.unused == 0);
        ca_credit_release(&lease);
    }
    CHECK(ca_builder_prepare(&builder) == CA_OK);
    CHECK(ca_builder_commit(&builder) == CA_OK);
    CHECK(drain_commit(queue, 128, NULL, 0) == 128);
    check_capacity(queue, 128, 128);
    CHECK(ca_producer_release(&producer) == CA_OK);
    finish_queue(queue);
}

static void test_record_pool_locality_and_trim(void) {
    enum { CAPACITY = 256 };
    ca_queue_t *queue = new_queue(CAPACITY, 2, NULL, NULL);
    ca_producer_t producer;
    CHECK(ca_producer_register(queue, 31, &producer) == CA_OK);
    for (size_t i = 0; i < 128; ++i) {
        CHECK(ca_submit_one(queue, &producer, item_id(i)) == CA_OK);
        CHECK(drain_commit(queue, 1, NULL, 0) == 1);
    }
    CHECK(ca_bbq_test_record_blocks(queue) == 1);

    void *items[CAPACITY];
    for (size_t i = 0; i < CAPACITY; ++i) items[i] = item_id(i);
    size_t accepted = 0;
    CHECK(ca_submit_span(queue, &producer, items, CAPACITY, &accepted) == CA_OK && accepted == CAPACITY);
    CHECK(ca_bbq_test_record_blocks(queue) == 4);
    CHECK(drain_commit(queue, 19, NULL, 0) == CAPACITY);
    CHECK(ca_producer_release(&producer) == CA_OK);

    /* Singleton reuse stays in the retained slab instead of walking the
     * directory. A high-water burst grows four slabs; quiescence is the safe
     * epoch that frees excess empty slabs and keeps one hot reserve. */
    CHECK(ca_quiesce(queue, CA_QUIESCE_DRAIN, NULL) == CA_OK);
    CHECK(ca_bbq_test_record_blocks(queue) == 1);
    CHECK(ca_destroy(queue) == CA_OK);
}

static void test_retry_and_return(void) {
    ca_queue_t *queue = new_queue(4, 2, NULL, NULL);
    ca_producer_t producer;
    CHECK(ca_producer_register(queue, 1, &producer) == CA_OK);
    void *items[4] = {item_id(0), item_id(1), item_id(2), item_id(3)};
    size_t accepted = 0;
    CHECK(ca_submit_span(queue, &producer, items, 4, &accepted) == CA_OK && accepted == 4);
    ca_claim_item_t claimed[4];
    ca_claim_t claim;
    CHECK(ca_claim_up_to(queue, &claim, claimed, 4) == CA_OK && claim.count == 4);
    const ca_completion_state_t states[4] = {CA_COMPLETE_COMMIT, CA_COMPLETE_RETRY, CA_COMPLETE_DISCARD,
                                             CA_COMPLETE_RETRY};
    CHECK(ca_complete(&claim, states) == CA_OK);
    check_capacity(queue, 4, 2);
    CHECK(ca_claim_up_to(queue, &claim, claimed, 1) == CA_OK && claim.count == 1);
    CHECK(claimed[0].was_retry && id_of(claimed[0].item) == 1);
    CHECK(ca_return_claim(&claim) == CA_OK);
    const ca_completion_state_t one_commit = CA_COMPLETE_COMMIT;
    CHECK(ca_claim_up_to(queue, &claim, claimed, 1) == CA_OK && claim.count == 1);
    CHECK(claimed[0].was_retry && id_of(claimed[0].item) == 1);
    CHECK(ca_complete(&claim, &one_commit) == CA_OK);
    CHECK(ca_claim_up_to(queue, &claim, claimed, 1) == CA_OK && claim.count == 1);
    CHECK(claimed[0].was_retry && id_of(claimed[0].item) == 3);
    CHECK(ca_return_claim(&claim) == CA_OK);
    CHECK(ca_claim_up_to(queue, &claim, claimed, 1) == CA_OK && claim.count == 1);
    CHECK(claimed[0].was_retry && id_of(claimed[0].item) == 3);
    CHECK(ca_complete(&claim, &one_commit) == CA_OK);
    check_capacity(queue, 4, 4);

    /* Two claims complete in reverse order. The later terminal completion may
     * return its credit immediately, while retrying the earlier claim must
     * remain owned and runnable. */
    CHECK(ca_submit_span(queue, &producer, items, 2, &accepted) == CA_OK && accepted == 2);
    ca_claim_item_t first_item;
    ca_claim_item_t second_item;
    ca_claim_t first;
    ca_claim_t second;
    CHECK(ca_claim_up_to(queue, &first, &first_item, 1) == CA_OK);
    CHECK(ca_claim_up_to(queue, &second, &second_item, 1) == CA_OK);
    const ca_completion_state_t one_retry = CA_COMPLETE_RETRY;
    CHECK(ca_complete(&second, &one_commit) == CA_OK);
    CHECK(ca_complete(&first, &one_retry) == CA_OK);
    check_capacity(queue, 4, 3);
    CHECK(ca_claim_up_to(queue, &first, &first_item, 1) == CA_OK);
    CHECK(first_item.was_retry);
    CHECK(ca_complete(&first, &one_commit) == CA_OK);
    check_capacity(queue, 4, 4);
    CHECK(ca_producer_release(&producer) == CA_OK);
    finish_queue(queue);
}

static void test_partial_reuse_progress(void) {
    enum { CAPACITY = 64 };
    ca_queue_t *queue = new_queue(CAPACITY, 2, NULL, NULL);
    ca_producer_t producer;
    CHECK(ca_producer_register(queue, 31, &producer) == CA_OK);
    void *items[CAPACITY];
    for (size_t i = 0; i < CAPACITY; ++i) items[i] = item_id(i);
    size_t accepted = 0;
    CHECK(ca_submit_span(queue, &producer, items, CAPACITY, &accepted) == CA_OK);
    CHECK(accepted == CAPACITY);
    ca_claim_item_t item;
    ca_claim_t claim;
    CHECK(ca_claim_up_to(queue, &claim, &item, 1) == CA_OK);
    CHECK(id_of(item.item) == 0);
    const ca_completion_state_t commit = CA_COMPLETE_COMMIT;
    CHECK(ca_complete(&claim, &commit) == CA_OK);

    /* One terminal item frees one exact credit while 63 old positions remain.
     * The replacement must reuse the released cell without waiting for the
     * whole 64-cell block to drain, and producer order remains exact. */
    CHECK(ca_submit_one(queue, &producer, item_id(CAPACITY)) == CA_OK);
    drain_expect_order(queue, 1, CAPACITY, 17);
    check_capacity(queue, CAPACITY, CAPACITY);
    CHECK(ca_producer_release(&producer) == CA_OK);
    finish_queue(queue);
}

static void test_producer_retry_barrier(void) {
    ca_queue_t *queue = new_queue(4, 2, NULL, NULL);
    ca_producer_t first_producer;
    ca_producer_t second_producer;
    CHECK(ca_producer_register(queue, 41, &first_producer) == CA_OK);
    CHECK(ca_producer_register(queue, 42, &second_producer) == CA_OK);
    void *first_items[3] = {item_id(0), item_id(1), item_id(2)};
    size_t accepted = 0;
    CHECK(ca_submit_span(queue, &first_producer, first_items, 3, &accepted) == CA_OK && accepted == 3);
    CHECK(ca_submit_one(queue, &second_producer, item_id(3)) == CA_OK);

    ca_claim_item_t first_item;
    ca_claim_item_t later_item;
    ca_claim_t first;
    ca_claim_t later;
    CHECK(ca_claim_up_to(queue, &first, &first_item, 1) == CA_OK);
    CHECK(ca_claim_up_to(queue, &later, &later_item, 1) == CA_OK);
    CHECK(id_of(first_item.item) == 0 && id_of(later_item.item) == 1);
    const ca_completion_state_t retry = CA_COMPLETE_RETRY;
    const ca_completion_state_t commit = CA_COMPLETE_COMMIT;
    CHECK(ca_complete(&first, &retry) == CA_OK);
    CHECK(ca_complete(&later, &commit) == CA_OK);

    /* The already-claimed later item may finish, but the next unclaimed item
     * from that producer is parked behind the retry barrier. The independent
     * producer must remain claimable instead of being globally blocked. */
    CHECK(ca_claim_up_to(queue, &later, &later_item, 1) == CA_OK);
    CHECK(id_of(later_item.item) == 3 && !later_item.was_retry);
    CHECK(ca_complete(&later, &commit) == CA_OK);
    CHECK(ca_claim_up_to(queue, &first, &first_item, 1) == CA_OK);
    CHECK(id_of(first_item.item) == 0 && first_item.was_retry);
    CHECK(ca_claim_up_to(queue, &later, &later_item, 1) == CA_EMPTY);
    CHECK(ca_complete(&first, &commit) == CA_OK);
    CHECK(ca_claim_up_to(queue, &later, &later_item, 1) == CA_OK);
    CHECK(id_of(later_item.item) == 2 && !later_item.was_retry);
    CHECK(ca_complete(&later, &commit) == CA_OK);
    check_capacity(queue, 4, 4);

    CHECK(ca_producer_release(&second_producer) == CA_OK);
    CHECK(ca_producer_release(&first_producer) == CA_OK);
    finish_queue(queue);
}

static void test_stable_key_reregistration_barrier(void) {
    ca_queue_t *queue = new_queue(3, 2, NULL, NULL);
    ca_producer_t first_handle;
    CHECK(ca_producer_register(queue, 49, &first_handle) == CA_OK);
    void *initial[] = {item_id(0), item_id(1)};
    size_t accepted = 0;
    CHECK(ca_submit_span(queue, &first_handle, initial, 2, &accepted) == CA_OK && accepted == 2);
    ca_claim_t claim;
    ca_claim_item_t item;
    CHECK(ca_claim_up_to(queue, &claim, &item, 1) == CA_OK && id_of(item.item) == 0);
    const ca_completion_state_t retry = CA_COMPLETE_RETRY;
    CHECK(ca_complete(&claim, &retry) == CA_OK);
    CHECK(ca_producer_release(&first_handle) == CA_OK);

    ca_producer_t second_handle;
    CHECK(ca_producer_register(queue, 49, &second_handle) == CA_OK);
    CHECK(ca_submit_one(queue, &second_handle, item_id(2)) == CA_OK);

    /* Re-registering the same stable key must reuse the pending producer
     * identity. Its later records remain behind the retry barrier until item
     * zero becomes terminal; independent state creation would expose them. */
    CHECK(ca_claim_up_to(queue, &claim, &item, 1) == CA_OK);
    CHECK(item.was_retry && id_of(item.item) == 0);
    const ca_completion_state_t commit = CA_COMPLETE_COMMIT;
    CHECK(ca_complete(&claim, &commit) == CA_OK);
    unsigned char seen[3] = {1, 0, 0};
    CHECK(drain_commit(queue, 2, seen, 3) == 2);
    CHECK(seen[1] && seen[2]);
    CHECK(ca_producer_release(&second_handle) == CA_OK);
    check_capacity(queue, 3, 3);
    finish_queue(queue);
}

struct paused_publish_context {
    ca_queue_t *queue;
    ca_producer_t *producer;
    void *item;
    ca_status_t status;
};

static void *paused_publish_thread(void *argument) {
    struct paused_publish_context *context = argument;
    context->status = ca_submit_one(context->queue, context->producer, context->item);
    return NULL;
}

static void test_help_stalled_faa_publisher(void) {
    ca_queue_t *queue = new_queue(2, 2, NULL, NULL);
    ca_producer_t stalled_producer;
    ca_producer_t independent_producer;
    CHECK(ca_producer_register(queue, 51, &stalled_producer) == CA_OK);
    CHECK(ca_producer_register(queue, 52, &independent_producer) == CA_OK);
    ca_bbq_test_pause_after_faa(queue);
    struct paused_publish_context context = {
        .queue = queue,
        .producer = &stalled_producer,
        .item = item_id(0),
        .status = CA_INVALID,
    };
    pthread_t publisher;
    CHECK(pthread_create(&publisher, NULL, paused_publish_thread, &context) == 0);
    while (!ca_bbq_test_after_faa_entered(queue)) sched_yield();
    CHECK(ca_submit_one(queue, &independent_producer, item_id(1)) == CA_OK);

    /* The first FAA position has no visible record. Claim tombstones that
     * generation and reaches the independent publisher; the stalled producer
     * then observes the tombstone and retries its same owned record. */
    ca_claim_item_t item;
    ca_claim_t claim;
    CHECK(ca_claim_up_to(queue, &claim, &item, 1) == CA_OK);
    CHECK(id_of(item.item) == 1);
    const ca_completion_state_t commit = CA_COMPLETE_COMMIT;
    CHECK(ca_complete(&claim, &commit) == CA_OK);
    ca_bbq_test_release_after_faa(queue);
    CHECK(pthread_join(publisher, NULL) == 0);
    CHECK(context.status == CA_OK);
    CHECK(ca_claim_up_to(queue, &claim, &item, 1) == CA_OK);
    CHECK(id_of(item.item) == 0);
    CHECK(ca_complete(&claim, &commit) == CA_OK);
    check_capacity(queue, 2, 2);
    CHECK(ca_producer_release(&independent_producer) == CA_OK);
    CHECK(ca_producer_release(&stalled_producer) == CA_OK);
    finish_queue(queue);
}

static void test_help_installed_publisher_generation(void) {
    ca_queue_t *queue = new_queue(1, 1, NULL, NULL);
    ca_producer_t producer;
    ca_producer_t independent_producer;
    CHECK(ca_producer_register(queue, 53, &producer) == CA_OK);
    CHECK(ca_producer_register(queue, 54, &independent_producer) == CA_OK);
    ca_bbq_test_pause_after_install(queue);
    struct paused_publish_context context = {
        .queue = queue,
        .producer = &producer,
        .item = item_id(0),
        .status = CA_INVALID,
    };
    pthread_t publisher;
    CHECK(pthread_create(&publisher, NULL, paused_publish_thread, &context) == 0);
    while (!ca_bbq_test_after_install_entered(queue)) sched_yield();

    /* The generation-tagged FULL control word is installed while the producer
     * remains paused in publication. The consumer must claim that exact
     * generation once and leave no duplicate after the producer resumes. */
    ca_claim_item_t item;
    ca_claim_t claim;
    CHECK(ca_claim_up_to(queue, &claim, &item, 1) == CA_OK);
    CHECK(id_of(item.item) == 0);
    const ca_completion_state_t commit = CA_COMPLETE_COMMIT;
    CHECK(ca_complete(&claim, &commit) == CA_OK);
    CHECK(ca_submit_one(queue, &independent_producer, item_id(1)) == CA_OK);
    CHECK(ca_claim_up_to(queue, &claim, &item, 1) == CA_OK);
    CHECK(id_of(item.item) == 1);
    CHECK(ca_complete(&claim, &commit) == CA_OK);
    ca_bbq_test_release_after_install(queue);
    CHECK(pthread_join(publisher, NULL) == 0);
    CHECK(context.status == CA_OK);
    check_capacity(queue, 1, 1);
    CHECK(ca_producer_release(&independent_producer) == CA_OK);
    CHECK(ca_producer_release(&producer) == CA_OK);
    finish_queue(queue);
}

struct paused_claim_context {
    ca_queue_t *queue;
    ca_claim_t claim;
    ca_claim_item_t item;
    ca_status_t status;
};

struct completion_context {
    ca_claim_t *claim;
    ca_completion_state_t state;
    ca_status_t status;
};

static void *completion_thread(void *argument) {
    struct completion_context *context = argument;
    context->status = ca_complete(context->claim, &context->state);
    return NULL;
}

struct quiesce_context {
    ca_queue_t *queue;
    ca_quiesce_mode_t mode;
    ca_status_t status;
};

static void *quiesce_thread(void *argument) {
    struct quiesce_context *context = argument;
    context->status = ca_quiesce(context->queue, context->mode, NULL);
    return NULL;
}

static void *paused_claim_thread(void *argument) {
    struct paused_claim_context *context = argument;
    context->status = ca_claim_up_to(context->queue, &context->claim, &context->item, 1);
    return NULL;
}

static void test_help_stalled_claimed_generation(void) {
    ca_queue_t *queue = new_queue(2, 2, NULL, NULL);
    ca_producer_t producer;
    CHECK(ca_producer_register(queue, 55, &producer) == CA_OK);
    void *initial[] = {item_id(0), item_id(1)};
    size_t accepted = 0;
    CHECK(ca_submit_span(queue, &producer, initial, 2, &accepted) == CA_OK && accepted == 2);
    ca_bbq_test_pause_after_claim(queue);
    struct paused_claim_context paused = {.queue = queue, .status = CA_INVALID};
    pthread_t consumer;
    CHECK(pthread_create(&consumer, NULL, paused_claim_thread, &paused) == 0);
    while (!ca_bbq_test_after_claim_entered(queue)) sched_yield();

    /* The stopped consumer owns position zero through CLAIMED(gen,index), but
     * its logical claim is not yet returned. Completing position one frees one
     * credit; publishing position two must help the old CLAIMED generation to
     * EMPTY(next gen) and remain claimable on the same physical cell. */
    ca_claim_t claim;
    ca_claim_item_t item;
    CHECK(ca_claim_up_to(queue, &claim, &item, 1) == CA_OK);
    CHECK(id_of(item.item) == 1);
    const ca_completion_state_t commit = CA_COMPLETE_COMMIT;
    CHECK(ca_complete(&claim, &commit) == CA_OK);
    CHECK(ca_submit_one(queue, &producer, item_id(2)) == CA_OK);
    CHECK(ca_claim_up_to(queue, &claim, &item, 1) == CA_OK);
    CHECK(id_of(item.item) == 2);
    CHECK(ca_complete(&claim, &commit) == CA_OK);
    ca_bbq_test_release_after_claim(queue);
    CHECK(pthread_join(consumer, NULL) == 0);
    CHECK(paused.status == CA_OK && id_of(paused.item.item) == 0);
    CHECK(ca_complete(&paused.claim, &commit) == CA_OK);
    check_capacity(queue, 2, 2);
    CHECK(ca_producer_release(&producer) == CA_OK);
    finish_queue(queue);
}

static void test_completion_releases_metadata_before_capacity(void) {
    enum { CAPACITY = 128 };
    _Atomic size_t disposed = 0;
    ca_queue_t *queue = new_queue(CAPACITY, 2, count_dispose, &disposed);
    ca_producer_t producer;
    CHECK(ca_producer_register(queue, 57, &producer) == CA_OK);
    void *items[CAPACITY];
    for (size_t i = 0; i < CAPACITY; ++i) items[i] = item_id(i);
    size_t accepted = 0;
    CHECK(ca_submit_span(queue, &producer, items, CAPACITY, &accepted) == CA_OK && accepted == CAPACITY);
    for (size_t i = 0; i < CAPACITY - 1; ++i) {
        ca_claim_t claim;
        ca_claim_item_t item;
        CHECK(ca_claim_up_to(queue, &claim, &item, 1) == CA_OK);
        const ca_completion_state_t commit = CA_COMPLETE_COMMIT;
        CHECK(ca_complete(&claim, &commit) == CA_OK);
    }
    ca_claim_t final_claim;
    ca_claim_item_t final_item;
    CHECK(ca_claim_up_to(queue, &final_claim, &final_item, 1) == CA_OK);
    CHECK(ca_bbq_test_record_blocks(queue) == 2);
    ca_bbq_test_pause_after_record_release(queue);

    struct quiesce_context quiesce = {.queue = queue, .mode = CA_QUIESCE_DRAIN, .status = CA_INVALID};
    pthread_t quiescer;
    CHECK(pthread_create(&quiescer, NULL, quiesce_thread, &quiesce) == 0);
    while (ca_bbq_test_capacity_sleepers(queue) != 1) sched_yield();
    struct completion_context completion = {
        .claim = &final_claim,
        .state = CA_COMPLETE_COMMIT,
        .status = CA_INVALID,
    };
    pthread_t completer;
    CHECK(pthread_create(&completer, NULL, completion_thread, &completion) == 0);
    while (!ca_bbq_test_after_record_release_entered(queue)) sched_yield();

    /* The dispose callback and record bitmap release are complete while the
     * capacity credit remains hidden. DRAIN therefore cannot observe a fully
     * available queue and trim the second slab until the completer publishes
     * that credit; joining both threads is the trim-race oracle. */
    CHECK(atomic_load_explicit(&disposed, memory_order_relaxed) == CAPACITY);
    check_capacity(queue, CAPACITY, CAPACITY - 1);
    CHECK(ca_bbq_test_record_blocks(queue) == 2);
    ca_bbq_test_release_after_record_release(queue);
    CHECK(pthread_join(completer, NULL) == 0);
    CHECK(completion.status == CA_OK);
    CHECK(pthread_join(quiescer, NULL) == 0);
    CHECK(quiesce.status == CA_OK);
    CHECK(ca_bbq_test_record_blocks(queue) == 1);
    CHECK(ca_producer_release(&producer) == CA_OK);
    CHECK(ca_destroy(queue) == CA_OK);
}

static void test_producer_release_during_discard(void) {
    _Atomic size_t disposed = 0;
    ca_queue_t *queue = new_queue(1, 1, count_dispose, &disposed);
    ca_producer_t producer;
    CHECK(ca_producer_register(queue, 59, &producer) == CA_OK);
    CHECK(ca_submit_one(queue, &producer, item_id(0)) == CA_OK);
    ca_bbq_test_pause_after_discard_producer(queue);
    struct quiesce_context quiesce = {.queue = queue, .mode = CA_QUIESCE_DISCARD, .status = CA_INVALID};
    pthread_t quiescer;
    CHECK(pthread_create(&quiescer, NULL, quiesce_thread, &quiesce) == 0);
    while (!ca_bbq_test_after_discard_producer_entered(queue)) sched_yield();

    /* DISCARD has detached and disposed the producer's final record, then is
     * paused before following producer->next. Releasing its last handle must
     * defer registry reclamation until destroy; otherwise this exact iterator
     * dereference is a use-after-free. */
    CHECK(atomic_load_explicit(&disposed, memory_order_relaxed) == 1);
    CHECK(ca_producer_release(&producer) == CA_OK);
    ca_bbq_test_release_after_discard_producer(queue);
    CHECK(pthread_join(quiescer, NULL) == 0);
    CHECK(quiesce.status == CA_OK);
    CHECK(ca_destroy(queue) == CA_OK);
}

static void test_quiesce_timeout_rollback(void) {
    ca_queue_t *queue = new_queue(1, 1, NULL, NULL);
    ca_producer_t producer;
    CHECK(ca_producer_register(queue, 1, &producer) == CA_OK);
    CHECK(ca_submit_one(queue, &producer, item_id(0)) == CA_OK);
    ca_claim_item_t item;
    ca_claim_t claim;
    CHECK(ca_claim_up_to(queue, &claim, &item, 1) == CA_OK);
    struct timespec expired;
    clock_gettime(CLOCK_MONOTONIC, &expired);
    CHECK(ca_quiesce(queue, CA_QUIESCE_DRAIN, &expired) == CA_TIMED_OUT);
    ca_capacity_snapshot_t snapshot;
    ca_capacity_read(queue, &snapshot);
    CHECK(snapshot.accepting && snapshot.claiming);
    const ca_completion_state_t commit = CA_COMPLETE_COMMIT;
    CHECK(ca_complete(&claim, &commit) == CA_OK);
    CHECK(ca_submit_one(queue, &producer, item_id(1)) == CA_OK);
    CHECK(drain_commit(queue, 1, NULL, 0) == 1);
    CHECK(ca_producer_release(&producer) == CA_OK);
    finish_queue(queue);
}

static void test_retry_from_closed_block(void) {
    ca_queue_t *queue = new_queue(65, 1, NULL, NULL);
    ca_producer_t producer;
    CHECK(ca_producer_register(queue, 1, &producer) == CA_OK);
    void *items[65];
    for (size_t i = 0; i < 65; ++i) items[i] = item_id(i);
    size_t accepted = 0;
    CHECK(ca_submit_span(queue, &producer, items, 65, &accepted) == CA_OK && accepted == 65);
    ca_claim_item_t item;
    ca_claim_t claim;
    CHECK(ca_claim_up_to(queue, &claim, &item, 1) == CA_OK);
    CHECK(id_of(item.item) == 0);
    const ca_completion_state_t retry = CA_COMPLETE_RETRY;
    CHECK(ca_complete(&claim, &retry) == CA_OK);
    CHECK(ca_claim_up_to(queue, &claim, &item, 1) == CA_OK);
    CHECK(item.was_retry && id_of(item.item) == 0);
    const ca_completion_state_t commit = CA_COMPLETE_COMMIT;
    CHECK(ca_complete(&claim, &commit) == CA_OK);
    drain_expect_order(queue, 1, 64, 7);
    CHECK(ca_producer_release(&producer) == CA_OK);
    finish_queue(queue);
}

static void test_retry_after_origin_reuse(void) {
    enum { CAPACITY = 128, BLOCK_ITEMS = 64 };
    ca_queue_t *queue = new_queue(CAPACITY, 2, NULL, NULL);
    ca_producer_t producer;
    CHECK(ca_producer_register(queue, 43, &producer) == CA_OK);
    void *initial[CAPACITY];
    void *replacement[BLOCK_ITEMS];
    for (size_t i = 0; i < CAPACITY; ++i) initial[i] = item_id(i);
    for (size_t i = 0; i < BLOCK_ITEMS; ++i) replacement[i] = item_id(CAPACITY + i);
    size_t accepted = 0;
    CHECK(ca_submit_span(queue, &producer, initial, CAPACITY, &accepted) == CA_OK);
    CHECK(accepted == CAPACITY);

    ca_claim_item_t held_items[BLOCK_ITEMS];
    ca_claim_item_t completed_items[BLOCK_ITEMS];
    ca_claim_t held;
    ca_claim_t completed;
    CHECK(ca_claim_up_to(queue, &held, held_items, BLOCK_ITEMS) == CA_OK);
    CHECK(held.count == BLOCK_ITEMS);
    CHECK(ca_claim_up_to(queue, &completed, completed_items, BLOCK_ITEMS) == CA_OK);
    CHECK(completed.count == BLOCK_ITEMS);
    ca_completion_state_t states[BLOCK_ITEMS];
    for (size_t i = 0; i < BLOCK_ITEMS; ++i) states[i] = CA_COMPLETE_COMMIT;
    CHECK(ca_complete(&completed, states) == CA_OK);

    /* Completing the second range frees enough credit to reuse the first 64
     * cells in their next generation while the detached first claim is held.
     * Retrying the held records must publish into later generations without
     * depending on their old cells. Retry order and exact ownership are the
     * oracles. */
    accepted = 0;
    CHECK(ca_submit_span(queue, &producer, replacement, BLOCK_ITEMS, &accepted) == CA_OK);
    CHECK(accepted == BLOCK_ITEMS);
    for (size_t i = 0; i < BLOCK_ITEMS; ++i) states[i] = CA_COMPLETE_RETRY;
    CHECK(ca_complete(&held, states) == CA_OK);
    drain_expect_order(queue, 0, BLOCK_ITEMS, 17);
    drain_expect_order(queue, CAPACITY, BLOCK_ITEMS, 17);
    check_capacity(queue, CAPACITY, CAPACITY);

    CHECK(ca_producer_release(&producer) == CA_OK);
    finish_queue(queue);
}

struct wait_context {
    ca_queue_t *queue;
    uint32_t observed;
    ca_status_t status;
    int capacity;
};

static void *wait_thread(void *argument) {
    struct wait_context *context = argument;
    struct timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += 5;
    context->status = context->capacity ? ca_wait_capacity_epoch(context->queue, context->observed, &deadline)
                                        : ca_wait_epoch(context->queue, context->observed, &deadline);
    return NULL;
}

#ifdef CA_FORCE_PTHREAD_WAIT
static void *cancel_wait_thread(void *argument) {
    struct wait_context *context = argument;
    context->status = ca_wait_epoch(context->queue, context->observed, NULL);
    return NULL;
}
#endif

static void test_wait_adapters_and_classes(void) {
#ifdef CA_FORCE_PTHREAD_WAIT
    CHECK(!ca_bbq_test_uses_futex());
#else
    CHECK(ca_bbq_test_uses_futex());
#endif
    ca_queue_t *queue = new_queue(1, 2, NULL, NULL);
    ca_producer_t producer;
    CHECK(ca_producer_register(queue, 61, &producer) == CA_OK);
    ca_reservation_t reservation;
    CHECK(ca_reserve(queue, &producer, 1, &reservation) == CA_OK);
    struct wait_context work = {.queue = queue, .observed = ca_epoch(queue), .status = CA_INVALID};
    struct wait_context capacity = {
        .queue = queue,
        .observed = ca_capacity_epoch(queue),
        .status = CA_INVALID,
        .capacity = 1,
    };
    pthread_t work_thread;
    pthread_t capacity_thread;
    CHECK(pthread_create(&work_thread, NULL, wait_thread, &work) == 0);
    CHECK(pthread_create(&capacity_thread, NULL, wait_thread, &capacity) == 0);
    while (ca_bbq_test_work_sleepers(queue) != 1 || ca_bbq_test_capacity_sleepers(queue) != 1) sched_yield();
    void *item = item_id(0);
    CHECK(ca_publish_reserved(&reservation, &item) == CA_OK);
    CHECK(pthread_join(work_thread, NULL) == 0);
    CHECK(work.status == CA_OK);
    CHECK(ca_bbq_test_capacity_sleepers(queue) == 1);
    ca_claim_item_t claimed;
    ca_claim_t claim;
    CHECK(ca_claim_up_to(queue, &claim, &claimed, 1) == CA_OK);
    const ca_completion_state_t commit = CA_COMPLETE_COMMIT;
    CHECK(ca_complete(&claim, &commit) == CA_OK);
    CHECK(pthread_join(capacity_thread, NULL) == 0);
    CHECK(capacity.status == CA_OK);

#ifdef CA_FORCE_PTHREAD_WAIT
    /* Forced pthread waits are cancellation points. Cleanup must unregister
     * the exact sleeper class and unlock the adapter for a later waiter. */
    struct wait_context cancelled = {.queue = queue, .observed = ca_epoch(queue), .status = CA_INVALID};
    pthread_t cancelled_thread;
    CHECK(pthread_create(&cancelled_thread, NULL, cancel_wait_thread, &cancelled) == 0);
    while (ca_bbq_test_work_sleepers(queue) != 1) sched_yield();
    CHECK(pthread_cancel(cancelled_thread) == 0);
    CHECK(pthread_join(cancelled_thread, NULL) == 0);
    CHECK(ca_bbq_test_work_sleepers(queue) == 0);
#endif
    CHECK(ca_producer_release(&producer) == CA_OK);
    finish_queue(queue);
}

static void test_quiesce_wakes_registered_waiters(void) {
    ca_queue_t *queue = new_queue(1, 2, NULL, NULL);
    struct wait_context work = {.queue = queue, .observed = ca_epoch(queue), .status = CA_INVALID};
    struct wait_context capacity = {
        .queue = queue,
        .observed = ca_capacity_epoch(queue),
        .status = CA_INVALID,
        .capacity = 1,
    };
    pthread_t work_thread;
    pthread_t capacity_thread;
    CHECK(pthread_create(&work_thread, NULL, wait_thread, &work) == 0);
    CHECK(pthread_create(&capacity_thread, NULL, wait_thread, &capacity) == 0);
    while (ca_bbq_test_work_sleepers(queue) != 1 || ca_bbq_test_capacity_sleepers(queue) != 1) sched_yield();

    /* Both wait classes are registered and sleeping before quiesce starts.
     * Quiesce must close waiting and increment both predicates without waiting
     * for their lifecycle admission; joining both sleepers is the deadlock and
     * lost-wake oracle. */
    CHECK(ca_quiesce(queue, CA_QUIESCE_DRAIN, NULL) == CA_OK);
    CHECK(pthread_join(work_thread, NULL) == 0);
    CHECK(pthread_join(capacity_thread, NULL) == 0);
    CHECK(work.status == CA_OK && capacity.status == CA_OK);
    CHECK(ca_destroy(queue) == CA_OK);
}

static void test_wait_lifecycle_and_discard(void) {
    _Atomic size_t disposed = 0;
    ca_queue_t *queue = new_queue(8, 2, count_dispose, &disposed);
    ca_lifecycle_binding_t first;
    ca_lifecycle_binding_t second;
    ca_lifecycle_scope_t outer;
    ca_lifecycle_scope_t inner;
    CHECK(ca_lifecycle_bind(queue, &first) == CA_OK);
    CHECK(ca_lifecycle_bind(queue, &second) == CA_OK);
    CHECK(ca_lifecycle_activate(&first, &outer) == CA_OK);
    CHECK(ca_lifecycle_activate(&second, &inner) == CA_OK);
    CHECK(ca_lifecycle_deactivate(&inner) == CA_OK);
    CHECK(ca_lifecycle_deactivate(&outer) == CA_OK);
    CHECK(ca_destroy(queue) == CA_BUSY);

    struct wait_context context = {.queue = queue, .observed = ca_epoch(queue), .status = CA_INVALID};
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, wait_thread, &context) == 0);
    ca_producer_t producer;
    CHECK(ca_producer_register(queue, 7, &producer) == CA_OK);
    CHECK(ca_submit_one(queue, &producer, item_id(0)) == CA_OK);
    CHECK(pthread_join(thread, NULL) == 0);
    CHECK(context.status == CA_OK);
    CHECK(ca_producer_release(&producer) == CA_OK);
    CHECK(ca_lifecycle_unbind(&second) == CA_OK);
    CHECK(ca_lifecycle_unbind(&first) == CA_OK);
    CHECK(ca_quiesce(queue, CA_QUIESCE_DISCARD, NULL) == CA_OK);
    CHECK(atomic_load_explicit(&disposed, memory_order_relaxed) == 1);
    CHECK(ca_destroy(queue) == CA_OK);
}

struct stress_context {
    ca_queue_t *queue;
    size_t producer;
    size_t per_producer;
    _Atomic unsigned char *seen;
    _Atomic size_t *consumed;
};

static void *producer_thread(void *argument) {
    struct stress_context *context = argument;
    ca_producer_t producer;
    CHECK(ca_producer_register(context->queue, context->producer + 1, &producer) == CA_OK);
    for (size_t i = 0; i < context->per_producer; ++i) {
        const size_t id = context->producer * context->per_producer + i;
        while (ca_submit_one(context->queue, &producer, item_id(id)) == CA_FULL) sched_yield();
    }
    CHECK(ca_producer_release(&producer) == CA_OK);
    return NULL;
}

static void *consumer_thread(void *argument) {
    struct stress_context *context = argument;
    ca_claim_item_t items[31];
    ca_completion_state_t states[31];
    const size_t total = context->per_producer * 8;
    while (atomic_load_explicit(context->consumed, memory_order_acquire) < total) {
        ca_claim_t claim;
        const ca_status_t status = ca_claim_up_to(context->queue, &claim, items, 31);
        if (status == CA_EMPTY) {
            sched_yield();
            continue;
        }
        CHECK(status == CA_OK);
        for (size_t i = 0; i < claim.count; ++i) {
            const size_t id = id_of(items[i].item);
            CHECK(id < total);
            CHECK(atomic_exchange_explicit(&context->seen[id], 1, memory_order_acq_rel) == 0);
            states[i] = CA_COMPLETE_COMMIT;
        }
        const size_t claimed = claim.count;
        CHECK(ca_complete(&claim, states) == CA_OK);
        atomic_fetch_add_explicit(context->consumed, claimed, memory_order_release);
    }
    return NULL;
}

static void test_concurrent_exact_ownership(void) {
    enum { PRODUCERS = 8, CONSUMERS = 8, PER_PRODUCER = 1000 };
    ca_queue_t *queue = new_queue(257, CONSUMERS, NULL, NULL);
    _Atomic unsigned char *seen = calloc(PRODUCERS * PER_PRODUCER, sizeof(*seen));
    CHECK(seen != NULL);
    _Atomic size_t consumed = 0;
    pthread_t producers[PRODUCERS];
    pthread_t consumers[CONSUMERS];
    struct stress_context contexts[PRODUCERS];
    for (size_t i = 0; i < PRODUCERS; ++i) {
        contexts[i] = (struct stress_context){
            .queue = queue,
            .producer = i,
            .per_producer = PER_PRODUCER,
            .seen = seen,
            .consumed = &consumed,
        };
    }
    for (size_t i = 0; i < CONSUMERS; ++i)
        CHECK(pthread_create(&consumers[i], NULL, consumer_thread, &contexts[0]) == 0);
    for (size_t i = 0; i < PRODUCERS; ++i)
        CHECK(pthread_create(&producers[i], NULL, producer_thread, &contexts[i]) == 0);
    for (size_t i = 0; i < PRODUCERS; ++i) CHECK(pthread_join(producers[i], NULL) == 0);
    for (size_t i = 0; i < CONSUMERS; ++i) CHECK(pthread_join(consumers[i], NULL) == 0);
    CHECK(atomic_load_explicit(&consumed, memory_order_acquire) == PRODUCERS * PER_PRODUCER);
    for (size_t i = 0; i < PRODUCERS * PER_PRODUCER; ++i)
        CHECK(atomic_load_explicit(&seen[i], memory_order_relaxed) == 1);
    check_capacity(queue, 257, 257);
    finish_queue(queue);
    free(seen);
}

int main(void) {
    alarm(120);
    test_capacity_boundaries();
    test_large_span_and_wrap();
    test_control_word_wrap_integrity();
    test_reservation_credit_and_builder();
    test_record_pool_locality_and_trim();
    test_retry_and_return();
    test_partial_reuse_progress();
    test_producer_retry_barrier();
    test_stable_key_reregistration_barrier();
    test_help_stalled_faa_publisher();
    test_help_installed_publisher_generation();
    test_help_stalled_claimed_generation();
    test_completion_releases_metadata_before_capacity();
    test_producer_release_during_discard();
    test_quiesce_timeout_rollback();
    test_retry_from_closed_block();
    test_retry_after_origin_reuse();
    test_wait_adapters_and_classes();
    test_quiesce_wakes_registered_waiters();
    test_wait_lifecycle_and_discard();
    test_concurrent_exact_ownership();
    puts("ConcurrentArray BBQ focused tests passed");
    return 0;
}
