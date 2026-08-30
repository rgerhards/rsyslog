/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Intent: validate the private ConcurrentArray contract and the first
 * sparseLanes store without involving the rsyslog execution engine.
 *
 * Oracles are exact: every accepted integer identity is claimed once before
 * final completion, capacity returns to its configured value, retries precede
 * later work from their lane, and all producer/consumer stress identities are
 * observed exactly once.  The epoch-wait case uses a five-second absolute
 * deadline only as hang protection; publication must change the predicate and
 * wake the waiter, so elapsed timing is not a success condition.
 */

#include "concurrent_array.h"

#include <pthread.h>
#include <sched.h>
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

static ca_queue_t *new_queue(size_t capacity, unsigned consumers) {
    ca_queue_t *queue = NULL;
    const ca_config_t config = {
        .core = CA_CORE_SPARSE_LANES,
        .capacity = capacity,
        .consumers = consumers,
    };
    CHECK(ca_create(&config, &queue) == CA_OK);
    CHECK(queue != NULL);
    return queue;
}

static void finish_queue(ca_queue_t *queue) {
    CHECK(ca_quiesce(queue, CA_QUIESCE_DRAIN, NULL) == CA_OK);
    CHECK(ca_destroy(queue) == CA_OK);
}

static size_t drain_commit(ca_queue_t *queue, size_t ceiling) {
    ca_claim_item_t *items = calloc(ceiling, sizeof(*items));
    ca_completion_state_t *states = calloc(ceiling, sizeof(*states));
    CHECK(items != NULL && states != NULL);
    size_t total = 0;
    for (;;) {
        ca_claim_t claim;
        const ca_status_t status = ca_claim_up_to(queue, &claim, items, ceiling);
        if (status == CA_EMPTY) break;
        CHECK(status == CA_OK);
        for (size_t i = 0; i < claim.count; ++i) states[i] = CA_COMPLETE_COMMIT;
        total += claim.count;
        CHECK(ca_complete(&claim, states) == CA_OK);
    }
    free(states);
    free(items);
    return total;
}

static void drain_expect(ca_queue_t *queue, void *const *expected, size_t count, size_t ceiling) {
    ca_claim_item_t *items = calloc(ceiling, sizeof(*items));
    ca_completion_state_t *states = calloc(ceiling, sizeof(*states));
    CHECK(items != NULL && states != NULL);
    size_t offset = 0;
    while (offset < count) {
        ca_claim_t claim;
        CHECK(ca_claim_up_to(queue, &claim, items, ceiling) == CA_OK);
        CHECK(claim.count <= count - offset);
        for (size_t i = 0; i < claim.count; ++i) {
            CHECK(items[i].item == expected[offset + i]);
            states[i] = CA_COMPLETE_COMMIT;
        }
        offset += claim.count;
        CHECK(ca_complete(&claim, states) == CA_OK);
    }
    ca_claim_t empty;
    CHECK(ca_claim_up_to(queue, &empty, items, ceiling) == CA_EMPTY);
    free(states);
    free(items);
}

static void check_capacity(ca_queue_t *queue, size_t capacity, size_t available, size_t speculative) {
    ca_capacity_snapshot_t snapshot;
    ca_capacity_read(queue, &snapshot);
    CHECK(snapshot.capacity == capacity);
    CHECK(snapshot.available == available);
    CHECK(snapshot.speculative_unused == speculative);
    CHECK(snapshot.available + snapshot.speculative_unused + snapshot.in_flight <= snapshot.capacity);
}

static void test_shape(void) {
    ca_queue_t *queue = new_queue(1, 1);
    CHECK(ca_dedicated_lane_limit(queue) == 16);
    CHECK(ca_fallback_lane_count(queue) == 2);
    CHECK(ca_ready_ring_capacity(queue) >= 19);
    CHECK((ca_ready_ring_capacity(queue) & (ca_ready_ring_capacity(queue) - 1)) == 0);
    CHECK(ca_test_lifecycle_alignment(queue) == 64);
    CHECK(ca_test_lifecycle_is_aligned(queue));
    CHECK(ca_test_lifecycle_bytes(queue) == 64 * 64);
    finish_queue(queue);

    queue = new_queue(1000, 16);
    CHECK(ca_dedicated_lane_limit(queue) == 64);
    CHECK(ca_fallback_lane_count(queue) == 32);
    CHECK(ca_ready_ring_capacity(queue) >= 112);
    CHECK(ca_test_lifecycle_bytes(queue) == 64 * 64);
    finish_queue(queue);
}

static void test_capacity_and_batch_boundaries(void) {
    static const size_t capacities[] = {1, 2, 3, 7, 64, 65, 1000};
    static const size_t batches[] = {1, 2, 7, 64, 65, 128, 1000, 4096, 8192, 65536};
    void **messages = calloc(65536, sizeof(*messages));
    CHECK(messages != NULL);
    for (size_t i = 0; i < 65536; ++i) messages[i] = item_id(i);

    for (size_t c = 0; c < sizeof(capacities) / sizeof(capacities[0]); ++c) {
        ca_queue_t *queue = new_queue(capacities[c], 1);
        ca_producer_t producer;
        CHECK(ca_producer_register(queue, 1, &producer) == CA_OK);
        for (size_t b = 0; b < sizeof(batches) / sizeof(batches[0]); ++b) {
            size_t offset = 0;
            while (offset < batches[b]) {
                size_t accepted;
                const ca_status_t status =
                    ca_submit_span(queue, &producer, &messages[offset], batches[b] - offset, &accepted);
                CHECK(status == CA_OK || status == CA_PARTIAL);
                CHECK(accepted > 0 && accepted <= capacities[c]);
                offset += accepted;
                check_capacity(queue, capacities[c], capacities[c] - accepted, 0);
                const size_t filler = capacities[c] - accepted;
                if (filler != 0) {
                    size_t filler_accepted = 0;
                    CHECK(ca_submit_span(queue, &producer, messages, filler, &filler_accepted) == CA_OK);
                    CHECK(filler_accepted == filler);
                }
                size_t full_accepted = 99;
                CHECK(ca_submit_span(queue, &producer, messages, 1, &full_accepted) == CA_FULL);
                CHECK(full_accepted == 0);
                CHECK(drain_commit(queue, 257) == capacities[c]);
                check_capacity(queue, capacities[c], capacities[c], 0);
            }
        }
        ca_producer_release(&producer);
        finish_queue(queue);
    }
    free(messages);
}

/* Intent: prove lease exhaustion is independent of publication and the
 * builder emits one logical range at every requested large boundary.  The
 * oracle is a single coalesced claim with exactly the built size and ordered
 * identities; incremental 64-credit admission must never force an early
 * publication. */
static void test_large_builder_publications(void) {
    static const size_t sizes[] = {4096, 8192, 65536};
    for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); ++s) {
        const size_t count = sizes[s];
        ca_queue_t *queue = new_queue(count, 1);
        ca_producer_t producer;
        CHECK(ca_producer_register(queue, 100 + s, &producer) == CA_OK);
        ca_builder_t builder;
        CHECK(ca_builder_begin(queue, &producer, &builder) == CA_OK);
        void **messages = calloc(count, sizeof(*messages));
        ca_claim_item_t *claimed = calloc(count, sizeof(*claimed));
        ca_completion_state_t *states = calloc(count, sizeof(*states));
        CHECK(messages != NULL && claimed != NULL && states != NULL);
        for (size_t i = 0; i < count; ++i) messages[i] = item_id(i);
        for (size_t offset = 0; offset < count;) {
            ca_credit_lease_t lease;
            CHECK(ca_credit_acquire(queue, &producer, 64, &lease) == CA_OK);
            size_t accepted = 0;
            CHECK(ca_builder_append(&builder, &lease, &messages[offset], 64, &accepted) == CA_OK);
            CHECK(accepted == 64 && lease.unused == 0);
            ca_credit_release(&lease);
            offset += accepted;
        }
        CHECK(ca_builder_publish(&builder) == CA_OK);
        ca_claim_t claim;
        CHECK(ca_claim_up_to(queue, &claim, claimed, count) == CA_OK);
        CHECK(claim.count == count);
        for (size_t i = 0; i < count; ++i) {
            CHECK(id_of(claimed[i].item) == i);
            states[i] = CA_COMPLETE_COMMIT;
        }
        CHECK(ca_complete(&claim, states) == CA_OK);
        check_capacity(queue, count, count, 0);
        CHECK(ca_producer_release(&producer) == CA_OK);
        finish_queue(queue);
        free(states);
        free(claimed);
        free(messages);
    }
}

/* Intent: the builder's N=1 fast path stores its item inline.  The test-only
 * heap-allocation counter stays zero for the first routed singleton, rises
 * only when a 65-item burst outgrows the inline slot, and stays unchanged for
 * a later independent singleton. Exact drain order is the ownership oracle. */
static void test_builder_inline_singleton(void) {
    ca_queue_t *queue = new_queue(65, 1);
    ca_producer_t producer;
    CHECK(ca_producer_register(queue, 698, &producer) == CA_OK);

    ca_builder_t singleton;
    ca_credit_lease_t singleton_lease;
    size_t accepted = 0;
    void *single[] = {item_id(700)};
    CHECK(ca_builder_begin(queue, &producer, &singleton) == CA_OK);
    CHECK(ca_credit_acquire(queue, &producer, 1, &singleton_lease) == CA_OK);
    CHECK(ca_builder_append(&singleton, &singleton_lease, single, 1, &accepted) == CA_OK && accepted == 1);
    ca_credit_release(&singleton_lease);
    CHECK(ca_test_builder_item_allocations(queue) == 0);
    CHECK(ca_builder_publish(&singleton) == CA_OK);
    drain_expect(queue, single, 1, 1);

    void *burst[65];
    for (size_t i = 0; i < 65; ++i) burst[i] = item_id(i);
    ca_builder_t builder;
    CHECK(ca_builder_begin(queue, &producer, &builder) == CA_OK);
    for (size_t offset = 0; offset < 65;) {
        const size_t wanted = 65 - offset < 64 ? 65 - offset : 64;
        ca_credit_lease_t lease;
        const ca_status_t credit_status = ca_credit_acquire(queue, &producer, wanted, &lease);
        CHECK(credit_status == CA_OK || credit_status == CA_PARTIAL);
        const size_t granted = lease.unused;
        CHECK(ca_builder_append(&builder, &lease, &burst[offset], granted, &accepted) == CA_OK && accepted == granted);
        ca_credit_release(&lease);
        offset += granted;
    }
    const size_t burst_allocations = ca_test_builder_item_allocations(queue);
    CHECK(burst_allocations != 0);
    CHECK(ca_builder_publish(&builder) == CA_OK);
    drain_expect(queue, burst, 65, 65);

    CHECK(ca_builder_begin(queue, &producer, &singleton) == CA_OK);
    CHECK(ca_credit_acquire(queue, &producer, 1, &singleton_lease) == CA_OK);
    CHECK(ca_builder_append(&singleton, &singleton_lease, single, 1, &accepted) == CA_OK && accepted == 1);
    ca_credit_release(&singleton_lease);
    CHECK(ca_builder_publish(&singleton) == CA_OK);
    CHECK(ca_test_builder_item_allocations(queue) == burst_allocations);
    drain_expect(queue, single, 1, 1);
    CHECK(ca_producer_release(&producer) == CA_OK);
    finish_queue(queue);
}

/* Intent: preparation must not capture a lane-tail alignment.  Two prepared
 * reservations on one handle are committed in reverse order at each inline
 * and 64-slot boundary.  Exact prefix/second/first order proves commit-time
 * linearization and that the worst-aligned prepared chunk budget never
 * reaches the core's missing-chunk invariant. */
static void test_overlapping_prepared_alignment(void) {
    static const size_t starts[] = {0, 1, 63, 64};
    static const size_t counts[] = {1, 64, 65};
    for (size_t s = 0; s < sizeof(starts) / sizeof(starts[0]); ++s) {
        for (size_t c = 0; c < sizeof(counts) / sizeof(counts[0]); ++c) {
            const size_t start = starts[s];
            const size_t count = counts[c];
            ca_queue_t *queue = new_queue(start + 2 * count, 1);
            ca_producer_t producer;
            CHECK(ca_producer_register(queue, 700 + s * 10 + c, &producer) == CA_OK);
            void **prefix = calloc(start == 0 ? 1 : start, sizeof(*prefix));
            void **first = calloc(count, sizeof(*first));
            void **second = calloc(count, sizeof(*second));
            void **expected = calloc(start + 2 * count, sizeof(*expected));
            CHECK(prefix != NULL && first != NULL && second != NULL && expected != NULL);
            for (size_t i = 0; i < start; ++i) prefix[i] = expected[i] = item_id(i);
            for (size_t i = 0; i < count; ++i) {
                first[i] = item_id(1000 + i);
                second[i] = item_id(2000 + i);
                expected[start + i] = second[i];
                expected[start + count + i] = first[i];
            }
            size_t accepted = 0;
            if (start != 0)
                CHECK(ca_submit_span(queue, &producer, prefix, start, &accepted) == CA_OK && accepted == start);
            ca_reservation_t first_reservation;
            ca_reservation_t second_reservation;
            CHECK(ca_reserve(queue, &producer, count, &first_reservation) == CA_OK);
            CHECK(ca_reserve(queue, &producer, count, &second_reservation) == CA_OK);
            CHECK(ca_prepare_reserved(&first_reservation) == CA_OK);
            CHECK(ca_prepare_reserved(&second_reservation) == CA_OK);
            CHECK(ca_commit_prepared(&second_reservation, second) == CA_OK);
            CHECK(ca_commit_prepared(&first_reservation, first) == CA_OK);
            drain_expect(queue, expected, start + 2 * count, start + 2 * count);
            check_capacity(queue, start + 2 * count, start + 2 * count, 0);
            CHECK(ca_producer_release(&producer) == CA_OK);
            finish_queue(queue);
            free(expected);
            free(second);
            free(first);
            free(prefix);
        }
    }
}

struct overlapping_prepare_context {
    ca_queue_t *queue;
    ca_producer_t *producer;
    void **items;
    size_t count;
    _Atomic unsigned *prepared_count;
    _Atomic int *release;
    ca_status_t status;
};

static void *overlapping_prepare_thread(void *argument) {
    struct overlapping_prepare_context *const context = argument;
    ca_reservation_t reservation;
    context->status = ca_reserve(context->queue, context->producer, context->count, &reservation);
    if (context->status == CA_OK) context->status = ca_prepare_reserved(&reservation);
    atomic_fetch_add_explicit(context->prepared_count, 1, memory_order_release);
    while (!atomic_load_explicit(context->release, memory_order_acquire)) sched_yield();
    if (context->status == CA_OK) context->status = ca_commit_prepared(&reservation, context->items);
    return NULL;
}

/* Intent: two threads can pause after preparing on the same producer handle.
 * Both commits must succeed without assertion; two contiguous, non-interleaved
 * 65-item ranges and exact identity multiplicity are the concurrency oracle. */
static void test_concurrent_same_handle_prepare(void) {
    enum { count = 65 };
    ca_queue_t *queue = new_queue(2 * count, 1);
    ca_producer_t producer;
    CHECK(ca_producer_register(queue, 799, &producer) == CA_OK);
    void *first[count];
    void *second[count];
    for (size_t i = 0; i < count; ++i) {
        first[i] = item_id(i);
        second[i] = item_id(count + i);
    }
    _Atomic unsigned prepared_count;
    _Atomic int release;
    atomic_init(&prepared_count, 0);
    atomic_init(&release, 0);
    struct overlapping_prepare_context contexts[2] = {
        {.queue = queue,
         .producer = &producer,
         .items = first,
         .count = count,
         .prepared_count = &prepared_count,
         .release = &release},
        {.queue = queue,
         .producer = &producer,
         .items = second,
         .count = count,
         .prepared_count = &prepared_count,
         .release = &release},
    };
    pthread_t threads[2];
    CHECK(pthread_create(&threads[0], NULL, overlapping_prepare_thread, &contexts[0]) == 0);
    CHECK(pthread_create(&threads[1], NULL, overlapping_prepare_thread, &contexts[1]) == 0);
    while (atomic_load_explicit(&prepared_count, memory_order_acquire) != 2) sched_yield();
    atomic_store_explicit(&release, 1, memory_order_release);
    CHECK(pthread_join(threads[0], NULL) == 0);
    CHECK(pthread_join(threads[1], NULL) == 0);
    CHECK(contexts[0].status == CA_OK && contexts[1].status == CA_OK);

    ca_claim_item_t claimed[2 * count];
    ca_completion_state_t states[2 * count];
    ca_claim_t claim;
    CHECK(ca_claim_up_to(queue, &claim, claimed, 2 * count) == CA_OK && claim.count == 2 * count);
    unsigned seen[2 * count];
    memset(seen, 0, sizeof(seen));
    const size_t first_id = id_of(claimed[0].item);
    const size_t first_base = first_id < count ? 0 : count;
    for (size_t i = 0; i < 2 * count; ++i) {
        const size_t id = id_of(claimed[i].item);
        CHECK(id < 2 * count && ++seen[id] == 1);
        const size_t base = i < count ? first_base : count - first_base;
        CHECK(id == base + i % count);
        states[i] = CA_COMPLETE_COMMIT;
    }
    CHECK(ca_complete(&claim, states) == CA_OK);
    check_capacity(queue, 2 * count, 2 * count, 0);
    CHECK(ca_producer_release(&producer) == CA_OK);
    finish_queue(queue);
}

enum oom_publish_kind { OOM_DIRECT, OOM_RESERVED, OOM_BUILDER };

/* Intent: fail allocation after one newly attached chunk, after the lane has
 * already prepared both inline and chunk slots. Exact full capacity after the
 * failure proves transactional rollback. A singleton and a 130-item recovery
 * publication then prove head/tail/hint and recycled-chunk integrity. */
static void test_transactional_chunk_oom(enum oom_publish_kind kind) {
    enum { count = 130, capacity = 200 };
    ca_queue_t *queue = new_queue(capacity, 1);
    ca_producer_t producer;
    CHECK(ca_producer_register(queue, 800 + kind, &producer) == CA_OK);
    void *messages[count];
    for (size_t i = 0; i < count; ++i) messages[i] = item_id(i);
    size_t accepted = 0;
    ca_builder_t builder;
    ca_test_fail_chunk_alloc_after(queue, 1);
    if (kind == OOM_DIRECT) {
        CHECK(ca_submit_span(queue, &producer, messages, count, &accepted) == CA_NO_MEMORY);
        CHECK(accepted == 0);
    } else if (kind == OOM_RESERVED) {
        ca_reservation_t reservation;
        CHECK(ca_reserve(queue, &producer, count, &reservation) == CA_OK);
        CHECK(ca_publish_reserved(&reservation, messages) == CA_NO_MEMORY);
    } else {
        CHECK(ca_builder_begin(queue, &producer, &builder) == CA_OK);
        for (size_t offset = 0; offset < count;) {
            const size_t wanted = count - offset < 64 ? count - offset : 64;
            ca_credit_lease_t lease;
            CHECK(ca_credit_acquire(queue, &producer, wanted, &lease) == CA_OK);
            CHECK(ca_builder_append(&builder, &lease, &messages[offset], wanted, &accepted) == CA_OK);
            CHECK(accepted == wanted);
            ca_credit_release(&lease);
            offset += wanted;
        }
        CHECK(ca_builder_publish(&builder) == CA_NO_MEMORY);
    }
    if (kind == OOM_BUILDER)
        check_capacity(queue, capacity, capacity - count, 0);
    else
        check_capacity(queue, capacity, capacity, 0);

    ca_test_fail_chunk_alloc_after(queue, SIZE_MAX);
    void *singleton[] = {item_id(500)};
    CHECK(ca_submit_one(queue, &producer, singleton[0]) == CA_OK);
    drain_expect(queue, singleton, 1, 1);
    if (kind == OOM_BUILDER) {
        CHECK(ca_builder_publish(&builder) == CA_OK);
        drain_expect(queue, messages, count, count);
    } else {
        CHECK(ca_submit_span(queue, &producer, messages, count, &accepted) == CA_OK && accepted == count);
        drain_expect(queue, messages, count, count);
    }
    check_capacity(queue, capacity, capacity, 0);
    CHECK(ca_producer_release(&producer) == CA_OK);
    finish_queue(queue);
}

/* Intent: canceling a builder after transactional publication OOM must return
 * every owned credit. Exact singleton and multi-item identities afterward
 * prove cancellation did not leave stale slot metadata or reorder recovery. */
static void test_failed_builder_cancel(void) {
    enum { count = 130, capacity = 200 };
    ca_queue_t *queue = new_queue(capacity, 1);
    ca_producer_t producer;
    CHECK(ca_producer_register(queue, 880, &producer) == CA_OK);
    void *messages[count];
    for (size_t i = 0; i < count; ++i) messages[i] = item_id(i);
    ca_builder_t builder;
    CHECK(ca_builder_begin(queue, &producer, &builder) == CA_OK);
    for (size_t offset = 0; offset < count;) {
        const size_t wanted = count - offset < 64 ? count - offset : 64;
        ca_credit_lease_t lease;
        size_t accepted = 0;
        CHECK(ca_credit_acquire(queue, &producer, wanted, &lease) == CA_OK);
        CHECK(ca_builder_append(&builder, &lease, &messages[offset], wanted, &accepted) == CA_OK);
        CHECK(accepted == wanted);
        ca_credit_release(&lease);
        offset += wanted;
    }
    ca_test_fail_chunk_alloc_after(queue, 1);
    CHECK(ca_builder_publish(&builder) == CA_NO_MEMORY);
    check_capacity(queue, capacity, capacity - count, 0);
    ca_builder_cancel(&builder);
    check_capacity(queue, capacity, capacity, 0);

    ca_test_fail_chunk_alloc_after(queue, SIZE_MAX);
    void *singleton[] = {item_id(500)};
    CHECK(ca_submit_one(queue, &producer, singleton[0]) == CA_OK);
    drain_expect(queue, singleton, 1, 1);
    size_t accepted = 0;
    CHECK(ca_submit_span(queue, &producer, messages, count, &accepted) == CA_OK && accepted == count);
    drain_expect(queue, messages, count, count);
    check_capacity(queue, capacity, capacity, 0);
    CHECK(ca_producer_release(&producer) == CA_OK);
    finish_queue(queue);
}

static void test_tiny_wraps_and_singleton_tail(void) {
    ca_queue_t *queue = new_queue(1, 1);
    ca_producer_t producer;
    CHECK(ca_producer_register(queue, 10, &producer) == CA_OK);
    ca_claim_item_t item;
    ca_completion_state_t committed = CA_COMPLETE_COMMIT;
    for (size_t i = 0; i < 10000; ++i) {
        CHECK(ca_submit_one(queue, &producer, item_id(i)) == CA_OK);
        ca_claim_t claim;
        CHECK(ca_claim_up_to(queue, &claim, &item, 1) == CA_OK);
        CHECK(claim.count == 1 && id_of(item.item) == i);
        CHECK(ca_complete(&claim, &committed) == CA_OK);
    }
    check_capacity(queue, 1, 1, 0);

    void *burst[1] = {item_id(2000000)};
    size_t accepted;
    CHECK(ca_submit_span(queue, &producer, burst, 1, &accepted) == CA_OK && accepted == 1);
    CHECK(drain_commit(queue, 8) == 1);
    CHECK(ca_submit_one(queue, &producer, item_id(2000001)) == CA_OK);
    ca_claim_t singleton_claim;
    CHECK(ca_claim_up_to(queue, &singleton_claim, &item, 1) == CA_OK);
    CHECK(singleton_claim.count == 1 && id_of(item.item) == 2000001);
    CHECK(ca_complete(&singleton_claim, &committed) == CA_OK);
    ca_producer_release(&producer);
    finish_queue(queue);
}

/* Intent: exercise the checked lane-ordinal boundary without billions of
 * wraps.  Seeding is allowed only on an empty test lane; publishing the last
 * representable ordinal succeeds and the following publication is rejected,
 * which is the exact overflow oracle. */
static void test_lane_ordinal_boundary(void) {
    ca_queue_t *queue = new_queue(2, 1);
    ca_producer_t producer;
    CHECK(ca_producer_register(queue, 88, &producer) == CA_OK);
    CHECK(ca_test_seed_empty_lane(queue, &producer, UINT64_MAX - 1) == CA_OK);
    CHECK(ca_submit_one(queue, &producer, item_id(1)) == CA_OK);
    ca_claim_item_t item;
    ca_claim_t claim;
    CHECK(ca_claim_up_to(queue, &claim, &item, 1) == CA_OK);
    CHECK(id_of(item.item) == 1);
    const ca_completion_state_t commit = CA_COMPLETE_COMMIT;
    CHECK(ca_complete(&claim, &commit) == CA_OK);
    CHECK(ca_submit_one(queue, &producer, item_id(2)) == CA_INVALID);
    CHECK(ca_producer_release(&producer) == CA_OK);
    finish_queue(queue);
}

static void test_burst_drain_singleton(void) {
    ca_queue_t *queue = new_queue(65, 2);
    ca_producer_t producer;
    CHECK(ca_producer_register(queue, 20, &producer) == CA_OK);
    void *messages[65];
    for (size_t i = 0; i < 65; ++i) messages[i] = item_id(i);
    size_t accepted;
    CHECK(ca_submit_span(queue, &producer, messages, 65, &accepted) == CA_OK && accepted == 65);
    CHECK(drain_commit(queue, 7) == 65);
    CHECK(ca_submit_one(queue, &producer, item_id(99)) == CA_OK);
    ca_claim_item_t item;
    ca_claim_t claim;
    CHECK(ca_claim_up_to(queue, &claim, &item, 64) == CA_OK);
    CHECK(claim.count == 1 && id_of(item.item) == 99);
    const ca_completion_state_t state = CA_COMPLETE_COMMIT;
    CHECK(ca_complete(&claim, &state) == CA_OK);
    ca_producer_release(&producer);
    finish_queue(queue);
}

static void test_stalled_reservation_and_credits(void) {
    ca_queue_t *queue = new_queue(2, 2);
    ca_producer_t first;
    ca_producer_t second;
    CHECK(ca_producer_register(queue, 1, &first) == CA_OK);
    CHECK(ca_producer_register(queue, 2, &second) == CA_OK);
    ca_reservation_t stalled;
    CHECK(ca_reserve(queue, &first, 1, &stalled) == CA_OK);
    CHECK(ca_submit_one(queue, &second, item_id(2)) == CA_OK);
    ca_claim_item_t item;
    ca_claim_t claim;
    CHECK(ca_claim_up_to(queue, &claim, &item, 1) == CA_OK);
    CHECK(id_of(item.item) == 2);
    const ca_completion_state_t commit = CA_COMPLETE_COMMIT;
    CHECK(ca_complete(&claim, &commit) == CA_OK);
    void *delayed[1] = {item_id(1)};
    CHECK(ca_publish_reserved(&stalled, delayed) == CA_OK);
    CHECK(ca_claim_up_to(queue, &claim, &item, 1) == CA_OK);
    CHECK(id_of(item.item) == 1);
    CHECK(ca_complete(&claim, &commit) == CA_OK);

    ca_reservation_t cancelled;
    CHECK(ca_reserve(queue, &first, 2, &cancelled) == CA_OK);
    check_capacity(queue, 2, 0, 0);
    ca_cancel_reservation(&cancelled);
    check_capacity(queue, 2, 2, 0);
    ca_producer_release(&first);
    ca_producer_release(&second);
    finish_queue(queue);

    queue = new_queue(7, 1);
    CHECK(ca_producer_register(queue, 3, &first) == CA_OK);
    ca_credit_lease_t lease;
    CHECK(ca_credit_acquire(queue, &first, 64, &lease) == CA_PARTIAL);
    CHECK(lease.unused == 4 && lease.speculative_unused == 3);
    check_capacity(queue, 7, 3, 3);
    ca_credit_lease_t second_lease;
    CHECK(ca_credit_acquire(queue, &first, 1, &second_lease) == CA_OK);
    CHECK(second_lease.unused == 1 && second_lease.speculative_unused == 0);
    check_capacity(queue, 7, 2, 3);
    ca_credit_release(&second_lease);
    check_capacity(queue, 7, 3, 3);
    void *leased[2] = {item_id(10), item_id(11)};
    size_t accepted = 0;
    CHECK(ca_credit_submit_span(&lease, leased, 2, &accepted) == CA_OK && accepted == 2);
    check_capacity(queue, 7, 3, 2);
    ca_credit_release(&lease);
    check_capacity(queue, 7, 5, 0);
    CHECK(drain_commit(queue, 8) == 2);
    check_capacity(queue, 7, 7, 0);
    ca_producer_release(&first);
    finish_queue(queue);
}

/* Intent: handles must be queue- and generation-bound, and a producer object
 * cannot be released while a reservation/lease/builder can still refer to its
 * stable lane handle.  Exact CA_INVALID/CA_BUSY results are the oracle. */
static void test_producer_handle_validation(void) {
    ca_queue_t *first = new_queue(7, 1);
    ca_queue_t *second = new_queue(7, 1);
    ca_producer_t producer;
    CHECK(ca_producer_register(first, 7, &producer) == CA_OK);
    CHECK(ca_submit_one(second, &producer, item_id(1)) == CA_INVALID);
    ca_reservation_t reservation;
    CHECK(ca_reserve(second, &producer, 1, &reservation) == CA_INVALID);
    CHECK(ca_reserve(first, &producer, 1, &reservation) == CA_OK);
    CHECK(ca_producer_release(&producer) == CA_BUSY);
    ca_cancel_reservation(&reservation);
    ca_credit_lease_t lease;
    CHECK(ca_credit_acquire(first, &producer, 1, &lease) == CA_OK);
    CHECK(ca_producer_release(&producer) == CA_BUSY);
    ca_credit_release(&lease);
    ca_builder_t builder;
    CHECK(ca_builder_begin(first, &producer, &builder) == CA_OK);
    CHECK(ca_producer_release(&producer) == CA_BUSY);
    ca_builder_cancel(&builder);
    CHECK(ca_producer_release(&producer) == CA_OK);
    finish_queue(first);
    finish_queue(second);
}

static void check_serial_model(ca_queue_t *queue, size_t capacity, size_t owned, size_t speculative, size_t in_flight) {
    ca_capacity_snapshot_t snapshot;
    ca_capacity_read(queue, &snapshot);
    CHECK(snapshot.capacity == capacity);
    CHECK(snapshot.available == capacity - owned);
    CHECK(snapshot.speculative_unused == speculative);
    CHECK(snapshot.in_flight == in_flight);
}

/* Intent: compare every ownership transition with a tiny exact serial model.
 * Reservations, unused credits, publication, claims, retry, and final
 * completion all remain message-counted; each snapshot is the oracle rather
 * than an eventual or inequality-only check. */
static void test_exact_serial_capacity_model(void) {
    ca_queue_t *queue = new_queue(7, 1);
    ca_producer_t producer;
    CHECK(ca_producer_register(queue, 70, &producer) == CA_OK);
    size_t owned = 0;
    ca_reservation_t reservation;
    CHECK(ca_reserve(queue, &producer, 2, &reservation) == CA_OK);
    owned += 2;
    check_serial_model(queue, 7, owned, 0, 0);
    ca_credit_lease_t lease;
    CHECK(ca_credit_acquire(queue, &producer, 2, &lease) == CA_OK);
    owned += 2;
    check_serial_model(queue, 7, owned, 1, 0);
    void *direct[4] = {item_id(0), item_id(1), item_id(2), item_id(99)};
    size_t accepted = 0;
    CHECK(ca_submit_span(queue, &producer, direct, 4, &accepted) == CA_PARTIAL && accepted == 3);
    owned += 3;
    check_serial_model(queue, 7, owned, 1, 0);
    ca_claim_item_t claimed[3];
    ca_claim_t claim;
    CHECK(ca_claim_up_to(queue, &claim, claimed, 3) == CA_OK && claim.count == 3);
    check_serial_model(queue, 7, owned, 1, 3);
    const ca_completion_state_t states[3] = {
        CA_COMPLETE_RETRY,
        CA_COMPLETE_COMMIT,
        CA_COMPLETE_DISCARD,
    };
    CHECK(ca_complete(&claim, states) == CA_OK);
    owned -= 2;
    check_serial_model(queue, 7, owned, 1, 0);
    void *reserved[2] = {item_id(3), item_id(4)};
    CHECK(ca_publish_reserved(&reservation, reserved) == CA_OK);
    check_serial_model(queue, 7, owned, 1, 0);
    void *leased[2] = {item_id(5), item_id(6)};
    CHECK(ca_credit_submit_span(&lease, leased, 2, &accepted) == CA_OK && accepted == 2);
    check_serial_model(queue, 7, owned, 0, 0);
    ca_credit_release(&lease);
    const size_t drained = drain_commit(queue, 7);
    CHECK(drained == owned);
    owned = 0;
    check_serial_model(queue, 7, owned, 0, 0);
    CHECK(ca_producer_release(&producer) == CA_OK);
    finish_queue(queue);
}

/* Intent: multiple failed claims completed in reverse order must retry by
 * original lane ordinal, not completion order.  Later normal work stays
 * blocked until every earlier retry reaches a terminal completion. */
static void test_multiple_retry_order(void) {
    ca_queue_t *queue = new_queue(8, 2);
    ca_producer_t producer;
    CHECK(ca_producer_register(queue, 71, &producer) == CA_OK);
    void *messages[6];
    for (size_t i = 0; i < 6; ++i) messages[i] = item_id(i);
    size_t accepted = 0;
    CHECK(ca_submit_span(queue, &producer, messages, 6, &accepted) == CA_OK && accepted == 6);
    ca_claim_item_t a_item;
    ca_claim_item_t b_item;
    ca_claim_t a;
    ca_claim_t b;
    CHECK(ca_claim_up_to(queue, &a, &a_item, 1) == CA_OK && id_of(a_item.item) == 0);
    CHECK(ca_claim_up_to(queue, &b, &b_item, 1) == CA_OK && id_of(b_item.item) == 1);
    const ca_completion_state_t retry = CA_COMPLETE_RETRY;
    CHECK(ca_complete(&b, &retry) == CA_OK);
    CHECK(ca_complete(&a, &retry) == CA_OK);
    for (size_t expected = 0; expected < 2; ++expected) {
        ca_claim_t retry_claim;
        ca_claim_item_t retry_item;
        CHECK(ca_claim_up_to(queue, &retry_claim, &retry_item, 1) == CA_OK);
        CHECK(retry_item.was_retry && id_of(retry_item.item) == expected);
        const ca_completion_state_t commit = CA_COMPLETE_COMMIT;
        CHECK(ca_complete(&retry_claim, &commit) == CA_OK);
    }
    CHECK(drain_commit(queue, 8) == 4);
    CHECK(ca_producer_release(&producer) == CA_OK);
    finish_queue(queue);
}

struct claim_once_context {
    ca_queue_t *queue;
    ca_claim_t claim;
    ca_claim_item_t item;
    _Atomic int started;
    ca_status_t status;
};

static void *claim_once_thread(void *argument) {
    struct claim_once_context *context = argument;
    atomic_store_explicit(&context->started, 1, memory_order_release);
    context->status = ca_claim_up_to(context->queue, &context->claim, &context->item, 1);
    return NULL;
}

struct complete_once_context {
    ca_claim_t *claim;
    ca_completion_state_t state;
    _Atomic int started;
    ca_status_t status;
};

static void *complete_once_thread(void *argument) {
    struct complete_once_context *context = argument;
    atomic_store_explicit(&context->started, 1, memory_order_release);
    context->status = ca_complete(context->claim, &context->state);
    return NULL;
}

/* Intent: force the historic claim/retry race at the precise point after the
 * normal claimant checks the barrier.  The lane gate is the linearization
 * oracle: the paused claim owns the earlier order, retry completion cannot
 * finish until it releases, and all subsequent claims observe the retry. */
static void test_retry_barrier_race(void) {
    ca_queue_t *queue = new_queue(4, 2);
    ca_producer_t producer;
    CHECK(ca_producer_register(queue, 72, &producer) == CA_OK);
    void *messages[3] = {item_id(0), item_id(1), item_id(2)};
    size_t accepted = 0;
    CHECK(ca_submit_span(queue, &producer, messages, 3, &accepted) == CA_OK && accepted == 3);
    ca_claim_item_t first_item;
    ca_claim_t first;
    CHECK(ca_claim_up_to(queue, &first, &first_item, 1) == CA_OK && id_of(first_item.item) == 0);

    ca_test_pause_normal_claim(queue);
    struct claim_once_context claimant = {.queue = queue};
    pthread_t claim_thread;
    CHECK(pthread_create(&claim_thread, NULL, claim_once_thread, &claimant) == 0);
    while (!ca_test_normal_claim_entered(queue)) sched_yield();
    struct complete_once_context completer = {.claim = &first, .state = CA_COMPLETE_RETRY};
    pthread_t complete_thread;
    CHECK(pthread_create(&complete_thread, NULL, complete_once_thread, &completer) == 0);
    while (!atomic_load_explicit(&completer.started, memory_order_acquire)) sched_yield();
    ca_test_release_normal_claim(queue);
    CHECK(pthread_join(claim_thread, NULL) == 0);
    CHECK(pthread_join(complete_thread, NULL) == 0);
    CHECK(claimant.status == CA_OK && id_of(claimant.item.item) == 1);
    CHECK(completer.status == CA_OK);
    const ca_completion_state_t commit = CA_COMPLETE_COMMIT;
    CHECK(ca_complete(&claimant.claim, &commit) == CA_OK);

    ca_claim_item_t retry_item;
    ca_claim_t retry_claim;
    CHECK(ca_claim_up_to(queue, &retry_claim, &retry_item, 1) == CA_OK);
    CHECK(retry_item.was_retry && id_of(retry_item.item) == 0);
    CHECK(ca_complete(&retry_claim, &commit) == CA_OK);
    CHECK(drain_commit(queue, 4) == 1);
    CHECK(ca_producer_release(&producer) == CA_OK);
    finish_queue(queue);
}

static void test_retry_and_out_of_order_completion(void) {
    ca_queue_t *queue = new_queue(8, 4);
    ca_producer_t producer;
    CHECK(ca_producer_register(queue, 50, &producer) == CA_OK);
    void *messages[8];
    for (size_t i = 0; i < 8; ++i) messages[i] = item_id(i);
    size_t accepted;
    CHECK(ca_submit_span(queue, &producer, messages, 6, &accepted) == CA_OK && accepted == 6);
    CHECK(ca_submit_span(queue, &producer, &messages[6], 2, &accepted) == CA_OK && accepted == 2);

    ca_claim_item_t first_items[2];
    ca_claim_item_t second_items[2];
    ca_claim_t first_claim;
    ca_claim_t second_claim;
    CHECK(ca_claim_up_to(queue, &first_claim, first_items, 2) == CA_OK);
    CHECK(ca_claim_up_to(queue, &second_claim, second_items, 2) == CA_OK);
    CHECK(id_of(first_items[0].item) == 0 && id_of(first_items[1].item) == 1);
    CHECK(id_of(second_items[0].item) == 2 && id_of(second_items[1].item) == 3);

    const ca_completion_state_t commits[2] = {CA_COMPLETE_COMMIT, CA_COMPLETE_COMMIT};
    CHECK(ca_complete(&second_claim, commits) == CA_OK);
    const ca_completion_state_t first_states[2] = {CA_COMPLETE_RETRY, CA_COMPLETE_DISCARD};
    CHECK(ca_complete(&first_claim, first_states) == CA_OK);

    ca_claim_item_t retry_items[4];
    ca_claim_t retry_claim;
    CHECK(ca_claim_up_to(queue, &retry_claim, retry_items, 4) == CA_OK);
    CHECK(retry_claim.count == 1 && id_of(retry_items[0].item) == 0 && retry_items[0].was_retry);
    /* While the retry is in flight, later normal elements from the lane are
     * barred even though their earlier claims completed out of order. */
    ca_claim_t blocked;
    ca_claim_item_t blocked_items[4];
    CHECK(ca_claim_up_to(queue, &blocked, blocked_items, 4) == CA_EMPTY);
    const ca_completion_state_t retry_again = CA_COMPLETE_RETRY;
    CHECK(ca_complete(&retry_claim, &retry_again) == CA_OK);
    CHECK(ca_claim_up_to(queue, &retry_claim, retry_items, 4) == CA_OK);
    CHECK(retry_claim.count == 1 && id_of(retry_items[0].item) == 0);
    const ca_completion_state_t commit = CA_COMPLETE_COMMIT;
    CHECK(ca_complete(&retry_claim, &commit) == CA_OK);

    CHECK(drain_commit(queue, 3) == 4);
    check_capacity(queue, 8, 8, 0);
    ca_producer_release(&producer);
    finish_queue(queue);
}

static void test_anonymous_fallback(void) {
    ca_queue_t *queue = new_queue(64, 3);
    for (size_t i = 0; i < 64; ++i) CHECK(ca_submit_one(queue, NULL, item_id(i)) == CA_OK);
    _Atomic unsigned char seen[64];
    memset(seen, 0, sizeof(seen));
    ca_claim_item_t items[11];
    ca_completion_state_t states[11];
    size_t total = 0;
    for (;;) {
        ca_claim_t claim;
        const ca_status_t status = ca_claim_up_to(queue, &claim, items, 11);
        if (status == CA_EMPTY) break;
        CHECK(status == CA_OK);
        for (size_t i = 0; i < claim.count; ++i) {
            const size_t id = id_of(items[i].item);
            CHECK(id < 64);
            CHECK(atomic_fetch_add_explicit(&seen[id], 1, memory_order_relaxed) == 0);
            states[i] = CA_COMPLETE_COMMIT;
        }
        total += claim.count;
        CHECK(ca_complete(&claim, states) == CA_OK);
    }
    CHECK(total == 64);
    for (size_t i = 0; i < 64; ++i) CHECK(atomic_load_explicit(&seen[i], memory_order_relaxed) == 1);
    finish_queue(queue);
}

struct collision_context {
    ca_queue_t *queue;
    ca_producer_t *producer;
    size_t producer_index;
    size_t count;
    _Atomic int *start;
};

static void *collision_producer(void *argument) {
    struct collision_context *context = argument;
    while (!atomic_load_explicit(context->start, memory_order_acquire)) sched_yield();
    for (size_t i = 0; i < context->count; ++i) {
        const size_t id = context->producer_index * 1000 + i;
        CHECK(ca_submit_one(context->queue, context->producer, item_id(id)) == CA_OK);
    }
    return NULL;
}

/* Intent: force four producer handles onto one sharded fallback lane by first
 * consuming all dedicated handles and registering equal fallback keys.  A
 * single consumer's exact per-producer sequence is the ordering oracle. */
static void test_shared_fallback_collisions(void) {
    enum { producer_count = 20, per_producer = 32 };
    ca_queue_t *queue = new_queue(producer_count * per_producer, 1);
    ca_producer_t producers[producer_count];
    pthread_t threads[producer_count];
    struct collision_context contexts[producer_count];
    _Atomic int start = 0;
    for (size_t i = 0; i < producer_count; ++i) {
        CHECK(ca_producer_register(queue, 1234, &producers[i]) == CA_OK);
        contexts[i] = (struct collision_context){
            .queue = queue,
            .producer = &producers[i],
            .producer_index = i,
            .count = per_producer,
            .start = &start,
        };
        CHECK(pthread_create(&threads[i], NULL, collision_producer, &contexts[i]) == 0);
    }
    atomic_store_explicit(&start, 1, memory_order_release);
    for (size_t i = 0; i < producer_count; ++i) CHECK(pthread_join(threads[i], NULL) == 0);

    size_t next[producer_count];
    memset(next, 0, sizeof(next));
    size_t total = 0;
    ca_claim_item_t items[37];
    ca_completion_state_t states[37];
    for (;;) {
        ca_claim_t claim;
        const ca_status_t status = ca_claim_up_to(queue, &claim, items, 37);
        if (status == CA_EMPTY) break;
        CHECK(status == CA_OK);
        for (size_t i = 0; i < claim.count; ++i) {
            const size_t id = id_of(items[i].item);
            const size_t producer_index = id / 1000;
            const size_t sequence = id % 1000;
            CHECK(producer_index < producer_count);
            CHECK(sequence == next[producer_index]++);
            states[i] = CA_COMPLETE_COMMIT;
        }
        total += claim.count;
        CHECK(ca_complete(&claim, states) == CA_OK);
    }
    CHECK(total == producer_count * per_producer);
    for (size_t i = 0; i < producer_count; ++i) {
        CHECK(next[i] == per_producer);
        CHECK(ca_producer_release(&producers[i]) == CA_OK);
    }
    finish_queue(queue);
}

/* Intent: exercise one historical four-chunk peak on every dedicated and
 * fallback lane sequentially. The exact accounting oracle bounds retained
 * memory by one tail plus one pooled chunk per lane, rather than multiplying
 * every lane by its historical peak. */
static void test_bounded_historical_chunk_retention(void) {
    enum { capacity = 256, dedicated = 16 };
    ca_queue_t *queue = new_queue(capacity, 1);
    ca_producer_t producers[dedicated];
    void *messages[capacity];
    for (size_t i = 0; i < capacity; ++i) messages[i] = item_id(i);
    for (size_t i = 0; i < dedicated; ++i) CHECK(ca_producer_register(queue, i, &producers[i]) == CA_OK);
    for (size_t lane = 0; lane < dedicated; ++lane) {
        size_t accepted = 0;
        CHECK(ca_submit_span(queue, &producers[lane], messages, capacity, &accepted) == CA_OK);
        CHECK(accepted == capacity && drain_commit(queue, capacity) == capacity);
    }
    for (size_t fallback = 0; fallback < ca_fallback_lane_count(queue); ++fallback) {
        size_t accepted = 0;
        CHECK(ca_submit_span(queue, NULL, messages, capacity, &accepted) == CA_OK);
        CHECK(accepted == capacity && drain_commit(queue, capacity) == capacity);
    }
    const size_t lanes = ca_dedicated_lane_limit(queue) + ca_fallback_lane_count(queue);
    CHECK(ca_test_chunks_live(queue) <= 2 * lanes);
    CHECK(ca_test_chunks_pooled(queue) <= lanes);
    for (size_t i = 0; i < dedicated; ++i) CHECK(ca_producer_release(&producers[i]) == CA_OK);
    CHECK(ca_test_chunks_live(queue) <= lanes + ca_fallback_lane_count(queue));
    finish_queue(queue);
}

/* Intent: worker restart must reuse quiescent dedicated lanes with a new
 * generation instead of permanently consuming the dedicated budget. One
 * hundred register/use/release cycles must all remain dedicated; filling the
 * simultaneous budget afterward must still route only the next handle to
 * fallback. */
static void test_dedicated_lane_reuse(void) {
    ca_queue_t *queue = new_queue(2, 1);
    uint64_t generations[16] = {0};
    for (size_t cycle = 0; cycle < 100; ++cycle) {
        ca_producer_t producer;
        CHECK(ca_producer_register(queue, cycle, &producer) == CA_OK && !producer.fallback);
        CHECK(producer.lane_generation > generations[producer.lane_index]);
        generations[producer.lane_index] = producer.lane_generation;
        CHECK(ca_submit_one(queue, &producer, item_id(cycle)) == CA_OK);
        CHECK(drain_commit(queue, 1) == 1);
        CHECK(ca_producer_release(&producer) == CA_OK);
    }
    ca_producer_t simultaneous[17];
    for (size_t i = 0; i < 17; ++i) CHECK(ca_producer_register(queue, i, &simultaneous[i]) == CA_OK);
    for (size_t i = 0; i < 16; ++i) CHECK(!simultaneous[i].fallback);
    CHECK(simultaneous[16].fallback);
    for (size_t i = 0; i < 17; ++i) CHECK(ca_producer_release(&simultaneous[i]) == CA_OK);
    finish_queue(queue);
}

/* Intent: releasing a producer does not orphan its published lane and does not
 * reuse that lane before drain. Exact old-item order is preserved; once drain
 * completes, a later registration reuses the index with a newer generation. */
static void test_release_before_drain_reuse(void) {
    ca_queue_t *queue = new_queue(3, 1);
    ca_producer_t first;
    CHECK(ca_producer_register(queue, 1000, &first) == CA_OK);
    const uint32_t old_lane = first.lane_index;
    const uint64_t old_generation = first.lane_generation;
    void *messages[] = {item_id(10), item_id(11), item_id(12)};
    size_t accepted = 0;
    CHECK(ca_submit_span(queue, &first, messages, 3, &accepted) == CA_OK && accepted == 3);
    CHECK(ca_producer_release(&first) == CA_OK);

    ca_producer_t interim;
    CHECK(ca_producer_register(queue, 1001, &interim) == CA_OK);
    CHECK(interim.lane_index != old_lane);
    drain_expect(queue, messages, 3, 3);
    CHECK(ca_producer_release(&interim) == CA_OK);

    int found = 0;
    for (size_t attempt = 0; attempt < 16; ++attempt) {
        ca_producer_t restarted;
        CHECK(ca_producer_register(queue, 1100 + attempt, &restarted) == CA_OK);
        if (restarted.lane_index == old_lane) {
            CHECK(restarted.lane_generation > old_generation);
            found = 1;
        }
        CHECK(ca_producer_release(&restarted) == CA_OK);
        if (found) break;
    }
    CHECK(found);
    check_capacity(queue, 3, 3, 0);
    finish_queue(queue);
}

struct inspect_context {
    ca_queue_t *queue;
    ca_capacity_snapshot_t snapshot;
    ca_status_t bind_status;
    ca_status_t unbind_status;
    _Atomic int read_done;
    _Atomic int release_binding;
};

struct destroy_context {
    ca_queue_t *queue;
    ca_status_t status;
};

static void *inspect_thread(void *argument) {
    struct inspect_context *context = argument;
    ca_lifecycle_binding_t binding;
    context->bind_status = ca_lifecycle_bind(context->queue, &binding);
    if (context->bind_status != CA_OK) return NULL;
    ca_capacity_read(context->queue, &context->snapshot);
    atomic_store_explicit(&context->read_done, 1, memory_order_release);
    while (!atomic_load_explicit(&context->release_binding, memory_order_acquire)) sched_yield();
    context->unbind_status = ca_lifecycle_unbind(&binding);
    return NULL;
}

static void *destroy_thread(void *argument) {
    struct destroy_context *context = argument;
    context->status = ca_destroy(context->queue);
    return NULL;
}

/* Intent: destruction must wait a bound worker's read already admitted through
 * inspection. Releasing the read and then its lifetime binding yields the
 * exact snapshot before destroy can free the core. */
static void test_destroy_waits_inspection(void) {
    ca_queue_t *queue = new_queue(3, 1);
    ca_test_pause_role(queue, CA_TEST_ROLE_INSPECT);
    struct inspect_context inspector = {.queue = queue};
    atomic_init(&inspector.read_done, 0);
    atomic_init(&inspector.release_binding, 0);
    pthread_t reader;
    CHECK(pthread_create(&reader, NULL, inspect_thread, &inspector) == 0);
    while (!ca_test_role_entered(queue)) sched_yield();
    struct destroy_context destroyer = {.queue = queue};
    pthread_t destroyer_thread;
    CHECK(pthread_create(&destroyer_thread, NULL, destroy_thread, &destroyer) == 0);
    while (!ca_test_destroying(queue)) sched_yield();
    ca_test_release_role(queue);
    while (!atomic_load_explicit(&inspector.read_done, memory_order_acquire)) sched_yield();
    CHECK(pthread_join(destroyer_thread, NULL) == 0);
    CHECK(destroyer.status == CA_BUSY);
    atomic_store_explicit(&inspector.release_binding, 1, memory_order_release);
    CHECK(pthread_join(reader, NULL) == 0);
    CHECK(inspector.bind_status == CA_OK && inspector.unbind_status == CA_OK);
    CHECK(inspector.snapshot.capacity == 3 && inspector.snapshot.available == 3);
    finish_queue(queue);
}

/* Intent: a live worker binding is the explicit queue-storage lifetime guard.
 * Destroy must return BUSY while it exists, then succeed after same-thread
 * unbind; callers without such a binding must not overlap destruction. */
static void test_destroy_refuses_live_binding(void) {
    ca_queue_t *queue = new_queue(1, 1);
    ca_lifecycle_binding_t binding;
    CHECK(ca_lifecycle_bind(queue, &binding) == CA_OK);
    CHECK(ca_destroy(queue) == CA_BUSY);
    CHECK(ca_lifecycle_unbind(&binding) == CA_OK);
    finish_queue(queue);
}

struct pre_cas_context {
    ca_queue_t *queue;
    ca_producer_t *producer;
    _Atomic int bound;
    _Atomic int go;
    ca_status_t status;
};

static void *pre_cas_submit_thread(void *argument) {
    struct pre_cas_context *context = argument;
    ca_lifecycle_binding_t binding;
    CHECK(ca_lifecycle_bind(context->queue, &binding) == CA_OK);
    atomic_store_explicit(&context->bound, 1, memory_order_release);
    while (!atomic_load_explicit(&context->go, memory_order_acquire)) sched_yield();
    context->status = ca_submit_one(context->queue, context->producer, item_id(77));
    CHECK(ca_lifecycle_unbind(&binding) == CA_OK);
    return NULL;
}

/* Intent: pause after selecting a lifecycle slot but before its packed-word
 * CAS. Quiesce closes every slot, changes accepting, and reopens; the delayed
 * CAS may enter only afterward and must observe CA_CLOSED without publishing. */
static void test_quiesce_closes_pre_cas_reader(void) {
    ca_queue_t *queue = new_queue(1, 1);
    ca_producer_t producer;
    CHECK(ca_producer_register(queue, 1234, &producer) == CA_OK);
    struct pre_cas_context context = {.queue = queue, .producer = &producer};
    atomic_init(&context.bound, 0);
    atomic_init(&context.go, 0);
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, pre_cas_submit_thread, &context) == 0);
    while (!atomic_load_explicit(&context.bound, memory_order_acquire)) sched_yield();
    ca_test_pause_before_lifecycle_cas(queue);
    atomic_store_explicit(&context.go, 1, memory_order_release);
    while (!ca_test_before_lifecycle_cas_entered(queue)) sched_yield();
    CHECK(ca_quiesce(queue, CA_QUIESCE_DRAIN, NULL) == CA_OK);
    ca_test_release_before_lifecycle_cas(queue);
    CHECK(pthread_join(thread, NULL) == 0);
    CHECK(context.status == CA_CLOSED);
    check_capacity(queue, 1, 1, 0);
    CHECK(ca_producer_release(&producer) == CA_OK);
    CHECK(ca_destroy(queue) == CA_OK);
}

struct cancelled_claim_context {
    ca_queue_t *queue;
    ca_claim_t claim;
    ca_claim_item_t items[2];
    _Atomic int cleanup_status;
    _Atomic int started;
};

static void return_claim_cleanup(void *argument) {
    struct cancelled_claim_context *context = argument;
    atomic_store_explicit(&context->cleanup_status, ca_return_claim(&context->claim), memory_order_release);
}

static void *cancelled_claim_thread(void *argument) {
    struct cancelled_claim_context *context = argument;
    CHECK(ca_claim_up_to(context->queue, &context->claim, context->items, 2) == CA_OK);
    pthread_cleanup_push(return_claim_cleanup, context);
    atomic_store_explicit(&context->started, 1, memory_order_release);
    for (;;) pthread_testcancel();
    pthread_cleanup_pop(0);
    return NULL;
}

/* Intent: codify the future WTI cancellation handoff. A cleanup handler uses
 * ca_return_claim(), and cancellation must make both claimed items retryable in
 * original order with no capacity or ownership loss. */
static void test_cancelled_claim_return(void) {
    ca_queue_t *queue = new_queue(3, 1);
    ca_producer_t producer;
    CHECK(ca_producer_register(queue, 990, &producer) == CA_OK);
    void *messages[3] = {item_id(0), item_id(1), item_id(2)};
    size_t accepted = 0;
    CHECK(ca_submit_span(queue, &producer, messages, 3, &accepted) == CA_OK && accepted == 3);
    struct cancelled_claim_context context = {.queue = queue};
    atomic_init(&context.cleanup_status, CA_INVALID);
    atomic_init(&context.started, 0);
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, cancelled_claim_thread, &context) == 0);
    while (!atomic_load_explicit(&context.started, memory_order_acquire)) sched_yield();
    CHECK(pthread_cancel(thread) == 0);
    void *thread_result = NULL;
    CHECK(pthread_join(thread, &thread_result) == 0 && thread_result == PTHREAD_CANCELED);
    CHECK(atomic_load_explicit(&context.cleanup_status, memory_order_acquire) == CA_OK);
    ca_claim_item_t item;
    ca_claim_t claim;
    const ca_completion_state_t commit = CA_COMPLETE_COMMIT;
    for (size_t expected = 0; expected < 2; ++expected) {
        CHECK(ca_claim_up_to(queue, &claim, &item, 1) == CA_OK);
        CHECK(item.was_retry && id_of(item.item) == expected);
        CHECK(ca_complete(&claim, &commit) == CA_OK);
    }
    CHECK(drain_commit(queue, 1) == 1);
    CHECK(ca_producer_release(&producer) == CA_OK);
    finish_queue(queue);
}

struct wait_context {
    ca_queue_t *queue;
    uint32_t observed;
    _Atomic int started;
    _Atomic int done;
    int capacity;
    ca_status_t result;
};

static void *wait_thread(void *argument) {
    struct wait_context *context = argument;
    struct timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += 5;
    atomic_store_explicit(&context->started, 1, memory_order_release);
    context->result = context->capacity ? ca_wait_capacity_epoch(context->queue, context->observed, &deadline)
                                        : ca_wait_epoch(context->queue, context->observed, &deadline);
    atomic_store_explicit(&context->done, 1, memory_order_release);
    return NULL;
}

static void test_epoch_wait(void) {
    ca_queue_t *queue = new_queue(2, 1);
    ca_producer_t producer;
    CHECK(ca_producer_register(queue, 1, &producer) == CA_OK);
    struct wait_context context = {.queue = queue, .observed = ca_epoch(queue)};
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, wait_thread, &context) == 0);
    while (!atomic_load_explicit(&context.started, memory_order_acquire)) sched_yield();
    CHECK(ca_submit_one(queue, &producer, item_id(1)) == CA_OK);
    CHECK(pthread_join(thread, NULL) == 0);
    CHECK(context.result == CA_OK);
    CHECK(drain_commit(queue, 2) == 1);
    ca_producer_release(&producer);
    finish_queue(queue);
}

/* Intent: reproduce the mixed-waiter liveness failure without timing luck.
 * One unpublished reservation fills capacity, then one work waiter and two
 * capacity waiters are observed asleep. Publication must wake only the work
 * waiter; terminal completion must wake a capacity waiter. Exact per-class
 * sleeper/done counts prove a wake cannot be consumed by the wrong predicate. */
static void test_split_work_capacity_waits(void) {
    ca_queue_t *queue = new_queue(1, 1);
    ca_producer_t producer;
    CHECK(ca_producer_register(queue, 12345, &producer) == CA_OK);
    ca_reservation_t reservation;
    CHECK(ca_reserve(queue, &producer, 1, &reservation) == CA_OK);
    CHECK(ca_prepare_reserved(&reservation) == CA_OK);

    struct wait_context work = {.queue = queue, .observed = ca_epoch(queue)};
    struct wait_context capacity[2] = {
        {.queue = queue, .observed = ca_capacity_epoch(queue), .capacity = 1},
        {.queue = queue, .observed = ca_capacity_epoch(queue), .capacity = 1},
    };
    pthread_t work_thread;
    pthread_t capacity_threads[2];
    CHECK(pthread_create(&work_thread, NULL, wait_thread, &work) == 0);
    for (size_t i = 0; i < 2; ++i) CHECK(pthread_create(&capacity_threads[i], NULL, wait_thread, &capacity[i]) == 0);
    while (ca_test_work_sleepers(queue) != 1 || ca_test_capacity_sleepers(queue) != 2) sched_yield();

    void *items[1] = {item_id(77)};
    CHECK(ca_commit_prepared(&reservation, items) == CA_OK);
    CHECK(pthread_join(work_thread, NULL) == 0 && work.result == CA_OK);
    CHECK(!atomic_load_explicit(&capacity[0].done, memory_order_acquire));
    CHECK(!atomic_load_explicit(&capacity[1].done, memory_order_acquire));

    ca_claim_item_t claim_item;
    ca_claim_t claim;
    const ca_completion_state_t commit = CA_COMPLETE_COMMIT;
    CHECK(ca_claim_up_to(queue, &claim, &claim_item, 1) == CA_OK);
    CHECK(ca_complete(&claim, &commit) == CA_OK);
    while (!atomic_load_explicit(&capacity[0].done, memory_order_acquire) &&
           !atomic_load_explicit(&capacity[1].done, memory_order_acquire))
        sched_yield();
    ca_interrupt_waiters(queue);
    for (size_t i = 0; i < 2; ++i) {
        CHECK(pthread_join(capacity_threads[i], NULL) == 0);
        CHECK(capacity[i].result == CA_OK);
    }
    CHECK(ca_producer_release(&producer) == CA_OK);
    finish_queue(queue);
}

/* Intent: a batch completion that returns two credits must make proportional
 * progress for two parked producers. Both waiters only observe the capacity
 * event and deliberately do not reserve, modeling an interrupted first woken
 * producer. Joining both without an interrupt or timeout proves the second
 * released credit cannot remain stranded behind wake-one. */
static void test_capacity_release_wakes_proportionally(void) {
    ca_queue_t *queue = new_queue(2, 1);
    ca_producer_t producer;
    CHECK(ca_producer_register(queue, 23456, &producer) == CA_OK);
    ca_reservation_t reservation;
    CHECK(ca_reserve(queue, &producer, 2, &reservation) == CA_OK);
    CHECK(ca_prepare_reserved(&reservation) == CA_OK);
    void *items[2] = {item_id(88), item_id(89)};
    CHECK(ca_commit_prepared(&reservation, items) == CA_OK);

    struct wait_context capacity[2] = {
        {.queue = queue, .observed = ca_capacity_epoch(queue), .capacity = 1},
        {.queue = queue, .observed = ca_capacity_epoch(queue), .capacity = 1},
    };
    pthread_t threads[2];
    for (size_t i = 0; i < 2; ++i) CHECK(pthread_create(&threads[i], NULL, wait_thread, &capacity[i]) == 0);
    while (ca_test_capacity_sleepers(queue) != 2) sched_yield();

    ca_claim_item_t claim_items[2];
    ca_claim_t claim;
    const ca_completion_state_t states[2] = {CA_COMPLETE_COMMIT, CA_COMPLETE_COMMIT};
    CHECK(ca_claim_up_to(queue, &claim, claim_items, 2) == CA_OK && claim.count == 2);
    CHECK(ca_complete(&claim, states) == CA_OK);
    for (size_t i = 0; i < 2; ++i) {
        CHECK(pthread_join(threads[i], NULL) == 0);
        CHECK(capacity[i].result == CA_OK);
    }
    check_capacity(queue, 2, 2, 0);
    CHECK(ca_producer_release(&producer) == CA_OK);
    finish_queue(queue);
}

struct submit_context {
    ca_queue_t *queue;
    ca_producer_t *producer;
    ca_status_t status;
};

static void *submit_thread(void *argument) {
    struct submit_context *context = argument;
    context->status = ca_submit_one(context->queue, context->producer, item_id(1));
    return NULL;
}

struct quiesce_context {
    ca_queue_t *queue;
    ca_status_t status;
};

static void *quiesce_thread(void *argument) {
    struct quiesce_context *context = argument;
    context->status = ca_quiesce(context->queue, CA_QUIESCE_DRAIN, NULL);
    return NULL;
}

/* Intent: quiesce closes admission before inspecting flags and waits entrants
 * already inside the publish role.  The paused submit must return CLOSED, the
 * quiesce must finish OK, and no ownership/capacity can leak. */
static void test_concurrent_quiesce_admission(void) {
    ca_queue_t *queue = new_queue(2, 1);
    ca_producer_t producer;
    CHECK(ca_producer_register(queue, 31, &producer) == CA_OK);
    ca_test_pause_role(queue, CA_TEST_ROLE_PUBLISH);
    struct submit_context submit = {.queue = queue, .producer = &producer};
    pthread_t submitter;
    CHECK(pthread_create(&submitter, NULL, submit_thread, &submit) == 0);
    while (!ca_test_role_entered(queue)) sched_yield();
    struct quiesce_context quiesce = {.queue = queue};
    pthread_t quiescer;
    CHECK(pthread_create(&quiescer, NULL, quiesce_thread, &quiesce) == 0);
    while (ca_test_accepting(queue)) sched_yield();
    ca_test_release_role(queue);
    CHECK(pthread_join(submitter, NULL) == 0);
    CHECK(pthread_join(quiescer, NULL) == 0);
    CHECK(submit.status == CA_CLOSED);
    CHECK(quiesce.status == CA_OK);
    check_capacity(queue, 2, 2, 0);
    CHECK(ca_producer_release(&producer) == CA_OK);
    CHECK(ca_destroy(queue) == CA_OK);
}

static void *paused_snapshot_thread(void *argument) {
    struct inspect_context *context = argument;
    ca_capacity_read(context->queue, &context->snapshot);
    return NULL;
}

/* Intent: a quiesce deadline can expire while an inspection reader is already
 * admitted. Reopening must clear only the slot's closed bit, preserving its
 * reader count until exit. Exact traffic afterward catches refcount underflow
 * or a slot left closed, and a second quiesce proves writer reuse. */
static void test_quiesce_timeout_preserves_admitted_ref(void) {
    ca_queue_t *queue = new_queue(2, 1);
    ca_producer_t producer;
    CHECK(ca_producer_register(queue, 32, &producer) == CA_OK);
    ca_test_pause_role(queue, CA_TEST_ROLE_INSPECT);
    struct inspect_context inspector = {.queue = queue};
    pthread_t reader;
    CHECK(pthread_create(&reader, NULL, paused_snapshot_thread, &inspector) == 0);
    while (!ca_test_role_entered(queue)) sched_yield();

    const struct timespec expired = {0, 0};
    CHECK(ca_quiesce(queue, CA_QUIESCE_DRAIN, &expired) == CA_TIMED_OUT);
    ca_test_release_role(queue);
    CHECK(pthread_join(reader, NULL) == 0);
    CHECK(inspector.snapshot.capacity == 2 && inspector.snapshot.available == 2);

    CHECK(ca_submit_one(queue, &producer, item_id(88)) == CA_OK);
    ca_claim_item_t item;
    ca_claim_t claim;
    CHECK(ca_claim_up_to(queue, &claim, &item, 1) == CA_OK);
    CHECK(claim.count == 1 && id_of(item.item) == 88);
    const ca_completion_state_t commit = CA_COMPLETE_COMMIT;
    CHECK(ca_complete(&claim, &commit) == CA_OK);
    check_capacity(queue, 2, 2, 0);
    CHECK(ca_quiesce(queue, CA_QUIESCE_DRAIN, NULL) == CA_OK);
    CHECK(ca_producer_release(&producer) == CA_OK);
    CHECK(ca_destroy(queue) == CA_OK);
}

#ifdef CA_FORCE_PTHREAD_WAIT
static void *cancel_wait_thread(void *argument) {
    struct wait_context *context = argument;
    atomic_store_explicit(&context->started, 1, memory_order_release);
    context->result = ca_wait_epoch(context->queue, context->observed, NULL);
    return NULL;
}

/* Intent: exercise the non-Linux adapter deterministically.  Registration is
 * observed before each signal, so success proves the mutex-protected predicate
 * cannot lose a wake.  Cancellation must restore sleeper count and unlock the
 * mutex, proven by a subsequent waiter completing normally. */
static void test_pthread_wait_lost_wake_and_cancel(void) {
    ca_queue_t *queue = new_queue(1, 1);
    ca_producer_t producer;
    CHECK(ca_producer_register(queue, 41, &producer) == CA_OK);
    for (size_t i = 0; i < 100; ++i) {
        struct wait_context context = {.queue = queue, .observed = ca_epoch(queue)};
        pthread_t thread;
        CHECK(pthread_create(&thread, NULL, wait_thread, &context) == 0);
        while (ca_test_waiter_count(queue) != 1) sched_yield();
        CHECK(ca_submit_one(queue, &producer, item_id(i)) == CA_OK);
        CHECK(pthread_join(thread, NULL) == 0 && context.result == CA_OK);
        CHECK(drain_commit(queue, 1) == 1);
    }
    struct wait_context cancelled = {.queue = queue, .observed = ca_epoch(queue)};
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, cancel_wait_thread, &cancelled) == 0);
    while (ca_test_waiter_count(queue) != 1) sched_yield();
    CHECK(pthread_cancel(thread) == 0);
    void *result = NULL;
    CHECK(pthread_join(thread, &result) == 0 && result == PTHREAD_CANCELED);
    CHECK(ca_test_waiter_count(queue) == 0);
    struct wait_context final = {.queue = queue, .observed = ca_epoch(queue)};
    CHECK(pthread_create(&thread, NULL, wait_thread, &final) == 0);
    while (ca_test_waiter_count(queue) != 1) sched_yield();
    CHECK(ca_submit_one(queue, &producer, item_id(999)) == CA_OK);
    CHECK(pthread_join(thread, NULL) == 0 && final.result == CA_OK);
    CHECK(drain_commit(queue, 1) == 1);
    CHECK(ca_producer_release(&producer) == CA_OK);
    finish_queue(queue);
}
#endif

struct dispose_context {
    _Atomic size_t count;
};

static void count_discard(void *item, ca_completion_state_t state, void *user) {
    struct dispose_context *context = user;
    CHECK(item != NULL);
    CHECK(state == CA_COMPLETE_DISCARD);
    atomic_fetch_add_explicit(&context->count, 1, memory_order_relaxed);
}

static void test_discard_quiesce(void) {
    struct dispose_context context = {0};
    ca_queue_t *queue = NULL;
    const ca_config_t config = {
        .core = CA_CORE_SPARSE_LANES,
        .capacity = 7,
        .consumers = 2,
        .dispose = count_discard,
        .dispose_user = &context,
    };
    CHECK(ca_create(&config, &queue) == CA_OK);
    ca_producer_t producer;
    CHECK(ca_producer_register(queue, 1, &producer) == CA_OK);
    void *items[7];
    for (size_t i = 0; i < 7; ++i) items[i] = item_id(i);
    size_t accepted;
    CHECK(ca_submit_span(queue, &producer, items, 7, &accepted) == CA_OK && accepted == 7);
    CHECK(ca_quiesce(queue, CA_QUIESCE_DISCARD, NULL) == CA_OK);
    CHECK(atomic_load_explicit(&context.count, memory_order_relaxed) == 7);
    check_capacity(queue, 7, 7, 0);
    ca_producer_release(&producer);
    CHECK(ca_destroy(queue) == CA_OK);
}

struct stress_context {
    ca_queue_t *queue;
    ca_producer_t *producers;
    size_t producer_count;
    size_t consumer_count;
    size_t per_producer;
    _Atomic unsigned char *seen;
    _Atomic size_t produced;
    _Atomic size_t completed;
    _Atomic size_t bound_count;
    _Atomic int start;
    size_t *producer_slots;
    size_t *consumer_slots;
};

struct stress_thread {
    struct stress_context *context;
    size_t index;
};

static void *stress_producer(void *argument) {
    struct stress_thread *thread = argument;
    struct stress_context *context = thread->context;
    ca_lifecycle_binding_t binding;
    CHECK(ca_lifecycle_bind(context->queue, &binding) == CA_OK);
    context->producer_slots[thread->index] = ca_test_lifecycle_slot(context->queue);
    atomic_fetch_add_explicit(&context->bound_count, 1, memory_order_release);
    while (!atomic_load_explicit(&context->start, memory_order_acquire)) sched_yield();
    const size_t base = thread->index * context->per_producer;
    for (size_t i = 0; i < context->per_producer; ++i) {
        const size_t id = base + i;
        while (ca_submit_one(context->queue, &context->producers[thread->index], item_id(id)) == CA_FULL) sched_yield();
        atomic_fetch_add_explicit(&context->produced, 1, memory_order_relaxed);
    }
    CHECK(ca_lifecycle_unbind(&binding) == CA_OK);
    return NULL;
}

static void *stress_consumer(void *argument) {
    struct stress_thread *thread = argument;
    struct stress_context *context = thread->context;
    const size_t total = context->producer_count * context->per_producer;
    ca_claim_item_t items[64];
    ca_completion_state_t states[64];
    ca_lifecycle_binding_t binding;
    CHECK(ca_lifecycle_bind(context->queue, &binding) == CA_OK);
    context->consumer_slots[thread->index] = ca_test_lifecycle_slot(context->queue);
    atomic_fetch_add_explicit(&context->bound_count, 1, memory_order_release);
    while (!atomic_load_explicit(&context->start, memory_order_acquire)) sched_yield();
    while (atomic_load_explicit(&context->completed, memory_order_acquire) < total) {
        ca_claim_t claim;
        if (ca_claim_up_to(context->queue, &claim, items, 64) != CA_OK) {
            sched_yield();
            continue;
        }
        for (size_t i = 0; i < claim.count; ++i) {
            const size_t id = id_of(items[i].item);
            CHECK(id < total);
            CHECK(atomic_fetch_add_explicit(&context->seen[id], 1, memory_order_relaxed) == 0);
            states[i] = CA_COMPLETE_COMMIT;
        }
        const size_t claimed = claim.count;
        CHECK(ca_complete(&claim, states) == CA_OK);
        atomic_fetch_add_explicit(&context->completed, claimed, memory_order_release);
    }
    CHECK(ca_lifecycle_unbind(&binding) == CA_OK);
    return NULL;
}

static void run_stress(size_t producer_count, size_t consumer_count) {
    const size_t per_producer = producer_count == 1 ? 20000 : 4000;
    const size_t total = producer_count * per_producer;
    ca_queue_t *queue = new_queue(1000, (unsigned)consumer_count);
    ca_producer_t *producers = calloc(producer_count, sizeof(*producers));
    _Atomic unsigned char *seen = calloc(total, sizeof(*seen));
    pthread_t *threads = calloc(producer_count + consumer_count, sizeof(*threads));
    struct stress_thread *arguments = calloc(producer_count + consumer_count, sizeof(*arguments));
    size_t *producer_slots = calloc(producer_count, sizeof(*producer_slots));
    size_t *consumer_slots = calloc(consumer_count, sizeof(*consumer_slots));
    CHECK(producers != NULL && seen != NULL && threads != NULL && arguments != NULL && producer_slots != NULL &&
          consumer_slots != NULL);
    for (size_t i = 0; i < producer_count; ++i) CHECK(ca_producer_register(queue, i, &producers[i]) == CA_OK);
    struct stress_context context = {
        .queue = queue,
        .producers = producers,
        .producer_count = producer_count,
        .consumer_count = consumer_count,
        .per_producer = per_producer,
        .seen = seen,
        .producer_slots = producer_slots,
        .consumer_slots = consumer_slots,
    };
    for (size_t i = 0; i < producer_count; ++i) {
        arguments[i] = (struct stress_thread){.context = &context, .index = i};
        CHECK(pthread_create(&threads[i], NULL, stress_producer, &arguments[i]) == 0);
    }
    for (size_t i = 0; i < consumer_count; ++i) {
        const size_t index = producer_count + i;
        arguments[index] = (struct stress_thread){.context = &context, .index = i};
        CHECK(pthread_create(&threads[index], NULL, stress_consumer, &arguments[index]) == 0);
    }
    while (atomic_load_explicit(&context.bound_count, memory_order_acquire) < producer_count + consumer_count)
        sched_yield();
    atomic_store_explicit(&context.start, 1, memory_order_release);
    for (size_t i = 0; i < producer_count + consumer_count; ++i) CHECK(pthread_join(threads[i], NULL) == 0);
    CHECK(atomic_load_explicit(&context.produced, memory_order_relaxed) == total);
    CHECK(atomic_load_explicit(&context.completed, memory_order_relaxed) == total);
    for (size_t i = 0; i < total; ++i) CHECK(atomic_load_explicit(&seen[i], memory_order_relaxed) == 1);
    if (producer_count == 16 && consumer_count == 16) {
        for (size_t i = 0; i < producer_count; ++i)
            for (size_t j = i + 1; j < producer_count; ++j) CHECK(producer_slots[i] != producer_slots[j]);
        for (size_t i = 0; i < consumer_count; ++i)
            for (size_t j = i + 1; j < consumer_count; ++j) CHECK(consumer_slots[i] != consumer_slots[j]);
        for (size_t i = 0; i < producer_count; ++i)
            for (size_t j = 0; j < consumer_count; ++j) CHECK(producer_slots[i] != consumer_slots[j]);
    }
    check_capacity(queue, 1000, 1000, 0);
    for (size_t i = 0; i < producer_count; ++i) ca_producer_release(&producers[i]);
    finish_queue(queue);
    free(arguments);
    free(consumer_slots);
    free(producer_slots);
    free(threads);
    free(seen);
    free(producers);
}

/* Model one WTI retaining bindings for its source and a target across batches.
 * Exact slots prove activation/restoration; target destroy must be BUSY while
 * the WTI binding is retained, then quiesce/destroy succeeds only after the
 * WTI cleanup path unbinds it. */
static void test_nested_lifecycle_bindings(void) {
    ca_queue_t *source = new_queue(7, 1);
    ca_queue_t *target = new_queue(7, 1);
    ca_lifecycle_binding_t source_binding;
    ca_lifecycle_binding_t target_binding;
    ca_lifecycle_scope_t target_scope;
    ca_lifecycle_scope_t source_scope;
    CHECK(ca_lifecycle_bind(source, &source_binding) == CA_OK);
    CHECK(ca_lifecycle_bind(target, &target_binding) == CA_OK);
    CHECK(ca_test_lifecycle_slot(source) == source_binding.slot);
    CHECK(ca_lifecycle_activate(&target_binding, &target_scope) == CA_OK);
    CHECK(ca_test_lifecycle_slot(target) == target_binding.slot);
    CHECK(ca_lifecycle_activate(&source_binding, &source_scope) == CA_OK);
    CHECK(ca_test_lifecycle_slot(source) == source_binding.slot);
    ca_lifecycle_deactivate(&source_scope);
    CHECK(ca_test_lifecycle_slot(target) == target_binding.slot);
    ca_lifecycle_deactivate(&target_scope);
    CHECK(ca_test_lifecycle_slot(source) == source_binding.slot);
    CHECK(ca_destroy(target) == CA_BUSY);
    CHECK(ca_lifecycle_unbind(&target_binding) == CA_OK);
    CHECK(ca_lifecycle_unbind(&source_binding) == CA_OK);
    finish_queue(target);
    finish_queue(source);
}

int main(void) {
    /* This is hang protection for the lock-free progress smoke, not a timing
     * pass criterion; every behavioral oracle remains an exact count/state. */
    alarm(120);
    test_shape();
    test_capacity_and_batch_boundaries();
    test_large_builder_publications();
    test_builder_inline_singleton();
    test_overlapping_prepared_alignment();
    test_concurrent_same_handle_prepare();
    test_transactional_chunk_oom(OOM_DIRECT);
    test_transactional_chunk_oom(OOM_RESERVED);
    test_transactional_chunk_oom(OOM_BUILDER);
    test_failed_builder_cancel();
    test_tiny_wraps_and_singleton_tail();
    test_lane_ordinal_boundary();
    test_burst_drain_singleton();
    test_stalled_reservation_and_credits();
    test_producer_handle_validation();
    test_exact_serial_capacity_model();
    test_retry_and_out_of_order_completion();
    test_multiple_retry_order();
    test_retry_barrier_race();
    test_anonymous_fallback();
    test_shared_fallback_collisions();
    test_bounded_historical_chunk_retention();
    test_dedicated_lane_reuse();
    test_release_before_drain_reuse();
    test_cancelled_claim_return();
    test_destroy_waits_inspection();
    test_destroy_refuses_live_binding();
    test_quiesce_closes_pre_cas_reader();
    test_epoch_wait();
    test_split_work_capacity_waits();
    test_capacity_release_wakes_proportionally();
    test_concurrent_quiesce_admission();
    test_quiesce_timeout_preserves_admitted_ref();
    test_nested_lifecycle_bindings();
#ifdef CA_FORCE_PTHREAD_WAIT
    test_pthread_wait_lost_wake_and_cancel();
#endif
    test_discard_quiesce();
    run_stress(1, 1);
    run_stress(8, 8);
    run_stress(16, 16);
    puts("ConcurrentArray sparseLanes focused tests passed");
    return 0;
}
