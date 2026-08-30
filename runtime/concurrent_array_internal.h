/* SPDX-License-Identifier: Apache-2.0 */

#ifndef INCLUDED_CONCURRENT_ARRAY_INTERNAL_H
#define INCLUDED_CONCURRENT_ARRAY_INTERNAL_H

#include "concurrent_array.h"

struct ca_ops {
    ca_status_t (*create)(const ca_config_t *, ca_queue_t **);
    ca_status_t (*destroy)(ca_queue_t *);
    ca_status_t (*lifecycle_bind)(ca_queue_t *, ca_lifecycle_binding_t *);
    ca_status_t (*lifecycle_unbind)(ca_lifecycle_binding_t *);
    ca_status_t (*lifecycle_activate)(ca_lifecycle_binding_t *, ca_lifecycle_scope_t *);
    ca_status_t (*lifecycle_deactivate)(ca_lifecycle_scope_t *);
    ca_status_t (*producer_register)(ca_queue_t *, uint64_t, ca_producer_t *);
    ca_status_t (*producer_register_fallback)(ca_queue_t *, size_t, ca_producer_t *);
    ca_status_t (*producer_release)(ca_producer_t *);
    ca_status_t (*reserve)(ca_queue_t *, ca_producer_t *, size_t, ca_reservation_t *);
    ca_status_t (*prepare_reserved)(ca_reservation_t *);
    ca_status_t (*commit_prepared)(ca_reservation_t *, void *const *);
    ca_status_t (*publish_reserved)(ca_reservation_t *, void *const *);
    void (*cancel_reservation)(ca_reservation_t *);
    ca_status_t (*submit_span)(ca_queue_t *, ca_producer_t *, void *const *, size_t, size_t *);
    ca_status_t (*credit_acquire)(ca_queue_t *, ca_producer_t *, size_t, ca_credit_lease_t *);
    ca_status_t (*credit_submit_span)(ca_credit_lease_t *, void *const *, size_t, size_t *);
    void (*credit_release)(ca_credit_lease_t *);
    ca_status_t (*builder_begin)(ca_queue_t *, ca_producer_t *, ca_builder_t *);
    ca_status_t (*builder_append)(ca_builder_t *, ca_credit_lease_t *, void *const *, size_t, size_t *);
    ca_status_t (*builder_prepare)(ca_builder_t *);
    ca_status_t (*builder_commit)(ca_builder_t *);
    ca_status_t (*builder_publish)(ca_builder_t *);
    void (*builder_cancel)(ca_builder_t *);
    ca_status_t (*claim)(ca_queue_t *, ca_claim_t *, ca_claim_item_t *, size_t);
    ca_status_t (*complete)(ca_claim_t *, const ca_completion_state_t *);
    ca_status_t (*return_claim)(ca_claim_t *);
    void (*capacity_read)(const ca_queue_t *, ca_capacity_snapshot_t *);
    uint32_t (*epoch)(const ca_queue_t *);
    ca_status_t (*wait_epoch)(ca_queue_t *, uint32_t, const struct timespec *);
    uint32_t (*capacity_epoch)(const ca_queue_t *);
    ca_status_t (*wait_capacity_epoch)(ca_queue_t *, uint32_t, const struct timespec *);
    void (*interrupt_waiters)(ca_queue_t *);
    ca_status_t (*quiesce)(ca_queue_t *, ca_quiesce_mode_t, const struct timespec *);
    void (*diagnostics_read)(const ca_queue_t *, ca_diagnostics_t *);
    size_t (*dedicated_lane_limit)(const ca_queue_t *);
    size_t (*fallback_lane_count)(const ca_queue_t *);
    size_t (*ready_ring_capacity)(const ca_queue_t *);
    void (*test_fail_next_chunk_allocations)(ca_queue_t *, size_t);
};

struct ca_queue {
    const struct ca_ops *ops;
};

extern const struct ca_ops ca_sparse_lanes_ops;
extern const struct ca_ops ca_bbq_ops;

#ifdef CA_TESTING
void ca_bbq_test_pause_after_faa(ca_queue_t *queue);
int ca_bbq_test_after_faa_entered(ca_queue_t *queue);
void ca_bbq_test_release_after_faa(ca_queue_t *queue);
void ca_bbq_test_pause_after_install(ca_queue_t *queue);
int ca_bbq_test_after_install_entered(ca_queue_t *queue);
void ca_bbq_test_release_after_install(ca_queue_t *queue);
void ca_bbq_test_pause_after_claim(ca_queue_t *queue);
int ca_bbq_test_after_claim_entered(ca_queue_t *queue);
void ca_bbq_test_release_after_claim(ca_queue_t *queue);
void ca_bbq_test_pause_after_record_release(ca_queue_t *queue);
int ca_bbq_test_after_record_release_entered(ca_queue_t *queue);
void ca_bbq_test_release_after_record_release(ca_queue_t *queue);
void ca_bbq_test_pause_after_discard_producer(ca_queue_t *queue);
int ca_bbq_test_after_discard_producer_entered(ca_queue_t *queue);
void ca_bbq_test_release_after_discard_producer(ca_queue_t *queue);
int ca_bbq_test_uses_futex(void);
size_t ca_bbq_test_work_sleepers(ca_queue_t *queue);
size_t ca_bbq_test_capacity_sleepers(ca_queue_t *queue);
size_t ca_bbq_test_record_blocks(ca_queue_t *queue);
void ca_bbq_test_reset_record_word_probes(ca_queue_t *queue);
size_t ca_bbq_test_record_word_probes(ca_queue_t *queue);
#endif

#endif
