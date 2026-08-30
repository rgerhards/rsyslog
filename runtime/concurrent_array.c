/* SPDX-License-Identifier: Apache-2.0 */

#include "concurrent_array_internal.h"

#include <string.h>

ca_status_t ca_create(const ca_config_t *config, ca_queue_t **queue) {
    if (config == NULL || queue == NULL || config->capacity == 0 || config->consumers == 0) return CA_INVALID;
    *queue = NULL;
    switch (config->core) {
        case CA_CORE_SPARSE_LANES:
            return ca_sparse_lanes_ops.create(config, queue);
        default:
            return CA_INVALID;
    }
}

ca_status_t ca_destroy(ca_queue_t *queue) {
    return queue == NULL ? CA_INVALID : queue->ops->destroy(queue);
}

ca_status_t ca_lifecycle_bind(ca_queue_t *queue, ca_lifecycle_binding_t *binding) {
    return queue == NULL ? CA_INVALID : queue->ops->lifecycle_bind(queue, binding);
}

ca_status_t ca_lifecycle_unbind(ca_lifecycle_binding_t *binding) {
    if (binding == NULL || binding->queue == NULL) return CA_INVALID;
    return binding->queue->ops->lifecycle_unbind(binding);
}

ca_status_t ca_lifecycle_activate(ca_lifecycle_binding_t *binding, ca_lifecycle_scope_t *scope) {
    if (binding == NULL || binding->queue == NULL) return CA_INVALID;
    return binding->queue->ops->lifecycle_activate(binding, scope);
}

ca_status_t ca_lifecycle_deactivate(ca_lifecycle_scope_t *scope) {
    if (scope == NULL || scope->binding == NULL || scope->binding->queue == NULL) return CA_INVALID;
    return scope->binding->queue->ops->lifecycle_deactivate(scope);
}

ca_status_t ca_producer_register(ca_queue_t *queue, uint64_t key, ca_producer_t *producer) {
    return queue == NULL ? CA_INVALID : queue->ops->producer_register(queue, key, producer);
}

ca_status_t ca_producer_register_fallback(ca_queue_t *queue, size_t fallback_index, ca_producer_t *producer) {
    return queue == NULL ? CA_INVALID : queue->ops->producer_register_fallback(queue, fallback_index, producer);
}

ca_status_t ca_producer_release(ca_producer_t *producer) {
    if (producer == NULL || producer->queue == NULL) return CA_INVALID;
    return producer->queue->ops->producer_release(producer);
}

ca_status_t ca_reserve(ca_queue_t *queue, ca_producer_t *producer, size_t wanted, ca_reservation_t *reservation) {
    return queue == NULL ? CA_INVALID : queue->ops->reserve(queue, producer, wanted, reservation);
}

ca_status_t ca_publish_reserved(ca_reservation_t *reservation, void *const *items) {
    if (reservation == NULL || reservation->queue == NULL) return CA_INVALID;
    return reservation->queue->ops->publish_reserved(reservation, items);
}

ca_status_t ca_prepare_reserved(ca_reservation_t *reservation) {
    if (reservation == NULL || reservation->queue == NULL) return CA_INVALID;
    return reservation->queue->ops->prepare_reserved(reservation);
}

ca_status_t ca_commit_prepared(ca_reservation_t *reservation, void *const *items) {
    if (reservation == NULL || reservation->queue == NULL) return CA_INVALID;
    return reservation->queue->ops->commit_prepared(reservation, items);
}

void ca_cancel_reservation(ca_reservation_t *reservation) {
    if (reservation != NULL && reservation->queue != NULL) reservation->queue->ops->cancel_reservation(reservation);
}

ca_status_t ca_submit_one(ca_queue_t *queue, ca_producer_t *producer, void *item) {
    void *items[1] = {item};
    size_t accepted;
    return ca_submit_span(queue, producer, items, 1, &accepted);
}

ca_status_t ca_submit_span(
    ca_queue_t *queue, ca_producer_t *producer, void *const *items, size_t count, size_t *accepted) {
    if (accepted == NULL) return CA_INVALID;
    *accepted = 0;
    if (queue == NULL) return CA_INVALID;
    return queue->ops->submit_span(queue, producer, items, count, accepted);
}

ca_status_t ca_credit_acquire(ca_queue_t *queue, ca_producer_t *producer, size_t wanted, ca_credit_lease_t *lease) {
    return queue == NULL ? CA_INVALID : queue->ops->credit_acquire(queue, producer, wanted, lease);
}

ca_status_t ca_credit_submit_span(ca_credit_lease_t *lease, void *const *items, size_t count, size_t *accepted) {
    if (lease == NULL || lease->queue == NULL) return CA_INVALID;
    return lease->queue->ops->credit_submit_span(lease, items, count, accepted);
}

void ca_credit_release(ca_credit_lease_t *lease) {
    if (lease != NULL && lease->queue != NULL) lease->queue->ops->credit_release(lease);
}

ca_status_t ca_builder_begin(ca_queue_t *queue, ca_producer_t *producer, ca_builder_t *builder) {
    return queue == NULL ? CA_INVALID : queue->ops->builder_begin(queue, producer, builder);
}

ca_status_t ca_builder_append(
    ca_builder_t *builder, ca_credit_lease_t *lease, void *const *items, size_t count, size_t *accepted) {
    if (builder == NULL || builder->queue == NULL) return CA_INVALID;
    return builder->queue->ops->builder_append(builder, lease, items, count, accepted);
}

ca_status_t ca_builder_publish(ca_builder_t *builder) {
    if (builder == NULL || builder->queue == NULL) return CA_INVALID;
    return builder->queue->ops->builder_publish(builder);
}

ca_status_t ca_builder_prepare(ca_builder_t *builder) {
    if (builder == NULL || builder->queue == NULL) return CA_INVALID;
    return builder->queue->ops->builder_prepare(builder);
}

ca_status_t ca_builder_commit(ca_builder_t *builder) {
    if (builder == NULL || builder->queue == NULL) return CA_INVALID;
    return builder->queue->ops->builder_commit(builder);
}

void ca_builder_cancel(ca_builder_t *builder) {
    if (builder != NULL && builder->queue != NULL) builder->queue->ops->builder_cancel(builder);
}

ca_status_t ca_claim_up_to(ca_queue_t *queue, ca_claim_t *claim, ca_claim_item_t *items, size_t maximum) {
    return queue == NULL ? CA_INVALID : queue->ops->claim(queue, claim, items, maximum);
}

ca_status_t ca_complete(ca_claim_t *claim, const ca_completion_state_t *states) {
    if (claim == NULL || claim->queue == NULL) return CA_INVALID;
    return claim->queue->ops->complete(claim, states);
}

ca_status_t ca_return_claim(ca_claim_t *claim) {
    if (claim == NULL || claim->queue == NULL) return CA_INVALID;
    return claim->queue->ops->return_claim(claim);
}

void ca_capacity_read(const ca_queue_t *queue, ca_capacity_snapshot_t *snapshot) {
    if (queue == NULL || snapshot == NULL) return;
    queue->ops->capacity_read(queue, snapshot);
}

uint32_t ca_epoch(const ca_queue_t *queue) {
    return queue == NULL ? 0 : queue->ops->epoch(queue);
}

ca_status_t ca_wait_epoch(ca_queue_t *queue, uint32_t observed, const struct timespec *deadline) {
    return queue == NULL ? CA_INVALID : queue->ops->wait_epoch(queue, observed, deadline);
}

uint32_t ca_capacity_epoch(const ca_queue_t *queue) {
    return queue == NULL ? 0 : queue->ops->capacity_epoch(queue);
}

ca_status_t ca_wait_capacity_epoch(ca_queue_t *queue, uint32_t observed, const struct timespec *deadline) {
    return queue == NULL ? CA_INVALID : queue->ops->wait_capacity_epoch(queue, observed, deadline);
}

void ca_interrupt_waiters(ca_queue_t *queue) {
    if (queue != NULL) queue->ops->interrupt_waiters(queue);
}

ca_status_t ca_quiesce(ca_queue_t *queue, ca_quiesce_mode_t mode, const struct timespec *deadline) {
    return queue == NULL ? CA_INVALID : queue->ops->quiesce(queue, mode, deadline);
}

void ca_diagnostics_read(const ca_queue_t *queue, ca_diagnostics_t *diagnostics) {
    if (diagnostics == NULL) return;
    memset(diagnostics, 0, sizeof(*diagnostics));
    if (queue != NULL) queue->ops->diagnostics_read(queue, diagnostics);
}

size_t ca_dedicated_lane_limit(const ca_queue_t *queue) {
    return queue == NULL ? 0 : queue->ops->dedicated_lane_limit(queue);
}

size_t ca_fallback_lane_count(const ca_queue_t *queue) {
    return queue == NULL ? 0 : queue->ops->fallback_lane_count(queue);
}

size_t ca_ready_ring_capacity(const ca_queue_t *queue) {
    return queue == NULL ? 0 : queue->ops->ready_ring_capacity(queue);
}
