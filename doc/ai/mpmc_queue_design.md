# Optional contention-distributed memory queue design

Status: draft architecture contract. No implementation is implied by this
document.

## Objective

Design an optional bounded in-memory queue core for rsyslog that:

- permits concurrent producers and consumers without a queue-wide steady-state
  mutex;
- performs well for both singleton traffic and batches through at least 65,536
  messages;
- scales usefully through 16 producers and 16 consumers, with 50 or more
  consumers as a later goal;
- does not allocate or touch excessive memory for low occupancy or singleton
  submissions;
- preserves rsyslog routing, action, retry, shutdown, and disk-assisted (DA)
  behavior;
- keeps the legacy queue engine as the default and the new engine optional.

The initial work is an algorithm bakeoff. A candidate is integrated only after
it passes deterministic ownership, progress, and memory gates. Performance
campaigns follow focused functional validation so semantic regressions are
found before expensive measurement.

## Non-goals

- No plugin callback, `smsg`, `multi_submit_t`, module ABI, or persistent queue
  format change.
- No new global FIFO guarantee between concurrent producers.
- No unified ordering guarantee between the memory parent and disk child in DA
  mode.
- No native replacement for classic or segmented disk storage in the first
  implementation.
- No `minDequeueBatchSize`; available work must be returned immediately.
- No guarantee that every accepted in-memory message survives a crash. Current
  DA durability and `queue.saveOnShutdown` semantics remain the baseline.
- No new worker model merely because one is architecturally attractive. Worker
  changes must remove a demonstrated queue serialization point.
- No promise of lock-free progress until that stronger requirement is selected
  explicitly and proven for every operation and supported architecture.

## Operational definition of contention-free

For this project, "largely contention-free" initially means all of the
following in the steady-state memory path:

- no queue-wide `pthread_mutex` in enqueue, publish, claim, or completion;
- no allocation for a warmed-up one-message submission or claim;
- no O(producers), O(consumers), O(lanes), or O(queue capacity) scan per
  operation;
- no per-message futex, condition-variable signal, or wake-all operation;
- no queue-capacity-sized publication or producer-lane metadata beyond the
  message-slot representation required by the selected algorithm;
- batch submission and claim amortize shared atomic operations;
- a stalled producer that reserved capacity cannot indefinitely hide already
  published work from unrelated producers;
- producer and consumer progress remains bounded under P1/C1 through P16/C16,
  including queue-full pushback and retry.

This is an operational scalability contract, not yet a formal nonblocking
progress classification. Lock-free, wait-free, and obstruction-free must be
used only if the exact algorithm and all paths satisfy those definitions.

## Compatibility contract

### Ownership and capacity

Each successful branch or queued action owns exactly one `smsg_t` reference or
`MsgDup()` snapshot. Ownership states are:

```text
caller -> prepared/staged -> published/runnable -> claimed -> complete/retry
```

- Submission transfers ownership only according to the existing caller
  contract. Existing immediate-drop paths continue to consume the message.
- Encounter-time snapshots are mandatory. Mutation after an earlier `call` or
  queued action must not alter that earlier branch.
- Capacity is counted in messages and includes runnable, claimed/in-flight,
  staged, and unused reserved credits.
- Accounted messages and credits must never exceed `queue.size`.
- A claim continues to consume capacity until completion.
- `BATCH_STATE_COMM` and final discard destroy the owned reference and release
  capacity.
- `BATCH_STATE_RDY` and `BATCH_STATE_SUB` remain queue-owned and become runnable
  again.
- Out-of-order completion may not reclaim storage that an earlier consumer
  still owns.
- Reservation or publication cancellation must either publish accepted work or
  return its unused capacity. It must not leak a reference or credit.

### Producer batches

- A producer publishes every available `1..N` messages immediately. Credit
  exhaustion is not a publication threshold.
- A quiet singleton and a post-burst singleton tail must run without a later
  arrival or timer.
- Existing `MultiSubmit` callers retain their known-target batch. The new core
  must not unpack it into independent public submissions.
- `multi_submit_t.nElem` remains its existing signed-short field. Private spans
  may use `size_t`, but a public ABI change is out of scope.
- Splits are allowed for capacity pressure, timeout/discard policy, memory and
  integer safety, or an unchanged backend limit. A local credit boundary alone
  does not split publication.

### Consumer batches and retry

- A consumer claims immediately any available `1..dequeueBatchSize` messages.
- A partial range tail remains runnable without another arrival.
- Source batch, publication range, dequeue batch, action transaction, and
  plugin bulk limits remain independent.
- Completion may be out of order across consumers. Retry tokens must still
  identify the original message and prevent unsafe storage reuse.
- A failed element must not be silently overtaken by later work from the same
  producer when the selected compatibility mode preserves per-producer order.

### Dynamic routing during execution

Destinations are discovered while a source message executes. Calls may be
conditional, indirect, repeated, and interleaved with message mutation.

- Maintain a target-local staging bucket for each target encountered by one
  source WTI batch.
- Preserve target-local encounter order and repeated-call multiplicity.
- Do not promise a new total order between concurrent producers.
- A single source message may call several targets with any subset full,
  suspended, or unavailable.
- Before blocking for one target, publish all branches already accepted by the
  WTI and return every unused target credit. Visit targets in encounter order
  while holding at most one target's admission state at a time. This prevents
  crossed-target reservation deadlock.
- If an earlier branch was accepted and a later allocation or admission fails,
  publish the earlier branch. Leave the source uncommitted so normal retry may
  replay it. The resulting duplicate is permitted; loss is not.
- Mark a source batch element committed only after `scriptExec()` succeeds.
- Publish staged branches before `actionCommitAllDirect()`, preserving the
  current relationship between queued submissions and direct transactions.

Current behavior does not guarantee that a fast sibling after a slow/full
target will progress. Fast-first ordering can progress before recovery;
slow-first may apply ordered pushback. Strong sibling isolation requires
continuation parking or a changed statement-execution contract and is a
separate decision.

### Ordering

- Preserve encounter order within one producer's known-target batch and within
  repeated calls to one target.
- Concurrent producer order is determined by publication/claim races and gains
  no new total-order guarantee.
- Multiple consumers may execute and finish out of order.
- DA mode explicitly has no unified memory/disk FIFO guarantee.
- Direct rulesets and actions remain synchronous, including their message
  mutation visibility.

### Actions and plugin transactions

- Direct actions remain unchanged.
- Filtering, action rate limiting, repeat handling,
  `execOnlyWhenPreviousIsSuspended`, `bCopyMsg`, and snapshot decisions remain
  before queued admission.
- Preserve per-worker action state and existing `beginTransaction`, parameter
  preparation, `commitTransaction`, resume, retry, suspend, disable, rollback
  limitations, and error-file behavior.
- A transactional callback may receive 8,192 or 65,536 parameters when all
  independent limits permit it.
- Transaction order remains `BEGIN`, contiguous message parameters, `COMMIT`.
- Current failure handling may split a failed transaction to individual
  messages to distinguish permanent data errors from suspension.
- If immediate shutdown interrupts transactional retry, its claimed elements
  become ready again.
- Delivery remains at least once. Duplicates are permitted at retry,
  cancellation, and restart boundaries; accepted messages may not disappear.

### Reload and configuration lifetime

- Capture the execution-engine selector and configuration pointer once at
  source-batch entry.
- Every queue, action, lane, token, and callback target must outlive its staged
  and claimed work.
- Shutdown and configuration teardown quiesce producers and consumers before
  freeing queue-core state.
- Worker timeout/restart may reuse a WTI object but may not create pointer-based
  ABA. Stable producer identities need an explicit generation or
  configuration-lifetime guarantee.
- No statement may reread a different active selector halfway through a source
  batch.

### Worker wakeup, retirement, and shutdown

The legacy WTI/WTP loop holds the queue's user mutex while evaluating work and
claiming a batch. A new store beneath that loop would still serialize
consumers. The optional queue therefore needs a claim/wait adapter while
retaining existing action worker state and callbacks initially.

- Use an eventcount or epoch predicate so a worker cannot miss an
  empty-to-nonempty transition.
- Wake one worker immediately for singleton work.
- Amortize additional wakes from visible ready work and backlog.
- Do not scan all workers or lanes and do not wake all workers in normal
  operation.
- Preserve bounded fairness so a hot producer cannot permanently starve a cold
  one.
- Preserve idle retirement and stable per-worker plugin state.
- Graceful shutdown first stops admission, publishes accepted staged work, and
  lets workers drain within the existing timeout.
- Immediate shutdown stops new claims, completes or returns in-flight claims,
  and enters existing timed cooperative/hard cancellation.
- Storage, tokens, lanes, and configurations are freed only after every worker
  is joined.

## FixedArray plus DA compatibility baseline

The baseline is the existing `FixedArray` memory queue with a disk queue
backend. The disk child is not required to adopt the new memory algorithm.

### Admission and activation

- The FixedArray parent applies `queue.size`, flow-control marks, enqueue
  timeout, and severity-discard policy.
- Defining `queue.filename` enables DA and creates a first-class classic or
  segmented disk child when needed.
- Reaching the high watermark activates one DA transfer worker.
- The parent regular consumers and DA transfer worker may run concurrently.
  One may process a parent message directly while the other spills another
  message. This is why DA has no memory/disk ordering guarantee.

### Spill and drain

- The transfer worker claims up to the configured dequeue ceiling from the
  memory parent and submits messages to the child.
- A parent element is completed after child admission according to the
  existing child-backend behavior. Retryable segmented-child failures leave
  the current and remaining parent elements ready.
- The transfer worker stops when the memory parent reaches the low watermark.
- New messages may remain in memory until the next high-water transition. If
  the disk child drains, the queue may return to memory-only processing.
- The disk child has its own regular consumer pool and preserves its existing
  retry, commit-frontier, corruption, checkpoint, and idle-dematerialization
  behavior.
- The parent and existing child currently share a queue mutex. The new memory
  core must instead expose a narrow DA adapter; it must not hold an internal
  memory-core lock during disk serialization or I/O.

### Pressure and durability

- If child admission blocks or fails, untransferred messages remain or become
  runnable in the parent. Parent exhaustion eventually applies normal producer
  wait, timeout, or discard policy.
- Parent message-count capacity and disk byte capacity remain separate.
- Existing child data may replay while new messages are accepted in memory.
  No order is promised across that boundary.
- Only child records already made durable survive an ungraceful process or
  system failure.
- With `queue.saveOnShutdown="on"`, orderly shutdown quiesces workers and
  transfers remaining parent messages to the child. With it off, remaining
  memory messages may be discarded as today.
- Preserve the current `.qi`, segmented store, engine marker, corruption,
  quarantine, encryption, and restart formats unchanged.

## Candidate A: sparse producer lanes with SCQ ready tokens

This candidate uses sparse producer-target lanes and a bounded MPMC ready-token
queue based on the Scalable Circular Queue (SCQ) family.

### Shape

- An explicit producer token or stable WTI identity owns an SPSC lane for each
  target it actively touches.
- Lane storage comes from a bounded pool of fixed-size blocks or compact spans;
  it is allocated lazily and recycled after quiescence.
- A transition from no runnable work to runnable work enqueues exactly one lane
  token in the SCQ ready queue.
- A consumer dequeues a token, claims up to its dequeue ceiling, and re-enqueues
  one token if the lane remains runnable.
- Known-target producers without an explicit token use a small set of central
  fallback lanes, not one global mutex-protected lane.
- An atomic capacity semaphore bounds messages across lane blocks, staged
  entries, and credits.

### Expected strengths

- Producers usually modify producer-local cache lines.
- Empty targets consume no capacity-sized lane arrays.
- Published batches remain natural ranges.
- Ready work is O(1) and fairness can be expressed by token rotation.
- The design resembles the useful part of Phase 4 without its capacity-sized
  metadata or central queue mutex.

### Risks to prove

- Sparse producer-by-target growth must remain bounded and reclaimable.
- Token duplication, loss, ABA, and lane destruction need explicit
  generations and quiescence.
- One held block per sparse lane may still make singleton fan-out expensive.
- Consumer retry must preserve the original lane's ordering.
- The SCQ implementation and memory ordering must be independently reviewed;
  do not copy code with incompatible licensing.
- Central fallback lanes must not become a new producer hotspot.

## Candidate B: block-based bounded ring (BBQ)

This candidate uses a bounded ring partitioned into cache-sized blocks, based
on the block-based bounded queue (BBQ) family.

### Shape

- Producers reserve positions within the current block and publish completed
  positions with per-block metadata.
- Consumers claim published positions from the current consumer block and
  advance between blocks with amortized shared atomics.
- Single submissions use one slot; batch submissions reserve or publish a
  contiguous portion of a block where possible.
- Block state and sequence/generation fields distinguish empty, reserved,
  published, claimed, and reusable cycles.
- Capacity is fixed and comprehensible; no publication descriptor exists for
  every possible singleton.

### Expected strengths

- Compact bounded storage with good cache locality.
- Shared producer/consumer-index traffic is amortized over a block.
- No persistent producer-target lane metadata.
- Potentially lower low-occupancy overhead than the current BatchArray plus
  producer-lane layout.

### Risks to prove

- A producer stalled after block reservation must not prevent unrelated
  published work from becoming visible indefinitely.
- Partial publication and holes complicate immediate singleton visibility.
- Large batches crossing block and ring boundaries must remain safe.
- In-place retry and per-producer order are less natural than in sparse lanes.
- Highly contended block transitions may become the global hotspot at P16.
- Wrap and generation arithmetic need deterministic reduced-width tests.

## Common prototype API

Both candidates must implement the same private experimental interface:

```text
submit_one(message, producer_token)
submit_span(messages, count, producer_token)
claim_up_to(batch, maximum)
complete(batch, per_element_state)
capacity_snapshot()
wait_epoch(observed_epoch, deadline)
wake_for_ready(ready_delta)
quiesce(mode, deadline)
```

This API is a prototype contract, not a proposed public C ABI. Ownership and
capacity transitions must be explicit in each call's implementation notes.

## Staged plan

### Stage 0: freeze contracts and evidence

- Persist this contract and an append-only lab notebook.
- Freeze current-main, Phase 2, and best Phase 5 build identities.
- Retain Phase 1-5 semantic tests as compatibility oracles.
- Add a small serial reference model for ownership and capacity histories.

Gate: every pending semantic decision below is answered or explicitly scoped
out of the first prototype.

### Stage 1: standalone algorithm bakeoff

Implement both candidates outside the rsyslog execution engine behind the
common private API.

Focused functional tests:

- capacities `1,2,3,7,8,15,16,17` and millions of reduced-size wrap cycles;
- batch boundaries `1,2,3,7,N-1,N,N+1,128,1000,4096,8192,16384,65536`;
- burst, complete drain, then an isolated singleton;
- a producer stalled between reservation and publication;
- mixed commit and retry with consumers completing out of order;
- cancellation during reservation, claim, and completion;
- P/C `1/1`, `2/2`, `8/8`, and `16/16` exact ownership histories;
- randomized histories checked against the serial capacity/ownership model;
- ASan/UBSan and TSAN after deterministic tests pass.

Screening measurements:

- throughput and CPU nanoseconds per message;
- atomic compare/exchange retries and failed ready-token operations;
- futex calls, context switches, cache misses, and cache-to-cache movement;
- RSS/PSS and allocator totals at configured capacity 1K, 50K, and 1M with
  occupancy 0, 1, 128, and full.

Gate: select no winner unless correctness is clean and its scaling and memory
direction clearly improve on a simple sequence-numbered MPMC reference.

### Stage 2: optional queue and claim/wait adapter

- Add an opaque queue-core pointer and an experimental configuration selector.
- Keep legacy as the default.
- Adapt WTI/WTP claim and sleep handling so new-core claims do not occur under
  `queue->mut`.
- Preserve existing `batch_t`, consumer callbacks, WTI action state, worker
  start/idle retirement, and shutdown timeouts.
- Integrate the main queue and one queued ruleset only.

Gate: exact singleton, tail, partial batch, retry, cancellation, shutdown, and
W1/W8/W16 behavior, with no public interface or persistent-format change.

### Stage 3: batching and dynamic routing

- Route known-target `MultiSubmit` directly to `submit_span`.
- Adapt the Phase 1 WTI target ledger to the new core.
- Use inline or pooled bucket storage rather than capacity-sized metadata.
- Preserve all-target pressure publication, credits, snapshots, repeated calls,
  and permitted duplicate replay.

Gate: conditional and indirect routing; repeated target calls; 2/3/6 targets;
any target subset full; crossed pressure; late OOM; and exact `1..65536` batch
behavior.

### Stage 4: bounded queued actions

- Use the same new core for memory-only queued actions.
- Keep Direct actions and unsupported queue types on legacy adapters.
- Preserve action transaction and retry state without changing callbacks.

Gate: full 8,192 and 65,536 transaction callbacks, suspension/recovery,
transaction interruption, fast/slow siblings, and accepted-set multiplicity.

### Stage 5: DA adapter

- Connect the new memory parent to the unchanged classic or segmented child.
- Use one spill mover and a private child batch adapter where safe.
- Never hold memory-core synchronization across disk I/O.
- Preserve existing unordered simultaneous direct consumption and spill.

Gate: high/low transitions, repeated spill/drain, child pressure/failure,
classic and segmented children, startup replay, orderly save, immediate stop,
restart, and no accepted-message loss. Compare sets and multiplicities, not DA
ordering.

### Stage 6: promotion campaign and later scale

- Run P/C `1,2,8,16` for queue-only and end-to-end ruleset/action/plugin paths.
- Test singleton and large-batch traffic at empty, low, and sustained occupancy.
- Alternate baseline/candidate order and retain raw CPU, lock, cache, wake, and
  memory evidence.
- Treat P/C 32, 50, and 64 as a separate follow-up after P16 and memory gates
  pass.

Gate: all correctness, compatibility, memory, latency, and performance gates
must repeat in two sessions before enabling the engine by default is discussed.

## Measurable gates

The initial recommended gates are:

- exact ownership and delivery under every focused test; expected pushback is
  evidence, unexpected discard is failure;
- no queue-wide mutex, O(N) scan, steady-state singleton allocation, or normal
  per-message wake syscall in the new core;
- singleton median latency no worse than `max(1.10 * baseline, baseline +
  250us)` and p95 no worse than `max(1.20 * baseline, baseline + 1ms)`;
- no singleton or tail depends on a later arrival;
- queue-only throughput at P1/C1 no worse than 95% of FixedArray;
- clear scaling through P8/C8 and P16/C16, with no producer or consumer
  starvation; establish the numeric efficiency threshold after calibration on
  the shared host;
- large-batch end-to-end throughput at least 20% above the best retained Phase
  5 configuration before promotion;
- queue/futex/system-CPU work at least 20% lower in selected contention cells;
- metadata target at most approximately 16 bytes per configured message slot,
  plus O(active producers + consumers + live ranges), pending user approval;
- occupancy-one RSS/PSS growth no more than 10% over FixedArray at the same
  capacity, unless a documented throughput tradeoff is approved;
- existing plugin source compiles unchanged and disk records restart unchanged;
- TSAN, cancellation, graceful/immediate shutdown, and PR-ready validation pass
  before a retained implementation is called complete.

## Reuse from the Phase 1-5 experiments

Retain:

- Phase 1 WTI batch lifecycle, dynamic target bucketing, encounter-time
  snapshots, accepted-work publication, and crossed-target pressure tests;
- Phase 2 message-count credit invariant and return-unused discipline;
- Phase 3 range abstraction, partial-tail contract, `batch_t` adapter, and
  retry/completion tests;
- Phase 4 stable producer identity, empty-to-ready token concept, fairness, and
  original-lane retry tests;
- Phase 5 queued-action seam, transaction tests, pushback journal, multiplicity
  oracle, and legacy persistent adapters.

Replace or discard:

- Phase 3's capacity-sized descriptor ring and queue-wide range mutex;
- Phase 4's capacity-sized slot/lane/completion arrays and permanently retained
  sparse lanes without a reclaim policy;
- any implementation that leaves the legacy WTI/WTP queue mutex around new-core
  claims;
- BatchArray as currently laid out. Its semantic tests remain valuable even if
  its storage does not.

## Pending user decisions

1. **Progress definition.** Must the implementation provide a formal lock-free
   progress guarantee, or is the operational no-global-lock/no-scan P16 contract
   sufficient? **Recommendation:** use the operational definition first and
   classify formal progress only after selecting and proving an algorithm.
2. **Slow sibling isolation.** Must a fast target later in one source message
   progress while an earlier target is full? **Recommendation:** preserve
   current ordered pushback initially; make continuation parking a separate
   optional phase.
3. **Memory ordering.** Is per-producer target-local FIFO sufficient without a
   global producer order? **Recommendation:** yes; retain explicit unordered DA
   behavior.
4. **Memory gate.** Is approximately 16 bytes/configured slot plus active-state
   metadata acceptable, with occupancy-one RSS/PSS within 10% of FixedArray?
   **Recommendation:** adopt both limits for the bakeoff and revisit only for a
   measured large benefit.
5. **Architecture scope.** May x86-64 be the first performance target while all
   supported platforms remain correct? **Recommendation:** yes, but review C11
   memory ordering and run at least one ARM correctness/sanitizer lane before
   promotion.
6. **DA durability.** Should crash durability remain current behavior: only
   records admitted to the disk child are durable, while the memory parent is
   saved only during orderly shutdown? **Recommendation:** yes.
7. **Configuration surface.** Should the first prototype be a new queue type or
   one `executionEngine`-style selector? **Recommendation:** use one clearly
   experimental engine selector until storage and worker choices stabilize;
   avoid exposing algorithm names as permanent configuration.

## 2026-08-30 standalone sparseLanes implementation addendum

The first sequential candidate now has a private, candidate-neutral C boundary
in `runtime/concurrent_array.h`. It is deliberately non-installed and contains
no `smsg_t`, `multi_submit_t`, plugin callback, disk record, or module ABI type.
Only `CA_CORE_SPARSE_LANES` is implemented; BBQ and daemon integration remain
future checkpoints.

The standalone implementation fixes these prototype decisions:

- dedicated lane metadata is `max(16, 4 * consumers)` and fallback metadata is
  `next_power_of_two(2 * consumers)`;
- ready-ring size is the next power of two covering lanes plus consumers, so it
  is independent of configured message capacity;
- a dedicated producer starts with one embedded singleton-capable range and
  later reuses stable range nodes only after completion and an API-operation
  quiescent point;
- spans use one inline pointer followed by lazily allocated 64-pointer chunks
  and remain one logical range while consumers claim immediate `1..N` slices;
- direct reservations and leases count against exact message capacity, leases
  are capped at 64 credits, and their aggregate unused count is strictly below
  half the configured capacity;
- the ready ring is an independently written bounded, per-cell
  sequence-tagged MPMC ring with SCQ-style cycle sequencing. This is not a copy
  of published SCQ source and does not claim SCQ's formal progress proof;
- successful completion is atomic-only. Retry uses an intrusive per-slot FIFO
  behind a per-lane atomic flag, creates a lane-local barrier, and is explicitly
  outside the successful steady-state progress claim;
- Linux waits use `FUTEX_WAIT_PRIVATE`/`FUTEX_WAKE_PRIVATE`; the portable path
  uses a pthread condition variable with the same monotonic epoch predicate;
- shutdown is the only path that scans lanes. Normal reserve, publish, claim,
  complete, and wake paths do not scan lane, worker, or capacity arrays.

The implementation currently satisfies the operational contention-free
definition only. Formal lock-free classification, rsyslog WTI/WTP integration,
dynamic routing, queued actions, DA, configuration syntax, sanitizers, static
analysis, containers, and performance selection remain deferred.

## 2026-08-30 independent-review repair addendum

The earlier standalone addendum describes the rejected first implementation.
The repaired candidate keeps the private boundary but replaces its storage,
lifecycle, ready-token, credit, and retry internals:

- A generation admission gate with cache-separated role counters covers handle,
  reservation, credit, publication, claim, completion, and wait entrances.
  Quiesce changes the generation before closing admissions, waits entrants, and
  closes reserved-handle publication for discard. Destroy additionally rejects
  live producers, reservations, leases, builders, claims, or waiters.
- A lane is now an ordinal log. Ordinal zero is inline and later entries occupy
  lazy reusable 64-pointer chunks. The compact 16-byte slot metadata contains
  only state, chunk offset, and retry link. Repeated singleton submission uses
  warmed lane storage; no singleton allocates a range object. Claims coalesce
  adjacent publications up to the requested ceiling.
- The builder API moves credits from multiple at-most-64 leases into one staged
  logical span. Credit exhaustion does not publish; one builder publication can
  contain 4,096, 8,192, 65,536, or more messages, subject to exact configured
  capacity and checked host-size/ordinal arithmetic.
- Retry insertion and normal claim reservation share the short lane gate.
  Failed slots are ordered by original ordinal, the earliest unfinished retry
  is the lane frontier, and later work is barred regardless of completion
  order. Multiple claims from the lane still execute concurrently outside the
  gate, and completion aggregates global count/epoch work per claim.
- The ready primitive is now an isolated bounded SCQ-family ticket/cycle queue
  with catch-up/tombstone helping. It is not the earlier simple sequence ring
  and is not a verbatim Nikolaev SCQ or a claim of that proof. Its private
  limits are 65,535 cells and `UINT32_MAX` tokens; sparseLanes uses only stable
  lane indices, and ring size remains derived from lanes plus consumers rather
  than message capacity.
- Per-lane token publication enqueues before changing `ABSENT` to `QUEUED`; a
  racing consumer may change either `ABSENT` or `QUEUED` to `OWNED`. There is
  no state-before-token hole, and at most one token is admitted for a lane.
- Linux steady state uses a private futex epoch. The pthread fallback protects
  its predicate and signal with the wait mutex and installs cancellation
  cleanup for mutex, sleeper, waiter, and lifecycle counts. That mutex is only
  the portable sleep adapter; it does not protect lane storage or claims.

The ordinary Linux submit/publish/claim/completion paths have no queue-wide
pthread mutex and do not scan producers, consumers, lanes, or message capacity.
They do use the role-sharded lifecycle counter, exact-capacity atomics, the SCQ
ready primitive, and one short per-lane atomic-flag section. The forced pthread
adapter briefly takes its wait mutex when changing/signalling the epoch, as
required for its lost-wake predicate.

## 2026-08-30 third-review lifetime and contention addendum

This entry corrects the previous private token and lifetime limits and fixes
the remaining standalone integration blockers:

- Chunk growth is transactional. Publication snapshots the original lane
  chain and hint, prepares slots without reclaiming, and only reclaims after the
  entire span is ready. Allocation failure clears prepared slots, detaches all
  additions, restores the exact head/tail/hint, and recycles those chunks before
  returning capacity. Direct, reserved, and builder publication share this
  path.
- Idle retention is bounded per lane: at most one tail and one pooled chunk.
  Extra completed chunks are freed. Thus historical peaks across many lanes do
  not multiply resident chunks; live and pooled counts are available through
  compiled-out diagnostics and standalone test hooks.
- Ready tokens are now 16-bit lane indices. The SCQ cell therefore has a
  47-bit generation rather than the previous 31-bit generation, giving a
  capacity-scaled ticket horizon of roughly `2^63` at maximum ring size. The
  generic primitive rejects tokens above `UINT16_MAX`; sparse queue creation
  rejects a lane shape that cannot fit. Overflow remains explicit rather than
  wrapping or aborting at the old realistic boundary.
- Lifecycle reader accounting is role-specific and cache-separated across at
  least 64 per-worker slots. One process-wide FAA assigns a thread slot once;
  steady submit/publish/claim/completion operations RMW only that worker's role
  line. The shared lifecycle generation is read on entry and changed only by
  quiesce/destroy. Those writer paths alone scan reader slots.
- Capacity, epoch, diagnostics, and shape reads use an inspection role.
  Destruction closes the generation and waits admitted inspectors before
  freeing the core. As with all C object APIs, no new call may begin after a
  successful destroy returns.
- Quiescent dedicated lanes return to the handle allocator with a new 64-bit
  generation. Release with live lane work marks reuse pending; the last terminal
  completion resets inline/chunk state and publishes the reusable assignment.
  Fallback lanes remain stable queue-lifetime shared shards.
- `ca_return_claim()` is the explicit cancellation handoff: every item in an
  active claim is returned to its original lane retry frontier. A claim owner
  must call either `ca_complete()` or `ca_return_claim()` exactly once; future
  WTI cleanup handlers can use the latter without allocating.

The ordinary path still shares the exact-capacity atomics and SCQ ticket words,
because those are the bounded queue's global invariants. It no longer shares a
single lifecycle PUBLISH or CLAIM counter between workers.

## 2026-08-30 final standalone lifecycle correction

This section supersedes the third-review lifecycle-table description. A
queue-local counter cannot make a raw queue pointer safe before the caller's
first atomic access. The candidate therefore uses an explicit, enforceable
worker-lifetime contract instead of claiming that internal admission alone
solves concurrent destruction:

- Each worker/shard has one 64-byte-aligned lifecycle slot. Its single 64-bit
  atomic word packs a high closed bit and a low 63-bit active-reader count. An
  ordinary call performs one CAS on its shard if open and one decrement on
  exit; it does not touch a role-global counter or scan any table.
- Quiesce/destroy serializes writers, atomically sets the closed bit in every
  slot, and then waits the packed reader counts. Existing `accepting`,
  `publishing`, `claiming`, and `waiting` flags preserve selective drain and
  discard semantics; only lifecycle writers scan slots.
- The minimum 64-slot table is allocated by checked `posix_memalign`, consumes
  exactly 4 KiB, and is explicitly freed. Stable WTI/WTP threads can call the
  candidate-neutral `ca_lifecycle_bind()` once, receive a unique slot, and
  unbind after their last queue call. Destroy returns `CA_BUSY` while any such
  binding lives.
- TLS-modulo slot selection remains only a standalone convenience. It does not
  promise uniqueness, and an unbound caller must not overlap `ca_destroy()`.
  Queue-local state cannot protect a caller paused before its first access;
  integration must join/unbind workers before freeing the core.
- A deterministic pause between slot selection and the packed-word admission
  CAS verifies the quiesce race: closure wins the CAS, changes the selective
  flags, and the delayed submission returns `CA_CLOSED` without publication.

Direct, reserved, and builder OOM recovery now asserts exact recovered message
identity and lane order, not only counts. A failed builder publication is also
canceled and followed by exact singleton and multi-item recovery. Dedicated
producer release before drain keeps the old lane generation unavailable until
its ordered work completes, after which registration reuses the index with a
new generation.

Claim cancellation remains a caller contract rather than implicit magic:
asynchronous pthread cancellation is prohibited around core calls. A
deferred-cancellation worker disables cancellation across `ca_claim_up_to()`
until it has installed cleanup that invokes `ca_return_claim()`; future WTI
integration must preserve this handoff.

### Checkpoint 3 multi-queue binding obligation

The standalone binding uses one TLS binding pointer, so a thread can be
explicitly bound to only one ConcurrentArray at a time. Dynamic routing will
make one Main/ruleset worker touch several target queues; leaving those target
calls on provisional TLS-modulo slots would lose both guaranteed uniqueness and
the destruction lifetime contract. Before enabling dynamic routing, Checkpoint
3 must let Main/ruleset assign stable producer/worker lifecycle slots across
all target queues used by that worker (for example, a per-worker binding table
owned and joined with WTI/WTP lifetime). This is an integration requirement,
not a property claimed by the standalone singleton TLS adapter.

## 2026-08-30 Checkpoint 3 qqueue and worker integration

Checkpoint 3 integrates only source queues: explicit Main and named ruleset
queues can select `queue.type="ConcurrentArray"` together with the mandatory
`queue.concurrentCore="sparseLanes"`. The qqueue owns the opaque core and
routes single submission plus the existing `MultiEnq` adapter into it. The
adapter deliberately submits existing multi-submit entries one at a time;
Checkpoint 4 will preserve their logical batch in the core builder interface.

The WTP integration is an opt-in worker-mode branch. FixedArray, LinkedList,
disk, segmentedDisk, and Direct workers keep the old user-mutex loop. A
ConcurrentArray WTI instead:

- binds one lifecycle shard to its source queue at worker activation and
  unbinds after returning any final active claim;
- allocates one reusable claim-item/completion buffer sized to the configured
  dequeue ceiling;
- completes the previous batch, claims immediately up to that ceiling, and
  runs the existing consumer without taking qqueue's user mutex;
- waits on the core monotonic epoch (private futex on Linux, the core pthread
  predicate adapter elsewhere); and
- enables deferred cancellation only around the existing consumer. The outer
  worker cleanup is installed before claim admission and calls
  `ca_return_claim()` before lifecycle unbind.

The source queue remains the only explicitly bound ConcurrentArray for a WTI
in this checkpoint. This is sufficient for Main and named-ruleset consumption.
Checkpoint 4/5 dynamic target/action routing must introduce a per-WTI binding
table or equivalent stable bindings before one worker can call several target
queues; it must not leave those calls on provisional TLS-modulo slots.

Configuration rejects missing or unknown cores, including `bbq`, instead of
falling back. Disk/DA/encryption/persistence parameters, sampling,
minimum-dequeue batching, dequeue slowdown, and dequeue time windows are also
rejected for this type. Legacy queue directives are not partially exposed.
BBQ selection, DA fallback, actual-core diagnostics, native MultiSubmit spans,
and action/target multi-queue binding remain later checkpoints.

## 2026-08-30 Checkpoint 3 ownership, ordering, and scaling correction

This section supersedes Checkpoint 3's provisional anonymous-submission and
worker-start allocation details:

- Each ConcurrentArray qqueue pre-registers an O(consumers) table of dedicated
  producer handles. A submission thread receives one process-wide stable key
  on its first ConcurrentArray call and maps that key to the same queue-local
  producer handle thereafter. A complete existing `MultiEnq` call holds one
  such handle for all entries. Shared-slot collisions may serialize briefly in
  a lane, but they cannot reorder one submitter's stream; queue submission no
  longer passes a null producer or rotates one stream across fallback lanes.
- The existing `MultiEnq` adapter remains per-entry until Checkpoint 4, but its
  ownership is exact. The qqueue takes ownership of every entry on call. A
  terminal core failure destroys the current unpublished message, and a fatal
  adapter exit also counts and destroys the untouched suffix before the caller
  clears `nElem`. Queue-full policy retains its existing discard accounting.
- Queue size, impstats size/max, and the process-wide queue-size mirror are
  accounted before core publication and rolled back on failure. A consumer
  that claims and completes immediately therefore cannot race publication into
  a size underflow. ConcurrentArray max-size uses an atomic CAS; legacy
  `ctrMaxqsize` remains under the legacy queue-mutex contract.
- Publisher-side scaling reads only the atomic backlog and immutable queue
  configuration, serializes worker creation with `mutThrdMgmt`, and invokes a
  ConcurrentArray-only WTP start-missing helper. Already-running workers are
  woken by the core epoch, so ordinary advice neither takes the qqueue user
  mutex nor scans/signals the WTI slot table. Legacy WTP advice is unchanged.
- Claim-item and completion arrays are allocated when the WTP constructs its
  WTI pool, before the queue admits messages. Worker activation only installs
  its source lifecycle binding. Partial WTP construction is destructible, and
  a deterministic preallocation failure proves startup fails before admission
  rather than accepting work that has no runnable consumer.
- Default-off test hooks can fail one sparse-lane lazy-chunk allocation when a
  configured message identity reaches publication. The normal path does not
  consult the environment. Exact single and existing-MultiEnq tests prove the
  failed identities are destroyed once, successful prefixes remain owned by
  the core, and a later independent singleton recovers.

The source-queue lifecycle binding remains one binding per WTI. Stable
producer/worker bindings across several dynamic target queues are still a
Checkpoint 4 obligation and must precede dynamic routing.

## 2026-08-30 Checkpoint 3 final integration clarifications

- Full- and light-delay watermark waits snapshot the core epoch before their
  final atomic backlog predicate check. A completion in that interval changes
  the epoch, so the subsequent wait cannot miss the transition and sleep until
  its deadline on an already-satisfied predicate.
- Core names are accepted case-insensitively and queue reload equality now
  compares them case-insensitively as well. A spelling-only case change cannot
  force replacement of an otherwise identical live queue.
- Default-off lifecycle test markers are cached at queue construction and emit
  only during successful worker unbind and successful core destruction. They
  add no ordinary-path branch and let immediate-shutdown tests distinguish a
  bounded process exit from a correctly completed binding/storage lifetime.

## 2026-08-30 Checkpoint 3 startup and accounting closure

The ConcurrentArray start path is transactional. Failure after core creation,
including failure before the WTP worker-pointer array exists or during an
individual WTI's reusable claim-buffer construction, destroys the partial WTP,
releases every producer handle, quiesces and destroys the core, tears down
start-owned synchronization, and resets the queue-start state. The existing
Main-queue Direct fallback can then reuse the object without double-initialized
statistics helpers or leftover ConcurrentArray ownership. `wtpDestruct()`
accepts both a null worker-pointer array and null entries in a partial array;
that is also safe for legacy WTP construction failures.

Terminal queue-size accounting now occurs from the core disposal callback,
before the core returns the item's exact capacity credit. Retry and claim
return do not dispose and therefore do not decrement. Quiesce-discard disposes
each remaining published item once. Admission reserves one non-visible core
credit, preaccounts the qqueue and process-wide mirrors, and then publishes;
failed publication rolls those mirrors back on the publisher. This ordering
keeps normal capacity and `maxqsize` bounded by the configured capacity. A
remaining Checkpoint 4 API obligation is a split prepare/commit publication
operation: on the rare lazy-chunk OOM path, core reservation cancellation
returns capacity immediately before qqueue's caller-side mirror rollback, so a
simultaneous successful admission can transiently raise only the diagnostic
mirror above capacity even though core ownership and physical capacity remain
exact.

The queue pre-registers the complete bounded producer shape: the dedicated
limit followed by the fallback-lane count. Stable submitter identities 1..D
map exactly to dedicated handles 0..D-1; every later identity, including churn
beyond D+F, hashes only over the F fallback handles. This preserves one
caller's order, prevents excess identities from stealing dedicated lanes, and
requires no per-submit allocation. A default-off key-bias hook verifies the
beyond-D+F fallback integration; it is not read on the normal submission path.
Cross-target stable producer and lifecycle binding is still required before
Checkpoint 4 dynamic routing.

Single-enqueue dispatch is bound once at queue start. The compatibility
`qqueueEnqMsg()` entry point performs an indirect call to the bound legacy or
ConcurrentArray implementation and contains no queue-type selector. The legacy
implementation retains its prior mutex/storage path. ConcurrentArray's raw
`qAdd` entry is assert-unreachable because bypassing reservation/preaccounting
would make terminal disposal underflow the qqueue mirrors.

Atomic-helper fallback mutexes remain alive through the type-specific queue
destructor. Consequently ConcurrentArray quiesce-discard can execute disposal
and size decrements safely on platforms where the integer operations use the
pthread helper; the helpers are destroyed only after `qDestruct()` returns.

## 2026-08-30 Checkpoint 4 native spans and reserved routing

Checkpoint 4 makes the existing private `MultiEnq` adapter preserve each
roomy, same-flow-control prefix as one core reservation and one logical range.
The core split publication contract is now `reserve`, `prepare`, account, and
infallible `commit_prepared`. Preparation obtains every lazy chunk before the
qqueue mirrors become visible; allocation failure cancels the reservation and
destroys the still-unpublished span exactly once. Partial capacity accepts the
largest available prefix, publishes it immediately, and repeats the existing
pressure policy for the suffix. A completed call performs one final worker
advice operation, while a one-message call remains immediately runnable.

The builder equivalent separates `builder_prepare` from `builder_commit`.
Builders may consume consecutive credit leases without publishing, including
logical ranges well above the 64-credit lease ceiling. Every lease contains
one mandatory admission credit; only its optional lookahead credits count
toward the queue-wide speculative-unused bound below half capacity. This lets a
capacity-one target make progress without weakening the speculative-credit
limit. Prepared chunks are detached transactionally and returned on cancel,
so failed preparation cannot expose a partial range or change ownership.

One source WTI now retains a dormant lifecycle binding and stable producer
handle for every ConcurrentArray target it has touched. `ca_lifecycle_activate`
and `ca_lifecycle_deactivate` explicitly nest a target binding over the
thread's source binding and restore the previous binding afterward. Target
bindings therefore never use TLS modulo selection, remain live across batches,
and are destroyed before source-worker cleanup. Queue/config ownership must
still join and destroy source WTIs before destroying their target queues; the
core does not promise raw-pointer-safe concurrent destruction without this
external lifetime contract.

`global(executionEngine="reservedBatch")` opts queued ruleset calls and queued
actions into target-local WTI builders. Each call snapshots the message at the
call site, so repeated destinations, indirect destinations, and intervening
mutations retain program order and value semantics. On target pressure, the
WTI publishes every earlier bucket before it blocks on the pressured target;
unused credits are returned per target and no target-global routing lock is
introduced. Direct actions and the legacy execution engine remain unchanged.
For this checkpoint every asynchronous target and the Main source queue must
be `ConcurrentArray` with `sparseLanes`; unsupported queue modes are rejected
during configuration instead of silently falling back.

Cancellation is disabled while a target builder is mutated or published. WTI
cleanup cancels all still-unpublished target builders, rolls back their queue
mirrors, and destroys each snapshot once before the source claim is returned.
If an end-of-batch target publication fails, source elements already marked
committed are restored to ready state so retry is at-least-once: an earlier
target bucket that already published may be duplicated, but accepted work is
not lost. Successful target preparation can be committed without a later
allocation failure, closing the Checkpoint 3 diagnostic-mirror race.

The testbench build exposes four atomic qqueue adapter counters only under
`ENABLE_IMDIAG`: native-Multi reservation attempts, successful logical
publications, published items, and worker advice calls. An rsyslogd startup
control-file hook constructs exact existing `multi_submit_t` calls after Main
workers start; the hook is absent from ordinary builds and does not change any
plugin, message, or MultiSubmit ABI. It makes caller boundaries deterministic
without inferring them from TCP packet aggregation or scanning live messages.

### Checkpoint 4 repair boundary

The retained-target description above is superseded. A WTI now acquires its
process-wide, non-reusing producer identity lazily on its first ConcurrentArray
egress operation. Native input submitters use the same allocator. A target
wrapper binds on first accepted snapshot and is cancelled or published,
unbound, and freed before the source batch returns; neither a queue pointer nor
a producer pointer crosses a batch/config-generation boundary. This deliberate
O(targets) per-batch purge is the safe baseline. A future optimization may
cache only objects carrying a validated config generation.

Prepared chunk counts no longer depend on the lane tail observed at prepare
time. Each reservation or builder prepares the worst-aligned number of 64-item
chunks, so overlapping preparations sharing a fallback handle may commit in
either order without missing storage. The builder itself has one inline item;
a routed singleton allocates no builder item array, while a later burst grows
to a modest heap block and a following singleton returns to the inline path.

`reservedBatch` completion policy is captured in the WTI at the beginning of
the actual batch invocation. The outer Main/ruleset consumer uses that captured
marker after `ProcessBatch` returns; it never rereads mutable `runConf` in the
completion window. A target publication error or FORCE_TERM therefore keeps
the original source RDY even across a config-generation selector change.
Legacy invocations retain their existing blanket-commit emulation. Queued
action egress is deferred to Checkpoint 5; Checkpoint 4 changes only dynamic
queued ruleset calls, native MultiSubmit, and the opt-in ConcurrentArray paths.
ReservedBatch rejects every queued action, and a ConcurrentArray action queue
is rejected in every engine until Checkpoint 5. Legacy queued actions retain
their existing implementation and hot path.

Cancellation remains disabled through target publication and the complete
target-wrapper purge. Once publication is visible and all target bindings are
gone, cancellation cleanup treats the PUBLISHED ledger idempotently and returns
the still-active source claim. An inactive wrapper created solely for a
discardMark-consumed snapshot is an exact publish no-op; inactive wrappers with
live builder or lease state remain an invariant error.

For avoidance of doubt, the earlier Checkpoint 4 paragraph describing dormant
target bindings across batches records the rejected first implementation. The
implemented contract is batch-scoped bind/publish-or-cancel/unbind/purge. This
checkpoint stages dynamic queued ruleset calls only; queued action staging and
its transaction/retry integration remain Checkpoint 5 work. Existing legacy
queued actions continue through their unchanged queue path, while reservedBatch
queued actions and ConcurrentArray action queues are rejected until that work.

Work availability and capacity availability use separate event-count channels.
Publication advances only the work epoch and wakes a work waiter. Terminal
completion or reservation cancellation advances only the capacity epoch and
wakes up to the number of credits released, bounded by the registered capacity
sleepers. The private-futex and pthread-condition adapters implement the same
separation and bounded fan-out. Quiesce, interruption, and shutdown advance and
wake both channels. This prevents a capacity producer from consuming the sole
consumer wake, and prevents a stalled first producer from stranding another
released credit behind wake-one.

ConcurrentArray startup under `reservedBatch` is topology-strict. Failure to
start either the Main ConcurrentArray or a named ConcurrentArray target cannot
fall back to Direct, because that would leave compiled queued-call routing with
a non-reservable target or remove the retryable source boundary. The legacy
engine retains its established Direct fallback. The `ENABLE_IMDIAG` native
MultiSubmit oracle is an rsyslogd startup control-file hook after Main workers
start; it is not an imdiag command, adds no plugin source or ABI change, and
does not scan ordinary messages.

An active `discardMark` policy deliberately fragments native MultiSubmit into
size-one decisions. Each item checks the actual qqueue gauge immediately before
its reservation, so a predecessor that times out or drains cannot make later
items appear speculatively resident. The normal/default policy has discard
severity outside the syslog range and retains one roomy span reservation and
publication. A deterministic severity transition across a full/drain boundary
guards both behaviors.

## 2026-08-30 Checkpoint 5 queued-action integration

Checkpoint 5 permits an asynchronous action only when the invocation uses
`executionEngine="reservedBatch"` and the action explicitly configures
`queue.type="ConcurrentArray"` plus `queue.concurrentCore="sparseLanes"`.
Direct actions retain their existing immediate path. Legacy execution retains
all existing queued-action modes, while reservedBatch rejects every other
queued-action type instead of silently adapting it. Disk assistance, sampling,
and `minDequeueBatchSize` remain unsupported for ConcurrentArray actions; any
fallback policy remains Checkpoint 6 work.

The source WTI uses the same batch-scoped target ledger introduced for dynamic
ruleset calls. Each queued-action invocation transfers exactly one owner to the
ledger: `MsgDup()` when `action.copyMsg` is enabled, otherwise `MsgAddRef()`.
Allocation or staging failure destroys that unpublished owner once and records
a new per-invocation egress-error generation. `execAct()` propagates only such
new egress failures, preserving historical handling of ordinary action return
codes. Earlier accepted action buckets publish before the source is restored
to RDY, so late failure is deliberately at-least-once rather than lossy.
Cancellation still runs with target mutation/publication disabled and purges
every unpublished owner before returning the source claim.

End-of-source-batch ordering is explicit: all ConcurrentArray action and
ruleset builders prepare and publish first, their bindings are unbound and
purged, and only then does `actionCommitAllDirect()` commit Direct
transactions. A queued transactional action receives its published logical
range through the ordinary action WTI consumer, retaining existing suspension,
retry, disable, and transaction callbacks. Action workers use the same
ConcurrentArray claim/completion/cancellation contract as Main and named
ruleset workers; an immediate-shutdown cancellation returns the active claim
before worker unbind and core destruction.

All new fault and batching controls compile only with `ENABLE_IMDIAG`. They are
parsed once while the action or queue is configured; ordinary builds contain
neither fields nor hot-path environment lookups. The deterministic worker gate
starts a selected ConcurrentArray queue only after an exact observed backlog,
allowing 8,192- and 65,536-message callback transcripts without
`minDequeueBatchSize`. The publication marker is written only after a selected
action builder commits and proves that visibility precedes a Direct COMMIT.
No plugin source or callback ABI, `smsg_t`, public `multi_submit_t`, or disk
format changes are part of this checkpoint.

## 2026-08-30 Checkpoint 6 disk assistance and configuration

`ConcurrentArray` now supports the existing disk-assisted model when a
`queue.filename` is configured.  The sparseLanes memory parent and the classic
or segmented disk child remain independent queues.  The normal consumers and
the single spill worker may therefore claim different parent ranges
concurrently, and no merged memory/disk output ordering is promised.  The
spill worker adds a reference and submits it through the unchanged child queue
API without holding a sparseLanes lane, ready-ring, or capacity lock during
serialization or I/O.  Only child-accepted records complete in the parent;
child pressure or error leaves the unaccepted suffix RDY and runnable.

High- and low-watermark control remains the established DA policy.  Reaching
the high watermark advises the spill pool, which stops only after the parent
falls to the low watermark.  Normal parent consumers continue independently.
During orderly shutdown the regular consumers first quiesce; when
`queue.saveOnShutdown="on"`, the same spill path transfers the remaining
memory work before the unchanged child persists.  An ungraceful crash still
protects only records already durable in that child.  Classic and segmented
disk formats, checkpointing, encryption, corruption handling, max-disk-space
behavior, and replay code are unchanged.

Startup creates the DA transfer pool and child transactionally.  If a later
step fails, rollback destroys the partial transfer pool and child before the
regular pool, sparse core, and parent synchronization state.  An
`ENABLE_IMDIAG` fault after child construction proves that the legacy engine's
intentional Direct fallback can reuse the queue object and shut down cleanly.
ReservedBatch retains its stricter topology rule and never falls back to a
non-reservable queue behind compiled asynchronous routing.

Modern RainerScript and YAML support the same explicit
`queue.type="ConcurrentArray"`, `queue.concurrentCore="sparseLanes"`, and DA
parameters.  Legacy Main-queue syntax adds `$MainMsgQueueConcurrentCore` beside
`$MainMsgQueueType ConcurrentArray`; the core is never inferred.  Missing or
unknown core names remain configuration errors.  Known ConcurrentArray
requests with a semantically compatible but unsupported memory-only option
warn and select FixedArray.  Startup diagnostics and immutable queue statistics
record requested and actual queue/core IDs, so fallback is observable.

DA recovery tests use an unordered accepted-set oracle with anchored IDs and
explicit multiplicity.  This is intentional: a memory parent and disk child
have never provided unified ordering while DA is active.  Duplicates remain
permitted only at the documented interrupted-claim/replay boundary; malformed,
out-of-range, or missing accepted IDs fail the oracle.
