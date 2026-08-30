# Contention-distributed queue design lab notebook

This is an append-only record. Add new dated entries at the end. Do not rewrite
earlier observations when assumptions or conclusions change; add a correcting
entry instead.

## 2026-08-30: architecture contract created

### Scope

- Planning and documentation only.
- Base revision: `upstream/main` at `f62bab368157d63e26b804aa9aadb7ae8642391a`.
- Design worktree: `/home/rger/rsyslog-mpmc-queue`.
- Branch: `codex/mpmc-queue-design`.
- No runtime or benchmark code changed.

### Goal recorded

Create an optional bounded memory queue that distributes contention across
concurrent producers and consumers, remains fast for both singleton and large
batch traffic, and avoids excessive low-occupancy memory. Initial scale is up
to 16 producers/consumers; 50 or more consumers is a later goal.

### Compatibility findings

- The storage algorithm is separate from rsyslog routing, retry, action, worker,
  and DA semantics.
- The legacy WTI/WTP loop holds the queue user mutex around predicate checks and
  claims. A new store alone cannot remove consumer serialization; an optional
  claim/wait adapter is necessary.
- Phase 1's dynamic per-target ledger and accepted-before-later-failure replay
  behavior are reusable semantic foundations.
- Phase 3's range abstraction is useful, but its capacity-sized descriptor ring
  is not.
- Phase 4's producer identity and empty-to-ready concept are useful, but its
  capacity-sized lane metadata is not.
- Phase 5's action and at-least-once tests are reusable independently of its
  BatchArray storage.

### DA baseline recorded

- Compatibility is based on `FixedArray` with a separate disk child.
- Parent regular consumers and the single spill worker may operate
  concurrently.
- No unified order is guaranteed between messages processed from memory and
  messages transferred to or replayed from disk.
- The new memory algorithm need not be used by the disk child.
- Existing disk formats, restart, corruption, checkpoint, and orderly
  save-on-shutdown behavior remain unchanged.

### Candidates selected for bakeoff

1. Sparse producer-target SPSC lanes with an SCQ-family MPMC ready-token queue.
2. A BBQ-family block-based bounded MPMC ring.

Neither candidate is preferred until deterministic ownership/progress tests and
low-occupancy memory screening pass.

### Pending decisions

- Operational versus formal lock-free progress requirement.
- Whether slow-first sibling isolation is required in the first engine.
- Acceptance of target-local producer order without global producer order.
- Exact per-slot and occupancy-one RSS/PSS memory gates.
- x86-64-first performance scope with cross-platform correctness.
- Confirmation of unchanged DA crash-durability semantics.
- Experimental selector versus immediately exposing a permanent queue type.

## 2026-08-30: sequential candidate 1 standalone checkpoint

### Cycle-start hosted status

- Inspected draft PR 7535 once with
  `gh pr view 7535 --repo rsyslog/rsyslog --json ...`.
- The PR was open and all reported required hosted checks were complete and
  successful; the Cubic review context was neutral. No hosted check was
  awaited or polled after this initial observation.

### Scope implemented

- Added a non-installed candidate-neutral API in
  `runtime/concurrent_array.h` and a private dispatch table.
- Implemented only `CA_CORE_SPARSE_LANES`. No BBQ, queue/ruleset/action/DA
  adapter, configuration selector, plugin change, public message type, or disk
  format was added.
- Fixed lane shape at `max(16, 4 * consumers)` dedicated lanes plus
  `next_power_of_two(2 * consumers)` fallback lanes.
- Added one embedded singleton range per dedicated lane, lazy 64-pointer
  chunks for the rest of a logical span, stable node indices/generations, and
  quiescent completed-node reuse.
- Added exact direct reservations, partial admission, cancellation, and
  speculative leases capped at 64 messages. Aggregate unused speculative
  credits are strictly less than half of configured capacity.
- Added a bounded per-cell sequence/cycle-tagged MPMC ready ring sized from
  lanes plus consumers. It is a simpler sequence ring with SCQ-style cycle
  tagging, not the full SCQ threshold/catch-up algorithm and not covered by
  SCQ's formal progress proof.
- Normal reserve, publish, claim, and successful completion contain no
  queue-wide pthread mutex or lane/capacity scan. Retry slots use a per-lane
  atomic-flag FIFO and create a lane-local barrier; this exceptional path is
  outside the successful steady-state progress claim.
- Added Linux private-futex epoch waiting and a pthread condition-variable
  adapter using the same monotonic epoch predicate.
- Added drain/discard quiescence and guarded destruction. Lane scans occur only
  during lifecycle teardown.
- Added default-off diagnostics for capacity attempts/failures, CAS/FAA work,
  publication/claim sizes, ready operations, dedicated/fallback use, chunk
  lifecycle, wake/sleep behavior, and retry barriers.

### Focused deterministic coverage

The registered `runtime_unit_concurrent_array_sparse_lanes` test covers:

- capacities 1, 2, 3, 7, 64, 65, and 1000;
- logical batch boundaries 1, 2, 7, 64, 65, 128, 1000, 4096, 8192, and 65536,
  using exact incremental admission/drain when the configured bound is lower;
- one million capacity-one reuse cycles, burst/drain/isolated singleton, exact
  partial/full admission, reservation cancellation, and an unpublished
  reservation that does not hide another lane's work;
- bounded speculative credits, mixed commit/retry/discard, out-of-order
  completion, retry-before-later-work, repeated retry, anonymous fallback, and
  discard quiescence;
- private-futex epoch wakeup and exact P1/C1, P8/C8, and P16/C16 ownership
  smokes with a byte oracle for every accepted identity.

### Development failures and corrections

1. The first direct compile failed because the standalone source unnecessarily
   included generated `config.h`. The include was removed; the core needs only
   standard C/POSIX headers.
2. The first matrix assertion incorrectly expected the queue to be full after
   a batch smaller than capacity. The test now fills the remaining exact
   capacity before asserting `CA_FULL`, then drains and verifies the configured
   count.
3. The first P8/C8 run stopped with three accepted identities stranded. GDB
   showed all producers complete and consumers spinning. The race was between
   a consumer changing an exhausted lane claim cursor to null and a producer
   linking the next range. Symmetric consumer/publisher cursor repair was
   added. The exact P8/P16 tests and five repeated full focused runs then
   passed.
4. Review found that discard quiescence could observe zero in-flight messages
   while a claim API call was between its admission check and in-flight
   accounting. Discard now also waits for the active API-operation count to
   reach zero before scanning lanes.
5. The pthread fallback initially requested a monotonic condition-variable
   clock with an API not available on every supported platform. It now converts
   the monotonic absolute deadline to the default real-time condition-variable
   clock while retaining the monotonic epoch predicate.
6. A final ownership audit found a quiescent-reclamation race: a new API
   operation could enter after the active count reached zero but before the
   previous operation exchanged the retired list. The operation counter now
   has an atomic reclaiming gate; entrants wait while the unique zero-count
   reclaimer returns nodes. Ten repeated complete focused runs passed after
   this correction.

### Commands and results

- `cc -std=gnu11 -Wall -Wextra -Werror -pthread ...` for both ordinary and
  `-DCA_ENABLE_DIAGNOSTICS` objects: passed after the initial include cleanup.
- Direct optimized focused runner under `timeout 60s`: passed.
- Five repeated complete direct focused runs: passed.
- `./autogen.sh --enable-debug --enable-testbench`: passed with existing
  Automake/Autoconf warnings.
- `make -j"$(nproc)" check TESTS=""`: passed; built normal runtime and test
  dependencies without running the suite.
- `make check TESTS='runtime_unit_concurrent_array_sparse_lanes'`: one test,
  one pass.
- Diagnostics-enabled complete focused runner: passed.

### Deferred gaps

- The ready ring is not the complete SCQ algorithm. Independent concurrency
  review must decide whether its simpler bounded sequence-ring progress is
  acceptable or whether full SCQ is mandatory before integration.
- No WTI/WTP, queue, ruleset, routing, action, DA, configuration, plugin, or
  persistence integration exists yet.
- ASan/UBSan, TSAN, static analysis, container lanes, broad tests, mock
  distcheck, formal performance work, and instrumented campaigns were
  intentionally not run in this code-generation checkpoint.
- The implementation is focused-functionally-tested only and is not PR-ready
  or fully validated.

### Final focused gate addendum

- Rebuilt and reran
  `make check TESTS='runtime_unit_concurrent_array_sparse_lanes'` after final
  formatting: one test, one pass.
- Compiled and ran the full suite with `CA_ENABLE_DIAGNOSTICS`: passed.
- Forced compilation and execution of the pthread wait adapter with
  `-U__linux__`: passed on the local Linux libc/pthread implementation. This is
  compile/behavioral coverage of the fallback branch, not a native macOS or BSD
  result.
- `devtools/format-code.sh --git-changed --check --check-if-available`: passed
  with clang-format 18 across five changed C/H files.
- `git diff --check`: passed.
- `devtools/check-test-antipatterns.sh` reported that the new unit source is not
  a shell test; its exact intent/oracle and 120-second deadlock guard are
  documented in the C source.
- `devtools/local-validation-plan.sh` classified the delta as
  `testbench-plumbing`. Its container, static-analysis, prompt-audit, and mock
  distcheck recommendations remain intentionally deferred by the current
  focused-validation instruction.
- Explicit artifact cleanup removed generated untracked unit binaries. The
  worktree contains only the preserved design changes and the new source/test
  edits and remains uncommitted for independent review.

## 2026-08-30: independent-review NO-GO repair cycle

### Review findings addressed

- Replaced the global active-operation scheme with a generation lifecycle gate
  and role-sharded counters. Stable lane index/generation handles are captured
  by reservations, leases, and builders; producer release returns `CA_BUSY`
  while any such handle remains live, and foreign-queue handles are rejected.
- Replaced allocated range-per-submit storage with lane-owned inline/lazy
  ordinal logs. A 64-entry chunk is retained or recycled only after every slot
  is terminal and both claim/final frontiers have passed it. Slot metadata was
  reduced to 16 bytes on this build by deriving chunk and ordinal from a compact
  offset.
- Added multi-lease builders, coalesced claims, aggregate claim completion,
  checked size/ordinal calculations, explicit atomic initialization, lock-free
  atomic/SCQ checks, futex alignment checking, and private token/ring width
  checks.
- Made retry ordering ordinal-based and linearized both retry insertion and
  normal reservation under the lane gate. Added deterministic coverage at the
  old check/reserve race and reverse completion of two failed claims.
- Corrected pthread waiting so epoch mutation and signalling occur under the
  wait mutex. Cancellation cleanup restores the mutex and every registered
  counter. A forced-pthread target checks 100 registered-before-signal cycles,
  cancellation, and a post-cancellation wake.
- Integrated the independently owned SCQ-family ready primitive without
  changing its API or implementation. Sparse lanes use the stable 32-bit lane
  index as token and drain stale ready tokens only during discard quiescence.

### New focused oracles

- Actual single builder publications and single coalesced claims of 4,096,
  8,192, and 65,536 ordered identities.
- Exact serial ownership snapshots across reservation, unused lease, partial
  publication, in-flight claim, commit/retry/discard, reserved publication,
  leased publication, and final drain.
- Foreign producer rejection and release-with-live-reservation/lease/builder.
- Per-producer ordering with four equal-key producer handles sharing a fallback
  lane, plus the existing anonymous fallback case.
- Concurrent quiesce versus an entrant paused after lifecycle admission; closed
  submit, successful quiesce, and full returned capacity are exact oracles.
- Checked lane-ordinal boundary and the exact P1/C1, P8/C8, and P16/C16
  identity/multiplicity smokes.

### Development failures and corrections

1. The first integrated SCQ run aborted during discard destruction because
   discard made lanes terminal but left their queued ready tokens admitted.
   Discard quiescence now drains the already-closed ready ring and resets token
   ownership before destruction.
2. The first combined O2 run stalled at P16/C16 with capacity full. GDB showed
   producers spinning on `CA_FULL` and consumers seeing no ready token. A
   consumer had observed `ABSENT`, then lost a one-shot CAS after the publisher
   changed it to `QUEUED`, dropping the dequeued token. Consumer acquisition is
   now a CAS loop over either pre- or post-publication state. The same complete
   run then passed in under one second.
3. The first forced-pthread compile exposed `pthread_cleanup_push/pop` macro
   scoping around the wait result. Moving the result declaration outside the
   cleanup scope fixed both the unused and out-of-scope errors; the forced
   behavioral target then passed.
4. A final lifecycle audit found that discard reopened the generation gate
   before scanning while existing reservations could still publish. A separate
   publication admission flag is now closed under the writer generation for
   discard/destroy; drain retains publication only until exact capacity is
   returned.

### Commands and focused results

- Direct `cc -std=gnu11 -O2 -g -Wall -Wextra -Werror -pthread` builds for
  normal futex, `CA_FORCE_PTHREAD_WAIT`, and `CA_ENABLE_DIAGNOSTICS`: passed;
  each sparseLanes runner passed its exact suite.
- Direct `CA_READY_SCQ_TESTING` build and runner: passed.
- `make -j10 check TESTS=''`: passed and registered/built the three new unit
  targets without running the suite.
- `make -C tests check TESTS='runtime_unit_concurrent_array_ready_scq
  runtime_unit_concurrent_array_sparse_lanes
  runtime_unit_concurrent_array_sparse_lanes_pthread'`: three tests, three
  passes.
- `devtools/format-code.sh --git-changed`: passed with clang-format 18 across
  the eight new C/H sources.

### Remaining scope and validation gaps

- No qqueue, WTI/WTP, ruleset, routing, action, DA, configuration, plugin,
  public-message ABI, or persistence integration was added. BBQ remains a later
  sequential candidate.
- This is focused functional/concurrency evidence, not exhaustive validation or
  a performance verdict. Sanitizers, static analysis, containers, broad suite,
  mock distcheck, formal progress proof, instrumented runs, and performance
  campaigns remain deliberately deferred.
- The ready queue is SCQ-family/helpable rather than a verbatim published SCQ.
  Independent review must assess its memory ordering and proof obligations
  before integration or benchmarking retention.

### Final repair-cycle gate addendum

- After the final token-handoff cancellation guard and formatting, direct
  normal-futex, forced-pthread, diagnostics, and standalone SCQ runners all
  rebuilt with `-Wall -Wextra -Werror` and passed.
- `devtools/format-code.sh --git-changed --check --check-if-available`, tracked
  and untracked whitespace checks, and the diff-scoped TODO/obsolete-API/
  non-wait-mutex scans passed.
- `devtools/check-test-antipatterns.sh` reported no shell tests; both C tests
  carry file-level and adversarial-case intent/oracle comments.
- The raw-allocation audit found only queue/ring creation and destruction,
  lazy 64-entry chunk creation, and builder growth. There is no singleton range
  allocation or claim allocation in the sparse core.
- `devtools/local-validation-plan.sh` classified the work as
  `testbench-plumbing`. Its container, static-analyzer, prompt-audit, and mock
  distcheck recommendations remain explicitly deferred by this checkpoint's
  focused-validation instruction.
- Explicit cleanup unlinked the six generated untracked `runtime_unit_*`
  binaries produced by the incremental/focused build. Only intended source,
  tests, and documentation remain uncommitted for the next independent review.

## 2026-08-30: third-review repair cycle

### Decisions and implementation

- Made lazy chunk attachment transactional. Reclamation is deferred until
  publication commit; failure restores original chain endpoints and lookup hint
  and returns every addition to the bounded pool.
- Added deterministic fail-after-N chunk allocation. Direct submit, reserved
  publication, and builder publication each fail after one successful new
  chunk, verify exact capacity, then recover through singleton and 130-item
  publication/drain.
- Bounded each lane to one pooled chunk. Extra returned chunks are freed, while
  the retained tail/pool pair avoids capacity-one churn. Always-on test counters
  and default-off `chunks_pooled` diagnostics accompany existing live/allocation
  counters.
- Repacked ready cells from 32 token bits/31 generation bits to 16 token bits/47
  generation bits. The test seeds the ring at the former generation horizon,
  interrupts an admitted publisher, helps its hole, and continues exact traffic
  across that old boundary. The true expanded limit still returns `OVERFLOW`
  without wrapping.
- Replaced the role-global lifecycle counters with cache-separated per-worker
  role slots. A thread performs one process-lifetime slot FAA; ordinary queue
  calls thereafter touch only its slot and the read-only generation. P16 records
  and verifies distinct producer and consumer slots. Quiesce/destroy alone scan
  the slot table.
- Added the inspection role to capacity, epoch, diagnostics, and shape reads;
  a paused-inspector test proves destroy closes admission and waits before free.
- Added 64-bit generation-checked dedicated-lane reuse. One hundred sequential
  worker restart cycles remain dedicated and advance per-lane generations;
  simultaneous exhaustion still routes only the excess handle to fallback.
- Added `ca_return_claim()` and documented the complete-or-return ownership
  rule. A canceled claim-owner thread invokes it from pthread cleanup; both
  items retry in original order and capacity returns exactly after drain.

### Development corrections

1. The first inspection-gate run deadlocked the old quiesce test: its main
   thread attempted an inspection read while the writer generation was closed,
   but that same test held a deliberately paused publisher the writer awaited.
   A raw test-only accepting flag now coordinates that adversarial setup; public
   inspection remains correctly blocked.
2. The initial post-release retention assertion allowed only one chunk per lane.
   Accounting showed exactly 20 live/18 pooled for 18 lanes: reset dedicated
   lanes retained one pool each, while the two queue-lifetime fallback lanes
   correctly retained both tail and pool. The bound was corrected to
   `lanes + fallback_lanes`, still independent of historical four-chunk peaks.

### Focused commands and results

- Normal futex, forced pthread fallback, diagnostics-enabled sparseLanes, and
  standalone SCQ direct builds used
  `cc -std=gnu11 -O2 -g -Wall -Wextra -Werror -pthread`; all four exact runners
  passed.
- `make -j10 check TESTS=''`: passed, building the normal tree and all three
  registered ConcurrentArray test targets without running the suite.
- `make -C tests check TESTS='runtime_unit_concurrent_array_ready_scq
  runtime_unit_concurrent_array_sparse_lanes
  runtime_unit_concurrent_array_sparse_lanes_pthread'`: three tests, three
  passes.
- No sanitizer, static analyzer, container, broad suite, performance campaign,
  or mock distcheck was run; those remain outside this focused code checkpoint.

### Third-cycle final static gate

- `devtools/format-code.sh --git-changed` and its read-only clang-format 18
  check passed across all eight C/H files.
- Tracked and untracked whitespace checks, C-test antipattern routing, obsolete
  ready-API, old range/active-operation, non-wait pthread mutex, and
  TODO/FIXME/XXX scans passed.
- Explicit final cleanup unlinked the six generated untracked unit binaries.
  The worktree remains uncommitted with only intended source, test, and
  documentation paths visible to `git status`.

## 2026-08-30: final standalone lifecycle repair

### Corrected design and focused oracles

- Replaced the generation plus seven-role counter table with one explicitly
  64-byte-aligned lifecycle slot per shard. The slot's 64-bit atomic state packs
  the close bit and reader count; ordinary calls CAS/increment and decrement
  only their shard. The 64-slot minimum is exactly 4 KiB rather than the prior
  roughly 28 KiB role matrix.
- Rejected an intermediate selection-counter idea during self-audit: it merely
  moved the raw-pointer race to the instant before that counter's increment.
  The enforceable lifetime boundary is now `ca_lifecycle_bind()`/`unbind()`.
  Destroy returns `CA_BUSY` while a worker binding exists. Unbound TLS-modulo
  sharding is explicitly provisional, may collide, and must not overlap
  destruction.
- Retained selective operation flags around the packed gate. Drain closes new
  submission while allowing publication, claim, wait, and completion until
  exact capacity returns; discard closes publication/claim/wait immediately.
- Added a deterministic hook after lifecycle-slot selection and before the
  packed admission CAS. A quiesce race closes the slot first, then the delayed
  submit observes closed admission and publishes nothing. Separate bound-reader
  tests prove destruction waits admitted inspection and refuses storage free
  until the binding is released.
- Lifecycle allocation tests assert 64-byte pointer alignment and exact 4 KiB
  minimum accounting. The P16/P16 smoke binds all 32 workers before release of
  its start barrier and verifies every producer/consumer slot is distinct.
- Strengthened transactional allocation-failure tests to assert exact recovered
  IDs and order for direct, reserved, and builder publication. Added builder
  cancel after failed publication followed by exact singleton and multi-item
  recovery.
- Added release-before-drain coverage: the old dedicated lane cannot be reused
  while its three ordered messages remain, drains with exact IDs, and is later
  reused only with a higher generation.
- Clarified the future WTI cancellation contract: asynchronous cancellation is
  prohibited around core calls; deferred cancellation remains disabled from
  claim return until `ca_return_claim()` cleanup is installed.

### Development correction and focused results

1. The first diagnostics run found the P16 slot oracle could observe reuse:
   the start flag was released before every thread had completed binding, so a
   fast producer could unbind before a late consumer recorded its slot. Added a
   binding-count barrier before workload start and strengthened the oracle to
   require uniqueness across producer/consumer groups as well as within them.
   Normal, pthread, and diagnostics reruns then passed.

- Direct normal-futex, forced-pthread, diagnostics-enabled sparseLanes, and
  standalone SCQ commands rebuilt with
  `cc -std=gnu11 -O2 -g -Wall -Wextra -Werror -pthread`; all four exact runners
  passed after the binding barrier correction and again after formatting where
  applicable.
- `make -j10 check TESTS=''`: passed, including compilation/linking of all three
  registered ConcurrentArray targets and a zero-test incremental suite.
- `make -C tests check TESTS='runtime_unit_concurrent_array_ready_scq
  runtime_unit_concurrent_array_sparse_lanes
  runtime_unit_concurrent_array_sparse_lanes_pthread'`: three tests, three
  passes after final formatting.
- `devtools/format-code.sh --git-changed` and
  `devtools/format-code.sh --git-changed --check --check-if-available`: all
  eight candidate C/H files passed clang-format 18.
- `devtools/check-test-antipatterns.sh` found no shell tests. Tracked/untracked
  whitespace, obsolete generation/role/range/ready API markers, TODO/FIXME/XXX,
  and pthread-mutex placement scans passed; the only mutex operations are in
  the documented pthread wait adapter and its cancellation cleanup.
- Sanitizers, static analysis, containers, broad suites, performance work,
  instrumented builds, and mock distcheck remain intentionally deferred under
  this standalone focused-validation checkpoint.
- Final cleanup explicitly unlinked the six generated untracked unit binaries;
  `git status --short` now lists only the intended source, tests, build
  registration, and append-only design/notebook paths.

## 2026-08-30: timed lifecycle-writer reopen correction

- Final rereview found `lifecycle_writer_end()` stored zero into every packed
  slot. If a timed quiesce reopened while an admitted reader remained, that
  erased its reference and the later reader exit underflowed the word. Reopen
  now uses atomic fetch-and with the reference mask, clearing only
  `CA_LIFECYCLE_CLOSED` and preserving every admitted count before releasing
  the writer.
- Admission-wait timeout restores the operation flags captured while all slots
  were closed. Without that rollback, a timed-out drain would leave submission
  closed even though quiescence did not complete.
- Added a deterministic inspection-role pause with an already-expired
  monotonic deadline. The first drain returns `CA_TIMED_OUT`; the reader then
  exits, exact submit/claim/commit succeeds, capacity returns exactly, and a
  second drain plus destroy succeeds. This sequence detects both refcount
  underflow and a slot left closed.
- Post-format direct normal-futex, forced-pthread, diagnostics-enabled, and SCQ
  runners passed. The registered Automake selection passed 3/3. The formatter
  read-only gate passed before those runs.
- Checkpoint 3 must replace the standalone one-binding TLS assumption for
  dynamic routing. Main/ruleset integration must assign each WTI/WTP stable
  producer/worker slots across every target queue it may touch, and join/unbind
  them before queue destruction; one TLS binding pointer cannot represent
  several target queues.
- Final format, diff, whitespace, obsolete-lifecycle marker, and antipattern
  gates passed. The six generated untracked unit binaries were explicitly
  unlinked again; final status contains only intended source/documentation.

## 2026-08-30: Checkpoint 3 qqueue/WTI/WTP integration

### Decisions and implementation

- Added internal `QUEUETYPE_CONCURRENT_ARRAY` and the modern shared-nvlist
  `queue.concurrentCore` parameter. `sparseLanes` is mandatory; missing,
  unknown/`bbq`, disk/DA, encryption, sampling, minimum-dequeue, and dequeue
  rate-window combinations are rejected with configuration diagnostics.
- Registered the three candidate sources in `runtime/librsyslog.la`. No public
  message, plugin, `multi_submit_t`, module ABI, disk format, or legacy queue
  directive changed.
- Added an opt-in unlocked WTP branch with worker start/stop, normal completion,
  cancellation return, epoch wait, and shutdown-wake callbacks. The legacy
  mutex worker branch is structurally unchanged. Each active WTI owns one
  reusable claim and completion buffer and one source-queue lifecycle binding.
- Single enqueue and the required existing `MultiEnq` adapter now use anonymous
  fallback lanes, exact core admission, core epoch backpressure, and existing
  qqueue enqueue/full/discard/size counters. The adapter remains per-entry;
  native logical-span MultiSubmit is Checkpoint 4.
- Batch states map `COMM` to commit, `DISC`/`BAD` to discard, and `RDY`/`SUB`
  to ordered retry. Different claims can execute concurrently. Core disposal
  owns final `smsg_t` destruction, including shutdown discard.
- Deferred cancellation is disabled before claims. The WTI outer cleanup was
  already installed by then; cancellation is enabled only around `pConsumer`,
  and cleanup returns the full claim before unbinding. A control-plane epoch
  interrupt wakes futex or pthread waiters during WTP shutdown; ordinary work
  publication retains the core's proportional wake.

### Development corrections

1. The first live test called `wait_file_lines` with the expected count as its
   filename argument. The queue had already produced all 511 records, but the
   oracle watched an empty filename. Correcting the helper call to pass output
   path and count made the W1/W8/W16 cycle pass immediately.
2. Linking the standalone core into `librsyslog.la` exposed rsyslog's historical
   declaration-after-statement warning profile. The private sparse C11 source
   now locally suppresses only that C90 style warning; the ready primitive's
   few mixed declarations were moved to block starts. No functional warning is
   suppressed.
3. The pthread wait adapter needed an explicit WTP shutdown wake because a
   legacy per-WTI condition signal does not change the core predicate. Added a
   candidate-neutral control-plane interrupt; it is wake-all only for shutdown,
   never for ordinary enqueue.

### Focused commands and results

- Hosted PR 7535 status was inspected once at cycle start by the parent: all
  completed checks were green; no hosted CI wait was performed.
- `autoreconf -fvi`, incremental `make -j4`, and the rebuilt full configured
  host tree passed.
- Registered focused selection passed 8/8:
  `runtime_unit_concurrent_array_ready_scq`, normal and forced-pthread
  sparseLanes, configuration, Main/named/W1/W8/W16, capacity-two full
  backpressure, active-claim immediate shutdown, and YAML runtime smoke.
- The Main/named live oracle recovered exact identities `0..1695` with no
  duplicates: every ConcurrentArray worker-count cycle drained a 511-message
  burst and then observed an independently submitted singleton; the named
  ruleset handled another exact 128; FixedArray and LinkedList handled their
  adjacent exact regression ranges.
- Capacity-two slow-consumer admission delivered exact `0..63` with no full
  discard. Immediate shutdown of a two-worker queue during a five-second
  consumer returned/cleaned its active claim and exited without assertion or
  worker-lifetime warning. The standalone cancellation oracle separately
  verifies exact returned-claim redelivery order inside one process.

### Deferred and unsupported

- Native batch publication from `MultiSubmit`, producer identity propagation,
  target/action multi-queue bindings, queued-action coverage, DA fallback,
  BBQ, actual-core diagnostics, and legacy directive parity remain Checkpoints
  4-6. One TLS lifecycle binding is used only for the worker's own source queue.
- No sanitizer, static analyzer, container, broad suite, mock distcheck,
  instrumented build, performance campaign, or final candidate verdict was run
  under the focused Checkpoint 3 validation instruction.

### Final focused repair and rerun

- Replaced the shutdown smoke's scheduler-dependent delay with an omtesting
  debug-log marker. The test now waits for `sleep(5, 0)`, which proves the
  consumer owns an active claim before immediate shutdown begins; shutdown
  still exits within the short testbench guard without an assertion or a
  worker-not-stopped diagnostic.
- `qqueuePersist()` now treats ConcurrentArray as explicitly memory-only.
  Shutdown returns active claims and core destruction discards remaining
  messages, so a non-empty in-memory ConcurrentArray no longer reports the
  legacy non-disk persistence error.
- After that correction, `make -j4` passed and the registered focused
  selection passed 8/8 again: SCQ, normal futex sparseLanes, forced-pthread
  sparseLanes, config, combined Main/named/legacy live smoke, capacity-two
  backpressure, active-claim immediate shutdown, and YAML.
- The three registered standalone binaries also passed when invoked directly.
  ShellCheck initially returned nonzero at its default informational level for
  established testbench here-document expansion and `diag.sh` sourcing; the
  repository-appropriate `shellcheck -S warning` rerun passed. The five-test
  antipattern scan reported zero matching classes, `git diff --check` and the
  clang-format-18 read-only gate passed, and the validation planner classified
  the change as testbench plumbing. Its broad container/static/distcheck lanes
  remain deliberately deferred by this checkpoint's focused-validation scope.

## 2026-08-30: Checkpoint 3 review repair — ordering, ownership, and starts

### Repairs

- Replaced null/anonymous qqueue submission with pre-registered queue-local
  dedicated producers selected by a stable per-thread key. The existing
  `MultiEnq` adapter uses one producer for its complete call.
- Added a ConcurrentArray-only WTP advice helper. It starts only missing
  workers under the queue thread-management lock; it does not use the legacy
  qqueue mutex and does not scan/signal all WTI slots when the requested
  workers already run. Core epoch publication remains the ordinary wake path.
- Added atomic ConcurrentArray size/max stats mirrors and moved local/global
  size admission before core publication with exact rollback on failure.
- Made qqueue ownership terminal on entry: non-full publication failures
  destroy the current message, and a fatal `MultiEnq` error destroys its
  unattempted suffix because `multiSubmitMsg2()` clears the caller's element
  count after return.
- Moved reusable claim/completion allocation into WTI pool construction.
  Changed the WTP worker pointer table to zero-initialized storage and made
  destruction skip unconstructed entries, so injected partial construction
  failure is safe and occurs before any queue admission.
- Added default-off deterministic worker-preallocation and identity-targeted
  lazy-chunk allocation hooks. The message hook is cached at queue construction
  and its string match is absent from the normal path.

### Test corrections and failure log

1. The first new OOM shell test was not executable and Automake reported
   `Permission denied`; its mode was corrected.
2. Arming allocation failure at queue construction let unrelated startup
   traffic consume the one-shot hook, so IDs 0, 1, and 2 were all published.
   The hook was moved to the configured message identity immediately before
   publication. The expected file was also corrected to the testbench's padded
   eight-digit identity format.
3. The worker-preallocation test initially used `rsyslogd -N1`, which validates
   syntax without constructing the WTI pool. It now starts a bounded normal
   daemon, waits for the exact pre-admission diagnostic, and deterministically
   kills/reaps the process.
4. The first producer-order oracle used `seq_check`, which sorts identities and
   cannot detect lane reordering. The W1 single-submit and TCP `MultiEnq`
   phases now use unsorted `cmp_exact`: 0..7 and then 0..15 respectively.
5. The final self-audit found the first repair still called legacy WTP advice.
   Its no-start branch scans and signals worker slots on each submission. A
   new ConcurrentArray-only start-missing helper removed that scan; the core
   epoch continues to wake existing workers.

### Focused results

- Incremental `make -j4`: passed after the final WTP advice correction.
- Registered selection passed 9/9 with no skips or failures:
  standalone SCQ, normal and forced-pthread sparseLanes, configuration,
  Main/named/W1/W8/W16/legacy queue smoke, capacity-two full backpressure,
  active-claim immediate shutdown, exact OOM ownership/recovery, and YAML.
- Direct execution of the SCQ, normal sparseLanes, and forced-pthread
  sparseLanes binaries passed.
- The OOM single-submit oracle published exact IDs 0 and 2 and logged exactly
  one destruction of ID 1. The `MultiEnq` oracle published ID 0, logged exactly
  one destruction for every ID 1..7, then published independent recovery ID 8.
- The exact unsorted ordering oracle passed for single submits 0..7 and for the
  existing TCP `MultiEnq` adapter 8..15. The combined queue smoke retained
  exact W1/W8/W16 identity/multiplicity, named ruleset, FixedArray, and
  LinkedList coverage.
- `shellcheck -S warning` passed for all six changed shell tests. The test
  antipattern scan found only the intentional worker-preallocation background
  daemon, which has a content readiness oracle plus explicit kill/wait cleanup.
  Clang-format 18's read-only changed-file gate and `git diff --check` passed.

Sanitizers, containers, static analysis, broad suites, formal performance,
instrumented builds, and mock distcheck remain deferred under the authorized
focused-validation scope. The implementation remains uncommitted for review.

### Final scaling fast-path correction

The last contention audit found qqueue still acquired `mutThrdMgmt` before the
new helper discovered that the desired workers were already running. Added an
atomic WTP current-worker accessor and return before that lock. Steady
submission now uses only the atomic backlog/worker reads and core epoch wake;
`mutThrdMgmt` is taken only when the queue may actually need to scale up.

## 2026-08-30: Checkpoint 3 final P2 closure

- Reordered full/light watermark admission to snapshot the core epoch and then
  recheck the atomic size predicate before every wait. This closes the
  completion-between-predicate-and-snapshot lost-wake window without adding a
  test-only synchronization branch to the enqueue hot path.
- Changed `queuesEqual()` to compare `concurrentCore` case-insensitively and
  made the positive parser test use mixed-case `SpArSeLaNeS`. A proposed live
  reload oracle was removed after it demonstrated that testbench `issue_HUP`
  performs module HUP processing rather than dynamic configuration replacement;
  it never invokes the main-queue comparison path.
- Strengthened the capacity-two test with impstats and a `full > 0` oracle.
  The consumer delay is 50 ms, making the 64-message producer deterministically
  encounter exact capacity while retaining the exact 0..63 ownership oracle.
- Cached a default-off lifecycle-marker switch at queue construction. The
  active-claim shutdown smoke now directly observes a successful worker
  lifecycle unbind followed by successful core destruction, in addition to
  its bounded-exit and no-assertion checks.
- Replaced the worker-preallocation background daemon plus forced kill with a
  synchronous ten-second guard. The oracle requires rsyslogd to exit nonzero
  by itself, rejects the timeout status, and checks the exact pre-admission
  diagnostic.

## 2026-08-30: Checkpoint 3 final rereview repairs

This entry corrects the immediately preceding preallocation note: rsyslogd
intentionally keeps running after the Main queue fails to start and replaces it
with Direct. The correct oracle is not process self-exit. Both deterministic
failure cases now require the injected diagnostic and the existing "could not
start (ruleset) main message queue" diagnostic, absence of the CA start-complete
marker, successful CA core destruction/startup rollback markers, exact Direct
fallback output, and a clean requested shutdown.

Repairs made in this pass:

- Made late CA startup failure transactional and initialized generic stats
  counters once at qqueue construction, so retrying the same object as Direct
  cannot leak the core/WTP/synchronization state or double-initialize helper
  mutexes.
- Added a second allocation boundary before `wtpConstructFinalize()`. It
  exercises rollback with `pWtpReg->pWrkr == NULL`; the WTP destructor guards
  the whole loop and also skips null entries after partial WTI construction.
- Moved terminal local, impstats, and process-wide size decrements into the core
  disposal callback, which runs before capacity release. Submission reserves a
  non-visible core credit before preaccounting and publishing. The capacity-two
  oracle observed `full > 0`, exact IDs 0..63, and `maxqsize=2`.
- Registered the complete O(consumers) producer table (dedicated plus fallback
  handles). Identities 1..D map exactly to dedicated handles and every later
  identity hashes only over fallback handles. A default-off key bias made the
  W1 smoke's synthetic identity 19, beyond D+F=18; debug markers confirmed 16
  dedicated plus 2 fallback handles and fallback publication, while unsorted
  output remained exact.
- Bound `SingleEnq` at queue start. `qqueueEnqMsg()` is now only the compatibility
  indirect-call wrapper, with no `qType` branch; the legacy implementation has
  no ConcurrentArray selector. Made the raw CA `qAdd` assert-unreachable to
  prevent an unaccounted submit followed by disposal underflow.
- Kept `mutQueueSize` and the other atomic-helper fallbacks alive until after
  the type-specific destructor, so non-lockfree builds can safely decrement
  during CA quiesce-discard.
- Calculated ConcurrentArray worker advice in widened arithmetic and clamped it
  to the configured WTP worker count before conversion back to `int`, avoiding
  overflow when a very large backlog is divided by a one-message threshold.

Focused commands and results:

- `devtools/format-code.sh --git-changed` and incremental `make -j4`: passed.
- Direct configuration, queue/order/fallback, capacity/full, OOM ownership,
  and active-claim shutdown tests: passed.
- `make -C tests -j3 check TESTS='runtime_unit_concurrent_array_ready_scq
  runtime_unit_concurrent_array_sparse_lanes
  runtime_unit_concurrent_array_sparse_lanes_pthread
  concurrent-array-config.sh concurrent-array-queue.sh
  concurrent-array-full.sh concurrent-array-shutdown.sh
  concurrent-array-oom.sh yaml-concurrent-array-queue.sh'`: 9/9 passed.
- Direct SCQ, normal sparseLanes, and forced-pthread sparseLanes binaries:
  passed.
- The registered queue smoke also performs source oracles: the public
  `qqueueEnqMsg()` body contains its bound `SingleEnq` call and no `qType`, and
  the unreachable CA `qAdd` body contains no core submission call.

Two command-location mistakes did not expose code failures. Appending
`./concurrent-array-queue.sh` to a root-directory format/build command failed
with "No such file or directory" after the build had passed; rerunning from
`tests/` passed. Likewise, invoking the root-relative format helper from
`tests/` could not find its changed-file helper and performed no check; the
same read-only command rerun from the repository root passed over all 15
changed C/header files.

The rare diagnostic-only mirror overshoot after lazy-chunk publication OOM is
recorded as a Checkpoint 4 split prepare/commit API obligation. Core capacity
and ownership remain exact. No sanitizer, container, static-analysis, broad,
performance, instrumented, or mock-distcheck lane was run under the authorized
focused scope.

## 2026-08-30: Checkpoint 4 implementation cycle

Hosted PR 7535 was inspected once at cycle start by the coordinator: all
completed checks were green and Cubic was skipped. No hosted check was waited
on or re-polled.

Implemented split prepare/commit for reservations and builders, nested explicit
lifecycle activation for persistent per-WTI target bindings, native qqueue
MultiSubmit spans, and `reservedBatch` target-local routing for queued ruleset
calls and queued actions. Dynamic calls snapshot at the call site; repeated,
conditional, indirect, and mutation-separated targets accumulate independently.
When any target runs out of credit, the WTI publishes all existing buckets
before performing the blocking admission retry.

Defects found during focused development:

1. The first prepared publication treated logical ordinal zero as an allocated
   chunk slot and used chunk bases at `64*k`. Live routing aborted on its first
   singleton. Restoring ordinal zero to the dedicated inline slot and using
   chunk bases `1 + 64*k` fixed both singleton and later chunk boundaries.
2. The first exact-credit model counted the mandatory current credit as
   speculative. Capacity-one target builders could therefore never acquire a
   lease. Leases now reserve one mandatory credit and count only optional
   lookahead in the global below-half speculative limit.
3. The first shutdown oracle required a staged target message to be absent.
   Graceful shutdown may publish that builder before escalation to immediate
   shutdown, so absence was not a valid ownership oracle. The test now accepts
   publish or cancel, while requiring bounded exit, active source-claim cleanup,
   target/source unbind, and core destruction without an assertion.
4. A final target publication failure could leave source elements committed
   even though routing had not completed. The WTI now cancels all unpublished
   builders and restores committed source elements to ready before completion,
   giving an explicit at-least-once retry contract.
5. The Checkpoint 3 MultiEnq OOM test expected ID 0 to survive because the old
   adapter unpacked the call. Native span preparation is transactional, so its
   correct oracle is that IDs 0..7 are each destroyed once and none publish;
   independent ID 8 must recover and is the sole output.

Focused commands and results at the pre-format boundary:

- Incremental `make -j4`: passed after the source-ready repair and again after
  caching the target-allocation test selector at queue construction.
- `make check TESTS='runtime_unit_concurrent_array_ready_scq
  runtime_unit_concurrent_array_sparse_lanes
  runtime_unit_concurrent_array_sparse_lanes_pthread'`: 3/3 passed.
- Direct `concurrent-array-reserved-batch.sh`: passed exact repeated-target
  first/second snapshots, indirect target, queued action, one-shot target
  preparation OOM recovery, second batch after HUP, and clean teardown.
- Direct `concurrent-array-reserved-pressure.sh`: passed exact crossed
  capacity-one A-then-B/B-then-A routing from two source workers.
- Direct `concurrent-array-shutdown.sh`: passed active-claim immediate shutdown
  and lifecycle-marker cleanup.
- Direct configuration, Main/named/W1/W8/W16/legacy queue, capacity/full,
  corrected native-span OOM ownership, and YAML smokes passed. The combined
  legacy queue smoke retained unchanged FixedArray and LinkedList behavior.

The standalone builder tests publish actual logical ranges of 4096, 8192, and
65536 items. An exact live qqueue oracle that forces each requested public
MultiSubmit size to remain one input call is not yet deterministic through
TCP packet batching; the live adapter has exact small MultiSubmit ownership and
recovery evidence, while exhaustive public-size/performance instrumentation
remains deferred to the dedicated campaign requested by the program owner.
Sanitizers, containers, static analysis, broad suites, formal performance,
instrumented builds, and mock distcheck were not run under the authorized
focused-validation scope.

### Checkpoint 4 exact adapter-oracle closure

The initial live coverage-gap note above is superseded by deterministic
testbench-only plumbing. Under `ENABLE_IMDIAG`, qqueue counts native-Multi
reservation attempts, successful publications, published items, and worker
advice. The imdiag-only `injectmultimsg` command constructs one exact existing
`multi_submit_t`; production builds and public structures are unchanged.

`concurrent-array-native-multi.sh` passed exact roomy calls of 1, 2, 7, 128,
1000, 4096, 8192, 16384, and 32767 (`SHRT_MAX`) messages. Every call reported
one reservation, one logical publication, one advice, and exactly N published
items. With a dequeue ceiling of seven, exact identities 0..62576 arrived once.
Its capacity-seven/N=128 phase reported multiple reservation, publication, and
advice cycles, exactly 128 published items, and exact identities 0..127.

The first direct run failed only because `diagtalker` prefixes successful
responses with `imdiag[port]:`; the command and one-message publication had
succeeded. The oracle now strips that transport prefix before comparing the
exact counter payload. The corrected direct run passed in three seconds.

After formatting, incremental `make -j4` passed, the registered standalone
SCQ/normal/pthread selection passed 3/3, and the registered native-Multi,
reserved-routing, crossed-pressure, and active-shutdown selection passed 4/4.
The nested lifecycle unit explicitly models a WTI retaining source and target
bindings: target destruction returns `CA_BUSY` while retained, then exact
quiesce/destruction succeeds after target unbind.

Final static gates passed: clang-format 18 changed-file formatting and dry-run
check, `git diff --check`, Bash syntax for every ConcurrentArray shell test,
and shellcheck warning level for all nine changed shell tests. The structural
scan confirmed `qqueueEnqMsg()` remains only the bound-dispatch wrapper with no
queue-type branch. Core pthread mutex use remains confined to the portable
epoch-wait adapter; storage publication, claim, and completion have no
queue-wide mutex. The six generated standalone/runtime unit binaries were
removed after validation, and the worktree remains uncommitted for review.
The repository test-antipattern scanner examined all nine changed shell tests
and reported zero matching antipattern classes. The validation planner
classified the diff as testbench plumbing; its container, static-analyzer, and
mock-distcheck recommendations remain intentionally deferred by the explicit
focused-validation scope.

### Checkpoint 4 reviewer repair cycle

The first CP4 routing implementation retained target bindings and queue-local
pointers across source batches. Review rejected that lifetime. Target buckets
are now strictly batch-scoped: final publish, error, and cancellation all run
with cancellation disabled through cancel/publish, unbind, wrapper destruction,
and bucket-array purge. An inactive wrapper produced by discardMark before the
first bind is a no-op. Queued-action egress was removed and explicitly deferred
to Checkpoint 5 so the existing action hot path remains unchanged.

Native input and WTI routing identities now come from one process-wide,
non-reusing allocator, with WTI allocation lazy until its first CA target.
Overlapping preparations on one shared handle exposed a tail-alignment hazard.
Preparation now obtains a worst-aligned chunk count independent of the current
tail; reverse commits at starts 0, 1, 63, and 64 for counts 1, 64, and 65, plus
two threads paused after prepare on one handle, passed without abort and with
exact contiguous identities. The builder gained one inline item. A CA_TESTING
counter proved zero item-array allocations for the first singleton, heap growth
only for a 65-item burst, and no new allocation for the later singleton.

Removing the qConcurrentTarget accepted-pointer mirror left builder.items as
the single unpublished ownership ledger. Cancellation decrements qqueue mirrors
and destroys every staged message once before builder cancellation. The qqueue
OOM hook was made lane-history-independent by rejecting the next chunk
acquisition even when a pooled chunk exists; the exact single/native-Multi OOM
ownership test then passed again.

A persistent two-allocation target preparation failure revealed a separate
integration defect: `msgConsumer` ignored `ruleset.ProcessBatch` errors and
blanket-marked the source COMM after `processBatch` had restored it RDY. The
reserved invocation now propagates its result and preserves exact batch states;
the legacy invocation retains the old emulation. Review then found that using
global `runConf->executionEngine` for that decision raced config replacement.
The policy is now captured in WTI state by `wtiEgressBegin`. A deterministic
post-ProcessBatch selector flip plus HUP passed both directions: reserved→legacy
kept the failed source RDY and replayed one exact target output, while
legacy→reserved kept legacy blanket completion.

Additional focused oracles passed:

- native and routed producers concurrently targeting one queue used distinct
  dedicated identities and delivered exact, ordered ranges 0..6 and 1000..1127;
- discardMark before first target bind committed the source exactly once and
  emitted only the independent filler at the target;
- A+B, A-only, then HUP and B-only emitted exact A={0,1}, B={0,2};
- persistent final-publish failure restored one source to RDY exactly once and
  replayed one exact target identity;
- native Multi timeout transferred three unpublished messages with zero
  publications, and discardMark transferred seven with zero admissions;
- crossed capacity-one pressure emitted IDs 0 and 1 exactly once at both
  targets; and
- immediate cancellation after target publication/binding purge returned the
  active source claim and completed worker unbind/core destruction.

Commands at this boundary included incremental `make -j4`, direct normal and
forced-pthread sparseLanes units, the SCQ unit, and registered focused
ConcurrentArray shell selections. One newly added persistent-failure test first
timed out: its debug trace directly exposed the blanket-COMM defect above. The
corrected retry and selector-race phases passed. The native timeout/discard test
first counted one unrelated startup diagnostic discard; narrowing its oracle to
the seven severity-7 injected messages passed. Heavy sanitizer, container,
static-analysis, broad-suite, performance, instrumented, and mock-distcheck
lanes remain deferred under the authorized focused scope.

Final post-format evidence: incremental `make -j4` passed; the registered SCQ,
normal sparseLanes, and forced-pthread units passed 3/3; the same sparseLanes
unit compiled with `CA_ENABLE_DIAGNOSTICS`, `-Wall -Wextra -Werror`, and passed.
The registered ConcurrentArray configuration, Main/named/legacy smoke,
capacity/full, OOM, native Multi, reserved routing/pressure, identity, discard,
retry/config-selector race, alternating subsets, and cancellation selection
passed 12/12. Clang-format-18 apply and dry-run, `git diff --check`, Bash syntax,
shellcheck warning level, the no-action-egress/no-mutable-selector structural
checks, and the test-antipattern scans passed. Six generated runtime-unit
binaries were removed; the tree remains uncommitted for independent review.

Documentation correction: the implementation-cycle entry above used
"persistent target bindings" and "queued action" for behavior that did not
survive review. The implemented target bindings are strictly source-batch
scoped, and the reserved-batch smoke exercises a direct `omfile` action after
dynamic queued ruleset staging. Queued-action staging remains deferred to
Checkpoint 5; `runtime/action.c` is unchanged by this checkpoint.

The deterministic post-`ProcessBatch` selector-flip hook and the
post-egress-publication cancellation pause are compiled only with
`ENABLE_IMDIAG`. Ordinary builds therefore contain neither their environment
lookups nor their hook strings or branches on the Main/legacy batch path.

Post-guard validation passed: incremental `make -j4`; registered
`concurrent-array-routing-retry.sh` and `concurrent-array-shutdown.sh` 2/2;
clang-format-18 dry-run; `git diff --check`; Bash syntax, shellcheck warning
level, and the repository antipattern scan across all 13 ConcurrentArray shell
tests. A source guard oracle counted both selector-flip references and the
post-publication pause reference and required each to occur inside an
`ENABLE_IMDIAG` region. The six runtime-unit binaries built as test
prerequisites were removed again.

## 2026-08-30 Checkpoint 4 final liveness and boundary correction

The earlier notebook entry naming an imdiag `injectmultimsg` command records a
discarded test implementation. The final exact native-Multi oracle is an
`ENABLE_IMDIAG`-only rsyslogd startup control-file hook invoked after Main
workers start. It creates an existing `multi_submit_t` directly, reports exact
adapter counters in the daemon log, and has no plugin source/ABI change or
ordinary per-message scan. Deterministic command-file `expect-error` replaced
the TCP-receive aggregation assumption in the late preparation-OOM ownership
test. Named target parsing accepts both the three-field normal and four-field
expected-error forms.

A capacity-two live pressure run exposed a real mixed-waiter deadlock: work
consumers and capacity producers shared one epoch/futex population, so a
publication wake could select a full producer and leave the only consumer
asleep with visible work. The core now has independent work and capacity
epochs, sleeper counts, and pthread condition variables. Publication signals
work; terminal completion/cancellation signals capacity; shutdown wakes both.
Every qqueue watermark, native Multi, and routed-target pressure wait now uses
the capacity epoch, while worker idle waits use only the work epoch.

Review then found that a batch completion releasing multiple credits still
used wake-one. Capacity release now wakes at most the number of released
credits and registered capacity sleepers in both futex and pthread adapters.
The deterministic unit parks one work waiter and two capacity waiters to prove
predicate separation, then a second case releases two credits and requires two
parked producers to return without another event even though neither reserves.
Registered SCQ, normal sparseLanes, and forced-pthread units passed 3/3. The
capacity-two live full test passed three consecutive runs in 5, 4, and 4
seconds, and crossed reserved-target pressure passed in one second.

Checkpoint 4 startup is also topology-strict: a failed ConcurrentArray Main or
named target under `reservedBatch` is fatal instead of silently converting to
Direct; deterministic injected failures cover both. Legacy execution keeps its
existing Direct fallback. The final focused post-format matrix passed the three
registered core tests, fourteen registered ConcurrentArray RainerScript/YAML
shell tests, repeated full-pressure runs, and reserved cross-pressure. The
design still defers queued-action staging and all ConcurrentArray action queues
to Checkpoint 5. Performance campaigns, sanitizers, containers, static
analysis, instrumented builds, broad suites, and mock distcheck remain deferred
under the authorized focused-validation scope.

The final native-Multi review found that filtering an entire span against
`initial_size + eligible` could discard a later message based on predecessors
that had not actually been admitted. Active discard policy now forces
per-message current-size checks and size-one admission; the default severity-8
policy still preserves roomy one-range publication. The startup oracle uses
severities 7,7,0,7 at capacity/discardMark two: the high-priority third item
forces worker drain, and exact admission/output of the fourth proves its size
was re-read after that drain. The native Multi test passed with exact counters
`reservations=5 publications=4 published=4 advice=2` and four identities.

Final documentation correction: an earlier entry said `runtime/action.c` was
unchanged in Checkpoint 4. Its execution/hot path is unchanged, but the file
does contain one configuration-only repair: action queue construction now
propagates `qqueueApplyCnfParam()` failure instead of ignoring it. ReservedBatch
queued actions and all ConcurrentArray action queues remain rejected until
Checkpoint 5.

## 2026-08-30 Checkpoint 5 implementation cycle

Checkpoint 5 reused the batch-scoped CP4 target wrapper for queued actions
rather than adding an action-specific storage path. `doSubmitToActionQ()` keeps
the Direct and legacy queued branches intact; the new middle branch is selected
only by an active reservedBatch WTI and an explicit supported ConcurrentArray
action queue. It transfers one `MsgDup`/`MsgAddRef` owner to
`wtiEgressStage()`. A monotonically changing egress-error generation lets
`execAct()` distinguish this invocation's staging failure from a prior target
failure without changing legacy action-error semantics.

The first live matrix covered synchronous and ConcurrentArray source rulesets,
each with Direct and ConcurrentArray actions, and produced ordered IDs 0..15 in
all four cells. Deterministic compiled-out faults then covered copy and
reference ownership at both the first and second action: early failure emitted
the source once after retry; late failure emitted the already published first
branch twice and the failed second branch once. The action-consumer fault
returned one claimed ID through the lane retry barrier and produced the exact
0..3 set. A held active action claim followed by immediate shutdown reached the
standard proper-termination marker after cancellation, claim return, worker
unbind, and core destruction.

An initial 8,192 transaction attempt claimed one testbench-internal startup
message plus 8,191 stimulus messages from Main. That was a test-design failure,
not a queue failure. The corrected test routes only numeric stimulus into a
named `source` ConcurrentArray and gates its worker advice until the impstats
enqueue counter reaches the exact count. The action then received one
transaction for 8,192 and one for 65,536 messages. The helper validated every
contiguous zero-based ID and recorded exact compact summaries
`BEGIN=1/MSG=N/COMMIT=1/ERRORS=0/EOF_IN_TX=no`. A three-message mixed case
observed the queued-action publication marker from the Direct transaction's
COMMIT callback, proving publish-before-Direct-commit ordering.

Suspension/recovery used a Direct omprog acceptance ledger and a
ConcurrentArray omfile action whose parent directory initially did not exist.
After impstats observed a real resume attempt, creating the directory drained
the action queue. Fast-first and slow-first order both ended with the exact 32
accepted IDs at the recovered output and no unaccepted IDs.

Focused commands at this point included:

- `./configure --cache-file=config.cache --enable-debug --enable-testbench --enable-omprog`
- `make -j4 check TESTS=''`
- direct `concurrent-array-action.sh`, `concurrent-array-action-oom.sh`,
  `concurrent-array-action-retry.sh`, `concurrent-array-action-shutdown.sh`,
  `concurrent-array-action-transaction.sh`, and
  `concurrent-array-action-suspend.sh`

The direct CP5 matrix passed. The transaction test passed its 8,192, 65,536,
and publish-before-Direct-COMMIT phases; suspension passed both action orders.
No plugin source changed; omprog was enabled only to compile the unchanged
plugin and exercise its existing transaction callback ABI. Sanitizers,
containers, static analysis, broad suites, performance, instrumented builds,
and mock distcheck remain deferred by the authorized focused scope.

The first ordinary-build configure command combined `--enable-testbench` with
`--disable-imdiag`; configure rejected that combination by design. The
corrected compile-out gate used
`./configure --enable-debug --disable-testbench --disable-imdiag
--enable-omprog` followed by `make -j4`. It found one real guard defect:
`concurrentArrayBatchProcessed()` used its queue parameter only inside the
`ENABLE_IMDIAG` marker block. An explicit non-imdiag unused-parameter guard
fixed the `-Werror` failure. The ordinary build then passed, and `strings` over
`runtime/.libs/librsyslog.a`, `tools/rsyslogd`, and the unchanged omprog shared
object found none of the ConcurrentArray action-publication, copy/stage,
consumer/claim, or worker-gate test-hook names.

After restoring `--enable-testbench --enable-omprog`, incremental
`make -j4 check TESTS=''` passed. The ready-SCQ unit, normal sparseLanes unit,
and forced-pthread sparseLanes unit passed directly. The six registered CP5
shell tests passed through Automake, and the post-format direct config, action
matrix, 8,192/65,536 transaction, and publication-order phases passed again.
`clang-format-18` dry-run, `git diff --check`, Bash syntax, shellcheck warning
level, Python style/byte compilation, and the focused test-antipattern review
were clean after documenting the deliberately backgrounded-and-awaited
suspension injector. The antipattern scan's only remaining matches are the
documented CI guard bounds and that explicitly owned injector. No plugin or
public message/MultiSubmit header diff exists.

At the Checkpoint 5 cycle start, hosted PR 7535 showed every completed check
green and Cubic skipped; no hosted check was waited on or re-polled. Disk
assistance and fallback selection remain Checkpoint 6 work. Formal throughput
and contention verdicts remain reserved for the later dedicated-machine
performance and instrumented-build campaigns, after candidate code is ready.

## 2026-08-30 Checkpoint 5 review P2 closure

The suspension/recovery oracle now snapshots a nonempty fast-first Direct
acceptance ledger before the missing queued-action directory is created. After
recovery it checks the raw row count and anchored message format for both the
acceptance ledger and queued output before extracting IDs, then retains the
exact unique-set comparison. This prevents malformed or extra rows from being
hidden by the extraction pipeline. Both fast-first and slow-first cells passed.

Transaction parameter growth now rejects `newMax > INT_MAX` before the checked
allocation multiplication and before assigning the result back to the `int`
capacity field. The exact 65,536-message transaction continues to exercise the
normal doubling path through multiple reallocations; a synthetic near-INT_MAX
WTI mutation hook was not added because it would introduce test-only state into
the transaction hot path solely to reach an impractical allocation boundary.
Incremental `make -j4 check TESTS=''`, the 8,192/65,536/order transaction cells,
and both suspension cells passed. Bash syntax, shellcheck warning level,
clang-format dry-run, `git diff --check`, and focused antipattern review passed;
generated runtime-unit binaries were removed again.
