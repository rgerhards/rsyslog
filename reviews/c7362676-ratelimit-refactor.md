# Review of commit c7362676fd939bdc14b44d91da56c6bc2116fee1

## Summary
The commit introduces a shared `ratelimit()` configuration object, a registry of named policies under `rsconf_t`, and updates numerous modules to resolve rate-limiter settings through that registry. Inline `ratelimit.*` parameters are promoted into the registry as ad-hoc entries. Modules then construct runtime limiters via `ratelimitNewFromConfig()` in addition to the legacy inline path.

## Positive aspects
* Central registry could help operators reuse the same policy across modules without repeating interval/burst settings and gives them a single naming scheme. The overview comment in `runtime/ratelimit.c` highlights the intended separation between parsing, registry management, and runtime enforcement.【F:runtime/ratelimit.c†L41-L67】
* API validation adds guard rails against mixing `ratelimit.name` with inline values, which prevents ambiguous configurations.【F:runtime/ratelimit.c†L400-L455】

## Complexity and maintenance costs
* `ratelimit_t` now needs both immutable and override paths (`cfg` versus `*_override` fields plus `has_override`), expanding the surface that every caller must understand before using the API.【F:runtime/ratelimit.h†L48-L83】
* The registry introduces linked-list management, synthetic-name generation for ad-hoc cases, and multiple helper entry points (`ratelimitConfigCreateNamed`, `CreateAdHoc`, `ResolveConfig`, `ResolveFromValues`). This adds ~200 lines of indirection before the actual limiter logic runs.【F:runtime/ratelimit.c†L83-L320】【F:runtime/ratelimit.c†L400-L455】
* Each module now carries both inline fields (`ratelimitInterval`, `ratelimitBurst`) and a `ratelimit_config_t *` plus name plumbing. That increases configuration-state duplication and error handling in every module that participates (for example `imudp`).【F:plugins/imudp/imudp.c†L109-L208】【F:plugins/imudp/imudp.c†L893-L982】
* Because ad-hoc entries are still generated for inline settings, the runtime has to support two parallel concepts (legacy overrides and shared configs) instead of simplifying to one path. The helper explicitly flips between them depending on whether `ratelimit.name` was present.【F:runtime/ratelimit.c†L400-L455】

Overall the ratelimiting subsystem now spans roughly 1,000 lines split across configuration storage, object parsing, and runtime execution. The indirection level is high compared to the previous inline-only approach, so future maintainers must reason about registry lifetime, synthetic identifiers, and override semantics before making changes. I would rate the complexity of the new design as **high** for the amount of functionality gained.

## Trade-off discussion
* **Pros:** shared naming can reduce config duplication; central validation could ease future enhancements if multiple modules need the same knobs.
* **Cons:** configuration registry maintenance adds global state, additional memory churn on reload, and many more code paths to audit for thread-safety. Modules lose the simplicity of "set interval/burst on the limiter" and must call the resolver helper correctly. The coexistence of shared and legacy limiters keeps the old complexity while adding new plumbing.

Given these trade-offs, the benefit of having both named and ad-hoc limiters seems limited. If the goal is to avoid retyping settings, a lighter approach would be to only use the shared registry when `ratelimit.name` is provided and otherwise keep module-local limiters as they were. The maintainer direction is that inline objects remain supported for now, while modules adopt the registry path whenever a name is configured, with deprecation of inline-only configuration deferred to a later phase.

## Suggested next steps
1. Clarify the transition plan: document that inline ratelimit parameters continue to work as-is today, but modules must honor `ratelimit.name` by resolving through the registry so that inline usage can be phased out later.
2. If named objects are kept, provide a thin adapter so modules that do not care about sharing can continue to use `ratelimitSetLinuxLike()` without tracking `ratelimit_config_t *`. That would isolate the new complexity to modules that opt-in to named policies.
3. Document the lifecycle and thread-safety guarantees of the registry, and consider unit coverage for reload scenarios to make sure ad-hoc entries do not leak or collide.
