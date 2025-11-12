ratelimit() YAML policy loading plan
===================================

Background
----------

The current :rainerscript:`ratelimit()` implementation stores immutable policy
parameters (``interval``, ``burst``, ``severity``) in
``ratelimit_config_t`` instances that are added both to a per-configuration
list and to a global registry so named policies can be reused across inputs and
outputs.【F:runtime/ratelimit.c†L78-L118】  Policies are created from inline
parameters parsed in :c:func:`ratelimitProcessCnf`, which enforces that every
object defines its own numeric values before persisting them in the store.【F:runtime/ratelimit.c†L620-L686】  The helper structure
:c:type:`ratelimit_config_spec_t` captures the same three fields and is used to
populate each policy entry.【F:runtime/ratelimit.h†L37-L48】

Goal
----

Add support for an optional ``policy=<filename.yml>`` parameter on
:rainerscript:`ratelimit()` so operators can externalize rate-limiting profiles
into reusable YAML documents instead of repeating values inline.

Desired behaviour:

* When ``policy`` is provided, rsyslog must load the referenced YAML file
  during configuration processing and populate the policy with its content.
* The YAML format should expose the same keys we already support inline
  (``interval``, ``burst``, ``severity``) while leaving room for future
  extensions.
* Inline numeric parameters remain supported but cannot be combined with a
  ``policy`` reference to avoid conflicting sources of truth.
* Errors in reading or parsing the file should abort configuration loading with
  actionable diagnostics.

Library evaluation
------------------

We need a small, widely packaged YAML parser with a C interface. Two candidates
stand out:

* **libyaml (a.k.a. yaml)** – MIT licensed, available in all major
  distributions, mature streaming API, already packaged as ``libyaml-dev`` on
  Debian/Ubuntu and ``yaml`` on RHEL/Fedora.
* **libfyaml** – modern C library with full YAML 1.2 support but comparatively
  newer and not yet ubiquitous on long-term-support distributions.

libyaml strikes the right balance between availability, maturity, and minimal
API surface, so the plan below assumes we integrate against ``yaml.h``. We can
wrap the streaming parser in a small helper that reads scalars into our spec
struct without exposing the rest of the codebase to libyaml types.

High-level implementation plan
------------------------------

1. **Configuration schema updates**

   * Extend ``ratelimit_config_spec_t`` with metadata about the originating
     file (e.g. ``char *policy_path``) so policies can report where their
     values came from. Update ``ratelimit_config_t`` and the registry teardown
     logic to duplicate and free the path alongside the existing ``name``
     field.【F:runtime/ratelimit.c†L78-L118】
   * Update ``ratelimitConfigSpecInit`` to reset the new field and extend
     ``ratelimitConfigValidateSpec`` to reject empty specs (e.g. file without
     ``interval``/``burst``) and to ensure ``policy_path`` is never combined
     with inline overrides.【F:runtime/ratelimit.c†L122-L160】【F:runtime/ratelimit.c†L620-L686】

2. **Grammar and parameter handling**

   * Add ``policy`` as an optional string descriptor in ``ratelimitpdescr`` so
     the parser accepts the new parameter.【F:runtime/ratelimit.c†L111-L118】
   * Teach ``ratelimitProcessCnf`` to detect ``policy``. When present, remember
     the path, skip inline value collection, and defer to the YAML loader. If
     inline numeric keys also appear, emit the same style of ``LogError`` used
     today for invalid combinations and abort processing.【F:runtime/ratelimit.c†L620-L686】

3. **YAML loading helper**

   * Introduce a new internal helper (e.g. ``ratelimitPolicyLoadFromYaml``)
     that accepts the file path and a spec pointer. It should:

       - Open the file relative to the current working directory (matching how
         other rsyslog includes behave) and surface ``errno`` on failure.
       - Use libyaml to parse the document, requiring a mapping at the top
         level with scalar keys ``interval``, ``burst``, and optional
         ``severity``. Values must be integers; emit descriptive errors when
         types mismatch or keys are missing.
       - Reuse ``ratelimitConfigValidateSpec`` for range checks so we keep a
         single validation path.
       - Record the absolute (or canonicalized) path in ``policy_path`` for
         diagnostics.

   * For builds compiled without libyaml, guard the helper behind
     ``#ifdef HAVE_LIBYAML`` and produce a ``LogError`` explaining that YAML
     support is disabled.

4. **Build system integration**

   * Add ``PKG_CHECK_MODULES([LIBYAML], [yaml-0.1])`` to ``configure.ac`` and
     wire ``HAVE_LIBYAML`` into ``config.h``. Fallback gracefully when the
     dependency is missing by disabling the feature.
   * Update ``runtime/Makefile.am`` to link ``librsyslog_runtime_la`` against
     ``$(LIBYAML_LIBS)`` and expose ``$(LIBYAML_CFLAGS)``.
   * Ensure packaging documentation references the new optional dependency.

5. **Registry and runtime plumbing**

   * When creating a configuration entry, duplicate ``policy_path`` into the
     stored ``ratelimit_config_t`` so runtime diagnostics can mention the file
     source. Ensure ``ratelimitStoreDestruct`` and registry removal free the
     additional allocation.【F:runtime/ratelimit.c†L200-L237】
   * Expose a lightweight accessor (e.g. ``ratelimitConfigGetPolicyPath``) for
     future modules that may want to surface the origin in status outputs.

6. **Documentation updates**

   * Extend ``doc/source/rainerscript/ratelimit.rst`` with an example YAML file
     and detail the new parameter semantics, including the prohibition on
     mixing inline values with ``policy`` references.【F:doc/source/rainerscript/ratelimit.rst†L1-L58】
   * Document the expected YAML schema, error handling, and build-time
     dependency in the developer section for future maintenance.

7. **Testing and validation**

   * Add configuration validation tests under ``tests/`` that cover successful
     YAML loading, missing-file failures, schema errors, and the "inline values
     mixed with policy" rejection path.
   * Introduce a unit-style regression test that instantiates a ratelimiter via
     ``ratelimit.name`` pointing at a YAML-backed policy to ensure runtime
     counters operate with the parsed values.
   * Gate YAML-specific tests so they skip (with a clear message) when rsyslog
     is built without libyaml.

Open questions / follow-ups
---------------------------

* Should we allow YAML files to define advanced fields (e.g. future
  repeat-suppression tuning)? The current plan limits scope to existing keys
  but leaves room for expansion once requirements solidify.
* Do we want to memoize file contents for reuse across multiple ratelimit
  objects that point to the same YAML file? That would require a hash table of
  parsed documents and cache invalidation on reload; for the first iteration we
  can reload the file on each object definition and revisit caching if needed.
* If operators expect ``policy`` paths to be relative to the configuration file
  that declares them, we may need to capture the include stack or reuse the
  config file directory when resolving paths. This is worth validating during
  implementation.
