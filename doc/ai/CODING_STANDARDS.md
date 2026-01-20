# Coding Standards and Workflow for AI Agents

This guide defines the coding standards, formatting rules, and workflow expectations for AI agents contributing to rsyslog.

## Development Workflow

### Base Repository
- URL: https://github.com/rsyslog/rsyslog
- **Default base branch: `main`**
- The `main` branch is the canonical base. Older references to `master` should be ignored.

### Contributor Workflow
1.  Fork the repository (for personal development).
2.  Create a feature/fix branch.
3.  Push changes to your fork.
4.  But always open a **pull request directly into `rsyslog/rsyslog:main`**.

> **Important**: AI-generated PRs must target the `rsyslog/rsyslog` repository directly.

### Branch Naming Conventions
- For issue-based work: `i-<issue-number>` (e.g., `i-2245`)
- For AI-generated work: prefix the branch name with the AI tool name (e.g., `gpt-i-2245-json-stats-export`)

## Coding Standards

- **Language**: Primary language is C.
- **Self-documenting code**: Favor clear variable/function names over excessive inline comments.
- **Public functions**: Must use Doxygen-style comments. See [`COMMENTING_STYLE.md`](../../COMMENTING_STYLE.md) for details.
- **Modules**: Must implement and register `modInit()` and `modExit()`.

## Defensive Coding and Assertions

Use `assert()` to signal "impossible" states to Static Analyzers and AI agents. Whenever feasible and low-complexity, follow with a defensive `if` check to prevent production crashes. See [Defensive Coding Practice](../source/development/coding_practices/defensive_coding.rst) for full details.

- **Mandatory**: `assert()` for invariants (allows SA/AI to reason about code).
- **Recommended**: Defensive `if` check (optional if fallback logic is excessively complex).
- **Prohibited**: `__builtin_unreachable()` (causes Undefined Behavior).

## Automated Formatting Normalization Strategy

We treat formatting as a normalization step, not a developer-side constraint. AI agents should follow this process:

1.  **Canonical formatting via clang-format**: Use the Google-style base with 4-space indentation in `.clang-format`.
2.  **Helper-based normalization**: Run `devtools/format-code.sh` to run clang-format and potential helper scripts.
3.  **Final formatting step**: Always run `devtools/format-code.sh` before committing.

## File Registration Rules (Makefile.am)

**Crucial Step:** When adding **ANY** new file to the repository, you **MUST** register it in the corresponding `Makefile.am`.

- **Documentation files (`doc/`)**: Add the filename to the `EXTRA_DIST` variable in `doc/Makefile.am`.
- **Source files (`plugins/`, `runtime/`)**: Add the filename to `_SOURCES` or `_LIBADD` lists in the Makefile.am of the directory.
- **Tests (`tests/`)**: Add test scripts to `TESTS` and `EXTRA_DIST` in `tests/Makefile.am`.

**Failure to do this will result in the file being missing from the distribution tarball.**

## Documentation Requirements

When introducing new configuration parameters, features, or significant behavior changes, you **must** update the user-facing documentation in the `doc/` subtree.

1.  **Locate the relevant guide**: Most module documentation is in `doc/source/configuration/modules/<module>.rst`.
2.  **Update parameter references**: If adding a parameter, create or update the corresponding file in `doc/source/reference/parameters/` and include it in the module's `.rst` file.
3.  **Cross-link**: Ensure new documentation is discoverable from the module's main page and appropriate `index.rst`.
4.  **Validate**: Run `make html` (from project root or `doc/`) to catch Sphinx errors.

## AI Agent Commit Convention

If you are an AI agent contributing code or documentation:

- Use the same rich commit message text as your PR description.
- Avoid generating multiple PRs for retries — reuse and update the original PR when possible.
- **Mandatory**: When crafting commit messages, you **must use the canonical commit-message base prompt** located at `ai/rsyslog_commit_assistant/base_prompt.txt`. Do not draft commit messages without the prompt.
- **Format**:
    - Commit message titles **must not exceed 62 characters**.
    - Body lines wrapped at **72 characters**.
    - Plain US ASCII.
- **Attribution**: Include a line in the commit footer like `With the help of AI-Agents: <agent-name>`.
- **Commit-first:** Ensure the substance is in the commit body (not only the PR).

## AI-Specific Hints

- The `plugins/` directory contains dynamically loaded input/output plugins.
- `contrib/` contains external contributions (e.g., plugins) that are not core-maintained.
- `statsobj.c` implements the statistics interface.
- Documentation resides in the monorepo’s `doc/` directory.
- **Discovery order**: Start with `AGENTS.md`, follow subtree `AGENTS.md`, then ingest `doc/source/development/coding_practices.rst`.
- **Shell Script Documentation**: Use shdoc-style comments (`##`, `###`) in new bash scripts.

## Quickstart for AI coding agents (v8 concurrency & state)

**Rules you must not break:**
1. The framework may run **multiple workers per action**.
2. `wrkrInstanceData_t` (WID) is **per-worker**; never share it.
3. Shared mutable state lives in **pData** (per-action) and **must be protected** by the module (mutex/rwlock). Do **not** rely on `mutAction` for this.
4. **Inherently serial resources** (e.g., a shared stream) must be serialized inside the module via a mutex in **pData**.
5. **Direct queues** do not remove the need to serialize serial resources.

**Common agent tasks:**
- Consult `doc/ai/module_map.yaml` to understand module paths and known locking.
- Add a “Concurrency & Locking” block at the top of output modules.
- Ensure serial modules guard stream/flush with a **pData** mutex.

## Privacy, Trust & Permissions

- AI agents **must not** push changes directly to user forks — always open PRs against `rsyslog/rsyslog`.
- Do not install third-party dependencies unless explicitly approved.
- PRs must pass standard CI and review checks.
- All code **must be reviewed manually**.

## Pre-Commit Checklist (AI Agents)

Complete these steps when the change is ready to commit:

1.  **Format code** (required): `devtools/format-code.sh`
2.  **Confirm validation** (required): See `doc/ai/BUILDING.md`.
3.  **Use commit prompt** (required): `ai/rsyslog_commit_assistant/base_prompt.txt`.
