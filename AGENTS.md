# AGENTS.md – rsyslog Repository Agent Guide

This file defines guidelines and instructions for AI assistants to understand and contribute effectively to the rsyslog codebase.

> **Note**: Detailed instructions have been moved to focused files in `doc/ai/`. See the **Quick Links** below.

## Quick Links

- **Build & Test Instructions**: [`doc/ai/BUILDING.md`](doc/ai/BUILDING.md) (The single source of truth for building and testing)
- **Coding Standards & Workflow**: [`doc/ai/CODING_STANDARDS.md`](doc/ai/CODING_STANDARDS.md) (Formatting, commits, privacy, defensive coding)
- **Module Capabilities**: [`doc/ai/MODULES.md`](doc/ai/MODULES.md) (Dependencies and testability)
- **Documentation Guide**: [`doc/AGENTS.md`](doc/AGENTS.md)
- **Commit Prompt**: [`ai/rsyslog_commit_assistant/base_prompt.txt`](ai/rsyslog_commit_assistant/base_prompt.txt) (Mandatory for commit messages)

## ⚠️ Critical: Definition of Done

**Before considering ANY task complete, you MUST verify:**

1.  **File Registration**: Did you create a new file? If yes, it **MUST** be registered in the corresponding `Makefile.am` (e.g., `doc/Makefile.am` for docs, `plugins/Makefile.am` for code). **If you skip this, the file will be excluded from the release.**
2.  **Build Check**: run `make` or `make html` to confirm your changes are valid.
3.  **No `autogen.sh`**: Do not run `autogen.sh` if `configure` exists.

## Agent Quick Start: The "Happy Path"

Follow these steps for a typical development task. **For granular details (e.g. environment setup), see [`doc/ai/BUILDING.md`](doc/ai/BUILDING.md).**

1.  **Set Up**: If in a fresh Debian/Ubuntu CI, install dependencies (detailed in `doc/ai/BUILDING.md`).
2.  **Build**:
    ```bash
    make -j$(nproc) check TESTS=""
    ```
3.  **Run Tests**:
    ```bash
    ./tests/imtcp-basic.sh
    ```
4.  **Format**:
    ```bash
    devtools/format-code.sh
    ```

## Repository Overview

- **Primary Language**: C
- **Build System**: autotools (`autogen.sh`, `configure`, `make`)
- **Architecture**: Microkernel-like core (`runtime/`) with loadable plugins (`plugins/`)
- **Modules**: Dynamically loaded from `plugins/` (legacy: `tools/`)
- **Contrib**: Community modules in `contrib/`
- **Documentation**: `doc/`
- **AI module map**: `doc/ai/module_map.yaml`

-----

## Agent Chat Keywords

The following chat codewords instruct AI assistants to perform standardized actions in this repository.

### `FINISH`

When the user says the codeword "FINISH", do the following:

- Perform a final review of all proposed code changes for correctness and style before concluding the session.

### `SUMMARIZE`

When the user says the codeword "SUMMARIZE", do the following:

- Create and print the following summaries in the Agent chat, each in a copy-ready TEXTBOX field:
  - A summary for the pull request
  - A summary for a squashed commit message

### `SETUP`

When the user says the codeword "SETUP", do the following:

- Follow the instructions in the "Step 1: Set Up the Environment" section of [`doc/ai/BUILDING.md`](doc/ai/BUILDING.md).

### `BUILD [configure-options]`

When the user says the codeword "BUILD" optionally followed by configure options, do the following:

1. **Check for existing build configuration**:
   - If `configure` and `Makefile` exist, no new configure options are provided, and you did not change `configure.ac`, `Makefile.am`, or files under `m4/`, **SKIP** to Step 3.

2. **Generate and Configure** (if Makefile is missing or options provided):
   ```bash
   ./autogen.sh --enable-debug
   ```
   - If configure options are provided: `./autogen.sh --enable-debug [user-provided-options]`
   - If no options: `./autogen.sh --enable-debug --enable-testbench --enable-imdiag --enable-omstdout --enable-mmsnareparse --enable-omotel --enable-imhttp`

3. **Build the project**:
   ```bash
   make -j$(nproc) check TESTS=""
   ```

### `TEST [test-script-names]`

When the user says the codeword "TEST" optionally followed by test script names, do the following:

1. **Ensure the project is built** (if not already built, run BUILD first)

2. **Run tests**:
   - If test script names are provided:
     ```bash
     ./tests/<test-script-name>.sh
     ```
   - If no test names are provided, run default smoke test:
     ```bash
     ./tests/imtcp-basic.sh
     ```

## Priming a fresh AI session

When starting a new AI-assisted coding session:

1.  **Ingest Context**: Read this file (`AGENTS.md`) and the relevant focused guides:
    - [`doc/ai/BUILDING.md`](doc/ai/BUILDING.md) for build/test mechanics.
    - [`doc/ai/CODING_STANDARDS.md`](doc/ai/CODING_STANDARDS.md) for style and workflow.
    - The subtree guide (`plugins/AGENTS.md`, etc.) for the specific component you are working on.
2.  **Load Metadata**: Read `MODULE_METADATA.yaml` for the component.
3.  **Read Prompts**: Load the commit assistant prompt (`ai/rsyslog_commit_assistant/base_prompt.txt`).
