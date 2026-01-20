# Building and Testing Guide for AI Agents

This guide provides detailed instructions on how to set up the environment, build rsyslog, and run tests. It is the single source of truth for build mechanics.

## Step 1: Set Up the Environment (If Needed)

For some agents, like Jules, the development environment is often Debian/Ubuntu-based. If you are in such an environment and need to install dependencies, the following command provides a complete set for building and testing.

**Warning:** Only run this command if you are on a Debian-based system (like Ubuntu) and have `sudo` privileges. Do not run this in an unknown CI or containerized environment, as it may cause unintended changes.

```bash
# Optional: For Debian/Ubuntu-based environments
sudo apt-get update && sudo apt-get install -y \
    autoconf autoconf-archive automake autotools-dev \
    bison flex gcc \
    libcurl4-gnutls-dev libdbi-dev libgcrypt20-dev \
    libglib2.0-dev libgnutls28-dev \
    libtool libtool-bin libzstd-dev make \
    libestr-dev python3-docutils libfastjson-dev \
    librelp-dev liblognorm-dev libaprutil1-dev libcivetweb-dev \
    valgrind clang-format
```

## Build System Generation

The `configure` script and `Makefile.in` files are **not** stored in git.

**Important**: If the `configure` script already exists, you should **NOT** run `autogen.sh` again unless you have modified `configure.ac`, `Makefile.am`, or `m4/` files. Re-running it wipes the current configuration.

If `configure` is missing or build inputs have changed, you **must** run:

```bash
./autogen.sh --enable-debug
```

`autogen.sh` accepts configure options and runs `configure`. Pass any additional module or test flags directly to `autogen.sh`.

This bootstraps autotools, downloads any required macros, and generates `configure`. `make` may rerun `config.status` when `configure` or `Makefile.in` change, but it does **not** regenerate `configure` or `Makefile.in` from `configure.ac` or `m4/`—that still requires `autogen.sh`.

Skipping this step is the most common reason for messages such as `configure: error: cannot find install-sh, install.sh, or shtool` or `make: *** No targets specified and no makefile found`. If a cleanup removed the generated files (e.g., `git clean -xfd`), re-run `./autogen.sh --enable-debug` before configuring again.

If `./autogen.sh --enable-debug` fails, run `./devtools/codex-setup.sh` first to install the toolchain dependencies inside the sandbox, then retry `./autogen.sh --enable-debug`.

## Configure & Build

Whenever `.c` or `.h` files are modified, a build should be performed.

### Efficient Build

Use the build-only command that prepares all test binaries without running tests:

```bash
make -j$(nproc) check TESTS=""
```

This is the recommended default build command for agents. It ensures that the core and all test dependencies are built, so you can run individual scripts immediately after.

### Build Triggers
- If `configure` is missing or when `configure.ac`, `Makefile.am`, or files under `m4/` change, run `./autogen.sh --enable-debug [configure-flags]` with any required module/test options.
- If only source files change, re-run `make -j$(nproc) check TESTS=""`.

> In restricted environments, a build may not be possible. In such cases, ensure the generated code is clear and well-commented to aid review.

## Testing & Validation

All test definitions live under the `tests/` directory and are driven by the `tests/diag.sh` framework. 

**Critical Rule for Agents:** **AI agents must use direct test scripts only**. Never use the `make check` harness.

Avoiding the harness matters because `make check`:
- Wraps tests in a harness that hides stdout/stderr on failure.
- Requires parsing `tests/test-suite.log` for details.
- Consumes significant resources on large suites (10+ minutes).

Instead, invoke individual test scripts directly. This yields unfiltered output and immediate feedback. The `diag.sh` framework builds required test support automatically, but the build-only step (`make ... check TESTS=""`) is still required when code changes warrant it.

### Running Individual Tests

1.  **Configure the project** (once per session, if `configure` is missing):
    ```bash
    ./autogen.sh --enable-debug --enable-imdiag --enable-testbench
    ```
2.  **Invoke your test**:
    ```bash
    ./tests/<test-script>.sh
    ```
    For example:
    ```bash
    ./tests/manytcp-too-few-tls-vg.sh > /tmp/test.log && tail -n20 /tmp/test.log
    ```
3.  **Why this works**:
      - Each test script transparently finds and loads the test harness.
      - You get unfiltered stdout/stderr without any CI wrapper.
      - No manual `cd` or log-file parsing required.

### Test Environment

Human developers can replicate CI conditions using the official container images available on **Docker Hub**. For single-test runs, we recommend `rsyslog/rsyslog_dev_base_ubuntu:24.04`. It is **recommended** that AI agents use the standard workflow within their existing environment to avoid potential complications, but they may use container images if necessary to reproduce a specific environment.

## Validate Code Changes

Run these checks after code changes, before you consider the work ready:

1.  **Build** (required):
    ```bash
    make -j$(nproc) check TESTS=""
    ```
2.  **Run relevant tests** (required):
    ```bash
    ./tests/<test-script>.sh
    ```
    If new functionality is introduced, at least a basic test should be created and run. `imtcp-basic.sh` serves as a good general-purpose smoke test if no specific test exists.

3.  **Run Cubic review** (best-effort):
    ```bash
    cubic review --json --base main
    ```
    If `cubic` is unavailable in the current session, skip this step. If it runs, address any reported issues.
