# proc-sentry

A lightweight, zero-dependency Linux process and memory integrity auditor written in strict ANSI C (C89) and POSIX.1-2008.

`proc-sentry` goes through `/proc` to inspect running processes for indicators of tampering, weird memory configurations, and dynamic linker hijacking.

---

## What It Checks

| Component | Target | Purpose | Mechanism |
|---|---|---|---|
| **Crawler** | `/proc` | Enumerate running tasks | Filters numeric directory entries using `opendir` and `readdir`. |
| **Exe Audit** | `/proc/[pid]/exe` | Detect deleted/unlinked binaries | Resolves symlinks using `readlink` to identify processes running purely from RAM (`(deleted)`). |
| **Maps Audit** | `/proc/[pid]/maps` | Check memory permissions | Identifies $W \oplus X$ violations (e.g. `rwx` pages) and anonymous executable mappings. |
| **Env Audit** | `/proc/[pid]/environ` | Spot linker hijacking vectors | Parses null-delimited initial environment streams for `LD_PRELOAD`, `LD_LIBRARY_PATH`, and `LD_AUDIT`. |
| **Watch Mode** | Terminal loop | Monitor process churn live | Clears the terminal using ANSI escapes, polls periodically, and catches `SIGINT` (`Ctrl+C`) cleanly. |

---

## Build Standards

- **Standard:** ANSI C89 (`-ansi`)
- **Flags:** `-Wall -Wextra -pedantic`
- **Feature Macro:** `-D_POSIX_C_SOURCE=200809L`
- **Dependencies:** None beyond the C standard library.

---

## Quickstart

```bash
# Build the binary
make proc-sentry

# Single-shot system sweep
./proc-sentry

# Continuous watch mode (polls every N seconds, default is 2)
./proc-sentry -w 2

# Remove compiled artifacts
make clean
