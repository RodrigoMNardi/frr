# FRR AI Agent Collaboration Guide

This document describes the conventions, patterns, and constraints that AI agents must follow when contributing to the FRR (Free Range Routing) codebase. It is a complement to the human-focused workflow documentation in `doc/developer/workflow.rst`.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Repository Structure](#2-repository-structure)
3. [Before Making Any Change](#3-before-making-any-change)
4. [C Coding Conventions](#4-c-coding-conventions)
5. [Memory Management](#5-memory-management)
6. [Error Handling and Logging](#6-error-handling-and-logging)
7. [Data Structures](#7-data-structures)
8. [CLI / VTY Integration](#8-cli--vty-integration)
9. [YANG / Northbound](#9-yang--northbound)
10. [Commit and PR Standards](#10-commit-and-pr-standards)
11. [Testing Requirements](#11-testing-requirements)
12. [Code Formatting](#12-code-formatting)
13. [Security and Defensive Coding](#13-security-and-defensive-coding)
14. [Common Pitfalls](#14-common-pitfalls)

---

## 1. Project Overview

FRR is a production-grade, multi-daemon IP routing suite for Linux and Unix platforms. It implements BGP, OSPF, IS-IS, RIP, PIM, LDP, EIGRP, NHRP, VRRP, BFD, and others. All daemons share a common library (`lib/`) and communicate through a central kernel abstraction layer (`zebra/`).

Key characteristics:
- Language: C (C11), Python (tests and tooling)
- Build system: GNU Autotools (`configure.ac` / `Makefile.am`)
- Kernel interface: Netlink (Linux), PF_ROUTE (BSD)
- Configuration: YANG models via `mgmtd`, legacy VTY still in use
- License: GPL-2.0-or-later (DCO required for all contributions)

---

## 2. Repository Structure

```
frr/
├── lib/           # Shared libraries: data structures, VTY, logging, memory, timers
├── zebra/         # Kernel abstraction / RIB manager
├── bgpd/          # BGP daemon
├── ospfd/         # OSPFv2 daemon
├── ospf6d/        # OSPFv3 daemon
├── isisd/         # IS-IS daemon
├── pimd/          # PIM-SM daemon
├── pim6d/         # PIMv6 daemon
├── ripd/          # RIPv2 daemon
├── ripngd/        # RIPng daemon
├── ldpd/          # LDP daemon
├── nhrpd/         # NHRP daemon
├── eigrpd/        # EIGRP daemon (alpha)
├── bfdd/          # BFD daemon
├── vrrpd/         # VRRP daemon
├── staticd/       # Static route daemon
├── pbrd/          # Policy-Based Routing daemon
├── pathd/         # Path computation daemon
├── mgmtd/         # Centralized management daemon
├── sharpd/        # Testing/debugging daemon
├── vtysh/         # Unified CLI shell
├── yang/          # YANG model definitions
├── tests/         # Test suite (Python + C unit tests)
├── tools/         # Maintenance and style scripts
├── doc/           # Documentation (RST)
│   └── developer/ # Developer workflow, coding guides
└── .github/       # CI workflows and PR templates
```

**Anatomy of a typical daemon directory** (e.g., `bgpd/`):

| File | Purpose |
|------|---------|
| `<daemon>.c` / `<daemon>.h` | Main daemon data structures and logic |
| `<daemon>_main.c` | Entry point, signal handling, daemon lifecycle |
| `<daemon>_vty.c` | CLI command definitions (DEFUN macros) |
| `<daemon>_zebra.c` | Zebra client integration |
| `<daemon>_errors.c/.h` | Daemon-specific error codes |
| `<daemon>_memory.c/.h` | Memory type declarations |
| `<daemon>_nb.c/.h` | YANG northbound callbacks (when migrated) |

---

## 3. Before Making Any Change

1. **Read the relevant daemon's main header** to understand existing data structures.
2. **Check `lib/` first** before implementing utility functions — it likely already exists.
3. **Search for the pattern** you need using `grep -r` before introducing a new one.
4. **Never modify generated files** — files under `yang/` compiled outputs, or autoconf artifacts.
5. **Run `./configure` before building** if the build system changed.
6. **Check CI workflows** in `.github/workflows/` to understand what the CI gate validates.

---

## 4. C Coding Conventions

### File Header

Every new `.c`, `.h`, or `.py` file **must** begin with:

```c
// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Brief description of this file's purpose.
 * Copyright (C) YEAR  Author Name <email>
 */
```

### Include Order

```c
#include <zebra.h>        // Always first in .c files

#include "lib/foo.h"      // lib/ headers next
#include "lib/bar.h"

#include "bgpd/bgp_foo.h" // Daemon-local headers last
```

Headers must use `#ifndef` guards:

```c
#ifndef _ZEBRA_BGPFOO_H
#define _ZEBRA_BGPFOO_H
/* ... */
#endif /* _ZEBRA_BGPFOO_H */
```

### Naming Conventions

| Kind | Convention | Example |
|------|-----------|---------|
| Functions | `lowercase_underscore` | `bgp_peer_create()` |
| Local macros | `UPPER_UNDERSCORE` | `BGP_TIMER_ON` |
| Constants / enums | `UPPER_UNDERSCORE` | `BGP_STATUS_IDLE` |
| Struct typedefs | `lowercase_underscore` then `_t` rarely; prefer plain `struct` | `struct bgp_peer` |
| Error codes | `EC_<DAEMON>_<ERROR>` | `EC_BGP_ATTR_FLAG` |
| Memory types | `MTYPE_<DAEMON>_<PURPOSE>` | `MTYPE_BGP_PEER` |

### Indentation and Style

- **8-space tabs** (Linux kernel style) — do not use spaces for indentation.
- **99-character column limit**.
- **K&R brace style**: opening brace on the same line for functions; on the next line only for structs/enums (follow clang-format output).
- Always run `git clang-format HEAD~1` or `tools/indent.py` before committing.

### Statements

- One statement per line.
- No assignments inside `if`/`while` conditions unless the intent is explicit.
- Prefer `!ptr` over `ptr == NULL`; prefer `ptr` over `ptr != NULL`.
- Use `sizeof(*ptr)` (not `sizeof(struct foo)`) so the type follows the variable.

---

## 5. Memory Management

FRR tracks all allocations by type. **Never use raw `malloc`/`free`/`calloc`**.

### Declaring Memory Types

In `<daemon>_memory.h`:
```c
#include "lib/memory.h"
DECLARE_MGROUP(BGP);
DECLARE_MTYPE(BGP_PEER);
```

In `<daemon>_memory.c`:
```c
#include "<daemon>_memory.h"
DEFINE_MGROUP(BGP, "BGP");
DEFINE_MTYPE(BGP, BGP_PEER, "BGP peer");
```

### Allocation Macros

```c
ptr = XMALLOC(MTYPE_BGP_PEER, sizeof(*ptr));   // malloc equivalent
ptr = XCALLOC(MTYPE_BGP_PEER, sizeof(*ptr));   // calloc (zero-initialized)
ptr = XREALLOC(MTYPE_BGP_PEER, ptr, new_size); // realloc equivalent
XFREE(MTYPE_BGP_PEER, ptr);                    // free (sets ptr to NULL)

str = XSTRDUP(MTYPE_BGP_PEER, other_str);      // strdup equivalent
```

### Zero Initialization

Prefer initializer syntax over `memset()`:
```c
/* Preferred */
struct bgp_peer peer = {};

/* Avoid */
struct bgp_peer peer;
memset(&peer, 0, sizeof(peer));
```

---

## 6. Error Handling and Logging

### Log Levels

Use the appropriate level — misuse breaks operational workflows:

| Level | Macro | When to use |
|-------|-------|-------------|
| Debug | `zlog_debug()` | Behind `IS_*DEBUG*` guards; developer details |
| Info | `zlog_info()` | Significant but normal events |
| Notice | `zlog_notice()` | Daemon startup / shutdown **only** |
| Warning | `zlog_warn()` | Unexpected but recoverable condition |
| Error | `zlog_err()` | Error requiring operator attention |

Debug logging **must** be guarded:
```c
if (BGP_DEBUG(update, UPDATE_IN))
    zlog_debug("BGP UPDATE received from %s", peer->host);
```

### Error Codes

Each daemon has an enum in `<daemon>_errors.h`:
```c
enum bgp_log_refs {
    EC_BGP_ATTR_FLAG = BGP_FERR_START,
    EC_BGP_ATTR_LEN,
    /* ... */
};
```

Reference codes in log calls:
```c
flog_err(EC_BGP_ATTR_FLAG,
         "%s attribute length is wrong, expected %d got %d",
         peer->host, expected, actual);
```

Never add hardcoded numeric error codes. Add a new enum value in `<daemon>_errors.h`.

---

## 7. Data Structures

### Use `typesafe.h` Containers

Prefer type-safe macros from `lib/typesafe.h` over ad-hoc linked lists:

```c
/* Declare a singly-linked list of peers */
PREDECL_LIST(peer_list);
struct bgp_peer {
    struct peer_list_item item;
    /* ... */
};
DECLARE_LIST(peer_list, struct bgp_peer, item);

/* Usage */
struct peer_list_head peers;
peer_list_init(&peers);
peer_list_add_tail(&peers, peer);
```

Available container types: `LIST`, `DLIST` (doubly-linked), `HASH`, `SKIPLIST`, `HEAP`, `RBTREE`.

### Patricia Trees / Tries

Use `lib/table.h` (`struct route_table`) for prefix-based lookups — do not reimplement trie logic.

---

## 8. CLI / VTY Integration

Commands are declared with `DEFUN` macros in `<daemon>_vty.c`:

```c
DEFUN(bgp_neighbor,
      bgp_neighbor_cmd,
      "neighbor A.B.C.D remote-as (1-4294967295)",
      NEIGHBOR_STR
      NEIGHBOR_ADDR_STR
      "Specify a BGP neighbor\n"
      AS_STR)
{
    /* implementation */
    return CMD_SUCCESS;
}
```

Register commands in the install function:
```c
void bgp_vty_init(void)
{
    install_element(BGP_NODE, &bgp_neighbor_cmd);
}
```

**Rules:**
- Always provide complete helpstrings for every token.
- Return `CMD_SUCCESS`, `CMD_WARNING`, or `CMD_ERR_*` — never bare integers.
- Do not call `exit()` inside a DEFUN handler.

---

## 9. YANG / Northbound

Modern daemons are migrating from legacy VTY to YANG-based configuration via `mgmtd`. When touching a daemon that has northbound (`*_nb.c`) files:

- Do **not** add legacy-only VTY config commands — add the YANG leaf first.
- YANG models live in `yang/<daemon>.yang`; compile with `make yang_modeldir`.
- Northbound callbacks must implement `nb_config_change()`, `nb_config_apply()`, etc. — see existing `*_nb.c` files for the pattern.
- When in doubt, look at `staticd/` as a reference for a fully migrated daemon.

---

## 10. Commit and PR Standards

### Commit Message Format

```
<subsystem>: <imperative summary, max 72 chars>

<Body: wrap at 72 chars. Explain WHY, not WHAT. Reference issues
with "Fixes: #NNNN" or "Closes: #NNNN".>

Signed-off-by: Full Name <email@example.com>
```

**Valid subsystem prefixes** (enforced by commitlint):

`babeld`, `bfdd`, `bgpd`, `build`, `doc`, `docker`, `eigrpd`, `fpm`,
`isisd`, `ldpd`, `lib`, `mgmtd`, `multi`, `nhrpd`, `ospf6d`, `ospfd`,
`pathd`, `pbrd`, `pimd`, `pim6d`, `ripd`, `ripngd`, `sharpd`,
`staticd`, `tests`, `tools`, `vtysh`, `vrrpd`, `yang`, `zebra`, `all`

### PR Rules

- Target `master` for new features and non-critical bugfixes.
- Bugfixes targeting stable releases must also be submitted against `stable/<VERSION>`.
- Squash trivial fixup commits (typos, whitespace, WIP markers) before submitting.
- Every new feature **must** include automated tests.
- All commits must be signed off (DCO requirement — `Signed-off-by:` line).
- Security fixes: CC <security@frrouting.org> **before** opening a public PR.

---

## 11. Testing Requirements

### Where Tests Live

| Type | Location | Runner |
|------|----------|--------|
| C unit tests | `tests/<daemon>/` | `make test` |
| Python topotests | `tests/topotests/` | pytest + FRR topology |
| Utility unit tests | `tests/lib/` | `make test` |

### Adding Tests

- For new protocol features: add a topotest under `tests/topotests/<feature>/`.
- For new library utilities: add a C unit test under `tests/lib/`.
- Tests must be deterministic — no timing-based `sleep` loops.
- Use `check_output()` helpers to verify FRR daemon state via `vtysh`.

### Running Tests Locally

```bash
# Unit tests
make check

# Single topotest (requires root / network namespaces)
cd tests/topotests/<test-name>
sudo pytest test_<name>.py -v
```

---

## 12. Code Formatting

### Automatic Formatting

Always format before committing:

```bash
# Format only staged changes
git clang-format HEAD~1

# Format a specific file (handles DEFUN macros correctly)
python3 tools/indent.py bgpd/bgp_attr.c
```

### Manual Checks

```bash
# Style check on a patch file
./tools/checkpatch.sh < my.patch

# Python style (tests/tools)
flake8 tests/
isort tests/
```

Formatting failures block merge — do not skip them.

---

## 13. Security and Defensive Coding

### Banned Functions

Never use these — the CI will reject them:

| Banned | Use instead |
|--------|-------------|
| `strcpy` | `strlcpy` |
| `strcat` | `strlcat` |
| `sprintf` | `snprintf` |
| `gets` | `fgets` |
| `system()`, `fork()`, `execXX()` | not permitted in daemon code |

### Buffer Sizes

Always use `sizeof()`:
```c
/* Correct */
snprintf(buf, sizeof(buf), "%s", prefix);

/* Wrong */
snprintf(buf, 64, "%s", prefix);
```

### Integer Arithmetic

Check for overflow before arithmetic on untrusted data (packet parsing, YANG input):
```c
if (len > sizeof(buf) - 1)
    return -1;
```

### Packet Parsing

- Always validate lengths before reading: `stream_getw()`, `stream_getl()` return values must be checked against remaining stream size.
- Use `stream_pnt()` / `stream_get_endp()` accessors — do not walk the raw buffer pointer.

---

## 14. Common Pitfalls

| Pitfall | Correct Approach |
|---------|-----------------|
| Using `malloc`/`free` directly | Use `XMALLOC` / `XFREE` with a declared `MTYPE_` |
| Hardcoding buffer sizes as literals | Always `sizeof(buf)` |
| Adding a CLI command without a helpstring token | Every token needs a helpstring |
| `memset` to zero-init a local struct | Use `struct foo x = {};` |
| Adding debug logs without an `IS_DEBUG` guard | Wrap with the daemon's debug flag check |
| Returning `void` from a function that can fail | Return `int` or an explicit status enum |
| Using `system()` or `popen()` inside a daemon | Not allowed — use existing IPC mechanisms |
| Skipping `Signed-off-by:` in a commit | Required for DCO compliance |
| Opening a PR for a security bug | Email security@frrouting.org first |
| Adding new data structures without `typesafe.h` | Use `DECLARE_LIST`, `DECLARE_HASH`, etc. |
| Modifying generated/compiled YANG outputs | Edit the `.yang` source and regenerate |

---

## References

- Developer workflow: `doc/developer/workflow.rst`
- Coding style details: `doc/developer/` (various `.rst` files)
- Clang-format config: `.clang-format`
- Commit lint rules: `.github/commitlint.config.js`
- Memory system: `lib/memory.h`
- Type-safe containers: `lib/typesafe.h`
- Logging API: `lib/log.h`
- Stream (packet) API: `lib/stream.h`
- FRR mailing list: <https://lists.frrouting.org/>
- Issue tracker: <https://github.com/FRRouting/frr/issues>