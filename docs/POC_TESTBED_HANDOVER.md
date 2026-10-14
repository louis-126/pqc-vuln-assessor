# Handover — Build a GENERIC PoC Testbed / Runner

**To:** the testbed agent
**From:** the PQC vulnerability assessor
**Goal:** build a **reusable** harness that can build, run, and judge **any** PoC package this assessor generates — given a PoC directory, it sets up the target library, compiles the server + client, runs them, captures sanitizer/output, and emits a structured verdict. It must NOT be specialised to a single finding; the one concrete PoC below is only the first test case to validate it against.

This is **authorized security research** on open-source libraries (wolfSSL, liboqs, …) for **coordinated disclosure**. PoCs are **demonstration harnesses** (trigger + observable effect), never weaponized exploits. Keep it that way.

---

## 1. The PoC package contract (true for every generated PoC)

The assessor emits one directory per confirmed finding:
```
runs/<run-name>/poc/<FND-id>/
  ├── server.c            # uses the target library normally; runs the vulnerable op on client-supplied input
  ├── client.c            # crafts input designed to trigger the bug
  ├── poc_net.h           # FIXED localhost-TCP transport — identical in every PoC; DO NOT edit
  ├── build.sh            # compile command: ${CC:=clang}, ASan+UBSan, detected INCLUDES + LIBS
  ├── README.md           # finding write-up: Library, Location, vulnerable line, Bug class, "Expected result"
  └── compile_errors.txt  # ONLY present if the generator's compile loop couldn't make it build
```

**Invariants the harness can rely on:**
- Transport API in `poc_net.h` is always: `pn_listen(port)`, `pn_accept(listen_fd)`, `pn_connect(port)`, `pn_send(fd,buf,n)`, `pn_recv(fd,buf,cap,&outn)` — length-prefixed localhost TCP.
- Run protocol is always: `./poc_server <port> &` then `./poc_client <port>` (same wire protocol on both).
- `build.sh` produces `poc_server` and `poc_client` and already includes `-fsanitize=address,undefined`.
- `README.md` has a parseable `| **Library** |`, `| **Location** |`, `| **Bug class** |` table and a "## Expected result" section.

---

## 2. What to build — a generic runner

A reusable tool (a shell script and/or small Python runner), e.g. `tools/run_poc.sh <poc_dir>` and `tools/run_pocs.py <run_dir>`, that does:

1. **Parse** the PoC dir + `README.md` → library, bug class, location, expected observable.
2. **Ensure the target library is built** with the features the PoC needs (cache per library; see §4). Detect the library from the README and the headers `server.c` includes.
3. **Build** the PoC: run its `build.sh` (override `CC` if needed), capturing stdout/stderr. If it fails, record `BUILD_FAILED` with the errors and stop for that PoC.
4. **Run** it deterministically:
   - pick a **free port** automatically (don't hardcode 21000 — PoCs collide).
   - start `poc_server` in the background with sanitizer env (`UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1`, `ASAN_OPTIONS=abort_on_error=1:detect_leaks=0`), wait until it prints "listening" (or a short sleep).
   - run `poc_client` with a **timeout** (e.g. 30s); always **kill the server and reap zombies** afterward.
   - capture `server.log` and `client.log`.
5. **Classify** the outcome (see §3) and **emit a structured result** — one JSON object per PoC plus a human summary line. Include log excerpts.
6. **Batch mode:** iterate every `runs/<run>/poc/<FND-id>/` and produce a summary table (id, library, bug class, build, run, verdict).

Keep it **idempotent and self-cleaning** (no orphaned servers, no port leaks). Put reusable build setup (per-library configure/make) in functions so it's cached, not repeated per PoC.

---

## 3. Classification must be BUG-CLASS-AWARE

Different bug classes have different "success" signals — read `Bug class` from the README and judge accordingly:

| Bug class (README) | What "demonstrated" looks like | Detector |
|---|---|---|
| `memory` | server aborts | **ASan** abort / SIGSEGV in `server.log` |
| arithmetic / correctness (often labelled `memory` wrongly) | `signed integer overflow`/`shift` UB, **or** a shared-secret/result mismatch the server prints | **UBSan** report; output comparison |
| `validation` | server **accepts** input it should reject (the server prints so) | the server's own "accepted/rejected" message |
| `leak` | observable output correlates with a secret | output diff across input classes |
| `timing` | this network harness is **not** a reliable timing oracle | note it; recommend the dudect/timing path instead |

> **Important:** never assume "no crash ⇒ false positive." A clean run for an arithmetic/validation bug just means the *network path didn't surface it*. Classify that as **NO_EFFECT / NOT_REACHED**, not FALSE_POSITIVE. When the network harness can't drive the input deep enough, the reliable fallback is a **direct unit harness** (see §5).

Suggested verdict enum per PoC: `BUILD_FAILED · NOT_REACHED · DEMONSTRATED · FALSE_POSITIVE`.

---

## 4. Generic concerns the harness must handle

- **Per-library build, cached.** wolfSSL/liboqs each need building once with the right features, then reused. Detect the library from the README; for wolfSSL ML-KEM that means a specific `./configure` (see the worked example). Keep a `built/<library>` marker so you don't rebuild every run.
- **API / version drift.** Generated PoCs may use `wc_KyberKey_*` vs `wc_MlKemKey_*`, or include paths that don't match the installed tree. Surface `build.sh` errors clearly so they can be fixed **once per library** (a small per-library patch/sed step is fine; editing each PoC by hand is not).
- **Never edit `poc_net.h`** — it's fixed/known-good. Edit only `server.c`/`client.c` or add a unit harness.
- **Robustness:** free-port selection, server-ready wait, client timeout, guaranteed teardown, capture exit codes + signals.

---

## 5. Fallback for "can't reach the bug": a direct unit harness

When the client/server path can't drive input into the vulnerable code, generate a **minimal unit harness**: a tiny C file that `#include`s the relevant wolfSSL internal header and calls the vulnerable function/macro directly with the crafted/extreme values, built under ASan+UBSan. This isolates the claim from all the I/O. Make this a **generic capability** of the runner (e.g. `--unit-harness`) where feasible, seeded from the README's vulnerable line.

---

## 6. Worked example to validate the harness first: `FND-673cfdd4`

Directory: `runs/wolfssl_local_v4/poc/FND-673cfdd4/`. Use this as the first PoC the harness runs end-to-end — it exercises the trickiest paths (UBSan detection + ML-KEM build + a unit-harness fallback).

- **Finding:** Barrett reduction signed-arithmetic underflow — `wolfcrypt/src/wc_mlkem_poly.c:166`, the `MLKEM_BARRETT_RED(a)` macro. FIPS 203 §6.3 (coefficients must reduce to `0 ≤ x < q`, q=3329). Pipeline verdict: confirmed, CVSS 5.9.
- **This is ARITHMETIC, not memory** — the README's "server crashes (ASan)" is misleading. Expect a **UBSan `signed integer overflow`** and/or an **incorrect shared-secret**, not a segfault. (Good first test of the bug-class-aware classifier.)
- **wolfSSL must be built WITH ML-KEM/Kyber** (a stock build won't link). Roughly:
  ```sh
  cd ~/wolfssl && ./autogen.sh 2>/dev/null
  ./configure --enable-kyber --enable-experimental
  make -j        # confirm src/.libs/libwolfssl.so exists
  ```
  Check `./configure --help | grep -iE 'kyber|mlkem|experimental'` for the exact flags in this version.
- **API-name mismatch is likely:** the PoC uses `wc_KyberKey_*` + `KYBER_LEVEL1`; this tree also has `wc_MlKemKey_*` (in `wc_mlkem.c`, `WC_ML_KEM_512` ≈ level 1). If linking fails on `wc_KyberKey_*`, that's the per-library fix to make.
- **Unit-harness fallback** is especially apt here: feed extreme `sword16` values straight into `MLKEM_BARRETT_RED(a)` under UBSan to test the arithmetic claim independent of decapsulation.

Target library on the box: `/home/isaac/wolfssl` (headers under `wolfssl/wolfcrypt/`, lib at `src/.libs/libwolfssl.so`). Environment: WSL Ubuntu; the project lives at `/mnt/p/ITP/LLM`.

---

## 7. Deliverables

1. **The generic runner** (`tools/run_poc.sh` + optional `tools/run_pocs.py`) with a short usage README. Works on any `runs/*/poc/<FND-id>/` directory.
2. **A results report** from running it over the available PoC(s), starting with `FND-673cfdd4` — build status, run logs/excerpts, and a per-PoC verdict (`BUILD_FAILED / NOT_REACHED / DEMONSTRATED / FALSE_POSITIVE`).
3. **Per-library build notes** (the wolfSSL ML-KEM configure flags you used, any per-library PoC fixups).
4. For any DEMONSTRATED finding: the minimal reproducer (final server/client or unit harness) and a one-line patch suggestion.

Build the harness to be reused for every future PoC this assessor emits — that is the deliverable, not a one-off run.
