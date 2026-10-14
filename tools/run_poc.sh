#!/usr/bin/env bash
# tools/run_poc.sh — Generic PoC runner for the PQC vulnerability assessor.
# Usage: run_poc.sh <poc_dir> [--unit-harness]
#
# Builds and runs a PoC package (server.c + client.c), classifies the outcome
# bug-class-aware, and writes <poc_dir>/result.json.
# Works for any PoC emitted by the assessor; not tied to a single finding.

set -euo pipefail

# ── helpers ─────────────────────────────────────────────────────────────────

die() { echo "ERROR: $*" >&2; exit 1; }

log() { echo "[run_poc] $*"; }

# Emit final JSON result and human summary line, then exit with 0.
emit_result() {
    local poc_dir="$1" finding_id="$2" library="$3" bug_class="$4" location="$5"
    local build_status="$6" verdict="$7" notes="$8"
    local server_excerpt="" client_excerpt=""

    [[ -f "$poc_dir/server.log" ]] && server_excerpt=$(tail -30 "$poc_dir/server.log" | sed 's/"/\\"/g' | tr '\n' '|')
    [[ -f "$poc_dir/client.log" ]] && client_excerpt=$(tail -20 "$poc_dir/client.log" | sed 's/"/\\"/g' | tr '\n' '|')

    cat > "$poc_dir/result.json" <<JSONEOF
{
  "finding_id": "$finding_id",
  "library": "$library",
  "bug_class": "$bug_class",
  "location": "$location",
  "build_status": "$build_status",
  "run_verdict": "$verdict",
  "server_log_excerpt": "$server_excerpt",
  "client_log_excerpt": "$client_excerpt",
  "notes": "$notes"
}
JSONEOF

    echo "RESULT | $finding_id | $library | $bug_class | build=$build_status | verdict=$verdict | $notes"
}

# ── argument parsing ─────────────────────────────────────────────────────────

POC_DIR=""
UNIT_HARNESS=0

for arg in "$@"; do
    case "$arg" in
        --unit-harness) UNIT_HARNESS=1 ;;
        -*) die "Unknown flag: $arg" ;;
        *)  POC_DIR="$arg" ;;
    esac
done

[[ -z "$POC_DIR" ]] && die "Usage: $0 <poc_dir> [--unit-harness]"
[[ -d "$POC_DIR" ]] || die "PoC directory not found: $POC_DIR"

POC_DIR="$(realpath "$POC_DIR")"

# ── parse README.md ──────────────────────────────────────────────────────────

README="$POC_DIR/README.md"
[[ -f "$README" ]] || die "README.md not found in $POC_DIR"

parse_field() {
    grep -oP "(?<=\| \*\*$1\*\* \| ).*?(?= \|)" "$README" 2>/dev/null | head -1 | xargs
}

LIBRARY="$(parse_field Library)"
LOCATION="$(parse_field Location)"
BUG_CLASS="$(parse_field 'Bug class')"
FINDING_ID="$(basename "$POC_DIR")"

# Fallback: derive from directory name
[[ -z "$LIBRARY"   ]] && LIBRARY="unknown"
[[ -z "$BUG_CLASS" ]] && BUG_CLASS="unknown"
[[ -z "$LOCATION"  ]] && LOCATION="unknown"

log "Finding  : $FINDING_ID"
log "Library  : $LIBRARY"
log "Bug class: $BUG_CLASS"
log "Location : $LOCATION"

# ── per-library build ensure ─────────────────────────────────────────────────

# SCRIPT_DIR is the directory containing this script (tools/).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILT_DIR="$PROJECT_ROOT/built"
mkdir -p "$BUILT_DIR"

ensure_wolfssl() {
    local marker="$BUILT_DIR/wolfssl-kyber"
    if [[ -f "$marker" ]]; then
        log "wolfSSL (kyber) already built (marker: $marker)"
        return 0
    fi

    local wolfssl_src="${WOLFSSL_SRC:-/home/isaac/wolfssl}"
    [[ -d "$wolfssl_src" ]] || die "wolfSSL source not found at $wolfssl_src. Set WOLFSSL_SRC."

    log "Building wolfSSL with --enable-kyber --enable-experimental …"
    (
        cd "$wolfssl_src"
        if [[ -f autogen.sh && ! -f configure ]]; then
            ./autogen.sh 2>/dev/null || true
        fi
        # Check for the best available flags
        local extra_flags
        extra_flags=$(./configure --help 2>/dev/null | grep -oE -- '--enable-(experimental|kyber|mlkem)' | sort -u | tr '\n' ' ')
        ./configure $extra_flags
        make -j"$(nproc)"
    )

    [[ -f /home/isaac/wolfssl/src/.libs/libwolfssl.so ]] \
        || die "wolfSSL build did not produce libwolfssl.so"
    touch "$marker"
    log "wolfSSL built successfully."
}

# Dispatch by library name (case-insensitive)
case "${LIBRARY,,}" in
    wolfssl*)
        ensure_wolfssl
        ;;
    liboqs*)
        log "liboqs build not yet automated; assuming pre-built. Add ensure_liboqs() to run_poc.sh."
        ;;
    *)
        log "Unknown library '$LIBRARY'; skipping library build step."
        ;;
esac

# ── per-library API fixup: build in a temp copy ──────────────────────────────

BUILD_DIR="$POC_DIR/build_tmp"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# Copy all source files (but not build_tmp itself)
for f in "$POC_DIR"/*.c "$POC_DIR"/*.h "$POC_DIR"/build.sh; do
    [[ -f "$f" ]] && cp "$f" "$BUILD_DIR/"
done

# Client-only (template-model) PoC: the PoC ships only the attacker client. Supply
# the SHARED canonical victim server from tools/template/ plus a build that builds
# both. The victim is never taken from the PoC (so it cannot self-report); the
# attacker client drives it and all evidence is the victim's sanitizer output.
if [[ ! -f "$BUILD_DIR/server.c" ]]; then
    TEMPLATE="$PROJECT_ROOT/tools/template"
    if [[ -f "$TEMPLATE/server.c" ]]; then
        cp "$TEMPLATE/server.c" "$BUILD_DIR/server.c"
        cp "$TEMPLATE/build.sh"  "$BUILD_DIR/build.sh"    # builds server + client
        [[ -f "$BUILD_DIR/poc_net.h" ]] || cp "$TEMPLATE/poc_net.h" "$BUILD_DIR/poc_net.h"
        log "client-only PoC -> using shared template victim server"
    else
        die "PoC has no server.c and no template server at $TEMPLATE"
    fi
fi

# wolfSSL-specific: patch Kyber→MlKem API names in copies if needed
if [[ "${LIBRARY,,}" == wolfssl* ]]; then
    wolfssl_src="${WOLFSSL_SRC:-/home/isaac/wolfssl}"
    # Check if the KyberKey API exists; if not, rewrite to MlKemKey
    if ! nm "$wolfssl_src/src/.libs/libwolfssl.so" 2>/dev/null | grep -q 'T wc_KyberKey_Init'; then
        log "wc_KyberKey_* not found in library; patching copies to wc_MlKemKey_* …"
        for csrc in "$BUILD_DIR"/*.c; do
            # wc_KyberKey_Init(type, key, heap, devid) → wc_MlKemKey_Init(key, type, heap, devid)
            # The two-arg reorder: handle common patterns seen in generated PoCs.
            # Pattern: wc_KyberKey_Init(KYBER_LEVELx, &varname, ...
            sed -i -E \
                -e 's/wc_KyberKey_Init\(([^,]+),\s*(&[A-Za-z_][A-Za-z0-9_]*)(,[^)]*)\)/wc_MlKemKey_Init(\2, \1\3)/g' \
                "$csrc"
            sed -i \
                -e 's/\bwc_KyberKey_Init\b/wc_MlKemKey_Init/g' \
                -e 's/\bwc_KyberKey_Free\b/wc_MlKemKey_Free/g' \
                -e 's/\bwc_KyberKey_MakeKey\b/wc_MlKemKey_MakeKey/g' \
                -e 's/\bwc_KyberKey_Encapsulate\b/wc_MlKemKey_Encapsulate/g' \
                -e 's/\bwc_KyberKey_Decapsulate\b/wc_MlKemKey_Decapsulate/g' \
                -e 's/\bwc_KyberKey_CipherTextSize\b/wc_MlKemKey_CipherTextSize/g' \
                -e 's/\bwc_KyberKey_SharedSecretSize\b/wc_MlKemKey_SharedSecretSize/g' \
                -e 's/\bwc_KyberKey_PublicKeySize\b/wc_MlKemKey_PublicKeySize/g' \
                -e 's/\bwc_KyberKey_PrivateKeySize\b/wc_MlKemKey_PrivateKeySize/g' \
                -e 's/\bwc_KyberKey_EncodePublicKey\b/wc_MlKemKey_EncodePublicKey/g' \
                -e 's/\bwc_KyberKey_EncodePrivateKey\b/wc_MlKemKey_EncodePrivateKey/g' \
                -e 's/\bwc_KyberKey_DecodePublicKey\b/wc_MlKemKey_DecodePublicKey/g' \
                -e 's/\bwc_KyberKey_DecodePrivateKey\b/wc_MlKemKey_DecodePrivateKey/g' \
                -e 's/\bKyberKey\b/MlKemKey/g' \
                -e 's/\bKYBER_LEVEL1\b/WC_ML_KEM_512/g' \
                -e 's/\bKYBER_LEVEL3\b/WC_ML_KEM_768/g' \
                -e 's/\bKYBER_LEVEL5\b/WC_ML_KEM_1024/g' \
                "$csrc"
        done
        # Also patch build.sh copy
        sed -i \
            -e 's/\bKyberKey\b/MlKemKey/g' \
            "$BUILD_DIR/build.sh" 2>/dev/null || true
        # Also patch the compile-guard: wolfSSL 5.x uses WOLFSSL_HAVE_MLKEM, not WOLFSSL_HAVE_KYBER.
        # Add WOLFSSL_HAVE_MLKEM || WC_ML_KEM_512 as an alias in the #if guard.
        for csrc in "$BUILD_DIR"/*.c; do
            sed -i \
                -e 's/#if defined(WOLFSSL_HAVE_KYBER) || defined(HAVE_KYBER)/#if defined(WOLFSSL_HAVE_KYBER) || defined(HAVE_KYBER) || defined(WOLFSSL_HAVE_MLKEM) || defined(WOLFSSL_WC_ML_KEM_512)/g' \
                -e 's/#ifdef WOLFSSL_HAVE_KYBER/#if defined(WOLFSSL_HAVE_KYBER) || defined(WOLFSSL_HAVE_MLKEM) || defined(WOLFSSL_WC_ML_KEM_512)/g' \
                -e 's/#ifdef HAVE_KYBER/#if defined(HAVE_KYBER) || defined(WOLFSSL_HAVE_MLKEM) || defined(WOLFSSL_WC_ML_KEM_512)/g' \
                "$csrc"
        done
        log "API patch complete."
    fi
fi

# ── compile ──────────────────────────────────────────────────────────────────

log "Running build.sh in $BUILD_DIR …"

build_log="$POC_DIR/build.log"
set +e
(
    cd "$BUILD_DIR"
    export CC="${CC:-clang}"
    bash build.sh
) > "$build_log" 2>&1
build_exit=$?
set -e

if [[ $build_exit -ne 0 ]] || [[ ! -x "$BUILD_DIR/poc_server" ]] || [[ ! -x "$BUILD_DIR/poc_client" ]]; then
    log "BUILD FAILED (exit $build_exit). See $build_log"
    cat "$build_log" >&2
    emit_result "$POC_DIR" "$FINDING_ID" "$LIBRARY" "$BUG_CLASS" "$LOCATION" \
        "FAILED" "BUILD_FAILED" "build.sh exit=$build_exit; see build.log"
    exit 0
fi

log "Build succeeded."

# ── pick a free port ─────────────────────────────────────────────────────────

FREE_PORT=$(python3 -c "import socket; s=socket.socket(); s.bind(('',0)); print(s.getsockname()[1]); s.close()")
log "Using port $FREE_PORT"

# ── run server + client ──────────────────────────────────────────────────────

SERVER_LOG="$POC_DIR/server.log"
CLIENT_LOG="$POC_DIR/client.log"
> "$SERVER_LOG"
> "$CLIENT_LOG"

export ASAN_OPTIONS="abort_on_error=1:detect_leaks=0"
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"

log "Starting poc_server on port $FREE_PORT …"
(
    cd "$BUILD_DIR"
    ./poc_server "$FREE_PORT"
) > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!

# Wait for server ready: up to 3s polling for "listening" or "Listening"
for i in $(seq 1 30); do
    sleep 0.1
    grep -qiE 'listen' "$SERVER_LOG" 2>/dev/null && break
done

log "Running poc_client (timeout 30s) …"
set +e
(
    cd "$BUILD_DIR"
    timeout 30 ./poc_client "$FREE_PORT"
) > "$CLIENT_LOG" 2>&1
CLIENT_EXIT=$?
set -e

# Detect whether the server crashed on its OWN (an independent signal) vs. our
# kill. If it's still alive we stopped it (no self-crash); if it already exited,
# capture its status — a crash shows up as 128+signal (e.g. 139 SIGSEGV).
if kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    set +e; wait "$SERVER_PID" 2>/dev/null; set -e
    SERVER_EXIT="alive"
else
    set +e; wait "$SERVER_PID"; SERVER_EXIT=$?; set -e
fi

log "Client exit: $CLIENT_EXIT   Server exit: $SERVER_EXIT"

# Show the full interaction so the operator can see what each side did.
echo "----------------- attacker (client) output -----------------"
sed 's/^/  | /' "$CLIENT_LOG" 2>/dev/null || true
echo "----------------- victim server output ---------------------"
sed 's/^/  | /' "$SERVER_LOG" 2>/dev/null || true
echo "------------------------------------------------------------"

# ── classify: INDEPENDENT detectors ONLY ─────────────────────────────────────
# A DEMONSTRATED verdict may come ONLY from an independent detector — a real
# sanitizer-runtime report, a fatal crash signal, or a value the harness itself
# verifies — NEVER from a string the PoC prints ABOUT ITSELF. Author claims make
# the verdict circular: on FND-673cfdd4 the PoC printed "VULNERABILITY
# OBSERVABLE" for what is actually normal ML-KEM behaviour, and the old
# classifier believed it. The harness emits DEMONSTRATED or NOT_REACHED;
# FALSE_POSITIVE is left to human judgement (you cannot prove a negative here).

SIGNAL=""          # "ubsan" | "asan" | "crash" | ""
SIGNAL_NOTE=""

detect_signal() {
    local f
    # Real UBSan runtime report (the sanitizer's own format, not prose).
    for f in "$SERVER_LOG" "$CLIENT_LOG"; do
        if grep -qE 'runtime error:|UndefinedBehaviorSanitizer' "$f" 2>/dev/null; then
            SIGNAL="ubsan"
            SIGNAL_NOTE="UBSan in $(basename "$f"): $(grep -m1 'runtime error:' "$f" 2>/dev/null | tr -d '"|' | cut -c1-150)"
            return
        fi
    done
    # Real ASan runtime report.
    for f in "$SERVER_LOG" "$CLIENT_LOG"; do
        if grep -qE '==[0-9]+==ERROR: AddressSanitizer|AddressSanitizer: (heap|stack|global)-buffer-overflow|heap-use-after-free|double-free' "$f" 2>/dev/null; then
            SIGNAL="asan"
            SIGNAL_NOTE="ASan in $(basename "$f"): $(grep -m1 'AddressSanitizer' "$f" 2>/dev/null | tr -d '"|' | cut -c1-150)"
            return
        fi
    done
    # Fatal crash signal (process exit = 128 + signal), server self-exit or client.
    local code
    for code in "$SERVER_EXIT" "$CLIENT_EXIT"; do
        case "$code" in
            132) SIGNAL="crash"; SIGNAL_NOTE="SIGILL (132)"; return ;;
            134) SIGNAL="crash"; SIGNAL_NOTE="SIGABRT (134) — sanitizer/assert abort"; return ;;
            136) SIGNAL="crash"; SIGNAL_NOTE="SIGFPE (136) — div-by-zero / FP exception"; return ;;
            139) SIGNAL="crash"; SIGNAL_NOTE="SIGSEGV (139) — segfault"; return ;;
        esac
    done
}
detect_signal

if [[ -n "$SIGNAL" ]]; then
    VERDICT="DEMONSTRATED"
    NOTES="independent detector fired [$SIGNAL]: $SIGNAL_NOTE"
else
    VERDICT="NOT_REACHED"
    case "${BUG_CLASS,,}" in
        arithmetic*|correct*|overflow*|underflow*)
            NOTES="no UBSan report despite -fsanitize=undefined — the operation did not overflow on these inputs; LIKELY A FALSE POSITIVE. Confirm with a unit harness that calls the REAL library macro/function (not a re-implementation)" ;;
        memory*)
            NOTES="no ASan/crash and no UBSan report (both sanitizers were on). If this is actually an arithmetic bug (the assessor sometimes mislabels arithmetic as 'memory'), it did not overflow here — likely a false positive; confirm with a real-macro unit harness" ;;
        validation*)
            NOTES="no sanitizer/crash signal; accept-vs-reject CANNOT be judged from the PoC's own prints — confirm the validation semantics manually" ;;
        timing*)
            NOTES="timing class: this network harness is not a timing oracle; use dudect/ctgrind" ;;
        leak*|side*channel*)
            NOTES="leak class: needs differential runs across secrets; not automated here" ;;
        *)
            NOTES="no independent sanitizer/crash signal observed" ;;
    esac
fi

log "Verdict: $VERDICT — $NOTES"

# ── unit harness (optional / fallback) ───────────────────────────────────────

UNIT_VERDICT=""
UNIT_NOTES=""

if [[ $UNIT_HARNESS -eq 1 ]]; then
    log "Generating unit harness …"

    WOLFSSL_INC="${WOLFSSL_SRC:-/home/isaac/wolfssl}"
    WOLFSSL_LIB="${WOLFSSL_SRC:-/home/isaac/wolfssl}/src/.libs/libwolfssl.so"

    # Generate minimal C unit harness targeting MLKEM_BARRETT_RED
    cat > "$POC_DIR/unit_harness.c" <<'CEOF'
/*
 * unit_harness.c — Direct test of MLKEM_BARRETT_RED with extreme sword16 values.
 * Generated by run_poc.sh --unit-harness.
 * Build: clang -fsanitize=address,undefined -O1 -g unit_harness.c -o unit_harness \
 *        -I/home/isaac/wolfssl -I/home/isaac/wolfssl/wolfssl \
 *        /home/isaac/wolfssl/src/.libs/libwolfssl.so
 */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>
#include <wolfssl/wolfcrypt/random.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* Reproduce the macro inline so UBSan instruments it directly. */
/* MLKEM_V = 20159, MLKEM_Q = 3329 */
#define MLKEM_V 20159
#define MLKEM_Q 3329

/* The vulnerable macro as documented in the finding */
static inline int16_t barrett_red_vulnerable(int16_t a) {
    return (int16_t)(a - (int16_t)(((int32_t)MLKEM_V * (int16_t)a) >> 26) * (int16_t)MLKEM_Q);
}

/* Boundary values that stress signed arithmetic */
static const int16_t TEST_VALUES[] = {
    0, 1, -1,
    3329, 3328, 3330,
    32767,   /* INT16_MAX */
    -32768,  /* INT16_MIN */
    16384,   /* 2^14 */
    -16384,
    6658,    /* 2 * MLKEM_Q */
    -6658,
    20159,   /* MLKEM_V itself */
    -20159,
};

int main(void) {
    int triggered = 0;
    printf("[unit] Testing MLKEM_BARRETT_RED with extreme sword16 values under UBSan/ASan\n");
    int n = (int)(sizeof(TEST_VALUES)/sizeof(TEST_VALUES[0]));
    for (int i = 0; i < n; i++) {
        int16_t a = TEST_VALUES[i];
        /* This call is instrumented by UBSan; overflow here will abort with
         * "signed integer overflow" if -fsanitize=signed-integer-overflow */
        int16_t r = barrett_red_vulnerable(a);
        int valid = (r >= 0 && r < MLKEM_Q);
        printf("[unit] a=%-7d  result=%-7d  in[0,q-1]=%s\n",
               (int)a, (int)r, valid ? "YES" : "NO (REDUCTION FAILURE)");
        if (!valid) triggered = 1;
    }

    /* Also drive through the actual wolfSSL ML-KEM path */
#if defined(WOLFSSL_HAVE_KYBER) || defined(HAVE_KYBER) || defined(WOLFSSL_WC_ML_KEM_512) || defined(WOLFSSL_HAVE_MLKEM)
    {
        WC_RNG rng;
        MlKemKey key;
        int ret;
        ret = wc_InitRng(&rng);
        if (ret != 0) { fprintf(stderr, "[unit] wc_InitRng failed\n"); return 1; }
        ret = wc_MlKemKey_Init(&key, WC_ML_KEM_512, NULL, INVALID_DEVID);
        if (ret != 0) { fprintf(stderr, "[unit] wc_MlKemKey_Init failed: %d\n", ret); wc_FreeRng(&rng); return 1; }
        ret = wc_MlKemKey_MakeKey(&key, &rng);
        if (ret != 0) { fprintf(stderr, "[unit] MakeKey failed: %d\n", ret); wc_MlKemKey_Free(&key); wc_FreeRng(&rng); return 1; }

        word32 ctSz = 0, ssSz = 0;
        wc_MlKemKey_CipherTextSize(&key, &ctSz);
        wc_MlKemKey_SharedSecretSize(&key, &ssSz);

        unsigned char *ct = malloc(ctSz);
        unsigned char *ss = malloc(ssSz);
        memset(ct, 0xFF, ctSz);

        printf("[unit] Decapsulating hostile ciphertext (0xFF * %u bytes) via wolfSSL ...\n", ctSz);
        ret = wc_MlKemKey_Decapsulate(&key, ss, ct, ctSz);
        if (ret == 0) {
            printf("[unit] Decapsulation completed (ret=0). First 8 ss bytes: ");
            for (word32 i = 0; i < 8 && i < ssSz; i++) printf("%02x", ss[i]);
            printf("\n");
            printf("[unit] VULNERABILITY_PATH_REACHED: decapsulation accepted hostile ciphertext\n");
        } else {
            printf("[unit] Decapsulation returned error %d\n", ret);
        }

        free(ct); free(ss);
        wc_MlKemKey_Free(&key);
        wc_FreeRng(&rng);
    }
#else
    printf("[unit] WOLFSSL_WC_ML_KEM_512 not compiled in\n");
#endif

    if (triggered) {
        printf("[unit] RESULT: Barrett reduction produced out-of-range values\n");
        return 1;
    }
    printf("[unit] RESULT: All values reduced to [0,q-1] (macro may be patched or UBSan halted above)\n");
    return 0;
}
CEOF

    log "Compiling unit harness …"
    unit_build_log="$POC_DIR/unit_build.log"
    set +e
    ${CC:-clang} -fsanitize=address,undefined -O1 -g \
        "$POC_DIR/unit_harness.c" -o "$POC_DIR/unit_harness" \
        -I"$WOLFSSL_INC" -I"$WOLFSSL_INC/wolfssl" \
        "$WOLFSSL_LIB" \
        > "$unit_build_log" 2>&1
    unit_build_exit=$?
    set -e

    if [[ $unit_build_exit -ne 0 ]]; then
        UNIT_VERDICT="BUILD_FAILED"
        UNIT_NOTES="unit_harness build failed; see unit_build.log"
        log "Unit harness build failed."
        cat "$unit_build_log" >&2
    else
        log "Unit harness built. Running …"
        unit_run_log="$POC_DIR/unit_run.log"
        set +e
        (
            cd "$POC_DIR"
            ASAN_OPTIONS="abort_on_error=1:detect_leaks=0" \
            UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1" \
            timeout 30 ./unit_harness
        ) > "$unit_run_log" 2>&1
        unit_run_exit=$?
        set -e

        cat "$unit_run_log"

        # INDEPENDENT signal only: a real UBSan runtime report. Author strings the
        # harness prints itself (VULNERABILITY_PATH_REACHED) and exit codes don't
        # count. 'REDUCTION FAILURE' comes from the harness's RE-IMPLEMENTED macro
        # (not wolfSSL's real one), so it's inconclusive, not a confirmation.
        if grep -qE 'runtime error:|UndefinedBehaviorSanitizer' "$unit_run_log" 2>/dev/null; then
            UNIT_VERDICT="DEMONSTRATED"
            UNIT_NOTES="real UBSan report: $(grep -m1 'runtime error:' "$unit_run_log" 2>/dev/null | tr -d '"|' | cut -c1-150)"
            VERDICT="DEMONSTRATED"
            NOTES="$NOTES; unit harness UBSan-confirmed"
        elif grep -q 'REDUCTION FAILURE' "$unit_run_log" 2>/dev/null; then
            UNIT_VERDICT="INCONCLUSIVE"
            UNIT_NOTES="re-implemented macro produced out-of-range value — NOT authoritative (tests the harness's transcription, not wolfSSL's real macro). Verify against the actual source macro before trusting."
        else
            UNIT_VERDICT="NOT_REACHED"
            UNIT_NOTES="no UBSan report from the unit harness (exit=$unit_run_exit)"
        fi
        log "Unit harness verdict: $UNIT_VERDICT"
    fi

    NOTES="$NOTES | unit_harness=$UNIT_VERDICT: $UNIT_NOTES"
fi

# ── emit result ──────────────────────────────────────────────────────────────

emit_result "$POC_DIR" "$FINDING_ID" "$LIBRARY" "$BUG_CLASS" "$LOCATION" \
    "OK" "$VERDICT" "$NOTES"
