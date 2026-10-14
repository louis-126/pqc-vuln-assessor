# Library Build Notes for the PoC Testbed

This file records the exact configure flags and API fixups needed to build
each library that PoCs target. Add a new section whenever a new library is
introduced.

---

## wolfSSL — ML-KEM / Kyber

### Version tested
wolfSSL 5.9.1 (at `/home/isaac/wolfssl`)

### Build command (already built; marker at `built/wolfssl-kyber`)

```sh
cd /home/isaac/wolfssl
./autogen.sh 2>/dev/null || true   # only needed if configure is absent
./configure --enable-kyber --enable-dilithium
make -j$(nproc)
# confirm:
ls src/.libs/libwolfssl.so
```

`--enable-experimental` is not required by this version; the configure help
output shows `--enable-kyber` alone enables ML-KEM. `--enable-dilithium` was
also present in the original build but is not needed for ML-KEM PoCs.

### How `run_poc.sh` detects the need to build
It checks for `built/wolfssl-kyber` marker in the project root. If absent,
`ensure_wolfssl()` probes `./configure --help` for the best available flags
and builds. Set `WOLFSSL_SRC=/path/to/wolfssl` to override the default path.

### API fixups applied automatically by `run_poc.sh`

The assessor may generate PoCs using the older `wc_KyberKey_*` API names
(wolfSSL ≤ 5.6). wolfSSL ≥ 5.7 renamed everything to `wc_MlKemKey_*`.
`run_poc.sh` detects this mismatch by checking for `wc_KyberKey_Init` in the
library symbol table and applies the following patches to **copies** in
`build_tmp/` (source files in the PoC directory are never modified):

| Old name (generated PoC) | New name (wolfSSL ≥ 5.7) |
|---|---|
| `wc_KyberKey_Init(type, &key, heap, devid)` | `wc_MlKemKey_Init(&key, type, heap, devid)` (**arg order swapped**) |
| `wc_KyberKey_Free` | `wc_MlKemKey_Free` |
| `wc_KyberKey_MakeKey` | `wc_MlKemKey_MakeKey` |
| `wc_KyberKey_Encapsulate` | `wc_MlKemKey_Encapsulate` |
| `wc_KyberKey_Decapsulate` | `wc_MlKemKey_Decapsulate` |
| `wc_KyberKey_CipherTextSize` | `wc_MlKemKey_CipherTextSize` |
| `wc_KyberKey_SharedSecretSize` | `wc_MlKemKey_SharedSecretSize` |
| `wc_KyberKey_PublicKeySize` | `wc_MlKemKey_PublicKeySize` |
| `wc_KyberKey_PrivateKeySize` | `wc_MlKemKey_PrivateKeySize` |
| `wc_KyberKey_EncodePublicKey` | `wc_MlKemKey_EncodePublicKey` |
| `wc_KyberKey_EncodePrivateKey` | `wc_MlKemKey_EncodePrivateKey` |
| `wc_KyberKey_DecodePublicKey` | `wc_MlKemKey_DecodePublicKey` |
| `wc_KyberKey_DecodePrivateKey` | `wc_MlKemKey_DecodePrivateKey` |
| `KyberKey` (struct/typedef) | `MlKemKey` |
| `KYBER_LEVEL1` | `WC_ML_KEM_512` |
| `KYBER_LEVEL3` | `WC_ML_KEM_768` |
| `KYBER_LEVEL5` | `WC_ML_KEM_1024` |

**Note on `wc_MlKemKey_Init` argument order:** The old API was
`wc_KyberKey_Init(int type, KyberKey* key, void* heap, int devId)`.
The new API swaps the first two arguments:
`wc_MlKemKey_Init(MlKemKey* key, int type, void* heap, int devId)`.
`run_poc.sh` handles this reordering automatically via sed regex.

### Compile-guard fixup
PoCs generated for the old API use `#if defined(WOLFSSL_HAVE_KYBER) || defined(HAVE_KYBER)`.
wolfSSL 5.7+ sets `WOLFSSL_HAVE_MLKEM` (not `WOLFSSL_HAVE_KYBER`) in `options.h`.
`run_poc.sh` patches these guards in the copies to include
`|| defined(WOLFSSL_HAVE_MLKEM) || defined(WOLFSSL_WC_ML_KEM_512)`.

### Include paths
```
-I/home/isaac/wolfssl -I/home/isaac/wolfssl/wolfssl
```
The second `-I` is needed because some headers use `#include <wolfssl/...>` and
others use bare `#include <options.h>`.

---

## liboqs — (not yet automated)

PoCs targeting liboqs are not yet supported in `ensure_*` functions.
When a liboqs PoC arrives, add an `ensure_liboqs()` function to `run_poc.sh`
following the same pattern:

```sh
ensure_liboqs() {
    local marker="$BUILT_DIR/liboqs"
    [[ -f "$marker" ]] && return 0
    local src="${LIBOQS_SRC:-/home/isaac/liboqs}"
    cmake -S "$src" -B "$src/build" -DCMAKE_BUILD_TYPE=Debug -DOQS_ENABLE_KEM_kyber=ON
    cmake --build "$src/build" -j"$(nproc)"
    touch "$marker"
}
```

---

## Adding a new library

1. Add an `ensure_<libname>()` function to `tools/run_poc.sh` that:
   - Checks a marker file at `built/<libname>`.
   - Builds the library if missing.
   - Touches the marker on success.
2. Add a `case` arm in the `ensure *` dispatch block (search for `wolfssl*`).
3. Add any per-library API fixup sed commands in the fixup block.
4. Add a section to this file documenting the flags and any name-drift fixups.
