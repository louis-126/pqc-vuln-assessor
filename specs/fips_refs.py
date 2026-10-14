"""FIPS reference material for spec comparison.

Open problem #1: does putting spec text in context beat the model's parametric
knowledge? To test that, this module separates two things:

  * `KEY_REQUIREMENTS` — concise, paraphrased security-relevant requirements we
    always inject. These are our own summaries, not verbatim spec text.
  * `load_full_text()` — optional hook to load fuller spec text from disk
    (FIPS 203/204 are US-government public-domain works) so you can A/B test
    "paraphrased requirements only" vs. "full text" on detection accuracy.

Drop the official .txt/.md next to this file as fips203.txt / fips204.txt to
enable the full-text arm of that experiment.
"""
from __future__ import annotations

from pathlib import Path

_HERE = Path(__file__).parent

# Paraphrased, security-focused requirement summaries (our wording).
KEY_REQUIREMENTS = {
    "FIPS 203": """\
ML-KEM (Kyber) key/ciphertext validation requirements, summarised:
- Encapsulation-key check: every coefficient must be in range, AND the encoded
  key must round-trip through byte-decode/encode unchanged (modulus reduction
  must not silently alter it). A bare 'coefficient < q' test is insufficient on
  its own to establish a well-formed key.
- Decapsulation uses the Fujisaki-Okamoto transform with IMPLICIT REJECTION:
  invalid ciphertexts must still return a pseudo-random shared secret derived
  from a stored rejection value, never an error and never a distinguishable
  output. Timing/branching must not reveal rejection.
- The decapsulation key carries a hash of the encapsulation key; re-encryption
  must be compared in constant time.
- Parameter sets (512/768/1024) fix all array bounds; lengths are never
  attacker-controlled.""",
    "FIPS 204": """\
ML-DSA (Dilithium) verification requirements, summarised:
- Signature verification must reject if z's infinity norm is >= (gamma1 - beta).
- The recomputed challenge must equal the provided challenge; comparison must
  not short-circuit on attacker-observable timing in a way that leaks.
- Hint bits must be validated (number of set hints <= omega); malformed hints
  must cause rejection, not out-of-bounds access.
- All decode steps must bounds-check encoded inputs before use.""",
    "FIPS 205": """\
SLH-DSA (SPHINCS+) signature requirements, summarised:
- Verification recomputes the WOTS+ public key and the FORS public key from the
  signature and message, then checks the resulting hypertree root equals the
  public-key root. It MUST reject when the recomputed root differs — never accept
  on a partial, short-circuited, or non-constant-time comparison.
- Hash-address (ADRS) construction must be exact: a wrong layer / tree / key-pair
  / type field lets distinct positions collide and enables forgery.
- The message randomizer R and the FORS/WOTS+ chains derive from the secret seed
  (SK.seed/SK.prf); their computation must not branch or index on secret bytes in
  a way that leaks (constant-time over secret-dependent data).
- Every length/format field of the signature must be validated before use; a
  malformed signature must cause rejection, not out-of-bounds access.
- Parameter sets fix all tree heights and chain lengths; lengths are never
  attacker-controlled.""",
}

# Map section references to the relevant requirement block.
_SECTION_INDEX = {
    "FIPS 203 §7.2": "FIPS 203",  # key validation
    "FIPS 203 §6.3": "FIPS 203",  # decaps / implicit rejection
    "FIPS 204 §8.3": "FIPS 204",  # verify
}


def spec_excerpt(ref: str) -> str:
    """Return the requirement text for a spec name or section reference.

    If full official text has been provided on disk, prefer the matching
    section from it (full-text experiment arm); otherwise return our summary.
    """
    spec_name = _SECTION_INDEX.get(ref, ref).split("§")[0].strip()
    full = load_full_text(spec_name)
    if full:
        return full[:6000]
    return KEY_REQUIREMENTS.get(spec_name, KEY_REQUIREMENTS.get(ref, ""))


def load_full_text(spec_name: str) -> str | None:
    fname = {"FIPS 203": "fips203.txt", "FIPS 204": "fips204.txt",
             "FIPS 205": "fips205.txt"}.get(spec_name)
    if not fname:
        return None
    path = _HERE / fname
    if path.exists():
        return path.read_text(errors="ignore")
    return None
