"""PoC package generator: draft documented client/server PoC code — DELIVERED,
not executed.

The assessor does NOT compile or run the PoC. For each confirmed finding it
generates a self-contained, documented package the USER runs in their own
sandbox (a machine with the target library built/installed):

  poc/<finding_id>/
    README.md   — what this is, the vulnerability, what the PoC does, how to run
                  it, and the expected result
    server.c    — uses the library normally; runs the vulnerable operation on
                  data received from the client
    client.c    — the attacker; sends crafted input to trigger the bug
    poc_net.h   — fixed localhost-TCP transport (length-prefixed buffers)
    build.sh    — the compile command (instructions; not run by the assessor)

Why generate-only: local models cannot reliably produce compile-ready code
against a complex crypto library, and a tool self-grading its own PoCs is the
weakest possible evidence. The honest deliverable is a documented scaffold a
human builds, runs, and confirms.
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

log = logging.getLogger("pqc")


# ── Library build-flag / header discovery (used to write correct build.sh and
#    to feed the model the real header layout) ────────────────────────────────

def _find_build_flags(target: str) -> tuple[list[str], list[str], bool]:
    """Return (include_flags, link_flags, has_real_artifact).

    has_real_artifact is True only when an actual compiled library (.a/.so) was
    found in the tree, so the README can tell the user to build it first if not.
    """
    t = Path(target)
    inc_flags: list[str] = [f"-I{t}"]
    link_flags: list[str] = []
    has_artifact = False

    for inc_dir in t.rglob("include"):
        if inc_dir.is_dir():
            inc_flags.append(f"-I{inc_dir}")
            break

    # Collect all candidate artifacts (static + shared), excluding obvious
    # test/example/bench builds.
    base = t.name.split("-")[0].lower()           # e.g. "wolfssl" from "wolfssl-5.7"
    candidates: list[Path] = []
    for pattern in ("**/*.a", "**/*.so", "**/*.dylib"):
        for lib_path in t.glob(pattern):
            low = str(lib_path).lower()
            if any(x in low for x in ("test", "example", "bench")):
                continue
            candidates.append(lib_path)

    if candidates:
        # Prefer an artifact whose filename actually names this library
        # (libwolfssl.a), not the lexicographically-first unrelated archive.
        named = [c for c in candidates if base in c.name.lower()]
        chosen = sorted(named or candidates, key=lambda p: len(str(p)))[0]
        link_flags.append(str(chosen))
        has_artifact = True
    else:
        link_flags = [f"-l{base}"]

    return inc_flags, link_flags, has_artifact


def _build_hint(target: str) -> str:
    """Detect the target's build system and suggest the command to produce a
    linkable library. Library-AGNOSTIC: keys off build-system marker files."""
    t = Path(target)
    if (t / "configure").exists() or (t / "configure.ac").exists() or (t / "autogen.sh").exists():
        return f"cd {target} && ./configure && make    # (autotools)"
    if (t / "CMakeLists.txt").exists():
        return f"cd {target} && cmake -B build && cmake --build build    # (cmake)"
    if (t / "go.mod").exists():
        return f"cd {target} && go build ./...    # (go)"
    if (t / "build.gradle").exists() or (t / "pom.xml").exists():
        return f"cd {target} && ./gradlew build    # (java)"
    if (t / "configure.py").exists():
        return f"cd {target} && ./configure.py && make    # (botan-style)"
    if (t / "Makefile").exists() or (t / "makefile").exists():
        return f"cd {target} && make"
    return (f"No recognised build system in {target}; build a static library "
            f"(.a) or shared object (.so) so the PoC can link against it.")


def _as_include(path: Path, roots: list[str]) -> str | None:
    """Express a header as an #include <...> line relative to the FIRST matching
    -I root (the target root → idiomatic full path, e.g.
    <wolfssl/wolfcrypt/wc_mlkem.h>)."""
    p = Path(path).resolve()
    for r in roots:
        try:
            rel = p.relative_to(Path(r).resolve())
        except ValueError:
            continue
        return f"#include <{str(rel).replace(chr(92), '/')}>"
    return None


def _extract_decl(txt: str, pos: int) -> str:
    """Grab the function declaration around a match position, stripping leaked
    preprocessor lines (header guards) and BOM."""
    start = 0
    for b in (";", "}", "{"):
        j = txt.rfind(b, 0, pos)
        if j + 1 > start:
            start = j + 1
    end = txt.find(";", pos)
    if end == -1:
        end = pos + 160
    decl = txt[start:end + 1].replace(chr(0xFEFF), "")
    decl = re.sub(r"(?m)^\s*#.*$", "", decl)
    return " ".join(decl.split())[:300]


def _discover_api(target: str, entry_point: str):
    """Discover the REAL include directives, entry-point signature, and -I roots
    from the target tree, so the drafter stops guessing wrong header paths/types.
    Returns (inc_roots, include_lines, signature)."""
    t = Path(target)
    inc_roots = [str(t)]
    for sub in ("include", t.name):
        if (t / sub).is_dir():
            inc_roots.append(str(t / sub))

    include_lines: list[str] = []
    signature = ""

    for cfg in ("options.h", "config.h", "build_config.h"):
        for h in list(t.rglob(cfg))[:5]:
            inc = _as_include(h, inc_roots)
            if inc:
                include_lines.append(inc)
                break
        if include_lines:
            break

    if entry_point:
        best = None
        scanned = 0
        for hp in t.rglob("*.h"):
            if scanned > 3000:
                break
            scanned += 1
            try:
                txt = hp.read_text(encoding="utf-8", errors="ignore").replace(chr(0xFEFF), "")
            except Exception:
                continue
            m = re.search(r"\b" + re.escape(entry_point) + r"\s*\(", txt)
            if not m:
                continue
            inc = _as_include(hp, inc_roots)
            if not inc:
                continue
            score = (1 if "include" in str(hp).lower() else 0, -len(str(hp)))
            if best is None or score > best[0]:
                best = (score, inc, _extract_decl(txt, m.start()))
        if best:
            if best[1] not in include_lines:
                include_lines.append(best[1])
            signature = best[2]

    return inc_roots, include_lines, signature


def _api_context(target: str, entry_point: str) -> tuple[str, list[str]]:
    """Build the API-context prompt block + the -I flags for build.sh."""
    inc_roots, includes, signature = _discover_api(target, entry_point)
    inc_flags = [f"-I{r}" for r in inc_roots]
    lines = []
    if includes:
        lines.append("Use EXACTLY these include directives (correct for this "
                     "library's real header layout — do not invent others):")
        lines += includes
    if signature:
        lines.append(f"\nThe entry point's REAL signature (call it exactly like "
                     f"this, do not invent types):\n  {signature}")
    return "\n".join(lines), inc_flags


# ── Bug classification (tailors the README's "expected result") ───────────────

def _is_timing_bug(title: str, cwe: str | None) -> bool:
    hints = ("constant-time", "timing", "non-ct", "non-constant")
    cwes = ("CWE-208", "CWE-385")
    return (any(h in title.lower() for h in hints)
            or any(c in (cwe or "").upper() for c in cwes))


def _cwe_nums(cwe: str | None) -> set[str]:
    """Exact CWE numbers (whole-number match — '20' must not match 'CWE-203')."""
    return set(re.findall(r"\d+", cwe or ""))


def _classify_bug(title: str, cwe: str | None, language: str = "c") -> str:
    """timing | memory | crash | resource | ssrf | validation | leak | cleanup.

    `language` only affects the fallback and the memory/crash split: a managed
    runtime has no out-of-bounds/use-after-free class, so an unclassified Java
    finding is a crash (uncaught exception), not "memory".
    """
    if _is_timing_bug(title, cwe):
        return "timing"
    nums = _cwe_nums(cwe)
    t = title.lower()
    is_managed = language.lower() in ("java", "kotlin", "scala", "csharp", "c#", "go")
    # Null-dereference / uncaught-exception DoS. Split out of "memory" because
    # the memory blurb ("out-of-bounds / overflow / use-after-free") is wrong for
    # it in any language and actively misleading in a managed one.
    if (nums & {"476", "248"}
            or any(w in t for w in ("null pointer", "nullpointerexception", "npe",
                                    "null deref", "uncaught exception",
                                    "unhandled exception", "without null guard"))):
        return "crash"
    # Attacker-controlled size/count drives allocation or work, with no ceiling.
    if (nums & {"770", "400", "789", "1284"}
            or any(w in t for w in ("unbounded", "no size cap", "size cap",
                                    "without a cap", "exhaustion", "iteration count",
                                    "attacker-declared", "attacker-controlled length"))):
        return "resource"
    # The library dereferences a URI it was handed.
    if (nums & {"918", "611"}
            or any(w in t for w in ("ssrf", "server-side request",
                                    "server side request"))):
        return "ssrf"
    # Missing-zeroization / sensitive-data-remnant: NOT a crash bug — a
    # memory-hygiene issue best confirmed with a debugger, not a network demo.
    if (nums & {"226", "212", "459", "244"}
            or any(w in t for w in ("zeroing", "zeroize", "zeroise", "scrub",
                                    "wipe", "not cleared", "missing zero",
                                    "cleanup", "not zeroed", "sensitive data"))):
        return "cleanup"
    if (not is_managed
            and (nums & {"787", "125", "416", "415", "190", "122", "124", "131"}
                 or any(w in t for w in ("overflow", "out-of-bounds", "out of bounds",
                                         "oob", "use-after-free", "use after free",
                                         "double-free", "double free", "buffer")))):
        return "memory"
    if (nums & {"20", "680", "347", "345", "290", "295"}
            or any(w in t for w in ("validation", "canonical", "accept",
                                    "reject", "malformed", "forge", "round-trip",
                                    "round trip", "non-canonical"))):
        return "validation"
    # Note: CWE-212 ("improper removal of sensitive info") is handled by the
    # cleanup class above — it's a zeroization/remnant issue, not a network
    # oracle — so it is deliberately NOT in this leak set.
    if (nums & {"200", "203", "532"}
            or any(w in t for w in ("leak", "disclosure", "oracle",
                                    "information exposure"))):
        return "leak"
    return "crash" if is_managed else "memory"


# ── Fixed localhost-TCP transport (library-neutral; the LLM fills in crypto) ──

_NET_H = r"""/* poc_net.h - minimal localhost TCP transport for PoC demos.
 * Length-prefixed (4-byte big-endian) byte buffers. Library-neutral. */
#ifndef POC_NET_H
#define POC_NET_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
static int pn_listen(int port){
    int s=socket(AF_INET,SOCK_STREAM,0); int yes=1;
    setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof yes);
    struct sockaddr_in a; memset(&a,0,sizeof a);
    a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK); a.sin_port=htons(port);
    if(bind(s,(struct sockaddr*)&a,sizeof a)<0){perror("bind");exit(2);}
    listen(s,1); return s;
}
static int pn_accept(int s){ return accept(s,NULL,NULL); }
static int pn_connect(int port){
    int s=socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in a; memset(&a,0,sizeof a);
    a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK); a.sin_port=htons(port);
    int tries=0; while(connect(s,(struct sockaddr*)&a,sizeof a)<0){ if(++tries>100){perror("connect");exit(2);} usleep(100000); }
    return s;
}
static int pn_send(int fd,const void*buf,uint32_t n){
    uint32_t net=htonl(n);
    if(write(fd,&net,4)!=4) return -1;
    return (write(fd,buf,n)==(ssize_t)n)?0:-1;
}
static int pn_recv(int fd,void*buf,uint32_t cap,uint32_t*outn){
    uint32_t net; if(read(fd,&net,4)!=4) return -1;
    uint32_t n=ntohl(net); if(n>cap) return -1;
    uint32_t got=0; while(got<n){ ssize_t r=read(fd,(char*)buf+got,n-got); if(r<=0) return -1; got+=(uint32_t)r; }
    *outn=n; return 0;
}
#endif
"""

# Code generation is done ONE FILE PER CALL, in plain text (a single ```c fenced
# block), NOT as a JSON object containing two files. JSON-wrapping long C
# degrades small-model code quality and turns any truncation into unparseable
# output; per-file plain text halves the per-call length, drops the escaping
# burden, and a truncated file is still usable. (Diagnosed from DeepHat runs.)
_CODE_SYSTEM = """\
You are an expert C security engineer supporting an AUTHORIZED post-quantum
cryptography vulnerability audit. The purpose is responsible, coordinated
disclosure to the library's vendor. Each PoC is a minimal DEMONSTRATION harness
that reliably triggers the bug and makes its effect observable — it is not a
weaponized exploit.

Output ONE complete, self-contained, compilable C file in a SINGLE ```c fenced
code block — nothing outside the code block (no prose, headings, or commentary).

Rules for the file:
- Begin with a /* comment block */ stating what this file does and which library
  operation/line it targets.
- Include every #include it needs and a main().
- Use the provided transport header  #include "poc_net.h"  for all networking;
  its functions are: pn_listen(port), pn_accept(listen_fd), pn_connect(port),
  pn_send(fd,buf,n), pn_recv(fd,buf,cap,&outn). Do NOT write your own sockets and
  do NOT name any local variable the same as those functions.
- Demonstration only: a reliable trigger and an observable effect (a crash under
  sanitizers, acceptance of input that should be rejected, or a measurable timing
  difference). No weaponization — no shellcode, ROP/JOP, heap grooming, or
  payloads."""


# ── ML-KEM template environment (wolfSSL) ─────────────────────────────────────
# wolfSSL PoCs are CLIENT-ONLY: an attacker client against the SHARED, canonical
# victim server (tools/template/). The server is never copied into the PoC and
# never model-written, so it cannot self-report a vulnerability — all evidence is
# server-side sanitizer output.

_CLIENT_BUILD_SH = """\
#!/usr/bin/env bash
# Build the ATTACKER client only. The victim is the shared ML-KEM template
# server (tools/template/) — run it separately, then: ./poc_client <port>.
# The attacker crafts raw bytes and needs no crypto library.
set -e
CC=${CC:-clang}
$CC -fsanitize=address,undefined -g -o poc_client client.c
echo "Built: poc_client   (run the template server, then ./poc_client <port>)"
"""


def _template_dir() -> "Path | None":
    """The canonical ML-KEM victim server/client template, if present
    (<project root>/tools/template)."""
    d = Path(__file__).resolve().parent.parent / "tools" / "template"
    return d if (d / "server.c").exists() else None


def _template_applicable(finding: dict) -> bool:
    """True only if the finding is on the ML-KEM DECAPSULATION path the template
    server actually exercises (wc_MlKemKey_Decapsulate -> wc_mlkem.c /
    wc_mlkem_poly.c). A finding in the PKCS#11 wrapper, the RNG (random.c),
    classical DSA/ECC, or signature code is NOT reachable through the template —
    forcing it there produces a PoC that tests unrelated code. Those fall back to
    a bespoke harness that calls the actual vulnerable function."""
    base = (finding.get("file") or "").lower().replace("\\", "/").rsplit("/", 1)[-1]
    return ("mlkem" in base or "kyber" in base) and "pkcs11" not in base


def _draft_attacker_client(finding: dict, bug_class: str, api_block: str,
                           target_path: str, template_server: str,
                           drafter_backend, critic_backend) -> str:
    """Draft ONLY the attacker client.c for the ML-KEM template victim server.
    The server is FIXED; the client speaks its protocol and feeds it malicious
    input so the SERVER runs the vulnerable code (evidence is server-side)."""
    finding = {**finding, "_bug_class": bug_class}
    role = (
        "Write client.c: an ATTACKER client for the ML-KEM messaging server shown "
        "below. You CANNOT modify the server. Speak its wire protocol using the "
        "pn_* transport from poc_net.h, and drive the server to run the vulnerable "
        f"operation on malicious input to demonstrate \"{finding.get('title','')}\".\n"
        "- For a KEM/decapsulation bug: receive the server's public key, then send a "
        "CRAFTED ciphertext (do NOT perform a real encapsulation) with extreme / "
        "boundary values aimed at the vulnerable line.\n"
        "- The client needs no crypto library — craft raw bytes.\n"
        "- After sending, usleep briefly and exit; do NOT block waiting for a reply "
        "(the server may enter an echo loop).\n"
        "VERBOSE NARRATION (important — the operator reads this to follow the "
        "attack live): print a clear `[attacker]` line for EVERY step — connecting, "
        "the byte-size of each buffer received and sent — and for the crafted "
        "payload print its length, a hex dump of the first 16 bytes, and ONE "
        "sentence on WHY it is crafted that way (which extreme/boundary values, "
        "aimed at which line/operation). Finish with a line stating the EXACT "
        "server-side observable to watch for (e.g. a UBSan 'signed integer "
        "overflow' at the vulnerable line, an ASan abort, or a wrong/rejected "
        "result).\n"
        "The observable is SERVER-SIDE (a sanitizer report), so the client only has "
        "to reach the vulnerable code path."
    )
    extra = ("\n## The victim server you must talk to (FIXED — match its protocol "
             "exactly):\n```c\n" + (template_server or "")[:5000] + "\n```")
    return _draft_one_file(role, finding, api_block, target_path, extra,
                           drafter_backend, critic_backend)


def _write_template_readme(out: Path, f: dict, library: str, bug_class: str) -> None:
    ep = f.get("entry_point", "") or "the vulnerable function"
    L = [
        f"# PoC — {f['id']} — {f.get('title','(untitled)')}", "",
        "| Field | Value |", "|---|---|",
        f"| **Library** | {library} (ML-KEM) |",
        f"| **Bug class** | {bug_class} |",
        f"| **CWE** | {f.get('cwe','') or '—'} |",
        f"| **Spec** | {f.get('spec_reference','') or '—'} |",
        f"| **Location** | `{f.get('file','')}:{f.get('line','')}` |", "",
        "## Model — CLIENT-ONLY attacker vs. the SHARED ML-KEM template server", "",
        "- **client.c** — the ATTACKER (this *is* the whole PoC). Completes the "
        f"handshake and feeds the victim server malicious input to reach `{ep}`. "
        "Crafts raw bytes; needs no crypto library.",
        "- **The victim server is SHARED** — the sanitized ML-KEM-512 server in "
        "`tools/template/`. Run it separately (or let `tools/run_poc.sh` start it); "
        "it is NOT copied into this PoC.",
        "- **build.sh** builds the client only; **poc_net.h** is the transport.", "",
        "## The finding",
        (f.get("description", "") or "").strip() or "(see the main report)", "",
        "## Run", "```sh",
        "# automated (runner builds + starts the template server):",
        f"bash tools/run_poc.sh runs/<run>/poc/{f['id']}",
        "# or manual: start the tools/template server, then:",
        "bash build.sh && ./poc_client <port>",
        "```", "",
        "## Reading the result — EVIDENCE IS ON THE SERVER",
        "The only trustworthy signal is the sanitized **server's** output:",
        "- **DEMONSTRATED** ⇐ the server emits a real sanitizer report (UBSan "
        "`runtime error:` / ASan / crash) in the vulnerable code.",
        "- **NOT_REACHED / likely FALSE POSITIVE** ⇐ the server runs cleanly with "
        "no sanitizer report. ML-KEM decapsulation returning a (pseudo-random) shared "
        "secret for any ciphertext is NORMAL FO implicit rejection, not a bug — never "
        "treat the PoC's own prints as evidence.",
    ]
    (out / "README.md").write_text("\n".join(L) + "\n", encoding="utf-8")


# ── Java emit path ────────────────────────────────────────────────────────────
# Java PoCs are STANDALONE, not client/server: the PKI/keystore bugs this targets
# (cert-path validation, OCSP, CRL fetch, keystore load) are reached by calling
# the provider API directly, so a socket pair adds noise without adding evidence.
# One file, one main(), compiled against the target's jars.

# Java PoCs mirror the C ones: a server that drives the library on attacker-
# supplied bytes, a separate attacker client, and a fixed transport shared by
# both. A single self-contained harness only shows the bug is reachable from
# the API; a client/server pair shows it is reachable from the NETWORK, which
# is the claim a library audit actually has to support.
_JAVA_NET_CLS = "PocNet"
_JAVA_SERVER_CLS = "PocServer"
_JAVA_CLIENT_CLS = "PocClient"
_JAVA_SOURCES = (f"{_JAVA_NET_CLS}.java", f"{_JAVA_SERVER_CLS}.java",
                 f"{_JAVA_CLIENT_CLS}.java")
_JAVA_PORT = 21000

# The Java counterpart of poc_net.h: same 4-byte big-endian length prefix, so
# the two languages' PoCs are wire-compatible and read the same way in a report.
# Fixed infrastructure — never drafted by a model, never edited.
_JAVA_NET = """\
/* PocNet.java - minimal localhost TCP transport for PoC demos.
 * Length-prefixed (4-byte big-endian) byte buffers. Library-neutral.
 * FIXED INFRASTRUCTURE: do not edit. */
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

public final class PocNet {
    /* Frame cap. Guards the TRANSPORT only: a PoC for an unbounded-allocation
     * bug must make the library allocate, not this class. */
    public static final int MAX_FRAME = 64 << 20;

    private PocNet() { }

    public static ServerSocket listen(int port) throws IOException {
        ServerSocket ss = new ServerSocket();
        ss.setReuseAddress(true);
        ss.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), port), 1);
        return ss;
    }

    public static Socket accept(ServerSocket ss) throws IOException {
        return ss.accept();
    }

    public static Socket connect(int port) throws IOException {
        IOException last = null;
        for (int i = 0; i < 100; i++) {
            try {
                return new Socket(InetAddress.getLoopbackAddress(), port);
            } catch (IOException e) {
                last = e;
                try {
                    Thread.sleep(100);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
        throw (last != null) ? last : new IOException("connect failed");
    }

    public static void send(Socket s, byte[] buf) throws IOException {
        DataOutputStream out = new DataOutputStream(s.getOutputStream());
        out.writeInt(buf.length);
        out.write(buf);
        out.flush();
    }

    public static byte[] recv(Socket s) throws IOException {
        DataInputStream in = new DataInputStream(s.getInputStream());
        int n = in.readInt();
        if (n < 0 || n > MAX_FRAME) {
            throw new IOException("bad frame length " + n);
        }
        byte[] buf = new byte[n];
        in.readFully(buf);
        return buf;
    }
}
"""

# One file per call, plain text in a single ```java block — same reasoning as
# the C path: JSON-wrapping long source degrades small-model output and makes
# truncation unparseable.
_JAVA_SYSTEM = """\
You are an expert Java security engineer supporting an AUTHORIZED cryptography
library audit. The purpose is responsible, coordinated disclosure to the
library's vendor. Each PoC is a minimal DEMONSTRATION harness that reliably
triggers the bug and makes its effect observable — it is not a weaponized
exploit.

Output ONE complete, self-contained, compilable Java file in a SINGLE ```java
fenced code block — nothing outside the code block (no prose, headings, or
commentary).

Rules for the file:
- No `package` declaration. The single public class MUST be named exactly
  `%(cls)s`, so the file compiles as %(cls)s.java.
- Include every import it needs and a `public static void main(String[] args)`.
- Use the provided transport class for ALL networking — it is already written
  and on the classpath:
      PocNet.listen(port) -> ServerSocket
      PocNet.accept(serverSocket) -> Socket
      PocNet.connect(port) -> Socket
      PocNet.send(socket, byte[])
      PocNet.recv(socket) -> byte[]
  Do NOT write your own sockets, do NOT redefine PocNet, and do NOT declare a
  variable named `PocNet`. PocNet is in the DEFAULT package, so never write
  `import PocNet;` — that is a compile error.
- Do not catch a checked exception the try block cannot throw; javac rejects
  it. Declaring `throws Exception` on main() is simpler and is preferred here.
- Take the port from `args[0]` (fall back to %(port)d when args is empty).
- Use ONLY the target library's public API plus the JDK. Do not invent classes
  or methods; if you need a helper (a throwaway CA, a self-signed certificate),
  build it with the library's own public API.
- Print a clear `[poc]` line for EVERY step so the operator can follow it live:
  what is being set up, what hostile value is being supplied, and what to watch
  for.
- Demonstration only: a reliable trigger and an observable effect. No
  weaponization, no payloads, no scanning of third-party hosts; every listener
  binds to 127.0.0.1 via PocNet."""


# Jars that are BUILD OUTPUT of this tree, not vendored third-party dependencies.
# A source checkout's libs/ and test/libs/ are full of junit, grpc, javax.mail —
# putting those on the classpath is worse than useless, because it looks like the
# library was found when it was not.
_JAVA_BUILD_OUT = ("/build/libs/", "/build/dist/", "/dist/", "/target/", "/out/")


def _find_java_classpath(target: str) -> tuple[list[str], bool]:
    """Jars to compile the PoC against.

    Returns (jar_paths, found_any). Only build output counts: a freshly-cloned
    source tree has no jars until it is built, and found_any=False drives a
    "build it first" note in the README instead of a bogus classpath.
    """
    t = Path(target)
    if not t.is_dir():
        return [], False
    hits: list[Path] = []
    scanned = 0
    for p in t.rglob("*.jar"):
        scanned += 1
        if scanned > 5000:
            break
        low = p.name.lower()
        if any(x in low for x in ("-sources", "-javadoc", "-tests", "-test")):
            continue
        s = str(p).replace("\\", "/").lower()
        if not any(marker in s for marker in _JAVA_BUILD_OUT):
            continue
        hits.append(p)
    if not hits:
        return [], False

    # One jar per artifact base name (bcprov-jdk18on-1.84.jar -> "bcprov").
    chosen: dict[str, Path] = {}
    for p in sorted(hits, key=lambda q: len(str(q))):
        base = re.split(r"[-_]\d", p.name)[0].lower()
        chosen.setdefault(base, p)
    return [str(p) for p in list(chosen.values())[:12]], True


# A method declaration HEADER. Deliberately does not require the opening brace:
# Allman brace style (which BouncyCastle uses) puts `{` on its own line, often
# after a `throws` clause on a continuation line.
_JAVA_METHOD_RE = re.compile(
    r"^\s*(?:public|protected|private)\s+"
    r"(?!class\b|interface\b|enum\b|record\b)"
    r"(?:(?:static|final|synchronized|abstract|native|strictfp|default)\s+)*"
    r"(?:<[^>]+>\s*)?"
    r"[\w$<>\[\],.\s?]+?\s+(\w+)\s*\(")


def _java_signature_at(lines: list[str], i: int) -> str:
    """Join a method header starting at line i up to the `{` or `;` that ends it."""
    out = []
    for j in range(i, min(i + 5, len(lines))):
        out.append(lines[j].strip())
        if "{" in lines[j] or lines[j].rstrip().endswith(";"):
            break
    return " ".join(" ".join(out).replace("{", "").split())[:220]


def _java_source_file(target: str, rel: str) -> Path | None:
    """Resolve a finding's `file` (often './prov/src/...') inside the target."""
    if not rel:
        return None
    rel = rel.replace("\\", "/").lstrip("./")
    p = (Path(target) / rel)
    if p.is_file():
        return p
    # The finding may carry only a partial path — fall back to a basename search.
    name = rel.rsplit("/", 1)[-1]
    for hit in Path(target).rglob(name):
        if hit.is_file():
            return hit
    return None


def _java_enclosing_method(text: str, line: int) -> str:
    """Signature of the method containing `line` (1-based), for use as a
    fallback entry_point when the researcher did not record one."""
    if line is None or line <= 0:
        return ""
    lines = text.splitlines()
    for i in range(min(line, len(lines)) - 1, -1, -1):
        if _JAVA_METHOD_RE.match(lines[i]):
            return _java_signature_at(lines, i)
    return ""


def _java_api_context(target: str, finding: dict) -> tuple[str, str]:
    """Build the API-context prompt block for a Java target, and an entry_point
    fallback. Reads the actual vulnerable file so the drafter sees the real
    package, class and surrounding code instead of guessing."""
    src = _java_source_file(target, finding.get("file", ""))
    if not src:
        return "", ""
    try:
        text = src.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "", ""

    parts: list[str] = []
    pkg = re.search(r"(?m)^\s*package\s+([\w.]+)\s*;", text)
    cls = re.search(r"(?m)^\s*(?:public\s+)?(?:final\s+|abstract\s+)?"
                    r"(?:class|interface|enum)\s+(\w+)", text)
    if pkg:
        parts.append(f"The vulnerable code lives in package `{pkg.group(1)}`"
                     + (f", class `{cls.group(1)}`." if cls else "."))
    if pkg and cls:
        parts.append(f"Fully-qualified: `{pkg.group(1)}.{cls.group(1)}`. Note whether "
                     "it is public — if it is package-private or internal, drive it "
                     "through the public JCE/JCA API that reaches it, not directly.")

    try:
        line = int(finding.get("line") or 0)
    except (TypeError, ValueError):
        line = 0
    ep_fallback = _java_enclosing_method(text, line)
    if ep_fallback:
        parts.append(f"\nThe vulnerable line sits in this method:\n  {ep_fallback}")

    if line:
        lines = text.splitlines()
        lo, hi = max(0, line - 25), min(len(lines), line + 15)
        window = "\n".join(f"{i + 1:5d}| {lines[i]}" for i in range(lo, hi))
        parts.append("\nReal source around the vulnerable line (line numbers "
                     "included; do NOT copy this into the PoC — call the public "
                     f"API that reaches it):\n```java\n{window}\n```")

    all_lines = text.splitlines()
    pub = []
    for i, ln in enumerate(all_lines):
        if ln.strip().startswith("public") and _JAVA_METHOD_RE.match(ln):
            pub.append(_java_signature_at(all_lines, i))
        if len(pub) >= 25:
            break
    if pub:
        parts.append("\nPublic methods on this class:\n  " + "\n  ".join(pub))

    return "\n".join(parts), ep_fallback


def _extract_java(text: str) -> str:
    """Pull Java source out of a model reply: prefer a ```java block, then any
    fenced block, then raw text that looks like Java. Survives truncation."""
    if not text:
        return ""
    m = re.search(r"```(?:java|Java)?\s*\n(.*?)```", text, re.DOTALL)
    if m and ("class " in m.group(1) or "import " in m.group(1)):
        return m.group(1).strip()
    m = re.search(r"```(?:java|Java)?\s*\n(.*)$", text, re.DOTALL)
    if m and ("class " in m.group(1) or "import " in m.group(1)):
        return m.group(1).strip()
    if "class " in text and "static void main" in text:
        return text.strip()
    return ""


def _java_looks_complete(code: str) -> bool:
    """Reject a draft that was cut off mid-file.

    _extract_java deliberately survives truncation, because a partial file is
    still worth reading. A file that ends inside a string literal cannot
    compile, though, so it must not be handed over as a drafted source — that
    would report "generated" for something javac rejects on line 9.

    Scans outside comments and literals: braces must balance, nothing may be
    left open at EOF, and the file must end on a closing brace.
    """
    if not code or "}" not in code:
        return False
    depth = 0
    i, n = 0, len(code)
    state = None          # None | "//" | "/*" | '"' | "'" | '"""'
    while i < n:
        c = code[i]
        two = code[i:i + 2]
        if state is None:
            if two == "//":
                state, i = "//", i + 2
            elif two == "/*":
                state, i = "/*", i + 2
            elif code[i:i + 3] == '"""':
                state, i = '"""', i + 3
            elif c in ('"', "'"):
                state, i = c, i + 1
            else:
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth < 0:
                        return False
                i += 1
        elif state == "//":
            if c == "\n":
                state = None
            i += 1
        elif state == "/*":
            if two == "*/":
                state, i = None, i + 2
            else:
                i += 1
        elif state == '"""':
            if code[i:i + 3] == '"""':
                state, i = None, i + 3
            else:
                i += 1
        else:                                   # "  or  '
            if c == chr(92):
                i += 2
            elif c == state:
                state, i = None, i + 1
            elif c == "\n":
                return False                    # Java literals cannot span lines
            else:
                i += 1
    return state is None and depth == 0 and code.rstrip().endswith("}")


def _normalise_java(code: str, cls: str) -> str:
    """Make the drafted file actually compile as <cls>.java: drop any package
    declaration and rename the public class to the expected name."""
    if not code:
        return code
    code = re.sub(r"(?m)^\s*package\s+[\w.]+\s*;\s*$", "", code, count=1)
    # PocNet sits in the default package alongside the PoC, so it needs no
    # import — and `import PocNet;` is a hard compile error, not a warning.
    code = re.sub(r"(?m)^\s*import\s+" + _JAVA_NET_CLS +
                  r"\s*(\.\*)?\s*;\s*$\n?", "", code)
    m = re.search(r"(?m)^\s*public\s+(?:final\s+)?class\s+(\w+)", code)
    if m and m.group(1) != cls:
        code = re.sub(r"\b" + re.escape(m.group(1)) + r"\b", cls, code)
    elif not m:
        # No public class at all (model emitted a bare class) — promote the first.
        m2 = re.search(r"(?m)^\s*(?:final\s+)?class\s+(\w+)", code)
        if m2:
            code = code[:m2.start()] + code[m2.start():].replace(
                m2.group(0), f"public class {cls}", 1)
            code = re.sub(r"\b" + re.escape(m2.group(1)) + r"\b", cls, code)
    return code.lstrip("\n")


def _draft_one_java(role: str, cls: str, finding: dict, api_block: str,
                    target_path: str, library: str, extra: str,
                    drafter_backend, critic_backend) -> str:
    """Draft ONE Java file (plain text, fenced ```java), drafter then critic."""
    f = finding
    system = _JAVA_SYSTEM % {"cls": cls, "port": _JAVA_PORT}
    user = (
        f"{role}\n\n"
        f"Library: {library or 'the target library'}\n"
        f"Finding: {f.get('title','')}\n"
        f"CWE: {f.get('cwe','')}   Bug class: {f.get('_bug_class','')}\n"
        f"Vulnerable entry point: {f.get('entry_point','') or '(not recorded — infer it from the source below)'}\n"
        f"Location: {f.get('file','')}:{f.get('line','')}\n"
        f"Proving line: {f.get('proving_line','')}\n"
        f"Why it's a bug: {f.get('claim_justification','')}\n\n"
        f"Description:\n{f.get('description','')}\n\n"
        f"Target library source: {target_path}\n\n"
        f"## API CONTEXT (real source — use it, do not guess)\n{api_block}\n"
        f"{extra}\n\n"
        f"Output the single ```java file now."
    )

    def _attempt(backend, label):
        if backend is None:
            return ""
        try:
            raw = backend.complete(system, user, temperature=0.2, max_tokens=8192)
            code = _extract_java(raw)
            if not code:
                log.debug("poc: %s returned no extractable Java (%d chars raw)",
                          label, len(raw or ""))
            elif not _java_looks_complete(code):
                log.warning("poc: %s returned a TRUNCATED %s (%d chars) — "
                            "discarding it rather than shipping a file that "
                            "cannot compile", label, cls, len(code))
                return ""
            return code
        except Exception as e:
            log.warning("poc: %s Java draft failed: %s", label, e)
            return ""

    code = _attempt(drafter_backend, getattr(drafter_backend, "model", "drafter"))
    if not code and critic_backend is not None and drafter_backend is not critic_backend:
        log.info("poc: primary drafter empty — falling back to critic model")
        code = _attempt(critic_backend, getattr(critic_backend, "model", "critic"))
    return _normalise_java(code, cls)


def _draft_java_client_server(finding: dict, bug_class: str, api_block: str,
                              target_path: str, library: str,
                              drafter_backend, critic_backend) -> tuple[str, str]:
    """Draft PocServer.java then PocClient.java as SEPARATE plain-text calls.
    The client is shown the generated server so their wire protocol matches.
    Returns (server_src, client_src)."""
    f = {**finding, "_bug_class": bug_class}
    lib = library or "the target library"
    ep = finding.get("entry_point", "") or "the vulnerable entry point"
    timing_note = (
        " For this TIMING bug the client sends MANY requests across two input "
        "classes and prints a measured 't = <value>' for each."
        if bug_class == "timing" else "")

    server_role = (
        f"Write {_JAVA_SERVER_CLS}.java: a TCP server that uses {lib} legitimately, "
        "the way a real application would.\n"
        "- Register the provider if the library needs it "
        "(e.g. Security.addProvider(new BouncyCastleProvider())).\n"
        "- Do all trustworthy setup BEFORE accepting: build whatever the operation "
        "needs from the library's own public API (a throwaway self-signed CA and "
        "leaf certificate, a keystore, a TrustAnchor — whatever this finding "
        "requires). Print each step.\n"
        f"- Then PocNet.listen(port), PocNet.accept(...), PocNet.recv(...) once, and "
        f"feed those attacker-supplied bytes into the PUBLIC entry point that "
        f"reaches the vulnerable line ({ep}).\n"
        "- Do not call package-private internals and do not copy library code into "
        "the PoC.\n"
        "- Make the misbehaviour observable server-side: let the exception "
        "propagate out of main() (or catch it, print the stack trace and "
        "System.exit(1)), or print that input was accepted which should have been "
        "rejected. The server is the victim — it is where the evidence appears.")
    server_src = _draft_one_java(server_role, _JAVA_SERVER_CLS, f, api_block,
                                 target_path, library, "",
                                 drafter_backend, critic_backend)

    client_extra = ""
    if server_src:
        client_extra = ("\n## The server your client must talk to (match what it "
                        "expects on the wire exactly):\n```java\n"
                        + server_src[:4000] + "\n```")
    client_role = (
        f"Write {_JAVA_CLIENT_CLS}.java: the ATTACKER. It needs NO crypto library "
        "of its own — it crafts raw bytes.\n"
        f"- PocNet.connect(port), then PocNet.send(...) the crafted or malformed "
        f"input designed to trigger \"{finding.get('title','')}\" at the proving "
        "line.\n"
        "- Print the hostile value being sent and what the operator should watch "
        "for in the SERVER's terminal." + timing_note)
    client_src = _draft_one_java(client_role, _JAVA_CLIENT_CLS, f, api_block,
                                 target_path, library, client_extra,
                                 drafter_backend, critic_backend)

    return server_src, client_src


# ── BouncyCastle: point the tester at the exact release they need ─────────────
#
# BouncyCastle only, by request. A PoC is only meaningful against the build the
# finding was reported against, and bouncycastle.org publishes just the current
# release — it keeps no archive, and its own "direct download" links resolve to
# Maven Central, which does carry every version. So Maven Central is what we cite.

_BC_MAVEN = "https://repo1.maven.org/maven2/org/bouncycastle"
_BC_JDK = "jdk18on"
_BC_META = f"{_BC_MAVEN}/bcprov-{_BC_JDK}/maven-metadata.xml"

# Repo module directory -> Maven artifact base. The finding's `file` says which
# module the bug lives in; bcprov/bcutil come along because the rest depend on them.
_BC_MODULE_ARTIFACT = {
    "prov": "bcprov", "core": "bcprov", "pkix": "bcpkix", "util": "bcutil",
    "pg": "bcpg", "tls": "bctls", "mail": "bcmail", "jmail": "bcjmail",
    "mls": "bcmls",
}
_BC_ALWAYS = ("bcprov", "bcutil")
_BC_WHY = {
    "bcprov": "provider + core crypto — always required",
    "bcutil": "ASN.1 utilities — bcpkix/bctls need it",
    "bcpkix": "PKIX / CMS / OCSP / TSP",
    "bcpg": "OpenPGP",
    "bctls": "DTLS / TLS / JSSE provider",
    "bcmail": "S/MIME",
    "bcjmail": "Jakarta S/MIME",
    "bcmls": "MLS",
}

_bc_release_cache: "list[str] | None" = None


def _is_bouncycastle(library: str, target_path: str) -> bool:
    hay = f"{library} {target_path}".lower().replace("\\", "/")
    return any(k in hay for k in ("bouncycastle", "bouncy castle", "bc-java"))


def _vtuple(v: str) -> tuple:
    try:
        return tuple(int(x) for x in v.split("."))
    except ValueError:
        return ()


def _bc_released_versions() -> list[str]:
    """Every published bcprov release, from Maven Central. [] when offline.

    Cached for the process: one generation writes many READMEs and they all
    want the same answer.
    """
    global _bc_release_cache
    if _bc_release_cache is None:
        try:
            import urllib.request
            with urllib.request.urlopen(_BC_META, timeout=6) as r:
                xml = r.read().decode("utf-8", "replace")
            _bc_release_cache = [v for v in re.findall(r"<version>([^<]+)</version>", xml)
                                 if _vtuple(v)]
        except Exception as e:
            log.info("poc: could not reach Maven Central for the BouncyCastle "
                     "version list (%s); using an offline estimate", e)
            _bc_release_cache = []
    return _bc_release_cache


def _bc_scanned_version(target_path: str) -> str:
    """What the scanned tree calls itself: '1.84', '1.87-SNAPSHOT', or ''.

    gradle.properties is authoritative; a tag-named clone
    (bc-java-r1rv84-<hash>) is the fallback.
    """
    try:
        gp = Path(target_path) / "gradle.properties"
        if gp.is_file():
            m = re.search(r"^\s*version\s*=\s*([\w.\-]+)\s*$",
                          gp.read_text(encoding="utf-8", errors="replace"), re.M)
            if m:
                return m.group(1).strip()
    except OSError:
        pass
    m = re.search(r"r1rv(\d+)", str(target_path), re.I)
    return f"1.{m.group(1)}" if m else ""


def _bc_version(target_path: str) -> str | None:
    """The exact published release the scan ran against, or None for a snapshot."""
    v = _bc_scanned_version(target_path)
    if not v or "snapshot" in v.lower():
        return None
    return v if re.fullmatch(r"\d+\.\d+(\.\d+)?", v) else None


def _bc_download_version(target_path: str) -> tuple[str, str]:
    """(version to download, kind) — kind is 'exact', 'nearest' or 'latest'.

    Downloading is always the default route: building BouncyCastle needs a
    Gradle toolchain and several JDKs, which is a far bigger ask than fetching
    a jar. A snapshot has no matching release, so we point at the newest one
    that predates it and say so, rather than sending the tester off to build.
    """
    exact = _bc_version(target_path)
    if exact:
        return exact, "exact"
    released = _bc_released_versions()
    m = re.match(r"(\d+)\.(\d+)", _bc_scanned_version(target_path) or "")
    if m:
        cap = (int(m.group(1)), int(m.group(2)))
        below = [v for v in released if _vtuple(v) < cap]
        if below:
            return max(below, key=_vtuple), "nearest"
        if not released and int(m.group(2)) > 0:
            # Offline: a 1.87-SNAPSHOT tree is development after 1.86.
            return f"{m.group(1)}.{int(m.group(2)) - 1}", "nearest"
    if released:
        return max(released, key=_vtuple), "latest"
    return "", ""


def _bc_artifacts(finding: dict) -> tuple[list[str], str]:
    """(jars this finding needs, the one holding the vulnerable class)."""
    rel = str(finding.get("file", "")).replace("\\", "/").lstrip("./")
    primary = _BC_MODULE_ARTIFACT.get(rel.split("/", 1)[0].lower(), "")
    arts = [primary] if primary else []
    arts += [a for a in _BC_ALWAYS if a not in arts]
    return arts, primary


def _bc_download_section(finding: dict, target_path: str,
                         has_artifact: bool) -> list[str]:
    """README section telling the tester where to download the matching jars."""
    ver, kind = _bc_download_version(target_path)
    L = ["", "## Get the matching library build", ""]
    if not ver:
        L += ["Could not determine which BouncyCastle release this tree "
              f"corresponds to. Pick one from <{_BC_MAVEN}/bcprov-{_BC_JDK}/> "
              "and drop the jars in `lib/`."]
        return L

    if kind == "exact":
        L += [
            f"Run this PoC against **BouncyCastle {ver}** — the release the finding "
            "was reported against. Another version may have moved, renamed or "
            "already fixed the code path, so a clean run there proves nothing.",
        ]
    else:
        scanned = _bc_scanned_version(target_path)
        what = f"a development snapshot (`{scanned}`)" if scanned else "an unreleased tree"
        near = ("the newest release before that snapshot" if kind == "nearest"
                else "the current release")
        L += [
            f"This finding was scanned against {what}, which is never published as "
            f"a release. Download **BouncyCastle {ver}** — {near} — and run the PoC "
            "against that.",
            "",
            "> **Caveat:** the line numbers in this finding refer to the snapshot, so "
            f"they will not line up exactly with {ver}. If the PoC comes back clean, "
            "confirm the code path still looks the way the finding describes before "
            "concluding the bug is absent. For a byte-exact match, build the scanned "
            f"tree instead:\n>\n>     {_build_hint(target_path)}",
        ]

    arts, primary = _bc_artifacts(finding)
    L += [
        "",
        "bouncycastle.org only ever publishes the current release, so use Maven "
        "Central. From this directory:",
        "",
        "```sh",
        "mkdir -p lib",
        f"for a in {' '.join(arts)}; do",
        f'  curl -fLo "lib/$a-{_BC_JDK}-{ver}.jar" \\',
        f'    "{_BC_MAVEN}/$a-{_BC_JDK}/{ver}/$a-{_BC_JDK}-{ver}.jar"',
        "done",
        "```",
        "",
        "| Jar | Why | Download |",
        "|---|---|---|",
    ]
    for a in arts:
        why = _BC_WHY.get(a, "")
        if a == primary:
            why = (f"**contains the vulnerable class** — {why}" if why
                   else "**contains the vulnerable class**")
        jar = f"{a}-{_BC_JDK}-{ver}.jar"
        L.append(f"| `{jar}` | {why} | "
                 f"[link]({_BC_MAVEN}/{a}-{_BC_JDK}/{ver}/{jar}) |")
    L += [
        "",
        "Every jar has a `.sha1` sibling on the same URL. To confirm a download is "
        "the genuine published artifact:",
        "",
        "```sh",
        f'curl -s "{_BC_MAVEN}/bcprov-{_BC_JDK}/{ver}/bcprov-{_BC_JDK}-{ver}.jar.sha1"; '
        f'sha1sum "lib/bcprov-{_BC_JDK}-{ver}.jar"',
        "```",
        "",
    ]
    L.append(
        "The build scripts already point at jars found in the scanned tree — this "
        "download is only needed if you want a clean, known-good copy."
        if has_artifact else
        "The build scripts set `CP` to `lib/*`, so once these jars are in place "
        "`sh build.sh` runs as written."
    )
    return L


def _write_java_build_scripts(out: Path, jars: list[str],
                              fallback_cp: str = "",
                              sources: "tuple[str, ...] | None" = None) -> None:
    """build.sh + build.bat. Both are instructions — neither is run by us.

    Compiles only, then prints the two commands to run, because the PoC is a
    client/server pair that needs two terminals (same shape as the C path).

    fallback_cp replaces the generic placeholder when no jars were found but the
    README tells the tester exactly where to put some (BouncyCastle: `lib/*`),
    so the scripts work as written once they follow it.
    """
    srcs = " ".join(sources or _JAVA_SOURCES)
    if jars:
        cp_posix, cp_win = ":".join(jars), ";".join(jars)
        note = "library jars."
    elif fallback_cp:
        cp_posix = fallback_cp
        cp_win = fallback_cp.replace("/", chr(92))
        note = 'library jars — see "Get the matching library build" in README.md.'
    else:
        cp_posix = "/path/to/library.jar"
        cp_win = "C:" + chr(92) + "path" + chr(92) + "to" + chr(92) + "library.jar"
        note = "(not yet built) library jars."

    (out / "build.sh").write_text(
        "#!/bin/sh\n"
        f"# Compile the PoC. Requires a JDK and the {note}\n"
        "# Adjust CP if your jar paths differ.\n"
        "set -e\n"
        f'CP="{cp_posix}"\n'
        f'javac -cp "$CP" {srcs}\n'
        'echo "Built. Now run these in two terminals:"\n'
        f'echo "  java -cp \\"$CP:.\\" {_JAVA_SERVER_CLS} {_JAVA_PORT}"\n'
        f'echo "  java -cp \\"$CP:.\\" {_JAVA_CLIENT_CLS} {_JAVA_PORT}"\n',
        encoding="utf-8")

    (out / "build.bat").write_text(
        "@echo off\r\n"
        f"REM Compile the PoC. Requires a JDK and the {note}\r\n"
        f"set CP={cp_win}\r\n"
        f'javac -cp "%CP%" {srcs} || exit /b 1\r\n'
        "echo Built. Now run these in two terminals:\r\n"
        f'echo   java -cp "%CP%;." {_JAVA_SERVER_CLS} {_JAVA_PORT}\r\n'
        f'echo   java -cp "%CP%;." {_JAVA_CLIENT_CLS} {_JAVA_PORT}\r\n',
        encoding="utf-8")


# ── Public entry point ────────────────────────────────────────────────────────

def generate_poc_package(
    finding: dict,
    language: str,
    drafter_backend,
    critic_backend,
    output_dir: str,
    target_path: str,
    library: str = "",
    compile_rounds: int = 0,
) -> dict:
    """Generate a documented, self-contained PoC package for one confirmed
    finding. Writes README.md + (for C targets) server.c/client.c/poc_net.h +
    build.sh. Does NOT compile or run anything. Returns {status, poc_dir}.

    status: generated   — README + both C files written
            partial     — README + one C file
            doc_only    — README only (non-C target, or drafting failed)
    """
    f = finding
    out = Path(output_dir) / f["id"]
    out.mkdir(parents=True, exist_ok=True)

    bug_class = _classify_bug(f.get("title", ""), f.get("cwe", ""), language)
    compile_report = None

    server_c = client_c = ""
    java_server = java_client = ""
    java_cp = ""
    use_template = False
    if language == "java":
        # Client/server pair over the fixed PocNet transport, mirroring the C
        # path; see the Java emit path above.
        jars, has_artifact = _find_java_classpath(target_path)
        api_block, ep_fallback = _java_api_context(target_path, f)
        if ep_fallback and not f.get("entry_point"):
            # The researcher often leaves entry_point empty for Java findings;
            # recover it from the source so the README and prompt aren't blank.
            f = {**f, "entry_point": ep_fallback}
        java_server, java_client = _draft_java_client_server(
            f, bug_class, api_block, target_path, library,
            drafter_backend, critic_backend)
        if java_server or java_client:
            # The transport is ours, never the model's, so it cannot be rewritten
            # into something that fakes the result.
            (out / f"{_JAVA_NET_CLS}.java").write_text(_JAVA_NET, encoding="utf-8")
            if java_server:
                (out / f"{_JAVA_SERVER_CLS}.java").write_text(
                    java_server, encoding="utf-8")
            if java_client:
                (out / f"{_JAVA_CLIENT_CLS}.java").write_text(
                    java_client, encoding="utf-8")
            java_cp = ":".join(jars) if jars else (
                "lib/*" if _is_bouncycastle(library, target_path) else "")
            _write_java_build_scripts(
                out, jars, fallback_cp=("" if jars else java_cp),
                sources=tuple(n for n in _JAVA_SOURCES if (out / n).is_file()))

            if compile_rounds > 0:
                repairable = {}
                if java_server:
                    repairable[f"{_JAVA_SERVER_CLS}.java"] = java_server
                if java_client:
                    repairable[f"{_JAVA_CLIENT_CLS}.java"] = java_client
                compile_report = _compile_and_fix_java(
                    out, repairable, (f"{_JAVA_NET_CLS}.java",),
                    _java_compile_cp(target_path, jars),
                    {**f, "_bug_class": bug_class}, api_block,
                    drafter_backend, critic_backend, compile_rounds)
                srcs = compile_report.get("sources") or {}
                java_server = srcs.get(f"{_JAVA_SERVER_CLS}.java", java_server)
                java_client = srcs.get(f"{_JAVA_CLIENT_CLS}.java", java_client)
                _c = compile_report["compiled"]
                log.info("poc: %s javac check: %s (%d round(s))%s", f["id"],
                         {True: "PASS", False: "FAIL", None: "skipped"}[_c],
                         compile_report["rounds_used"],
                         f" — {compile_report['reason']}" if compile_report["reason"] else "")
                if _c is False:
                    errs = "\n\n".join(
                        f"== {n} ==\n{pf.get('errors', '')}"
                        for n, pf in compile_report["per_file"].items()
                        if not pf.get("ok"))
                    if errs.strip():
                        (out / "compile_errors.txt").write_text(errs, encoding="utf-8")
        else:
            log.info("poc: %s — no Java source drafted; writing documentation only",
                     f["id"])
        inc_flags = []
    elif language == "c":
        _, link_flags, has_artifact = _find_build_flags(target_path)
        api_block, inc_flags = _api_context(target_path, f.get("entry_point", ""))
        template = _template_dir()
        on_decap_path = _template_applicable(f)
        use_template = (library.lower() == "wolfssl" and template is not None
                        and on_decap_path)
        if library.lower() == "wolfssl" and template is not None and not on_decap_path:
            log.info("poc: %s is NOT on the ML-KEM decapsulation path (%s) — the "
                     "template server never runs that code; using a bespoke harness "
                     "instead", f["id"], f.get("file", "?"))
        if use_template:
            # CLIENT-ONLY: the victim is the SHARED tools/template server (run
            # separately or started by the runner), never copied here. We supply
            # only the transport + a client-only build, and draft the attacker.
            (out / "poc_net.h").write_text(
                (template / "poc_net.h").read_text(encoding="utf-8"), encoding="utf-8")
            (out / "build.sh").write_text(_CLIENT_BUILD_SH, encoding="utf-8")
            server_tmpl = (template / "server.c").read_text(encoding="utf-8")
            client_c = _ensure_transport_include(_draft_attacker_client(
                f, bug_class, api_block, target_path, server_tmpl,
                drafter_backend, critic_backend))
            if client_c:
                (out / "client.c").write_text(client_c, encoding="utf-8")
            log.info("poc: %s using ML-KEM template environment (client-only "
                     "attacker; victim = shared tools/template server)", f["id"])
        else:
            (out.resolve() / "poc_net.h").write_text(_NET_H, encoding="utf-8")
            server_c, client_c = _draft_client_server(
                f, bug_class, api_block, target_path, drafter_backend, critic_backend)
            # Models routinely use the pn_* transport but forget to #include it —
            # inject it deterministically so the scaffold is closer to compiling.
            server_c = _ensure_transport_include(server_c)
            client_c = _ensure_transport_include(client_c)
            if server_c:
                (out / "server.c").write_text(server_c, encoding="utf-8")
            if client_c:
                (out / "client.c").write_text(client_c, encoding="utf-8")
            _write_build_script(out, inc_flags, link_flags)
        # Optional CodeAct compile-and-fix. In template mode only the ATTACKER
        # client is fixable — the canonical victim server is never fed to the
        # model so it can't be rewritten.
        if compile_rounds > 0:
            files = {}
            if client_c:
                files["client.c"] = client_c
            if server_c and not use_template:
                files["server.c"] = server_c
            if files:
                compile_report = _compile_and_fix(
                    out, files, inc_flags, {**f, "_bug_class": bug_class}, api_block,
                    drafter_backend, critic_backend, compile_rounds)
                srcs = compile_report.get("sources") or {}
                client_c = srcs.get("client.c", client_c)
                if not use_template:
                    server_c = srcs.get("server.c", server_c)
                _c = compile_report["compiled"]
                log.info("poc: %s compile check: %s (%d round(s))%s", f["id"],
                         {True: "PASS", False: "FAIL", None: "skipped"}[_c],
                         compile_report["rounds_used"],
                         f" — {compile_report['reason']}" if compile_report["reason"] else "")
                # Persist unresolved compiler errors so a FAIL is actionable.
                if _c is False:
                    errs = "\n\n".join(
                        f"== {n} ==\n{pf.get('errors', '')}"
                        for n, pf in compile_report["per_file"].items() if not pf.get("ok"))
                    if errs.strip():
                        (out / "compile_errors.txt").write_text(errs, encoding="utf-8")
    else:
        inc_flags = []
        has_artifact = False
        log.info("poc: %s target language %s has no code generator — writing "
                 "documentation only", f["id"], language)

    if use_template:
        _write_template_readme(out, f, library, bug_class)
    else:
        _write_readme(out, f, library, bug_class, has_artifact,
                      target_path,
                      has_code=bool(server_c or client_c or java_server or java_client),
                      language=language, java_cp=java_cp)

    if use_template:
        status = "generated" if client_c else "doc_only"   # client-only PoC
    elif java_server and java_client:
        status = "generated"
    elif java_server or java_client:
        status = "partial"
    elif server_c and client_c:
        status = "generated"
    elif server_c or client_c:
        status = "partial"
    else:
        status = "doc_only"
    log.info("poc: %s package %s -> %s", f["id"], status, out)
    result = {"status": status, "poc_dir": str(out)}
    if compile_report is not None:
        result["compiled"] = compile_report["compiled"]
        result["compile_rounds"] = compile_report["rounds_used"]
        if compile_report.get("reason"):
            result["compile_note"] = compile_report["reason"]
    return result


def _ensure_transport_include(code: str) -> str:
    """If the file uses the pn_* transport but forgot `#include "poc_net.h"`,
    inject it after the last top-of-file #include. poc_net.h also pulls in
    unistd.h/string.h/etc., so this fixes the common 'undeclared pn_listen' and
    'implicit close()' errors in one shot."""
    if not code:
        return code
    if not re.search(r"\bpn_(listen|accept|connect|send|recv)\b", code):
        return code
    if '"poc_net.h"' in code or "<poc_net.h>" in code:
        return code
    lines = code.splitlines()
    insert_at = 0
    for i, ln in enumerate(lines[:60]):
        if ln.strip().startswith("#include"):
            insert_at = i + 1
    lines.insert(insert_at, '#include "poc_net.h"')
    return "\n".join(lines)


def _extract_c(text: str) -> str:
    """Pull the C source out of a model reply: prefer a ```c fenced block, then
    any fenced block, then raw text that looks like C. Survives truncation."""
    if not text:
        return ""
    m = re.search(r"```(?:c|C)?\s*\n(.*?)```", text, re.DOTALL)
    if m:
        return m.group(1).strip()
    # Unterminated fence (truncated) — take everything after the opening fence.
    m = re.search(r"```(?:c|C)?\s*\n(.*)$", text, re.DOTALL)
    if m and ("#include" in m.group(1) or "int main" in m.group(1)):
        return m.group(1).strip()
    if "#include" in text or "int main" in text:
        return text.strip()
    return ""


def _draft_one_file(role: str, finding: dict, api_block: str, target_path: str,
                    extra: str, drafter_backend, critic_backend) -> str:
    """Draft ONE C file (plain text, fenced ```c). Try the drafter, fall back to
    the critic model if it returns nothing usable. No JSON, no compile."""
    f = finding
    user = (
        f"{role}\n\n"
        f"Finding: {f.get('title','')}\n"
        f"CWE: {f.get('cwe','')}   Bug class: {finding.get('_bug_class','')}\n"
        f"Vulnerable entry point: {f.get('entry_point','')}\n"
        f"Location: {f.get('file','')}:{f.get('line','')}\n"
        f"Proving line: {f.get('proving_line','')}\n"
        f"Why it's a bug: {f.get('claim_justification','')}\n\n"
        f"Description:\n{f.get('description','')}\n\n"
        f"Target library path: {target_path}\n\n"
        f"## API CONTEXT (use this — do not guess headers or signatures)\n{api_block}\n"
        f"{extra}\n\n"
        f"Output the single ```c file now."
    )

    def _attempt(backend, label):
        try:
            raw = backend.complete(_CODE_SYSTEM, user, temperature=0.2,
                                   max_tokens=8192)
            code = _extract_c(raw)
            if not code:
                log.debug("poc: %s returned no extractable C (%d chars raw)",
                          label, len(raw or ""))
            return code
        except Exception as e:
            log.warning("poc: %s file draft failed: %s", label, e)
            return ""

    code = _attempt(drafter_backend, getattr(drafter_backend, "model", "drafter"))
    if not code and drafter_backend is not critic_backend:
        log.info("poc: primary drafter empty — falling back to critic model")
        code = _attempt(critic_backend, getattr(critic_backend, "model", "critic"))
    return code


def _draft_client_server(finding, bug_class, api_block, target_path,
                         drafter_backend, critic_backend):
    """Draft server.c then client.c as SEPARATE plain-text calls (per-file fenced
    ```c). The client is shown the generated server so their wire protocol stays
    consistent. Returns (server_c, client_c)."""
    finding = {**finding, "_bug_class": bug_class}
    timing_note = (
        " For this TIMING bug, the client sends MANY requests across two input "
        "classes and prints a measured 't = <value>'." if bug_class == "timing"
        else "")

    server_role = (
        "Write server.c: a TCP server that uses the target library legitimately. "
        "It takes the port as argv[1], accepts a connection, receives a buffer "
        "from the client via pn_recv, and runs the VULNERABLE operation "
        f"({finding.get('entry_point','the entry point')}) on that buffer. It must "
        "reach the vulnerable line when fed the client's hostile input. For a "
        "memory or validation bug, make the misbehaviour observable (it crashes "
        "under AddressSanitizer, or it accepts input it should reject and prints "
        "so).")
    server_c = _draft_one_file(server_role, finding, api_block, target_path,
                               "", drafter_backend, critic_backend)

    client_extra = ""
    if server_c:
        client_extra = ("\n## The server your client must talk to (match its wire "
                        "protocol exactly):\n```c\n" + server_c[:4000] + "\n```")
    client_role = (
        "Write client.c: the ATTACKER. It connects to the server "
        "(port = argv[1]) via pn_connect and sends crafted / malformed PQC input "
        "via pn_send designed to trigger the vulnerability "
        f"\"{finding.get('title','')}\" at the proving line." + timing_note)
    client_c = _draft_one_file(client_role, finding, api_block, target_path,
                               client_extra, drafter_backend, critic_backend)

    return server_c, client_c


def _write_build_script(out: Path, inc_flags: list[str], link_flags: list[str]) -> None:
    inc = " ".join(inc_flags)
    link = " ".join(link_flags)
    content = (
        "#!/bin/sh\n"
        "# Build the PoC client + server. Requires the target library built/\n"
        "# installed. Adjust INCLUDES / LIBS to your install if compilation fails.\n"
        "set -e\n"
        ': "${CC:=clang}"\n'
        f'INCLUDES="{inc}"\n'
        f'LIBS="{link}"\n'
        '$CC -fsanitize=address,undefined -O1 -g server.c -o poc_server $INCLUDES $LIBS\n'
        '$CC -fsanitize=address,undefined -O1 -g client.c -o poc_client $INCLUDES $LIBS -lm\n'
        'echo "Built poc_server and poc_client."\n'
        'echo "Run:  ./poc_server <port> &   then   ./poc_client <port>"\n'
    )
    (out / "build.sh").write_text(content, encoding="utf-8")


# ── Compile-and-fix loop (CodeAct-style) ──────────────────────────────────────
# The drafter one-shots C blind, so PoCs often don't compile (the reason the
# package was historically emit-only). When a compiler is available we instead
# run a `-fsyntax-only` check and feed the REAL compiler errors back to the model
# to fix, a few rounds. -fsyntax-only needs only the target HEADERS (not a built
# .a/.so), so it runs far more widely than a full link; the full sanitiser build
# + run stays the user's step (they have the library). Degrades gracefully to
# emit-only when there's no compiler or the headers can't be found.

_NO_CC = "__NO_CC__"


def _compile_c(out: Path, src_name: str, inc_flags: list[str]) -> tuple[bool, str]:
    """Syntax/semantic compile check of one C file against the target headers.
    No link. Returns (ok, stderr); stderr == _NO_CC signals no compiler found."""
    cc = os.environ.get("CC") or shutil.which("clang") or shutil.which("gcc") or ""
    if not cc:
        return False, _NO_CC
    cmd = [cc, "-fsyntax-only", *inc_flags, src_name]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=120,
                           cwd=str(out))
        return p.returncode == 0, (p.stderr or p.stdout or "")
    except Exception as e:  # pragma: no cover - environment dependent
        return False, f"compiler invocation failed: {e}"


def _is_env_error(errors: str) -> bool:
    """A missing-header error is an ENVIRONMENT problem (build the library / fix
    -I paths), not something the model can fix by editing code — so we bail
    rather than thrash the fix loop against it."""
    e = (errors or "").lower()
    return ("file not found" in e and ".h" in e) or "no such file or directory" in e


def _fix_file(name: str, code: str, errors: str, finding: dict, api_block: str,
              drafter_backend, critic_backend) -> str:
    """Ask the drafter to FIX a C file given the real compiler errors (CodeAct
    feedback). Returns the revised C, or '' if nothing usable came back."""
    user = (
        f"The C file `{name}` below FAILED to compile (`clang -fsyntax-only`). "
        f"Fix it so it compiles cleanly. Change as little as possible and keep the "
        f"PoC behaviour. Use ONLY the headers/signatures in the API context.\n\n"
        f"## Compiler errors\n{(errors or '')[-2500:]}\n\n"
        f"## API CONTEXT (correct headers/signatures — do not guess)\n{api_block}\n\n"
        f"## Current {name}\n```c\n{code[:8000]}\n```\n\n"
        f"Output the corrected single ```c file now."
    )

    def _attempt(backend, label):
        try:
            raw = backend.complete(_CODE_SYSTEM, user, temperature=0.2,
                                   max_tokens=8192)
            return _extract_c(raw)
        except Exception as e:
            log.warning("poc: fix attempt (%s) failed: %s", label, e)
            return ""

    fixed = _attempt(drafter_backend, getattr(drafter_backend, "model", "drafter"))
    if not fixed and drafter_backend is not critic_backend:
        fixed = _attempt(critic_backend, getattr(critic_backend, "model", "critic"))
    return fixed


def _compile_and_fix(out: Path, files: dict, inc_flags: list[str], finding: dict,
                     api_block: str, drafter_backend, critic_backend, rounds: int,
                     compile_fn=None) -> dict:
    """Syntax-check each generated C file; on failure feed the compiler errors
    back to the drafter to fix, up to `rounds` times. `files` maps name->source.

    Returns {compiled, reason, rounds_used, per_file:{name:{ok,errors}}, sources}.
    `compiled` is True/False, or None when the check can't run (no compiler, or
    headers absent) — the caller then keeps the emit-only behaviour unchanged.
    `compile_fn` is injectable for testing; defaults to _compile_c.
    """
    compile_fn = compile_fn or _compile_c
    rounds = max(1, rounds)
    sources = dict(files)
    report: dict = {"compiled": None, "reason": "", "rounds_used": 0, "per_file": {},
                    "sources": sources}
    for rnd in range(1, rounds + 1):
        report["rounds_used"] = rnd
        for name, src in sources.items():
            (out / name).write_text(src, encoding="utf-8")
        all_ok = True
        for name, src in sources.items():
            ok, errors = compile_fn(out, name, inc_flags)
            if errors == _NO_CC:
                # The only HARD bail: no compiler at all means the check can't run.
                # A missing HEADER, by contrast, is often a hallucinated #include
                # the fix loop can correct — so let it try rather than bailing.
                report["reason"] = "no C compiler on PATH (clang/gcc); compile check skipped"
                return report
            report["per_file"][name] = {"ok": ok, "errors": (errors or "")[-2000:]}
            all_ok = all_ok and ok
        if all_ok:
            report["compiled"] = True
            return report
        if rnd == rounds:
            break   # no more rounds to re-check a fix, so stop here
        for name, src in sources.items():
            if report["per_file"].get(name, {}).get("ok"):
                continue
            fixed = _fix_file(name, src, report["per_file"][name]["errors"],
                              finding, api_block, drafter_backend, critic_backend)
            if fixed:
                sources[name] = _ensure_transport_include(fixed)
    report["compiled"] = False
    # If we still fail on a missing header after all rounds, the library headers
    # probably aren't where the -I flags point (vs a fixable bad #include) — say so.
    if any(_is_env_error(pf.get("errors", "")) for pf in report["per_file"].values()):
        report["reason"] = ("still failing on a missing header — build the target "
                            "library or fix the build.sh include paths")
    return report


# ── Java compile-and-fix ──────────────────────────────────────────────────────
# The C loop's sibling, but three things differ enough to keep it separate:
# javac compiles the PoC as a SET (server and client share PocNet, so a repair
# that desyncs their wire protocol has to show up as an error, not pass because
# each file was checked alone); it needs a classpath rather than -I flags; and
# it produces .class files, which go to a throwaway directory and are discarded.
# Nothing is ever executed.

_JAVA_CP_ENV = "POC_JAVA_CP"


def _java_compile_cp(target_path: str, jars: list[str]) -> str:
    """Classpath for the compile check, or '' when we have nothing to compile
    against.

    POC_JAVA_CP wins — a freshly cloned source tree has no jars, so without an
    explicit override the check could never run on the one case that matters.
    A directory is expanded to its wildcard, so pointing it at a folder of jars
    just works.
    """
    env = (os.environ.get(_JAVA_CP_ENV) or "").strip()
    if env:
        return f"{env.rstrip('/' + chr(92))}/*" if Path(env).is_dir() else env
    return os.pathsep.join(jars) if jars else ""


def _compile_java(out: Path, names: list[str], cp: str) -> tuple[bool, str]:
    """Compile the PoC sources together. Returns (ok, stderr); stderr == _NO_CC
    when javac is not on PATH. Class files land in a temp dir and are thrown
    away — this is a check, not a build, and nothing is run."""
    javac = os.environ.get("JAVAC") or shutil.which("javac") or ""
    if not javac:
        return False, _NO_CC
    with tempfile.TemporaryDirectory() as tmp:
        cmd = [javac, "-nowarn", "-d", tmp]
        if cp:
            cmd += ["-cp", cp]
        cmd += list(names)
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=180,
                               cwd=str(out))
            return p.returncode == 0, (p.stderr or p.stdout or "")
        except Exception as e:  # pragma: no cover - environment dependent
            return False, f"compiler invocation failed: {e}"


def _java_errors_by_file(errors: str, names: list[str]) -> dict[str, str]:
    """Split javac's output per source file. javac prints absolute paths, and a
    diagnostic's follow-on lines (the caret, 'symbol:', 'location:') belong to
    the file named on the line above."""
    buckets: dict[str, list[str]] = {n: [] for n in names}
    cur = None
    for line in (errors or "").splitlines():
        m = re.match(r"^(?:.*[\\/])?([\w$]+\.java):(\d+):", line)
        if m and m.group(1) in buckets:
            cur = m.group(1)
        if cur:
            buckets[cur].append(line)
    return {n: "\n".join(v) for n, v in buckets.items() if v}


def _fix_java_file(name: str, cls: str, code: str, errors: str, api_block: str,
                   drafter_backend, critic_backend) -> str:
    """Ask the drafter to fix one Java file given the real javac errors."""
    body = code if len(code) <= 24000 else (
        code[:24000] + "\n// ... TRUNCATED FOR THIS PROMPT — return the whole file")
    user = (
        f"The Java file `{name}` below FAILED to compile with javac. Fix it so it "
        "compiles cleanly. Change as little as possible: keep the PoC doing what "
        "it does, and do NOT delete the call that reaches the vulnerable code — "
        "a PoC that compiles because the interesting part was removed is worse "
        "than one that does not compile.\n\n"
        f"## javac errors\n{(errors or '')[-3000:]}\n\n"
        f"## API CONTEXT (real signatures — do not guess)\n{api_block}\n\n"
        f"## Current {name}\n```java\n{body}\n```\n\n"
        "Output the corrected single ```java file now."
    )
    system = _JAVA_SYSTEM % {"cls": cls, "port": _JAVA_PORT}

    def _attempt(backend, label):
        if backend is None:
            return ""
        try:
            raw = backend.complete(system, user, temperature=0.2, max_tokens=8192)
            code2 = _extract_java(raw)
            if code2 and not _java_looks_complete(code2):
                log.warning("poc: %s returned a TRUNCATED fix for %s — ignoring it",
                            label, name)
                return ""
            return code2
        except Exception as e:
            log.warning("poc: Java fix attempt (%s) failed: %s", label, e)
            return ""

    fixed = _attempt(drafter_backend, getattr(drafter_backend, "model", "drafter"))
    if not fixed and critic_backend is not None and drafter_backend is not critic_backend:
        fixed = _attempt(critic_backend, getattr(critic_backend, "model", "critic"))
    return _normalise_java(fixed, cls) if fixed else ""


def _compile_and_fix_java(out: Path, sources: dict, extra_names: tuple,
                          cp: str, finding: dict, api_block: str,
                          drafter_backend, critic_backend, rounds: int,
                          compile_fn=None) -> dict:
    """javac the PoC, feed errors back, repeat up to `rounds` times.

    `sources` maps repairable filename -> source. `extra_names` are compiled
    alongside but never repaired (PocNet), so the transport cannot be rewritten
    into something that hides a failure.

    Same report shape as the C loop. `compiled` is None when the check could not
    run at all — no javac, or nothing to compile against — which is reported as
    "skipped", never as a failure.
    """
    compile_fn = compile_fn or _compile_java
    rounds = max(1, rounds)
    sources = dict(sources)
    report: dict = {"compiled": None, "reason": "", "rounds_used": 0,
                    "per_file": {}, "sources": sources}
    if not cp:
        report["reason"] = (f"no library jars to compile against — set {_JAVA_CP_ENV} "
                            "to a folder of jars, or build the target library")
        return report

    names = list(sources) + list(extra_names)
    ep = (finding.get("entry_point") or "").strip()

    for rnd in range(1, rounds + 1):
        report["rounds_used"] = rnd
        for name, src in sources.items():
            (out / name).write_text(src, encoding="utf-8")

        ok, errors = compile_fn(out, names, cp)
        if errors == _NO_CC:
            report["reason"] = "javac not on PATH; compile check skipped"
            report["rounds_used"] = 0
            return report
        per_file = _java_errors_by_file(errors, names)
        report["per_file"] = {
            n: {"ok": n not in per_file, "errors": per_file.get(n, "")[-2000:]}
            for n in names}
        if ok:
            report["compiled"] = True
            return report
        if rnd == rounds:
            break

        for name in list(sources):
            errs = per_file.get(name, "")
            if not errs:
                continue
            cls = Path(name).stem
            fixed = _fix_java_file(name, cls, sources[name], errs, api_block,
                                   drafter_backend, critic_backend)
            if not fixed:
                continue
            # A repair that drops the vulnerable call compiles and proves nothing.
            if ep and ep in sources[name] and ep not in fixed:
                log.warning("poc: rejecting a repair of %s — it removed the entry "
                            "point %s, which is the whole point of the PoC",
                            name, ep)
                continue
            sources[name] = fixed

    report["compiled"] = False
    if not report["reason"] and any(
            "cannot find symbol" in (pf.get("errors") or "")
            for pf in report["per_file"].values()):
        report["reason"] = ("still failing on an unresolved symbol — the draft may "
                            "be using an API that does not exist in this version")
    return report


_BUG_DESC = {
    "memory": "a memory-safety issue (out-of-bounds / overflow / use-after-free)",
    "validation": "an input-validation flaw — malformed input is accepted when the spec requires it to be rejected",
    "leak": "an information leak — observable output is correlated with a secret",
    "timing": "a timing side-channel — the operation is not constant-time on secret data",
    "cleanup": "a missing-zeroization / sensitive-data-remnant issue — secrets are not cleared from memory after use",
}
_BUG_DESC.update({
    "crash": "a null-dereference / unhandled-failure defect — input that should be "
             "rejected cleanly instead crashes the operation (denial of service)",
    "resource": "an unbounded-resource issue — an attacker-controlled size, count or "
                "iteration value drives allocation or work with no ceiling",
    "ssrf": "a server-side request forgery — the library dereferences a URI taken from "
            "attacker-supplied input",
})
_OBSERVE = {
    "memory": "the **server crashes** (segfault / AddressSanitizer abort) when the client sends its crafted input.",
    # Overridden per language by _observe() — the managed-runtime wording below
    # is wrong for a C PoC, which segfaults rather than throwing.
    "crash": "the **harness dies on input a correct library rejects cleanly** — it "
             "should keep running instead.",
    "resource": "the **harness allocates or spins far beyond what the real input size "
                "justifies** — watch heap growth, or wall-clock time climbing with the "
                "attacker's declared value, against a fixed library that refuses it.",
    "ssrf": "the **library issues a request to the URI the attacker supplied** — watch "
            "the loopback listener in the PoC receive the connection (or a local file "
            "being read) instead of the request being refused.",
    "validation": "the **server accepts** the malformed input the client sends, where a correct library would reject it.",
    "leak": "the **server's observable response correlates with the secret** the attacker should not learn.",
    "timing": "the **client reports a significant timing difference** (large `t`) between its two input classes.",
    "cleanup": "**secret/sensitive bytes remain in memory after the operation** — this is a memory-hygiene "
               "issue, usually NOT observable over the network. Confirm by inspecting the stack/heap with a "
               "debugger (gdb) or running under Valgrind/ASan and checking that the secret buffer is not zeroed "
               "after use. The client/server here is a harness to reach the code path, not a network oracle.",
}


# A crash looks completely different depending on the runtime, and the generic
# blurb has to say which one the reader should expect.
_OBSERVE_BY_LANG = {
    ("crash", "java"): "the **harness terminates with an uncaught exception** (e.g. a "
                       "NullPointerException) where a correct library rejects the input "
                       "cleanly and keeps running.",
    ("crash", "c"): "the **server dies on the crafted input** — a segfault, or an "
                    "AddressSanitizer/UBSan report at the vulnerable line — where a "
                    "correct library rejects it and keeps serving.",
}


def _observe(bug_class: str, language: str) -> str:
    return (_OBSERVE_BY_LANG.get((bug_class, language.lower()))
            or _OBSERVE.get(bug_class, "the documented effect."))


def _write_readme(out: Path, f: dict, library: str, bug_class: str,
                  has_artifact: bool,
                  target_path: str, has_code: bool, language: str,
                  java_cp: str = "") -> None:
    lib = library or "the target library"
    # entry_point is frequently empty for Java findings. Don't render the literal
    # words "the vulnerable function" inside backticks as if it were a symbol —
    # fall back to the file:line, which is always known.
    _ep_raw = (f.get("entry_point") or "").strip()
    ep = f"`{_ep_raw}`" if _ep_raw else f"the vulnerable line (`{f.get('file','')}:{f.get('line','')}`)"
    fence = "java" if language == "java" else "c"
    # BouncyCastle only: the tester needs the exact release that was scanned,
    # and there is no archive on bouncycastle.org to send them to.
    bc = (_bc_download_section(f, target_path, has_artifact)
          if _is_bouncycastle(library, target_path) else [])
    L: list[str] = []
    L += [f"# PoC — {f.get('title','(untitled finding)')}", ""]
    L += [
        "| Field | Value |", "|---|---|",
        f"| **Library** | {library or '(target)'} |",
        f"| **Severity** | {f.get('severity','')} |",
        f"| **CWE** | {f.get('cwe','') or '—'} |",
        f"| **Spec** | {f.get('spec_reference','') or '—'} |",
        f"| **Location** | `{f.get('file','')}:{f.get('line','')}` |",
        f"| **Vulnerable function** | `{f.get('entry_point','') or '—'}` |",
        f"| **Bug class** | {bug_class} |",
        "",
    ]
    _shape = "**client/server demonstration**"
    L += [
        "## What this is",
        f"A proof-of-concept {_shape} of "
        f"{_BUG_DESC.get(bug_class, 'a security issue')} in {lib}, reached through "
        f"{ep}. You run it yourself against a sandbox that has {lib} "
        f"built/installed — the assessor does **not** run it for you.",
        "",
        "## The vulnerability",
        (f.get("description", "") or "").strip() or "(see the finding in the main report)",
    ]
    if f.get("proving_line"):
        L += ["", f"**Vulnerable line** (`{f.get('file','')}:{f.get('line','')}`):",
              f"```{fence}", f["proving_line"], "```"]
    if f.get("claim_justification"):
        L += ["", f"**Why it's a bug:** {f['claim_justification']}"]
    if f.get("evidence_quote") and f.get("evidence_quote") != f.get("proving_line"):
        L += ["", "**Evidence from source:**", f"```{fence}", f["evidence_quote"], "```"]

    if has_code and language == "java":
        L += [
            "", "## What the PoC does",
            f"- **{_JAVA_SERVER_CLS}.java** — the victim. It uses {lib} the way a "
            f"real application would, then runs the vulnerable operation "
            f"({ep}) on bytes received from the client.",
            f"- **{_JAVA_CLIENT_CLS}.java** — the attacker. It connects and sends "
            "crafted input designed to trigger the bug. It needs no crypto "
            "library of its own.",
            f"- **{_JAVA_NET_CLS}.java** — fixed localhost-TCP transport "
            "(length-prefixed buffers, same wire format as the C PoCs); do not edit.",
            "- **build.sh / build.bat** — compile all three; edit `CP` if your jar "
            "paths differ.",
            "", "## Expected result (if the bug is present)",
            f"You should observe: {_observe(bug_class, language)}",
        ]
        L += bc
        L += [
            "", "## How to run it (in your sandbox)",
            "Requires a JDK and the library jars. From this directory:",
            "```sh",
            "sh build.sh                  # compile (build.bat on Windows cmd)",
            (f'CP="{java_cp}"' if java_cp
             else "CP=...                       # the classpath build.sh printed"),
            f'java -cp "$CP:." {_JAVA_SERVER_CLS} {_JAVA_PORT} &   # terminal 1: the victim',
            f'java -cp "$CP:." {_JAVA_CLIENT_CLS} {_JAVA_PORT}     # terminal 2: the attacker',
            "```",
            "The evidence appears in the **server's** terminal — that is the process "
            "running the library.",
        ]
        # bc: the download section already covers this, better.
        if not has_artifact and not bc:
            L += ["", f"> **Note:** no jars were found under `{target_path}`, so the "
                  f"classpath in the build scripts is a placeholder. Build the library "
                  f"first:\n>\n>     {_build_hint(target_path)}\n>\n"
                  "> then point `CP` at the produced jars (for a Gradle build they land "
                  "in `<module>/build/libs/`)."]
        L += [
            "", "> **IMPORTANT:** This is a **generated scaffold**. Review the code and "
            "adjust the API calls and crafted inputs to your library version before "
            "trusting the result. The assessor identifies and documents the "
            "vulnerability; **you** build, run, and confirm the PoC.",
        ]
    elif has_code:
        L += [
            "", "## What the PoC does",
            f"- **server.c** — uses {lib} normally and runs the vulnerable "
            f"operation ({ep}) on data received from the client.",
            "- **client.c** — the attacker; connects and sends crafted input "
            "designed to trigger the bug.",
            "- **poc_net.h** — fixed localhost-TCP transport (length-prefixed "
            "buffers); do not edit.",
        ]
        L += [
            "", "## Expected result (if the bug is present)",
            f"You should observe: {_observe(bug_class, language)}",
        ]
        L += [
            "", "## How to run it (in your sandbox)",
            f"Requires {lib} built/installed (headers + a static/shared library). "
            "From this directory:",
            "```sh",
            "sh build.sh            # compile server.c + client.c (edit paths if needed)",
            "./poc_server 21000 &   # terminal 1: start the server on a port",
            "./poc_client 21000     # terminal 2: run the attacker client",
            "```",
        ]
        if not has_artifact:
            L += ["", f"> **Note:** no compiled library was found under "
                  f"`{target_path}`. Build it first:\n>\n>     {_build_hint(target_path)}\n>\n"
                  f"> then re-run `sh build.sh` (adjust the lib path in build.sh if needed)."]
        L += [
            "", "> **IMPORTANT:** This is a **generated scaffold**. Review the code and adjust "
            "the input crafting and API calls to your library version before "
            "trusting the result. The assessor identifies and documents the "
            "vulnerability; **you** build, run, and confirm the PoC.",
        ]
    else:
        _why = ("the drafting model returned no usable source"
                if language in ("c", "java")
                else f"there is no code generator for `{language}` targets yet")
        L += [
            "", "## PoC code",
            f"No code scaffold was generated — {_why}. Use the vulnerability "
            f"details above to write a PoC against your {lib} test harness.",
        ]
        L += bc

    if f.get("proposed_fix"):
        L += ["", "## Suggested fix", f["proposed_fix"]]

    (out / "README.md").write_text("\n".join(L) + "\n", encoding="utf-8")
