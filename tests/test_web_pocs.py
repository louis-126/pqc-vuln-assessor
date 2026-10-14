"""PoC package reading + routing tests. No scan, no model, no network.

Builds a throwaway runs/ tree in a temp dir and points web.pocs / web.scans at
it, so the real runs/ directory is never touched.
"""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from web import pocs, runner
from web.app import app


def _make_run(root: Path) -> str:
    """A runs/<lib>/<ts>/ tree with a report and two PoC packages."""
    run_dir = root / "demolib" / "20260101-000000"
    (run_dir / "poc" / "FND-aaa").mkdir(parents=True)
    (run_dir / "poc" / "FND-bbb").mkdir(parents=True)

    (run_dir / "report.json").write_text(json.dumps({
        "summary": {"HIGH": 1},
        "findings": [
            {"id": "FND-aaa", "title": "Unbounded CRL read", "severity": "HIGH",
             "cwe": "CWE-770", "file": "src/crl.c", "confidence": "confirmed"},
            {"id": "FND-bbb", "title": "Doc only one", "severity": "LOW",
             "cwe": "CWE-20", "file": "src/x.c", "confidence": "confirmed"},
        ],
    }), encoding="utf-8")

    # Package one: README + two drafted sources + transport + build script.
    pkg = run_dir / "poc" / "FND-aaa"
    (pkg / "README.md").write_text("# PoC\nbuild it\n", encoding="utf-8")
    (pkg / "server.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
    (pkg / "client.c").write_text("int main(void){return 1;}\n", encoding="utf-8")
    (pkg / "poc_net.h").write_text("#define X 1\n", encoding="utf-8")
    (pkg / "build.sh").write_text("cc server.c\n", encoding="utf-8")

    # Package two: README only.
    (run_dir / "poc" / "FND-bbb" / "README.md").write_text("# doc\n", encoding="utf-8")
    return "demolib/20260101-000000"


class PocPackageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.run_id = _make_run(self.tmp)
        # Both modules resolve run dirs against their own RUNS_DIR constant.
        self.patches = [patch.object(pocs, "RUNS_DIR", self.tmp)]
        from web import scans
        self.patches.append(patch.object(scans, "RUNS_DIR", self.tmp))
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_status_is_inferred_from_the_drafted_sources(self):
        by_id = {p["id"]: p for p in pocs.list_packages(self.run_id)}
        self.assertEqual(by_id["FND-aaa"]["status"], "generated")
        self.assertEqual(by_id["FND-bbb"]["status"], "doc_only")

    def test_poc_net_header_does_not_count_as_a_drafted_source(self):
        """poc_net.h is copied verbatim from the template, so a package with a
        README, poc_net.h and ONE source is 'partial', not 'generated'."""
        pkg = self.tmp / "demolib" / "20260101-000000" / "poc" / "FND-aaa"
        (pkg / "client.c").unlink()
        by_id = {p["id"]: p for p in pocs.list_packages(self.run_id)}
        self.assertEqual(by_id["FND-aaa"]["status"], "partial")

    def test_finding_metadata_is_joined_from_report_json(self):
        pkg = pocs.package_detail(self.run_id, "FND-aaa")
        self.assertEqual(pkg["finding"]["title"], "Unbounded CRL read")
        self.assertEqual(pkg["finding"]["severity"], "HIGH")
        self.assertIn("build it", pkg["contents"]["README.md"])

    def test_runs_with_pocs_skips_runs_that_have_none(self):
        (self.tmp / "otherlib" / "20260101-111111").mkdir(parents=True)
        (self.tmp / "otherlib" / "20260101-111111" / "report.json").write_text(
            json.dumps({"findings": []}), encoding="utf-8")
        ids = [r["id"] for r in pocs.runs_with_pocs()]
        self.assertEqual(ids, [self.run_id])

    def test_traversal_and_suffix_guards(self):
        self.assertIsNone(pocs.package_detail(self.run_id, ".."))
        self.assertIsNone(pocs.package_detail(self.run_id, "a/b"))
        # Escaping the package dir, and a suffix outside the allowed set.
        self.assertIsNone(pocs.poc_file(self.run_id, "FND-aaa", "../../report.json"))
        self.assertIsNone(pocs.poc_file(self.run_id, "FND-aaa", "evil.exe"))
        self.assertIsNotNone(pocs.poc_file(self.run_id, "FND-aaa", "server.c"))

    def test_pages_render(self):
        client = app.test_client()
        self.assertEqual(client.get("/pocs").status_code, 200)
        lib, ts = self.run_id.split("/")
        page = client.get(f"/scan/{lib}/{ts}/poc")
        self.assertEqual(page.status_code, 200)
        self.assertIn("FND-aaa", page.get_data(as_text=True))
        detail = client.get(f"/scan/{lib}/{ts}/poc/FND-aaa")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(client.get(f"/scan/{lib}/{ts}/poc/nope").status_code, 404)

    def test_zip_download_contains_every_file(self):
        import io
        import zipfile
        lib, ts = self.run_id.split("/")
        r = app.test_client().get(f"/scan/{lib}/{ts}/poc/FND-aaa/download")
        self.assertEqual(r.status_code, 200)
        names = zipfile.ZipFile(io.BytesIO(r.data)).namelist()
        self.assertIn("FND-aaa/server.c", names)
        self.assertIn("FND-aaa/README.md", names)


class PocJobOptionTests(unittest.TestCase):
    """start_job's PoC validation — the scan itself is never launched because
    every case here is expected to raise before the thread starts."""

    def setUp(self):
        # preflight_poc_models probes Ollama over the network; stub it so these
        # stay offline and fast, and so the assertions below are about the rule
        # under test rather than whatever Ollama happens to be doing.
        self._p = patch.object(runner, "_ollama_reachable", return_value=True)
        self._p.start()

    def tearDown(self):
        self._p.stop()

    def _start(self, **kw):
        base = dict(library="demolib", mode="reason", backend="ollama", model=None,
                    explain=False, source_kind="path", source=".")
        return runner.start_job(**{**base, **kw})

    def test_rejects_compile_rounds_above_the_cap(self):
        with self.assertRaises(ValueError) as ctx:
            self._start(poc=True, poc_compile_rounds=99)
        self.assertIn("at most", str(ctx.exception))

    def test_rejects_negative_compile_rounds(self):
        with self.assertRaises(ValueError) as ctx:
            self._start(poc=True, poc_compile_rounds=-1)
        self.assertIn("non-negative", str(ctx.exception))

    def test_rejects_anthropic_poc_model_without_a_key(self):
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": ""}):
            with self.assertRaises(ValueError) as ctx:
                self._start(poc=True, poc_drafter_model="claude-opus-5")
            self.assertIn("ANTHROPIC_API_KEY", str(ctx.exception))

    def test_rejects_local_poc_model_when_ollama_is_down(self):
        """The failure that silently killed a completed scan: a Claude drafter
        paired with the DEFAULT local critic, and no Ollama running."""
        self._p.stop()
        try:
            with patch.object(runner, "_ollama_reachable", return_value=False), \
                 patch.dict("os.environ", {"ANTHROPIC_API_KEY": "k"}):
                with self.assertRaises(ValueError) as ctx:
                    self._start(poc=True, poc_drafter_model="claude-opus-5")
                msg = str(ctx.exception)
                self.assertIn("critic", msg)
                self.assertIn("Ollama", msg)
        finally:
            self._p.start()

    def test_all_claude_pairing_needs_no_ollama(self):
        with patch.object(runner, "_ollama_reachable",
                          side_effect=AssertionError("must not probe Ollama")), \
             patch.dict("os.environ", {"ANTHROPIC_API_KEY": "k"}):
            runner.preflight_poc_models("claude-opus-5", "claude-opus-5")

    def test_poc_flags_reach_the_cli_command(self):
        """The subprocess argv is the contract between the web layer and the
        CLI's PoC stage — assert the flags are actually passed through."""
        job = runner.Job("demolib", "reason", "ollama", None, False, "path", ".",
                         poc=True, poc_drafter_model="deepseek-r1:14b",
                         poc_critic_model="llama3:8b", poc_compile_rounds=2)
        captured = {}

        class _Proc:
            returncode = 0

            def wait(self_inner):
                return 0

        def _popen(cmd, **kwargs):
            captured["cmd"] = cmd
            return _Proc()

        with tempfile.TemporaryDirectory() as td:
            with patch.object(runner, "RUNS_DIR", Path(td)), \
                 patch.object(runner.subprocess, "Popen", _popen):
                job.run()

        cmd = captured["cmd"]
        self.assertIn("--poc", cmd)
        self.assertIn("deepseek-r1:14b", cmd)
        self.assertIn("llama3:8b", cmd)
        self.assertEqual(cmd[cmd.index("--poc-compile-rounds") + 1], "2")

    def test_no_poc_flags_when_disabled(self):
        job = runner.Job("demolib", "reason", "ollama", None, False, "path", ".")
        captured = {}

        class _Proc:
            returncode = 0

            def wait(self_inner):
                return 0

        def _popen(cmd, **kwargs):
            captured["cmd"] = cmd
            return _Proc()

        with tempfile.TemporaryDirectory() as td:
            with patch.object(runner, "RUNS_DIR", Path(td)), \
                 patch.object(runner.subprocess, "Popen", _popen):
                job.run()

        self.assertNotIn("--poc", captured["cmd"])


class _MockJava:
    """A drafter that returns a Java file needing normalisation (a package line
    and a class name that does not match the required filename)."""
    model = "mock-java"

    def complete(self, system, user, **kw):
        assert "Java" in system, "Java drafting must use the Java system prompt"
        assert "PocNet.recv" in system, "the fixed transport must be offered"
        # Server and client are drafted in separate calls; name the class wrongly
        # in both so normalisation has something to fix.
        which = "Srv" if "PocServer.java" in user else "Cli"
        return (
            "```java\n"
            "package com.example.demo;\n"
            "import java.security.Security;\n"
            f"public class SomethingElse{which} {{\n"
            f"    public static void main(String[] a) {{ new SomethingElse{which}(); }}\n"
            "}\n```"
        )


class JavaEmitPathTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        # A minimal Java "target tree" with Allman braces, as BouncyCastle uses.
        src = self.tmp / "prov/src/main/java/org/example"
        src.mkdir(parents=True)
        (src / "Thing.java").write_text(
            "package org.example;\n"
            "\n"
            "public class Thing\n"
            "{\n"
            "    public void check(Certificate cert, Collection<String> c)\n"
            "        throws CertPathValidatorException\n"
            "    {\n"
            "        int x = 1;\n"
            "        boom(anchor.getTrustedCert().getSubject());\n"
            "    }\n"
            "}\n", encoding="utf-8")
        self.finding = {
            "id": "FND-java", "title": "Dereferenced without null guard (NPE / DoS)",
            "cwe": "CWE-476", "severity": "MEDIUM", "spec_reference": "",
            "entry_point": "", "file": "prov/src/main/java/org/example/Thing.java",
            "line": 9, "description": "NPE on a name-based anchor.",
            "proving_line": "boom(anchor.getTrustedCert().getSubject());",
            "claim_justification": "no null check", "evidence_quote": "",
            "proposed_fix": "guard it",
        }

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_null_deref_is_crash_not_memory(self):
        from poc.generator import _classify_bug
        self.assertEqual(_classify_bug("NPE without null guard", "CWE-476", "java"),
                         "crash")
        # An unclassifiable Java finding must not fall back to "memory".
        self.assertEqual(_classify_bug("Something odd happens", "", "java"), "crash")
        # C behaviour is unchanged for the classic memory CWEs.
        self.assertEqual(_classify_bug("Heap buffer overflow", "CWE-787", "c"),
                         "memory")

    def test_crash_wording_follows_the_language(self):
        """The crash class applies to C too, so its expected-result text must not
        talk about NullPointerException in a C package."""
        from poc.generator import _observe
        self.assertIn("segfault", _observe("crash", "c"))
        self.assertNotIn("NullPointerException", _observe("crash", "c"))
        self.assertIn("NullPointerException", _observe("crash", "java"))

    def test_c_memory_classes_are_unaffected(self):
        """The classifier split must not move the classic C memory CWEs."""
        from poc.generator import _classify_bug
        for title, cwe in [("Heap buffer overflow", "CWE-787"),
                           ("Out-of-bounds read", "CWE-125"),
                           ("Use-after-free", "CWE-416"),
                           ("Integer overflow", "CWE-190")]:
            self.assertEqual(_classify_bug(title, cwe, "c"), "memory", cwe)

    def test_unbounded_and_ssrf_classes(self):
        from poc.generator import _classify_bug
        self.assertEqual(_classify_bug("reads stream with no size cap", "CWE-770",
                                       "java"), "resource")
        self.assertEqual(_classify_bug("CRLDP fetched with no scheme restriction",
                                       "CWE-918", "java"), "ssrf")

    def test_entry_point_recovered_from_allman_braced_source(self):
        """The signature's `{` is on a later line — the common Java style, and
        the reason entry_point came back empty before."""
        from poc.generator import _java_api_context
        ctx, ep = _java_api_context(str(self.tmp), self.finding)
        self.assertIn("public void check(", ep)
        self.assertIn("CertPathValidatorException", ep)
        self.assertIn("org.example", ctx)

    def test_only_build_output_jars_count(self):
        from poc.generator import _find_java_classpath
        # Vendored third-party deps must NOT be mistaken for the library.
        (self.tmp / "libs").mkdir()
        (self.tmp / "libs/junit-4.13.2.jar").write_bytes(b"x")
        jars, found = _find_java_classpath(str(self.tmp))
        self.assertEqual((jars, found), ([], False))
        # A real build output does count.
        (self.tmp / "prov/build/libs").mkdir(parents=True)
        (self.tmp / "prov/build/libs/bcprov-jdk18on-1.84.jar").write_bytes(b"x")
        jars, found = _find_java_classpath(str(self.tmp))
        self.assertTrue(found)
        self.assertTrue(any("bcprov" in j for j in jars))

    def test_java_package_is_generated_and_normalised(self):
        from poc.generator import generate_poc_package
        out = self.tmp / "out"
        res = generate_poc_package(self.finding, "java", _MockJava(), _MockJava(),
                                   str(out), str(self.tmp), "bouncycastle")
        self.assertEqual(res["status"], "generated")   # server + client both drafted
        d = Path(res["poc_dir"])
        names = sorted(p.name for p in d.iterdir())
        self.assertEqual(names, ["PocClient.java", "PocNet.java", "PocServer.java",
                                 "README.md", "build.bat", "build.sh"])
        for cls in ("PocServer", "PocClient"):
            src = (d / f"{cls}.java").read_text(encoding="utf-8")
            self.assertNotIn("package ", src)            # package line stripped
            self.assertIn(f"public class {cls}", src)    # renamed to match filename
            self.assertNotIn("SomethingElse", src)
        # The transport is ours, copied verbatim — the model never writes it.
        self.assertIn("FIXED INFRASTRUCTURE",
                      (d / "PocNet.java").read_text(encoding="utf-8"))

    def test_java_readme_uses_java_fences_and_real_entry_point(self):
        from poc.generator import generate_poc_package
        out = self.tmp / "out2"
        res = generate_poc_package(self.finding, "java", _MockJava(), _MockJava(),
                                   str(out), str(self.tmp), "bouncycastle")
        readme = (Path(res["poc_dir"]) / "README.md").read_text(encoding="utf-8")
        self.assertIn("```java", readme)
        self.assertNotIn("```c\n", readme)
        self.assertIn("| **Bug class** | crash |", readme)
        self.assertIn("public void check(", readme)        # recovered entry point
        self.assertNotIn("`the vulnerable function`", readme)
        # The C memory blurb must not be applied to a Java null-dereference.
        self.assertNotIn("out-of-bounds", readme)
        self.assertNotIn("use-after-free", readme)
        self.assertIn("uncaught exception", readme)

    def test_no_backend_still_writes_documentation(self):
        from poc.generator import generate_poc_package
        out = self.tmp / "out3"
        res = generate_poc_package(self.finding, "java", None, None,
                                   str(out), str(self.tmp), "bouncycastle")
        self.assertEqual(res["status"], "doc_only")
        self.assertTrue((Path(res["poc_dir"]) / "README.md").is_file())


class PocJobTests(unittest.TestCase):
    """PocJob shells out to `main.py --poc-only` — assert the argv contract."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.run_dir = self.tmp / "demolib" / "20260101-000000"
        self.run_dir.mkdir(parents=True)
        (self.run_dir / "report.json").write_text(json.dumps({"findings": []}),
                                                  encoding="utf-8")
        self.patches = [
            patch.object(runner, "RUNS_DIR", self.tmp),
            patch.object(runner, "_ollama_reachable", return_value=True),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _capture(self, **kw):
        captured = {}

        class _Proc:
            returncode = 0

            def wait(self_inner):
                return 0

        def _popen(cmd, **kwargs):
            captured["cmd"] = cmd
            return _Proc()

        job = runner.PocJob("demolib/20260101-000000", **kw)
        with patch.object(runner.subprocess, "Popen", _popen):
            job.run()
        return captured["cmd"], job

    def test_argv_carries_poc_only_and_models(self):
        cmd, job = self._capture(drafter_model="claude-opus-5",
                                 critic_model="claude-opus-5", compile_rounds=2)
        self.assertIn("--poc-only", cmd)
        self.assertEqual(cmd[cmd.index("--poc-only") + 1], str(self.run_dir))
        self.assertEqual(cmd[cmd.index("--poc-drafter-model") + 1], "claude-opus-5")
        self.assertEqual(cmd[cmd.index("--poc-compile-rounds") + 1], "2")
        self.assertNotIn("--poc-keep-existing", cmd)
        self.assertEqual(job.state, "done")

    def test_keep_existing_flag_is_passed(self):
        cmd, _ = self._capture(drafter_model=None, critic_model=None,
                               compile_rounds=0, overwrite=False)
        self.assertIn("--poc-keep-existing", cmd)

    def test_start_poc_job_rejects_a_run_with_no_report(self):
        (self.run_dir / "report.json").unlink()
        with self.assertRaises(ValueError) as ctx:
            runner.start_poc_job("demolib/20260101-000000")
        self.assertIn("report.json", str(ctx.exception))

    def test_start_poc_job_rejects_traversal(self):
        with self.assertRaises(ValueError):
            runner.start_poc_job("../../etc/passwd")


class GenerateForFinishedRunTests(unittest.TestCase):
    """pipeline.generate_pocs_for_run — the --poc-only / web button path."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.run_dir = self.tmp / "run"
        self.run_dir.mkdir()
        self.target = self.tmp / "src"
        (self.target / "a").mkdir(parents=True)
        (self.target / "a/T.java").write_text(
            "package a;\npublic class T\n{\n    public void go()\n    {\n    }\n}\n",
            encoding="utf-8")
        (self.run_dir / "run.json").write_text(json.dumps({
            "target": str(self.target), "library": "demolib", "lang": "java",
        }), encoding="utf-8")
        (self.run_dir / "report.json").write_text(json.dumps({"findings": [
            {"id": "FND-1", "title": "NPE without null guard", "cwe": "CWE-476",
             "severity": "MEDIUM", "file": "a/T.java", "line": 5,
             "description": "d", "confidence": "confirmed",
             "evidence": ["[proving_line] boom();", "[proposed_fix] guard it"]},
            {"id": "FND-2", "title": "Only suspected", "cwe": "CWE-20",
             "severity": "LOW", "file": "a/T.java", "line": 5,
             "description": "d", "confidence": "suspected", "evidence": []},
        ]}), encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, **kw):
        import pipeline
        with patch.object(pipeline, "_poc_backend", return_value=_MockJava()):
            return pipeline.generate_pocs_for_run(self.run_dir, "m", "m", **kw)

    def test_generates_for_confirmed_only(self):
        res = self._run()
        self.assertTrue(res["ok"])
        self.assertEqual(res["generated"], 1)
        self.assertEqual([p["id"] for p in res["packages"]], ["FND-1"])
        self.assertTrue((self.run_dir / "poc/FND-1/PocServer.java").is_file())
        self.assertTrue((self.run_dir / "poc/FND-1/PocClient.java").is_file())
        self.assertFalse((self.run_dir / "poc/FND-2").exists())

    def test_evidence_tags_are_parsed_out_of_report_json(self):
        from pipeline import _report_finding_to_dict
        d = json.loads((self.run_dir / "report.json").read_text(encoding="utf-8"))
        got = _report_finding_to_dict(d["findings"][0])
        self.assertEqual(got["proving_line"], "boom();")
        self.assertEqual(got["proposed_fix"], "guard it")

    def test_keep_existing_skips_instead_of_overwriting(self):
        self._run()
        marker = self.run_dir / "poc/FND-1/PocServer.java"
        marker.write_text("// edited by hand\n", encoding="utf-8")
        res = self._run(overwrite=False)
        self.assertEqual(res["skipped"], 1)
        self.assertEqual(res["generated"], 0)
        self.assertIn("edited by hand", marker.read_text(encoding="utf-8"))

    def test_missing_source_tree_is_refused_clearly(self):
        shutil.rmtree(self.target)
        res = self._run()
        self.assertFalse(res["ok"])
        self.assertIn("no longer on disk", res["error"])

    def test_missing_report_is_refused(self):
        (self.run_dir / "report.json").unlink()
        res = self._run()
        self.assertFalse(res["ok"])
        self.assertIn("not a completed run", res["error"])


if __name__ == "__main__":
    unittest.main()


class BouncyCastleDownloadTests(unittest.TestCase):
    """BC-only: the README must name the exact release the scan ran against and
    point at somewhere it can actually be downloaded from."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.finding = {
            "id": "FND-bc", "title": "Unbounded cache growth", "cwe": "CWE-770",
            "severity": "MEDIUM", "spec_reference": "", "entry_point": "getCrl",
            "file": "pkix/src/main/java/org/bouncycastle/pkix/jcajce/CrlCache.java",
            "line": 9, "description": "no ceiling on the cache",
        }

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _tree(self, name, version=None):
        d = self.tmp / name
        d.mkdir(parents=True)
        if version:
            (d / "gradle.properties").write_text(
                f"org.gradle.jvmargs=-Xmx2g\nversion={version}\nmaxVersion=1.85\n",
                encoding="utf-8")
        return d

    def _readme(self, library, target, has_artifact=False, has_code=True):
        from poc.generator import _write_readme
        out = self.tmp / f"out-{library}-{has_artifact}-{has_code}"
        out.mkdir(parents=True, exist_ok=True)
        _write_readme(out, self.finding, library, "resource", has_artifact,
                      str(target), has_code, "java")
        return (out / "README.md").read_text(encoding="utf-8")

    def test_version_comes_from_gradle_properties(self):
        from poc.generator import _bc_version
        self.assertEqual(_bc_version(str(self._tree("a", "1.84"))), "1.84")

    def test_version_falls_back_to_tag_named_clone(self):
        from poc.generator import _bc_version
        self.assertEqual(_bc_version(str(self._tree("bc-java-r1rv84-1d1be78a"))), "1.84")

    def test_snapshot_has_no_downloadable_version(self):
        from poc.generator import _bc_version
        self.assertIsNone(_bc_version(str(self._tree("b", "1.87-SNAPSHOT"))))

    def test_artifacts_include_the_module_holding_the_bug(self):
        from poc.generator import _bc_artifacts
        arts, primary = _bc_artifacts(self.finding)
        self.assertEqual(primary, "bcpkix")
        self.assertEqual(arts, ["bcpkix", "bcprov", "bcutil"])
        # bcprov findings must not list bcprov twice.
        arts, primary = _bc_artifacts({"file": "prov/src/main/java/x.java"})
        self.assertEqual(arts, ["bcprov", "bcutil"])

    def test_readme_links_the_scanned_version_on_maven_central(self):
        readme = self._readme("BouncyCastle", self._tree("c", "1.84"))
        self.assertIn("Get the matching library build", readme)
        self.assertIn("## Get the matching library build", readme)
        self.assertIn("BouncyCastle 1.84", readme)
        self.assertIn(
            "https://repo1.maven.org/maven2/org/bouncycastle/bcpkix-jdk18on/1.84/"
            "bcpkix-jdk18on-1.84.jar", readme)
        self.assertIn(".sha1", readme)          # so the tester can verify it
        self.assertNotIn("1.86", readme)        # never the current release

    def test_snapshot_still_defaults_to_an_online_download(self):
        """Building BouncyCastle needs Gradle and several JDKs. A snapshot has no
        matching release, but the default route stays 'download' — the nearest
        release, with the mismatch spelled out."""
        with patch("poc.generator._bc_released_versions",
                   return_value=["1.84", "1.85", "1.85.2", "1.86"]):
            readme = self._readme("BouncyCastle", self._tree("d", "1.87-SNAPSHOT"))
        self.assertIn("Download **BouncyCastle 1.86**", readme)
        self.assertIn("newest release before that snapshot", readme)
        self.assertIn("bcpkix-jdk18on-1.86.jar", readme)
        self.assertIn("Caveat", readme)              # line numbers will not match
        self.assertNotIn("1.87-SNAPSHOT.jar", readme)

    def test_nearest_release_is_resolved_from_maven_central(self):
        from poc.generator import _bc_download_version
        with patch("poc.generator._bc_released_versions",
                   return_value=["1.84", "1.85", "1.85.2", "1.86"]):
            self.assertEqual(
                _bc_download_version(str(self._tree("n1", "1.87-SNAPSHOT"))),
                ("1.86", "nearest"))
            self.assertEqual(
                _bc_download_version(str(self._tree("n2", "1.84"))), ("1.84", "exact"))

    def test_nearest_release_falls_back_when_maven_is_unreachable(self):
        """Offline, a 1.87-SNAPSHOT tree is still development after 1.86 — the
        README must not lose its download just because the network was down."""
        from poc.generator import _bc_download_version
        with patch("poc.generator._bc_released_versions", return_value=[]):
            self.assertEqual(
                _bc_download_version(str(self._tree("n3", "1.87-SNAPSHOT"))),
                ("1.86", "nearest"))

    def test_section_is_bouncycastle_only(self):
        from poc.generator import _write_readme
        out = self.tmp / "wolf"
        out.mkdir()
        _write_readme(out, {**self.finding, "file": "src/tls.c"}, "wolfSSL",
                      "memory", False, str(self._tree("wolfssl-src")), True, "c")
        self.assertNotIn("Get the matching library build",
                         (out / "README.md").read_text(encoding="utf-8"))

    def test_local_jars_win_over_the_download(self):
        readme = self._readme("BouncyCastle", self._tree("e", "1.84"), has_artifact=True)
        self.assertIn("already point at jars found in the scanned tree", readme)
        # The generic "build the library first" note would contradict it.
        self.assertNotIn("no jars were found under", readme)

    def test_build_scripts_default_to_the_download_dir_for_bouncycastle(self):
        from poc.generator import _write_java_build_scripts
        out = self.tmp / "bs"
        out.mkdir()
        _write_java_build_scripts(out, [], fallback_cp="lib/*")
        sh = (out / "build.sh").read_text(encoding="utf-8")
        bat = (out / "build.bat").read_text(encoding="utf-8")
        self.assertIn('CP="lib/*"', sh)
        self.assertIn("README.md", sh)
        self.assertIn(r"set CP=lib\*", bat)

    def test_build_scripts_keep_the_generic_placeholder_otherwise(self):
        from poc.generator import _write_java_build_scripts
        out = self.tmp / "bs2"
        out.mkdir()
        _write_java_build_scripts(out, [])
        sh = (out / "build.sh").read_text(encoding="utf-8")
        self.assertIn("/path/to/library.jar", sh)
        self.assertNotIn("lib/*", sh)


class JavaClientServerTests(unittest.TestCase):
    """Java PoCs are a client/server pair over the fixed PocNet transport, the
    same shape as the C ones — the point is to show the bug is reachable over
    the network, not just from the API."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_build_scripts_compile_all_three_and_name_both_runs(self):
        from poc.generator import _write_java_build_scripts
        _write_java_build_scripts(self.tmp, [], fallback_cp="lib/*")
        sh = (self.tmp / "build.sh").read_text(encoding="utf-8")
        self.assertIn("javac -cp \"$CP\" PocNet.java PocServer.java PocClient.java", sh)
        self.assertIn("PocServer 21000", sh)
        self.assertIn("PocClient 21000", sh)
        # Compiling is not running: the pair needs two terminals, so build.sh
        # must not try to launch either side itself.
        self.assertNotIn("\njava -cp", sh)

    def test_build_scripts_only_list_the_files_that_exist(self):
        from poc.generator import _write_java_build_scripts
        _write_java_build_scripts(self.tmp, [], sources=("PocNet.java",
                                                         "PocServer.java"))
        sh = (self.tmp / "build.sh").read_text(encoding="utf-8")
        self.assertIn("PocNet.java PocServer.java", sh)
        self.assertNotIn("PocClient.java", sh.split("echo")[0])

    def test_transport_is_not_counted_as_a_drafted_source(self):
        """PocNet.java is copied verbatim, so a package with only it and a server
        is half-drafted, not complete — same rule as poc_net.h."""
        self.assertEqual(
            pocs._infer_status(["README.md", "PocNet.java", "PocServer.java"]),
            "partial")
        self.assertEqual(
            pocs._infer_status(["README.md", "PocNet.java", "PocServer.java",
                                "PocClient.java"]),
            "generated")
        self.assertEqual(pocs._infer_status(["README.md", "PocNet.java"]), "doc_only")

    def test_only_one_side_drafted_is_partial(self):
        from poc.generator import generate_poc_package

        class _ServerOnly:
            model = "mock"

            def complete(self, system, user, **kw):
                if "PocServer.java" not in user:
                    return "sorry, no code"
                return "```java\npublic class X { public static void main(String[] a) {} }\n```"

        res = generate_poc_package(
            {"id": "F1", "title": "t", "cwe": "CWE-476", "severity": "LOW",
             "file": "a/T.java", "line": 1, "description": "d"},
            "java", _ServerOnly(), _ServerOnly(), str(self.tmp / "out"),
            str(self.tmp), "bouncycastle")
        self.assertEqual(res["status"], "partial")
        d = Path(res["poc_dir"])
        self.assertTrue((d / "PocServer.java").is_file())
        self.assertFalse((d / "PocClient.java").is_file())
        self.assertTrue((d / "PocNet.java").is_file())   # transport always ships

    def test_readme_describes_the_pair_and_where_evidence_appears(self):
        from poc.generator import _write_readme
        out = self.tmp / "rd"
        out.mkdir()
        _write_readme(out, {"id": "F", "title": "t", "cwe": "", "severity": "LOW",
                            "file": "a/T.java", "line": 1, "entry_point": "go",
                            "description": "d"},
                      "demolib", "crash", False, str(self.tmp), True, "java")
        readme = (out / "README.md").read_text(encoding="utf-8")
        self.assertIn("PocServer.java", readme)
        self.assertIn("PocClient.java", readme)
        self.assertIn("do not edit", readme)                 # the transport
        self.assertIn("client/server demonstration", readme)
        self.assertIn("server's** terminal", readme)

    def test_truncated_draft_is_discarded_not_shipped(self):
        """A file cut off mid-string cannot compile. _extract_java survives
        truncation on purpose, so the completeness gate is what stops a package
        claiming 'generated' for something javac rejects on line 9."""
        from poc.generator import _java_looks_complete
        cut = ('import java.net.Socket;\n'
               'public class PocClient {\n'
               '    public static void main(String[] a) throws Exception {\n'
               '        System.out.println("[poc] ATTACKER starting')
        self.assertFalse(_java_looks_complete(cut))
        self.assertFalse(_java_looks_complete("public class A { void f() {"))
        self.assertFalse(_java_looks_complete(""))
        # Braces inside a literal or a comment must not be miscounted.
        self.assertTrue(_java_looks_complete(
            'public class A { void f() { String s = "}{"; /* } */ char c = 0; } }'))
        self.assertTrue(_java_looks_complete(
            'public class A { void f() { String s = "a\\"}"; } }'))

    def test_truncated_draft_does_not_count_as_generated(self):
        from poc.generator import generate_poc_package

        class _Truncating:
            model = "mock"

            def complete(self, system, user, **kw):
                if "PocServer.java" in user:
                    return ("```java\npublic class X { "
                            "public static void main(String[] a) {} }\n```")
                return '```java\npublic class Y { void f() { String s = "oops'

        res = generate_poc_package(
            {"id": "F2", "title": "t", "cwe": "", "severity": "LOW",
             "file": "a/T.java", "line": 1, "description": "d"},
            "java", _Truncating(), _Truncating(), str(self.tmp / "o2"),
            str(self.tmp), "bouncycastle")
        self.assertEqual(res["status"], "partial")
        self.assertFalse((Path(res["poc_dir"]) / "PocClient.java").exists())

    def test_import_of_the_transport_is_stripped(self):
        """PocNet is in the default package, so `import PocNet;` is a hard
        compile error — seen in a real draft."""
        from poc.generator import _normalise_java
        src = ("import java.util.Date;\n"
               "import PocNet;\n"
               "public class PocServer { public static void main(String[] a) {} }\n")
        out = _normalise_java(src, "PocServer")
        self.assertNotIn("import PocNet", out)
        self.assertIn("import java.util.Date;", out)   # real imports survive


class JavaCompileLoopTests(unittest.TestCase):
    """javac-backed compile-and-fix for Java, the counterpart of the C loop."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.src = "public class PocServer { void go() { getCrl(); } }"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    @staticmethod
    def _always_fails(out, names, cp):
        return False, "PocServer.java:1: error: cannot find symbol"

    def _run(self, backend, rounds=3, cp="cp", finding=None, compile_fn=None):
        from poc.generator import _compile_and_fix_java
        return _compile_and_fix_java(
            self.tmp, {"PocServer.java": self.src}, (), cp, finding or {}, "",
            backend, backend, rounds, compile_fn=compile_fn or self._always_fails)

    def test_rounds_are_compiles_not_repairs(self):
        """N rounds = N compiles, N-1 repairs — the same arithmetic as the C
        loop, so '1 round' is a check with no repair."""
        counts = {"compile": 0, "fix": 0}

        def counting(out, names, cp):
            counts["compile"] += 1
            return False, "PocServer.java:1: error: boom"

        class B:
            model = "mock"

            def complete(self, system, user, **kw):
                counts["fix"] += 1
                return "```java\npublic class PocServer { void go() { getCrl(); } }\n```"

        for n, fixes in ((1, 0), (2, 1), (3, 2)):
            counts.update(compile=0, fix=0)
            self._run(B(), rounds=n, compile_fn=counting)
            self.assertEqual((counts["compile"], counts["fix"]), (n, fixes))

    def test_missing_classpath_is_skipped_not_failed(self):
        """No jars means the check could not run. Reporting False would brand a
        fine PoC as broken."""
        rep = self._run(None, cp="")
        self.assertIsNone(rep["compiled"])
        self.assertIn("POC_JAVA_CP", rep["reason"])

    def test_missing_javac_is_skipped_not_failed(self):
        from poc.generator import _NO_CC
        rep = self._run(None, compile_fn=lambda o, n, c: (False, _NO_CC))
        self.assertIsNone(rep["compiled"])
        self.assertIn("javac", rep["reason"])

    def test_repair_that_removes_the_entry_point_is_rejected(self):
        """The loop's success signal is 'javac is happy', which a model can
        satisfy by deleting the vulnerable call. That must not be accepted."""
        class Gutter:
            model = "gutter"

            def complete(self, system, user, **kw):
                return "```java\npublic class PocServer { void go() { } }\n```"

        rep = self._run(Gutter(), finding={"entry_point": "getCrl"})
        self.assertIn("getCrl", rep["sources"]["PocServer.java"])

    def test_truncated_repair_is_ignored(self):
        class Trunc:
            model = "trunc"

            def complete(self, system, user, **kw):
                return '```java\npublic class PocServer { void go() { String s = "x'

        rep = self._run(Trunc())
        self.assertEqual(rep["sources"]["PocServer.java"], self.src)

    def test_errors_are_attributed_to_the_right_file(self):
        """javac prints absolute paths and puts 'symbol:'/'location:' on follow-on
        lines, so a naive split would repair the wrong file."""
        from poc.generator import _java_errors_by_file
        errs = (r"C:\x\PocServer.java:54: error: cannot find symbol" "\n"
                "                .getConverter().getCertificate(h);\n"
                "  symbol:   method getConverter()\n"
                r"C:\x\PocClient.java:9: error: unclosed string literal" "\n")
        got = _java_errors_by_file(errs, ["PocNet.java", "PocServer.java",
                                          "PocClient.java"])
        self.assertEqual(sorted(got), ["PocClient.java", "PocServer.java"])
        self.assertIn("symbol:   method getConverter()", got["PocServer.java"])
        self.assertNotIn("getConverter", got["PocClient.java"])
        self.assertNotIn("PocNet.java", got)

    def test_classpath_prefers_the_env_override_and_expands_a_directory(self):
        from poc.generator import _java_compile_cp
        jars = str(self.tmp / "build/libs/bcprov.jar")
        # A directory becomes a wildcard, so pointing it at a folder just works.
        with patch.dict("os.environ", {"POC_JAVA_CP": str(self.tmp)}):
            self.assertTrue(_java_compile_cp("t", []).endswith("/*"))
            self.assertTrue(_java_compile_cp("t", [jars]).endswith("/*"))
        # Otherwise: build output from the scanned tree, else nothing to do.
        with patch.dict("os.environ", {}, clear=True):
            self.assertEqual(_java_compile_cp("t", [jars]), jars)
            self.assertEqual(_java_compile_cp("t", []), "")
