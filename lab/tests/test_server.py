import gzip
import io
import json
import os
import shlex
import stat
import struct
import tempfile
import time
import unittest
import zipfile
import zlib
from pathlib import Path
from unittest.mock import patch

from blackwall_lab import server


class ServerHelperTests(unittest.TestCase):
    def test_strict_profile_excludes_arbitrary_process_tools(self):
        self.assertEqual(server.DEFAULT_PROFILE, "strict")
        strict = server.mcp
        manifest = server.profile_manifest("strict", strict)
        tools = set(manifest["tools"])

        self.assertTrue(server.EXPERT_ONLY_TOOLS.isdisjoint(tools))
        self.assertNotIn("run_python", tools)
        self.assertNotIn("shell", tools)
        self.assertEqual(server.STRICT_TOOL_ALLOWLIST, tools)
        self.assertEqual(manifest["runtime_rea_commands_exposed"], [])

    def test_expert_profile_requires_explicit_process_tools(self):
        manifest = server.profile_manifest("expert", server.build_mcp("expert"))
        self.assertTrue(server.EXPERT_ONLY_TOOLS <= set(manifest["tools"]))
        with self.assertRaisesRegex(ValueError, "unknown analysis profile"):
            server.build_mcp("permissive")

    def test_strict_profile_audit_fails_closed_on_registry_drift(self):
        strict = server.build_mcp("strict")
        strict.add_tool(server.shell)
        with self.assertRaisesRegex(RuntimeError, "profile registry mismatch"):
            server.profile_manifest("strict", strict)

    def test_run_success(self):
        with tempfile.TemporaryDirectory() as td:
            result = server._run(["sh", "-c", "printf ok"], timeout=2, cwd=Path(td))
        self.assertEqual(result["rc"], 0)
        self.assertEqual(result["stdout"], "ok")
        self.assertFalse(result["timed_out"])

    def test_run_timeout_kills_child_process_group(self):
        with tempfile.TemporaryDirectory() as td:
            marker = Path(td) / "orphaned"
            command = f"(sleep 0.4; printf orphan > {shlex.quote(str(marker))}) & wait"
            result = server._run(command, timeout=0.1, cwd=Path(td), shell=True)
            time.sleep(0.6)
            self.assertTrue(result["timed_out"])
            self.assertIsNone(result["rc"])
            self.assertFalse(marker.exists(), "a timed-out child survived its process group")

    def test_ilspy_decompile_uses_token_argv_and_retains_full_source(self):
        completed = {
            "rc": 0, "stdout": "private static string Secret() => \"password=hunter2\";",
            "stderr": "", "seconds": 0.1, "timed_out": False,
            "cancelled": False, "crashed": False, "termination_signal": None,
            "output_limited": False,
        }
        with tempfile.TemporaryDirectory() as td:
            work = Path(td) / "work"
            samples = work / "samples"
            out = work / "out"
            sample = samples / "original" / "sample"
            sample.parent.mkdir(parents=True)
            sample.write_bytes(b"managed fixture")
            with (
                patch.object(server, "WORK", work),
                patch.object(server, "SAMPLES", samples),
                patch.object(server, "OUT", out),
                patch.object(server, "ILSPY_BIN", "ilspy-test"),
                patch.object(server, "_run", return_value=completed) as run,
            ):
                result = server.dotnet_decompile(
                    "original/sample", method="0x06000001", timeout=61,
                )

            run.assert_called_once_with(
                ["ilspy-test", str(sample), "--member", "0x06000001"],
                timeout=61,
                max_output_bytes=8 * 1024 * 1024,
            )
            self.assertNotIn("hunter2", result["source_preview"])
            self.assertIn("hunter2", Path(result["saved_to"]).read_text())
            self.assertEqual(result["tool_version"], server.ILSPY_VERSION)

        with self.assertRaisesRegex(ValueError, "MethodDef token"):
            server.dotnet_decompile("anything", method="--project")
        with self.assertRaisesRegex(ValueError, "type_name"):
            server.dotnet_decompile("anything", type_name="--help")

    def test_dotnet_inventory_maps_method_tokens_to_types_and_pages(self):
        documents = {
            "Assembly": {"rowCount": 1, "rows": [{"Name": "Fixture"}]},
            "Module": {"rowCount": 1, "rows": [{"Name": "Fixture.dll"}]},
            "AssemblyRef": {"rowCount": 0, "rows": []},
            "TypeDef": {"rowCount": 2, "rows": [
                {"RID": 1, "Token": "0x02000001", "Name": "<Module>",
                 "Namespace": "", "MethodList": "1"},
                {"RID": 2, "Token": "0x02000002", "Name": "Program",
                 "Namespace": "Fixture", "MethodList": "1"},
            ]},
            "MethodDef": {"rowCount": 2, "rows": [
                {"RID": 1, "Token": "0x06000001", "Name": "Alpha", "RVA": "0x2050"},
                {"RID": 2, "Token": "0x06000002", "Name": "Beta", "RVA": "0x2060"},
            ]},
        }

        def table(_target, name, _timeout):
            return documents[name], None

        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "out"
            with (
                patch.object(server, "OUT", out),
                patch.object(server, "_dotnet_target", return_value=Path("/work/sample")),
                patch.object(server, "_dotnet_characteristics", return_value={"mixed_mode": False}),
                patch.object(server, "_ilspy_table", side_effect=table),
            ):
                result = server.dotnet_inventory("sample", query="beta", limit=10)

            self.assertTrue(Path(result["saved_to"]).is_file())

        self.assertEqual(result["methods"]["matched"], 1)
        self.assertEqual(result["methods"]["items"][0]["Token"], "0x06000002")
        self.assertEqual(result["methods"]["items"][0]["DeclaringType"], "Fixture.Program")

    def test_document_vba_uses_pinned_static_cli_and_retains_full_json(self):
        completed = {
            "rc": 0,
            "stdout": json.dumps([
                {"type": "MetaInformation", "version": server.OLETOOLS_VERSION},
                {
                    "type": "OpenXML",
                    "analysis": [{"type": "Suspicious", "keyword": "AutoOpen"}],
                    "code_deobfuscated": "password=hunter2",
                    "macros": [{"vba_filename": "Module1.bas", "code": "Sub AutoOpen()"}],
                },
            ]),
            "stderr": "", "seconds": 0.1, "timed_out": False,
            "cancelled": False, "crashed": False,
            "termination_signal": None, "output_limited": False,
            "status": "ok",
        }
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "sample"
            target.write_bytes(b"PK\x03\x04fixture")
            out = Path(temporary) / "out"
            with (
                patch.object(server, "OUT", out),
                patch.object(
                    server, "_document_target",
                    return_value=(target, {"format": "ooxml-word"}),
                ),
                patch.object(server, "OLEVBA_BIN", "olevba-test"),
                patch.object(server, "_run", return_value=completed) as run,
            ):
                result = server.document_vba("sample", timeout=91)

            run.assert_called_once_with(
                [
                    server.sys.executable, "-m", "blackwall_lab.documents",
                    "vba-analyze", str(target), "--olevba-bin", "olevba-test",
                ],
                timeout=91,
                max_output_bytes=server.MAX_DOCUMENT_OUTPUT,
            )
            retained = Path(result["saved_to"]).read_text()
        self.assertEqual(result["macro_count"], 1)
        self.assertEqual(result["tool_version"], server.OLETOOLS_VERSION)
        self.assertNotIn("hunter2", str(result))
        self.assertIn("hunter2", retained)

    def test_document_extraction_registers_only_verified_generated_artifacts(self):
        completed = {
            "rc": 0, "stdout": "", "stderr": "", "seconds": 0.1,
            "timed_out": False, "cancelled": False, "crashed": False,
            "termination_signal": None, "output_limited": False, "status": "ok",
        }
        payload = b"BLACKWALL_INERT_DOCUMENT_CHILD"
        digest = server.hashlib.sha256(payload).hexdigest()

        def worker(command, _timeout):
            output_dir = Path(command[2])
            output_dir.joinpath("artifact-0000.bin").write_bytes(payload)
            return ({
                "schema": "blackwall.document-extraction.v1",
                "artifacts": [{
                    "file": "artifact-0000.bin", "size": len(payload),
                    "sha256": digest, "kind": "ooxml-active-part",
                    "source": "word/embeddings/child.bin",
                }],
            }, completed)

        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "sample"
            target.write_bytes(b"PK\x03\x04fixture")
            out = Path(temporary) / "out"
            registration = {
                "path": f"/work/samples/derived/{digest}",
                "sha256": digest,
                "relationship": "document-embedded-artifact",
            }
            with (
                patch.object(server, "OUT", out),
                patch.object(
                    server, "_document_target",
                    return_value=(target, {"format": "ooxml-word"}),
                ),
                patch.object(server, "_worker_json", side_effect=worker),
                patch.object(server, "_register_derived", return_value=registration) as register,
                patch.object(server, "_run", return_value={"stdout": "ASCII text"}),
            ):
                result = server.document_extract_artifacts("sample")

        self.assertEqual(result["count"], 1)
        self.assertEqual(result["artifacts"][0]["sha256"], digest)
        self.assertEqual(
            register.call_args.kwargs["relationship"],
            "document-embedded-artifact",
        )
        self.assertEqual(
            register.call_args.kwargs["producer_tool"],
            "lab.document_extract_artifacts",
        )

    def test_recursive_unpack_routes_children_and_preserves_lineage(self):
        payload = json.dumps({
            "endpoint": "https://recursive.fixture.invalid/api",
            "campaign": "recursive-inert",
        }, sort_keys=True, separators=(",", ":")).encode()
        config = (
            b"BWCFG1\0" + struct.pack("<I", len(payload)) + payload
            + struct.pack("<I", zlib.crc32(payload) & 0xFFFFFFFF)
        )
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("layers/config.gz", gzip.compress(config, mtime=0))

        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary) / "work"
            samples = work / "samples"
            original = samples / "original"
            derived = samples / "derived"
            out = work / "out"
            original.mkdir(parents=True)
            digest = server.hashlib.sha256(stream.getvalue()).hexdigest()
            target = original / digest
            target.write_bytes(stream.getvalue())
            target.chmod(0o444)
            (original / ".meta.json").write_text(json.dumps({
                "sha256": digest, "original_name": "nested.zip",
            }))
            with (
                patch.object(server, "WORK", work),
                patch.object(server, "SAMPLES", samples),
                patch.object(server, "DERIVED", derived),
                patch.object(server, "OUT", out),
                patch.dict(os.environ, {
                    "PYTHONPATH": str(Path(__file__).resolve().parents[1]),
                }),
            ):
                result = server.recursive_unpack(
                    f"original/{digest}", max_depth=3, max_artifacts=8,
                    max_artifact_bytes=1024 * 1024,
                    max_expanded_bytes=4 * 1024 * 1024,
                    max_elapsed_seconds=30,
                )

        self.assertEqual(result["counts"]["artifacts"], 2)
        self.assertEqual(result["counts"]["configuration_matches"], 1)
        self.assertEqual(result["stop_reason"], "complete")
        self.assertTrue(all(row["route"]["plan_id"] for row in result["artifacts"]))
        self.assertEqual(
            {row["lineage"]["lineage_depth"] for row in result["artifacts"]},
            {1, 2},
        )

    def test_auto_script_language_uses_router_evidence_not_content_addressed_name(self):
        self.assertEqual(
            server._worker_script_language("auto", {"format": "powershell"}),
            "powershell",
        )
        self.assertEqual(
            server._worker_script_language("javascript", {"format": "powershell"}),
            "javascript",
        )

    def test_dotnet_call_references_and_literal_search_are_method_bounded(self):
        index = {
            "method_rows": [
                {"Token": "0x06000001", "Name": "Caller", "DeclaringType": "Fixture.Program"},
                {"Token": "0x06000002", "Name": "Target", "DeclaringType": "Fixture.Program"},
            ],
            "method_count": 2,
            "indexed_count": 2,
            "index_truncated": False,
            "saved_to": "/work/out/ilspy.json",
            "methods": [
                {
                    "token": "0x06000001", "declaring_type": "Fixture.Program",
                    "name": "Caller", "rva": "0x2050",
                    "body": 'IL_0000: ldstr "needle"\nIL_0005: call void Fixture.Program::Target()',
                    "calls": [{"offset": "IL_0005", "opcode": "call", "target": "void Fixture.Program::Target()"}],
                },
                {
                    "token": "0x06000002", "declaring_type": "Fixture.Program",
                    "name": "Target", "rva": "0x2070", "body": "IL_0000: ret",
                    "calls": [],
                },
            ],
        }
        with tempfile.TemporaryDirectory() as td:
            with (
                patch.object(server, "OUT", Path(td)),
                patch.object(server, "_dotnet_target", return_value=Path("/work/sample")),
                patch.object(server, "_dotnet_il_index", return_value=(index, None)),
            ):
                references = server.dotnet_call_references(
                    "sample", "0x06000002", direction="both",
                )
                search = server.dotnet_search("sample", "needle")

            self.assertTrue(Path(references["saved_to"]).is_file())
            self.assertTrue(Path(search["saved_to"]).is_file())

        self.assertEqual(references["incoming_total"], 1)
        self.assertEqual(references["incoming"][0]["from_token"], "0x06000001")
        self.assertEqual(search["matched_methods"], 1)
        self.assertEqual(search["matches"][0]["token"], "0x06000001")

    def test_il_method_parser_prefers_rva_and_owner_over_ambiguous_names(self):
        rows = [
            {"Token": "0x06000001", "Name": "Run", "RVA": "0x2050",
             "DeclaringType": "First.Program"},
            {"Token": "0x06000002", "Name": "Run", "RVA": "0x2070",
             "DeclaringType": "Second.Program"},
        ]
        il = """
.method private static void Run () cil managed
{
  // Method begins at RVA 0x2070
  IL_0000: ret
} // end of method Program::Run
.method private static void Run () cil managed
{
  // Method begins at RVA 0x2050
  IL_0000: ret
} // end of method Program::Run
"""
        parsed = server._parse_il_methods(il, rows, 10)
        self.assertEqual(
            [method["token"] for method in parsed],
            ["0x06000002", "0x06000001"],
        )

    def test_secret_redaction(self):
        text = "= password hunter2\nAuthorization eyJaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbb.cccccccccc"
        redacted, count = server._redact_text(text)
        self.assertGreaterEqual(count, 2)
        self.assertNotIn("hunter2", redacted)
        self.assertNotIn("eyJaaaaaaaa", redacted)

    def test_wallet_validation(self):
        self.assertTrue(server._valid_btc_wallet("1BoatSLRHtKNngkdXEeobR76b53LETtpyT"))
        self.assertFalse(server._valid_btc_wallet("1Uf3GuU06TO7aztKvWGYKmmb4Td0SY5h"))

    def test_ioc_filtering_and_confidence(self):
        text = " ".join((
            "1.4.1.0", "1.1.1.1", "1.2.840.113", "4.1.188.7", "193.161.193.99:51272",
            "yoenacevedo7-51272.portmap.host", "System.IO", "Org.BouncyCastle.Crypto.IO",
            "1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
        ))
        result = server._extract_iocs_from_text(text)
        self.assertEqual(result["ipv4"], ["193.161.193.99:51272"])
        self.assertNotIn("1.4.1.0", result.get("ipv4_candidates", []))
        self.assertIn("1.1.1.1", result["ipv4_candidates"])
        self.assertIn("4.1.188.7", result["ipv4_candidates"])
        self.assertIn("yoenacevedo7-51272.portmap.host", result["domain"])
        self.assertNotIn("system.io", result["domain"])
        self.assertEqual(result["btc_wallet"], ["1BoatSLRHtKNngkdXEeobR76b53LETtpyT"])

    def test_benign_url_domain_and_dotnet_namespace_stay_filtered(self):
        result = server._extract_iocs_from_text(
            "https://schemas.microsoft.com/example MyApplication.app "
            "https://stackoverflow.com/q/1 Org.BouncyCastle.Utilities.IO "
            "https://microsoft.com.evil.com/payload https://ipwho.is/"
        )
        self.assertEqual(result["url"], [
            "https://ipwho.is/", "https://microsoft.com.evil.com/payload",
        ])
        self.assertEqual(result["domain"], ["ipwho.is", "microsoft.com.evil.com"])

    def test_rea_allowlist_excludes_runtime_capabilities(self):
        commands = set(server.REA_REQUIRED_COMMANDS)
        forbidden = set(server.REA_RUNTIME_COMMANDS)
        self.assertTrue(commands.isdisjoint(forbidden))
        self.assertEqual(server.REA_STATIC_WORKFLOWS["go"], "inspect-go-binary")
        self.assertIn("function", server.REA_NATIVE_COMMANDS)
        self.assertIn("trace-native-values", server.REA_NATIVE_COMMANDS)
        self.assertNotIn("inspect-desktop-application", commands)
        self.assertNotIn("inspect-il2cpp-metadata", commands)
        self.assertIn("inspect-binary-layout", commands)
        self.assertIn("inspect-recorded-crash", commands)
        self.assertEqual(server.REA_UNADVERTISED_OPTIONAL_COMMANDS, {
            "inspect-desktop-application", "inspect-il2cpp-metadata",
        })

    def test_rea_pwntools_wrappers_use_only_static_exact_commands(self):
        target = Path("/work/samples/original/input")
        with (
            patch.object(server, "_sample", return_value=target),
            patch.object(server, "_original_name_for", return_value=None),
            patch.object(server, "detect_format", return_value={"format": "elf"}),
            patch.object(server, "_rea_run", return_value={"ok": True}) as run,
        ):
            server.rea_elf_layout("original/input", timeout=77)
            run.assert_called_once_with(
                target, "elf_layout", ["inspect-binary-layout", str(target)], 77,
            )
        with (
            patch.object(server, "_sample", return_value=target),
            patch.object(server, "_original_name_for", return_value=None),
            patch.object(server, "detect_format", return_value={"format": "elf-core"}),
            patch.object(server, "_rea_run", return_value={"ok": True}) as run,
        ):
            server.rea_recorded_crash("original/input", timeout=78)
            run.assert_called_once_with(
                target, "recorded_crash", ["inspect-recorded-crash", str(target)], 78,
            )

    def test_rea_static_analysis_uses_argument_vector_and_saves_full_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            work = Path(td) / "work"
            samples = work / "samples"
            out = work / "out"
            sample = samples / "original" / "sample"
            sample.parent.mkdir(parents=True)
            sample.write_bytes(b"fixture")
            evidence = {"kind": "go", "password": "password=hunter2"}
            completed = {
                "rc": 0, "stdout": json.dumps(evidence),
                "stderr": "progress", "seconds": 0.2, "timed_out": False,
            }
            with (
                patch.object(server, "WORK", work),
                patch.object(server, "SAMPLES", samples),
                patch.object(server, "OUT", out),
                patch.object(server, "REA_BIN", "rea-test"),
                patch.object(server, "_run", return_value=completed) as run,
            ):
                result = server.rea_static_analysis("original/sample", "go", timeout=42)

            run.assert_called_once_with(
                ["rea-test", "inspect-go-binary", str(sample), "--format", "json"],
                timeout=42,
            )
            self.assertEqual(result["rc"], 0)
            self.assertNotIn("hunter2", str(result["evidence"]))
            self.assertGreater(result["redactions"], 0)
            saved = Path(result["saved_to"])
            self.assertTrue(saved.is_file())
            self.assertIn("hunter2", saved.read_text())

    def test_rea_evidence_identity_includes_focused_arguments(self):
        path = Path("/work/samples/derived/sample")
        completed = {
            "rc": 0, "stdout": json.dumps({"ok": True}), "stderr": "",
            "seconds": 0.1, "timed_out": False,
        }
        with tempfile.TemporaryDirectory() as td:
            with (
                patch.object(server, "OUT", Path(td)),
                patch.object(server, "_run", return_value=completed),
            ):
                one = server._rea_run(
                    path, "native_function", ["function", str(path), "0x1000"], 30,
                )
                two = server._rea_run(
                    path, "native_function", ["function", str(path), "0x2000"], 30,
                )
        self.assertNotEqual(one["saved_to"], two["saved_to"])

    def test_rea_structured_unsupported_result_normalizes_as_unsupported(self):
        target = Path("/work/samples/original/sample")
        completed = {
            "rc": 1,
            "stdout": json.dumps({
                "code": "unsupported_target",
                "error": "Static provider rejected this input",
                "message": "Unsupported target format",
            }),
            "stderr": "",
            "seconds": 0.1,
            "timed_out": False,
        }
        with tempfile.TemporaryDirectory() as td:
            with (
                patch.object(server, "OUT", Path(td)),
                patch.object(server, "_run", return_value=completed),
            ):
                result = server._rea_run(
                    target, "artifact", ["inspect-artifact", str(target)], 30,
                )

        normalized = server.normalize_analysis_result(
            "triage.rea", "lab.rea_static_analysis", result,
        )
        self.assertIn("Unsupported", result["unsupported_format"])
        self.assertEqual(normalized["status"], "unsupported")

    def test_rea_rejects_unknown_workflows_and_option_like_selectors(self):
        with self.assertRaisesRegex(ValueError, "unknown REA static workflow"):
            server.rea_static_analysis("anything", "launch_process")
        with self.assertRaisesRegex(ValueError, "invalid query"):
            server._rea_selector("--runtime-option", "query")

    def test_rea_required_formats_are_explicit_positional_arguments(self):
        target = Path("/work/samples/original/input")
        with (
            patch.object(server, "_rea_target", return_value=target),
            patch.object(server, "_rea_run", return_value={"ok": True}) as run,
        ):
            server.rea_evm_interface("original/input", "hex", timeout=55)
            run.assert_called_once_with(
                target, "evm", ["inspect-evm-interface", str(target), "hex"], 55,
            )
            run.reset_mock()
            server.rea_web_capture("original/input", "har", timeout=66)
            run.assert_called_once_with(
                target, "web_capture",
                ["inspect-web-network-capture", str(target), "har"], 66,
            )
        with self.assertRaisesRegex(ValueError, "encoding"):
            server.rea_evm_interface("anything", "auto")
        with self.assertRaisesRegex(ValueError, "capture_format"):
            server.rea_web_capture("anything", "auto")

    def test_rea_android_uses_content_addressed_read_only_apk_snapshot(self):
        with tempfile.TemporaryDirectory() as td:
            work = Path(td) / "work"
            samples = work / "samples"
            source = samples / "original" / ("a" * 64)
            source.parent.mkdir(parents=True)
            source.write_bytes(b"PK\x03\x04apk fixture")
            with (
                patch.object(server, "WORK", work),
                patch.object(server, "SAMPLES", samples),
                patch.object(server, "_rea_run", return_value={"ok": True}) as run,
            ):
                server.rea_static_analysis(f"original/{source.name}", "android")

            source_arg, workflow, arguments, timeout = run.call_args.args
            snapshot = Path(arguments[1])
            self.assertEqual(source_arg, source)
            self.assertEqual(workflow, "android")
            self.assertEqual(arguments[0], "inspect-android-package")
            self.assertEqual(snapshot.suffix, ".apk")
            self.assertEqual(snapshot.read_bytes(), source.read_bytes())
            self.assertFalse(snapshot.is_symlink())
            self.assertFalse(snapshot.stat().st_mode & stat.S_IWUSR)
            self.assertEqual(timeout, 600)

    def test_rea_objdump_uses_a_fixed_operation_allowlist(self):
        target = Path("/work/samples/original/input")
        with (
            patch.object(server, "_rea_target", return_value=target),
            patch.object(server, "_rea_run", return_value={"ok": True}) as run,
        ):
            server.rea_objdump("original/input", "section_headers", timeout=77)
            run.assert_called_once_with(
                target, "objdump_section_headers",
                ["inspect-with-objdump", str(target), "section_headers"], 77,
            )
        with self.assertRaisesRegex(ValueError, "operation"):
            server.rea_objdump("anything", "--disassemble")

    def test_rea_native_tools_force_ghidra_and_bound_value_flow(self):
        target = Path("/work/samples/derived/input")
        with (
            patch.object(server, "_sample", return_value=target),
            patch.object(server, "_rea_run", return_value={"ok": True}) as run,
        ):
            server.rea_native_overview("derived/input", timeout=71)
            run.assert_called_once_with(
                target, "native_overview",
                ["analyze", str(target), "--provider", "ghidra"], 71,
            )
            run.reset_mock()
            server.rea_native_function("derived/input", "0x401000", timeout=72)
            run.assert_called_once_with(
                target, "native_function",
                ["function", str(target), "0x401000", "--provider", "ghidra"], 72,
            )
            run.reset_mock()
            server.rea_native_search(
                "derived/input", "OneDrive", kind="strings", mode="literal",
                case_sensitive=True, timeout=73,
            )
            run.assert_called_once_with(
                target, "native_search_strings",
                ["search", str(target), "OneDrive", "--kind", "strings",
                 "--mode", "literal", "--provider", "ghidra", "--case-sensitive"],
                73,
            )
            run.reset_mock()
            server.rea_native_value_flow(
                "derived/input", "0x401000", max_depth=3, max_functions=8,
                max_call_sites=64, max_nodes=1000, max_edges=2000, timeout=74,
            )
            run.assert_called_once_with(
                target, "native_value_flow",
                ["trace-native-values", str(target), "0x401000",
                 "--max-depth", "3", "--max-functions", "8",
                 "--max-call-sites", "64", "--max-nodes", "1000",
                 "--max-edges", "2000", "--limit", "1000",
                 "--provider", "ghidra"],
                74,
            )

        with self.assertRaisesRegex(ValueError, "kind"):
            server.rea_native_search("anything", "x", kind="bytes")
        with self.assertRaisesRegex(ValueError, "max_depth"):
            server.rea_native_value_flow("anything", "0x401000", max_depth=99)
        with self.assertRaisesRegex(ValueError, "invalid procedure"):
            server.rea_native_function("anything", "--execute")

    def test_rea_manifest_parser_rejects_missing_commands(self):
        help_text = """rea@6.7.0\n\nCommands:\n  inspect-artifact  Inspect\n  inspect-pe-resources  Resources\n\nIntegrations:\n  mcp  MCP\n"""
        completed = {
            "rc": 0, "stdout": help_text, "stderr": "",
            "seconds": 0.1, "timed_out": False,
        }
        with patch.object(server, "_run", return_value=completed):
            self.assertEqual(
                server._rea_available_commands(),
                {"inspect-artifact", "inspect-pe-resources"},
            )
            with self.assertRaisesRegex(RuntimeError, "commands missing"):
                server._validate_rea_command_manifest()


if __name__ == "__main__":
    unittest.main()
