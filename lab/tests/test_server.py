import json
import shlex
import stat
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from blackwall_lab import server


class ServerHelperTests(unittest.TestCase):
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
        forbidden = {
            "capture-process", "debug-with-gdb", "debug-with-rizin",
            "instrument-with-frida", "install-adb-package", "start-adb-app",
            "capture-browser-scenario", "capture-electron-scenario",
            "observe-native-calls",
        }
        self.assertTrue(commands.isdisjoint(forbidden))
        self.assertEqual(server.REA_STATIC_WORKFLOWS["go"], "inspect-go-binary")
        self.assertIn("function", server.REA_NATIVE_COMMANDS)
        self.assertIn("trace-native-values", server.REA_NATIVE_COMMANDS)
        self.assertNotIn("inspect-desktop-application", commands)
        self.assertNotIn("inspect-il2cpp-metadata", commands)
        self.assertNotIn("inspect-binary-layout", commands)
        self.assertNotIn("inspect-recorded-crash", commands)

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
