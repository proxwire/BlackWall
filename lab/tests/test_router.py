import inspect
import io
import json
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from blackwall_lab import router, server

ROOT = Path(__file__).resolve().parents[2]


def pe_fixture(*, dotnet: bool = False, corflags: int | None = 0x1,
               marker: bytes = b"") -> bytes:
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", data, 0x84, 0x8664)
    struct.pack_into("<H", data, 0x94, 0xF0)
    struct.pack_into("<H", data, 0x98, 0x20B)
    if dotnet:
        clr_directory = 0x98 + 112 + 14 * 8
        struct.pack_into("<II", data, clr_directory, 0x2000, 0x48)
        if corflags is not None:
            struct.pack_into("<H", data, 0x86, 1)
            section = 0x80 + 24 + 0xF0
            data[section:section + 8] = b".text\0\0\0"
            struct.pack_into("<IIII", data, section + 8, 0x200, 0x2000, 0x200, 0x200)
            struct.pack_into("<I", data, 0x200 + 16, corflags)
    data.extend(marker)
    return bytes(data)


def zip_fixture(*names: str) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name in names:
            archive.writestr(name, b"inert fixture")
    return output.getvalue()


def cab_fixture(payload: bytes = b"inert") -> bytes:
    name = b"fixture.bin\0"
    files_offset = 44
    data_offset = files_offset + 16 + len(name)
    cabinet_size = data_offset + 8 + len(payload)
    return (
        struct.pack(
            "<4sIIIII BB HHHHH", b"MSCF", 0, cabinet_size, 0,
            files_offset, 0, 3, 1, 1, 1, 0, 0, 0,
        )
        + struct.pack("<IHH", data_offset, 1, 0)
        + struct.pack("<IIHHHH", len(payload), 0, 0, 0, 0, 0) + name
        + struct.pack("<IHH", 0, len(payload), len(payload)) + payload
    )


class RouterDetectionTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)

    def tearDown(self):
        self.tempdir.cleanup()

    def write(self, name: str, data: bytes) -> Path:
        target = self.root / name
        target.write_bytes(data)
        return target

    def test_required_format_categories_are_detected_from_inert_inputs(self):
        fixtures = {
            "container": (zip_fixture("readme.txt"), "sample.zip"),
            "executable": (b"\x7fELF\x02\x01\x01" + b"\0" * 128, "sample"),
            "managed-runtime": (pe_fixture(dotnet=True), "sample.exe"),
            "script": (b"function go() { return require('fs'); }", "sample.js"),
            "capture": (b"\x0a\x0d\x0d\x0a" + b"\0" * 32, "capture"),
            "document": (b"%PDF-1.7\n%%EOF", "document"),
            "mobile": (
                zip_fixture("AndroidManifest.xml", "classes.dex"),
                "sample.apk",
            ),
            "bytecode": (b"\0asm\x01\0\0\0", "module"),
        }
        for category, (data, hint) in fixtures.items():
            with self.subTest(category=category):
                detection = router.detect_format(
                    self.write(category, data), original_name=hint,
                )
                self.assertIn(category, detection["categories"])
                self.assertLessEqual(
                    detection["detector_limits"]["head_bytes"], router.HEAD_LIMIT,
                )
                self.assertFalse(
                    detection["detector_limits"]["archive_contents_extracted"],
                )

    def test_content_magic_wins_over_a_misleading_name(self):
        detection = router.detect_format(
            self.write("misleading", pe_fixture()), original_name="invoice.js",
        )
        self.assertEqual(detection["format"], "pe")
        self.assertEqual(detection["architecture"]["name"], "x86_64")

    def test_archive_families_are_distinguished_without_extraction(self):
        cases = {
            "apk": zip_fixture("AndroidManifest.xml", "classes.dex"),
            "ooxml-word": zip_fixture("[Content_Types].xml", "word/document.xml"),
            "java-archive": zip_fixture("META-INF/MANIFEST.MF", "A.class"),
            "ipa": zip_fixture("Payload/App.app/Info.plist"),
        }
        for expected, data in cases.items():
            with self.subTest(expected=expected):
                actual = router.detect_format(self.write(expected, data))["format"]
                self.assertEqual(actual, expected)

    def test_capture_database_document_and_evm_signatures(self):
        cases = {
            "pcap": b"\xd4\xc3\xb2\xa1" + b"\0" * 40,
            "har": b'{"log":{"entries":[{"request":{},"response":{}}]}}',
            "qlog": b'{"qlog_version":"0.3","traces":[],"vantage_point":{}}',
            "sqlite": b"SQLite format 3\0" + b"\0" * 80,
            "rtf": b"{\\rtf1\\ansi inert}",
            "ole-compound": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\0" * 80,
            "evm-hex": b"0x" + b"60806040526001600055" * 3,
            "evm-raw": b"\x60\x80\x60\x40\x52\x60\x01\x60\x00\x55",
        }
        for expected, data in cases.items():
            with self.subTest(expected=expected):
                actual = router.detect_format(self.write(expected, data))["format"]
                self.assertEqual(actual, expected)

    def test_packing_signal_and_post_triage_override_are_visible(self):
        target = self.write("packed", pe_fixture(marker=b"UPX!"))
        automatic = router.detect_format(target)
        overridden = router.detect_format(target, packing_state="not_packed")
        self.assertEqual(automatic["packing"]["state"], "likely_packed")
        self.assertEqual(overridden["packing"]["state"], "not_detected")
        self.assertEqual(overridden["packing"]["source"], "analyst_override")
        with self.assertRaisesRegex(ValueError, "packing_state"):
            router.detect_format(target, packing_state="maybe")

    def test_pe_with_structural_cab_gets_automatic_recursive_route(self):
        target = self.write("iexpress", pe_fixture(marker=cab_fixture()))
        detection = router.detect_format(target)
        self.assertEqual(detection["embedded"][0]["format"], "cab")
        plan = router.build_analysis_plan(target)
        recursive = next(
            step for step in plan["selected"]
            if step["tool"] == "lab.recursive_unpack"
        )
        self.assertEqual(recursive["state"], "ready")
        self.assertIn("RCDATA", recursive["reason"])

    def test_mixed_mode_corflags_are_detected_without_widening_reads(self):
        target = ROOT / "benchmarks" / "fixtures" / "dotnet-mixed.pe"
        detection = router.detect_format(target)
        self.assertEqual(detection["format"], "dotnet")
        self.assertTrue(detection["managed"]["mixed_mode"])
        self.assertFalse(detection["managed"]["il_only"])
        self.assertIn("mixed managed/native", " ".join(detection["evidence"]))


class RouterPlanTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)

    def tearDown(self):
        self.tempdir.cleanup()

    def write(self, name: str, data: bytes) -> Path:
        target = self.root / name
        target.write_bytes(data)
        return target

    def test_native_plan_is_deterministic_visible_and_ghidra_first(self):
        target = self.write("native", pe_fixture())
        one = router.build_analysis_plan(target, display_path="original/sample")
        two = router.build_analysis_plan(target, display_path="original/sample")
        self.assertEqual(one, two)
        self.assertEqual(one["schema"], router.PLAN_SCHEMA)

        selected = {step["tool"]: step for step in one["selected"]}
        self.assertIn("ghidra.list_project_binaries", selected)
        self.assertEqual(selected["ghidra.list_project_binaries"]["arguments"], {})
        self.assertEqual(selected["lab.rea_native_function"]["state"], "deferred")
        self.assertNotIn("lab.rea_native_overview", selected)
        self.assertTrue(any(
            item["tool"] == "lab.rea_native_overview" for item in one["skipped"]
        ))
        for step in one["selected"]:
            self.assertTrue({
                "id", "phase", "state", "tool", "arguments", "reason",
                "deadline_seconds", "fallbacks",
            } <= set(step))
            self.assertGreater(step["deadline_seconds"], 0)

    def test_triage_phase_excludes_deep_steps_but_explains_them(self):
        plan = router.build_analysis_plan(
            self.write("native", b"\x7fELF\x02\x01\x01" + b"\0" * 128),
            phase="triage",
        )
        self.assertTrue(all(step["phase"] == "triage" for step in plan["selected"]))
        self.assertTrue(any(
            "excluded from requested triage phase" in item["reason"]
            for item in plan["skipped"]
        ))
        tools = {step["tool"] for step in plan["selected"]}
        self.assertIn("lab.strings", tools)
        self.assertNotIn("lab.floss", tools)

    def test_macho_avoids_pe_elf_only_capability_tools(self):
        macho = b"\xcf\xfa\xed\xfe\x07\x00\x00\x01" + b"\0" * 80
        plan = router.build_analysis_plan(self.write("macho", macho))
        self.assertEqual(plan["detection"]["architecture"]["name"], "x86_64")
        selected = {step["tool"] for step in plan["selected"]}
        self.assertNotIn("lab.capa", selected)
        self.assertNotIn("lab.floss", selected)
        self.assertIn("lab.macho_info", selected)
        self.assertIn("ghidra.list_project_binaries", selected)

    def test_elf_core_routes_to_recorded_crash_without_native_execution(self):
        core = bytearray(b"\x7fELF\x02\x01\x01" + b"\0" * 121)
        struct.pack_into("<H", core, 16, 4)
        struct.pack_into("<H", core, 18, 0x3E)
        plan = router.build_analysis_plan(self.write("core", bytes(core)))
        self.assertEqual(plan["detection"]["format"], "elf-core")
        selected = {step["tool"] for step in plan["selected"]}
        self.assertIn("lab.rea_recorded_crash", selected)
        self.assertNotIn("lab.emulate_elf", selected)
        self.assertNotIn("ghidra.list_project_binaries", selected)

    def test_dotnet_prefers_managed_workflows_over_native_ghidra(self):
        plan = router.build_analysis_plan(self.write("managed", pe_fixture(dotnet=True)))
        workflows = {
            step["arguments"].get("workflow")
            for step in plan["selected"]
            if step["tool"] == "lab.rea_static_analysis"
        }
        self.assertEqual(workflows, {"managed", "managed_native_boundaries"})
        selected = {s["tool"]: s for s in plan["selected"]}
        self.assertIn("lab.rea_managed_members", selected)
        self.assertIn("lab.dotnet_inventory", selected)
        self.assertIn("lab.dotnet_list_resources", selected)
        self.assertIn("lab.dotnet_extract_resources", selected)
        self.assertEqual(selected["lab.dotnet_decompile"]["state"], "deferred")
        self.assertEqual(selected["lab.dotnet_call_references"]["state"], "deferred")
        self.assertEqual(selected["lab.dotnet_search"]["state"], "deferred")
        self.assertTrue(any(
            item["tool"] == "ghidra.list_project_binaries" for item in plan["skipped"]
        ))

    def test_mixed_mode_dotnet_adds_focused_native_workspace(self):
        plan = router.build_analysis_plan(
            ROOT / "benchmarks" / "fixtures" / "dotnet-mixed.pe",
        )
        selected = {step["tool"]: step for step in plan["selected"]}
        self.assertIn("lab.dotnet_inventory", selected)
        self.assertIn("ghidra.list_project_binaries", selected)
        self.assertEqual(selected["lab.rea_native_function"]["state"], "deferred")

    def test_unknown_dotnet_corflags_keep_a_conservative_native_workspace(self):
        plan = router.build_analysis_plan(
            self.write("managed-unknown", pe_fixture(dotnet=True, corflags=None)),
        )
        selected = {step["tool"]: step for step in plan["selected"]}
        self.assertIn("ghidra.list_project_binaries", selected)
        self.assertIn("unavailable", selected["ghidra.list_project_binaries"]["reason"])

    def test_focused_formats_select_focused_rea_workflows(self):
        cases = [
            (
                "apk", zip_fixture("AndroidManifest.xml", "classes.dex"),
                "lab.android_resources", ("timeout", 600),
            ),
            (
                "electron", b"const {app} = require('electron'); function f(){}",
                "lab.rea_static_analysis", ("workflow", "javascript"),
            ),
            (
                "wasm", b"\0asm\x01\0\0\0", "lab.rea_static_analysis",
                ("workflow", "wasm"),
            ),
            (
                "evm", b"0x" + b"60806040526001600055" * 3,
                "lab.rea_evm_interface", ("encoding", "hex"),
            ),
            (
                "pcap", b"\xd4\xc3\xb2\xa1" + b"\0" * 40,
                "lab.rea_static_analysis", ("workflow", "pcap"),
            ),
            (
                "har", b'{"log":{"entries":[{"request":{},"response":{}}]}}',
                "lab.rea_web_capture", ("capture_format", "har"),
            ),
            (
                "sqlite", b"SQLite format 3\0" + b"\0" * 80,
                "lab.rea_static_analysis", ("workflow", "sqlite"),
            ),
        ]
        for name, data, tool_name, argument in cases:
            with self.subTest(name=name):
                plan = router.build_analysis_plan(self.write(name, data))
                key, value = argument
                self.assertTrue(any(
                    step["tool"] == tool_name and step["arguments"].get(key) == value
                    for step in plan["selected"]
                ))

    def test_standalone_javascript_skips_rea_application_workflow(self):
        plan = router.build_analysis_plan(
            self.write("standalone.js", b"function f(){ return require('fs'); }"),
        )
        self.assertEqual(plan["detection"]["format"], "javascript")
        self.assertFalse(any(
            step["tool"] == "lab.rea_static_analysis" for step in plan["selected"]
        ))
        self.assertIn("lab.script_analyze", {step["tool"] for step in plan["selected"]})
        self.assertIn("lab.script_extract_payloads", {step["tool"] for step in plan["selected"]})
        self.assertTrue(any(
            item["tool"] == "lab.rea_static_analysis"
            and item.get("arguments", {}).get("workflow") == "javascript"
            and "standalone" in item["reason"]
            for item in plan["skipped"]
        ))

    def test_upx_plan_adds_focused_unpacking(self):
        plan = router.build_analysis_plan(
            self.write("upx", pe_fixture(marker=b"UPX!")),
        )
        tools = {step["tool"] for step in plan["selected"]}
        self.assertIn("lab.upx_unpack", tools)
        self.assertNotIn("lab.binwalk_scan", tools)
        self.assertTrue(any(
            item["tool"] == "lab.binwalk_scan" and "redundant" in item["reason"]
            for item in plan["skipped"]
        ))
        phases = [step["phase"] for step in plan["selected"]]
        self.assertEqual(phases, sorted(phases, key={"triage": 0, "deep": 1}.get))
        self.assertEqual(
            next(step for step in plan["selected"] if step["tool"] == "lab.rea_native_load_image")["state"],
            "deferred",
        )

    def test_document_uses_bounded_structure_and_extraction_tools(self):
        plan = router.build_analysis_plan(
            self.write("document.pdf", b"%PDF-1.7\n%%EOF"),
        )
        selected = {step["tool"]: step for step in plan["selected"]}
        self.assertEqual(selected["lab.document_triage"]["state"], "ready")
        self.assertEqual(selected["lab.document_extract_artifacts"]["state"], "ready")
        self.assertNotIn("lab.binwalk_scan", selected)
        self.assertTrue(any(
            item["tool"] == "lab.document_vba" and "not an OLE" in item["reason"]
            for item in plan["skipped"]
        ))

    def test_vba_powershell_and_vbscript_route_to_static_script_tools(self):
        cases = {
            "vba": (b'Attribute VB_Name = "Fixture"\nSub AutoOpen()\nEnd Sub', "fixture.bas"),
            "powershell": (b'$env:Fixture = "x"', "fixture.ps1"),
            "vbscript": (b'On Error Resume Next\nvalue = "x"', "fixture.vbs"),
        }
        for expected, (data, name) in cases.items():
            with self.subTest(expected=expected):
                plan = router.build_analysis_plan(self.write(name, data))
                self.assertEqual(plan["detection"]["format"], expected)
                selected = {step["tool"]: step for step in plan["selected"]}
                self.assertEqual(
                    selected["lab.script_analyze"]["arguments"]["language"], expected,
                )
                self.assertIn("lab.script_extract_payloads", selected)

    def test_native_electron_wrapper_keeps_ghidra_and_adds_fuse_inspection(self):
        plan = router.build_analysis_plan(
            self.write("electron-pe", pe_fixture(marker=b"resources/app.asar")),
        )
        self.assertEqual(plan["detection"]["format"], "electron-pe")
        self.assertIn("ghidra.list_project_binaries", {s["tool"] for s in plan["selected"]})
        self.assertTrue(any(
            step["tool"] == "lab.rea_static_analysis"
            and step["arguments"].get("workflow") == "electron_fuses"
            for step in plan["selected"]
        ))

    def test_raw_cab_skips_known_unsupported_rea_artifact_route(self):
        plan = router.build_analysis_plan(self.write("cab", b"MSCF" + b"\0" * 80))
        self.assertFalse(any(
            step["tool"] == "lab.rea_static_analysis" for step in plan["selected"]
        ))
        self.assertTrue(any(
            item["tool"] == "lab.rea_static_analysis"
            and item.get("arguments", {}).get("workflow") == "artifact"
            for item in plan["skipped"]
        ))
        self.assertIn(
            "lab.recursive_unpack", {step["tool"] for step in plan["selected"]},
        )

    def test_unknown_format_records_unsupported_gap_instead_of_guessing(self):
        plan = router.build_analysis_plan(self.write("unknown", b"\x01\x02\x03\x04"))
        self.assertEqual(plan["detection"]["format"], "unknown")
        self.assertTrue(any(
            item["tool"] == "lab.rea_static_analysis" and "unknown format" in item["reason"]
            for item in plan["skipped"]
        ))

    def test_planned_lab_arguments_match_registered_tool_signatures(self):
        fixtures = [
            pe_fixture(),
            pe_fixture(dotnet=True),
            b"\x7fELF\x02\x01\x01" + b"\0" * 128,
            zip_fixture("AndroidManifest.xml", "classes.dex"),
            b"function f(){ return require('fs'); }",
            b'$env:Fixture = "x"',
            b'Attribute VB_Name = "Fixture"\nSub AutoOpen()\nEnd Sub',
            b"%PDF-1.7\n%%EOF",
            b"\0asm\x01\0\0\0",
            b"SQLite format 3\0" + b"\0" * 80,
        ]
        for index, data in enumerate(fixtures):
            plan = router.build_analysis_plan(self.write(f"signature-{index}", data))
            for step in plan["selected"]:
                if not step["tool"].startswith("lab."):
                    continue
                function = getattr(server, step["tool"].removeprefix("lab."))
                signature = inspect.signature(function)
                extras = set(step["arguments"]) - set(signature.parameters)
                self.assertEqual(extras, set(), step["id"])
                missing = {
                    name for name, parameter in signature.parameters.items()
                    if parameter.default is inspect.Parameter.empty
                    and name not in step["arguments"]
                }
                if missing:
                    self.assertEqual(step["state"], "deferred", step["id"])
                    self.assertIn("inputs_required", step, step["id"])

    def test_server_tool_persists_the_same_plan_schema(self):
        work = self.root / "work"
        samples = work / "samples"
        original = samples / "original"
        out = work / "out"
        original.mkdir(parents=True)
        digest = "a" * 64
        target = original / digest
        target.write_bytes(b"\0asm\x01\0\0\0")
        (original / ".meta.json").write_text(json.dumps({
            "sha256": digest, "original_name": "module.wasm",
        }))
        with (
            patch.object(server, "WORK", work),
            patch.object(server, "SAMPLES", samples),
            patch.object(server, "OUT", out),
        ):
            plan = server.analysis_plan(f"original/{digest}")
        self.assertEqual(plan["target"]["sha256"], digest)
        self.assertEqual(plan["target"]["original_name_hint"], "module.wasm")
        saved = Path(plan["saved_to"])
        self.assertTrue(saved.is_file())
        self.assertEqual(json.loads(saved.read_text())["plan_id"], plan["plan_id"])

    def test_server_router_rejects_unregistered_scratch_files(self):
        work = self.root / "work"
        samples = work / "samples"
        scratch = work / "scratch"
        scratch.mkdir(parents=True)
        (scratch / ("b" * 64)).write_bytes(b"\0asm\x01\0\0\0")
        with (
            patch.object(server, "WORK", work),
            patch.object(server, "SAMPLES", samples),
        ):
            with self.assertRaisesRegex(ValueError, "content-addressed original or derived"):
                server.analysis_plan(f"../scratch/{'b' * 64}")


class ResultNormalizationTests(unittest.TestCase):
    def test_all_failure_states_remain_visible_and_continuable(self):
        cases = {
            "timeout": ({"timed_out": True, "stderr": "timed out after 30s"}, None),
            "unsupported": ({"unsupported_format": "dex", "error": "not supported"}, None),
            "partial": ({"rc": 2, "evidence": {"header": "ok"}, "error": "parser stopped"}, None),
            "failed": ({"rc": 2, "error": "parser crashed"}, None),
            "skipped": ({"status": "skipped"}, None),
            "failed-ok": ({"ok": False}, None),
            "timeout-deadline": ({}, "deadline exceeded while parsing"),
            "cancelled": ({"cancelled": True, "stderr": "cancelled by caller"}, None),
            "crashed": ({"crashed": True, "termination_signal": 11}, None),
        }
        for label, (result, error) in cases.items():
            expected = label.split("-", 1)[0]
            with self.subTest(case=label):
                normalized = router.normalize_result(
                    "triage.step", "lab.fixture", result=result, error=error,
                )
                self.assertEqual(normalized["status"], expected)
                self.assertTrue(normalized["continue_analysis"])
                self.assertEqual(normalized["gap"]["kind"], expected)

    def test_redundant_step_is_distinct_from_success_and_failure(self):
        normalized = router.normalize_result(
            "triage.step",
            "lab.fixture",
            result={"status": "not_run_redundant", "reason": "same evidence exists"},
        )
        self.assertEqual(normalized["status"], "not_run_redundant")
        self.assertTrue(normalized["continue_analysis"])
        self.assertIsNone(normalized["gap"])
        self.assertTrue(normalized["observed"]["redundant"])
        self.assertFalse(normalized["observed"]["has_evidence"])

    def test_success_has_no_gap_and_exception_is_failed(self):
        success = router.normalize_result(
            "triage.step", "lab.fixture", result={"rc": 0, "summary": {"ok": True}},
        )
        failure = router.normalize_result(
            "triage.step", "lab.fixture", error="tool transport failed",
        )
        self.assertEqual(success["status"], "success")
        self.assertIsNone(success["gap"])
        self.assertEqual(failure["status"], "failed")
        self.assertIn("transport", failure["gap"]["message"])

    def test_doctor_self_check_is_deterministic(self):
        manifest = router.router_self_check()
        self.assertTrue(manifest["deterministic"])
        self.assertEqual(manifest["schema"], router.PLAN_SCHEMA)


if __name__ == "__main__":
    unittest.main()
