import base64
import io
import tempfile
import unittest
import zipfile
from pathlib import Path

from blackwall_lab import documents

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "benchmarks" / "fixtures"


class DocumentWorkerTests(unittest.TestCase):
    def test_embedded_vba_project_exercises_ole_compound_lane(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "vbaProject.bin"
            with zipfile.ZipFile(FIXTURES / "office-macro.xlsm") as archive:
                target.write_bytes(archive.read("xl/vbaProject.bin"))

            triage = documents.document_triage(target)
            output = Path(temporary) / "output"
            output.mkdir()
            extracted = documents.document_extract(target, output)

        self.assertEqual(triage["format"], "ole-compound")
        self.assertGreater(triage["structure"]["stream_count"], 0)
        self.assertTrue(any(
            row["kind"] == "ole-active-stream" for row in triage["findings"]
        ))
        self.assertTrue(any(
            row["source"] == "VBA/Module1" for row in extracted["artifacts"]
        ))

    def test_ooxml_relationships_and_generated_name_extraction(self):
        result = documents.document_triage(FIXTURES / "office.docx")
        self.assertEqual(result["format"], "ooxml")
        self.assertTrue(any(row["external"] for row in result["relationships"]))
        self.assertTrue(any(
            row["kind"] == "active-content-part" for row in result["findings"]
        ))

        with tempfile.TemporaryDirectory() as temporary:
            extracted = documents.document_extract(
                FIXTURES / "office.docx", Path(temporary),
            )
            artifact = extracted["artifacts"][0]
            payload = Path(temporary, artifact["file"]).read_bytes()
        self.assertEqual(artifact["file"], "artifact-0000.bin")
        self.assertIn(b"BLACKWALL_INERT_OFFICE_EMBEDDED_PAYLOAD", payload)
        self.assertEqual(artifact["source"], "word/embeddings/payload.bin")

    def test_rtf_and_pdf_active_content_is_recovered_with_provenance(self):
        rtf = documents.document_triage(FIXTURES / "document.rtf")
        pdf = documents.document_triage(FIXTURES / "document.pdf")
        self.assertEqual(rtf["structure"]["object_count"], 1)
        self.assertTrue(any(row["kind"] == "javascript-action" for row in pdf["findings"]))
        self.assertTrue(any("cmd.exe" in row["value"] for row in pdf["commands"]))

        with tempfile.TemporaryDirectory() as temporary:
            result = documents.document_extract(
                FIXTURES / "document.pdf", Path(temporary),
            )
            sources = {row["source"] for row in result["artifacts"]}
            payloads = [Path(temporary, row["file"]).read_bytes() for row in result["artifacts"]]
        self.assertEqual(sources, {"pdf-object:8:0", "pdf-object:9:0"})
        self.assertTrue(any(blob.startswith(b"var endpoint") for blob in payloads))

    def test_archive_expansion_ratio_is_enforced(self):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("[Content_Types].xml", b"A" * 200_000)
            archive.writestr("word/document.xml", b"fixture")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "ratio.docx"
            path.write_bytes(output.getvalue())
            result = documents.document_triage(path)
        self.assertTrue(any("expansion ratio" in row["error"] for row in result["errors"]))

    def test_rtf_extraction_enforces_aggregate_limit_before_writing(self):
        first = bytes(range(16))
        second = bytes(range(16, 32))
        payload = (
            b"{\\rtf1{\\object\\objdata " + first.hex().encode() + b"}"
            b"{\\object\\objdata " + second.hex().encode() + b"}}"
        )
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "bounded.rtf"
            target.write_bytes(payload)
            output = Path(temporary) / "output"
            output.mkdir()
            result = documents.document_extract(
                target, output, member_limit=16, total_limit=16,
            )

        self.assertEqual(result["count"], 1)
        self.assertEqual(result["total_bytes"], 16)
        self.assertTrue(any("aggregate" in row["error"] for row in result["errors"]))

    def test_script_fixtures_are_deobfuscated_without_an_interpreter(self):
        cases = {
            "javascript.js": ("javascript", "javascript.fixture.invalid", "cmd.exe"),
            "powershell.ps1": ("powershell", "powershell-decoded.fixture.invalid", None),
            "vbscript.vbs": ("vbscript", "vbscript.fixture.invalid", "cmd.exe"),
            "vba.bas": ("vba", "vba.fixture.invalid", "powershell.exe"),
        }
        for name, (language, domain, command) in cases.items():
            with self.subTest(name=name):
                result, _ = documents.script_analyze(FIXTURES / name)
                self.assertEqual(result["language"], language)
                self.assertFalse(result["interpreter_used"])
                self.assertTrue(any(domain in row["value"] for row in result["urls"]))
                if command:
                    self.assertTrue(any(command in row["value"] for row in result["commands"]))
                self.assertTrue(result["decoded_strings"])

    def test_only_encoded_payloads_become_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = documents.script_extract(
                FIXTURES / "vbscript.vbs", Path(temporary),
            )
            self.assertEqual(result["count"], 1)
            artifact = result["artifacts"][0]
            payload = Path(temporary, artifact["file"]).read_bytes()
        self.assertTrue(payload.startswith(b"%PDF-"))
        self.assertEqual(artifact["transform"], "base64:utf-8")

    def test_long_decoded_script_is_fully_scanned_but_bounded_in_output(self):
        late_url = "https://late-decoded.fixture.invalid/payload"
        decoded = ("A" * 3000 + "\n" + late_url).encode()
        source = b'const payload = "' + base64.b64encode(decoded) + b'";\n'
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "long.js"
            target.write_bytes(source)
            result, _ = documents.script_analyze(target)

        self.assertGreater(result["decoded_strings"][0]["full_length"], 2048)
        self.assertLess(len(result["decoded_strings"][0]["value"]), 2200)
        self.assertEqual(result["coverage"]["decoded_bytes"], len(decoded))
        self.assertTrue(any(late_url in row["value"] for row in result["urls"]))

    def test_binary_payload_bytes_are_charged_to_decode_budget(self):
        decoded = b"%PDF-1.4\n" + b"A" * 128
        source = b'const payload = "' + base64.b64encode(decoded) + b'";\n'
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "bounded.js"
            target.write_bytes(source)
            result, payloads = documents.script_analyze(target, decoded_limit=64)

        self.assertEqual(result["decoded_strings"], [])
        self.assertEqual(payloads, [])
        self.assertTrue(result["coverage"]["result_truncated"])


if __name__ == "__main__":
    unittest.main()
