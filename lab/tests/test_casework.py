import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from blackwall_lab.casework import (
    BUNDLE_SCHEMA,
    COMPARISON_SCHEMA,
    REPORT_SCHEMA,
    build_report,
    case_status,
    cleanup_scratch,
    compare_reports,
    create_bundle,
    import_bundle,
    inspect_bundle,
    render_markdown,
)
from blackwall_lab.evidence import EvidenceStore


class CaseworkTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.work = self.root / "work"
        self.case = self.root / "case"
        original = self.work / "samples" / "original"
        original.mkdir(parents=True)
        self.case.mkdir()
        payload = b"inert casework fixture https://fixture.invalid/path"
        self.sha256 = hashlib.sha256(payload).hexdigest()
        self.sample = original / self.sha256
        self.sample.write_bytes(payload)
        (original / ".meta.json").write_text(json.dumps({
            "sha256": self.sha256, "original_name": "fixture.exe",
        }))
        (self.case / "case.json").write_text(json.dumps({
            "sha256": self.sha256,
            "source": "inert-test",
            "original_name": "fixture.exe",
            "analysis_profile": {"name": "strict", "selected_at": "fixture-time"},
        }))
        (self.case / "sample.zip").write_bytes(b"inert encrypted-sample placeholder")
        self.store = EvidenceStore(self.work)
        self.plan = {
            "schema": "blackwall.analysis-plan.v1",
            "plan_id": "0123456789abcdef",
            "target": {
                "path": str(self.sample), "sha256": self.sha256,
                "routing_fingerprint": "casework-fixture",
            },
            "phase": "full",
            "selected": [{
                "id": "triage.fixture", "tool": "lab.fixture", "state": "ready",
                "arguments": {"path": str(self.sample)}, "fallbacks": [],
            }],
        }
        self.store.ensure_plan(self.plan)
        evidence, _ = self.store.record_result(
            plan_id=self.plan["plan_id"], step_id="triage.fixture",
            tool_name="lab.fixture", normalized={"status": "success", "gap": None},
            result={"summary": {"url": "https://fixture.invalid/path"}}, error=None,
        )
        self.store.record_findings(evidence["evidence_id"], [{
            "subject": "network.url", "value": "https://fixture.invalid/path",
        }])
        self.store.link_claim(
            statement="The fixture contains one inert URL.",
            evidence_ids=[evidence["evidence_id"]],
        )

    def test_report_is_reproducible_audited_and_renderable(self):
        first = build_report(self.work, self.case)
        second = build_report(self.work, self.case)
        self.assertEqual(first, second)
        self.assertEqual(first["schema"], REPORT_SCHEMA)
        self.assertTrue(first["audit"]["ok"])
        self.assertEqual(first["target"]["sha256"], self.sha256)
        self.assertEqual(first["status"]["progress"]["percent"], 100.0)
        markdown = render_markdown(first)
        self.assertIn(first["report_id"], markdown)
        self.assertIn("network.url", markdown)
        self.assertNotIn(str(self.root), json.dumps(first))

    def test_sample_and_run_comparison_has_stable_categories(self):
        left = build_report(self.work, self.case, self.plan["plan_id"])
        right = json.loads(json.dumps(left))
        right["report_id"] = "report_right"
        right["findings"]["groups"]["added"] = {
            "subject": "configuration.campaign",
            "variants": {"one": {"canonical_value": "fixture-campaign"}},
        }
        comparison = compare_reports(left, right)
        self.assertEqual(comparison["schema"], COMPARISON_SCHEMA)
        self.assertEqual(len(comparison["categories"]["configurations"]["added"]), 1)
        self.assertEqual(comparison, compare_reports(left, right))

    def test_password_protected_bundle_round_trip_validates_every_file(self):
        (self.case / "notes").mkdir()
        (self.case / "notes" / "note.txt").write_text("inert note")
        (self.case / "notes" / "manifest.json").write_text("inert nested manifest")
        output = self.root / "portable.7z"
        created = create_bundle(self.work, self.case, output, "fixture-password")
        self.assertEqual(created["schema"], BUNDLE_SCHEMA)
        self.assertNotIn(b"manifest.json", output.read_bytes())
        inspected = inspect_bundle(output, "fixture-password")
        self.assertEqual(inspected["manifest_id"], created["manifest_id"])
        with self.assertRaisesRegex(ValueError, "wrong password|corrupt"):
            inspect_bundle(output, "incorrect")

        imported_work = self.root / "imported-work"
        imported_case = self.root / "imported-case"
        result = import_bundle(
            output, imported_work, imported_case, "fixture-password",
        )
        self.assertTrue(result["imported"])
        self.assertEqual(
            (imported_case / "case.json").read_bytes(),
            (self.case / "case.json").read_bytes(),
        )
        self.assertTrue((imported_work / "state" / "artifacts.json").is_file())
        self.assertEqual(
            (imported_case / "notes" / "manifest.json").read_text(),
            "inert nested manifest",
        )

    def test_bundle_link_member_is_rejected_before_extraction(self):
        payload = self.root / "malicious-bundle"
        payload.mkdir()
        (payload / "link").symlink_to("/etc/passwd")
        archive = self.root / "link.7z"
        subprocess.run(
            [
                "7z", "a", "-snl", "-t7z", "-mhe=on", "-pfixture-password",
                str(archive), ".",
            ],
            cwd=payload,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        with self.assertRaisesRegex(ValueError, "link member"):
            inspect_bundle(archive, "fixture-password")

    def test_cleanup_is_explicitly_scratch_only(self):
        scratch = self.work / "scratch"
        scratch.mkdir()
        (scratch / "temporary.bin").write_bytes(b"temporary")
        before = (self.work / "state" / "artifacts.json").read_bytes()
        result = cleanup_scratch(self.work)
        self.assertEqual(result["scope"], "scratch-only")
        self.assertFalse(scratch.exists())
        self.assertEqual((self.work / "state" / "artifacts.json").read_bytes(), before)
        self.assertEqual(case_status(self.work)["counts"]["evidence_records"], 1)


if __name__ == "__main__":
    unittest.main()
