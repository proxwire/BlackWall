import hashlib
import tempfile
import unittest
from pathlib import Path

from blackwall_lab.detections import (
    ATTACK_SCHEMA,
    SIGMA_SCHEMA,
    SURICATA_SCHEMA,
    YARA_SCHEMA,
    generate_sigma,
    generate_suricata,
    generate_yara,
    map_attack,
)
from blackwall_lab.evidence import EvidenceStore


class DetectionCandidateTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.work = self.root / "work"
        original = self.work / "samples" / "original"
        original.mkdir(parents=True)
        payload = b"MZ BLACKWALL_UNIQUE_POSITIVE_ANCHOR side-load fixture"
        digest = hashlib.sha256(payload).hexdigest()
        self.positive = original / digest
        self.positive.write_bytes(payload)
        self.negative = self.root / "negative.bin"
        self.negative.write_bytes(b"MZ ordinary inert negative fixture")
        self.output = self.work / "rules"
        self.export = self.root / "detections"
        store = EvidenceStore(self.work)
        plan = {
            "schema": "blackwall.analysis-plan.v1",
            "plan_id": "0123456789abcdef",
            "target": {
                "path": str(self.positive), "sha256": digest,
                "routing_fingerprint": "detection-fixture",
            },
            "phase": "full",
            "selected": [{
                "id": "triage.fixture", "tool": "lab.fixture", "state": "ready",
                "arguments": {"path": str(self.positive)}, "fallbacks": [],
            }],
        }
        store.ensure_plan(plan)
        evidence, _ = store.record_result(
            plan_id=plan["plan_id"], step_id="triage.fixture",
            tool_name="lab.fixture", normalized={"status": "success", "gap": None},
            result={"summary": {"behavior": "dll-side-loading"}}, error=None,
        )
        self.evidence_ids = [evidence["evidence_id"]]

    def test_yara_exports_only_after_positive_and_negative_validation(self):
        result = generate_yara(
            name="BlackWallFixture",
            evidence_ids=self.evidence_ids,
            strings=["BLACKWALL_UNIQUE_POSITIVE_ANCHOR", "side-load fixture"],
            positive_paths=[self.positive],
            negative_paths=[self.negative],
            state=self.work / "state",
            output=self.output,
            export=self.export,
        )
        self.assertEqual(result["schema"], YARA_SCHEMA)
        self.assertTrue(result["validation"]["passed"])
        self.assertEqual(result["validation"]["positive_count"], 1)
        self.assertEqual(result["validation"]["negative_count"], 1)
        self.assertTrue((self.export / "BlackWallFixture.yar").is_file())
        self.assertIn(self.evidence_ids[0], (self.export / "BlackWallFixture.yar").read_text())

        rejected = generate_yara(
            name="OverbroadFixture",
            evidence_ids=self.evidence_ids,
            strings=["MZ ordinary"],
            positive_paths=[self.negative],
            negative_paths=[self.negative, self.positive],
            state=self.work / "state",
            output=self.output,
            export=self.export,
        )
        # Identical positive hashes are removed from the negative set, while
        # the unrelated positive fixture remains a true negative.
        self.assertTrue(rejected["validation"]["passed"])
        failed = generate_yara(
            name="FalseNegativeFixture",
            evidence_ids=self.evidence_ids,
            strings=["does-not-occur"],
            positive_paths=[self.positive],
            negative_paths=[self.negative],
            state=self.work / "state",
            output=self.output,
            export=self.export,
        )
        self.assertFalse(failed["validation"]["passed"])
        self.assertFalse((self.output / "FalseNegativeFixture.yar").exists())

    def test_sigma_and_suricata_reject_unsupported_telemetry(self):
        sigma = generate_sigma(
            title="Inert suspicious process fixture",
            name="InertProcessFixture",
            telemetry="process_creation",
            selection={"Image": "*\\fixture.exe", "CommandLine": "*-fixture*"},
            evidence_ids=self.evidence_ids,
            state=self.work / "state", output=self.output,
        )
        self.assertEqual(sigma["schema"], SIGMA_SCHEMA)
        self.assertIn("category: process_creation", (self.output / "InertProcessFixture.yml").read_text())
        with self.assertRaisesRegex(ValueError, "unavailable"):
            generate_sigma(
                title="Unsupported telemetry field",
                name="BadSigmaFixture", telemetry="dns_query",
                selection={"CommandLine": "not present in DNS telemetry"},
                evidence_ids=self.evidence_ids,
                state=self.work / "state", output=self.output,
            )

        suricata = generate_suricata(
            name="InertDnsFixture", kind="dns", indicator="fixture.invalid",
            evidence_ids=self.evidence_ids,
            state=self.work / "state", output=self.output,
        )
        self.assertEqual(suricata["schema"], SURICATA_SCHEMA)
        self.assertIn("dns.query", (self.output / "InertDnsFixture.rules").read_text())
        with self.assertRaisesRegex(ValueError, "invalid"):
            generate_suricata(
                name="BadDnsFixture", kind="dns", indicator="not a domain",
                evidence_ids=self.evidence_ids,
                state=self.work / "state", output=self.output,
            )

    def test_dll_side_loading_regression_is_t1574_002(self):
        result = map_attack(
            behavior="dll-side-loading", evidence_ids=self.evidence_ids,
            confidence="high", state=self.work / "state", output=self.output,
        )
        self.assertEqual(result["schema"], ATTACK_SCHEMA)
        self.assertEqual(result["technique_id"], "T1574.002")
        self.assertEqual(result["technique"], "DLL Side-Loading")
        self.assertNotEqual(result["technique_id"], "T1574.001")
        with self.assertRaisesRegex(ValueError, "reviewed"):
            map_attack(
                behavior="model-guessed-technique", evidence_ids=self.evidence_ids,
                confidence="high", state=self.work / "state", output=self.output,
            )


if __name__ == "__main__":
    unittest.main()
