import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from blackwall_lab import server
from blackwall_lab.evidence import (
    AUDIT_SCHEMA,
    CHECKPOINT_SCHEMA,
    CLAIM_SCHEMA,
    EVIDENCE_SCHEMA,
    FINDINGS_SCHEMA,
    LINEAGE_SCHEMA,
    EvidenceStore,
    evidence_self_check,
)


class EvidenceStoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name) / "work"
        self.original_dir = self.work / "samples" / "original"
        self.original_dir.mkdir(parents=True)
        data = b"inert original fixture"
        self.original_sha256 = hashlib.sha256(data).hexdigest()
        self.original = self.original_dir / self.original_sha256
        self.original.write_bytes(data)
        self.store = EvidenceStore(self.work)
        self.plan = {
            "schema": "blackwall.analysis-plan.v1",
            "plan_id": "0123456789abcdef",
            "target": {
                "path": str(self.original),
                "sha256": self.original_sha256,
                "routing_fingerprint": "fixture-fingerprint",
            },
            "phase": "full",
            "selected": [
                {
                    "id": "triage.first", "tool": "lab.first", "state": "ready",
                    "arguments": {"path": str(self.original)},
                    "fallbacks": [{
                        "tool": "lab.fallback", "arguments": {"length": 256},
                        "reason": "retain bounded bytes",
                    }],
                },
                {
                    "id": "triage.second", "tool": "lab.second", "state": "ready",
                    "arguments": {"path": str(self.original), "mode": "focused"},
                },
                {
                    "id": "deep.deferred", "tool": "lab.deferred", "state": "deferred",
                    "arguments": {"path": str(self.original)},
                },
            ],
        }

    def record(self, step_id="triage.first", tool="lab.first", result=None, normalized=None):
        self.store.ensure_plan(self.plan)
        return self.store.record_result(
            plan_id=self.plan["plan_id"],
            step_id=step_id,
            tool_name=tool,
            normalized=normalized or {"status": "success", "gap": None},
            result=result or {"summary": {"family": "Fixture"}},
            error=None,
        )

    def test_versioned_record_has_auditable_required_fields_and_resumes(self):
        initial = self.store.ensure_plan(self.plan)
        record, completed = self.record()
        resumed = self.store.ensure_plan(self.plan)
        repeated_record, repeated_checkpoint = self.record()

        self.assertEqual(initial["schema"], CHECKPOINT_SCHEMA)
        self.assertIn("triage.first", initial["remaining_ready_steps"])
        self.assertEqual(record["schema"], EVIDENCE_SCHEMA)
        self.assertEqual(record["tool"]["name"], "lab.first")
        self.assertIn("version", record["tool"])
        self.assertEqual(record["artifact"]["sha256"], self.original_sha256)
        self.assertIsNone(record["artifact"]["parent_sha256"])
        self.assertIn("identity", record["command"])
        self.assertIn("observed_at", record["timestamps"])
        self.assertEqual(record["confidence"], "observed")
        self.assertIn("occurred", record["truncation"])
        self.assertTrue(Path(record["retained_output"]["path"]).is_file())
        self.assertIn("triage.first", completed["completed_steps"])
        self.assertNotIn("triage.first", resumed["remaining_ready_steps"])
        self.assertTrue(resumed["resumed"])
        self.assertEqual(repeated_record, record)
        self.assertEqual(repeated_checkpoint["revision"], completed["revision"])

    def test_non_success_is_checkpointed_as_a_visible_gap_not_requeued(self):
        record, checkpoint = self.record(
            result={"timed_out": True, "stderr": "timed out"},
            normalized={
                "status": "timeout",
                "gap": {"kind": "timeout", "message": "timed out"},
            },
        )
        resumed = self.store.ensure_plan(self.plan)
        self.assertEqual(record["status"], "timeout")
        self.assertIn("triage.first", checkpoint["recorded_gap_steps"])
        self.assertNotIn("triage.first", resumed["remaining_ready_steps"])

    def test_redundant_step_is_checkpointed_without_a_false_gap(self):
        record, checkpoint = self.record(
            result={"status": "not_run_redundant", "reason": "equivalent evidence"},
            normalized={"status": "not_run_redundant", "gap": None},
        )
        resumed = self.store.ensure_plan(self.plan)
        self.assertEqual(record["status"], "not_run_redundant")
        self.assertIn("triage.first", checkpoint["redundant_steps"])
        self.assertNotIn("triage.first", checkpoint["recorded_gap_steps"])
        self.assertNotIn("triage.first", resumed["remaining_ready_steps"])

    def test_checkpoint_recovers_evidence_committed_before_an_interruption(self):
        evidence, _ = self.record()
        checkpoint_path = self.store.checkpoint_dir / f"{self.plan['plan_id']}.json"
        checkpoint = json.loads(checkpoint_path.read_text())
        checkpoint["steps"]["triage.first"]["attempts"] = []
        checkpoint_path.write_text(json.dumps(checkpoint))

        resumed = self.store.ensure_plan(self.plan)
        recovered = json.loads(checkpoint_path.read_text())
        attempt = recovered["steps"]["triage.first"]["attempts"][0]
        self.assertEqual(attempt["evidence_id"], evidence["evidence_id"])
        self.assertTrue(attempt["recovered_after_interruption"])
        self.assertIn("triage.first", resumed["completed_steps"])
        self.assertNotIn("triage.first", resumed["remaining_ready_steps"])

    def test_planned_fallback_gets_its_own_exact_command_identity(self):
        first, _ = self.record(
            result={"timed_out": True},
            normalized={"status": "timeout", "gap": {"kind": "timeout"}},
        )
        with self.assertRaisesRegex(ValueError, "command_arguments"):
            self.store.record_result(
                plan_id=self.plan["plan_id"], step_id="triage.first",
                tool_name="lab.fallback",
                normalized={"status": "success", "gap": None},
                result={"output": "header"}, error=None,
            )
        fallback, checkpoint = self.store.record_result(
            plan_id=self.plan["plan_id"], step_id="triage.first",
            tool_name="lab.fallback",
            normalized={"status": "success", "gap": None},
            result={"output": "header"}, error=None,
            command_arguments={"path": str(self.original), "length": 256},
        )
        self.assertEqual(fallback["command"]["role"], "fallback")
        self.assertNotEqual(
            first["command"]["identity"], fallback["command"]["identity"],
        )
        self.assertIn("triage.first", checkpoint["completed_steps"])

    def test_equivalent_findings_merge_but_engine_disagreement_survives(self):
        first, _ = self.record()
        second, _ = self.record(step_id="triage.second", tool="lab.second")
        created = self.store.record_findings(first["evidence_id"], [
            {"subject": "classification.family", "value": "Fixture"},
        ])
        merged = self.store.record_findings(second["evidence_id"], [
            {"subject": "classification.family", "value": "fixture"},
        ])
        conflict = self.store.record_findings(second["evidence_id"], [
            {"subject": "classification.family", "value": "Other"},
        ])

        self.assertEqual(created["schema"], FINDINGS_SCHEMA)
        self.assertEqual(merged["equivalent_findings_deduplicated"], 1)
        self.assertEqual(len(conflict["disagreements"]), 1)
        index = json.loads(self.store.findings_path.read_text())
        group = next(iter(index["groups"].values()))
        self.assertEqual(len(group["variants"]), 2)
        fixture = next(
            value for value in group["variants"].values()
            if value["canonical_value"] == "fixture"
        )
        self.assertEqual(set(fixture["engines"]), {"lab.first", "lab.second"})
        status = self.store.status()
        self.assertEqual(status["counts"]["finding_disagreements"], 1)
        self.assertEqual(len(status["disagreements"]), 1)

    def test_lineage_deduplicates_content_and_rejects_self_and_ancestry_loops(self):
        scratch = self.work / "scratch"
        scratch.mkdir()
        child = scratch / "child"
        child.write_bytes(b"inert child")
        first = self.store.register_artifact(
            child,
            parent_path=self.original,
            relationship="decoded",
            label="decoded child",
            producer_tool="lab.fixture",
        )
        repeated = self.store.register_artifact(
            child,
            parent_path=self.original,
            relationship="decoded",
            label="decoded child",
            producer_tool="lab.fixture",
        )
        grandchild = scratch / "grandchild"
        grandchild.write_bytes(b"inert grandchild")
        grandchild_record = self.store.register_artifact(
            grandchild,
            parent_path=Path(first["path"]),
            relationship="unpacked",
            label="unpacked grandchild",
            producer_tool="lab.fixture",
        )

        self.assertFalse(first["deduplicated"])
        self.assertTrue(repeated["deduplicated"])
        self.assertEqual(grandchild_record["lineage_depth"], 2)
        with self.assertRaisesRegex(ValueError, "loop"):
            self.store.register_artifact(
                self.original,
                parent_path=self.original,
                relationship="loop",
                label="self loop",
                producer_tool="lab.fixture",
            )
        with self.assertRaisesRegex(ValueError, "cycle"):
            self.store.register_artifact(
                self.original,
                parent_path=Path(grandchild_record["path"]),
                relationship="loop",
                label="ancestry loop",
                producer_tool="lab.fixture",
            )
        lineage = json.loads(self.store.lineage_path.read_text())
        self.assertEqual(lineage["schema"], LINEAGE_SCHEMA)
        self.assertEqual(
            lineage["artifacts"][first["sha256"]]["parents"][0]["sha256"],
            self.original_sha256,
        )
        inventory = self.store.artifact_inventory()
        self.assertEqual(inventory["total"], 3)
        self.assertFalse(inventory["truncated"])

    def test_identical_output_in_a_new_plan_keeps_distinct_plan_provenance(self):
        first, _ = self.record()
        second_plan = self.plan | {"plan_id": "fedcba9876543210"}
        self.store.ensure_plan(second_plan)
        second, _ = self.store.record_result(
            plan_id=second_plan["plan_id"],
            step_id="triage.first",
            tool_name="lab.first",
            normalized={"status": "success", "gap": None},
            result={"summary": {"family": "Fixture"}},
            error=None,
        )
        self.assertNotEqual(first["evidence_id"], second["evidence_id"])
        persisted = json.loads(
            (self.store.evidence_dir / f"{second['evidence_id']}.json").read_text()
        )
        self.assertEqual(persisted["plan_id"], second_plan["plan_id"])

    def test_legacy_derived_artifact_must_be_relinked_not_assumed(self):
        derived_dir = self.work / "samples" / "derived"
        derived_dir.mkdir()
        data = b"legacy child"
        digest = hashlib.sha256(data).hexdigest()
        legacy = derived_dir / digest
        legacy.write_bytes(data)
        inventory = self.store.artifact_inventory()
        legacy_entry = next(
            artifact for artifact in inventory["artifacts"]
            if artifact["sha256"] == digest
        )
        self.assertTrue(legacy_entry["legacy_unlinked"])
        self.store.record_observation(
            artifact_path=legacy,
            step_id="legacy.inspect",
            tool_name="lab.fixture",
            command_arguments={"path": str(legacy)},
            normalized={"status": "success", "gap": None},
            result={"summary": "legacy"},
            error=None,
        )
        before = self.store.audit()
        self.assertIn(
            "unlinked_derived_artifact",
            {issue["kind"] for issue in before["issues"]},
        )

        self.store.register_artifact(
            legacy,
            parent_path=self.original,
            relationship="legacy-migration",
            label="relinked legacy child",
            producer_tool="lab.register_derived",
        )
        self.assertTrue(self.store.audit()["ok"])

    def test_claim_audit_detects_changed_retained_output(self):
        evidence, _ = self.record()
        claim = self.store.link_claim(
            statement="The fixture family was observed.",
            evidence_ids=[evidence["evidence_id"]],
            claim_type="annotation",
            location="0x401000",
            confidence="confirmed",
        )
        clean = self.store.audit(claim["claim_id"])
        self.assertEqual(claim["schema"], CLAIM_SCHEMA)
        self.assertEqual(clean["schema"], AUDIT_SCHEMA)
        self.assertTrue(clean["ok"])

        retained_path = Path(evidence["retained_output"]["path"])
        retained_path.chmod(0o644)
        retained_path.write_text("changed")
        changed = self.store.audit(claim["claim_id"])
        self.assertFalse(changed["ok"])
        self.assertIn("output_digest_mismatch", {issue["kind"] for issue in changed["issues"]})

    def test_named_tool_output_is_copied_to_immutable_content_storage(self):
        output = self.work / "out" / "tool.json"
        output.parent.mkdir(parents=True)
        output.write_text('{"observation": "first"}\n')
        evidence, _ = self.record(result={
            "summary": {"ok": True}, "saved_to": str(output),
        })
        claim = self.store.link_claim(
            statement="The first observation was retained.",
            evidence_ids=[evidence["evidence_id"]],
        )
        retained = Path(evidence["retained_output"]["path"])
        self.assertNotEqual(retained, output)
        self.assertEqual(evidence["retained_output"]["source_path"], str(output))
        self.assertEqual(retained.read_text(), output.read_text())

        output.write_text('{"observation": "second"}\n')
        self.assertTrue(self.store.audit(claim["claim_id"])["ok"])
        self.assertIn("first", retained.read_text())

    def test_self_check_covers_every_state_contract(self):
        result = evidence_self_check()
        self.assertTrue(result["ok"])
        self.assertTrue(all(result["checks"].values()))


class EvidenceServerIntegrationTests(unittest.TestCase):
    def test_plan_normalization_and_replan_resume_end_to_end(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary) / "work"
            samples = work / "samples"
            original_dir = samples / "original"
            original_dir.mkdir(parents=True)
            data = b"\0asm\x01\0\0\0"
            digest = hashlib.sha256(data).hexdigest()
            target = original_dir / digest
            target.write_bytes(data)
            out = work / "out"
            with (
                patch.object(server, "WORK", work),
                patch.object(server, "SAMPLES", samples),
                patch.object(server, "DERIVED", samples / "derived"),
                patch.object(server, "OUT", out),
            ):
                plan = server.analysis_plan(f"original/{digest}")
                step = plan["selected"][0]
                normalized = server.normalize_analysis_result(
                    step["id"], step["tool"],
                    result={"summary": {"ok": True}},
                    plan_id=plan["plan_id"],
                    findings=[{"subject": "fixture.result", "value": "ok"}],
                )
                standalone = server.normalize_analysis_result(
                    "deep.manual-function",
                    "ghidra.decompile_function",
                    result={"summary": "returns a fixed inert value"},
                    artifact_path=f"original/{digest}",
                    command_arguments={"name_or_address": "entry"},
                    tool_version="pyghidra-mcp fixture",
                )
                resumed = server.analysis_plan(f"original/{digest}")
                audit = server.audit_evidence()

            self.assertTrue(normalized["evidence_record"]["evidence_id"].startswith("ev_"))
            self.assertIn(step["id"], resumed["checkpoint"]["completed_steps"])
            resumed_step = next(item for item in resumed["selected"] if item["id"] == step["id"])
            self.assertEqual(resumed_step["checkpoint_state"], "completed")
            self.assertNotIn(step["id"], resumed["checkpoint"]["remaining_ready_steps"])
            self.assertIsNone(standalone["evidence_record"]["plan_id"])
            self.assertEqual(standalone["evidence_record"]["command"]["role"], "standalone")
            self.assertTrue(audit["ok"])

    def test_manual_registration_requires_and_returns_parent_lineage(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary) / "work"
            samples = work / "samples"
            original_dir = samples / "original"
            scratch = work / "scratch"
            original_dir.mkdir(parents=True)
            scratch.mkdir(parents=True)
            original_data = b"parent"
            digest = hashlib.sha256(original_data).hexdigest()
            original = original_dir / digest
            original.write_bytes(original_data)
            child = scratch / "decoded.bin"
            child.write_bytes(b"child")
            with (
                patch.object(server, "WORK", work),
                patch.object(server, "SAMPLES", samples),
                patch.object(server, "DERIVED", samples / "derived"),
                patch.object(server, "OUT", work / "out"),
            ):
                registration = server.register_derived(
                    str(child), "decoded payload", f"original/{digest}", "decoded",
                )

            self.assertEqual(registration["parent_sha256"], digest)
            self.assertEqual(registration["relationship"], "decoded")
            self.assertTrue(Path(registration["path"]).is_file())


if __name__ == "__main__":
    unittest.main()
