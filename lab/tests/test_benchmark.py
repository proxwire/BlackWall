import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from blackwall_lab import benchmark

ROOT = Path(__file__).resolve().parents[2]
INERT_MANIFEST = ROOT / "benchmarks" / "corpus" / "inert-manifest.json"
MALWARE_MANIFEST = ROOT / "benchmarks" / "corpus" / "malware-manifest.json"


class BenchmarkCorpusTests(unittest.TestCase):
    def test_inert_corpus_hashes_and_routes_are_admitted(self):
        manifest = benchmark.load_manifest(INERT_MANIFEST)
        fixtures = benchmark.resolve_fixtures(manifest)

        self.assertEqual(len(fixtures), 11)
        self.assertEqual({item[0]["id"] for item in fixtures}, {
            "native-pe", "packed-pe", "dotnet", "elf", "apk", "javascript",
            "wasm", "office", "rtf", "pdf", "pcap",
        })
        self.assertTrue(all(path.is_file() for _, path in fixtures))

        check = benchmark.benchmark_self_check(INERT_MANIFEST)
        self.assertTrue(check["ok"])
        self.assertEqual(check["fixtures"], 11)
        self.assertEqual(check["lanes"], list(benchmark.LANES))

    def test_plan_records_all_lanes_without_making_execution_claims(self):
        result = benchmark.run_benchmark(
            INERT_MANIFEST,
            mode="plan",
            fixture_ids={"packed-pe", "wasm"},
        )

        self.assertEqual(result["schema"], benchmark.RESULT_SCHEMA)
        self.assertEqual(result["corpus"]["fixture_count"], 2)
        for fixture in result["fixtures"]:
            self.assertEqual([lane["lane"] for lane in fixture["lanes"]], list(benchmark.LANES))
            for lane in fixture["lanes"]:
                self.assertEqual(lane["status"], "planned")
                self.assertIsNone(lane["wall_seconds"])
                self.assertEqual(lane["metrics"]["tool_success"]["attempted"], 0)
                self.assertEqual(lane["metrics"]["useful_evidence"]["status"], "not_measured")
        packed = next(item for item in result["fixtures"] if item["id"] == "packed-pe")
        self.assertEqual(packed["route"]["detection"]["packing"]["state"], "likely_packed")

        wasm = next(item for item in result["fixtures"] if item["id"] == "wasm")
        self.assertNotIn(
            "lab.binwalk_scan",
            {operation["tool"] for operation in wasm["lanes"][0]["operations"]},
        )

        changed_plan = json.loads(json.dumps(result))
        changed_plan["fixtures"][0]["route"]["plan_id"] = "changed-plan"
        identity = {
            "corpus": result["corpus"]["id"],
            "mode": result["mode"],
            "lanes": list(benchmark.LANES),
            "fixtures": [item["sha256"] for item in changed_plan["fixtures"]],
            "plans": [item["route"]["plan_id"] for item in changed_plan["fixtures"]],
        }
        changed_id = benchmark.hashlib.sha256(
            json.dumps(identity, sort_keys=True, separators=(",", ":")).encode(),
        ).hexdigest()[:16]
        self.assertNotEqual(changed_id, result["run_id"])

    def test_core_binwalk_keeps_its_narrow_timeout(self):
        fixture = next(
            item
            for item in benchmark.load_manifest(INERT_MANIFEST)["fixtures"]
            if item["id"] == "office"
        )
        binwalk = next(
            step
            for step in benchmark._core_steps(fixture, 300)
            if step["tool"] == "lab.binwalk_scan"
        )
        self.assertEqual(binwalk["deadline_seconds"], 30)
        self.assertEqual(binwalk["arguments"]["timeout"], 30)

    def test_malware_manifest_is_hash_only_and_requires_opt_in(self):
        manifest = benchmark.load_manifest(MALWARE_MANIFEST)
        self.assertEqual(manifest["kind"], "malware")
        self.assertTrue(all("path" not in fixture for fixture in manifest["fixtures"]))

        with self.assertRaisesRegex(benchmark.BenchmarkError, "--allow-malware"):
            benchmark.resolve_fixtures(manifest)
        with tempfile.TemporaryDirectory() as temporary:
            with patch.dict(os.environ, {"CI": "true"}):
                with self.assertRaisesRegex(benchmark.BenchmarkError, "forbidden"):
                    benchmark.resolve_fixtures(
                        manifest,
                        samples_dir=Path(temporary),
                        allow_malware=True,
                    )

    def test_hash_mismatch_fails_before_routing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "fixtures").mkdir()
            (root / "corpus").mkdir()
            (root / "fixtures" / "sample.js").write_text("changed")
            manifest = {
                "schema": benchmark.CORPUS_SCHEMA,
                "id": "tamper-test",
                "kind": "inert",
                "network_policy": "offline",
                "fixtures": [{
                    "id": "sample",
                    "path": "../fixtures/sample.js",
                    "sha256": "0" * 64,
                    "raw_rea": {"workflow": "javascript"},
                    "expected": {"router_format": "javascript"},
                }],
            }
            path = root / "corpus" / "manifest.json"
            path.write_text(json.dumps(manifest))
            loaded = benchmark.load_manifest(path)
            with self.assertRaisesRegex(benchmark.BenchmarkError, "hash mismatch"):
                benchmark.resolve_fixtures(loaded)

    def test_report_accuracy_is_separate_from_tool_evidence(self):
        fixture = benchmark.load_manifest(INERT_MANIFEST)["fixtures"][0]
        self.assertEqual(
            benchmark._report_score(None, fixture, "core")["status"],
            "not_measured",
        )
        with tempfile.TemporaryDirectory() as temporary:
            report_dir = Path(temporary) / fixture["id"]
            report_dir.mkdir()
            report_dir.joinpath("core.md").write_text(
                "BLACKWALL_INERT_NATIVE_FIXTURE\n"
                "https://native.fixture.invalid/api\n"
                "campaign=native-inert\n"
            )
            score = benchmark._report_score(Path(temporary), fixture, "core")
        self.assertEqual(score["status"], "measured")
        self.assertEqual(score["matched"], 3)
        self.assertEqual(score["score"], 1.0)

    def test_workspace_paths_are_normalized_before_output_hashing(self):
        root = Path("/tmp/blackwall-benchmark-random")
        value = {"path": f"{root}/work/samples/original/hash", "nested": [str(root)]}
        normalized = benchmark._normalize_workspace_paths(value, root)
        self.assertEqual(
            normalized,
            {
                "path": "<benchmark-workspace>/work/samples/original/hash",
                "nested": ["<benchmark-workspace>"],
            },
        )

    def test_lane_status_preserves_a_uniform_unsupported_outcome(self):
        self.assertEqual(
            benchmark._lane_status([{"status": "unsupported"}]),
            "unsupported",
        )
        self.assertEqual(
            benchmark._lane_status([{"status": "success"}, {"status": "timeout"}]),
            "partial",
        )

    def test_machine_and_markdown_results_are_written_together(self):
        result = benchmark.run_benchmark(
            INERT_MANIFEST,
            mode="plan",
            lanes=("core",),
            fixture_ids={"javascript"},
        )
        with tempfile.TemporaryDirectory() as temporary:
            json_path, markdown_path = benchmark.write_results(
                result, Path(temporary) / "result",
            )
            decoded = json.loads(json_path.read_text())
            markdown = markdown_path.read_text()
        self.assertEqual(decoded["run_id"], result["run_id"])
        self.assertIn("| javascript | javascript | core | planned |", markdown)
        self.assertIn("Plan mode checks corpus integrity", markdown)


if __name__ == "__main__":
    unittest.main()
