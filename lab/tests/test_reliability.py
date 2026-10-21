import json
import os
import shlex
import signal
import sys
import tempfile
import threading
import time
import unittest
from collections import namedtuple
from pathlib import Path
from unittest.mock import patch

from blackwall_lab import reliability


class ProcessSupervisionTests(unittest.TestCase):
    def test_timeout_kills_complete_process_group(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "timeout-orphan"
            command = (
                f"(sleep 0.3; printf orphan > {shlex.quote(str(marker))}) & wait"
            )
            result = reliability.run_bounded(
                command, timeout=0.05, cwd=Path(directory), shell=True,
            )
            time.sleep(0.35)
        self.assertEqual(result["status"], "timeout")
        self.assertTrue(result["timed_out"])
        self.assertFalse(marker.exists())

    def test_cooperative_cancel_kills_complete_process_group(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "cancel-orphan"
            command = (
                f"(sleep 0.3; printf orphan > {shlex.quote(str(marker))}) & wait"
            )
            event = threading.Event()
            timer = threading.Timer(0.05, event.set)
            timer.start()
            try:
                result = reliability.run_bounded(
                    command,
                    timeout=2,
                    cwd=Path(directory),
                    shell=True,
                    cancel_event=event,
                )
            finally:
                timer.cancel()
            time.sleep(0.35)
        self.assertEqual(result["status"], "cancelled")
        self.assertTrue(result["cancelled"])
        self.assertFalse(marker.exists())

    @unittest.skipUnless(hasattr(os, "kill"), "requires POSIX signals")
    def test_parser_signal_crash_is_distinct_from_normal_failure(self):
        result = reliability.run_bounded(
            [
                sys.executable,
                "-c",
                "import os, signal; os.kill(os.getpid(), signal.SIGKILL)",
            ],
            timeout=2,
            cwd=Path("/tmp"),
        )
        self.assertEqual(result["status"], "crashed")
        self.assertEqual(result["termination_signal"], signal.SIGKILL)
        self.assertFalse(result["timed_out"])


class DiagnosticTests(unittest.TestCase):
    def test_diagnostic_reports_candidates_without_changing_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            evidence = work / "state" / "evidence"
            evidence.mkdir(parents=True)
            record = evidence / "ev_000000000000000000000000.json"
            record.write_text(json.dumps({"status": "failed"}), encoding="utf-8")
            scratch = work / "scratch" / "extract.partial"
            scratch.mkdir(parents=True)
            (scratch / "fragment").write_bytes(b"fixture")
            before = record.read_bytes()

            report = reliability.diagnose_workspace(work, min_free_bytes=0)

            self.assertEqual(record.read_bytes(), before)
            self.assertFalse(report["cleanup_performed"])
            self.assertEqual(report["retained"]["evidence_records"], 1)
            self.assertEqual(report["retained"]["outcomes"], {"failed": 1})
            self.assertEqual(report["cleanup_candidate_count"], 1)
            self.assertIn(str(work / "state"), report["protected_paths"])

    def test_low_disk_is_actionable_and_does_not_recommend_evidence_deletion(self):
        usage = namedtuple("usage", "total used free")(1_000, 990, 10)
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(reliability.shutil, "disk_usage", return_value=usage):
                report = reliability.diagnose_workspace(
                    Path(directory), min_free_bytes=100,
                )

        self.assertEqual(report["health"], "critical")
        self.assertIn("only 10 bytes", report["errors"][0])
        self.assertIn("Preserve /work/state", report["actions"][0])
        self.assertFalse(report["cleanup_performed"])

    def test_corrupt_retained_json_is_reported_not_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            evidence = work / "state" / "evidence"
            evidence.mkdir(parents=True)
            record = evidence / "ev_000000000000000000000000.json"
            record.write_text("{broken", encoding="utf-8")

            report = reliability.diagnose_workspace(work, min_free_bytes=0)

            self.assertTrue(record.exists())
            self.assertEqual(report["health"], "critical")
            self.assertEqual(len(report["corrupt_state"]), 1)
            self.assertIn("do not delete corrupt state", " ".join(report["actions"]))


if __name__ == "__main__":
    unittest.main()
