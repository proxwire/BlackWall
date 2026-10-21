import asyncio
import json
import unittest

from blackwall_lab import ghidra_ready


class Result:
    def __init__(self, *, structured=None, text=None):
        self.structuredContent = structured
        self.content = [] if text is None else [type("Text", (), {"text": text})()]


class GhidraReadinessTests(unittest.TestCase):
    def test_analysis_and_search_readiness_are_separate(self):
        status = ghidra_ready.readiness_status(
            [
                {
                    "name": "fixture",
                    "analysis_complete": True,
                    "code_indexed": False,
                    "strings_indexed": True,
                }
            ]
        )
        self.assertTrue(status["ready"])
        self.assertTrue(status["analysis_ready"])
        self.assertFalse(status["search_ready"])

    def test_empty_project_is_ready_for_non_importable_case_formats(self):
        status = ghidra_ready.readiness_status([])
        self.assertTrue(status["ready"])
        self.assertEqual(status["program_count"], 0)

    def test_result_parser_accepts_structured_and_text_content(self):
        fixture = {"programs": [{"name": "a", "analysis_complete": True}]}
        self.assertEqual(
            ghidra_ready._programs_from_result(Result(structured=fixture)),
            fixture["programs"],
        )
        self.assertEqual(
            ghidra_ready._programs_from_result(Result(text=json.dumps(fixture))),
            fixture["programs"],
        )

    def test_malformed_program_status_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "malformed"):
            ghidra_ready.readiness_status([{"analysis_complete": True}])

    def test_dead_service_process_fails_without_waiting_for_deadline(self):
        with self.assertRaisesRegex(RuntimeError, "exited during startup"):
            asyncio.run(
                ghidra_ready.wait_until_ready(
                    "http://127.0.0.1:1/mcp",
                    timeout=60,
                    interval=1,
                    require_indexes=False,
                    state_file=None,
                    watch_pid=999_999_999,
                )
            )


if __name__ == "__main__":
    unittest.main()
