"""Repeatable, offline comparison harness for BlackWall analysis lanes.

The harness has no networking or sample-acquisition code.  Inert corpus runs
are the default.  A malware corpus requires an explicit flag, is refused in
CI, and resolves only caller-supplied files whose names and bytes match the
manifest SHA-256 values.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Iterator

from .router import build_analysis_plan

CORPUS_SCHEMA = "blackwall.benchmark-corpus.v1"
RESULT_SCHEMA = "blackwall.benchmark-result.v1"
LANES = ("core", "raw-rea", "hybrid")
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_EVIDENCE_BYTES = 8 * 1024 * 1024
MAX_EXCERPT_CHARS = 12_000

_CORE_COMMON = (
    "lab.file_overview",
    "lab.yara_scan",
    "lab.strings",
    "lab.extract_iocs",
)
_CORE_BY_FORMAT = {
    "pe": ("lab.pe_info", "lab.floss", "lab.capa"),
    "dotnet": ("lab.pe_info", "lab.dotnet_info"),
    "elf": ("lab.elf_info", "lab.capa"),
    "ooxml-word": ("lab.binwalk_scan",),
    "rtf": ("lab.binwalk_scan",),
    "pdf": ("lab.binwalk_scan",),
}
_RUNNABLE_LAB_TOOLS = frozenset({
    "lab.binwalk_scan",
    "lab.capa",
    "lab.dotnet_info",
    "lab.elf_info",
    "lab.extract_iocs",
    "lab.file_overview",
    "lab.floss",
    "lab.pe_info",
    "lab.rea_managed_members",
    "lab.rea_static_analysis",
    "lab.strings",
    "lab.upx_unpack",
    "lab.yara_scan",
})


class BenchmarkError(RuntimeError):
    """Raised when corpus admission or harness invariants fail."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json(path: Path) -> dict:
    if not path.is_file():
        raise BenchmarkError(f"manifest not found: {path}")
    if path.stat().st_size > MAX_MANIFEST_BYTES:
        raise BenchmarkError(f"manifest exceeds {MAX_MANIFEST_BYTES} bytes: {path}")
    try:
        value = json.loads(path.read_text())
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BenchmarkError(f"invalid JSON manifest {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise BenchmarkError("manifest root must be an object")
    return value


def load_manifest(path: Path) -> dict:
    """Load and fail-closed validate a benchmark corpus manifest."""
    path = path.resolve()
    manifest = _read_json(path)
    if manifest.get("schema") != CORPUS_SCHEMA:
        raise BenchmarkError(f"manifest schema must be {CORPUS_SCHEMA}")
    kind = manifest.get("kind")
    if kind not in {"inert", "malware"}:
        raise BenchmarkError("manifest kind must be inert or malware")
    if manifest.get("network_policy") != "offline":
        raise BenchmarkError("benchmark corpora must declare network_policy=offline")
    fixtures = manifest.get("fixtures")
    if not isinstance(fixtures, list) or not fixtures:
        raise BenchmarkError("manifest fixtures must be a non-empty array")

    identifiers: set[str] = set()
    for fixture in fixtures:
        if not isinstance(fixture, dict):
            raise BenchmarkError("each fixture must be an object")
        fixture_id = fixture.get("id")
        digest = fixture.get("sha256")
        if not isinstance(fixture_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", fixture_id):
            raise BenchmarkError(f"invalid fixture id: {fixture_id!r}")
        if fixture_id in identifiers:
            raise BenchmarkError(f"duplicate fixture id: {fixture_id}")
        identifiers.add(fixture_id)
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise BenchmarkError(f"invalid SHA-256 for fixture {fixture_id}")
        workflow = fixture.get("raw_rea", {}).get("workflow")
        if not isinstance(workflow, str) or not workflow:
            raise BenchmarkError(f"fixture {fixture_id} lacks a raw REA workflow")
        if kind == "inert":
            relative = fixture.get("path")
            if not isinstance(relative, str) or Path(relative).is_absolute():
                raise BenchmarkError(f"inert fixture {fixture_id} needs a relative path")
            expected = fixture.get("expected", {})
            if not isinstance(expected.get("router_format"), str):
                raise BenchmarkError(f"inert fixture {fixture_id} lacks expected.router_format")
        elif "path" in fixture:
            raise BenchmarkError("malware manifests must be hash-only and cannot contain paths")
    manifest["_manifest_path"] = str(path)
    return manifest


def _ci_environment() -> bool:
    return os.environ.get("CI", "").strip().lower() not in {"", "0", "false", "no"}


def resolve_fixtures(
    manifest: dict,
    *,
    samples_dir: Path | None = None,
    allow_malware: bool = False,
    selected: set[str] | None = None,
) -> list[tuple[dict, Path]]:
    """Resolve admitted files without ever acquiring or unpacking a sample."""
    kind = manifest["kind"]
    manifest_path = Path(manifest["_manifest_path"])
    if kind == "malware":
        if not allow_malware:
            raise BenchmarkError("malware corpus requires --allow-malware")
        if _ci_environment():
            raise BenchmarkError("malware corpus execution is forbidden when CI is set")
        if samples_dir is None:
            raise BenchmarkError("malware corpus requires --samples-dir")
        samples_root = samples_dir.resolve()
        if not samples_root.is_dir():
            raise BenchmarkError(f"samples directory not found: {samples_root}")
    else:
        samples_root = manifest_path.parent

    resolved = []
    known_ids = {fixture["id"] for fixture in manifest["fixtures"]}
    unknown = (selected or set()) - known_ids
    if unknown:
        raise BenchmarkError(f"unknown fixture ids: {', '.join(sorted(unknown))}")
    for fixture in manifest["fixtures"]:
        if selected and fixture["id"] not in selected:
            continue
        if kind == "malware":
            path = samples_root / fixture["sha256"]
        else:
            path = (manifest_path.parent / fixture["path"]).resolve()
            corpus_root = manifest_path.parent.parent.resolve()
            if not path.is_relative_to(corpus_root):
                raise BenchmarkError(f"fixture escapes corpus root: {fixture['id']}")
        if not path.is_file():
            raise BenchmarkError(f"fixture not found: {fixture['id']} ({path})")
        observed = _sha256(path)
        if observed != fixture["sha256"]:
            raise BenchmarkError(
                f"fixture hash mismatch for {fixture['id']}: "
                f"expected {fixture['sha256']}, got {observed}"
            )
        resolved.append((fixture, path))
    return resolved


def _step(step_id: str, tool: str, deadline: int, **arguments: object) -> dict:
    return {
        "id": step_id,
        "state": "ready",
        "tool": tool,
        "arguments": dict(arguments),
        "deadline_seconds": deadline,
    }


def _core_steps(fixture: dict, timeout: int) -> list[dict]:
    fmt = fixture.get("expected", {}).get("router_format") or fixture.get("format", "unknown")
    tools = list(_CORE_COMMON)
    tools[2:2] = _CORE_BY_FORMAT.get(fmt, ())
    if "upx" in fixture.get("labels", []):
        tools.extend(("lab.binwalk_scan", "lab.upx_unpack"))
    steps = []
    for index, tool in enumerate(dict.fromkeys(tools)):
        arguments: dict[str, object] = {}
        deadline = min(timeout, 30) if tool == "lab.binwalk_scan" else timeout
        if tool in {"lab.capa", "lab.floss", "lab.binwalk_scan"}:
            arguments["timeout"] = deadline
        steps.append(_step(
            f"core.{index:02d}.{tool.rsplit('.', 1)[-1]}",
            tool,
            deadline,
            **arguments,
        ))
    return steps


def _raw_rea_steps(fixture: dict, timeout: int) -> list[dict]:
    workflow = fixture["raw_rea"]["workflow"]
    if workflow == "native_overview":
        return [_step("raw-rea.native-overview", "lab.rea_native_overview", timeout, timeout=timeout)]
    return [_step(
        f"raw-rea.{workflow}", "lab.rea_static_analysis", timeout,
        workflow=workflow, timeout=timeout,
    )]


def _hybrid_steps(plan: dict, timeout: int) -> list[dict]:
    steps = []
    for source in plan["selected"]:
        copied = {
            "id": source["id"],
            "state": source["state"],
            "tool": source["tool"],
            "arguments": {
                key: value for key, value in source["arguments"].items() if key != "path"
            },
            "deadline_seconds": min(source["deadline_seconds"], timeout),
        }
        if "timeout" in copied["arguments"]:
            copied["arguments"]["timeout"] = min(int(copied["arguments"]["timeout"]), timeout)
        steps.append(copied)
    return steps


def _planned_lane(lane: str, steps: list[dict]) -> dict:
    ready = [step for step in steps if step["state"] == "ready"]
    return {
        "lane": lane,
        "status": "planned",
        "wall_seconds": None,
        "operations": [
            {
                "id": step["id"],
                "tool": step["tool"],
                "status": "not_run",
                "deadline_seconds": step["deadline_seconds"],
                "arguments": step["arguments"],
            }
            for step in steps
        ],
        "metrics": {
            "tool_success": {"succeeded": 0, "attempted": 0, "rate": None},
            "timeouts": 0,
            "useful_evidence": _not_measured(),
            "iocs": _not_measured(),
            "configuration": _not_measured(),
            "analyst_report_accuracy": _not_measured(),
        },
        "ready_operations": len(ready),
        "deferred_operations": len(steps) - len(ready),
    }


@contextlib.contextmanager
def _staged_workspace(path: Path, digest: str) -> Iterator[tuple[str, Path]]:
    """Stage one immutable fixture under the same layout as a real case."""
    from . import server

    with tempfile.TemporaryDirectory(prefix="blackwall-benchmark-") as temporary:
        root = Path(temporary)
        work = root / "work"
        samples = work / "samples"
        original = samples / "original"
        derived = samples / "derived"
        out = work / "out"
        case = root / "case"
        for directory in (original, derived, out, case):
            directory.mkdir(parents=True, exist_ok=True)
        target = original / digest
        shutil.copyfile(path, target)
        target.chmod(0o444)
        previous = (server.WORK, server.SAMPLES, server.DERIVED, server.OUT, server.CASE)
        server.WORK, server.SAMPLES, server.DERIVED = work, samples, derived
        server.OUT, server.CASE = out, case
        try:
            yield f"original/{digest}", out
        finally:
            server.WORK, server.SAMPLES, server.DERIVED, server.OUT, server.CASE = previous


def _tool_function(tool_name: str):
    from . import server

    name = tool_name.removeprefix("lab.")
    function = getattr(server, name, None)
    if not callable(function):
        raise BenchmarkError(f"benchmark dispatcher has no callable for {tool_name}")
    return function


def _string_values(value: object) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _string_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from _string_values(item)


def _normalize_workspace_paths(value: object, workspace_root: Path) -> object:
    marker = str(workspace_root.resolve())
    if isinstance(value, str):
        return value.replace(marker, "<benchmark-workspace>")
    if isinstance(value, dict):
        return {
            key: _normalize_workspace_paths(item, workspace_root)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_normalize_workspace_paths(item, workspace_root) for item in value]
    return value


def _retained_evidence(result: dict, out: Path) -> tuple[str, list[dict]]:
    workspace_root = out.parents[1]
    texts = [json.dumps(result, sort_keys=True, default=str), *_string_values(result)]
    retained = []

    def visit(value: object) -> Iterator[str]:
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "saved_to" and isinstance(item, str):
                    yield item
                else:
                    yield from visit(item)
        elif isinstance(value, list):
            for item in value:
                yield from visit(item)

    for raw_path in dict.fromkeys(visit(result)):
        path = Path(raw_path)
        try:
            resolved = path.resolve()
        except OSError:
            continue
        if not resolved.is_file() or not resolved.is_relative_to(out.resolve()):
            continue
        size = resolved.stat().st_size
        digest = _sha256(resolved)
        metadata = {"name": resolved.name, "size": size, "sha256": digest}
        if size <= MAX_EVIDENCE_BYTES:
            try:
                raw_text = resolved.read_text(errors="replace")
                normalized_text = raw_text.replace(
                    str(workspace_root.resolve()), "<benchmark-workspace>",
                )
                metadata["normalized_sha256"] = hashlib.sha256(
                    normalized_text.encode(),
                ).hexdigest()
                texts.append(raw_text)
                try:
                    texts.extend(_string_values(json.loads(raw_text)))
                except json.JSONDecodeError:
                    pass
            except OSError:
                pass
        retained.append(metadata)
    return "\n".join(texts), retained


def _execute_step(step: dict, sample_path: str, out: Path) -> tuple[dict, str, str | None]:
    from .router import normalize_result

    tool_name = step["tool"]
    if step["state"] != "ready":
        return ({
            "id": step["id"], "tool": tool_name, "status": "not_run",
            "reason": "router marked this step deferred", "wall_seconds": 0.0,
        }, "", None)
    if tool_name.startswith("ghidra."):
        return ({
            "id": step["id"], "tool": tool_name, "status": "not_run",
            "reason": "persistent Ghidra is MCP-only and outside this CLI harness",
            "wall_seconds": 0.0,
        }, "", None)
    if tool_name not in _RUNNABLE_LAB_TOOLS and tool_name != "lab.rea_native_overview":
        return ({
            "id": step["id"], "tool": tool_name, "status": "not_run",
            "reason": "tool is outside the benchmark dispatch allowlist",
            "wall_seconds": 0.0,
        }, "", None)

    arguments = dict(step["arguments"])
    arguments["path"] = sample_path
    started = time.monotonic()
    raw: dict
    try:
        value = _tool_function(tool_name)(**arguments)
        raw = value if isinstance(value, dict) else {"output": value}
        normalized = normalize_result(step["id"], tool_name, result=raw)
    except Exception as exc:  # Tool failures are benchmark observations.
        raw = {"error": f"{type(exc).__name__}: {exc}"}
        normalized = normalize_result(step["id"], tool_name, error=raw["error"])
    elapsed = round(time.monotonic() - started, 6)
    evidence, retained = _retained_evidence(raw, out)
    normalized_raw = _normalize_workspace_paths(raw, out.parents[1])
    encoded = json.dumps(normalized_raw, sort_keys=True, default=str)
    unpacked = raw.get("unpacked") if raw.get("ok") is True else None
    operation = {
        "id": step["id"],
        "tool": tool_name,
        "status": normalized["status"],
        "wall_seconds": elapsed,
        "timed_out": normalized["observed"]["timed_out"],
        "has_evidence": normalized["observed"]["has_evidence"],
        "output_sha256": hashlib.sha256(encoded.encode()).hexdigest(),
        "output_excerpt": encoded[:MAX_EXCERPT_CHARS],
        "output_truncated": len(encoded) > MAX_EXCERPT_CHARS,
        "retained_evidence": retained,
        "gap": _normalize_workspace_paths(normalized["gap"], out.parents[1]),
    }
    return operation, evidence, unpacked if isinstance(unpacked, str) else None


def _not_measured(reason: str = "no executed evidence") -> dict:
    return {"status": "not_measured", "score": None, "reason": reason}


def _score_groups(text: str, groups: list[dict]) -> dict:
    if not groups:
        return {"status": "not_applicable", "matched": 0, "total": 0, "score": None}
    lowered = text.casefold()
    details = []
    for group in groups:
        terms = group.get("terms", [])
        mode = group.get("match", "all")
        hits = [isinstance(term, str) and term.casefold() in lowered for term in terms]
        matched = bool(hits) and (any(hits) if mode == "any" else all(hits))
        details.append({"id": group.get("id"), "matched": matched})
    count = sum(item["matched"] for item in details)
    return {
        "status": "measured",
        "matched": count,
        "total": len(details),
        "score": round(count / len(details), 4),
        "details": details,
    }


def _score_values(text: str, values: list[str]) -> dict:
    groups = [{"id": value, "terms": [value]} for value in values]
    return _score_groups(text, groups)


def _report_score(reports_dir: Path | None, fixture: dict, lane: str) -> dict:
    if reports_dir is None:
        return _not_measured("no --reports-dir supplied")
    root = reports_dir.resolve()
    fixture_dir = (root / fixture["id"]).resolve()
    if not fixture_dir.is_relative_to(root):
        raise BenchmarkError("report path escaped reports root")
    candidates = (fixture_dir / f"{lane}.md", fixture_dir / f"{lane}.json")
    report = next((path for path in candidates if path.is_file()), None)
    if report is None:
        return _not_measured(f"no report for {fixture['id']}/{lane}")
    if report.stat().st_size > MAX_EVIDENCE_BYTES:
        raise BenchmarkError(f"analyst report is too large: {report}")
    claims = fixture.get("expected", {}).get("report_claims")
    if claims is None:
        claims = [
            {"id": f"coarse-{index}", "terms": [finding]}
            for index, finding in enumerate(
                fixture.get("expected", {}).get("coarse_findings", []), 1
            )
        ]
    result = _score_groups(report.read_text(errors="replace"), claims)
    result["source"] = str(report)
    return result


def _metrics(evidence: str, expected: dict, report_score: dict, operations: list[dict]) -> dict:
    attempted = [operation for operation in operations if operation["status"] != "not_run"]
    succeeded = sum(operation["status"] == "success" for operation in attempted)
    return {
        "tool_success": {
            "succeeded": succeeded,
            "attempted": len(attempted),
            "rate": round(succeeded / len(attempted), 4) if attempted else None,
        },
        "timeouts": sum(operation.get("timed_out", False) for operation in attempted),
        "useful_evidence": _score_groups(evidence, expected.get("useful_evidence", [])),
        "iocs": _score_values(evidence, expected.get("iocs", [])),
        "configuration": _score_values(evidence, expected.get("configuration", [])),
        "analyst_report_accuracy": report_score,
    }


def _lane_status(operations: list[dict]) -> str:
    attempted = [operation for operation in operations if operation["status"] != "not_run"]
    if not attempted:
        return "not_run"
    statuses = {operation["status"] for operation in attempted}
    if statuses == {"success"}:
        return "success"
    if len(statuses) == 1:
        return statuses.pop()
    if "success" in statuses or "partial" in statuses:
        return "partial"
    return "failed"


def _execute_lane(
    lane: str,
    fixture: dict,
    path: Path,
    steps: list[dict],
    reports_dir: Path | None,
) -> dict:
    started = time.monotonic()
    operations = []
    evidence_parts = []
    with _staged_workspace(path, fixture["sha256"]) as (sample_path, out):
        unpacked_paths = []
        for step in steps:
            operation, evidence, unpacked = _execute_step(step, sample_path, out)
            operations.append(operation)
            if evidence and operation["status"] in {"success", "partial"}:
                evidence_parts.append(evidence)
            if unpacked:
                unpacked_paths.append(unpacked)

        # A successful UPX step creates a new immutable layer.  Score the same
        # bounded string/IOC probes on that layer so config recovery measures
        # the router's unpack-and-reroute behavior rather than packed bytes.
        for index, unpacked in enumerate(unpacked_paths):
            for suffix, tool in (("strings", "lab.strings"), ("iocs", "lab.extract_iocs")):
                followup = _step(f"post-unpack.{index}.{suffix}", tool, 180)
                operation, evidence, _ = _execute_step(followup, unpacked, out)
                operations.append(operation)
                if evidence and operation["status"] in {"success", "partial"}:
                    evidence_parts.append(evidence)

    report_score = _report_score(reports_dir, fixture, lane)
    evidence = "\n".join(evidence_parts)
    return {
        "lane": lane,
        "status": _lane_status(operations),
        "wall_seconds": round(time.monotonic() - started, 6),
        "operations": operations,
        "metrics": _metrics(evidence, fixture.get("expected", {}), report_score, operations),
        "ready_operations": sum(step["state"] == "ready" for step in steps),
        "deferred_operations": sum(step["state"] != "ready" for step in steps),
    }


def _command_version(command: list[str]) -> str | None:
    executable = command[0]
    if not (Path(executable).is_file() or shutil.which(executable)):
        return None
    try:
        run = subprocess.run(
            command, check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    lines = run.stdout.strip().splitlines()
    return lines[0][:300] if lines else None


def _environment(mode: str) -> dict:
    environment = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "mode": mode,
        "network_required": False,
        "sample_execution": False,
    }
    if mode == "execute":
        candidates = {
            "file": ["file", "--version"],
            "diec": ["diec", "--version"],
            "capa": ["capa", "--version"],
            "floss": ["floss", "--version"],
            "upx": ["upx", "--version"],
            "rea": ["/opt/rea/runtime/node_modules/.bin/rea", "--version"],
        }
        environment["tools"] = {
            name: version
            for name, command in candidates.items()
            if (version := _command_version(command)) is not None
        }
    return environment


def _aggregate(fixtures: list[dict]) -> dict:
    aggregate = {}
    for lane in LANES:
        runs = [
            lane_result
            for fixture in fixtures
            for lane_result in fixture["lanes"]
            if lane_result["lane"] == lane
        ]
        attempted = sum(run["metrics"]["tool_success"]["attempted"] for run in runs)
        succeeded = sum(run["metrics"]["tool_success"]["succeeded"] for run in runs)
        measured = {}
        for metric in ("useful_evidence", "iocs", "configuration", "analyst_report_accuracy"):
            scores = [
                run["metrics"][metric]["score"]
                for run in runs
                if run["metrics"][metric]["status"] == "measured"
            ]
            measured[metric] = round(sum(scores) / len(scores), 4) if scores else None
        aggregate[lane] = {
            "fixtures": len(runs),
            "successful_fixtures": sum(run["status"] == "success" for run in runs),
            "tool_success": {
                "succeeded": succeeded,
                "attempted": attempted,
                "rate": round(succeeded / attempted, 4) if attempted else None,
            },
            "wall_seconds": (
                round(sum(run["wall_seconds"] for run in runs), 6)
                if all(run["wall_seconds"] is not None for run in runs) else None
            ),
            "timeouts": sum(run["metrics"]["timeouts"] for run in runs),
            "mean_scores": measured,
        }
    return aggregate


def run_benchmark(
    manifest_path: Path,
    *,
    mode: str = "plan",
    lanes: tuple[str, ...] = LANES,
    samples_dir: Path | None = None,
    allow_malware: bool = False,
    reports_dir: Path | None = None,
    fixture_ids: set[str] | None = None,
    tool_timeout: int = 180,
) -> dict:
    """Verify a corpus and plan or execute the selected comparison lanes."""
    if mode not in {"plan", "execute"}:
        raise BenchmarkError("mode must be plan or execute")
    unknown_lanes = set(lanes) - set(LANES)
    if unknown_lanes:
        raise BenchmarkError(f"unknown lanes: {', '.join(sorted(unknown_lanes))}")
    if not 10 <= tool_timeout <= 1800:
        raise BenchmarkError("tool timeout must be between 10 and 1800 seconds")

    manifest = load_manifest(manifest_path)
    admitted = resolve_fixtures(
        manifest,
        samples_dir=samples_dir,
        allow_malware=allow_malware,
        selected=fixture_ids,
    )
    started = dt.datetime.now(dt.timezone.utc)
    fixture_results = []
    for fixture, path in admitted:
        plan = build_analysis_plan(
            path,
            display_path=f"fixture:{fixture['id']}",
            original_name=path.name,
            phase="full",
        )
        expected_format = fixture.get("expected", {}).get("router_format")
        if expected_format and plan["detection"]["format"] != expected_format:
            raise BenchmarkError(
                f"router regression for {fixture['id']}: expected {expected_format}, "
                f"got {plan['detection']['format']}"
            )
        expected_packing = fixture.get("expected", {}).get("packing_state")
        if expected_packing and plan["detection"]["packing"]["state"] != expected_packing:
            raise BenchmarkError(
                f"packing regression for {fixture['id']}: expected {expected_packing}, "
                f"got {plan['detection']['packing']['state']}"
            )
        lane_steps = {
            "core": _core_steps(fixture, tool_timeout),
            "raw-rea": _raw_rea_steps(fixture, tool_timeout),
            "hybrid": _hybrid_steps(plan, tool_timeout),
        }
        lane_results = []
        for lane in lanes:
            if mode == "plan":
                planned = _planned_lane(lane, lane_steps[lane])
                planned["metrics"]["analyst_report_accuracy"] = _report_score(
                    reports_dir, fixture, lane,
                )
                lane_results.append(planned)
            else:
                lane_results.append(_execute_lane(
                    lane, fixture, path, lane_steps[lane], reports_dir,
                ))
        fixture_results.append({
            "id": fixture["id"],
            "sha256": fixture["sha256"],
            "format": plan["detection"]["format"],
            "labels": fixture.get("labels", []),
            "route": {
                "plan_id": plan["plan_id"],
                "detection": plan["detection"],
                "selected": plan["selected"],
                "skipped": plan["skipped"],
            },
            "lanes": lane_results,
        })

    identity = {
        "corpus": manifest["id"],
        "mode": mode,
        "lanes": list(lanes),
        "fixtures": [fixture["sha256"] for fixture, _ in admitted],
        "plans": [fixture["route"]["plan_id"] for fixture in fixture_results],
    }
    result = {
        "schema": RESULT_SCHEMA,
        "run_id": hashlib.sha256(
            json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()[:16],
        "started_at": started.isoformat().replace("+00:00", "Z"),
        "finished_at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "mode": mode,
        "corpus": {
            "id": manifest["id"],
            "kind": manifest["kind"],
            "manifest_sha256": _sha256(Path(manifest["_manifest_path"])),
            "fixture_count": len(admitted),
        },
        "environment": _environment(mode),
        "semantics": {
            "plan": "validates hashes and deterministic route admission; no tools are executed",
            "execute": "runs static tools only; target programs are never launched",
            "core": "bounded BlackWall lab probes without REA or persistent Ghidra MCP",
            "raw-rea": "one manifest-selected upstream REA workflow without router-selected BlackWall probes",
            "hybrid": "ready steps selected by the router; deferred and MCP-only Ghidra steps remain visible as not_run",
            "analyst_report_accuracy": "scored only from caller-supplied lane reports; absent reports are not_measured",
            "expectation_scores": "case-insensitive recall against manifest-declared evidence, IOC, and configuration values; not a score of every structural fact a tool may return",
        },
        "fixtures": fixture_results,
    }
    result["aggregate"] = _aggregate(fixture_results)
    return result


def benchmark_self_check(manifest_path: Path) -> dict:
    result = run_benchmark(manifest_path, mode="plan")
    observed = {fixture["format"] for fixture in result["fixtures"]}
    required = {
        "pe", "dotnet", "elf", "apk", "javascript", "wasm",
        "ooxml-word", "rtf", "pdf", "pcap",
    }
    missing = sorted(required - observed)
    if missing:
        raise BenchmarkError(f"inert corpus lacks required formats: {', '.join(missing)}")
    if not any("upx" in fixture["labels"] for fixture in result["fixtures"]):
        raise BenchmarkError("inert corpus lacks a packed PE fixture")
    return {
        "ok": True,
        "schema": RESULT_SCHEMA,
        "corpus": result["corpus"]["id"],
        "fixtures": result["corpus"]["fixture_count"],
        "formats": sorted(observed),
        "lanes": list(LANES),
    }


def _score_cell(metric: dict) -> str:
    score = metric.get("score")
    return "—" if score is None else f"{score * 100:.0f}%"


def _percentage(value: float | None) -> str:
    return "—" if value is None else f"{value * 100:.0f}%"


def render_markdown(result: dict) -> str:
    lines = [
        f"# BlackWall benchmark: {result['corpus']['id']}",
        "",
        f"Run `{result['run_id']}` used `{result['mode']}` mode across "
        f"{result['corpus']['fixture_count']} verified fixtures.",
        "",
        "| fixture | format | lane | status | tools | seconds | timeouts | evidence | IOCs | config | report |",
        "|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for fixture in result["fixtures"]:
        for lane in fixture["lanes"]:
            success = lane["metrics"]["tool_success"]
            tools = f"{success['succeeded']}/{success['attempted']}" if success["attempted"] else "—"
            seconds = "—" if lane["wall_seconds"] is None else f"{lane['wall_seconds']:.3f}"
            lines.append(
                f"| {fixture['id']} | {fixture['format']} | {lane['lane']} | "
                f"{lane['status']} | {tools} | {seconds} | {lane['metrics']['timeouts']} | "
                f"{_score_cell(lane['metrics']['useful_evidence'])} | "
                f"{_score_cell(lane['metrics']['iocs'])} | "
                f"{_score_cell(lane['metrics']['configuration'])} | "
                f"{_score_cell(lane['metrics']['analyst_report_accuracy'])} |"
            )
    lines.extend(["", "## Aggregate", ""])
    lines.extend([
        "| lane | successful fixtures | tool success | seconds | timeouts | evidence | IOCs | config | report |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ])
    for lane, aggregate in result["aggregate"].items():
        success = aggregate["tool_success"]
        tool_rate = "—" if success["rate"] is None else f"{success['rate'] * 100:.0f}%"
        seconds = "—" if aggregate["wall_seconds"] is None else f"{aggregate['wall_seconds']:.3f}"
        scores = aggregate["mean_scores"]
        lines.append(
            f"| {lane} | {aggregate['successful_fixtures']}/{aggregate['fixtures']} | "
            f"{tool_rate} ({success['succeeded']}/{success['attempted']}) | {seconds} | "
            f"{aggregate['timeouts']} | {_percentage(scores['useful_evidence'])} | "
            f"{_percentage(scores['iocs'])} | {_percentage(scores['configuration'])} | "
            f"{_percentage(scores['analyst_report_accuracy'])} |"
        )
    gaps = []
    for fixture in result["fixtures"]:
        for lane in fixture["lanes"]:
            for operation in lane["operations"]:
                if operation["status"] not in {"success", "not_run"}:
                    gaps.append(
                        f"- `{fixture['id']}` / `{lane['lane']}` / `{operation['tool']}`: "
                        f"**{operation['status']}**"
                    )
    if gaps:
        lines.extend(["", "## Recorded gaps", "", *gaps])
    lines.extend([
        "",
        "## Interpretation limits",
        "",
        "- Plan mode checks corpus integrity and route selection; it makes no speed or recovery claim.",
        "- Execute mode uses static tooling only. It never launches target programs or enables network access.",
        "- Persistent Ghidra is MCP-only and is recorded as `not_run` by this CLI harness.",
        "- Analyst-report accuracy is `—` unless lane reports were supplied with `--reports-dir`.",
        "- Evidence, IOC, and config percentages are recall against manifest expectations; they do not grade every structural fact an analyzer returns.",
        "- Raw wall times are single-run observations, not statistically stable performance estimates.",
        "",
    ])
    return "\n".join(lines)


def write_results(result: dict, output_prefix: Path) -> tuple[Path, Path]:
    output_prefix = output_prefix.resolve()
    output_prefix.parent.mkdir(parents=True, exist_ok=True)
    json_path = output_prefix.with_suffix(".json")
    markdown_path = output_prefix.with_suffix(".md")
    json_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    markdown_path.write_text(render_markdown(result))
    return json_path, markdown_path


def default_manifest() -> Path:
    installed = Path("/opt/blackwall/benchmarks/corpus/inert-manifest.json")
    if installed.is_file():
        return installed
    return Path(__file__).resolve().parents[2] / "benchmarks" / "corpus" / "inert-manifest.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BlackWall offline benchmark harness")
    parser.add_argument("--manifest", type=Path, default=default_manifest())
    parser.add_argument("--mode", choices=("plan", "execute"), default="plan")
    parser.add_argument("--lane", action="append", choices=LANES, dest="lanes")
    parser.add_argument("--fixture", action="append", dest="fixtures")
    parser.add_argument("--samples-dir", type=Path)
    parser.add_argument("--allow-malware", action="store_true")
    parser.add_argument("--reports-dir", type=Path)
    parser.add_argument("--tool-timeout", type=int, default=180)
    parser.add_argument("--output", type=Path, help="output prefix; writes .json and .md")
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.self_check:
            print(json.dumps(benchmark_self_check(args.manifest), sort_keys=True))
            return 0
        result = run_benchmark(
            args.manifest,
            mode=args.mode,
            lanes=tuple(args.lanes or LANES),
            samples_dir=args.samples_dir,
            allow_malware=args.allow_malware,
            reports_dir=args.reports_dir,
            fixture_ids=set(args.fixtures) if args.fixtures else None,
            tool_timeout=args.tool_timeout,
        )
        if args.output:
            json_path, markdown_path = write_results(result, args.output)
            print(f"wrote {json_path}")
            print(f"wrote {markdown_path}")
        else:
            print(render_markdown(result))
        return 0
    except BenchmarkError as exc:
        print(f"benchmark error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
