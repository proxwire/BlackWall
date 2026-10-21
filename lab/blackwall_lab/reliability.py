"""Process supervision and read-only case reliability diagnostics.

Every parser is treated as hostile-input code.  Commands run in their own
process group so a timeout or cancellation cannot leave helpers behind.  The
diagnostic path deliberately performs no cleanup: evidence, samples, and the
Ghidra project remain untouched until an analyst makes an explicit decision.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from pathlib import Path
from typing import Protocol

DEFAULT_MIN_FREE_BYTES = 256 * 1024 * 1024
MAX_DIAGNOSTIC_FILES = 2_000
MAX_REPORTED_PATHS = 20


class CancellationEvent(Protocol):
    """The small portion of ``threading.Event`` used by ``run_bounded``."""

    def is_set(self) -> bool: ...


def _terminate_group(
    process: subprocess.Popen[str],
    *,
    initial_signal: signal.Signals,
    grace_seconds: float = 0.5,
) -> tuple[str, str]:
    """Stop a complete parser process group and collect its remaining output."""
    if process.poll() is None:
        try:
            os.killpg(process.pid, initial_signal)
        except ProcessLookupError:
            pass
    try:
        return process.communicate(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        return process.communicate()


def run_bounded(
    cmd: list[str] | str,
    *,
    timeout: float = 300,
    cwd: Path = Path("/work"),
    shell: bool = False,
    cancel_event: CancellationEvent | None = None,
    poll_interval: float = 0.1,
) -> dict:
    """Run a command with whole-process-group timeout and cancellation.

    ``cancel_event`` is optional so synchronous MCP tools keep a compact API,
    while orchestration and integration tests can request cooperative
    cancellation.  Unexpected cancellation of the Python caller also tears
    down the complete child group before the exception is re-raised.
    """
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    started = time.monotonic()
    deadline = started + timeout
    # Only the explicit expert MCP tool chooses a shell; all other callers use argv.
    process = subprocess.Popen(
        cmd,
        cwd=cwd,
        shell=shell,  # nosec B602
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
        executable="/bin/bash" if shell else None,
        start_new_session=True,
    )

    try:
        while True:
            if cancel_event is not None and cancel_event.is_set():
                stdout, stderr = _terminate_group(
                    process, initial_signal=signal.SIGTERM,
                )
                message = "cancelled by caller"
                stderr = f"{stderr.rstrip()}\n{message}" if stderr else message
                return _result(
                    process, started, stdout, stderr, cancelled=True,
                )

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                stdout, stderr = _terminate_group(
                    process, initial_signal=signal.SIGKILL, grace_seconds=0,
                )
                message = f"timed out after {timeout:g}s"
                stderr = f"{stderr.rstrip()}\n{message}" if stderr else message
                return _result(
                    process, started, stdout, stderr, timed_out=True,
                )

            wait_for = min(max(poll_interval, 0.01), remaining)
            try:
                stdout, stderr = process.communicate(timeout=wait_for)
                return _result(process, started, stdout, stderr)
            except subprocess.TimeoutExpired:
                continue
    except BaseException:
        _terminate_group(process, initial_signal=signal.SIGTERM)
        raise


def _result(
    process: subprocess.Popen[str],
    started: float,
    stdout: str,
    stderr: str,
    *,
    timed_out: bool = False,
    cancelled: bool = False,
) -> dict:
    return_code = None if timed_out or cancelled else process.returncode
    termination_signal = (
        -return_code if isinstance(return_code, int) and return_code < 0 else None
    )
    crashed = termination_signal is not None
    if timed_out:
        status = "timeout"
    elif cancelled:
        status = "cancelled"
    elif crashed:
        status = "crashed"
    elif return_code == 0:
        status = "ok"
    else:
        status = "failed"
    return {
        "rc": return_code,
        "stdout": stdout,
        "stderr": stderr,
        "seconds": round(time.monotonic() - started, 1),
        "timed_out": timed_out,
        "cancelled": cancelled,
        "crashed": crashed,
        "termination_signal": termination_signal,
        "status": status,
    }


def _path_size(path: Path, *, limit: int = MAX_DIAGNOSTIC_FILES) -> tuple[int, int]:
    if path.is_file():
        try:
            return path.stat().st_size, 1
        except OSError:
            return 0, 0
    total = 0
    count = 0
    try:
        descendants = path.rglob("*")
        for child in descendants:
            if count >= limit:
                break
            try:
                if child.is_file() and not child.is_symlink():
                    total += child.stat().st_size
                    count += 1
            except OSError:
                continue
    except OSError:
        pass
    return total, count


def _json_health(paths: list[Path]) -> tuple[Counter, list[str]]:
    outcomes: Counter = Counter()
    corrupt: list[str] = []
    for path in paths[:MAX_DIAGNOSTIC_FILES]:
        try:
            if path.stat().st_size > 8 * 1024 * 1024:
                raise ValueError("record exceeds 8 MiB")
            value = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(value, dict) and path.parent.name == "evidence":
                outcomes[str(value.get("status", "unknown"))] += 1
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
            if len(corrupt) < MAX_REPORTED_PATHS:
                corrupt.append(f"{path}: {exc}")
    return outcomes, corrupt


def diagnose_workspace(
    work: Path = Path("/work"),
    *,
    min_free_bytes: int = DEFAULT_MIN_FREE_BYTES,
) -> dict:
    """Inspect a case volume without writing to it or deleting anything."""
    work = Path(work).resolve()
    if min_free_bytes < 0:
        raise ValueError("min_free_bytes cannot be negative")
    if not work.is_dir():
        return {
            "schema": "blackwall.reliability-diagnostic.v1",
            "work": str(work),
            "health": "critical",
            "errors": [f"workspace does not exist: {work}"],
            "actions": ["Start the case once to create its retained analysis volume."],
            "protected_paths": [],
            "cleanup_performed": False,
        }

    usage = shutil.disk_usage(work)
    state = work / "state"
    evidence_paths = sorted((state / "evidence").glob("ev_*.json"))
    checkpoint_paths = sorted((state / "checkpoints").glob("*.json"))
    claim_paths = sorted((state / "claims").glob("claim_*.json"))
    output_paths = sorted(
        path for path in (state / "outputs").glob("*") if path.is_file()
    )
    state_json = evidence_paths + checkpoint_paths + claim_paths
    for name in ("artifacts.json", "findings.json"):
        path = state / name
        if path.is_file():
            state_json.append(path)
    outcomes, corrupt = _json_health(state_json)

    candidates: list[dict] = []
    scratch = work / "scratch"
    if scratch.is_dir():
        try:
            children = sorted(scratch.iterdir(), key=lambda path: path.name)
        except OSError:
            children = []
        for path in children[:MAX_DIAGNOSTIC_FILES]:
            size, files = _path_size(path)
            candidates.append({"path": str(path), "bytes": size, "files": files})

    temporary_patterns = (".*.tmp", ".*.tmp.*", ".*.json.*")
    for parent in (state, work / "out"):
        if not parent.is_dir():
            continue
        for pattern in temporary_patterns:
            for path in sorted(parent.glob(pattern)):
                size, files = _path_size(path)
                candidates.append({"path": str(path), "bytes": size, "files": files})
                if len(candidates) >= MAX_DIAGNOSTIC_FILES:
                    break

    candidate_bytes = sum(item["bytes"] for item in candidates)
    errors: list[str] = []
    warnings: list[str] = []
    actions: list[str] = []
    if usage.free < min_free_bytes:
        errors.append(
            f"only {usage.free} bytes are free; at least {min_free_bytes} are required"
        )
        actions.append(
            "Inspect the reported /work/scratch candidates and free host/Docker "
            "storage before retrying. Preserve /work/state, /work/samples, and /work/ghidra."
        )
    if corrupt:
        errors.append(f"{len(corrupt)} retained JSON state file(s) could not be parsed")
        actions.append(
            "Copy the case volume before repair; do not delete corrupt state because it is "
            "part of the audit trail."
        )
    if candidates:
        warnings.append(
            f"{len(candidates)} scratch/temporary cleanup candidate(s) use "
            f"{candidate_bytes} bytes"
        )
        actions.append(
            "Review cleanup candidates in a case shell. They are reported only; this "
            "command never removes them."
        )
    if not actions:
        actions.append("No cleanup action is currently required.")

    protected = [work / "state", work / "samples", work / "ghidra"]
    health = "critical" if errors else "warning" if warnings else "ok"
    return {
        "schema": "blackwall.reliability-diagnostic.v1",
        "work": str(work),
        "health": health,
        "disk": {
            "total_bytes": usage.total,
            "used_bytes": usage.used,
            "free_bytes": usage.free,
            "minimum_free_bytes": min_free_bytes,
        },
        "retained": {
            "evidence_records": len(evidence_paths),
            "retained_outputs": len(output_paths),
            "checkpoints": len(checkpoint_paths),
            "claims": len(claim_paths),
            "outcomes": dict(sorted(outcomes.items())),
        },
        "protected_paths": [str(path) for path in protected if path.exists()],
        "cleanup_candidates": candidates[:MAX_REPORTED_PATHS],
        "cleanup_candidate_count": len(candidates),
        "cleanup_candidate_bytes": candidate_bytes,
        "corrupt_state": corrupt,
        "errors": errors,
        "warnings": warnings,
        "actions": actions,
        "cleanup_performed": False,
    }


def _format_diagnostic(report: dict) -> str:
    lines = [
        f"case-volume health: {report['health']}",
        "cleanup mode: diagnostic only (nothing deleted)",
    ]
    disk = report.get("disk")
    if isinstance(disk, dict):
        lines.append(
            "disk: "
            f"{disk['free_bytes']} bytes free / {disk['total_bytes']} total "
            f"(minimum {disk['minimum_free_bytes']})"
        )
    retained = report.get("retained")
    if isinstance(retained, dict):
        lines.append(
            "retained: "
            f"{retained['evidence_records']} evidence, "
            f"{retained['retained_outputs']} outputs, "
            f"{retained['checkpoints']} checkpoints, {retained['claims']} claims"
        )
    protected = report.get("protected_paths", [])
    if protected:
        lines.append("protected: " + ", ".join(protected))
    candidates = report.get("cleanup_candidates", [])
    if candidates:
        lines.append("cleanup candidates (review before removing):")
        for item in candidates:
            lines.append(f"  {item['bytes']:>10} bytes  {item['path']}")
        omitted = int(report.get("cleanup_candidate_count", 0)) - len(candidates)
        if omitted > 0:
            lines.append(f"  ... {omitted} additional candidate(s) omitted")
    for label in ("errors", "warnings", "actions"):
        values = report.get(label, [])
        if values:
            lines.append(f"{label}:")
            lines.extend(f"  - {value}" for value in values)
    return "\n".join(lines)


def reliability_self_check() -> dict:
    """Exercise supervision paths with inert children and a fixture ledger."""
    with tempfile.TemporaryDirectory(prefix="blackwall-reliability-") as directory:
        root = Path(directory)

        timeout_marker = root / "timeout-orphan"
        timeout_command = (
            f"(sleep 0.4; printf orphan > {timeout_marker}) & wait"
        )
        timeout_result = run_bounded(
            timeout_command, timeout=0.05, cwd=root, shell=True,
        )
        time.sleep(0.45)
        if not timeout_result["timed_out"] or timeout_marker.exists():
            raise RuntimeError("timeout left a parser descendant running")

        cancel_marker = root / "cancel-orphan"
        cancellation = threading.Event()
        timer = threading.Timer(0.05, cancellation.set)
        timer.start()
        try:
            cancel_result = run_bounded(
                f"(sleep 0.4; printf orphan > {cancel_marker}) & wait",
                timeout=2,
                cwd=root,
                shell=True,
                cancel_event=cancellation,
            )
        finally:
            timer.cancel()
        time.sleep(0.45)
        if not cancel_result["cancelled"] or cancel_marker.exists():
            raise RuntimeError("cancellation left a parser descendant running")

        crash_result = run_bounded(
            [
                sys.executable,
                "-c",
                "import os, signal; os.kill(os.getpid(), signal.SIGKILL)",
            ],
            timeout=2,
            cwd=root,
        )
        if not crash_result["crashed"] or crash_result["termination_signal"] != 9:
            raise RuntimeError("parser crash was not classified")

        work = root / "work"
        evidence = work / "state" / "evidence"
        evidence.mkdir(parents=True)
        sentinel = evidence / "ev_000000000000000000000000.json"
        sentinel.write_text('{"status":"failed"}\n', encoding="utf-8")
        scratch = work / "scratch" / "extract.abcd"
        scratch.mkdir(parents=True)
        (scratch / "partial").write_bytes(b"inert")
        before = sentinel.read_bytes()
        diagnostic = diagnose_workspace(work, min_free_bytes=0)
        if sentinel.read_bytes() != before or diagnostic["cleanup_performed"]:
            raise RuntimeError("diagnostic changed retained evidence")
        if diagnostic["cleanup_candidate_count"] != 1:
            raise RuntimeError("stale extraction directory was not diagnosed")

    return {
        "ok": True,
        "timeout": timeout_result["status"],
        "cancellation": cancel_result["status"],
        "parser_crash": crash_result["status"],
        "cleanup_diagnostic": "non-destructive",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BlackWall reliability diagnostics")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--diagnose", action="store_true")
    action.add_argument("--check-space", action="store_true")
    action.add_argument("--self-check", action="store_true")
    parser.add_argument("--work", type=Path, default=Path("/work"))
    parser.add_argument("--min-free-bytes", type=int, default=DEFAULT_MIN_FREE_BYTES)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    if args.self_check:
        print(json.dumps(reliability_self_check(), sort_keys=True))
        return 0

    report = diagnose_workspace(args.work, min_free_bytes=args.min_free_bytes)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(_format_diagnostic(report))
    return 1 if args.check_space and report["health"] == "critical" else 0


if __name__ == "__main__":
    raise SystemExit(main())
