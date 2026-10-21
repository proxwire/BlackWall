"""MCP-level readiness probe for BlackWall's persistent Ghidra service."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import tempfile
import time
from datetime import timedelta
from pathlib import Path

import httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client

READINESS_SCHEMA = "blackwall.ghidra-readiness.v1"


def _programs_from_result(result) -> list[dict]:
    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict) and isinstance(structured.get("programs"), list):
        return structured["programs"]

    for content in getattr(result, "content", []):
        text = getattr(content, "text", None)
        if not isinstance(text, str):
            continue
        try:
            value = json.loads(text)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and isinstance(value.get("programs"), list):
            return value["programs"]
    raise RuntimeError("list_project_binaries returned no structured program list")


def readiness_status(programs: list[dict]) -> dict:
    normalized = []
    for program in programs:
        if not isinstance(program, dict) or not isinstance(program.get("name"), str):
            raise ValueError("Ghidra returned a malformed program status")
        normalized.append(
            {
                "name": program["name"],
                "analysis_complete": program.get("analysis_complete") is True,
                "code_indexed": program.get("code_indexed") is True,
                "strings_indexed": program.get("strings_indexed") is True,
            }
        )
    return {
        "schema": READINESS_SCHEMA,
        "ready": all(program["analysis_complete"] for program in normalized),
        "analysis_ready": all(
            program["analysis_complete"] for program in normalized
        ),
        "search_ready": all(
            program["code_indexed"] and program["strings_indexed"]
            for program in normalized
        ),
        "program_count": len(normalized),
        "programs": normalized,
        "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


async def probe_once(url: str, *, request_timeout: float = 15) -> dict:
    timeout = httpx.Timeout(request_timeout)
    async with httpx.AsyncClient(timeout=timeout, trust_env=False) as client:
        async with streamable_http_client(url, http_client=client) as streams:
            read_stream, write_stream, _session_id = streams
            async with ClientSession(
                read_stream,
                write_stream,
                read_timeout_seconds=timedelta(seconds=request_timeout),
            ) as session:
                await session.initialize()
                result = await session.call_tool("list_project_binaries", {})
                if getattr(result, "isError", False):
                    raise RuntimeError(f"Ghidra readiness tool failed: {result}")
                return readiness_status(_programs_from_result(result))


def _write_state(path: Path, status: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(status, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


async def wait_until_ready(
    url: str,
    *,
    timeout: float,
    interval: float,
    require_indexes: bool,
    state_file: Path | None,
    watch_pid: int | None = None,
) -> dict:
    deadline = time.monotonic() + timeout
    attempts = 0
    last_error = "server has not responded"
    last_status: dict | None = None
    while time.monotonic() < deadline:
        if watch_pid is not None:
            try:
                os.kill(watch_pid, 0)
            except ProcessLookupError as exc:
                detail = {
                    "schema": READINESS_SCHEMA,
                    "ready": False,
                    "attempts": attempts,
                    "error": f"Ghidra service process {watch_pid} exited during startup",
                }
                if state_file is not None:
                    try:
                        _write_state(state_file, detail)
                    except OSError:
                        pass
                raise RuntimeError(detail["error"]) from exc
        attempts += 1
        try:
            last_status = await probe_once(
                url, request_timeout=min(15, max(1, deadline - time.monotonic())),
            )
            last_status["attempts"] = attempts
            ready = last_status["search_ready"] if require_indexes else last_status["ready"]
            if state_file is not None:
                try:
                    _write_state(state_file, last_status)
                except OSError as exc:
                    last_status["state_file_warning"] = str(exc)
            if ready:
                return last_status
            incomplete = [
                program["name"]
                for program in last_status["programs"]
                if not program["analysis_complete"]
            ]
            last_error = "analysis incomplete: " + ", ".join(incomplete)
        except Exception as exc:  # the service legitimately refuses connections while starting
            last_error = f"{type(exc).__name__}: {exc}"
        await asyncio.sleep(min(interval, max(0, deadline - time.monotonic())))

    detail = dict(last_status or {})
    detail.update(
        {
            "schema": READINESS_SCHEMA,
            "ready": False,
            "attempts": attempts,
            "timeout_seconds": timeout,
            "error": last_error,
        }
    )
    if state_file is not None:
        try:
            _write_state(state_file, detail)
        except OSError:
            pass
    raise TimeoutError(json.dumps(detail, sort_keys=True))


async def integration_check() -> dict:
    """Connect through the production stdio wrapper and inspect real MCP state."""
    parameters = StdioServerParameters(command="bw-ghidra-mcp", env=dict(os.environ))
    async with stdio_client(parameters) as streams:
        read_stream, write_stream = streams
        async with ClientSession(
            read_stream,
            write_stream,
            read_timeout_seconds=timedelta(minutes=10),
        ) as session:
            await session.initialize()
            result = await session.call_tool("list_project_binaries", {})
            if getattr(result, "isError", False):
                raise RuntimeError(f"Ghidra integration probe failed: {result}")
            status = readiness_status(_programs_from_result(result))
            if not status["ready"]:
                raise RuntimeError(f"Ghidra served before analysis was ready: {status}")
            return status


def _self_check() -> dict:
    fixture = {
        "programs": [
            {
                "name": "fixture",
                "analysis_complete": True,
                "code_indexed": False,
                "strings_indexed": True,
            }
        ]
    }

    class Result:
        structuredContent = fixture
        content = []

    status = readiness_status(_programs_from_result(Result()))
    if not status["ready"] or status["search_ready"]:
        raise RuntimeError("readiness dimensions were conflated")
    empty = readiness_status([])
    if not empty["ready"] or empty["program_count"] != 0:
        raise RuntimeError("an empty, non-importable project cannot become available")
    return {"ok": True, "analysis_ready": True, "search_ready": False}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Probe BlackWall Ghidra MCP readiness")
    parser.add_argument("--url", default="http://127.0.0.1:8000/mcp")
    parser.add_argument("--timeout", type=float, default=600)
    parser.add_argument("--interval", type=float, default=1)
    parser.add_argument("--require-indexes", action="store_true")
    parser.add_argument("--state-file", type=Path)
    parser.add_argument("--watch-pid", type=int)
    parser.add_argument("--self-check", action="store_true")
    parser.add_argument("--integration-check", action="store_true")
    args = parser.parse_args(argv)
    if args.self_check:
        print(json.dumps(_self_check(), sort_keys=True))
        return 0
    if args.integration_check:
        print(json.dumps(asyncio.run(integration_check()), sort_keys=True))
        return 0
    if args.timeout <= 0 or args.interval <= 0:
        parser.error("--timeout and --interval must be positive")
    try:
        status = asyncio.run(
            wait_until_ready(
                args.url,
                timeout=args.timeout,
                interval=args.interval,
                require_indexes=args.require_indexes,
                state_file=args.state_file,
                watch_pid=args.watch_pid,
            )
        )
    except (RuntimeError, TimeoutError) as exc:
        print(f"Ghidra readiness failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(status, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
