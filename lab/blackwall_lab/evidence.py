"""Durable evidence, artifact-lineage, finding, and checkpoint storage.

The store lives entirely below ``/work/state`` in a case volume.  Records are
small JSON documents and every material output is addressed by SHA-256.  This
module deliberately has no parser or MCP dependencies, which makes the state
machine straightforward to exercise with inert fixtures.
"""

from __future__ import annotations

import fcntl
import hashlib
import importlib.metadata
import json
import os
import re
import shutil
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator
from urllib.parse import urlsplit, urlunsplit

EVIDENCE_SCHEMA = "blackwall.evidence-record.v1"
LINEAGE_SCHEMA = "blackwall.artifact-lineage.v1"
FINDINGS_SCHEMA = "blackwall.finding-index.v1"
CHECKPOINT_SCHEMA = "blackwall.analysis-checkpoint.v1"
CLAIM_SCHEMA = "blackwall.evidence-claim.v1"
AUDIT_SCHEMA = "blackwall.evidence-audit.v1"

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ID_RE = re.compile(r"^(?:ev|claim)_[0-9a-f]{24}$")
CONFIDENCE_LEVELS = frozenset({"observed", "confirmed", "derived", "likely", "speculative"})
CLAIM_TYPES = frozenset({"report", "annotation", "note"})
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_FINDINGS = 100
MAX_CLAIM_EVIDENCE = 50
MAX_INVENTORY_ARTIFACTS = 250
MAX_INVENTORY_PARENTS = 20
MAX_STATUS_DISAGREEMENTS = 25
MAX_STATUS_VARIANTS = 10
MAX_AUDIT_ISSUES = 500
MAX_STEP_EVIDENCE = 50


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str,
    ).encode("utf-8")


def _digest_json(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _bounded_text(value: object, label: str, limit: int) -> str:
    if not isinstance(value, str) or not value or len(value) > limit or "\0" in value:
        raise ValueError(f"invalid {label}")
    return value


def _object(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _expected_evidence_id(record: dict) -> str:
    artifact = _object(record.get("artifact"))
    tool = _object(record.get("tool"))
    command = _object(record.get("command"))
    retained = _object(record.get("retained_output"))
    snapshot = _object(record.get("result_snapshot"))
    identity = {
        "schema": EVIDENCE_SCHEMA,
        "plan_id": record.get("plan_id"),
        "step_id": record.get("step_id"),
        "artifact_sha256": artifact.get("sha256"),
        "tool": tool.get("name"),
        "tool_version": tool.get("version"),
        "command_identity": command.get("identity"),
        "status": record.get("status"),
        "retained_sha256": retained.get("sha256"),
        "snapshot_sha256": snapshot.get("sha256"),
        "confidence": record.get("confidence"),
    }
    return f"ev_{_digest_json(identity)[:24]}"


class EvidenceStore:
    """Filesystem-backed case ledger with atomic, locked state transitions."""

    def __init__(self, work: Path, *, samples: Path | None = None, out: Path | None = None):
        self.work = Path(work).resolve()
        self.samples = Path(samples or self.work / "samples").resolve()
        self.out = Path(out or self.work / "out").resolve()
        self.state = self.work / "state"
        self.evidence_dir = self.state / "evidence"
        self.output_dir = self.state / "outputs"
        self.checkpoint_dir = self.state / "checkpoints"
        self.claim_dir = self.state / "claims"
        self.lineage_path = self.state / "artifacts.json"
        self.findings_path = self.state / "findings.json"

    def _ensure_dirs(self) -> None:
        for path in (
            self.state, self.evidence_dir, self.output_dir,
            self.checkpoint_dir, self.claim_dir,
        ):
            path.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def _lock(self) -> Iterator[None]:
        self._ensure_dirs()
        lock_path = self.state / ".lock"
        with lock_path.open("a+b") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

    @staticmethod
    def _read_json(path: Path, default: object) -> object:
        if not path.exists():
            return default
        if path.stat().st_size > MAX_JSON_BYTES:
            raise ValueError(f"state file exceeds {MAX_JSON_BYTES} bytes: {path}")
        with path.open(encoding="utf-8") as stream:
            return json.load(stream)

    @staticmethod
    def _atomic_json(path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        encoded = json.dumps(value, indent=2, ensure_ascii=False, default=str) + "\n"
        fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, 0o644)
            os.replace(temporary, path)
            directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _inside_work(self, path: Path) -> Path:
        resolved = Path(path).resolve()
        if resolved != self.work and self.work not in resolved.parents:
            raise ValueError(f"path must be inside {self.work}: {path}")
        return resolved

    def _lineage(self) -> dict:
        value = self._read_json(
            self.lineage_path,
            {"schema": LINEAGE_SCHEMA, "updated_at": None, "artifacts": {}},
        )
        if not isinstance(value, dict) or value.get("schema") != LINEAGE_SCHEMA:
            raise ValueError("artifact lineage has an unsupported schema")
        if not isinstance(value.get("artifacts"), dict):
            raise ValueError("artifact lineage is malformed")
        return value

    def _bootstrap_artifacts(self, lineage: dict) -> bool:
        changed = False
        roots = (
            (self.samples / "original", "original"),
            (self.samples / "derived", "derived"),
        )
        for root, kind in roots:
            if not root.is_dir():
                continue
            for path in sorted(root.iterdir()):
                if not path.is_file() or not SHA256_RE.fullmatch(path.name):
                    continue
                if path.name in lineage["artifacts"]:
                    continue
                lineage["artifacts"][path.name] = {
                    "sha256": path.name,
                    "kind": kind,
                    "size": path.stat().st_size,
                    "paths": [str(path.resolve())],
                    "parents": [],
                    "first_seen": _utc_now(),
                    "depth": 0 if kind == "original" else None,
                    "legacy_unlinked": kind == "derived",
                }
                changed = True
        return changed

    def _artifact_for_path(self, path: Path, lineage: dict, *, verify: bool = True) -> dict:
        path = self._inside_work(path)
        allowed = {(self.samples / "original").resolve(), (self.samples / "derived").resolve()}
        if path.parent not in allowed or not SHA256_RE.fullmatch(path.name) or not path.is_file():
            raise ValueError("artifact must be a content-addressed original or derived sample")
        if verify:
            actual, size = _hash_file(path)
            if actual != path.name:
                raise ValueError(f"artifact filename/hash mismatch: {path}")
        else:
            size = path.stat().st_size
        entry = lineage["artifacts"].get(path.name)
        if entry is None:
            entry = {
                "sha256": path.name,
                "kind": "original" if path.parent == (self.samples / "original").resolve() else "derived",
                "size": size,
                "paths": [str(path)],
                "parents": [],
                "first_seen": _utc_now(),
                "depth": 0 if path.parent == (self.samples / "original").resolve() else None,
                "legacy_unlinked": path.parent == (self.samples / "derived").resolve(),
            }
            lineage["artifacts"][path.name] = entry
        elif str(path) not in entry.get("paths", []):
            entry.setdefault("paths", []).append(str(path))
        return entry

    @staticmethod
    def _would_cycle(artifacts: dict, parent_sha256: str, child_sha256: str) -> bool:
        """Return true when adding parent -> child closes an ancestry cycle."""
        pending = [parent_sha256]
        visited: set[str] = set()
        while pending:
            current = pending.pop()
            if current == child_sha256:
                return True
            if current in visited:
                continue
            visited.add(current)
            entry = artifacts.get(current, {})
            if not isinstance(entry, dict) or not isinstance(entry.get("parents", []), list):
                continue
            pending.extend(
                edge.get("sha256") for edge in entry.get("parents", [])
                if isinstance(edge, dict) and SHA256_RE.fullmatch(str(edge.get("sha256", "")))
            )
        return False

    def register_artifact(
        self,
        source: Path,
        *,
        parent_path: Path,
        relationship: str,
        label: str,
        producer_tool: str,
        producer_evidence_id: str | None = None,
    ) -> dict:
        """Content-address a child and atomically add one provenance edge."""
        source = Path(source).resolve()
        if not source.is_file() or source.is_symlink():
            raise ValueError(f"derived source must be a regular file: {source}")
        relationship = _bounded_text(relationship, "relationship", 100)
        label = _bounded_text(label, "label", 1000)
        producer_tool = _bounded_text(producer_tool, "producer_tool", 200)
        if producer_evidence_id is not None and not ID_RE.fullmatch(producer_evidence_id):
            raise ValueError("invalid producer_evidence_id")
        child_sha256, size = _hash_file(source)

        with self._lock():
            lineage = self._lineage()
            self._bootstrap_artifacts(lineage)
            parent = self._artifact_for_path(parent_path, lineage)
            parent_sha256 = parent["sha256"]
            if child_sha256 == parent_sha256:
                raise ValueError("recursive extraction loop: child content equals its parent")
            if self._would_cycle(lineage["artifacts"], parent_sha256, child_sha256):
                raise ValueError("recursive extraction loop: lineage edge would create a cycle")

            derived = self.samples / "derived"
            derived.mkdir(parents=True, exist_ok=True)
            destination = (derived / child_sha256).resolve()
            created = not destination.exists()
            if created:
                fd, temporary = tempfile.mkstemp(prefix=".derived.", dir=derived)
                try:
                    with source.open("rb") as src, os.fdopen(fd, "wb") as dst:
                        shutil.copyfileobj(src, dst, length=1024 * 1024)
                        dst.flush()
                        os.fsync(dst.fileno())
                    os.chmod(temporary, 0o444)
                    os.replace(temporary, destination)
                    directory_fd = os.open(derived, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        os.fsync(directory_fd)
                    finally:
                        os.close(directory_fd)
                finally:
                    if os.path.exists(temporary):
                        os.unlink(temporary)
            existing_sha256, existing_size = _hash_file(destination)
            if existing_sha256 != child_sha256 or existing_size != size:
                if created:
                    destination.unlink(missing_ok=True)
                raise ValueError(f"corrupt content-addressed artifact: {destination}")
            os.chmod(destination, 0o444)

            child = lineage["artifacts"].setdefault(child_sha256, {
                "sha256": child_sha256,
                "kind": "derived",
                "size": size,
                "paths": [str(destination)],
                "parents": [],
                "first_seen": _utc_now(),
                "depth": (parent.get("depth") or 0) + 1,
            })
            child.pop("legacy_unlinked", None)
            if str(destination) not in child.setdefault("paths", []):
                child["paths"].append(str(destination))
            edge_identity = {
                "sha256": parent_sha256,
                "relationship": relationship,
                "producer_tool": producer_tool,
            }
            edge = next(
                (
                    candidate for candidate in child.setdefault("parents", [])
                    if all(candidate.get(key) == value for key, value in edge_identity.items())
                ),
                None,
            )
            edge_added = edge is None
            if edge is None:
                edge = edge_identity | {
                    "label": label,
                    "labels": [label],
                    "observed_at": _utc_now(),
                    "producer_evidence_ids": [],
                }
                child["parents"].append(edge)
            else:
                labels = edge.setdefault("labels", [edge.get("label", label)])
                if label not in labels:
                    labels.append(label)
            if producer_evidence_id and producer_evidence_id not in edge["producer_evidence_ids"]:
                edge["producer_evidence_ids"].append(producer_evidence_id)
            depths = [
                lineage["artifacts"].get(item["sha256"], {}).get("depth")
                for item in child["parents"]
            ]
            known_depths = [depth for depth in depths if isinstance(depth, int)]
            child["depth"] = min(known_depths) + 1 if known_depths else None
            lineage["updated_at"] = _utc_now()
            self._atomic_json(self.lineage_path, lineage)
            self._update_legacy_index(child_sha256, child, label, relationship, parent_sha256)

        return {
            "schema": "blackwall.artifact-registration.v1",
            "path": str(destination),
            "sha256": child_sha256,
            "size": size,
            "parent_sha256": parent_sha256,
            "relationship": relationship,
            "lineage_depth": child.get("depth"),
            "content_created": created,
            "lineage_edge_added": edge_added,
            "deduplicated": not created and not edge_added,
        }

    def _update_legacy_index(
        self, sha256: str, child: dict, label: str, relationship: str, parent_sha256: str,
    ) -> None:
        path = self.samples / "derived" / ".index.json"
        index = self._read_json(path, {})
        if not isinstance(index, dict):
            raise ValueError("legacy derived index is malformed")
        index.setdefault(sha256, {
            "label": label,
            "size": child["size"],
            "created": child["first_seen"],
            "parent_sha256": parent_sha256,
            "relationship": relationship,
        })
        self._atomic_json(path, index)

    def ensure_plan(self, plan: dict) -> dict:
        plan_id = str(plan.get("plan_id", ""))
        if not re.fullmatch(r"[0-9a-f]{16}", plan_id):
            raise ValueError("invalid plan_id")
        selected = plan.get("selected")
        if not isinstance(selected, list):
            raise ValueError("analysis plan has no selected steps")
        path = self.checkpoint_dir / f"{plan_id}.json"
        with self._lock():
            checkpoint = self._read_json(path, None)
            if checkpoint is None:
                now = _utc_now()
                checkpoint = {
                    "schema": CHECKPOINT_SCHEMA,
                    "plan_id": plan_id,
                    "plan_schema": plan.get("schema"),
                    "target": plan.get("target"),
                    "phase": plan.get("phase"),
                    "created_at": now,
                    "updated_at": now,
                    "revision": 1,
                    "steps": {
                        step["id"]: {
                            "tool": step["tool"],
                            "planned_state": step.get("state", "ready"),
                            "command_identity": _digest_json({
                                "step_id": step["id"],
                                "tool": step["tool"],
                                "arguments": step.get("arguments", {}),
                            }),
                            "arguments": step.get("arguments", {}),
                            "fallbacks": step.get("fallbacks", []),
                            "attempts": [],
                        }
                        for step in selected
                    },
                }
                self._atomic_json(path, checkpoint)
            else:
                if (
                    not isinstance(checkpoint, dict)
                    or checkpoint.get("schema") != CHECKPOINT_SCHEMA
                    or not isinstance(checkpoint.get("steps"), dict)
                ):
                    raise ValueError("analysis checkpoint has an unsupported schema")
                target = checkpoint.get("target") or {}
                incoming = plan.get("target") or {}
                if (
                    target.get("sha256") != incoming.get("sha256")
                    or target.get("routing_fingerprint") != incoming.get("routing_fingerprint")
                ):
                    raise ValueError("checkpoint target does not match deterministic plan")
                planned = {
                    step["id"]: (
                        step["tool"],
                        _digest_json({
                            "step_id": step["id"], "tool": step["tool"],
                            "arguments": step.get("arguments", {}),
                        }),
                        step.get("fallbacks", []),
                    )
                    for step in selected
                }
                stored = {
                    step_id: (
                        step.get("tool"), step.get("command_identity"),
                        step.get("fallbacks", []),
                    )
                    for step_id, step in checkpoint.get("steps", {}).items()
                }
                if planned != stored:
                    raise ValueError("checkpoint steps do not match deterministic plan")
            self._reconcile_checkpoint(checkpoint, path)
            return self._checkpoint_summary(checkpoint, path)

    def _reconcile_checkpoint(self, checkpoint: dict, path: Path) -> None:
        """Recover evidence committed just before an interrupted checkpoint write."""
        known = {
            attempt.get("evidence_id")
            for step in checkpoint.get("steps", {}).values()
            for attempt in step.get("attempts", [])
        }
        recovered = []
        for evidence_path in sorted(self.evidence_dir.glob("ev_*.json")):
            if evidence_path.stem in known:
                continue
            record = self._read_json(evidence_path, None)
            if (
                not isinstance(record, dict)
                or record.get("schema") != EVIDENCE_SCHEMA
                or record.get("evidence_id") != evidence_path.stem
                or _expected_evidence_id(record) != evidence_path.stem
                or record.get("plan_id") != checkpoint.get("plan_id")
                or not self._evidence_files_intact(record)
            ):
                continue
            step = checkpoint.get("steps", {}).get(record.get("step_id"))
            if not isinstance(step, dict):
                continue
            tool = _object(record.get("tool"))
            command = _object(record.get("command"))
            timestamps = _object(record.get("timestamps"))
            attempt = {
                "evidence_id": record["evidence_id"],
                "status": record.get("status"),
                "tool": tool.get("name"),
                "command_identity": command.get("identity"),
                "recorded_at": timestamps.get("recorded_at"),
                "recovered_after_interruption": True,
            }
            step.setdefault("attempts", []).append(attempt)
            recovered.append(attempt)
        if not recovered:
            return
        for step in checkpoint.get("steps", {}).values():
            step.get("attempts", []).sort(key=lambda attempt: (
                str(attempt.get("recorded_at", "")), str(attempt.get("evidence_id", "")),
            ))
        checkpoint["revision"] = int(checkpoint.get("revision", 1)) + 1
        checkpoint["updated_at"] = _utc_now()
        self._atomic_json(path, checkpoint)

    def _evidence_files_intact(self, record: dict) -> bool:
        candidates = [
            _object(record.get("retained_output")),
            _object(record.get("result_snapshot")),
        ]
        try:
            for candidate in candidates:
                path = self._inside_work(Path(str(candidate.get("path", ""))))
                digest, size = _hash_file(path)
                if digest != candidate.get("sha256") or size != candidate.get("size"):
                    return False
            artifact = _object(record.get("artifact"))
            artifact_path = self._inside_work(Path(str(artifact.get("path", ""))))
            digest, _ = _hash_file(artifact_path)
            return digest == artifact.get("sha256")
        except (OSError, ValueError):
            return False

    @staticmethod
    def _step_state(step: dict) -> str:
        attempts = step.get("attempts", [])
        if attempts:
            return "completed" if attempts[-1].get("status") == "success" else "recorded_gap"
        return "deferred" if step.get("planned_state") == "deferred" else "pending"

    def _checkpoint_summary(self, checkpoint: dict, path: Path) -> dict:
        by_state: dict[str, list[str]] = {
            "completed": [], "recorded_gap": [], "pending": [], "deferred": [],
        }
        step_evidence: dict[str, list[str]] = {}
        step_evidence_totals: dict[str, int] = {}
        for step_id, step in checkpoint.get("steps", {}).items():
            by_state[self._step_state(step)].append(step_id)
            evidence_ids = [attempt["evidence_id"] for attempt in step.get("attempts", [])]
            if evidence_ids:
                step_evidence[step_id] = evidence_ids[-MAX_STEP_EVIDENCE:]
                step_evidence_totals[step_id] = len(evidence_ids)
        return {
            "schema": CHECKPOINT_SCHEMA,
            "plan_id": checkpoint["plan_id"],
            "path": str(path),
            "revision": checkpoint.get("revision", 1),
            "updated_at": checkpoint.get("updated_at"),
            "completed_steps": by_state["completed"],
            "recorded_gap_steps": by_state["recorded_gap"],
            "remaining_ready_steps": by_state["pending"],
            "deferred_steps": by_state["deferred"],
            "step_evidence": step_evidence,
            "step_evidence_totals": step_evidence_totals,
            "step_evidence_truncated": any(
                total > MAX_STEP_EVIDENCE for total in step_evidence_totals.values()
            ),
            "resumed": bool(step_evidence),
        }

    def annotate_plan(self, plan: dict, summary: dict) -> None:
        completed = set(summary["completed_steps"])
        gaps = set(summary["recorded_gap_steps"])
        pending = set(summary["remaining_ready_steps"])
        for step in plan.get("selected", []):
            step_id = step["id"]
            if step_id in completed:
                state = "completed"
            elif step_id in gaps:
                state = "recorded_gap"
            elif step_id in pending:
                state = "pending"
            else:
                state = "deferred"
            step["checkpoint_state"] = state
            if step_id in summary["step_evidence"]:
                step["evidence_ids"] = summary["step_evidence"][step_id]
        plan["checkpoint"] = summary

    @staticmethod
    def _tool_version(tool_name: str, supplied: str | None) -> tuple[str, str]:
        if supplied:
            return _bounded_text(supplied, "tool_version", 200), "caller"
        if tool_name.startswith("lab."):
            try:
                version = importlib.metadata.version("blackwall-lab")
            except importlib.metadata.PackageNotFoundError:
                version = "development"
            return version, "blackwall-lab package"
        return "unknown", "not supplied"

    def _retain_result(self, payload: dict) -> dict:
        encoded = (
            json.dumps(payload, indent=2, ensure_ascii=False, default=str) + "\n"
        ).encode("utf-8")
        if len(encoded) > MAX_JSON_BYTES:
            raise ValueError(f"normalized result exceeds {MAX_JSON_BYTES} bytes")
        digest = hashlib.sha256(encoded).hexdigest()
        path = self.output_dir / f"{digest}.json"
        if not path.exists():
            self._atomic_json(path, payload)
        file_digest, size = _hash_file(path)
        if file_digest != digest:
            raise ValueError(f"corrupt content-addressed result snapshot: {path}")
        os.chmod(path, 0o444)
        return {"path": str(path), "sha256": file_digest, "size": size, "media_type": "application/json"}

    def _retained_output(self, result: dict, snapshot: dict) -> dict:
        candidate = result.get("saved_to")
        if isinstance(candidate, str):
            try:
                path = self._inside_work(Path(candidate))
            except ValueError:
                path = None
            if path is not None and path.is_file():
                sha256, size = _hash_file(path)
                retained_path = self.output_dir / f"{sha256}.blob"
                retained_created = False
                if retained_path != path:
                    if not retained_path.exists():
                        retained_created = True
                        fd, temporary = tempfile.mkstemp(prefix=".output.", dir=self.output_dir)
                        try:
                            with path.open("rb") as src, os.fdopen(fd, "wb") as dst:
                                shutil.copyfileobj(src, dst, length=1024 * 1024)
                                dst.flush()
                                os.fsync(dst.fileno())
                            os.chmod(temporary, 0o444)
                            os.replace(temporary, retained_path)
                            directory_fd = os.open(
                                self.output_dir, os.O_RDONLY | os.O_DIRECTORY,
                            )
                            try:
                                os.fsync(directory_fd)
                            finally:
                                os.close(directory_fd)
                        finally:
                            if os.path.exists(temporary):
                                os.unlink(temporary)
                    retained_sha256, retained_size = _hash_file(retained_path)
                    if retained_sha256 != sha256 or retained_size != size:
                        if retained_created:
                            retained_path.unlink(missing_ok=True)
                        raise ValueError(f"corrupt content-addressed retained output: {retained_path}")
                else:
                    retained_path = path
                return {
                    "path": str(retained_path), "source_path": str(path),
                    "sha256": sha256, "size": size,
                    "media_type": (
                        "application/json" if path.suffix == ".json"
                        else "text/plain" if path.suffix in {".txt", ".log"}
                        else "application/octet-stream"
                    ),
                }
        return snapshot

    @staticmethod
    def _truncation(result: dict) -> dict:
        signals: set[str] = set()
        pending: list[object] = [result]
        inspected = 0
        while pending and inspected < 10_000:
            value = pending.pop()
            inspected += 1
            if isinstance(value, dict):
                for key, nested in value.items():
                    if key in {"truncated", "evidence_truncated", "output_truncated"} and nested is True:
                        signals.add(key)
                    pending.append(nested)
            elif isinstance(value, list):
                pending.extend(value)
            elif isinstance(value, str) and "... [truncated " in value:
                signals.add("bounded_text_marker")
        return {
            "occurred": bool(signals),
            "signals": sorted(signals),
            "inspection_limited": bool(pending),
        }

    def record_result(
        self,
        *,
        plan_id: str,
        step_id: str,
        tool_name: str,
        normalized: dict,
        result: dict | None,
        error: str | None,
        confidence: str = "observed",
        tool_version: str | None = None,
        command_arguments: dict | None = None,
    ) -> tuple[dict, dict]:
        if confidence not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid confidence: {confidence}")
        if not re.fullmatch(r"[0-9a-f]{16}", plan_id):
            raise ValueError("invalid plan_id")
        version, version_source = self._tool_version(tool_name, tool_version)
        checkpoint_path = self.checkpoint_dir / f"{plan_id}.json"
        payload = {"result": result, "error": error, "normalized": normalized}

        with self._lock():
            checkpoint = self._read_json(checkpoint_path, None)
            if (
                not isinstance(checkpoint, dict)
                or checkpoint.get("schema") != CHECKPOINT_SCHEMA
                or not isinstance(checkpoint.get("steps"), dict)
            ):
                raise ValueError(f"unknown analysis checkpoint: {plan_id}")
            step = checkpoint.get("steps", {}).get(step_id)
            if not isinstance(step, dict):
                raise ValueError(f"step is not part of plan {plan_id}: {step_id}")
            expected_tool = step.get("tool")
            aliases = {expected_tool, str(expected_tool).removeprefix("lab.")}
            role = "primary"
            fallback = None
            if tool_name not in aliases:
                fallback = next(
                    (
                        item for item in step.get("fallbacks", [])
                        if tool_name in {
                            item.get("tool"), str(item.get("tool", "")).removeprefix("lab."),
                        }
                    ),
                    None,
                )
                if fallback is None:
                    allowed = [expected_tool] + [
                        item.get("tool") for item in step.get("fallbacks", [])
                    ]
                    raise ValueError(f"tool does not match planned step or fallback: expected one of {allowed}")
                if command_arguments is None:
                    raise ValueError("command_arguments are required when recording a fallback")
                role = "fallback"
            if command_arguments is not None and not isinstance(command_arguments, dict):
                raise ValueError("command_arguments must be an object or null")
            actual_arguments = command_arguments if command_arguments is not None else step.get("arguments", {})
            if len(_canonical_json(actual_arguments)) > 64_000:
                raise ValueError("command_arguments are too large")
            command_identity = _digest_json({
                "step_id": step_id,
                "tool": tool_name,
                "arguments": actual_arguments,
                "role": role,
            })

            snapshot = self._retain_result(payload)
            retained = self._retained_output(result or {}, snapshot)
            lineage = self._lineage()
            self._bootstrap_artifacts(lineage)
            target = checkpoint.get("target") or {}
            target_path = Path(str(target.get("path", "")))
            artifact = self._artifact_for_path(target_path, lineage, verify=False)
            parents = [edge.get("sha256") for edge in artifact.get("parents", [])]
            now = _utc_now()
            identity = {
                "schema": EVIDENCE_SCHEMA,
                "plan_id": plan_id,
                "step_id": step_id,
                "artifact_sha256": artifact["sha256"],
                "tool": tool_name,
                "tool_version": version,
                "command_identity": command_identity,
                "status": normalized.get("status"),
                "retained_sha256": retained["sha256"],
                "snapshot_sha256": snapshot["sha256"],
                "confidence": confidence,
            }
            evidence_id = f"ev_{_digest_json(identity)[:24]}"
            record = {
                "schema": EVIDENCE_SCHEMA,
                "evidence_id": evidence_id,
                "plan_id": plan_id,
                "step_id": step_id,
                "tool": {
                    "name": tool_name,
                    "version": version,
                    "version_source": version_source,
                },
                "command": {
                    "identity": command_identity,
                    "role": role,
                    "arguments": actual_arguments,
                    "planned_fallback": fallback,
                },
                "artifact": {
                    "sha256": artifact["sha256"],
                    "path": str(target_path),
                    "parent_sha256": parents[0] if parents else None,
                    "parent_sha256s": parents,
                },
                "timestamps": {
                    "observed_at": now,
                    "completed_at": now,
                    "recorded_at": now,
                },
                "confidence": confidence,
                "status": normalized.get("status"),
                "truncation": self._truncation(result or {}),
                "retained_output": retained,
                "result_snapshot": snapshot,
                "normalized_gap": normalized.get("gap"),
            }
            evidence_path = self.evidence_dir / f"{evidence_id}.json"
            if evidence_path.exists():
                persisted = self._read_json(evidence_path, None)
                if not isinstance(persisted, dict) or persisted.get("schema") != EVIDENCE_SCHEMA:
                    raise ValueError(f"invalid existing evidence record: {evidence_path}")
                record = persisted
            else:
                self._atomic_json(evidence_path, record)
            attempts = step.setdefault("attempts", [])
            if not any(attempt.get("evidence_id") == evidence_id for attempt in attempts):
                attempts.append({
                    "evidence_id": evidence_id,
                    "status": normalized.get("status"),
                    "tool": tool_name,
                    "command_identity": command_identity,
                    "recorded_at": now,
                })
                checkpoint["revision"] = int(checkpoint.get("revision", 1)) + 1
                checkpoint["updated_at"] = now
                self._atomic_json(checkpoint_path, checkpoint)
            self._attach_evidence_to_derived(
                lineage, result or {}, evidence_id, artifact["sha256"],
            )
            lineage["updated_at"] = now
            self._atomic_json(self.lineage_path, lineage)
            summary = self._checkpoint_summary(checkpoint, checkpoint_path)
        return record, summary

    def _attach_evidence_to_derived(
        self, lineage: dict, value: object, evidence_id: str, parent_sha256: str,
    ) -> None:
        strings: list[str] = []

        def collect(item: object) -> None:
            if isinstance(item, str):
                strings.append(item)
            elif isinstance(item, dict):
                for nested in item.values():
                    collect(nested)
            elif isinstance(item, list):
                for nested in item:
                    collect(nested)

        collect(value)
        derived = (self.samples / "derived").resolve()
        for text in strings:
            try:
                path = Path(text).resolve()
            except (OSError, ValueError):
                continue
            if path.parent != derived or not SHA256_RE.fullmatch(path.name):
                continue
            entry = lineage["artifacts"].get(path.name)
            if not entry:
                continue
            for edge in entry.get("parents", []):
                if edge.get("sha256") != parent_sha256:
                    continue
                ids = edge.setdefault("producer_evidence_ids", [])
                if evidence_id not in ids:
                    ids.append(evidence_id)

    def record_observation(
        self,
        *,
        artifact_path: Path,
        step_id: str,
        tool_name: str,
        command_arguments: dict,
        normalized: dict,
        result: dict | None,
        error: str | None,
        confidence: str = "observed",
        tool_version: str | None = None,
    ) -> dict:
        """Retain a bounded tool observation that is outside a router step."""
        if confidence not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid confidence: {confidence}")
        if not isinstance(command_arguments, dict):
            raise ValueError("command_arguments are required for standalone evidence")
        if len(_canonical_json(command_arguments)) > 64_000:
            raise ValueError("command_arguments are too large")
        version, version_source = self._tool_version(tool_name, tool_version)
        command_identity = _digest_json({
            "step_id": step_id,
            "tool": tool_name,
            "arguments": command_arguments,
            "role": "standalone",
        })
        payload = {"result": result, "error": error, "normalized": normalized}

        with self._lock():
            snapshot = self._retain_result(payload)
            retained = self._retained_output(result or {}, snapshot)
            lineage = self._lineage()
            self._bootstrap_artifacts(lineage)
            artifact = self._artifact_for_path(artifact_path, lineage, verify=False)
            parents = [edge.get("sha256") for edge in artifact.get("parents", [])]
            now = _utc_now()
            identity = {
                "schema": EVIDENCE_SCHEMA,
                "plan_id": None,
                "step_id": step_id,
                "artifact_sha256": artifact["sha256"],
                "tool": tool_name,
                "tool_version": version,
                "command_identity": command_identity,
                "status": normalized.get("status"),
                "retained_sha256": retained["sha256"],
                "snapshot_sha256": snapshot["sha256"],
                "confidence": confidence,
            }
            evidence_id = f"ev_{_digest_json(identity)[:24]}"
            record = {
                "schema": EVIDENCE_SCHEMA,
                "evidence_id": evidence_id,
                "plan_id": None,
                "step_id": step_id,
                "tool": {
                    "name": tool_name,
                    "version": version,
                    "version_source": version_source,
                },
                "command": {
                    "identity": command_identity,
                    "role": "standalone",
                    "arguments": command_arguments,
                    "planned_fallback": None,
                },
                "artifact": {
                    "sha256": artifact["sha256"],
                    "path": str(Path(artifact_path).resolve()),
                    "parent_sha256": parents[0] if parents else None,
                    "parent_sha256s": parents,
                },
                "timestamps": {
                    "observed_at": now,
                    "completed_at": now,
                    "recorded_at": now,
                },
                "confidence": confidence,
                "status": normalized.get("status"),
                "truncation": self._truncation(result or {}),
                "retained_output": retained,
                "result_snapshot": snapshot,
                "normalized_gap": normalized.get("gap"),
            }
            evidence_path = self.evidence_dir / f"{evidence_id}.json"
            if evidence_path.exists():
                persisted = self._read_json(evidence_path, None)
                if not isinstance(persisted, dict) or persisted.get("schema") != EVIDENCE_SCHEMA:
                    raise ValueError(f"invalid existing evidence record: {evidence_path}")
                record = persisted
            else:
                self._atomic_json(evidence_path, record)
            self._attach_evidence_to_derived(
                lineage, result or {}, evidence_id, artifact["sha256"],
            )
            lineage["updated_at"] = now
            self._atomic_json(self.lineage_path, lineage)
            return record

    @staticmethod
    def _canonical_finding_value(subject: str, value: object) -> object:
        if isinstance(value, dict):
            return {
                str(key): EvidenceStore._canonical_finding_value(subject, nested)
                for key, nested in sorted(value.items(), key=lambda item: str(item[0]))
            }
        if isinstance(value, list):
            return [EvidenceStore._canonical_finding_value(subject, item) for item in value]
        if not isinstance(value, str):
            return value
        compact = " ".join(value.strip().split())
        lowered_subject = subject.casefold()
        if "url" in lowered_subject:
            parts = urlsplit(compact)
            return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path, parts.query, parts.fragment))
        if any(token in lowered_subject for token in (
            "hash", "sha", "md5", "domain", "host", "family", "mitre", "technique", "ip",
        )):
            return compact.casefold().rstrip(".")
        return compact

    def record_findings(self, evidence_id: str, findings: list[dict]) -> dict:
        if not ID_RE.fullmatch(evidence_id):
            raise ValueError("invalid evidence_id")
        if not isinstance(findings, list) or not findings or len(findings) > MAX_FINDINGS:
            raise ValueError(f"findings must contain 1..{MAX_FINDINGS} objects")
        evidence_path = self.evidence_dir / f"{evidence_id}.json"
        with self._lock():
            evidence = self._read_json(evidence_path, None)
            if not isinstance(evidence, dict) or evidence.get("schema") != EVIDENCE_SCHEMA:
                raise ValueError(f"unknown evidence record: {evidence_id}")
            index = self._read_json(
                self.findings_path,
                {"schema": FINDINGS_SCHEMA, "updated_at": None, "groups": {}},
            )
            if (
                not isinstance(index, dict)
                or index.get("schema") != FINDINGS_SCHEMA
                or not isinstance(index.get("groups"), dict)
            ):
                raise ValueError("finding index has an unsupported schema")
            added = deduplicated = 0
            touched: list[str] = []
            for finding in findings:
                if not isinstance(finding, dict):
                    raise ValueError("each finding must be an object")
                subject = _bounded_text(finding.get("subject"), "finding subject", 300)
                if "value" not in finding:
                    raise ValueError("finding value is required")
                value = finding["value"]
                if len(_canonical_json(value)) > 64_000:
                    raise ValueError("finding value is too large")
                location = finding.get("location")
                if location is not None:
                    location = _bounded_text(location, "finding location", 500)
                confidence = finding.get("confidence", evidence.get("confidence", "observed"))
                if confidence not in CONFIDENCE_LEVELS:
                    raise ValueError(f"invalid confidence: {confidence}")
                group_key = {
                    "subject": " ".join(subject.strip().split()).casefold(),
                    "location": location,
                }
                group_id = f"fg_{_digest_json(group_key)[:24]}"
                canonical = self._canonical_finding_value(subject, value)
                variant_id = f"fv_{_digest_json(canonical)[:24]}"
                group = index["groups"].setdefault(group_id, {
                    "subject": subject,
                    "location": location,
                    "variants": {},
                    "disagreement": False,
                })
                variant = group["variants"].get(variant_id)
                if variant is None:
                    variant = {
                        "canonical_value": canonical,
                        "display_values": [value],
                        "evidence_ids": [],
                        "engines": [],
                        "confidences": [],
                    }
                    group["variants"][variant_id] = variant
                    added += 1
                else:
                    deduplicated += 1
                    if value not in variant["display_values"]:
                        variant["display_values"].append(value)
                if evidence_id not in variant["evidence_ids"]:
                    variant["evidence_ids"].append(evidence_id)
                engine = evidence.get("tool", {}).get("name")
                if engine and engine not in variant["engines"]:
                    variant["engines"].append(engine)
                if confidence not in variant["confidences"]:
                    variant["confidences"].append(confidence)
                group["disagreement"] = len(group["variants"]) > 1
                touched.append(group_id)
            index["updated_at"] = _utc_now()
            self._atomic_json(self.findings_path, index)
            disagreements = [
                group_id for group_id in sorted(set(touched))
                if index["groups"][group_id]["disagreement"]
            ]
        return {
            "schema": FINDINGS_SCHEMA,
            "evidence_id": evidence_id,
            "groups": sorted(set(touched)),
            "variants_added": added,
            "equivalent_findings_deduplicated": deduplicated,
            "disagreements": disagreements,
        }

    def link_claim(
        self,
        *,
        statement: str,
        evidence_ids: list[str],
        claim_type: str = "report",
        location: str | None = None,
        confidence: str = "derived",
    ) -> dict:
        statement = _bounded_text(statement, "statement", 4000)
        if claim_type not in CLAIM_TYPES:
            raise ValueError(f"invalid claim_type: {claim_type}")
        if confidence not in CONFIDENCE_LEVELS:
            raise ValueError(f"invalid confidence: {confidence}")
        if not isinstance(evidence_ids, list) or not 1 <= len(evidence_ids) <= MAX_CLAIM_EVIDENCE:
            raise ValueError(f"evidence_ids must contain 1..{MAX_CLAIM_EVIDENCE} IDs")
        evidence_ids = sorted(set(evidence_ids))
        if any(not ID_RE.fullmatch(item) for item in evidence_ids):
            raise ValueError("invalid evidence_id")
        if location is not None:
            location = _bounded_text(location, "claim location", 1000)
        identity = {
            "claim_type": claim_type,
            "statement": " ".join(statement.split()),
            "location": location,
            "evidence_ids": evidence_ids,
        }
        claim_id = f"claim_{_digest_json(identity)[:24]}"
        with self._lock():
            missing = [
                item for item in evidence_ids
                if not (self.evidence_dir / f"{item}.json").is_file()
            ]
            if missing:
                raise ValueError(f"unknown evidence records: {', '.join(missing)}")
            record = {
                "schema": CLAIM_SCHEMA,
                "claim_id": claim_id,
                "claim_type": claim_type,
                "statement": statement,
                "location": location,
                "confidence": confidence,
                "evidence_ids": evidence_ids,
                "created_at": _utc_now(),
            }
            path = self.claim_dir / f"{claim_id}.json"
            if path.exists():
                persisted = self._read_json(path, None)
                if not isinstance(persisted, dict) or persisted.get("schema") != CLAIM_SCHEMA:
                    raise ValueError(f"invalid existing claim record: {path}")
                record = persisted
            else:
                self._atomic_json(path, record)
        return record | {
            "path": str(path),
            "citation": f"[evidence:{claim_id}]",
        }

    def status(self, plan_id: str | None = None) -> dict:
        with self._lock():
            checkpoints = sorted(self.checkpoint_dir.glob("*.json"))
            if plan_id is not None:
                if not re.fullmatch(r"[0-9a-f]{16}", plan_id):
                    raise ValueError("invalid plan_id")
                path = self.checkpoint_dir / f"{plan_id}.json"
                checkpoint = self._read_json(path, None)
                if (
                    not isinstance(checkpoint, dict)
                    or checkpoint.get("schema") != CHECKPOINT_SCHEMA
                    or not isinstance(checkpoint.get("steps"), dict)
                ):
                    raise ValueError(f"unknown analysis checkpoint: {plan_id}")
                selected = self._checkpoint_summary(checkpoint, path)
            else:
                selected = None
            lineage = self._lineage()
            if self._bootstrap_artifacts(lineage):
                lineage["updated_at"] = _utc_now()
                self._atomic_json(self.lineage_path, lineage)
            findings = self._read_json(
                self.findings_path, {"schema": FINDINGS_SCHEMA, "groups": {}},
            )
            if (
                not isinstance(findings, dict)
                or findings.get("schema") != FINDINGS_SCHEMA
                or not isinstance(findings.get("groups"), dict)
            ):
                raise ValueError("finding index is malformed or has an unsupported schema")
            groups = findings["groups"]
            disagreements = []
            for group_id, group in sorted(groups.items()):
                if not isinstance(group, dict):
                    continue
                if not group.get("disagreement"):
                    continue
                variants = []
                for variant_id, variant in list(sorted(group.get("variants", {}).items()))[
                    :MAX_STATUS_VARIANTS
                ]:
                    encoded_value = json.dumps(
                        variant.get("canonical_value"), ensure_ascii=False, default=str,
                    )
                    variants.append({
                        "variant_id": variant_id,
                        "value": (
                            variant.get("canonical_value") if len(encoded_value) <= 2000
                            else encoded_value[:2000] + "... [truncated]"
                        ),
                        "engines": variant.get("engines", [])[:20],
                        "evidence_ids": variant.get("evidence_ids", [])[:20],
                    })
                disagreements.append({
                    "group_id": group_id,
                    "subject": group.get("subject"),
                    "location": group.get("location"),
                    "variants": variants,
                    "variant_count": len(group.get("variants", {})),
                    "variants_truncated": len(group.get("variants", {})) > MAX_STATUS_VARIANTS,
                })
            return {
                "schema": "blackwall.evidence-status.v1",
                "state_dir": str(self.state),
                "counts": {
                    "artifacts": len(lineage["artifacts"]),
                    "evidence_records": len(list(self.evidence_dir.glob("ev_*.json"))),
                    "finding_groups": len(groups),
                    "finding_disagreements": sum(
                        bool(group.get("disagreement")) for group in groups.values()
                    ),
                    "claims": len(list(self.claim_dir.glob("claim_*.json"))),
                    "checkpoints": len(checkpoints),
                },
                "checkpoint": selected,
                "disagreements": disagreements[:MAX_STATUS_DISAGREEMENTS],
                "disagreements_truncated": len(disagreements) > MAX_STATUS_DISAGREEMENTS,
            }

    def artifact_inventory(self) -> dict:
        """Return a bounded, authoritative parent/child inventory for analysts."""
        with self._lock():
            lineage = self._lineage()
            if self._bootstrap_artifacts(lineage):
                lineage["updated_at"] = _utc_now()
                self._atomic_json(self.lineage_path, lineage)
            artifacts = []
            for sha256 in sorted(lineage["artifacts"]):
                stored = lineage["artifacts"][sha256]
                if not isinstance(stored, dict):
                    raise ValueError(f"artifact lineage entry is malformed: {sha256}")
                parents = stored.get("parents", [])
                if not isinstance(parents, list):
                    raise ValueError(f"artifact lineage parents are malformed: {sha256}")
                bounded_parents = [
                    parent | {
                        "labels": parent.get("labels", [])[:10],
                        "producer_evidence_ids": parent.get("producer_evidence_ids", [])[:20],
                    }
                    for parent in parents[:MAX_INVENTORY_PARENTS]
                ]
                artifacts.append(stored | {
                    "paths": stored.get("paths", [])[:5],
                    "paths_total": len(stored.get("paths", [])),
                    "parents": bounded_parents,
                    "parents_total": len(parents),
                    "parents_truncated": len(parents) > MAX_INVENTORY_PARENTS,
                })
            return {
                "schema": LINEAGE_SCHEMA,
                "path": str(self.lineage_path),
                "artifacts": artifacts[:MAX_INVENTORY_ARTIFACTS],
                "total": len(artifacts),
                "truncated": len(artifacts) > MAX_INVENTORY_ARTIFACTS,
            }

    def audit(self, claim_id: str | None = None) -> dict:
        issues: list[dict] = []
        checked_evidence: set[str] = set()
        with self._lock():
            if claim_id is not None:
                if not ID_RE.fullmatch(claim_id) or not claim_id.startswith("claim_"):
                    raise ValueError("invalid claim_id")
                claim_paths = [self.claim_dir / f"{claim_id}.json"]
            else:
                claim_paths = sorted(self.claim_dir.glob("claim_*.json"))
            claims = []
            for path in claim_paths:
                claim = self._read_json(path, None)
                if not isinstance(claim, dict) or claim.get("schema") != CLAIM_SCHEMA:
                    issues.append({"kind": "invalid_claim", "path": str(path)})
                    continue
                evidence_ids = claim.get("evidence_ids")
                if not isinstance(evidence_ids, list) or any(
                    not isinstance(item, str) for item in evidence_ids
                ):
                    issues.append({"kind": "invalid_claim_evidence_ids", "claim_id": path.stem})
                    evidence_ids = []
                claim_identity = {
                    "claim_type": claim.get("claim_type"),
                    "statement": " ".join(str(claim.get("statement", "")).split()),
                    "location": claim.get("location"),
                    "evidence_ids": sorted(set(evidence_ids)),
                }
                expected_claim_id = f"claim_{_digest_json(claim_identity)[:24]}"
                if claim.get("claim_id") != expected_claim_id or path.stem != expected_claim_id:
                    issues.append({"kind": "claim_identity_mismatch", "claim_id": path.stem})
                claims.append(claim)
                for evidence_id in evidence_ids:
                    checked_evidence.add(evidence_id)
            if claim_id is None:
                checked_evidence.update(path.stem for path in self.evidence_dir.glob("ev_*.json"))

            for evidence_id in sorted(checked_evidence):
                path = self.evidence_dir / f"{evidence_id}.json"
                record = self._read_json(path, None)
                if not isinstance(record, dict) or record.get("schema") != EVIDENCE_SCHEMA:
                    issues.append({"kind": "missing_or_invalid_evidence", "evidence_id": evidence_id})
                    continue
                expected_evidence_id = _expected_evidence_id(record)
                if record.get("evidence_id") != expected_evidence_id or evidence_id != expected_evidence_id:
                    issues.append({"kind": "evidence_identity_mismatch", "evidence_id": evidence_id})
                command = _object(record.get("command"))
                tool = _object(record.get("tool"))
                expected_command_identity = _digest_json({
                    "step_id": record.get("step_id"),
                    "tool": tool.get("name"),
                    "arguments": command.get("arguments"),
                    "role": command.get("role"),
                })
                if command.get("identity") != expected_command_identity:
                    issues.append({"kind": "command_identity_mismatch", "evidence_id": evidence_id})
                for field in ("retained_output", "result_snapshot"):
                    retained = _object(record.get(field))
                    retained_path = Path(str(retained.get("path", "")))
                    if not retained_path.is_file():
                        issues.append({"kind": "missing_output", "evidence_id": evidence_id, "field": field})
                        continue
                    digest, size = _hash_file(retained_path)
                    if digest != retained.get("sha256") or size != retained.get("size"):
                        issues.append({"kind": "output_digest_mismatch", "evidence_id": evidence_id, "field": field})
                artifact = _object(record.get("artifact"))
                artifact_path = Path(str(artifact.get("path", "")))
                if not artifact_path.is_file():
                    issues.append({"kind": "missing_artifact", "evidence_id": evidence_id})
                else:
                    digest, _ = _hash_file(artifact_path)
                    if digest != artifact.get("sha256"):
                        issues.append({"kind": "artifact_digest_mismatch", "evidence_id": evidence_id})

            lineage = self._lineage()
            if self._bootstrap_artifacts(lineage):
                lineage["updated_at"] = _utc_now()
                self._atomic_json(self.lineage_path, lineage)
            artifacts = lineage["artifacts"]
            for child_sha256, child in artifacts.items():
                if not isinstance(child, dict):
                    issues.append({"kind": "invalid_lineage_artifact", "artifact": child_sha256})
                    continue
                parents = child.get("parents")
                paths_value = child.get("paths")
                if not isinstance(parents, list) or not isinstance(paths_value, list):
                    issues.append({"kind": "invalid_lineage_artifact", "artifact": child_sha256})
                    continue
                if child.get("kind") == "derived" and not parents:
                    issues.append({
                        "kind": "unlinked_derived_artifact",
                        "artifact": child_sha256,
                    })
                paths = [Path(path) for path in paths_value if isinstance(path, str)]
                existing_paths = [path for path in paths if path.is_file()]
                if not existing_paths:
                    issues.append({"kind": "missing_lineage_artifact", "artifact": child_sha256})
                else:
                    digest, size = _hash_file(existing_paths[0])
                    if digest != child_sha256 or size != child.get("size"):
                        issues.append({"kind": "lineage_artifact_mismatch", "artifact": child_sha256})
                for edge in parents:
                    if not isinstance(edge, dict):
                        issues.append({"kind": "invalid_parent_edge", "child": child_sha256})
                        continue
                    parent_sha256 = edge.get("sha256")
                    if parent_sha256 not in artifacts:
                        issues.append({"kind": "missing_parent", "child": child_sha256, "parent": parent_sha256})
                    elif self._would_cycle(artifacts, parent_sha256, child_sha256):
                        issues.append({"kind": "lineage_cycle", "child": child_sha256, "parent": parent_sha256})
            return {
                "schema": AUDIT_SCHEMA,
                "ok": not issues,
                "claim_id": claim_id,
                "claims_checked": len(claims),
                "evidence_checked": len(checked_evidence),
                "artifacts_checked": len(artifacts),
                "issue_count": len(issues),
                "issues": issues[:MAX_AUDIT_ISSUES],
                "issues_truncated": len(issues) > MAX_AUDIT_ISSUES,
                "audited_at": _utc_now(),
            }


def evidence_self_check() -> dict:
    """Exercise resume, deduplication, disagreements, lineage, and audit."""
    with tempfile.TemporaryDirectory() as temporary:
        work = Path(temporary) / "work"
        original_dir = work / "samples" / "original"
        scratch = work / "scratch"
        original_dir.mkdir(parents=True)
        scratch.mkdir(parents=True)
        original_data = b"blackwall evidence fixture"
        original_sha256 = hashlib.sha256(original_data).hexdigest()
        original = original_dir / original_sha256
        original.write_bytes(original_data)
        plan = {
            "schema": "blackwall.analysis-plan.v1",
            "plan_id": "0123456789abcdef",
            "target": {
                "path": str(original), "sha256": original_sha256,
                "routing_fingerprint": "fixture",
            },
            "phase": "full",
            "selected": [{
                "id": "triage.fixture", "tool": "lab.fixture", "state": "ready",
                "arguments": {"path": str(original)},
            }],
        }
        store = EvidenceStore(work)
        initial = store.ensure_plan(plan)
        normalized = {"status": "success", "gap": None}
        evidence, completed = store.record_result(
            plan_id=plan["plan_id"], step_id="triage.fixture", tool_name="lab.fixture",
            normalized=normalized, result={"summary": {"family": "Fixture"}}, error=None,
        )
        first = store.record_findings(evidence["evidence_id"], [
            {"subject": "classification.family", "value": "Fixture"},
        ])
        duplicate = store.record_findings(evidence["evidence_id"], [
            {"subject": "classification.family", "value": "fixture"},
        ])
        child = scratch / "child"
        child.write_bytes(b"derived fixture")
        registered = store.register_artifact(
            child, parent_path=original, relationship="self-check", label="fixture child",
            producer_tool="lab.fixture", producer_evidence_id=evidence["evidence_id"],
        )
        repeated = store.register_artifact(
            child, parent_path=original, relationship="self-check", label="fixture child",
            producer_tool="lab.fixture", producer_evidence_id=evidence["evidence_id"],
        )
        loop_prevented = False
        try:
            store.register_artifact(
                original, parent_path=original, relationship="self-check", label="loop",
                producer_tool="lab.fixture",
            )
        except ValueError as exc:
            loop_prevented = "loop" in str(exc)
        claim = store.link_claim(
            statement="The inert fixture was identified.",
            evidence_ids=[evidence["evidence_id"]],
        )
        audit = store.audit(claim["claim_id"])
        resumed = store.ensure_plan(plan)
        checks = {
            "initial_pending": initial["remaining_ready_steps"] == ["triage.fixture"],
            "completed": completed["completed_steps"] == ["triage.fixture"],
            "resumed_without_rebuild": resumed["remaining_ready_steps"] == [] and resumed["resumed"],
            "finding_added": first["variants_added"] == 1,
            "equivalent_finding_deduplicated": duplicate["equivalent_findings_deduplicated"] == 1,
            "artifact_parent_recorded": registered["parent_sha256"] == original_sha256,
            "artifact_deduplicated": repeated["deduplicated"],
            "recursive_loop_prevented": loop_prevented,
            "claim_auditable": audit["ok"] and audit["evidence_checked"] == 1,
        }
        if not all(checks.values()):
            raise RuntimeError(f"evidence self-check failed: {checks}")
        return {
            "schema": "blackwall.evidence-self-check.v1",
            "ok": True,
            "checks": checks,
            "schemas": [
                EVIDENCE_SCHEMA, LINEAGE_SCHEMA, FINDINGS_SCHEMA,
                CHECKPOINT_SCHEMA, CLAIM_SCHEMA, AUDIT_SCHEMA,
            ],
        }
