"""Deterministic case reports, comparisons, and encrypted portable bundles.

The module is intentionally usable without MCP. Host lifecycle commands invoke
it in the same hardened image that owns the analysis volume, so raw sample
bytes are never extracted onto the host.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path, PurePosixPath

REPORT_SCHEMA = "blackwall.case-report.v1"
COMPARISON_SCHEMA = "blackwall.case-comparison.v1"
BUNDLE_SCHEMA = "blackwall.case-bundle.v1"
STATUS_SCHEMA = "blackwall.case-status.v1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PLAN_RE = re.compile(r"^[0-9a-f]{16}$")
MAX_STATE_FILE = 16 * 1024 * 1024
MAX_RECORDS = 20_000
MAX_BUNDLE_FILES = 100_000
MAX_BUNDLE_BYTES = 64 * 1024 * 1024 * 1024
CASE_FILES = (
    "case.json", "sample.zip", "report.md", "evidence-report.json",
    "evidence-report.md",
)
CASE_DIRS = ("notes", "detections")
WORK_DIRS = ("state", "samples", "out", "rules", "ghidra")


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _json(path: Path, default: object = None) -> object:
    if not path.is_file() or path.is_symlink():
        return default
    if path.stat().st_size > MAX_STATE_FILE:
        raise ValueError(f"JSON file exceeds {MAX_STATE_FILE} bytes: {path}")
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def _replace_paths(value: object, work: Path, case: Path | None) -> object:
    """Make retained records portable without changing evidence hashes."""
    if isinstance(value, dict):
        return {
            str(key): _replace_paths(item, work, case)
            for key, item in sorted(value.items())
        }
    if isinstance(value, list):
        return [_replace_paths(item, work, case) for item in value]
    if isinstance(value, str):
        result = value.replace(str(work), "<work>")
        if case is not None:
            result = result.replace(str(case), "<case>")
        return result
    return value


def _checkpoint_summary(checkpoint: dict) -> dict:
    states = {
        "completed": [], "recorded_gap": [], "not_run_redundant": [],
        "pending": [], "deferred": [],
    }
    for step_id, step in sorted(checkpoint.get("steps", {}).items()):
        attempts = step.get("attempts", []) if isinstance(step, dict) else []
        if attempts:
            status = attempts[-1].get("status")
            state = (
                "completed" if status == "success" else
                "not_run_redundant" if status == "not_run_redundant" else
                "recorded_gap"
            )
        else:
            state = "deferred" if step.get("planned_state") == "deferred" else "pending"
        states[state].append(step_id)
    return {
        "plan_id": checkpoint.get("plan_id"),
        "revision": checkpoint.get("revision"),
        "updated_at": checkpoint.get("updated_at"),
        "completed_steps": states["completed"],
        "recorded_gap_steps": states["recorded_gap"],
        "redundant_steps": states["not_run_redundant"],
        "remaining_ready_steps": states["pending"],
        "deferred_steps": states["deferred"],
    }


def case_status(work: Path) -> dict:
    work = work.resolve()
    state = work / "state"
    checkpoints = []
    for path in sorted((state / "checkpoints").glob("*.json")):
        value = _json(path)
        if isinstance(value, dict):
            checkpoints.append(_checkpoint_summary(value))
    counts = {
        "original_samples": len([
            path for path in (work / "samples" / "original").glob("*")
            if path.is_file() and SHA256_RE.fullmatch(path.name)
        ]),
        "derived_artifacts": len([
            path for path in (work / "samples" / "derived").glob("*")
            if path.is_file() and SHA256_RE.fullmatch(path.name)
        ]),
        "evidence_records": len(list((state / "evidence").glob("ev_*.json"))),
        "claims": len(list((state / "claims").glob("claim_*.json"))),
        "checkpoints": len(checkpoints),
    }
    total = sum(
        len(checkpoint[key])
        for checkpoint in checkpoints
        for key in (
            "completed_steps", "recorded_gap_steps", "redundant_steps",
            "remaining_ready_steps", "deferred_steps",
        )
    )
    finished = sum(
        len(checkpoint[key])
        for checkpoint in checkpoints
        for key in ("completed_steps", "recorded_gap_steps", "redundant_steps")
    )
    return {
        "schema": STATUS_SCHEMA,
        "counts": counts,
        "progress": {
            "finished_steps": finished,
            "total_steps": total,
            "percent": round((finished / total) * 100, 1) if total else 0.0,
        },
        "checkpoints": checkpoints,
    }


def _load_records(directory: Path, pattern: str, schema: str | None = None) -> list[dict]:
    paths = sorted(directory.glob(pattern))
    if len(paths) > MAX_RECORDS:
        raise ValueError(f"record count exceeds {MAX_RECORDS}: {directory}")
    records = []
    for path in paths:
        value = _json(path)
        if not isinstance(value, dict):
            raise ValueError(f"malformed record: {path}")
        if schema is not None and value.get("schema") != schema:
            raise ValueError(f"unsupported record schema: {path}")
        records.append(value)
    return records


def _audit_report(work: Path, evidence: list[dict]) -> dict:
    issues = []
    for record in evidence:
        evidence_id = record.get("evidence_id")
        for label in ("retained_output", "result_snapshot"):
            item = record.get(label)
            if not isinstance(item, dict):
                issues.append({"kind": f"missing_{label}", "evidence_id": evidence_id})
                continue
            raw_path = item.get("path")
            try:
                path = Path(str(raw_path)).resolve()
                path.relative_to(work)
                digest, size = _hash_file(path)
            except (OSError, ValueError):
                issues.append({"kind": f"unreadable_{label}", "evidence_id": evidence_id})
                continue
            if digest != item.get("sha256") or size != item.get("size"):
                issues.append({"kind": f"changed_{label}", "evidence_id": evidence_id})
        artifact = record.get("artifact", {})
        try:
            path = Path(str(artifact.get("path"))).resolve()
            path.relative_to(work)
            digest, _ = _hash_file(path)
        except (OSError, ValueError):
            issues.append({"kind": "unreadable_artifact", "evidence_id": evidence_id})
            continue
        if digest != artifact.get("sha256"):
            issues.append({"kind": "changed_artifact", "evidence_id": evidence_id})
    return {
        "ok": not issues,
        "records_checked": len(evidence),
        "issues": issues[:500],
        "issues_truncated": len(issues) > 500,
    }


def _filter_findings(findings: object, evidence_ids: set[str]) -> object:
    if not isinstance(findings, dict) or not isinstance(findings.get("groups"), dict):
        return findings
    selected = dict(findings)
    groups = {}
    for group_id, group in sorted(findings["groups"].items()):
        if not isinstance(group, dict) or not isinstance(group.get("variants"), dict):
            continue
        variants = {
            variant_id: variant
            for variant_id, variant in sorted(group["variants"].items())
            if isinstance(variant, dict)
            and set(variant.get("evidence_ids", [])) & evidence_ids
        }
        if variants:
            groups[group_id] = group | {
                "variants": variants,
                "disagreement": len(variants) > 1,
            }
    selected["groups"] = groups
    return selected


def _filter_lineage(lineage: object, evidence: list[dict]) -> object:
    if not isinstance(lineage, dict) or not isinstance(lineage.get("artifacts"), dict):
        return lineage
    artifacts = lineage["artifacts"]
    wanted = {
        str(record.get("artifact", {}).get("sha256"))
        for record in evidence
        if isinstance(record.get("artifact"), dict)
    }
    changed = True
    while changed:
        changed = False
        for digest in list(wanted):
            row = artifacts.get(digest)
            if not isinstance(row, dict):
                continue
            for parent in row.get("parents", []):
                if isinstance(parent, dict):
                    parent_sha = parent.get("sha256") or parent.get("parent_sha256")
                    if isinstance(parent_sha, str) and parent_sha not in wanted:
                        wanted.add(parent_sha)
                        changed = True
    selected = dict(lineage)
    selected["artifacts"] = {
        digest: row for digest, row in sorted(artifacts.items()) if digest in wanted
    }
    return selected


def build_report(work: Path, case: Path | None = None, plan_id: str | None = None) -> dict:
    work = work.resolve()
    case = case.resolve() if case is not None else None
    if plan_id is not None and not PLAN_RE.fullmatch(plan_id):
        raise ValueError("plan_id must be 16 lowercase hexadecimal characters")
    state = work / "state"
    evidence = _load_records(state / "evidence", "ev_*.json", "blackwall.evidence-record.v1")
    if plan_id is not None:
        evidence = [record for record in evidence if record.get("plan_id") == plan_id]
    evidence_ids = {str(record.get("evidence_id")) for record in evidence}
    claims = _load_records(state / "claims", "claim_*.json", "blackwall.evidence-claim.v1")
    if plan_id is not None:
        claims = [
            claim for claim in claims
            if set(claim.get("evidence_ids", [])) & evidence_ids
        ]
    checkpoints = []
    for path in sorted((state / "checkpoints").glob("*.json")):
        checkpoint = _json(path)
        if not isinstance(checkpoint, dict):
            continue
        if plan_id is None or checkpoint.get("plan_id") == plan_id:
            checkpoints.append(_checkpoint_summary(checkpoint))

    lineage = _json(
        state / "artifacts.json",
        {"schema": "blackwall.artifact-lineage.v1", "artifacts": {}},
    )
    findings = _json(
        state / "findings.json",
        {"schema": "blackwall.finding-index.v1", "groups": {}},
    )
    if plan_id is not None:
        lineage = _filter_lineage(lineage, evidence)
        findings = _filter_findings(findings, evidence_ids)
    metadata = _json(work / "samples" / "original" / ".meta.json", {})
    case_metadata = _json(case / "case.json", {}) if case is not None else {}
    detection_records = []
    roots = [work / "rules"]
    if case is not None:
        roots.append(case / "detections")
    seen_detection_ids = set()
    for root in roots:
        for path in sorted(root.glob("*.json")):
            value = _json(path)
            if not isinstance(value, dict) or not str(value.get("schema", "")).startswith(
                "blackwall.detection-"
            ):
                continue
            identity = str(value.get("detection_id") or _digest(value))
            if identity not in seen_detection_ids:
                if plan_id is not None and not (
                    set(value.get("evidence_ids", [])) & evidence_ids
                ):
                    continue
                seen_detection_ids.add(identity)
                detection_records.append(value)

    body = {
        "schema": REPORT_SCHEMA,
        "target": {
            "sha256": case_metadata.get("sha256") or metadata.get("sha256"),
            "original_name": case_metadata.get("original_name") or metadata.get("original_name"),
            "source": case_metadata.get("source"),
        },
        "analysis_profile": case_metadata.get("analysis_profile"),
        "scope": {"plan_id": plan_id},
        "status": case_status(work),
        "audit": _audit_report(work, evidence),
        "checkpoints": checkpoints,
        "artifacts": lineage,
        "evidence": evidence,
        "findings": findings,
        "claims": claims,
        "detections": detection_records,
    }
    body = _replace_paths(body, work, case)
    body["report_id"] = f"report_{_digest(body)[:24]}"
    return body


def render_markdown(report: dict) -> str:
    target = report.get("target", {})
    status = report.get("status", {})
    counts = status.get("counts", {})
    progress = status.get("progress", {})
    audit = report.get("audit", {})
    checkpoints = report.get("checkpoints", [])
    findings = report.get("findings", {}).get("groups", {})
    lines = [
        "# BlackWall evidence report",
        "",
        f"- Report ID: `{report.get('report_id', 'unknown')}`",
        f"- Sample SHA-256: `{target.get('sha256') or 'unknown'}`",
        f"- Original name: `{target.get('original_name') or 'unknown'}`",
        f"- Evidence audit: `{'passed' if audit.get('ok') else 'failed'}`",
        f"- Progress: `{progress.get('finished_steps', 0)}/{progress.get('total_steps', 0)}` steps ({progress.get('percent', 0)}%)",
        "",
        "## Inventory",
        "",
        f"- Original samples: {counts.get('original_samples', 0)}",
        f"- Derived artifacts: {counts.get('derived_artifacts', 0)}",
        f"- Evidence records: {counts.get('evidence_records', 0)}",
        f"- Claims: {counts.get('claims', 0)}",
        f"- Detection candidates: {len(report.get('detections', []))}",
        "",
        "## Runs",
        "",
    ]
    if checkpoints:
        for checkpoint in checkpoints:
            lines.append(
                f"- `{checkpoint.get('plan_id')}`: "
                f"{len(checkpoint.get('completed_steps', []))} completed, "
                f"{len(checkpoint.get('recorded_gap_steps', []))} gaps, "
                f"{len(checkpoint.get('redundant_steps', []))} redundant, "
                f"{len(checkpoint.get('remaining_ready_steps', []))} pending"
            )
    else:
        lines.append("- No checkpointed runs.")
    lines.extend(["", "## Findings", ""])
    if findings:
        for _, group in sorted(findings.items()):
            variants = group.get("variants", {})
            values = [
                json.dumps(item.get("canonical_value"), ensure_ascii=False)
                for _, item in sorted(variants.items())
            ]
            lines.append(
                f"- **{group.get('subject', 'unknown')}**: " + "; ".join(values[:10])
            )
    else:
        lines.append("- No structured findings recorded.")
    if not audit.get("ok"):
        lines.extend(["", "## Audit issues", ""])
        for issue in audit.get("issues", []):
            lines.append(f"- `{issue.get('kind')}` — `{issue.get('evidence_id', 'unknown')}`")
    lines.extend([
        "",
        "This document is a deterministic rendering of retained evidence. The JSON report is authoritative.",
        "",
    ])
    return "\n".join(lines)


def _category(subject: str) -> str:
    lowered = subject.casefold()
    if any(word in lowered for word in ("yara", "sigma", "suricata", "detection")):
        return "detections"
    if any(word in lowered for word in ("config", "campaign", "family", "mutex", "c2")):
        return "configurations"
    if any(word in lowered for word in ("ioc", "url", "domain", "ipv4", "email", "registry")):
        return "iocs"
    if any(word in lowered for word in ("string", "literal")):
        return "strings"
    return "code"


def _comparison_sets(report: dict) -> dict[str, set[str]]:
    values: dict[str, set[str]] = {
        "artifacts": set(), "code": set(), "strings": set(), "iocs": set(),
        "configurations": set(), "detections": set(),
    }
    artifacts = report.get("artifacts", {}).get("artifacts", {})
    values["artifacts"].update(str(key) for key in artifacts)
    for _, group in sorted(report.get("findings", {}).get("groups", {}).items()):
        subject = str(group.get("subject", ""))
        category = _category(subject)
        for _, variant in sorted(group.get("variants", {}).items()):
            item = {"subject": subject, "value": variant.get("canonical_value")}
            values[category].add(_canonical(item).decode("utf-8"))
    for detection in report.get("detections", []):
        values["detections"].add(str(
            detection.get("detection_id") or _digest(detection)
        ))
    return values


def compare_reports(left: dict, right: dict) -> dict:
    left_sets, right_sets = _comparison_sets(left), _comparison_sets(right)
    categories = {}
    for name in left_sets:
        left_values, right_values = left_sets[name], right_sets[name]
        categories[name] = {
            "added": sorted(right_values - left_values),
            "removed": sorted(left_values - right_values),
            "unchanged_count": len(left_values & right_values),
        }
    result = {
        "schema": COMPARISON_SCHEMA,
        "left": {
            "report_id": left.get("report_id"),
            "sha256": left.get("target", {}).get("sha256"),
            "plan_id": left.get("scope", {}).get("plan_id"),
        },
        "right": {
            "report_id": right.get("report_id"),
            "sha256": right.get("target", {}).get("sha256"),
            "plan_id": right.get("scope", {}).get("plan_id"),
        },
        "categories": categories,
    }
    result["comparison_id"] = f"comparison_{_digest(result)[:24]}"
    return result


def _safe_relative(path: str) -> Path:
    pure = PurePosixPath(path)
    if not path or pure.is_absolute() or ".." in pure.parts or "\0" in path:
        raise ValueError(f"unsafe bundle member: {path!r}")
    return Path(*pure.parts)


def _copy_tree(source: Path, destination: Path, prefix: str, inventory: list[dict]) -> None:
    if not source.exists():
        return
    for path in sorted(source.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"bundle input contains a symlink: {path}")
        if not path.is_file():
            continue
        relative = Path(prefix) / path.relative_to(source)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        digest, size = _hash_file(target)
        inventory.append({"path": relative.as_posix(), "sha256": digest, "size": size})


def _bundle_inputs(work: Path, case: Path, staging: Path) -> list[dict]:
    inventory: list[dict] = []
    for name in CASE_FILES:
        source = case / name
        if source.exists():
            target = staging / "case" / name
            if source.is_symlink() or not source.is_file():
                raise ValueError(f"invalid case bundle input: {source}")
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            digest, size = _hash_file(target)
            inventory.append({"path": f"case/{name}", "sha256": digest, "size": size})
    for name in CASE_DIRS:
        _copy_tree(case / name, staging, f"case/{name}", inventory)
    for name in WORK_DIRS:
        _copy_tree(work / name, staging, f"work/{name}", inventory)
    if len(inventory) > MAX_BUNDLE_FILES:
        raise ValueError(f"bundle exceeds {MAX_BUNDLE_FILES} files")
    total = sum(item["size"] for item in inventory)
    if total > MAX_BUNDLE_BYTES:
        raise ValueError(f"bundle exceeds {MAX_BUNDLE_BYTES} bytes")
    return inventory


def create_bundle(work: Path, case: Path, output: Path, password: str) -> dict:
    if not password or "\0" in password:
        raise ValueError("bundle password must be non-empty and contain no NUL")
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise ValueError(f"refusing to overwrite existing bundle: {output}")
    with tempfile.TemporaryDirectory(prefix="blackwall-bundle-") as temporary:
        staging = Path(temporary) / "payload"
        staging.mkdir()
        inventory = _bundle_inputs(work.resolve(), case.resolve(), staging)
        case_metadata = _json(case / "case.json", {})
        manifest = {
            "schema": BUNDLE_SCHEMA,
            "case_sha256": case_metadata.get("sha256"),
            "file_count": len(inventory),
            "total_bytes": sum(item["size"] for item in inventory),
            "files": inventory,
        }
        manifest["manifest_id"] = f"bundle_{_digest(manifest)[:24]}"
        (staging / "manifest.json").write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8",
        )
        run = subprocess.run(
            ["7z", "a", "-t7z", "-mhe=on", f"-p{password}", "-mx=3", str(output), "."],
            cwd=staging, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=3600, check=False,
        )
        if run.returncode != 0 or not output.is_file():
            output.unlink(missing_ok=True)
            message = (run.stdout + run.stderr).decode("utf-8", errors="replace")[:2000]
            raise ValueError(f"7z bundle creation failed: {message}")
    digest, size = _hash_file(output)
    return manifest | {"archive": str(output), "archive_sha256": digest, "archive_size": size}


def _archive_members(bundle: Path, password: str) -> list[str]:
    if bundle.is_symlink() or not bundle.is_file():
        raise ValueError("bundle must be a regular, non-symlink file")
    if bundle.stat().st_size > MAX_BUNDLE_BYTES:
        raise ValueError("compressed bundle exceeds the byte safety limit")
    run = subprocess.run(
        ["7z", "l", "-slt", f"-p{password}", str(bundle)],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=300, check=False,
    )
    if run.returncode != 0:
        raise ValueError("bundle could not be opened (wrong password or corrupt archive)")
    names = []
    total = 0
    current: dict[str, str] = {}

    def admit(item: dict[str, str]) -> None:
        nonlocal total
        name = item.get("Path")
        if not name or name == str(bundle):
            return
        _safe_relative(name)
        names.append(name)
        attributes = item.get("Attributes", "")
        unix_mode = attributes.split()[-1] if attributes.split() else ""
        if (
            unix_mode.startswith("l")
            or "Symbolic Link" in item
            or "Hard Link" in item
        ):
            raise ValueError(f"bundle contains a link member: {name}")
        if attributes.startswith("D") or name.endswith("/"):
            return
        try:
            size = int(item["Size"])
        except (KeyError, ValueError) as exc:
            raise ValueError(f"bundle member has no valid declared size: {name}") from exc
        if size < 0 or size > MAX_BUNDLE_BYTES:
            raise ValueError(f"bundle member exceeds the byte safety limit: {name}")
        total += size
        if total > MAX_BUNDLE_BYTES:
            raise ValueError("bundle declared expansion exceeds the byte safety limit")

    for line in run.stdout.decode("utf-8", errors="replace").splitlines():
        if not line:
            admit(current)
            current = {}
        elif " = " in line:
            key, value = line.split(" = ", 1)
            current[key] = value
    admit(current)
    return names


def _extract_and_validate(bundle: Path, password: str, destination: Path) -> dict:
    members = _archive_members(bundle, password)
    if len(members) > MAX_BUNDLE_FILES + 100:
        raise ValueError("bundle member count exceeds safety limit")
    run = subprocess.run(
        ["7z", "x", "-y", f"-p{password}", f"-o{destination}", str(bundle)],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=3600, check=False,
    )
    if run.returncode != 0:
        raise ValueError("bundle extraction failed")
    for path in destination.rglob("*"):
        if path.is_symlink():
            raise ValueError("bundle contains a symbolic link")
    manifest = _json(destination / "manifest.json")
    if not isinstance(manifest, dict) or manifest.get("schema") != BUNDLE_SCHEMA:
        raise ValueError("bundle manifest is missing or unsupported")
    files = manifest.get("files")
    if not isinstance(files, list) or len(files) > MAX_BUNDLE_FILES:
        raise ValueError("bundle manifest file inventory is malformed")
    expected = set()
    total = 0
    for item in files:
        if not isinstance(item, dict):
            raise ValueError("bundle manifest file entry is malformed")
        relative = _safe_relative(str(item.get("path", "")))
        if relative.parts[0] not in {"case", "work"}:
            raise ValueError(f"bundle path is outside allowed roots: {relative}")
        if relative.as_posix() in expected:
            raise ValueError(f"bundle manifest contains a duplicate path: {relative}")
        path = destination / relative
        digest, size = _hash_file(path)
        if digest != item.get("sha256") or size != item.get("size"):
            raise ValueError(f"bundle file failed integrity validation: {relative}")
        expected.add(relative.as_posix())
        total += size
    actual = {
        path.relative_to(destination).as_posix()
        for path in destination.rglob("*")
        if path.is_file()
        and path.relative_to(destination).as_posix() != "manifest.json"
    }
    if actual != expected:
        raise ValueError("bundle contains files absent from its manifest")
    if total != manifest.get("total_bytes") or len(files) != manifest.get("file_count"):
        raise ValueError("bundle manifest totals do not match its inventory")
    identity = dict(manifest)
    claimed_id = identity.pop("manifest_id", None)
    if claimed_id != f"bundle_{_digest(identity)[:24]}":
        raise ValueError("bundle manifest identity is invalid")
    sha256 = manifest.get("case_sha256")
    if not isinstance(sha256, str) or not SHA256_RE.fullmatch(sha256):
        raise ValueError("bundle case SHA-256 is invalid")
    return manifest


def inspect_bundle(bundle: Path, password: str) -> dict:
    with tempfile.TemporaryDirectory(prefix="blackwall-bundle-inspect-") as temporary:
        return _extract_and_validate(bundle.resolve(), password, Path(temporary))


def import_bundle(bundle: Path, work: Path, case: Path, password: str) -> dict:
    work, case = work.resolve(), case.resolve()
    work.mkdir(parents=True, exist_ok=True)
    case.mkdir(parents=True, exist_ok=True)
    if any(work.iterdir()) or any(case.iterdir()):
        raise ValueError("bundle import destinations must be empty")
    with tempfile.TemporaryDirectory(prefix="blackwall-bundle-import-") as temporary:
        extracted = Path(temporary)
        manifest = _extract_and_validate(bundle.resolve(), password, extracted)
        for source, destination in ((extracted / "work", work), (extracted / "case", case)):
            if not source.is_dir():
                continue
            for path in sorted(source.rglob("*")):
                relative = path.relative_to(source)
                target = destination / relative
                if path.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(path, target)
    return {
        "schema": BUNDLE_SCHEMA,
        "imported": True,
        "case_sha256": manifest["case_sha256"],
        "manifest_id": manifest["manifest_id"],
        "file_count": manifest["file_count"],
    }


def cleanup_scratch(work: Path) -> dict:
    """Delete only documented regenerable scratch trees, never evidence."""
    work = work.resolve()
    protected = {"state", "samples", "ghidra", "rules"}
    targets = (work / "scratch", work / "tmp")
    removed_files = 0
    removed_bytes = 0
    for target in targets:
        if target.name in protected or target.parent != work:
            raise ValueError("cleanup target invariant failed")
        if not target.exists():
            continue
        if target.is_symlink() or not target.is_dir():
            raise ValueError(f"scratch target is not a real directory: {target}")
        for path in target.rglob("*"):
            if path.is_file() and not path.is_symlink():
                removed_files += 1
                removed_bytes += path.stat().st_size
        shutil.rmtree(target)
    return {
        "schema": "blackwall.case-cleanup.v1",
        "scope": "scratch-only",
        "removed_files": removed_files,
        "removed_bytes": removed_bytes,
        "protected": sorted(protected),
    }


def _password(args: argparse.Namespace) -> str:
    return args.password or os.environ.get("BLACKWALL_BUNDLE_PASSWORD", "infected")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="BlackWall case lifecycle worker")
    sub = parser.add_subparsers(dest="command", required=True)
    status_parser = sub.add_parser("status")
    status_parser.add_argument("work", type=Path)
    report_parser = sub.add_parser("report")
    report_parser.add_argument("work", type=Path)
    report_parser.add_argument("--case", type=Path)
    report_parser.add_argument("--plan-id")
    report_parser.add_argument("--json-out", type=Path)
    report_parser.add_argument("--markdown-out", type=Path)
    compare_parser = sub.add_parser("compare")
    compare_parser.add_argument("left", type=Path)
    compare_parser.add_argument("right", type=Path)
    compare_parser.add_argument("--left-case", type=Path)
    compare_parser.add_argument("--right-case", type=Path)
    compare_parser.add_argument("--left-plan")
    compare_parser.add_argument("--right-plan")
    bundle_parser = sub.add_parser("bundle")
    bundle_parser.add_argument("work", type=Path)
    bundle_parser.add_argument("case", type=Path)
    bundle_parser.add_argument("output", type=Path)
    bundle_parser.add_argument("--password")
    inspect_parser = sub.add_parser("inspect-bundle")
    inspect_parser.add_argument("bundle", type=Path)
    inspect_parser.add_argument("--password")
    import_parser = sub.add_parser("import-bundle")
    import_parser.add_argument("bundle", type=Path)
    import_parser.add_argument("work", type=Path)
    import_parser.add_argument("case", type=Path)
    import_parser.add_argument("--password")
    cleanup_parser = sub.add_parser("cleanup")
    cleanup_parser.add_argument("work", type=Path)
    cleanup_parser.add_argument("--scratch", action="store_true", required=True)
    args = parser.parse_args(argv)

    if args.command == "status":
        result = case_status(args.work)
    elif args.command == "report":
        result = build_report(args.work, args.case, args.plan_id)
        if args.json_out:
            args.json_out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        if args.markdown_out:
            args.markdown_out.write_text(render_markdown(result), encoding="utf-8")
    elif args.command == "compare":
        result = compare_reports(
            build_report(args.left, args.left_case, args.left_plan),
            build_report(args.right, args.right_case, args.right_plan),
        )
    elif args.command == "bundle":
        result = create_bundle(args.work, args.case, args.output, _password(args))
    elif args.command == "inspect-bundle":
        result = inspect_bundle(args.bundle, _password(args))
    elif args.command == "import-bundle":
        result = import_bundle(args.bundle, args.work, args.case, _password(args))
    else:
        result = cleanup_scratch(args.work)
    print(json.dumps(result, sort_keys=True, ensure_ascii=False))


if __name__ == "__main__":
    main()
