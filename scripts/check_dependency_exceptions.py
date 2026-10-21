#!/usr/bin/env python3
"""Fail closed when BlackWall's temporary dependency exceptions go stale."""

from __future__ import annotations

import argparse
import json
import re
import time
import urllib.error
import urllib.request
from datetime import date, timedelta
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / ".github" / "dependency-exceptions.json"
REQUIREMENTS_PATH = ROOT / "lab" / "requirements.txt"
LOCK_PATH = ROOT / "lab" / "requirements.lock"
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "ci.yml"
OFFICIAL_JSON_HOSTS = frozenset({"pypi.org", "api.osv.dev"})


def _load_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object: {path}")
    return value


def _exact_pin(text: str, package: str) -> str | None:
    pattern = re.compile(rf"^{re.escape(package)}==([^\s\\]+)", re.MULTILINE | re.I)
    match = pattern.search(text)
    return match.group(1) if match else None


def validate_local_policy(policy: dict) -> list[str]:
    errors: list[str] = []
    if policy.get("schema") != "blackwall.dependency-exceptions.v1":
        errors.append("dependency exception policy has an unsupported schema")
    if not isinstance(policy.get("pyghidra_chromadb_requirement"), str):
        errors.append("expected pyghidra-mcp ChromaDB requirement is missing")
    packages = policy.get("packages")
    exceptions = policy.get("audit_exceptions")
    if not isinstance(packages, dict) or not isinstance(exceptions, list):
        return errors + ["dependency exception policy is malformed"]

    requirements = REQUIREMENTS_PATH.read_text(encoding="utf-8")
    lock = LOCK_PATH.read_text(encoding="utf-8")
    expected_locations = {
        "pyghidra-mcp": requirements,
        "chromadb": lock,
    }
    for package, details in packages.items():
        if not isinstance(details, dict):
            errors.append(f"package policy is malformed: {package}")
            continue
        pinned = details.get("pinned")
        actual = _exact_pin(expected_locations.get(package, ""), package)
        if actual != pinned:
            errors.append(
                f"{package} policy says {pinned}, but the resolved pin is {actual}"
            )
        if details.get("latest_reviewed") != pinned:
            errors.append(
                f"{package} latest_reviewed must match the reviewed pin until a release review"
            )

    exception_ids = {
        item.get("id") for item in exceptions if isinstance(item, dict)
    }
    workflow_ids = set(
        re.findall(
            r"--ignore-vuln\s+(PYSEC-[0-9-]+)",
            WORKFLOW_PATH.read_text(encoding="utf-8"),
        )
    )
    if workflow_ids != exception_ids:
        errors.append(
            "CI audit ignores do not exactly match policy: "
            f"workflow={sorted(workflow_ids)}, policy={sorted(exception_ids)}"
        )
    if len(exception_ids) != len(exceptions):
        errors.append("dependency exception IDs must be unique and present")
    return errors


def _official_json(url: str) -> dict:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in OFFICIAL_JSON_HOSTS:
        raise ValueError(f"refusing non-official dependency metadata URL: {url}")
    # URLs are constrained to HTTPS on the two official metadata hosts above.
    request = urllib.request.Request(  # nosec B310
        url,
        headers={"User-Agent": "BlackWall dependency-exception monitor/1"},
    )
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=20) as response:  # nosec B310
                value = json.load(response)
            if not isinstance(value, dict):
                raise ValueError(f"expected object from {url}")
            return value
        except (OSError, ValueError, urllib.error.URLError) as exc:
            last_error = exc
            if attempt < 2:
                time.sleep(1 + attempt)
    raise RuntimeError(f"could not fetch {url}: {last_error}")


def _affected_versions(advisory: dict, package: str) -> set[str]:
    versions: set[str] = set()
    for affected in advisory.get("affected", []):
        if not isinstance(affected, dict):
            continue
        identity = affected.get("package")
        if not isinstance(identity, dict) or identity.get("name", "").lower() != package:
            continue
        listed = affected.get("versions", [])
        if isinstance(listed, list):
            versions.update(str(version) for version in listed)
    return versions


def validate_online_policy(policy: dict, *, today: date | None = None) -> tuple[list[str], dict]:
    errors: list[str] = []
    report: dict = {"packages": {}, "advisories": {}}
    reviewed = date.fromisoformat(str(policy["reviewed_at"]))
    maximum_age = int(policy["maximum_review_age_days"])
    current_date = today or date.today()
    if current_date > reviewed + timedelta(days=maximum_age):
        errors.append(
            f"exception review expired on {reviewed + timedelta(days=maximum_age)}; "
            "revalidate publishers and every advisory"
        )

    package_payloads: dict[str, dict] = {}
    for package, details in policy["packages"].items():
        payload = _official_json(details["index"])
        package_payloads[package] = payload
        info = payload.get("info", {})
        latest = info.get("version") if isinstance(info, dict) else None
        report["packages"][package] = {
            "pinned": details["pinned"],
            "latest": latest,
        }
        if latest != details["latest_reviewed"]:
            errors.append(
                f"{package} published {latest!r}; reviewed release was "
                f"{details['latest_reviewed']!r}. Test compatibility and update/remove exceptions."
            )

    pyghidra_info = package_payloads["pyghidra-mcp"].get("info", {})
    requirements = pyghidra_info.get("requires_dist", []) if isinstance(pyghidra_info, dict) else []
    chroma_constraints = [
        item for item in requirements
        if isinstance(item, str) and item.lower().startswith("chromadb")
    ]
    report["pyghidra_chromadb_constraints"] = chroma_constraints
    expected_constraint = policy["pyghidra_chromadb_requirement"]
    if chroma_constraints != [expected_constraint]:
        errors.append(
            "published pyghidra-mcp ChromaDB requirement changed: "
            f"expected {[expected_constraint]}, found {chroma_constraints}"
        )

    chroma_latest = report["packages"]["chromadb"]["latest"]
    chroma_pin = policy["packages"]["chromadb"]["pinned"]
    for exception in policy["audit_exceptions"]:
        advisory = _official_json(exception["advisory"])
        affected = _affected_versions(advisory, exception["package"])
        current_affected = chroma_pin in affected
        latest_affected = chroma_latest in affected
        report["advisories"][exception["id"]] = {
            "pinned_affected": current_affected,
            "latest_affected": latest_affected,
            "modified": advisory.get("modified"),
        }
        if not current_affected:
            errors.append(
                f"{exception['id']} no longer affects ChromaDB {chroma_pin}; "
                "remove its pip-audit exception now"
            )
        if chroma_latest != chroma_pin and not latest_affected:
            errors.append(
                f"{exception['id']} does not affect latest ChromaDB {chroma_latest}; "
                "upgrade compatibility must be evaluated now"
            )
    return errors, report


def self_check() -> dict:
    affected = _affected_versions(
        {
            "affected": [
                {
                    "package": {"name": "chromadb"},
                    "versions": ["1.5.8", "1.5.9"],
                },
                {"package": {"name": "other"}, "versions": ["1.5.9"]},
            ]
        },
        "chromadb",
    )
    if affected != {"1.5.8", "1.5.9"}:
        raise RuntimeError("OSV affected-version parsing failed")
    local_errors = validate_local_policy(_load_json(POLICY_PATH))
    if local_errors:
        raise RuntimeError("; ".join(local_errors))
    return {"ok": True, "affected_version_parser": True, "local_policy": True}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--online", action="store_true")
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args(argv)
    if args.self_check:
        print(json.dumps(self_check(), sort_keys=True))
        return 0

    policy = _load_json(POLICY_PATH)
    errors = validate_local_policy(policy)
    report: dict = {"local_policy": not errors}
    if args.online:
        try:
            online_errors, online_report = validate_online_policy(policy)
            errors.extend(online_errors)
            report["online"] = online_report
        except (KeyError, TypeError, ValueError, RuntimeError) as exc:
            errors.append(f"online exception monitoring failed: {exc}")
    report["ok"] = not errors
    report["errors"] = errors
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
