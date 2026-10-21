#!/usr/bin/env python3
"""Apply one allowlisted dependency update and regenerate its lock."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / ".github" / "dependency-update-policy.json"
VERSION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+_-]{0,79}$")


def _policy() -> dict:
    value = json.loads(POLICY.read_text(encoding="utf-8"))
    if value.get("schema") != "blackwall.dependency-update-policy.v1":
        raise ValueError("dependency update policy has an unsupported schema")
    return value


def _run(command: list[str]) -> None:
    completed = subprocess.run(command, cwd=ROOT, check=False)
    if completed.returncode != 0:
        raise RuntimeError(f"dependency lock command failed with status {completed.returncode}")


def _replace_python_pin(package: str, version: str) -> None:
    path = ROOT / "lab" / "requirements.txt"
    text = path.read_text(encoding="utf-8")
    pattern = re.compile(
        rf"^(?P<name>{re.escape(package)})==[^\s#]+(?P<tail>\s*(?:#.*)?)$",
        re.MULTILINE | re.IGNORECASE,
    )
    updated, count = pattern.subn(
        lambda match: f"{match.group('name')}=={version}{match.group('tail')}", text,
    )
    if count != 1:
        raise ValueError(f"expected exactly one direct pin for {package}, found {count}")
    path.write_text(updated, encoding="utf-8")


def apply_update(ecosystem: str, package: str, version: str, *, execute: bool = True) -> dict:
    policy = _policy()
    ecosystems = policy.get("ecosystems", {})
    selected = ecosystems.get(ecosystem)
    if not isinstance(selected, dict):
        raise ValueError("ecosystem is not controlled by the update policy")
    normalized = package.lower()
    allowed = {str(item).lower(): str(item) for item in selected.get("allowlist", [])}
    if normalized not in allowed:
        raise ValueError(f"package is not allowlisted for {ecosystem}: {package}")
    package = allowed[normalized]
    if not VERSION_RE.fullmatch(version):
        raise ValueError("version contains characters outside the controlled format")
    slug = re.sub(r"[^a-z0-9]+", "-", package.lower()).strip("-")
    result = {
        "schema": "blackwall.dependency-update.v1",
        "ecosystem": ecosystem,
        "package": package,
        "version": version,
        "branch": f"deps/{ecosystem}-{slug}-{version.lower()}",
        "inputs": selected["inputs"],
        "locks": selected["locks"],
        "executed": execute,
    }
    if not execute:
        return result
    if ecosystem == "python":
        _replace_python_pin(package, version)
        _run([
            "uv", "pip", "compile", "lab/requirements.txt",
            "--python-version", "3.12",
            "--python-platform", "x86_64-unknown-linux-gnu",
            "--generate-hashes", "--no-emit-index-url",
            "--output-file", "lab/requirements.lock",
        ])
    else:
        _run([
            "npm", "install", "--prefix", "rea-runtime", "--package-lock-only",
            "--ignore-scripts", "--save-exact", f"{package}@{version}",
        ])
    return result


def self_check() -> dict:
    policy = _policy()
    for ecosystem, details in policy.get("ecosystems", {}).items():
        if not details.get("allowlist") or not details.get("inputs") or not details.get("locks"):
            raise RuntimeError(f"incomplete dependency policy: {ecosystem}")
        for relative in details["inputs"] + details["locks"]:
            if not (ROOT / relative).is_file():
                raise RuntimeError(f"dependency policy references a missing file: {relative}")
    fixture = apply_update("python", "pefile", "2024.8.26", execute=False)
    if fixture["branch"] != "deps/python-pefile-2024.8.26":
        raise RuntimeError("dependency branch normalization failed")
    try:
        apply_update("python", "not-allowlisted", "1.0.0", execute=False)
    except ValueError:
        pass
    else:
        raise RuntimeError("dependency allowlist failed open")
    return {"ok": True, "ecosystems": sorted(policy["ecosystems"]), "allowlisted": True}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ecosystem", choices=("python", "npm"))
    parser.add_argument("--package")
    parser.add_argument("--version")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args(argv)
    if args.self_check:
        print(json.dumps(self_check(), sort_keys=True))
        return 0
    if not args.ecosystem or not args.package or not args.version:
        parser.error("--ecosystem, --package, and --version are required")
    result = apply_update(
        args.ecosystem, args.package, args.version, execute=not args.dry_run,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
