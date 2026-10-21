#!/usr/bin/env python3
"""Generate deterministic CycloneDX SBOMs for BlackWall's locked ecosystems."""

from __future__ import annotations

import argparse
import base64
import json
import re
import subprocess
import uuid
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
PYTHON_LOCK = ROOT / "lab" / "requirements.lock"
NPM_LOCK = ROOT / "rea-runtime" / "package-lock.json"
SCHEMA = "http://cyclonedx.org/schema/bom-1.6.schema.json"
SERIAL_NAMESPACE = uuid.UUID("e042cde9-809a-5cf7-a61c-30e801bf64f6")


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _serial(identity: str) -> str:
    return f"urn:uuid:{uuid.uuid5(SERIAL_NAMESPACE, identity)}"


def _component(name: str, version: str, ecosystem: str, *,
               hashes: list[dict] | None = None, component_type: str = "library") -> dict:
    normalized = _normalize(name)
    purl_type = "pypi" if ecosystem == "python" else ecosystem
    purl = f"pkg:{purl_type}/{quote(normalized, safe='/')}@{quote(version, safe='.+-_:')}"
    result = {
        "type": component_type,
        "bom-ref": f"{ecosystem}:{normalized}@{version}",
        "name": name,
        "version": version,
        "purl": purl,
    }
    if hashes:
        result["hashes"] = hashes
    return result


def parse_python_lock(text: str) -> list[dict]:
    rows: list[dict] = []
    current: dict | None = None
    for line in text.splitlines():
        match = re.match(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)(?:\s*\\)?$", line)
        if match:
            current = {"name": match.group(1), "version": match.group(2), "hashes": []}
            rows.append(current)
            continue
        hash_match = re.search(r"--hash=sha256:([0-9a-f]{64})", line)
        if hash_match and current is not None:
            current["hashes"].append({"alg": "SHA-256", "content": hash_match.group(1)})
    if not rows or any(not row["hashes"] for row in rows):
        raise ValueError("Python lock contains an unpinned or unhashed distribution")
    return [
        _component(row["name"], row["version"], "python", hashes=row["hashes"])
        for row in rows
    ]


def _npm_name(path: str, details: dict) -> str | None:
    explicit = details.get("name")
    if isinstance(explicit, str) and explicit:
        return explicit
    marker = "node_modules/"
    if marker not in path:
        return None
    return path.rsplit(marker, 1)[1]


def parse_npm_lock(value: dict) -> list[dict]:
    packages = value.get("packages")
    if value.get("lockfileVersion") != 3 or not isinstance(packages, dict):
        raise ValueError("npm lock must use lockfileVersion 3")
    rows = {}
    for path, details in packages.items():
        if not path or not isinstance(details, dict):
            continue
        name = _npm_name(path, details)
        version = details.get("version")
        if not name or not isinstance(version, str):
            continue
        hashes = []
        integrity = details.get("integrity")
        if isinstance(integrity, str) and integrity.startswith("sha512-"):
            try:
                content = base64.b64decode(integrity[7:], validate=True).hex()
            except ValueError as exc:
                raise ValueError(f"invalid npm integrity for {name}") from exc
            hashes.append({"alg": "SHA-512", "content": content})
        component = _component(name, version, "npm", hashes=hashes or None)
        rows[component["bom-ref"]] = component
    if not rows:
        raise ValueError("npm lock contains no resolved packages")
    return [rows[key] for key in sorted(rows)]


def _bom(name: str, components: list[dict], *, metadata_component: dict | None = None) -> dict:
    components = sorted(components, key=lambda item: item["bom-ref"])
    identity = "\n".join(item["bom-ref"] for item in components)
    root = metadata_component or {
        "type": "application", "bom-ref": f"blackwall:{name}",
        "name": name, "version": "source",
    }
    return {
        "$schema": SCHEMA,
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": _serial(f"{name}\n{identity}"),
        "version": 1,
        "metadata": {
            "component": root,
            "tools": {"components": [{
                "type": "application", "name": "BlackWall SBOM generator",
                "version": "1",
            }]},
        },
        "components": components,
        "dependencies": [{
            "ref": root["bom-ref"],
            "dependsOn": [item["bom-ref"] for item in components],
        }],
    }


def source_boms() -> dict[str, dict]:
    python = parse_python_lock(PYTHON_LOCK.read_text(encoding="utf-8"))
    npm = parse_npm_lock(json.loads(NPM_LOCK.read_text(encoding="utf-8")))
    return {
        "blackwall-python.cdx.json": _bom("blackwall-python", python),
        "blackwall-npm.cdx.json": _bom("blackwall-rea-runtime", npm),
    }


def _run(command: list[str]) -> str:
    completed = subprocess.run(
        command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=300, check=False,
    )
    if completed.returncode != 0:
        error = completed.stderr.decode("utf-8", errors="replace")[:2000]
        raise RuntimeError(f"command failed ({command[0]}): {error}")
    return completed.stdout.decode("utf-8", errors="strict")


def image_bom(image: str) -> dict:
    if not image or len(image) > 300 or "\0" in image:
        raise ValueError("invalid image reference")
    inspect = json.loads(_run(["docker", "image", "inspect", image]))[0]
    image_id = str(inspect.get("Id", ""))
    dpkg = _run([
        "docker", "run", "--rm", "--network", "none", "--entrypoint", "dpkg-query",
        image, "-W", "-f=${Package}\\t${Version}\\t${Architecture}\\n",
    ])
    pip = json.loads(_run([
        "docker", "run", "--rm", "--network", "none", "--entrypoint",
        "/opt/venv/bin/python", image, "-m", "pip", "list", "--format", "json",
    ]))
    npm = json.loads(_run([
        "docker", "run", "--rm", "--network", "none", "--entrypoint", "npm",
        image, "list", "--prefix", "/opt/rea/runtime", "--omit=dev", "--all", "--json",
    ]))
    components: dict[str, dict] = {}
    for line in dpkg.splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        name, version, architecture = parts
        component = _component(name, version, "deb", component_type="operating-system")
        component["properties"] = [{"name": "blackwall:architecture", "value": architecture}]
        components[component["bom-ref"]] = component
    for row in pip:
        component = _component(str(row["name"]), str(row["version"]), "python")
        components[component["bom-ref"]] = component

    def walk_npm(node: dict) -> None:
        for name, details in sorted(node.get("dependencies", {}).items()):
            if not isinstance(details, dict) or not isinstance(details.get("version"), str):
                continue
            component = _component(name, details["version"], "npm")
            components[component["bom-ref"]] = component
            walk_npm(details)

    walk_npm(npm)
    digest = image_id.removeprefix("sha256:")
    root = {
        "type": "container", "bom-ref": f"oci:{image_id}", "name": image,
        "version": digest[:16] or "unknown",
    }
    if re.fullmatch(r"[0-9a-f]{64}", digest):
        root["hashes"] = [{"alg": "SHA-256", "content": digest}]
    return _bom("blackwall-image", list(components.values()), metadata_component=root)


def validate_bom(value: dict) -> None:
    if value.get("bomFormat") != "CycloneDX" or value.get("specVersion") != "1.6":
        raise ValueError("SBOM is not CycloneDX 1.6")
    if not str(value.get("serialNumber", "")).startswith("urn:uuid:"):
        raise ValueError("SBOM has no deterministic serial number")
    components = value.get("components")
    if not isinstance(components, list) or not components:
        raise ValueError("SBOM contains no components")
    references = [item.get("bom-ref") for item in components]
    if any(not isinstance(item, str) or not item for item in references):
        raise ValueError("SBOM component is missing bom-ref")
    if len(references) != len(set(references)):
        raise ValueError("SBOM contains duplicate bom-ref values")


def self_check() -> dict:
    python = parse_python_lock(
        "fixture==1.2.3 \\\n+    --hash=sha256:" + "a" * 64 + "\n"
    )
    npm = parse_npm_lock({
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "root", "version": "1"},
            "node_modules/fixture": {
                "version": "2.0.0", "integrity": "sha512-" + base64.b64encode(b"x" * 64).decode(),
            },
        },
    })
    bom = _bom("self-check", python + npm)
    validate_bom(bom)
    scoped = _component("@fixture/scoped", "2.0.0", "npm")
    if scoped["purl"] != "pkg:npm/%40fixture/scoped@2.0.0":
        raise RuntimeError("scoped npm package URL encoding is invalid")
    if bom != _bom("self-check", python + npm):
        raise RuntimeError("SBOM generation is not deterministic")
    return {"ok": True, "schema": "CycloneDX-1.6", "deterministic": True}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--image")
    parser.add_argument("--verify", nargs="*", type=Path)
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args(argv)
    if args.self_check:
        print(json.dumps(self_check(), sort_keys=True))
        return 0
    if args.verify is not None:
        for path in args.verify:
            validate_bom(json.loads(path.read_text(encoding="utf-8")))
        print(json.dumps({"verified": len(args.verify)}, sort_keys=True))
        return 0
    if args.output_dir is None:
        parser.error("--output-dir is required unless --self-check or --verify is used")
    outputs = source_boms()
    if args.image:
        outputs["blackwall-image.cdx.json"] = image_bom(args.image)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for name, value in outputs.items():
        validate_bom(value)
        (args.output_dir / name).write_text(
            json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8",
        )
    print(json.dumps({"generated": sorted(outputs)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
