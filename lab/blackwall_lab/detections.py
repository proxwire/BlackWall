"""Evidence-linked, validation-gated detection candidate generation."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import tempfile
import uuid
from pathlib import Path
from urllib.parse import urlsplit

YARA_SCHEMA = "blackwall.detection-yara.v1"
SIGMA_SCHEMA = "blackwall.detection-sigma.v1"
SURICATA_SCHEMA = "blackwall.detection-suricata.v1"
ATTACK_SCHEMA = "blackwall.detection-attack.v1"
EVIDENCE_ID_RE = re.compile(r"^ev_[0-9a-f]{24}$")
NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{2,63}$")
DOMAIN_RE = re.compile(
    r"(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
)
MAX_TARGETS = 64
MAX_SCAN_BYTES = 256 * 1024 * 1024
MAX_TOTAL_SCAN_BYTES = 1024 * 1024 * 1024
MAX_ANCHORS = 32

SIGMA_FIELDS = {
    "process_creation": frozenset({
        "Image", "OriginalFileName", "CommandLine", "ParentImage", "ParentCommandLine",
        "CurrentDirectory", "User", "IntegrityLevel", "Hashes",
    }),
    "registry_set": frozenset({"Image", "TargetObject", "Details", "EventType", "User"}),
    "file_event": frozenset({"Image", "TargetFilename", "CreationUtcTime", "User"}),
    "network_connection": frozenset({
        "Image", "DestinationIp", "DestinationHostname", "DestinationPort",
        "SourceIp", "SourcePort", "Initiated", "Protocol", "User",
    }),
    "dns_query": frozenset({"Image", "QueryName", "QueryStatus", "QueryResults", "User"}),
}

ATTACK_BEHAVIORS = {
    "dll-side-loading": {
        "technique_id": "T1574.002",
        "technique": "DLL Side-Loading",
        "tactic": "Defense Evasion, Persistence, Privilege Escalation",
        "description": "A legitimate executable loads a malicious DLL from an attacker-controlled search location.",
    },
    "powershell": {
        "technique_id": "T1059.001", "technique": "PowerShell",
        "tactic": "Execution", "description": "PowerShell commands or scripts are used for execution.",
    },
    "scheduled-task": {
        "technique_id": "T1053.005", "technique": "Scheduled Task/Job: Scheduled Task",
        "tactic": "Execution, Persistence, Privilege Escalation",
        "description": "A Windows scheduled task is created or modified.",
    },
    "process-injection": {
        "technique_id": "T1055", "technique": "Process Injection",
        "tactic": "Defense Evasion, Privilege Escalation",
        "description": "Code is inserted into another process.",
    },
    "credential-dumping": {
        "technique_id": "T1003", "technique": "OS Credential Dumping",
        "tactic": "Credential Access", "description": "Credential material is read from operating-system stores.",
    },
    "web-protocol-c2": {
        "technique_id": "T1071.001", "technique": "Web Protocols",
        "tactic": "Command and Control", "description": "HTTP(S) carries command-and-control traffic.",
    },
}


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


def _validate_evidence(state: Path, evidence_ids: list[str]) -> list[str]:
    if not isinstance(evidence_ids, list) or not 1 <= len(evidence_ids) <= 50:
        raise ValueError("evidence_ids must contain 1..50 records")
    result = sorted(set(evidence_ids))
    if any(not isinstance(item, str) or not EVIDENCE_ID_RE.fullmatch(item) for item in result):
        raise ValueError("invalid evidence id")
    for evidence_id in result:
        path = state / "evidence" / f"{evidence_id}.json"
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"unknown evidence id: {evidence_id}")
        if path.stat().st_size > 16 * 1024 * 1024:
            raise ValueError(f"oversized evidence record: {evidence_id}")
        value = json.loads(path.read_text(encoding="utf-8"))
        if value.get("schema") != "blackwall.evidence-record.v1":
            raise ValueError(f"unsupported evidence record: {evidence_id}")
    return result


def _validate_name(name: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9_]", "_", name)
    if not NAME_RE.fullmatch(normalized):
        raise ValueError("name must normalize to 3..64 identifier characters")
    return normalized


def _atomic_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _save_candidate(record: dict, content: str, suffix: str,
                    output: Path, export: Path | None) -> dict:
    name = record["name"]
    content_path = output / f"{name}.{suffix}"
    sidecar_path = output / f"{name}.{suffix}.json"
    _atomic_text(content_path, content)
    _atomic_text(sidecar_path, json.dumps(record, indent=2, ensure_ascii=False) + "\n")
    exported = []
    if export is not None:
        export.mkdir(parents=True, exist_ok=True)
        export_content = export / content_path.name
        export_sidecar = export / sidecar_path.name
        _atomic_text(export_content, content)
        _atomic_text(export_sidecar, json.dumps(record, indent=2, ensure_ascii=False) + "\n")
        exported = [str(export_content), str(export_sidecar)]
    return record | {
        "saved": [str(content_path), str(sidecar_path)],
        "exported": exported,
    }


def _validated_targets(paths: list[Path]) -> list[dict]:
    if not isinstance(paths, list) or not 1 <= len(paths) <= MAX_TARGETS:
        raise ValueError(f"target set must contain 1..{MAX_TARGETS} files")
    rows = []
    total = 0
    for path in paths:
        path = Path(path).resolve()
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"detection target must be a regular file: {path}")
        digest, size = _hash_file(path)
        if size > MAX_SCAN_BYTES:
            raise ValueError(f"detection target exceeds {MAX_SCAN_BYTES} bytes: {path}")
        total += size
        if total > MAX_TOTAL_SCAN_BYTES:
            raise ValueError("detection target set exceeds aggregate byte limit")
        rows.append({"path": path, "sha256": digest, "size": size})
    return rows


def _yara_source(name: str, evidence_ids: list[str], strings: list[str],
                 hex_patterns: list[str], minimum_matches: int) -> str:
    declarations = []
    for index, value in enumerate(strings):
        declarations.append(f"    $s{index} = {json.dumps(value, ensure_ascii=True)} ascii wide")
    for index, value in enumerate(hex_patterns):
        declarations.append(f"    $h{index} = {{ {value.upper()} }}")
    evidence = ",".join(evidence_ids)
    condition = "all of them" if minimum_matches == len(declarations) else f"{minimum_matches} of them"
    return (
        f"rule {name} {{\n"
        "  meta:\n"
        "    author = \"BlackWall candidate generator\"\n"
        "    status = \"candidate\"\n"
        f"    evidence = {json.dumps(evidence)}\n"
        "  strings:\n"
        + "\n".join(declarations)
        + "\n  condition:\n"
        f"    {condition}\n"
        "}\n"
    )


def generate_yara(
    *, name: str, evidence_ids: list[str], strings: list[str],
    positive_paths: list[Path], negative_paths: list[Path], state: Path,
    output: Path, export: Path | None = None, hex_patterns: list[str] | None = None,
    minimum_matches: int | None = None,
) -> dict:
    import yara

    name = _validate_name(name)
    evidence_ids = _validate_evidence(state, evidence_ids)
    hex_patterns = hex_patterns or []
    if not isinstance(strings, list) or not isinstance(hex_patterns, list):
        raise ValueError("YARA strings and hex_patterns must be lists")
    if not 1 <= len(strings) + len(hex_patterns) <= MAX_ANCHORS:
        raise ValueError(f"YARA candidate needs 1..{MAX_ANCHORS} anchors")
    if any(not isinstance(value, str) or not 4 <= len(value) <= 256 or "\0" in value
           for value in strings):
        raise ValueError("YARA text anchors must contain 4..256 characters and no NUL")
    token_re = re.compile(r"^(?:[0-9A-Fa-f]{2}|\?\?)(?: (?:[0-9A-Fa-f]{2}|\?\?)){3,127}$")
    if any(not isinstance(value, str) or not token_re.fullmatch(value) for value in hex_patterns):
        raise ValueError("YARA hex anchors must contain 4..128 byte/wildcard tokens")
    anchor_count = len(strings) + len(hex_patterns)
    minimum_matches = minimum_matches or anchor_count
    if not 1 <= minimum_matches <= anchor_count:
        raise ValueError("minimum_matches is outside the anchor count")
    positives = _validated_targets(positive_paths)
    negatives = _validated_targets(negative_paths) if negative_paths else []
    positive_hashes = {row["sha256"] for row in positives}
    negatives = [row for row in negatives if row["sha256"] not in positive_hashes]
    source = _yara_source(name, evidence_ids, strings, hex_patterns, minimum_matches)
    rules = yara.compile(sources={"candidate": source})

    def matches(row: dict) -> bool:
        return bool(rules.match(str(row["path"]), timeout=30))

    positive_results = [row | {"matched": matches(row)} for row in positives]
    negative_results = [row | {"matched": matches(row)} for row in negatives]
    false_negatives = [row["sha256"] for row in positive_results if not row["matched"]]
    false_positives = [row["sha256"] for row in negative_results if row["matched"]]
    if false_negatives or false_positives:
        return {
            "schema": YARA_SCHEMA,
            "name": name,
            "exported": False,
            "validation": {
                "passed": False,
                "false_negatives": false_negatives,
                "false_positives": false_positives,
                "positive_count": len(positives),
                "negative_count": len(negatives),
            },
        }
    body = {
        "schema": YARA_SCHEMA,
        "name": name,
        "type": "yara",
        "status": "candidate",
        "evidence_ids": evidence_ids,
        "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "validation": {
            "passed": True,
            "compiler": "yara-python",
            "positive_count": len(positives),
            "negative_count": len(negatives),
            "positive_sha256": [row["sha256"] for row in positive_results],
            "negative_sha256": [row["sha256"] for row in negative_results],
            "false_negatives": [],
            "false_positives": [],
        },
    }
    body["detection_id"] = f"det_{_digest(body)[:24]}"
    return _save_candidate(body, source, "yar", output, export)


def _selection(selection: dict, allowed: frozenset[str]) -> dict:
    if not isinstance(selection, dict) or not 1 <= len(selection) <= 20:
        raise ValueError("selection must contain 1..20 fields")
    if set(selection) - allowed:
        raise ValueError("selection contains fields unavailable in the chosen telemetry")
    result = {}
    for key, value in sorted(selection.items()):
        values = value if isinstance(value, list) else [value]
        if not 1 <= len(values) <= 20 or any(
            not isinstance(item, (str, int, bool))
            or len(str(item)) > 1000 or "\0" in str(item)
            for item in values
        ):
            raise ValueError(f"invalid Sigma selection value for {key}")
        result[key] = value
    return result


def _yaml_scalar(value: object) -> str:
    return json.dumps(value, ensure_ascii=False)


def _sigma_yaml(record: dict, selection: dict) -> str:
    lines = [
        f"title: {_yaml_scalar(record['title'])}",
        f"id: {_yaml_scalar(record['sigma_id'])}",
        "status: experimental",
        "description: \"Evidence-linked BlackWall detection candidate\"",
        "references:",
    ]
    lines.extend(f"  - {_yaml_scalar('blackwall-evidence:' + item)}" for item in record["evidence_ids"])
    lines.extend([
        "logsource:",
        "  product: windows",
        f"  category: {record['telemetry']}",
        "detection:",
        "  selection:",
    ])
    for key, value in selection.items():
        if isinstance(value, list):
            lines.append(f"    {key}:")
            lines.extend(f"      - {_yaml_scalar(item)}" for item in value)
        else:
            lines.append(f"    {key}: {_yaml_scalar(value)}")
    lines.extend(["  condition: selection", "falsepositives:", "  - Unknown", "level: medium", ""])
    return "\n".join(lines)


def generate_sigma(*, title: str, name: str, telemetry: str, selection: dict,
                   evidence_ids: list[str], state: Path, output: Path,
                   export: Path | None = None) -> dict:
    name = _validate_name(name)
    if not isinstance(title, str) or not 5 <= len(title) <= 200 or "\0" in title:
        raise ValueError("Sigma title must contain 5..200 characters")
    allowed = SIGMA_FIELDS.get(telemetry)
    if allowed is None:
        raise ValueError("unsupported Sigma telemetry category")
    evidence_ids = _validate_evidence(state, evidence_ids)
    selection = _selection(selection, allowed)
    identity = {
        "schema": SIGMA_SCHEMA, "name": name, "title": title,
        "type": "sigma", "status": "candidate", "telemetry": telemetry,
        "selection": selection, "evidence_ids": evidence_ids,
        "validation": {"passed": True, "mode": "fixed-schema", "allowed_fields": sorted(allowed)},
    }
    identity["detection_id"] = f"det_{_digest(identity)[:24]}"
    identity["sigma_id"] = str(uuid.uuid5(
        uuid.UUID("b515db9e-23a1-5a5f-a935-8fc3aec34951"),
        identity["detection_id"],
    ))
    return _save_candidate(identity, _sigma_yaml(identity, selection), "yml", output, export)


def _suricata_indicator(kind: str, indicator: str) -> str:
    if not isinstance(indicator, str) or len(indicator) > 500 or "\0" in indicator:
        raise ValueError("invalid Suricata indicator")
    value = indicator.strip().lower()
    if kind in {"dns", "http_host", "tls_sni"}:
        host = urlsplit(value).hostname if "://" in value else value
        if host is None or not DOMAIN_RE.fullmatch(host):
            raise ValueError("Suricata domain indicator is invalid")
        return host
    if kind == "http_uri":
        if not value.startswith("/") or any(char in value for char in '";\r\n'):
            raise ValueError("Suricata HTTP URI must be a safe absolute path")
        return value
    if kind == "ip":
        return str(ipaddress.ip_address(value))
    raise ValueError("unsupported Suricata telemetry kind")


def generate_suricata(*, name: str, kind: str, indicator: str,
                       evidence_ids: list[str], state: Path, output: Path,
                       export: Path | None = None) -> dict:
    name = _validate_name(name)
    evidence_ids = _validate_evidence(state, evidence_ids)
    indicator = _suricata_indicator(kind, indicator)
    seed = {"name": name, "kind": kind, "indicator": indicator, "evidence_ids": evidence_ids}
    sid = 4_000_000 + (int(_digest(seed)[:8], 16) % 999_999)
    escaped = indicator.replace("\\", "\\\\").replace('"', '\\"')
    if kind == "dns":
        rule = f'alert dns $HOME_NET any -> $EXTERNAL_NET 53 (msg:"BlackWall candidate {name}"; dns.query; content:"{escaped}"; nocase; endswith; sid:{sid}; rev:1;)\n'
    elif kind == "http_host":
        rule = f'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"BlackWall candidate {name}"; flow:established,to_server; http.host; content:"{escaped}"; nocase; endswith; sid:{sid}; rev:1;)\n'
    elif kind == "http_uri":
        rule = f'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"BlackWall candidate {name}"; flow:established,to_server; http.uri; content:"{escaped}"; sid:{sid}; rev:1;)\n'
    elif kind == "tls_sni":
        rule = f'alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"BlackWall candidate {name}"; flow:established,to_server; tls.sni; content:"{escaped}"; nocase; endswith; sid:{sid}; rev:1;)\n'
    else:
        rule = f'alert ip $HOME_NET any -> {indicator} any (msg:"BlackWall candidate {name}"; sid:{sid}; rev:1;)\n'
    body = {
        "schema": SURICATA_SCHEMA, "name": name, "type": "suricata",
        "status": "candidate", "telemetry": kind, "indicator": indicator,
        "sid": sid, "evidence_ids": evidence_ids,
        "validation": {"passed": True, "mode": "fixed-template"},
    }
    body["detection_id"] = f"det_{_digest(body)[:24]}"
    return _save_candidate(body, rule, "rules", output, export)


def map_attack(*, behavior: str, evidence_ids: list[str], confidence: str,
               state: Path, output: Path, export: Path | None = None) -> dict:
    mapping = ATTACK_BEHAVIORS.get(behavior)
    if mapping is None:
        raise ValueError("behavior is not in the reviewed ATT&CK mapping catalog")
    if confidence not in {"low", "medium", "high"}:
        raise ValueError("ATT&CK confidence must be low, medium, or high")
    evidence_ids = _validate_evidence(state, evidence_ids)
    body = {
        "schema": ATTACK_SCHEMA,
        "name": f"attack_{behavior.replace('-', '_')}",
        "type": "attack-mapping",
        "status": "candidate",
        "behavior": behavior,
        **mapping,
        "evidence_ids": evidence_ids,
        "confidence": confidence,
        "validation": {"passed": True, "mode": "reviewed-catalog"},
    }
    body["detection_id"] = f"det_{_digest(body)[:24]}"
    return _save_candidate(
        body, json.dumps(body, indent=2, ensure_ascii=False) + "\n",
        "attack.json", output, export,
    )
