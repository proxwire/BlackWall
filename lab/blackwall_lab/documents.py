"""Bounded, non-executing document and script inspection worker.

This module is deliberately usable through ``python -m`` so the MCP process
can supervise hostile parsers as a separate process group.  It never invokes
Office, a PDF renderer, or a script interpreter.  Extracted names are metadata
only; output files always use BlackWall-generated names.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import io
import json
import os
import re
import resource
import zipfile
import zlib
from pathlib import Path
from xml.etree import ElementTree

DOCUMENT_INPUT_LIMIT = 128 * 1024 * 1024
SCRIPT_INPUT_LIMIT = 8 * 1024 * 1024
MAX_MEMBER_LIMIT = 8 * 1024 * 1024
MAX_TOTAL_LIMIT = 32 * 1024 * 1024
MAX_MEMBERS = 4096
MAX_RELATIONSHIPS = 2048
MAX_FINDINGS = 512
MAX_TEXT_VALUE = 2048
MAX_ARCHIVE_RATIO = 100
MAX_PDF_OBJECTS = 4096
MAX_RTF_DEPTH = 64
MAX_SCRIPT_LAYERS = 8
MAX_ARTIFACTS = 128

URL_RE = re.compile(
    r"(?i)\b(?:(?:https?|ftp)://[A-Za-z0-9][^\s<>\"'{}|\\^`\[\]]{1,2047}|"
    r"(?:file|mhtml):[^\s<>\"'{}|\\^`\[\]]{2,2048})"
)
COMMAND_RE = re.compile(
    r"(?i)\b(?:cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh(?:\.exe)?|mshta(?:\.exe)?|"
    r"rundll32(?:\.exe)?|regsvr32(?:\.exe)?|certutil(?:\.exe)?|bitsadmin(?:\.exe)?|"
    r"wscript(?:\.exe)?|cscript(?:\.exe)?|curl(?:\.exe)?|wget(?:\.exe)?|"
    r"invoke-expression|iex|invoke-webrequest|start-process)\b"
    r"(?=[\s(\"'`]|$)[^\r\n\x00]{0,384}"
)
DDE_RE = re.compile(r"(?i)\bDDE(?:AUTO)?\b[^\r\n\x00]{0,384}")
BASE64_RE = re.compile(rb"(?<![A-Za-z0-9_+/=-])[A-Za-z0-9_+/-]{16,}={0,2}(?![A-Za-z0-9_+/=-])")
HEX_RE = re.compile(rb"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){8,}(?![0-9A-Fa-f])")

SCRIPT_SUFFIXES = {
    ".js": "javascript",
    ".jse": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".vbs": "vbscript",
    ".vbe": "vbscript",
    ".wsf": "vbscript",
    ".hta": "javascript",
    ".ps1": "powershell",
    ".psm1": "powershell",
    ".psd1": "powershell",
    ".bas": "vba",
    ".vba": "vba",
    ".cls": "vba",
}

SCRIPT_RULES = (
    ("auto-execution", "high", re.compile(
        r"(?i)\b(?:AutoOpen|Auto_Open|Document_Open|Workbook_Open|"
        r"Document_Close|Workbook_Activate|Window_OnLoad)\b"
    )),
    ("dynamic-execution", "high", re.compile(
        r"(?i)\b(?:eval|ExecuteGlobal|Execute|Invoke-Expression|IEX)\s*(?:\(|\s)"
    )),
    ("process-execution", "high", re.compile(
        r"(?i)(?:WScript\.Shell|Shell\.Application|CreateObject\s*\(\s*[\"']WScript\.Shell|"
        r"\.Run\s*\(|\.Exec\s*\(|\bShell\s*\(|\bStart-Process\b|\bWMI\b)"
    )),
    ("download", "high", re.compile(
        r"(?i)(?:DownloadString|DownloadFile|Invoke-WebRequest|Net\.WebClient|"
        r"XMLHTTP|WinHttpRequest|URLDownloadToFile|bitsadmin|certutil\s+-urlcache)"
    )),
    ("file-write", "medium", re.compile(
        r"(?i)(?:ADODB\.Stream|Scripting\.FileSystemObject|WriteAllBytes|"
        r"CreateTextFile|SaveToFile|Out-File|Set-Content)"
    )),
    ("persistence", "high", re.compile(
        r"(?i)(?:CurrentVersion\\Run|CurrentVersion\\RunOnce|RegWrite|"
        r"schtasks(?:\.exe)?|Register-ScheduledTask)"
    )),
    ("obfuscation", "medium", re.compile(
        r"(?i)(?:String\.fromCharCode|\bChrW?\s*\(|\bStrReverse\s*\(|"
        r"FromBase64String|EncodedCommand|\s-(?:e|en|enc|enco|encod|encodedcommand)\s+)"
    )),
)


def _bounded_file(path: Path, limit: int) -> bytes:
    if path.is_symlink():
        raise ValueError("target must be a regular, non-symlink file")
    path = path.resolve()
    if not path.is_file():
        raise ValueError("target must be a regular, non-symlink file")
    size = path.stat().st_size
    if size > limit:
        raise ValueError(f"input exceeds {limit} byte limit ({size} bytes)")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"input exceeds {limit} byte limit")
    return data


def _safe_text(value: object, limit: int = 512) -> str:
    text = str(value).replace("\x00", "\\0")
    text = "".join(char if char >= " " or char in "\t\r\n" else "�" for char in text)
    return text if len(text) <= limit else text[:limit] + f"…[{len(text) - limit} chars omitted]"


def _decode_text(data: bytes) -> tuple[str, str]:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        encoding = "utf-16"
    elif data.startswith(b"\xef\xbb\xbf"):
        encoding = "utf-8-sig"
    elif data[:4096].count(b"\x00") > max(4, len(data[:4096]) // 8):
        encoding = "utf-16-le"
    else:
        encoding = "utf-8"
    try:
        return data.decode(encoding), encoding
    except UnicodeDecodeError:
        return data.decode("latin-1", errors="replace"), "latin-1"


def _unique_rows(rows: list[dict], keys: tuple[str, ...], limit: int) -> tuple[list[dict], bool]:
    result: list[dict] = []
    seen: set[tuple[object, ...]] = set()
    truncated = False
    for row in rows:
        identity = tuple(row.get(key) for key in keys)
        if identity in seen:
            continue
        seen.add(identity)
        if len(result) >= limit:
            truncated = True
            continue
        result.append(row)
    return result, truncated


def _extend_bounded(target: list, values: list, limit: int) -> bool:
    remaining = max(0, limit - len(target))
    target.extend(values[:remaining])
    return len(values) > remaining


def _scan_text(text: str, source: str, transform: str = "raw") -> dict:
    urls = []
    commands = []
    truncated = False
    for match in URL_RE.finditer(text):
        if len(urls) >= MAX_FINDINGS:
            truncated = True
            break
        urls.append({
            "value": _safe_text(match.group(0), MAX_TEXT_VALUE),
            "source": _safe_text(source),
            "offset": match.start(),
            "transform": transform,
        })
    for pattern, kind in ((COMMAND_RE, "command"), (DDE_RE, "dde-field")):
        for match in pattern.finditer(text):
            if len(commands) >= MAX_FINDINGS:
                truncated = True
                break
            commands.append({
                "value": _safe_text(match.group(0).strip(), MAX_TEXT_VALUE),
                "kind": kind,
                "source": _safe_text(source),
                "offset": match.start(),
                "transform": transform,
            })
    urls, urls_truncated = _unique_rows(urls, ("value", "source", "transform"), MAX_FINDINGS)
    commands, commands_truncated = _unique_rows(
        commands, ("value", "kind", "source", "transform"), MAX_FINDINGS,
    )
    return {
        "urls": urls,
        "commands": commands,
        "truncated": truncated or urls_truncated or commands_truncated,
    }


def _document_format(data: bytes) -> str:
    if data.startswith(b"%PDF-"):
        return "pdf"
    if data.startswith(b"{\\rtf"):
        return "rtf"
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole-compound"
    if data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "ooxml"
    raise ValueError("unsupported document signature")


def _zip_read(archive: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int) -> tuple[bytes | None, str | None]:
    if info.flag_bits & 0x1:
        return None, "encrypted member"
    if info.file_size > limit:
        return None, f"declared size exceeds {limit} bytes"
    if info.file_size and info.compress_size == 0:
        return None, "non-empty member has zero compressed size"
    if info.compress_size and info.file_size > info.compress_size * MAX_ARCHIVE_RATIO:
        return None, f"declared expansion ratio exceeds {MAX_ARCHIVE_RATIO}:1"
    try:
        with archive.open(info) as stream:
            value = stream.read(limit + 1)
    except (OSError, RuntimeError, zipfile.BadZipFile, zlib.error) as exc:
        return None, f"read failed: {type(exc).__name__}"
    if len(value) > limit:
        return None, f"expanded data exceeds {limit} bytes"
    return value, None


def _zip_is_active_part(name: str) -> bool:
    lowered = name.lower()
    return (
        lowered.endswith("vbaproject.bin")
        or "/embeddings/" in lowered
        or "/activex/" in lowered
        or "/externallinks/" in lowered
        or "/customui/" in lowered
        or Path(lowered).suffix in SCRIPT_SUFFIXES
    )


def _relationship_rows(data: bytes, source: str) -> tuple[list[dict], str | None]:
    if len(data) > 2 * 1024 * 1024:
        return [], "relationship part exceeds 2097152 bytes"
    if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        return [], "DTD/entity declaration rejected"
    try:
        root = ElementTree.fromstring(data)
    except ElementTree.ParseError as exc:
        return [], f"XML parse failed: {_safe_text(exc, 200)}"
    rows = []
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] != "Relationship":
            continue
        target = element.attrib.get("Target", "")
        mode = element.attrib.get("TargetMode", "Internal")
        rows.append({
            "source": _safe_text(source),
            "id": _safe_text(element.attrib.get("Id", "")),
            "type": _safe_text(element.attrib.get("Type", "")),
            "target": _safe_text(target, MAX_TEXT_VALUE),
            "target_mode": _safe_text(mode),
            "external": mode.lower() == "external" or bool(re.match(r"(?i)^[a-z][a-z0-9+.-]*:", target)),
        })
        if len(rows) >= MAX_RELATIONSHIPS:
            break
    return rows, None


def _ooxml_triage(path: Path, max_members: int, member_limit: int, total_limit: int) -> dict:
    members = []
    findings = []
    relationships = []
    urls = []
    commands = []
    errors = []
    scanned_bytes = 0
    collection_truncated = False
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        duplicate_names = len(infos) - len({info.filename for info in infos})
        for index, info in enumerate(infos[:max_members]):
            name = _safe_text(info.filename)
            active = _zip_is_active_part(info.filename)
            members.append({
                "index": index,
                "name": name,
                "compressed_size": info.compress_size,
                "size": info.file_size,
                "encrypted": bool(info.flag_bits & 0x1),
                "active_content": active,
            })
            if active:
                findings.append({
                    "kind": "active-content-part",
                    "severity": "high" if info.filename.lower().endswith("vbaproject.bin") else "medium",
                    "source": name,
                    "value": name,
                })
            lowered = info.filename.lower()
            should_read = lowered.endswith((".xml", ".rels", ".txt", ".js", ".vbs", ".ps1"))
            if not should_read or scanned_bytes >= total_limit:
                continue
            remaining = min(member_limit, total_limit - scanned_bytes)
            value, error = _zip_read(archive, info, remaining)
            if error:
                errors.append({"source": name, "error": error})
                continue
            if value is None:
                continue
            scanned_bytes += len(value)
            if lowered.endswith(".rels"):
                rows, relationship_error = _relationship_rows(value, name)
                collection_truncated |= _extend_bounded(
                    relationships, rows, MAX_RELATIONSHIPS + 1,
                )
                if relationship_error:
                    errors.append({"source": name, "error": relationship_error})
                for row in rows:
                    if row["external"]:
                        findings.append({
                            "kind": "external-relationship",
                            "severity": "high",
                            "source": name,
                            "value": row["target"],
                        })
            text, _ = _decode_text(value)
            scan = _scan_text(text, name)
            collection_truncated |= _extend_bounded(urls, scan["urls"], MAX_FINDINGS + 1)
            collection_truncated |= _extend_bounded(
                commands, scan["commands"], MAX_FINDINGS + 1,
            )
            collection_truncated |= scan["truncated"]
            if re.search(r"(?i)\bDDE(?:AUTO)?\b", text):
                findings.append({
                    "kind": "dde-field",
                    "severity": "high",
                    "source": name,
                    "value": "DDE/DDEAUTO field text",
                })
        member_count = len(infos)
    relationships, rel_truncated = _unique_rows(
        relationships, ("source", "id", "type", "target"), MAX_RELATIONSHIPS,
    )
    urls, url_truncated = _unique_rows(urls, ("value", "source", "transform"), MAX_FINDINGS)
    commands, command_truncated = _unique_rows(
        commands, ("value", "kind", "source", "transform"), MAX_FINDINGS,
    )
    findings, findings_truncated = _unique_rows(
        findings, ("kind", "source", "value"), MAX_FINDINGS,
    )
    return {
        "format": "ooxml",
        "structure": {
            "member_count": member_count,
            "members": members,
            "duplicate_member_names": duplicate_names,
        },
        "findings": findings,
        "relationships": relationships,
        "urls": urls,
        "commands": commands,
        "errors": errors[:MAX_FINDINGS],
        "coverage": {
            "members_scanned": min(member_count, max_members),
            "member_scan_truncated": member_count > max_members,
            "content_bytes_scanned": scanned_bytes,
            "result_truncated": (
                collection_truncated or rel_truncated or url_truncated
                or command_truncated or findings_truncated
            ),
        },
    }


def _ole_triage(path: Path, max_members: int, member_limit: int, total_limit: int) -> dict:
    try:
        import olefile
    except ImportError as exc:  # pragma: no cover - production lock supplies it
        raise RuntimeError("olefile from the pinned oletools dependency is unavailable") from exc

    members = []
    findings = []
    urls = []
    commands = []
    errors = []
    scanned_bytes = 0
    collection_truncated = False
    with olefile.OleFileIO(str(path)) as ole:
        streams = ole.listdir(streams=True, storages=False)
        for index, parts in enumerate(streams[:max_members]):
            raw_name = "/".join(parts)
            name = _safe_text(raw_name)
            lowered = raw_name.lower()
            try:
                size = int(ole.get_size(parts))
            except (OSError, TypeError, ValueError) as exc:
                errors.append({"source": name, "error": f"size failed: {type(exc).__name__}"})
                continue
            active = any(token in lowered for token in (
                "vba/", "macros", "ole10native", "objectpool", "package", "compobj",
            ))
            members.append({"index": index, "name": name, "size": size, "active_content": active})
            if active:
                findings.append({
                    "kind": "ole-active-stream",
                    "severity": "high" if "vba/" in lowered or "ole10native" in lowered else "medium",
                    "source": name,
                    "value": name,
                })
            if size > member_limit or scanned_bytes >= total_limit:
                continue
            try:
                with ole.openstream(parts) as stream:
                    value = stream.read(min(member_limit, total_limit - scanned_bytes) + 1)
            except (OSError, TypeError, ValueError) as exc:
                errors.append({"source": name, "error": f"read failed: {type(exc).__name__}"})
                continue
            if len(value) > min(member_limit, total_limit - scanned_bytes):
                errors.append({"source": name, "error": "stream exceeded remaining scan limit"})
                continue
            scanned_bytes += len(value)
            text, _ = _decode_text(value)
            scan = _scan_text(text, name)
            collection_truncated |= _extend_bounded(urls, scan["urls"], MAX_FINDINGS + 1)
            collection_truncated |= _extend_bounded(
                commands, scan["commands"], MAX_FINDINGS + 1,
            )
            collection_truncated |= scan["truncated"]
        stream_count = len(streams)
    urls, url_truncated = _unique_rows(urls, ("value", "source", "transform"), MAX_FINDINGS)
    commands, command_truncated = _unique_rows(
        commands, ("value", "kind", "source", "transform"), MAX_FINDINGS,
    )
    findings, findings_truncated = _unique_rows(
        findings, ("kind", "source", "value"), MAX_FINDINGS,
    )
    return {
        "format": "ole-compound",
        "structure": {"stream_count": stream_count, "streams": members},
        "findings": findings,
        "relationships": [],
        "urls": urls,
        "commands": commands,
        "errors": errors[:MAX_FINDINGS],
        "coverage": {
            "members_scanned": min(stream_count, max_members),
            "member_scan_truncated": stream_count > max_members,
            "content_bytes_scanned": scanned_bytes,
            "result_truncated": (
                collection_truncated or url_truncated
                or command_truncated or findings_truncated
            ),
        },
    }


def _rtf_objects(
    data: bytes, member_limit: int, max_objects: int, total_limit: int,
) -> tuple[list[tuple[bytes, dict]], list[dict]]:
    candidates = []
    errors = []
    total = 0
    lowered = data.lower()
    cursor = 0
    while True:
        marker = lowered.find(b"\\objdata", cursor)
        if marker < 0:
            break
        if len(candidates) >= max_objects:
            errors.append({
                "source": f"rtf-offset:{marker}",
                "error": f"object count limit reached ({max_objects})",
            })
            break
        if total >= total_limit:
            errors.append({
                "source": f"rtf-offset:{marker}",
                "error": f"aggregate object limit reached ({total_limit} bytes)",
            })
            break
        cursor = marker + 8
        digits = bytearray()
        scan_limit = min(len(data), cursor + member_limit * 4 + 4096)
        while cursor < scan_limit:
            byte = data[cursor]
            if byte in b"0123456789abcdefABCDEF":
                digits.append(byte)
                if len(digits) > member_limit * 2:
                    break
            elif byte in b" \t\r\n":
                pass
            else:
                break
            cursor += 1
        if len(digits) < 2:
            errors.append({"source": f"rtf-offset:{marker}", "error": "objdata contained no hex bytes"})
            continue
        if len(digits) % 2:
            digits.pop()
            errors.append({"source": f"rtf-offset:{marker}", "error": "odd trailing objdata nibble ignored"})
        try:
            blob = binascii.unhexlify(digits)
        except binascii.Error as exc:
            errors.append({"source": f"rtf-offset:{marker}", "error": f"hex decode failed: {exc}"})
            continue
        if len(blob) > total_limit - total:
            errors.append({
                "source": f"rtf-offset:{marker}",
                "error": f"object exceeds remaining aggregate limit ({total_limit - total} bytes)",
            })
            continue
        candidates.append((blob, {
            "kind": "rtf-objdata",
            "source": f"rtf-offset:{marker}",
            "transform": "rtf-hex",
        }))
        total += len(blob)
    return candidates, errors


def _rtf_depth(data: bytes) -> tuple[int, bool]:
    depth = maximum = 0
    escaped = False
    unbalanced = False
    for byte in data:
        if escaped:
            escaped = False
            continue
        if byte == 0x5C:
            escaped = True
        elif byte == 0x7B:
            depth += 1
            maximum = max(maximum, depth)
        elif byte == 0x7D:
            depth -= 1
            if depth < 0:
                unbalanced = True
                depth = 0
    return maximum, unbalanced or depth != 0


def _rtf_triage(data: bytes, member_limit: int, total_limit: int) -> dict:
    scanned_data = data[:total_limit]
    text, encoding = _decode_text(scanned_data)
    scan = _scan_text(text, "rtf-document")
    objects, errors = _rtf_objects(data, member_limit, MAX_ARTIFACTS, total_limit)
    depth, unbalanced = _rtf_depth(data)
    findings = []
    if objects:
        findings.append({
            "kind": "embedded-object",
            "severity": "high",
            "source": "rtf-document",
            "value": f"{len(objects)} objdata group(s)",
        })
    if DDE_RE.search(text):
        findings.append({
            "kind": "dde-field", "severity": "high",
            "source": "rtf-document", "value": "DDE/DDEAUTO field text",
        })
    if depth > MAX_RTF_DEPTH:
        errors.append({"source": "rtf-document", "error": f"nesting depth {depth} exceeds {MAX_RTF_DEPTH}"})
    return {
        "format": "rtf",
        "structure": {
            "encoding": encoding,
            "maximum_group_depth": depth,
            "unbalanced_groups": unbalanced,
            "object_count": len(objects),
        },
        "findings": findings,
        "relationships": [],
        "urls": scan["urls"],
        "commands": scan["commands"],
        "errors": errors[:MAX_FINDINGS],
        "coverage": {
            "members_scanned": len(objects),
            "member_scan_truncated": len(objects) >= MAX_ARTIFACTS,
            "content_bytes_scanned": len(scanned_data),
            "result_truncated": scan["truncated"] or len(scanned_data) < len(data),
        },
    }


def _pdf_objects(data: bytes) -> list[tuple[str, int, bytes]]:
    objects = []
    cursor = 0
    header = re.compile(rb"(?m)(\d{1,10})\s+(\d{1,10})\s+obj\b")
    while cursor < len(data) and len(objects) < MAX_PDF_OBJECTS:
        match = header.search(data, cursor)
        if match is None:
            break
        end = data.find(b"endobj", match.end())
        if end < 0:
            break
        label = f"pdf-object:{match.group(1).decode()}:{match.group(2).decode()}"
        objects.append((label, match.start(), data[match.end():end]))
        cursor = end + 6
    return objects


def _pdf_stream(body: bytes, member_limit: int) -> tuple[bytes | None, str | None, str]:
    marker = re.search(rb"stream(?:\r\n|\n|\r)", body)
    if marker is None:
        return None, None, "raw"
    end = body.find(b"endstream", marker.end())
    if end < 0:
        return None, "stream has no endstream marker", "raw"
    raw = body[marker.end():end]
    if raw.endswith(b"\r\n"):
        raw = raw[:-2]
    elif raw.endswith((b"\r", b"\n")):
        raw = raw[:-1]
    if len(raw) > member_limit:
        return None, f"raw stream exceeds {member_limit} bytes", "raw"
    dictionary = body[:marker.start()]
    if b"/FlateDecode" not in dictionary:
        return raw, None, "raw"
    inflater = zlib.decompressobj()
    try:
        expanded = inflater.decompress(raw, member_limit + 1)
        if len(expanded) <= member_limit:
            expanded += inflater.flush(member_limit + 1 - len(expanded))
    except zlib.error as exc:
        return None, f"FlateDecode failed: {_safe_text(exc, 200)}", "flate"
    if len(expanded) > member_limit or inflater.unconsumed_tail:
        return None, f"expanded stream exceeds {member_limit} bytes", "flate"
    if raw and len(expanded) > len(raw) * MAX_ARCHIVE_RATIO:
        return None, f"stream expansion ratio exceeds {MAX_ARCHIVE_RATIO}:1", "flate"
    return expanded, None, "flate"


def _pdf_candidates(
    data: bytes, member_limit: int, total_limit: int, max_artifacts: int,
) -> tuple[list[tuple[bytes, dict]], list[dict]]:
    candidates = []
    errors = []
    total = 0
    for label, offset, body in _pdf_objects(data):
        active = any(marker in body for marker in (
            b"/EmbeddedFile", b"/JavaScript", b"/JS", b"/Launch", b"/RichMedia",
        ))
        if not active:
            continue
        if len(candidates) >= max_artifacts:
            errors.append({"source": label, "error": "artifact count limit reached"})
            break
        if total >= total_limit:
            errors.append({
                "source": label,
                "error": f"aggregate stream limit reached ({total_limit} bytes)",
            })
            break
        stream, error, transform = _pdf_stream(
            body, min(member_limit, total_limit - total),
        )
        if error:
            errors.append({"source": label, "error": error})
            continue
        if stream:
            kind = "pdf-embedded-file" if b"/EmbeddedFile" in body else "pdf-active-stream"
            candidates.append((stream, {
                "kind": kind,
                "source": label,
                "source_offset": offset,
                "transform": transform,
            }))
            total += len(stream)
    return candidates, errors


def _pdf_triage(data: bytes, member_limit: int, total_limit: int) -> dict:
    objects = _pdf_objects(data)
    findings = []
    relationships = []
    urls = []
    commands = []
    errors = []
    scanned = 0
    collection_truncated = False
    markers = {
        b"/JavaScript": ("javascript-action", "high"),
        b"/JS": ("javascript-action", "high"),
        b"/OpenAction": ("open-action", "high"),
        b"/AA": ("additional-action", "high"),
        b"/Launch": ("launch-action", "high"),
        b"/EmbeddedFile": ("embedded-file", "high"),
        b"/RichMedia": ("rich-media", "medium"),
    }
    for label, offset, body in objects:
        for marker, (kind, severity) in markers.items():
            if marker in body:
                if len(findings) < MAX_FINDINGS + 1:
                    findings.append({
                        "kind": kind, "severity": severity, "source": label,
                        "source_offset": offset, "value": marker.decode("ascii"),
                    })
                else:
                    collection_truncated = True
        uri = re.compile(rb"/URI\s*\(([^)]{1,2048})\)")
        for match in uri.finditer(body):
            if len(relationships) >= MAX_RELATIONSHIPS + 1:
                collection_truncated = True
                break
            target = match.group(1).decode("latin-1", errors="replace")
            relationships.append({
                "source": label, "type": "pdf-uri", "target": _safe_text(target, MAX_TEXT_VALUE),
                "external": True, "source_offset": offset + match.start(),
            })
        if scanned < total_limit:
            stream, error, transform = _pdf_stream(body, min(member_limit, total_limit - scanned))
            if error:
                errors.append({"source": label, "error": error})
            elif stream:
                scanned += len(stream)
                text, _ = _decode_text(stream)
                scan = _scan_text(text, label, transform)
                collection_truncated |= _extend_bounded(
                    urls, scan["urls"], MAX_FINDINGS + 1,
                )
                collection_truncated |= _extend_bounded(
                    commands, scan["commands"], MAX_FINDINGS + 1,
                )
                collection_truncated |= scan["truncated"]
        remaining = total_limit - scanned
        if remaining > 0:
            raw = body[: min(len(body), member_limit, remaining)]
            scanned += len(raw)
            text = raw.decode("latin-1", errors="replace")
            scan = _scan_text(text, label)
            collection_truncated |= _extend_bounded(
                urls, scan["urls"], MAX_FINDINGS + 1,
            )
            collection_truncated |= _extend_bounded(
                commands, scan["commands"], MAX_FINDINGS + 1,
            )
            collection_truncated |= scan["truncated"]
            if len(raw) < len(body):
                collection_truncated = True
        elif body:
            collection_truncated = True
    findings, findings_truncated = _unique_rows(
        findings, ("kind", "source", "value"), MAX_FINDINGS,
    )
    relationships, rel_truncated = _unique_rows(
        relationships, ("source", "type", "target"), MAX_RELATIONSHIPS,
    )
    urls, url_truncated = _unique_rows(urls, ("value", "source", "transform"), MAX_FINDINGS)
    commands, command_truncated = _unique_rows(
        commands, ("value", "kind", "source", "transform"), MAX_FINDINGS,
    )
    return {
        "format": "pdf",
        "structure": {
            "object_count": len(objects),
            "object_scan_truncated": len(objects) >= MAX_PDF_OBJECTS,
        },
        "findings": findings,
        "relationships": relationships,
        "urls": urls,
        "commands": commands,
        "errors": errors[:MAX_FINDINGS],
        "coverage": {
            "members_scanned": len(objects),
            "member_scan_truncated": len(objects) >= MAX_PDF_OBJECTS,
            "content_bytes_scanned": scanned,
            "result_truncated": (
                collection_truncated or findings_truncated or rel_truncated
                or url_truncated or command_truncated
            ),
        },
    }


def document_triage(
    path: Path,
    *,
    max_members: int = 1024,
    member_limit: int = 2 * 1024 * 1024,
    total_limit: int = 16 * 1024 * 1024,
) -> dict:
    data = _bounded_file(path, DOCUMENT_INPUT_LIMIT)
    fmt = _document_format(data)
    if fmt == "ooxml":
        result = _ooxml_triage(path, max_members, member_limit, total_limit)
    elif fmt == "ole-compound":
        result = _ole_triage(path, max_members, member_limit, total_limit)
    elif fmt == "rtf":
        result = _rtf_triage(data, member_limit, total_limit)
    else:
        result = _pdf_triage(data, member_limit, total_limit)
    result.update({
        "schema": "blackwall.document-triage.v1",
        "target": {
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        },
        "limits": {
            "input_bytes": DOCUMENT_INPUT_LIMIT,
            "max_members": max_members,
            "member_bytes": member_limit,
            "aggregate_content_bytes": total_limit,
            "archive_expansion_ratio": MAX_ARCHIVE_RATIO,
            "rtf_group_depth": MAX_RTF_DEPTH,
        },
    })
    return result


def _ooxml_candidates(
    path: Path, max_members: int, member_limit: int, total_limit: int, max_depth: int,
) -> tuple[list[tuple[bytes, dict]], list[dict]]:
    candidates: list[tuple[bytes, dict]] = []
    errors: list[dict] = []
    total = 0

    def visit(archive_data: bytes | None, archive_path: Path | None, prefix: str, depth: int) -> None:
        nonlocal total
        try:
            archive_context = zipfile.ZipFile(
                archive_path if archive_path is not None else io.BytesIO(archive_data)
            )
        except (OSError, zipfile.BadZipFile) as exc:
            errors.append({"source": _safe_text(prefix), "error": f"ZIP open failed: {type(exc).__name__}"})
            return
        with archive_context as archive:
            infos = archive.infolist()
            for info in infos[:max_members]:
                if len(candidates) >= MAX_ARTIFACTS or total >= total_limit:
                    return
                source = f"{prefix}!/{info.filename}" if prefix else info.filename
                if not _zip_is_active_part(info.filename):
                    continue
                remaining = min(member_limit, total_limit - total)
                value, error = _zip_read(archive, info, remaining)
                if error:
                    errors.append({"source": _safe_text(source), "error": error})
                    continue
                if value is None:
                    continue
                candidates.append((value, {
                    "kind": "ooxml-active-part",
                    "source": _safe_text(source),
                    "original_name": _safe_text(info.filename),
                    "depth": depth,
                    "transform": "zip-member",
                }))
                total += len(value)
                if depth < max_depth and value.startswith((b"PK\x03\x04", b"PK\x05\x06")):
                    visit(value, None, source, depth + 1)

    visit(None, path, "", 0)
    return candidates, errors


def _ole_candidates(
    path: Path, max_members: int, member_limit: int, total_limit: int,
) -> tuple[list[tuple[bytes, dict]], list[dict]]:
    try:
        import olefile
        from oletools.oleobj import OleNativeStream
    except ImportError as exc:  # pragma: no cover - production lock supplies it
        raise RuntimeError("oletools extraction modules are unavailable") from exc
    candidates = []
    errors = []
    total = 0
    with olefile.OleFileIO(str(path)) as ole:
        for parts in ole.listdir(streams=True, storages=False)[:max_members]:
            if len(candidates) >= MAX_ARTIFACTS or total >= total_limit:
                break
            raw_name = "/".join(parts)
            lowered = raw_name.lower()
            interesting = any(token in lowered for token in (
                "ole10native", "package", "objectpool", "vba/", "macros",
            ))
            try:
                size = int(ole.get_size(parts))
            except (OSError, TypeError, ValueError):
                continue
            if not interesting and size > member_limit:
                continue
            try:
                with ole.openstream(parts) as stream:
                    blob = stream.read(min(member_limit, total_limit - total) + 1)
            except (OSError, TypeError, ValueError) as exc:
                errors.append({"source": _safe_text(raw_name), "error": f"read failed: {type(exc).__name__}"})
                continue
            if len(blob) > min(member_limit, total_limit - total):
                errors.append({"source": _safe_text(raw_name), "error": "stream exceeds extraction limit"})
                continue
            kind = "ole-stream"
            metadata = {
                "kind": kind, "source": _safe_text(raw_name),
                "original_name": _safe_text(parts[-1]), "depth": 0,
                "transform": "ole-stream",
            }
            if "ole10native" in lowered:
                try:
                    native = OleNativeStream(blob)
                    if not native.is_link and native.data is not None:
                        if native.actual_size > member_limit or native.actual_size > total_limit - total:
                            raise ValueError("Ole10Native payload exceeds extraction limit")
                        blob = bytes(native.data)
                        metadata.update({
                            "kind": "ole-native-payload",
                            "original_name": _safe_text(native.filename or parts[-1]),
                            "source_path": _safe_text(native.src_path or ""),
                            "transform": "ole10native",
                        })
                except (AssertionError, IndexError, OSError, TypeError, ValueError) as exc:
                    errors.append({
                        "source": _safe_text(raw_name),
                        "error": f"Ole10Native decode failed: {type(exc).__name__}",
                    })
            magic = blob.startswith((b"MZ", b"\x7fELF", b"PK\x03\x04", b"%PDF-", b"{\\rtf"))
            if interesting or magic:
                candidates.append((blob, metadata))
                total += len(blob)
    return candidates, errors


def _write_candidates(
    candidates: list[tuple[bytes, dict]], output_dir: Path, max_artifacts: int,
    member_limit: int, total_limit: int,
) -> dict:
    output_dir = output_dir.resolve()
    if not output_dir.is_dir() or output_dir.is_symlink():
        raise ValueError("output directory must already exist and must not be a symlink")
    artifacts = []
    skipped = []
    total = 0
    for blob, metadata in candidates:
        if len(artifacts) >= max_artifacts:
            skipped.append({"source": metadata.get("source"), "reason": "artifact count limit"})
            continue
        if len(blob) > member_limit:
            skipped.append({"source": metadata.get("source"), "reason": "artifact byte limit"})
            continue
        if total + len(blob) > total_limit:
            skipped.append({"source": metadata.get("source"), "reason": "aggregate byte limit"})
            continue
        name = f"artifact-{len(artifacts):04d}.bin"
        target = output_dir / name
        with target.open("xb") as stream:
            stream.write(blob)
        digest = hashlib.sha256(blob).hexdigest()
        artifacts.append(metadata | {
            "file": name,
            "size": len(blob),
            "sha256": digest,
            "head": blob[:16].hex(),
        })
        total += len(blob)
    return {
        "artifacts": artifacts,
        "skipped": skipped[:MAX_FINDINGS],
        "count": len(artifacts),
        "total_bytes": total,
        "limits": {
            "max_artifacts": max_artifacts,
            "artifact_bytes": member_limit,
            "aggregate_bytes": total_limit,
        },
    }


def document_extract(
    path: Path,
    output_dir: Path,
    *,
    max_members: int = 1024,
    max_artifacts: int = 32,
    member_limit: int = 8 * 1024 * 1024,
    total_limit: int = 32 * 1024 * 1024,
    max_depth: int = 2,
) -> dict:
    data = _bounded_file(path, DOCUMENT_INPUT_LIMIT)
    fmt = _document_format(data)
    if fmt == "ooxml":
        candidates, errors = _ooxml_candidates(
            path, max_members, member_limit, total_limit, max_depth,
        )
    elif fmt == "ole-compound":
        candidates, errors = _ole_candidates(path, max_members, member_limit, total_limit)
    elif fmt == "rtf":
        candidates, errors = _rtf_objects(
            data, member_limit, max_artifacts, total_limit,
        )
    else:
        candidates, errors = _pdf_candidates(
            data, member_limit, total_limit, max_artifacts,
        )
    result = _write_candidates(candidates, output_dir, max_artifacts, member_limit, total_limit)
    result.update({
        "schema": "blackwall.document-extraction.v1",
        "format": fmt,
        "target_sha256": hashlib.sha256(data).hexdigest(),
        "errors": errors[:MAX_FINDINGS],
        "limits": result["limits"] | {
            "input_bytes": DOCUMENT_INPUT_LIMIT,
            "max_members": max_members,
            "max_depth": max_depth,
            "archive_expansion_ratio": MAX_ARCHIVE_RATIO,
        },
    })
    return result


def detect_script_language(text: str, name: str = "") -> str:
    suffix = Path(name.lower()).suffix
    if suffix in SCRIPT_SUFFIXES:
        return SCRIPT_SUFFIXES[suffix]
    lowered = text.lower()
    if re.search(r"(?im)^\s*attribute\s+vb_name", text) or re.search(
        r"(?i)\b(?:document_open|workbook_open|autoopen)\b", text,
    ):
        return "vba"
    if re.search(r"(?im)^\s*(?:param\s*\(|using namespace|\$env:)", text) or "invoke-expression" in lowered:
        return "powershell"
    if "wscript.shell" in lowered or re.search(r"(?im)^\s*on error resume next", text):
        return "vbscript"
    if re.search(r"\b(?:function\s+[A-Za-z_$]|const\s+|let\s+|var\s+|require\s*\()", text):
        return "javascript"
    return "unknown"


def _unescape_script_string(value: str) -> str:
    escapes = {
        "n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f",
        "v": "\v", "0": "\0", "\\": "\\", "\"": "\"", "'": "'",
    }

    def replace(match: re.Match[str]) -> str:
        token = match.group(1)
        if token.startswith("x"):
            return chr(int(token[1:], 16))
        if token.startswith("u"):
            return chr(int(token[1:], 16))
        return escapes.get(token, token)

    return re.sub(r"\\(x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|[nrtbfv0\\\"'])", replace, value)


def _string_concat_values(text: str) -> list[tuple[str, int]]:
    quoted = r'(?:"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\')'
    expression = re.compile(rf"({quoted}(?:\s*[+&]\s*{quoted}){{1,1023}})")
    literal = re.compile(quoted)
    values = []
    for match in expression.finditer(text):
        pieces = []
        for item in literal.finditer(match.group(1)):
            token = item.group(0)
            pieces.append(_unescape_script_string(token[1:-1]))
        value = "".join(pieces)
        if value:
            values.append((value, match.start()))
    return values


def _decode_base64_token(token: bytes) -> bytes | None:
    if len(token) > (MAX_MEMBER_LIMIT * 4 // 3 + 8):
        return None
    normalized = token.replace(b"-", b"+").replace(b"_", b"/")
    normalized += b"=" * (-len(normalized) % 4)
    try:
        return base64.b64decode(normalized, validate=True)
    except (binascii.Error, ValueError):
        return None


def _decoded_text(blob: bytes) -> tuple[str | None, str]:
    if not blob:
        return None, "binary"
    candidates = []
    if len(blob) >= 4 and blob[1::2][:64].count(0) > max(2, len(blob[1::2][:64]) // 2):
        candidates.append(("utf-16-le", blob.decode("utf-16-le", errors="replace")))
    candidates.extend((
        ("utf-8", blob.decode("utf-8", errors="replace")),
        ("latin-1", blob.decode("latin-1", errors="replace")),
    ))
    for encoding, value in candidates:
        printable = sum(char.isprintable() or char in "\r\n\t" for char in value)
        if value and printable / len(value) >= 0.75:
            return value, encoding
    return None, "binary"


def _useful_payload(blob: bytes, text: str | None) -> bool:
    if blob.startswith((b"MZ", b"\x7fELF", b"PK\x03\x04", b"%PDF-", b"{\\rtf")):
        return True
    if text is None:
        return False
    return bool(
        URL_RE.search(text)
        or COMMAND_RE.search(text)
        or any(rule.search(text) for _, _, rule in SCRIPT_RULES)
        or "BLACKWALL_INERT_" in text
    )


def _extractable_payload(blob: bytes, text: str, transform: str) -> bool:
    if blob.startswith((b"MZ", b"\x7fELF", b"PK\x03\x04", b"%PDF-", b"{\\rtf")):
        return True
    if transform.startswith(("base64:", "hex:", "powershell-encoded-command:")):
        return bool(
            URL_RE.search(text)
            or COMMAND_RE.search(text)
            or any(rule.search(text) for _, _, rule in SCRIPT_RULES)
        )
    return False


def _decode_script(
    text: str, max_layers: int, decoded_limit: int,
) -> tuple[
    list[dict],
    list[tuple[bytes, dict]],
    list[tuple[str, str, str]],
    int,
    bool,
]:
    decoded = []
    payloads: list[tuple[bytes, dict]] = []
    decoded_sources: list[tuple[str, str, str]] = []
    seen = {text}
    queue = [(text, 0, "source")]
    total = 0
    truncated = False

    def admit(value: str, transform: str, offset: int, layer: int, blob: bytes | None = None) -> None:
        nonlocal total, truncated
        if not value or value in seen:
            return
        encoded = value.encode("utf-8", errors="replace")
        charged_bytes = max(len(encoded), len(blob) if blob is not None else 0)
        if charged_bytes > decoded_limit - total or len(decoded) >= MAX_FINDINGS:
            truncated = True
            return
        seen.add(value)
        total += charged_bytes
        decoded.append({
            "value": _safe_text(value, MAX_TEXT_VALUE),
            "full_length": len(value),
            "transform": transform,
            "source_offset": offset,
            "layer": layer,
            "sha256": hashlib.sha256(encoded).hexdigest(),
        })
        decoded_sources.append((value, f"decoded-layer:{layer}", transform))
        if layer < max_layers:
            queue.append((value, layer, transform))
        candidate = blob if blob is not None else encoded
        if _extractable_payload(candidate, value, transform):
            payloads.append((candidate, {
                "kind": "decoded-script-payload",
                "source": f"script-offset:{offset}",
                "transform": transform,
                "depth": layer,
            }))

    while queue:
        current, layer, _ = queue.pop(0)
        next_layer = layer + 1
        if next_layer > max_layers:
            continue
        for value, offset in _string_concat_values(current):
            admit(value, "literal-concatenation", offset, next_layer)
        for match in re.finditer(r"(?i)String\.fromCharCode\s*\(([^)]{1,4096})\)", current):
            tokens = re.findall(r"(?:0x[0-9A-Fa-f]+|\d+)", match.group(1))
            if tokens and len(tokens) <= 1024:
                numbers = [int(token, 0) for token in tokens]
                if all(0 <= number <= 0x10FFFF for number in numbers):
                    admit("".join(chr(number) for number in numbers), "from-char-code", match.start(), next_layer)
        chr_chain = re.compile(
            r"(?i)(?:ChrW?\s*\(\s*(?:&H[0-9A-F]{1,8}|\d{1,10})\s*\)"
            r"\s*(?:&\s*)?){2,1024}"
        )
        for match in chr_chain.finditer(current):
            tokens = re.findall(r"(?i)ChrW?\s*\(\s*(&H[0-9A-F]+|\d+)\s*\)", match.group(0))
            numbers = [int(token[2:], 16) if token.lower().startswith("&h") else int(token) for token in tokens]
            if all(0 <= number <= 0x10FFFF for number in numbers):
                admit("".join(chr(number) for number in numbers), "chr-chain", match.start(), next_layer)
        for match in re.finditer(r"(?i)StrReverse\s*\(\s*([\"'])(.{1,4096}?)\1\s*\)", current):
            admit(_unescape_script_string(match.group(2))[::-1], "string-reverse", match.start(), next_layer)
        for match in re.finditer(r"(?i)(?:-|/)e(?:n(?:c(?:o(?:d(?:e(?:dcommand)?)?)?)?)?)?\s+([A-Za-z0-9_+/-]{8,}={0,2})", current):
            blob = _decode_base64_token(match.group(1).encode("ascii"))
            if blob is None:
                continue
            try:
                value = blob.decode("utf-16-le")
                encoding = "utf-16-le"
            except UnicodeDecodeError:
                value, encoding = _decoded_text(blob)
            if value is not None:
                admit(value, f"powershell-encoded-command:{encoding}", match.start(1), next_layer, blob)
        current_bytes = current.encode("latin-1", errors="ignore")
        for match in BASE64_RE.finditer(current_bytes):
            blob = _decode_base64_token(match.group(0))
            if blob is None or len(blob) < 8:
                continue
            value, encoding = _decoded_text(blob)
            if _useful_payload(blob, value):
                display = value if value is not None else f"binary:{hashlib.sha256(blob).hexdigest()}"
                admit(display, f"base64:{encoding}", match.start(), next_layer, blob)
        for match in HEX_RE.finditer(current_bytes):
            try:
                blob = binascii.unhexlify(match.group(0))
            except binascii.Error:
                continue
            value, encoding = _decoded_text(blob)
            if _useful_payload(blob, value):
                display = value if value is not None else f"binary:{hashlib.sha256(blob).hexdigest()}"
                admit(display, f"hex:{encoding}", match.start(), next_layer, blob)
    return decoded, payloads, decoded_sources, total, truncated


def script_analyze(
    path: Path,
    *,
    language: str = "auto",
    max_layers: int = 4,
    decoded_limit: int = 4 * 1024 * 1024,
) -> tuple[dict, list[tuple[bytes, dict]]]:
    raw = _bounded_file(path, SCRIPT_INPUT_LIMIT)
    text, encoding = _decode_text(raw)
    detected = detect_script_language(text, path.name)
    selected = detected if language == "auto" else language
    if selected not in {"javascript", "jscript", "vbscript", "powershell", "vba", "unknown"}:
        raise ValueError("language must be auto, javascript, jscript, vbscript, powershell, vba, or unknown")
    (
        decoded,
        payloads,
        decoded_sources,
        decoded_bytes,
        decode_truncated,
    ) = _decode_script(text, max_layers, decoded_limit)
    sources = [(text, "source", "raw"), *decoded_sources]
    findings = []
    urls = []
    commands = []
    collection_truncated = False
    for source_text, source, transform in sources:
        scan = _scan_text(source_text, source, transform)
        collection_truncated |= _extend_bounded(urls, scan["urls"], MAX_FINDINGS + 1)
        collection_truncated |= _extend_bounded(
            commands, scan["commands"], MAX_FINDINGS + 1,
        )
        collection_truncated |= scan["truncated"]
        for rule_id, severity, pattern in SCRIPT_RULES:
            for match in pattern.finditer(source_text):
                if len(findings) >= MAX_FINDINGS + 1:
                    collection_truncated = True
                    break
                findings.append({
                    "rule": rule_id,
                    "severity": severity,
                    "value": _safe_text(match.group(0), 512),
                    "source": source,
                    "source_offset": match.start(),
                    "transform": transform,
                })
    findings, findings_truncated = _unique_rows(
        findings, ("rule", "value", "source", "transform"), MAX_FINDINGS,
    )
    urls, urls_truncated = _unique_rows(urls, ("value", "source", "transform"), MAX_FINDINGS)
    commands, commands_truncated = _unique_rows(
        commands, ("value", "kind", "source", "transform"), MAX_FINDINGS,
    )
    result = {
        "schema": "blackwall.script-analysis.v1",
        "target": {
            "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "encoding": encoding,
        },
        "language": selected,
        "language_detected": detected,
        "interpreter_used": False,
        "findings": findings,
        "urls": urls,
        "commands": commands,
        "decoded_strings": decoded,
        "payload_candidates": [
            metadata | {"size": len(blob), "sha256": hashlib.sha256(blob).hexdigest()}
            for blob, metadata in payloads[:MAX_ARTIFACTS]
        ],
        "coverage": {
            "layers_requested": max_layers,
            "decoded_bytes": decoded_bytes,
            "result_truncated": (
                collection_truncated or decode_truncated or findings_truncated
                or urls_truncated or commands_truncated
            ),
        },
        "limits": {
            "input_bytes": SCRIPT_INPUT_LIMIT,
            "max_layers": max_layers,
            "decoded_bytes": decoded_limit,
            "findings": MAX_FINDINGS,
        },
    }
    return result, payloads


def script_extract(
    path: Path,
    output_dir: Path,
    *,
    language: str = "auto",
    max_layers: int = 4,
    max_artifacts: int = 16,
    member_limit: int = 8 * 1024 * 1024,
    total_limit: int = 16 * 1024 * 1024,
) -> dict:
    analysis, candidates = script_analyze(
        path, language=language, max_layers=max_layers, decoded_limit=total_limit,
    )
    result = _write_candidates(candidates, output_dir, max_artifacts, member_limit, total_limit)
    result.update({
        "schema": "blackwall.script-extraction.v1",
        "language": analysis["language"],
        "target_sha256": analysis["target"]["sha256"],
        "analysis_summary": {
            "finding_count": len(analysis["findings"]),
            "decoded_string_count": len(analysis["decoded_strings"]),
            "url_count": len(analysis["urls"]),
            "command_count": len(analysis["commands"]),
        },
    })
    return result


def _bounded_int(value: int, name: str, minimum: int, maximum: int) -> int:
    value = int(value)
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _apply_worker_limits() -> None:
    # Preserve stricter inherited limits while adding defense in depth for a
    # directly invoked worker.  Docker still owns the aggregate container cap.
    limits = (
        (resource.RLIMIT_AS, 768 * 1024 * 1024),
        (resource.RLIMIT_FSIZE, 64 * 1024 * 1024),
        (resource.RLIMIT_NOFILE, 128),
        (resource.RLIMIT_CORE, 0),
    )
    for kind, requested in limits:
        soft, hard = resource.getrlimit(kind)
        ceiling = requested if hard == resource.RLIM_INFINITY else min(requested, hard)
        new_soft = ceiling if soft == resource.RLIM_INFINITY else min(soft, ceiling)
        resource.setrlimit(kind, (new_soft, ceiling))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="BlackWall bounded document/script worker")
    subparsers = parser.add_subparsers(dest="operation", required=True)

    triage = subparsers.add_parser("document-triage")
    triage.add_argument("path", type=Path)
    triage.add_argument("--max-members", type=int, default=1024)
    triage.add_argument("--member-limit", type=int, default=2 * 1024 * 1024)
    triage.add_argument("--total-limit", type=int, default=16 * 1024 * 1024)

    vba = subparsers.add_parser("vba-analyze")
    vba.add_argument("path", type=Path)
    vba.add_argument("--olevba-bin", required=True)

    extraction = subparsers.add_parser("document-extract")
    extraction.add_argument("path", type=Path)
    extraction.add_argument("output_dir", type=Path)
    extraction.add_argument("--max-members", type=int, default=1024)
    extraction.add_argument("--max-artifacts", type=int, default=32)
    extraction.add_argument("--member-limit", type=int, default=8 * 1024 * 1024)
    extraction.add_argument("--total-limit", type=int, default=32 * 1024 * 1024)
    extraction.add_argument("--max-depth", type=int, default=2)

    analysis = subparsers.add_parser("script-analyze")
    analysis.add_argument("path", type=Path)
    analysis.add_argument("--language", default="auto")
    analysis.add_argument("--max-layers", type=int, default=4)
    analysis.add_argument("--decoded-limit", type=int, default=4 * 1024 * 1024)

    script_extraction = subparsers.add_parser("script-extract")
    script_extraction.add_argument("path", type=Path)
    script_extraction.add_argument("output_dir", type=Path)
    script_extraction.add_argument("--language", default="auto")
    script_extraction.add_argument("--max-layers", type=int, default=4)
    script_extraction.add_argument("--max-artifacts", type=int, default=16)
    script_extraction.add_argument("--member-limit", type=int, default=8 * 1024 * 1024)
    script_extraction.add_argument("--total-limit", type=int, default=16 * 1024 * 1024)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    _apply_worker_limits()
    os.umask(0o077)
    try:
        if args.operation == "vba-analyze":
            os.execvp(args.olevba_bin, [
                args.olevba_bin, "-j", "--decode", "--deobf", "--reveal",
                "--no-pcode", str(args.path),
            ])
        elif args.operation == "document-triage":
            result = document_triage(
                args.path,
                max_members=_bounded_int(args.max_members, "max_members", 1, MAX_MEMBERS),
                member_limit=_bounded_int(args.member_limit, "member_limit", 1, MAX_MEMBER_LIMIT),
                total_limit=_bounded_int(args.total_limit, "total_limit", 1, MAX_TOTAL_LIMIT),
            )
        elif args.operation == "document-extract":
            result = document_extract(
                args.path, args.output_dir,
                max_members=_bounded_int(args.max_members, "max_members", 1, MAX_MEMBERS),
                max_artifacts=_bounded_int(args.max_artifacts, "max_artifacts", 1, MAX_ARTIFACTS),
                member_limit=_bounded_int(args.member_limit, "member_limit", 1, MAX_MEMBER_LIMIT),
                total_limit=_bounded_int(args.total_limit, "total_limit", 1, MAX_TOTAL_LIMIT),
                max_depth=_bounded_int(args.max_depth, "max_depth", 0, 4),
            )
        elif args.operation == "script-analyze":
            result, _ = script_analyze(
                args.path, language=args.language,
                max_layers=_bounded_int(args.max_layers, "max_layers", 0, MAX_SCRIPT_LAYERS),
                decoded_limit=_bounded_int(args.decoded_limit, "decoded_limit", 1, MAX_TOTAL_LIMIT),
            )
        else:
            result = script_extract(
                args.path, args.output_dir, language=args.language,
                max_layers=_bounded_int(args.max_layers, "max_layers", 0, MAX_SCRIPT_LAYERS),
                max_artifacts=_bounded_int(args.max_artifacts, "max_artifacts", 1, MAX_ARTIFACTS),
                member_limit=_bounded_int(args.member_limit, "member_limit", 1, MAX_MEMBER_LIMIT),
                total_limit=_bounded_int(args.total_limit, "total_limit", 1, MAX_TOTAL_LIMIT),
            )
    except Exception as exc:
        print(json.dumps({
            "schema": "blackwall.worker-error.v1",
            "error": _safe_text(exc, 1000),
            "error_type": type(exc).__name__,
        }, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
