"""Deterministic, bounded format detection and analysis planning.

The router deliberately does not invoke parsers or analysis engines.  It reads
small, fixed windows from a target, classifies only strong format signals, and
returns a plan that an analyst (or ``--auto``) can execute step by step.  Tool
results are normalized separately so one failed parser does not erase the gap
or stop unrelated analysis.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import struct
import tempfile
from collections import Counter
from pathlib import Path

PLAN_SCHEMA = "blackwall.analysis-plan.v1"
RESULT_SCHEMA = "blackwall.analysis-result.v1"

HEAD_LIMIT = 1024 * 1024
TAIL_LIMIT = 256 * 1024
PE_HEADER_LIMIT = 512
MAX_PE_OFFSET = 16 * 1024 * 1024
MAX_NAME_HINT = 255
PLAN_PHASES = frozenset({"triage", "deep", "full"})
PACKING_OVERRIDES = frozenset({"auto", "packed", "not_packed", "unknown"})
RESULT_STATUSES = (
    "success", "partial", "unsupported", "timeout", "cancelled", "crashed",
    "failed", "skipped", "not_run_redundant",
)

FORMAT_CATEGORIES = (
    "container",
    "executable",
    "managed-runtime",
    "script",
    "capture",
    "document",
    "mobile",
    "bytecode",
    "database",
)

_PE_MACHINES = {
    0x014C: ("x86", 32),
    0x8664: ("x86_64", 64),
    0x01C0: ("arm", 32),
    0x01C4: ("armv7", 32),
    0xAA64: ("aarch64", 64),
}
_ELF_MACHINES = {
    0x0003: "x86",
    0x0008: "mips",
    0x0014: "powerpc",
    0x0028: "arm",
    0x003E: "x86_64",
    0x00B7: "aarch64",
    0x00F3: "riscv",
}
_MACHO_CPUS = {
    7: "x86",
    12: "arm",
    0x01000007: "x86_64",
    0x0100000C: "aarch64",
}


def _read_windows(path: Path) -> tuple[int, bytes, bytes]:
    """Read no more than HEAD_LIMIT + TAIL_LIMIT bytes from a regular file."""
    if not path.is_file():
        raise ValueError(f"analysis target must be a regular file: {path}")
    size = path.stat().st_size
    with path.open("rb") as stream:
        head = stream.read(HEAD_LIMIT)
        if size > HEAD_LIMIT:
            stream.seek(max(HEAD_LIMIT, size - TAIL_LIMIT))
            tail = stream.read(TAIL_LIMIT)
        else:
            tail = b""
    return size, head, tail


def _read_at(path: Path, offset: int, length: int) -> bytes:
    if offset < 0 or offset > MAX_PE_OFFSET or length < 0 or length > 4096:
        return b""
    with path.open("rb") as stream:
        stream.seek(offset)
        return stream.read(length)


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _name_hint(original_name: str | None, path: Path) -> str:
    value = Path(original_name or path.name).name.lower()
    return value[:MAX_NAME_HINT]


def _bounded_fingerprint(size: int, head: bytes, tail: bytes) -> str:
    digest = hashlib.sha256()
    digest.update(str(size).encode("ascii"))
    digest.update(b"\0")
    digest.update(head)
    digest.update(b"\0")
    digest.update(tail)
    return digest.hexdigest()


def _pe_details(path: Path, head: bytes) -> dict | None:
    if len(head) < 64 or head[:2] != b"MZ":
        return None
    pe_offset = int.from_bytes(head[0x3C:0x40], "little")
    if pe_offset > MAX_PE_OFFSET:
        return None
    header = head[pe_offset:pe_offset + 512]
    if len(header) < 32:
        header = _read_at(path, pe_offset, PE_HEADER_LIMIT)
    if len(header) < 32 or header[:4] != b"PE\0\0":
        return None

    machine = int.from_bytes(header[4:6], "little")
    arch, bits = _PE_MACHINES.get(machine, (f"pe-machine-{machine:#06x}", None))
    optional_size = int.from_bytes(header[20:22], "little")
    magic = int.from_bytes(header[24:26], "little")
    data_directory = 24 + (112 if magic == 0x20B else 96)
    clr_offset = data_directory + 14 * 8
    is_dotnet = False
    corflags = None
    if optional_size >= (clr_offset - 24 + 8) and len(header) >= clr_offset + 8:
        clr_rva, clr_size = struct.unpack_from("<II", header, clr_offset)
        is_dotnet = bool(clr_rva and clr_size)
        # For ordinary PEs the CLR header and section table are already inside
        # the bounded 1 MiB head window. Decode CorFlags only when its RVA maps
        # completely inside that existing window; never widen detection reads.
        section_table = pe_offset + 24 + optional_size
        section_count = int.from_bytes(header[6:8], "little")
        for index in range(min(section_count, 96)):
            section = section_table + index * 40
            if section + 40 > len(head):
                break
            virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
                "<IIII", head, section + 8,
            )
            if virtual_address <= clr_rva < virtual_address + max(virtual_size, raw_size):
                delta = clr_rva - virtual_address
                file_offset = raw_offset + delta
                if delta < raw_size and file_offset + 20 <= len(head):
                    corflags = struct.unpack_from("<I", head, file_offset + 16)[0]
                break
    return {
        "architecture": {"name": arch, "bits": bits, "endianness": "little"},
        "is_dotnet": is_dotnet,
        "dotnet": ({
            "corflags": f"0x{corflags:08x}",
            "il_only": bool(corflags & 0x1),
            "mixed_mode": not bool(corflags & 0x1) or bool(corflags & 0x10),
        } if corflags is not None else None),
    }


def _elf_architecture(head: bytes) -> dict:
    bits = {1: 32, 2: 64}.get(head[4] if len(head) > 4 else 0)
    endian = {1: "little", 2: "big"}.get(head[5] if len(head) > 5 else 0, "unknown")
    byteorder = "little" if endian != "big" else "big"
    machine = int.from_bytes(head[18:20], byteorder) if len(head) >= 20 else 0
    return {
        "name": _ELF_MACHINES.get(machine, f"elf-machine-{machine:#06x}"),
        "bits": bits,
        "endianness": endian,
    }


def _macho_architecture(head: bytes) -> dict | None:
    if len(head) < 8:
        return None
    magic = head[:4]
    magics = {
        b"\xfe\xed\xfa\xce": ("big", 32),
        b"\xce\xfa\xed\xfe": ("little", 32),
        b"\xfe\xed\xfa\xcf": ("big", 64),
        b"\xcf\xfa\xed\xfe": ("little", 64),
    }
    if magic not in magics:
        return None
    endian, bits = magics[magic]
    cpu = int.from_bytes(head[4:8], endian)
    return {
        "name": _MACHO_CPUS.get(cpu, f"macho-cpu-{cpu:#x}"),
        "bits": bits,
        "endianness": endian,
    }


def _embedded_cab_signals(head: bytes, file_size: int) -> list[dict]:
    """Return bounded, structurally plausible embedded CAB headers."""
    signals = []
    cursor = 0
    while len(signals) < 8:
        offset = head.find(b"MSCF", cursor)
        if offset < 0:
            break
        cursor = offset + 4
        if offset + 36 > len(head):
            continue
        cabinet_size = struct.unpack_from("<I", head, offset + 8)[0]
        files_offset = struct.unpack_from("<I", head, offset + 16)[0]
        minor, major = head[offset + 24], head[offset + 25]
        folders, files = struct.unpack_from("<HH", head, offset + 26)
        if (
            36 <= cabinet_size <= file_size - offset
            and 36 <= files_offset < cabinet_size
            and major == 1
            and minor <= 3
            and 1 <= folders <= 256
            and 1 <= files <= 8192
        ):
            signals.append({
                "format": "cab",
                "offset": offset,
                "declared_size": cabinet_size,
                "folders": folders,
                "files": files,
            })
    return signals


def _zip_markers(probe: bytes, name: str) -> tuple[str, list[str], list[str]]:
    """Classify ZIP families from names visible in bounded local/central data."""
    lowered = probe.lower()
    markers = []
    categories = ["container"]
    if b"androidmanifest.xml" in lowered and b"classes.dex" in lowered:
        return "apk", ["container", "mobile", "managed-runtime", "bytecode"], [
            "ZIP contains AndroidManifest.xml and classes.dex",
        ]
    if b"payload/" in lowered and b".app/" in lowered:
        return "ipa", ["container", "mobile"], ["ZIP contains an iOS Payload/*.app bundle"]
    if b"[content_types].xml" in lowered:
        categories.append("document")
        if b"word/" in lowered:
            family = "ooxml-word"
        elif b"xl/" in lowered:
            family = "ooxml-spreadsheet"
        elif b"ppt/" in lowered:
            family = "ooxml-presentation"
        else:
            family = "ooxml"
        return family, categories, ["ZIP contains [Content_Types].xml"]
    if b"meta-inf/manifest.mf" in lowered or name.endswith((".jar", ".war")):
        return "java-archive", ["container", "managed-runtime", "bytecode"], [
            "ZIP contains a Java manifest or has a Java archive name hint",
        ]
    if b"package.json" in lowered and (
        b"electron" in lowered or b"app.asar" in lowered or name.endswith(".asar")
    ):
        return "electron", ["container", "script"], [
            "package metadata contains Electron markers",
        ]
    if name.endswith(".saz"):
        return "saz", ["container", "capture"], ["ZIP magic with .saz metadata hint"]
    if name.endswith(".apk"):
        markers.append("ZIP magic with .apk metadata hint; Android members were not visible")
        return "apk", ["container", "mobile", "managed-runtime", "bytecode"], markers
    return "zip", categories, ["ZIP local-file or empty-archive signature"]


def _text_kind(head: bytes, name: str) -> tuple[str, list[str], list[str]] | None:
    if not head:
        return None
    sample = head[:262144]
    printable = sum(byte in b"\t\n\r" or 32 <= byte < 127 for byte in sample)
    if printable / len(sample) < 0.85 or b"\0" in sample[:4096]:
        return None
    text = sample.decode("utf-8", errors="replace")
    lowered = text.lower()
    stripped = text.lstrip("\ufeff\t\r\n ")

    if (
        '"log"' in lowered and '"entries"' in lowered
        and ('"request"' in lowered or '"response"' in lowered)
    ):
        return "har", ["capture"], ["JSON contains HAR log/entries/request fields"]
    if '"qlog_version"' in lowered or (
        '"traces"' in lowered and '"vantage_point"' in lowered
    ):
        return "qlog", ["capture"], ["JSON contains qlog trace fields"]
    compact = re.sub(r"\s+", "", stripped)
    evm = compact[2:] if compact.startswith("0x") else compact
    if len(evm) >= 40 and len(evm) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", evm):
        if evm.lower().startswith(("60806040", "60606040", "7f")) or name.endswith((".evm", ".bytecode")):
            return "evm-hex", ["bytecode"], ["ASCII hex contains a common EVM bytecode prefix"]

    suffix = Path(name).suffix
    if stripped.startswith("#!") and "python" in stripped.splitlines()[0].lower():
        return "python", ["script"], ["Python shebang"]
    if stripped.startswith("#!") and re.search(r"\b(?:ba|z|k)?sh\b", stripped.splitlines()[0]):
        return "shell-script", ["script"], ["shell shebang"]
    if (
        re.search(r"(?im)^\s*(?:using namespace|param\s*\(|\$env:)", text)
        or "invoke-expression" in lowered
        or "new-object " in lowered
        or suffix in {".ps1", ".psm1", ".psd1"}
    ):
        return "powershell", ["script"], ["PowerShell syntax or metadata hint"]
    if (
        re.search(r"(?im)^\s*attribute\s+vb_name\s*=", text)
        or (
            re.search(r"(?i)\b(?:AutoOpen|Document_Open|Workbook_Open)\b", text)
            and re.search(r"(?im)^\s*(?:Private\s+)?Sub\s+", text)
        )
        or suffix in {".bas", ".vba", ".cls"}
    ):
        return "vba", ["script"], ["VBA source syntax or metadata hint"]
    if (
        re.search(r"(?im)^\s*(?:set\s+\w+\s*=\s*createobject|on error resume next)", text)
        or "wscript.shell" in lowered
        or re.search(r"(?i)<script[^>]+language\s*=\s*[\"']?vbscript", text)
        or suffix in {".vbs", ".vbe"}
    ):
        return "vbscript", ["script"], ["VBScript syntax or metadata hint"]
    if (
        re.search(r"(?m)^\s*(?:import|from)\s+[A-Za-z_]", text)
        and re.search(r"(?m)^\s*(?:def|class)\s+[A-Za-z_]", text)
    ) or suffix == ".py":
        return "python", ["script"], ["Python syntax or metadata hint"]
    if (
        re.search(r"\b(?:function\s+[A-Za-z_$]|require\s*\(|module\.exports|=>|console\.)", text)
        or re.search(r"(?i)<script[^>]+language\s*=\s*[\"']?(?:java|j)script", text)
        or suffix in {".js", ".jse", ".mjs", ".cjs", ".jsx", ".hta", ".wsf"}
    ):
        family = "electron" if "electron" in lowered and "require" in lowered else "javascript"
        evidence = "JavaScript syntax"
        if family == "electron":
            evidence = "JavaScript contains Electron import markers"
        return family, ["script"], [evidence]
    return None


def detect_format(
    path: Path,
    *,
    original_name: str | None = None,
    packing_state: str = "auto",
) -> dict:
    """Classify a target using bounded byte windows and stable, strong signals."""
    path = Path(path)
    if packing_state not in PACKING_OVERRIDES:
        choices = ", ".join(sorted(PACKING_OVERRIDES))
        raise ValueError(f"packing_state must be one of: {choices}")
    size, head, tail = _read_windows(path)
    probe = head + tail
    name = _name_hint(original_name, path)
    categories: list[str] = []
    evidence: list[str] = []
    architecture = None
    fmt = "unknown"
    confidence = "low"
    encoding = None
    embedded: list[dict] = []

    pe = _pe_details(path, head)
    if pe:
        architecture = pe["architecture"]
        categories = ["executable"]
        fmt = "pe"
        evidence = ["DOS MZ header and valid PE signature"]
        confidence = "high"
        if pe["is_dotnet"]:
            fmt = "dotnet"
            categories.append("managed-runtime")
            evidence.append("PE CLR data directory is present")
            if pe["dotnet"] and pe["dotnet"]["mixed_mode"]:
                evidence.append("CLR CorFlags indicate mixed managed/native code")
        elif b"app.asar" in probe.lower() or b"electron.exe" in probe.lower():
            fmt = "electron-pe"
            categories.extend(["container", "script"])
            evidence.append("native wrapper contains Electron application markers")
        embedded = _embedded_cab_signals(head, size)
        if embedded:
            evidence.append(
                f"bounded PE bytes contain {len(embedded)} structurally valid embedded CAB header(s)"
            )
    elif head.startswith(b"\x7fELF"):
        endian = "big" if len(head) > 5 and head[5] == 2 else "little"
        object_type = int.from_bytes(head[16:18], endian) if len(head) >= 18 else 0
        fmt = "elf-core" if object_type == 4 else "elf"
        categories = ["capture"] if object_type == 4 else ["executable"]
        evidence = ["ELF magic"]
        if object_type == 4:
            evidence.append("ELF object type is ET_CORE")
        architecture = _elf_architecture(head)
        confidence = "high"
    elif (macho_arch := _macho_architecture(head)) is not None:
        fmt = "mach-o"
        categories = ["executable"]
        evidence = ["Mach-O magic"]
        architecture = macho_arch
        confidence = "high"
    elif head.startswith(b"dex\n") and len(head) >= 8 and head[7] == 0:
        fmt = "dex"
        categories = ["mobile", "managed-runtime", "bytecode"]
        evidence = ["Android DEX header"]
        architecture = {"name": "dalvik", "bits": None, "endianness": "little"}
        confidence = "high"
    elif head.startswith(b"\0asm"):
        fmt = "wasm"
        categories = ["bytecode"]
        evidence = ["WebAssembly magic"]
        architecture = {"name": "wasm32", "bits": 32, "endianness": "little"}
        confidence = "high"
    elif head.startswith(b"\xca\xfe\xba\xbe"):
        fmt = "java-class"
        categories = ["managed-runtime", "bytecode"]
        evidence = ["Java class magic"]
        architecture = {"name": "jvm", "bits": None, "endianness": "big"}
        confidence = "high"
    elif head.startswith(b"SQLite format 3\0"):
        fmt = "sqlite"
        categories = ["database"]
        evidence = ["SQLite 3 header"]
        confidence = "high"
    elif head.startswith((b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")):
        fmt = "pcap"
        categories = ["capture"]
        evidence = ["pcap magic"]
        confidence = "high"
    elif head.startswith(b"\x0a\x0d\x0d\x0a"):
        fmt = "pcapng"
        categories = ["capture"]
        evidence = ["pcapng section-header magic"]
        confidence = "high"
    elif head.startswith(b"%PDF-"):
        fmt = "pdf"
        categories = ["document"]
        evidence = ["PDF header"]
        confidence = "high"
    elif head.startswith(b"{\\rtf"):
        fmt = "rtf"
        categories = ["document"]
        evidence = ["RTF header"]
        confidence = "high"
    elif head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        fmt = "ole-compound"
        categories = ["container", "document"]
        evidence = ["OLE Compound File header"]
        confidence = "high"
    elif head.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        fmt, categories, evidence = _zip_markers(probe, name)
        used_name_hint = any("hint" in item.lower() for item in evidence)
        confidence = "high" if fmt != "zip" and not used_name_hint else "medium"
    elif head.startswith(b"7z\xbc\xaf'\x1c"):
        fmt, categories, evidence, confidence = "7z", ["container"], ["7z magic"], "high"
    elif head.startswith(b"Rar!\x1a\x07"):
        fmt, categories, evidence, confidence = "rar", ["container"], ["RAR magic"], "high"
    elif head.startswith(b"\x1f\x8b"):
        fmt, categories, evidence, confidence = "gzip", ["container"], ["gzip magic"], "high"
    elif head.startswith(b"BZh"):
        fmt, categories, evidence, confidence = "bzip2", ["container"], ["bzip2 magic"], "high"
    elif head.startswith(b"\xfd7zXZ\x00"):
        fmt, categories, evidence, confidence = "xz", ["container"], ["XZ magic"], "high"
    elif len(head) > 265 and head[257:262] == b"ustar":
        fmt, categories, evidence, confidence = "tar", ["container"], ["ustar header"], "high"
    elif head.startswith(b"MSCF"):
        fmt, categories, evidence, confidence = "cab", ["container"], ["Microsoft CAB magic"], "high"
    elif head.startswith((b"070701", b"070702")):
        fmt, categories, evidence, confidence = "cpio-newc", ["container"], ["newc CPIO magic"], "high"
    elif head.startswith(b"'\x05\x19V"):
        fmt, categories, evidence, confidence = "uimage", ["container"], ["legacy U-Boot uImage magic"], "high"
    elif head.startswith(b"BWCFG1\0"):
        fmt, categories, evidence, confidence = "blackwall-config", ["container"], ["versioned inert configuration fixture magic"], "high"
    elif name.endswith(".asar") and len(head) >= 16:
        fmt = "electron"
        categories = ["container", "script"]
        evidence = ["ASAR metadata hint with a binary archive header"]
        confidence = "medium"
    elif name.endswith((".mitm", ".mitmproxy")) and head:
        fmt = "mitmproxy"
        categories = ["capture"]
        evidence = ["non-empty input with a mitmproxy capture metadata hint"]
        confidence = "low"
    else:
        text_kind = _text_kind(head, name)
        if text_kind:
            fmt, categories, evidence = text_kind
            confidence = "high" if fmt in {"har", "qlog"} else "medium"
            if fmt == "evm-hex":
                architecture = {"name": "evm", "bits": 256, "endianness": "big"}
                encoding = "hex"
        elif head.startswith((b"\x60\x80\x60\x40", b"\x60\x60\x60\x40")):
            fmt = "evm-raw"
            categories = ["bytecode"]
            evidence = ["binary contains a common EVM bytecode prefix"]
            architecture = {"name": "evm", "bits": 256, "endianness": "big"}
            encoding = "raw"
            confidence = "medium"

    pack_markers = [
        marker.decode("ascii")
        for marker in (b"UPX!", b"MPRESS1", b"MPRESS2", b"ASPack")
        if marker in probe
    ]
    if packing_state == "auto":
        if pack_markers:
            packing = {
                "state": "likely_packed",
                "source": "router",
                "reasons": [f"bounded input contains {marker} marker" for marker in pack_markers],
            }
        elif "executable" in categories and len(head) >= 4096 and _entropy(head) > 7.45:
            packing = {
                "state": "possibly_packed",
                "source": "router",
                "reasons": ["bounded leading-byte entropy exceeds 7.45 bits/byte"],
            }
        elif "executable" in categories:
            packing = {
                "state": "not_detected",
                "source": "router",
                "reasons": ["no strong packer marker in bounded input windows"],
            }
        else:
            packing = {
                "state": "not_applicable",
                "source": "router",
                "reasons": ["packing heuristic applies only to executable formats"],
            }
    else:
        normalized = "not_detected" if packing_state == "not_packed" else packing_state
        packing = {
            "state": normalized,
            "source": "analyst_override",
            "reasons": ["caller supplied a post-triage packing verdict"],
        }

    primary = categories[0] if categories else "unknown"
    return {
        "primary_category": primary,
        "categories": categories,
        "format": fmt,
        "architecture": architecture,
        "managed": pe.get("dotnet") if pe and pe["is_dotnet"] else None,
        "confidence": confidence,
        "evidence": evidence,
        "encoding": encoding,
        "packing": packing,
        "embedded": embedded,
        "detector_limits": {
            "head_bytes": HEAD_LIMIT,
            "tail_bytes": TAIL_LIMIT,
            "additional_pe_header_bytes": PE_HEADER_LIMIT,
            "archive_contents_extracted": False,
        },
        "routing_fingerprint": _bounded_fingerprint(size, head, tail),
        "size": size,
    }


class _PlanBuilder:
    def __init__(self, path: str, phase: str):
        self.path = path
        self.phase = phase
        self.selected: list[dict] = []
        self.skipped: list[dict] = []
        self._ids: set[str] = set()

    def add(
        self,
        step_id: str,
        tool_name: str,
        *,
        phase: str,
        reason: str,
        deadline: int,
        arguments: dict | None = None,
        fallbacks: list[dict] | None = None,
        state: str = "ready",
        inputs_required: list[str] | None = None,
        include_path: bool = True,
    ) -> None:
        if step_id in self._ids:
            return
        self._ids.add(step_id)
        if self.phase != "full" and phase != self.phase:
            self.skip(tool_name, f"{phase} step excluded from requested {self.phase} phase", phase)
            return
        step = {
            "id": step_id,
            "phase": phase,
            "state": state,
            "tool": tool_name,
            "arguments": ({"path": self.path} if include_path else {}) | (arguments or {}),
            "reason": reason,
            "deadline_seconds": deadline,
            "fallbacks": fallbacks or [],
        }
        if inputs_required:
            step["inputs_required"] = inputs_required
        self.selected.append(step)

    def skip(self, tool_name: str, reason: str, phase: str = "deep",
             arguments: dict | None = None) -> None:
        entry = {"tool": tool_name, "phase": phase, "reason": reason}
        if arguments:
            entry["arguments"] = arguments
        if entry not in self.skipped:
            self.skipped.append(entry)


def _generic_triage(builder: _PlanBuilder) -> None:
    builder.add(
        "triage.file-overview",
        "lab.file_overview",
        phase="triage",
        reason="confirm hashes, libmagic type, entropy, and Detect-It-Easy verdict",
        deadline=150,
        fallbacks=[{"tool": "lab.hexdump", "reason": "retain bounded header evidence"}],
    )
    builder.add(
        "triage.yara",
        "lab.yara_scan",
        phase="triage",
        reason="apply local and bundled signatures",
        deadline=150,
        fallbacks=[],
    )


def _content_triage(builder: _PlanBuilder, *, decoded_strings: bool = False) -> None:
    if decoded_strings:
        builder.add(
            "triage.floss",
            "lab.floss",
            phase="triage",
            reason="recover static, stack, and decoded strings from native code",
            deadline=900,
            arguments={"timeout": 840},
            fallbacks=[{"tool": "lab.strings", "reason": "retain raw ASCII/UTF-16 strings"}],
        )
    else:
        builder.add(
            "triage.strings",
            "lab.strings",
            phase="triage",
            reason="collect printable content without executing the target",
            deadline=180,
            fallbacks=[{"tool": "lab.hexdump", "reason": "inspect a bounded byte window"}],
        )
    builder.add(
        "triage.iocs",
        "lab.extract_iocs",
        phase="triage",
        reason="surface candidate indicators for later code-level verification",
        deadline=240,
        fallbacks=[{"tool": "lab.strings", "reason": "manually review bounded strings"}],
    )


def _native_plan(builder: _PlanBuilder, detection: dict) -> None:
    fmt = detection["format"]
    if fmt in {"pe", "dotnet", "electron-pe"}:
        builder.add(
            "triage.pe-metadata",
            "lab.pe_info",
            phase="triage",
            reason="parse PE headers, imports, resources, sections, and CLR metadata presence",
            deadline=240,
            fallbacks=[{"tool": "lab.rea_objdump", "arguments": {"operation": "file_headers"}, "reason": "independent bounded header view"}],
        )
    elif fmt == "elf":
        builder.add(
            "triage.elf-metadata",
            "lab.elf_info",
            phase="triage",
            reason="parse ELF headers, sections, symbols, libraries, and packer hints",
            deadline=240,
            fallbacks=[{"tool": "lab.rea_objdump", "arguments": {"operation": "file_headers"}, "reason": "independent bounded header view"}],
        )
        builder.add(
            "triage.rea-elf-layout",
            "lab.rea_elf_layout",
            phase="triage",
            reason="retain REA's exact-profile ELF64 linked/file layout and mitigation evidence",
            deadline=360,
            arguments={"timeout": 300},
            fallbacks=[{"tool": "lab.elf_info", "reason": "retain BlackWall/LIEF ELF metadata"}],
        )
    elif fmt == "mach-o":
        builder.add(
            "triage.macho-metadata",
            "lab.macho_info",
            phase="triage",
            reason="parse Mach-O imports, symbols, signature structure, and Objective-C/Swift markers",
            deadline=180,
            arguments={"timeout": 120},
            fallbacks=[{"tool": "lab.rea_objdump", "arguments": {"operation": "file_headers"}, "reason": "retain an independent header view"}],
        )
    _content_triage(builder, decoded_strings=fmt in {"pe", "electron-pe"})
    if any(item.get("format") == "cab" for item in detection.get("embedded", [])):
        builder.add(
            "deep.recursive-unpack",
            "lab.recursive_unpack",
            phase="deep",
            reason=(
                "validated embedded CAB headers admit automatic PE RCDATA carving, "
                "bounded CAB decoding, lineage, and immediate child rerouting"
            ),
            deadline=360,
            arguments={
                "max_depth": 3,
                "max_artifacts": 64,
                "max_artifact_bytes": 33554432,
                "max_expanded_bytes": 134217728,
                "max_elapsed_seconds": 300,
            },
            fallbacks=[{
                "tool": "lab.extract_pe_resource",
                "reason": "carve one resource explicitly if the bounded resource walker rejects it",
            }],
        )
    if fmt in {"pe", "electron-pe", "elf"}:
        builder.add(
            "triage.capabilities",
            "lab.capa",
            phase="triage",
            reason="identify malware capabilities and high-value native addresses",
            deadline=660,
            arguments={"timeout": 600},
            fallbacks=[{"tool": "ghidra.list_imports", "reason": "infer capabilities from native imports"}],
        )
    else:
        builder.skip("lab.capa", "the installed capa release does not accept Mach-O input", "triage")
    if fmt in {"elf", "mach-o"}:
        builder.skip("lab.floss", "FLOSS decoded-string analysis supports PE input only", "triage")
    builder.add(
        "deep.ghidra-primary",
        "ghidra.list_project_binaries",
        phase="deep",
        reason="use the persistent BlackWall Ghidra project as the primary native workspace",
        deadline=180,
        arguments={},
        fallbacks=[{"tool": "lab.rea_native_load_image", "reason": "validate the static load image if the primary import is malformed"}],
        include_path=False,
    )
    builder.add(
        "deep.ghidra-target-function",
        "ghidra.decompile_function",
        phase="deep",
        reason="decompile the selected high-value function in the persistent primary workspace first",
        deadline=180,
        arguments={"include_callees": True, "include_strings": True, "include_xrefs": True},
        fallbacks=[{"tool": "lab.rea_native_function", "reason": "retain an independent static dossier"}],
        state="deferred",
        inputs_required=["binary_name from project inventory", "name_or_address from capa or Ghidra"],
        include_path=False,
    )
    builder.add(
        "deep.rea-focused-function",
        "lab.rea_native_function",
        phase="deep",
        reason="independently inspect only a high-value function selected by capa or persistent Ghidra",
        deadline=960,
        arguments={"timeout": 900},
        fallbacks=[{"tool": "ghidra.decompile_function", "reason": "continue in the persistent primary workspace"}],
        state="deferred",
        inputs_required=["procedure address or symbol from prior evidence"],
    )
    builder.add(
        "deep.rea-feature-trace",
        "lab.rea_native_trace",
        phase="deep",
        reason="corroborate one relevant recovered feature through static references",
        deadline=960,
        arguments={"timeout": 900},
        fallbacks=[{"tool": "ghidra.list_xrefs", "reason": "trace the feature in persistent Ghidra"}],
        state="deferred",
        inputs_required=["literal feature from prior evidence"],
    )
    builder.add(
        "deep.rea-value-flow",
        "lab.rea_native_value_flow",
        phase="deep",
        reason="answer a bounded value-flow question only after a relevant procedure is known",
        deadline=1260,
        arguments={"timeout": 1200},
        fallbacks=[{"tool": "ghidra.decompile_function", "reason": "manually trace values in persistent Ghidra"}],
        state="deferred",
        inputs_required=["procedure address or symbol from prior evidence"],
    )
    if fmt == "elf":
        builder.add(
            "deep.elf-emulation",
            "lab.emulate_elf",
            phase="deep",
            reason="probe the ELF entry point in a syscall-blocked instruction-bounded emulator when static evidence needs corroboration",
            deadline=90,
            arguments={"max_instructions": 100000, "emulation_timeout_ms": 5000, "timeout": 30},
            fallbacks=[{"tool": "ghidra.decompile_function", "reason": "continue with static entry-point analysis"}],
            state="deferred",
            inputs_required=["static triage justifies bounded entry-point emulation"],
        )
    builder.skip(
        "lab.rea_native_overview",
        "broad duplicate native analysis is low-value by default; use only for unusual or conflicting evidence",
    )
    builder.skip(
        "lab.rea_static_analysis",
        "generic REA artifact analysis is redundant for a recognized native executable",
        arguments={"workflow": "artifact"},
    )


def _packing_plan(builder: _PlanBuilder, detection: dict) -> None:
    packing = detection["packing"]
    if packing["state"] in {"packed", "likely_packed", "possibly_packed"}:
        upx_detected = any("UPX" in reason for reason in packing["reasons"])
        if upx_detected:
            builder.skip(
                "lab.binwalk_scan",
                "a strong UPX marker admits the focused unpacker; a broad embedded scan is redundant unless unpacking fails",
                phase="triage",
                arguments={"timeout": 30},
            )
            builder.add(
                "triage.upx-unpack",
                "lab.upx_unpack",
                phase="triage",
                reason="UPX marker supports a focused, non-executing unpack attempt before deep analysis",
                deadline=180,
                fallbacks=[{"tool": "lab.carve_embedded", "reason": "recover embedded PE/ELF layers without executing them"}],
            )
        else:
            builder.add(
                "triage.embedded-scan",
                "lab.binwalk_scan",
                phase="triage",
                reason="unidentified packing evidence warrants a bounded embedded-content scan",
                deadline=60,
                arguments={"timeout": 30},
                fallbacks=[{"tool": "lab.hexdump", "reason": "inspect suspected embedded signatures"}],
            )
        if "executable" in detection["categories"]:
            builder.add(
                "deep.rea-packed-load-image",
                "lab.rea_native_load_image",
                phase="deep",
                reason="validate the mapped image only if unpacking fails or original addresses remain relevant",
                deadline=960,
                arguments={"timeout": 900},
                fallbacks=[{"tool": "lab.pe_info", "reason": "retain BlackWall header and section evidence"}],
                state="deferred",
                inputs_required=["unpacking unavailable, failed, or left conflicting mapped addresses"],
            )


def _managed_plan(builder: _PlanBuilder, detection: dict) -> None:
    builder.add(
        "triage.dotnet-metadata",
        "lab.dotnet_info",
        phase="triage",
        reason="retain an independent bounded CLR metadata and user-string inventory",
        deadline=360,
        fallbacks=[{"tool": "lab.strings", "reason": "retain raw managed metadata strings"}],
    )
    builder.add(
        "triage.dotnet-inventory",
        "lab.dotnet_inventory",
        phase="triage",
        reason="enumerate ILSpy assembly, type, and MethodDef-token metadata for focused decompilation",
        deadline=240,
        arguments={"entity": "all", "offset": 0, "limit": 200, "timeout": 180},
        fallbacks=[{"tool": "lab.dotnet_info", "reason": "continue from the dnfile metadata inventory"}],
    )
    builder.add(
        "triage.dotnet-resources",
        "lab.dotnet_list_resources",
        phase="triage",
        reason="list embedded CLR and .resources entries without writing attacker-selected paths",
        deadline=180,
        arguments={"offset": 0, "limit": 200, "timeout": 120},
        fallbacks=[{"tool": "lab.dotnet_info", "reason": "retain manifest-resource names from CLR metadata"}],
    )
    _content_triage(builder)
    builder.add(
        "deep.dotnet-resource-extraction",
        "lab.dotnet_extract_resources",
        phase="deep",
        reason="content-address and lineage-link bounded raw manifest resources for recursive routing",
        deadline=240,
        arguments={
            "min_size": 1, "max_resources": 64,
            "max_resource_bytes": 33554432, "max_total_bytes": 67108864,
        },
        fallbacks=[{"tool": "lab.dotnet_list_resources", "reason": "retain the resource inventory without extraction"}],
    )
    builder.add(
        "deep.dotnet-decompile",
        "lab.dotnet_decompile",
        phase="deep",
        reason="decompile one high-value MethodDef token to retained C# source",
        deadline=240,
        arguments={"timeout": 180},
        fallbacks=[{"tool": "lab.rea_managed_members", "reason": "inspect bounded CIL anchors and literals"}],
        state="deferred",
        inputs_required=["MethodDef token selected from dotnet_inventory or dotnet_search"],
    )
    builder.add(
        "deep.dotnet-call-references",
        "lab.dotnet_call_references",
        phase="deep",
        reason="map bounded static IL callers and callees for a selected managed method",
        deadline=300,
        arguments={"direction": "both", "max_methods": 1000, "limit": 200, "timeout": 240},
        fallbacks=[{"tool": "lab.rea_managed_members", "reason": "retain REA managed-member call anchors"}],
        state="deferred",
        inputs_required=["MethodDef token selected from dotnet_inventory or dotnet_search"],
    )
    builder.add(
        "deep.dotnet-search",
        "lab.dotnet_search",
        phase="deep",
        reason="attribute a literal of interest to bounded decoded IL method bodies",
        deadline=300,
        arguments={"max_methods": 1000, "limit": 100, "case_sensitive": False, "timeout": 240},
        fallbacks=[{"tool": "lab.rea_managed_members", "reason": "search selected managed members through REA"}],
        state="deferred",
        inputs_required=["literal derived from metadata, strings, resources, or an IOC"],
    )
    builder.add(
        "deep.rea-managed-overview",
        "lab.rea_static_analysis",
        phase="deep",
        reason="use REA's focused PE/CLI evidence workflow instead of native decompilation",
        deadline=660,
        arguments={"workflow": "managed", "timeout": 600},
        fallbacks=[{"tool": "lab.dotnet_info", "reason": "continue from BlackWall CLR metadata"}],
    )
    builder.add(
        "deep.rea-managed-members",
        "lab.rea_managed_members",
        phase="deep",
        reason="inspect CIL anchors and literals for selected managed members",
        deadline=660,
        arguments={"timeout": 600},
        fallbacks=[{"tool": "lab.dotnet_info", "reason": "use the bounded type and method inventory"}],
    )
    builder.add(
        "deep.rea-managed-boundaries",
        "lab.rea_static_analysis",
        phase="deep",
        reason="identify P/Invoke and mixed native boundaries that need separate review",
        deadline=660,
        arguments={"workflow": "managed_native_boundaries", "timeout": 600},
        fallbacks=[{"tool": "lab.pe_info", "reason": "review PE imports and CLR metadata"}],
    )
    managed = detection.get("managed")
    # Missing CorFlags are not evidence of IL-only code.  If the bounded
    # detector cannot map the CLR header, conservatively retain the native
    # workspace until dotnet_inventory supplies stronger evidence.
    mixed_mode = managed is None or bool(managed.get("mixed_mode"))
    if mixed_mode:
        native_reason = (
            "CLR CorFlags show native code, so retain a persistent workspace for the native half"
            if managed is not None
            else "CLR CorFlags were unavailable, so conservatively retain a persistent native workspace"
        )
        builder.add(
            "deep.ghidra-mixed-native",
            "ghidra.list_project_binaries",
            phase="deep",
            reason=native_reason,
            deadline=180,
            arguments={},
            fallbacks=[{"tool": "lab.rea_native_load_image", "reason": "inspect the mixed-mode native load image independently"}],
            include_path=False,
        )
        builder.add(
            "deep.rea-mixed-native-function",
            "lab.rea_native_function",
            phase="deep",
            reason="inspect a high-value native boundary identified by managed/native metadata",
            deadline=960,
            arguments={"timeout": 900},
            fallbacks=[{"tool": "ghidra.decompile_function", "reason": "use the persistent native workspace"}],
            state="deferred",
            inputs_required=["native address identified by dotnet inventory or managed-boundary analysis"],
        )
        builder.skip(
            "lab.rea_native_overview",
            "mixed-mode analysis keeps Ghidra primary and uses focused native functions after boundaries are known",
        )
    else:
        builder.skip(
            "ghidra.list_project_binaries",
            "Ghidra native decompilation is not the primary path for IL-only CLR code",
        )
        builder.skip(
            "lab.rea_native_overview",
            "managed-specific workflows provide higher-value evidence than a native overview",
        )


def _script_plan(builder: _PlanBuilder, language: str) -> None:
    builder.add(
        "triage.script-static-analysis",
        "lab.script_analyze",
        phase="triage",
        reason=(
            "recover script-specific behaviors, commands, URLs, and bounded "
            "deobfuscation layers without invoking an interpreter"
        ),
        deadline=120,
        arguments={
            "language": language,
            "max_layers": 4,
            "max_decoded_bytes": 4194304,
            "timeout": 60,
        },
        fallbacks=[{"tool": "lab.strings", "reason": "retain raw script text for manual review"}],
    )
    builder.add(
        "deep.script-payload-extraction",
        "lab.script_extract_payloads",
        phase="deep",
        reason=(
            "content-address decoded payload bytes with transform provenance "
            "for recursive routing"
        ),
        deadline=120,
        arguments={
            "language": language,
            "max_layers": 4,
            "max_artifacts": 16,
            "max_artifact_bytes": 8388608,
            "max_total_bytes": 16777216,
            "timeout": 60,
        },
        fallbacks=[{"tool": "lab.script_analyze", "reason": "retain decoded metadata without writing payloads"}],
    )


def _focused_rea_plan(builder: _PlanBuilder, detection: dict) -> bool:
    fmt = detection["format"]
    if fmt == "apk":
        builder.add(
            "triage.android-resources",
            "lab.android_resources",
            phase="triage",
            reason="use pinned JADX for manifest/package evidence and safely lineage-link bounded raw resources",
            deadline=660,
            arguments={
                "max_resources": 128,
                "max_resource_bytes": 8388608,
                "max_total_bytes": 33554432,
                "timeout": 600,
            },
            fallbacks=[{"tool": "lab.strings", "reason": "recover manifest and DEX string evidence"}],
        )
        builder.add(
            "deep.rea-android-search",
            "lab.rea_android_search",
            phase="deep",
            reason="search relevant classes after components and indicators are known",
            deadline=660,
            arguments={"timeout": 600},
            fallbacks=[{"tool": "lab.strings", "reason": "search raw package strings"}],
            state="deferred",
            inputs_required=["query derived from Android overview"],
        )
        builder.add(
            "deep.android-decompile",
            "lab.android_decompile",
            phase="deep",
            reason="decompile one selected Java/Kotlin class or method with the pinned JADX engine",
            deadline=660,
            arguments={"timeout": 600},
            fallbacks=[{"tool": "lab.rea_android_class", "reason": "retain the underlying focused JADX class evidence"}],
            state="deferred",
            inputs_required=["class_name and optional method_name from Android inventory/search"],
        )
    elif fmt == "electron":
        _script_plan(builder, "javascript")
        builder.add(
            "triage.rea-javascript",
            "lab.rea_static_analysis",
            phase="triage",
            reason="analyze JavaScript application structure and suspicious static behavior",
            deadline=660,
            arguments={"workflow": "javascript", "timeout": 600},
            fallbacks=[{"tool": "lab.strings", "reason": "retain script text for manual review"}],
        )
        builder.skip(
            "lab.rea_static_analysis",
            "Electron fuse inspection requires a packaged native executable or .app, not JavaScript/ASAR alone",
            arguments={"workflow": "electron_fuses"},
        )
    elif fmt == "javascript":
        _script_plan(builder, "javascript")
        builder.skip(
            "lab.rea_static_analysis",
            "REA 6.7.0 application analysis accepts a directory or ASAR, not a standalone JavaScript file",
            phase="triage",
            arguments={"workflow": "javascript"},
        )
    elif fmt == "wasm":
        builder.add(
            "triage.rea-wasm",
            "lab.rea_static_analysis",
            phase="triage",
            reason="validate and inspect WebAssembly sections, imports, exports, and functions",
            deadline=660,
            arguments={"workflow": "wasm", "timeout": 600},
            fallbacks=[{"tool": "lab.strings", "reason": "retain embedded strings"}],
        )
    elif fmt in {"evm-raw", "evm-hex"}:
        builder.add(
            "triage.rea-evm",
            "lab.rea_evm_interface",
            phase="triage",
            reason="infer an EVM interface using the detected carrier encoding",
            deadline=660,
            arguments={"encoding": detection["encoding"], "timeout": 600},
            fallbacks=[{"tool": "lab.hexdump", "reason": "retain bounded bytecode evidence"}],
        )
    elif fmt in {"pcap", "pcapng"}:
        builder.add(
            "triage.rea-pcap",
            "lab.rea_static_analysis",
            phase="triage",
            reason="inspect the retained packet capture without contacting observed endpoints",
            deadline=660,
            arguments={"workflow": "pcap", "timeout": 600},
            fallbacks=[{"tool": "lab.strings", "reason": "recover visible protocol strings and indicators"}],
        )
    elif fmt in {"har", "mitmproxy", "qlog", "saz"}:
        builder.add(
            "triage.rea-web-capture",
            "lab.rea_web_capture",
            phase="triage",
            reason="parse the retained web capture with an explicit, detected format",
            deadline=660,
            arguments={"capture_format": fmt, "timeout": 600},
            fallbacks=[{"tool": "lab.strings", "reason": "recover visible request/response evidence"}],
        )
    elif fmt == "sqlite":
        builder.add(
            "triage.rea-sqlite",
            "lab.rea_static_analysis",
            phase="triage",
            reason="inspect SQLite schema and stored records with a focused static workflow",
            deadline=660,
            arguments={"workflow": "sqlite", "timeout": 600},
            fallbacks=[{"tool": "lab.strings", "reason": "recover visible database text"}],
        )
    else:
        return False
    _content_triage(builder)
    builder.skip(
        "ghidra.list_project_binaries",
        "a focused format workflow is higher value than native Ghidra for this target",
    )
    builder.skip(
        "lab.rea_native_overview",
        "the target is not routed as a native PE or ELF executable",
    )
    return True


def build_analysis_plan(
    path: Path,
    *,
    display_path: str | None = None,
    original_name: str | None = None,
    phase: str = "full",
    packing_state: str = "auto",
) -> dict:
    """Return a deterministic plan with explicit selections, skips, and gaps."""
    if phase not in PLAN_PHASES:
        raise ValueError(f"phase must be one of: {', '.join(sorted(PLAN_PHASES))}")
    path = Path(path)
    detection = detect_format(path, original_name=original_name, packing_state=packing_state)
    routed_path = display_path or str(path)
    builder = _PlanBuilder(routed_path, phase)
    _generic_triage(builder)

    fmt = detection["format"]
    if fmt == "dotnet":
        builder.add(
            "triage.pe-metadata",
            "lab.pe_info",
            phase="triage",
            reason="confirm PE structure and CLR data-directory evidence",
            deadline=240,
            fallbacks=[{"tool": "lab.hexdump", "reason": "retain bounded PE header evidence"}],
        )
        _managed_plan(builder, detection)
    elif fmt == "electron-pe":
        _native_plan(builder, detection)
        builder.add(
            "deep.rea-electron-fuses",
            "lab.rea_static_analysis",
            phase="deep",
            reason="inspect the native Electron wrapper's fuse configuration with a focused workflow",
            deadline=660,
            arguments={"workflow": "electron_fuses", "timeout": 600},
            fallbacks=[{"tool": "lab.strings", "reason": "review embedded Electron markers"}],
        )
    elif fmt in {"pe", "elf", "mach-o"}:
        _native_plan(builder, detection)
    elif fmt == "elf-core":
        _content_triage(builder)
        builder.add(
            "triage.rea-recorded-crash",
            "lab.rea_recorded_crash",
            phase="triage",
            reason="parse supplied core notes, threads, registers, signals, and mappings without launching a debugger or target",
            deadline=360,
            arguments={"timeout": 300},
            fallbacks=[{"tool": "lab.rea_objdump", "arguments": {"operation": "file_headers"}, "reason": "retain ELF core headers"}],
        )
        builder.skip("ghidra.list_project_binaries", "an ELF core is recorded state, not a native executable to import")
    elif fmt == "blackwall-config":
        _content_triage(builder)
        builder.add(
            "triage.configuration-recovery",
            "lab.config_extract",
            phase="triage",
            reason="a versioned family marker admits its bounded configuration extractor",
            deadline=90,
            arguments={"family": "auto", "timeout": 60},
            fallbacks=[{"tool": "lab.hexdump", "reason": "inspect the bounded configuration carrier"}],
        )
        builder.skip("ghidra.list_project_binaries", "configuration data is not a native executable")
    elif _focused_rea_plan(builder, detection):
        pass
    elif fmt in {"java-class", "java-archive", "dex"}:
        _content_triage(builder)
        builder.add(
            "triage.rea-artifact",
            "lab.rea_static_analysis",
            phase="triage",
            reason="request bounded artifact metadata for recognized managed bytecode",
            deadline=660,
            arguments={"workflow": "artifact", "timeout": 600},
            fallbacks=[{"tool": "lab.strings", "reason": "retain class and package strings"}],
        )
        builder.skip("lab.rea_native_overview", "managed bytecode is not a native executable")
    elif "document" in detection["categories"]:
        _content_triage(builder)
        builder.add(
            "triage.document-structure",
            "lab.document_triage",
            phase="triage",
            reason=(
                "parse bounded document structure, relationships, active-content "
                "markers, URLs, and command fields"
            ),
            deadline=180,
            arguments={
                "max_members": 1024,
                "max_member_bytes": 2097152,
                "max_total_bytes": 16777216,
                "timeout": 120,
            },
            fallbacks=[{"tool": "lab.hexdump", "reason": "retain bounded structural bytes"}],
        )
        if fmt in {
            "ooxml", "ooxml-word", "ooxml-spreadsheet",
            "ooxml-presentation", "ole-compound",
        }:
            builder.add(
                "triage.document-vba",
                "lab.document_vba",
                phase="triage",
                reason="extract VBA source and decoded/deobfuscated expressions with pinned oletools",
                deadline=240,
                arguments={"timeout": 180},
                fallbacks=[{"tool": "lab.document_triage", "reason": "retain macro-container and active-part evidence"}],
            )
        else:
            builder.skip(
                "lab.document_vba",
                f"{fmt} is not an OLE or OOXML VBA container",
                phase="triage",
            )
        builder.add(
            "deep.document-artifact-extraction",
            "lab.document_extract_artifacts",
            phase="deep",
            reason=(
                "extract bounded active parts and embedded payloads with generated "
                "names and content-addressed lineage"
            ),
            deadline=180,
            arguments={
                "max_members": 1024,
                "max_artifacts": 32,
                "max_artifact_bytes": 8388608,
                "max_total_bytes": 33554432,
                "max_depth": 2,
                "timeout": 120,
            },
            fallbacks=[{"tool": "lab.document_triage", "reason": "retain structure without extraction"}],
        )
        builder.skip(
            "lab.binwalk_scan",
            "the bounded document parser supersedes broad signature scanning; retain binwalk only as an analyst-selected fallback",
            phase="deep",
            arguments={"timeout": 30},
        )
        builder.skip(
            "lab.rea_static_analysis",
            "no allowlisted focused REA workflow matches this document family",
        )
        builder.skip(
            "ghidra.list_project_binaries",
            "documents require static document tooling rather than native decompilation",
        )
    elif fmt == "cab":
        _content_triage(builder)
        builder.add(
            "deep.recursive-unpack",
            "lab.recursive_unpack",
            phase="deep",
            reason="extract CAB members with bounded expansion, generated names, lineage, and immediate rerouting",
            deadline=360,
            arguments={"max_depth": 3, "max_artifacts": 64, "max_artifact_bytes": 33554432, "max_expanded_bytes": 134217728, "max_elapsed_seconds": 300},
            fallbacks=[{"tool": "lab.binwalk_scan", "arguments": {"timeout": 30}, "reason": "retain signatures when CAB extraction rejects the structure"}],
        )
        builder.skip(
            "lab.rea_static_analysis",
            "REA 6.7.0 artifact extraction does not support raw CAB input",
            arguments={"workflow": "artifact"},
        )
        builder.skip("ghidra.list_project_binaries", "CAB members must be extracted before native import")
    elif "container" in detection["categories"]:
        _content_triage(builder)
        if fmt not in {"apk", "ooxml", "ooxml-word", "ooxml-spreadsheet", "ooxml-presentation"}:
            builder.add(
                "triage.rea-artifact",
                "lab.rea_static_analysis",
                phase="triage",
                reason="inspect recognized archive metadata without executing members",
                deadline=660,
                arguments={"workflow": "artifact", "timeout": 600},
                fallbacks=[{"tool": "lab.binwalk_scan", "reason": "retain bounded embedded signatures"}],
            )
        builder.add(
            "deep.recursive-unpack",
            "lab.recursive_unpack",
            phase="deep",
            reason="walk nested archive, installer, firmware, filesystem, and packer layers under global graph budgets",
            deadline=360,
            arguments={"max_depth": 3, "max_artifacts": 64, "max_artifact_bytes": 33554432, "max_expanded_bytes": 134217728, "max_elapsed_seconds": 300},
            fallbacks=[{"tool": "lab.binwalk_scan", "arguments": {"timeout": 30}, "reason": "retain signatures for unsupported container layers"}],
        )
        builder.skip("ghidra.list_project_binaries", "container members must be identified before native import")
    elif "script" in detection["categories"]:
        _content_triage(builder)
        language = {
            "javascript": "javascript",
            "powershell": "powershell",
            "vbscript": "vbscript",
            "vba": "vba",
        }.get(fmt, "unknown")
        _script_plan(builder, language)
        builder.skip(
            "lab.rea_static_analysis",
            "no focused allowlisted REA workflow matches this script language",
        )
        builder.skip("ghidra.list_project_binaries", "script text is not a native Ghidra target")
    else:
        _content_triage(builder)
        builder.add(
            "triage.unknown-embedded-scan",
            "lab.binwalk_scan",
            phase="triage",
            reason="seek strong embedded-format signatures for an otherwise unknown target",
            deadline=60,
            arguments={"timeout": 30},
            fallbacks=[{"tool": "lab.hexdump", "reason": "inspect bounded bytes manually"}],
        )
        builder.skip(
            "lab.rea_static_analysis",
            "unknown format: do not guess a broad REA workflow and hide unsupported-format gaps",
        )
        builder.skip("ghidra.list_project_binaries", "unknown target is not admitted as a native executable")

    if fmt != "blackwall-config":
        builder.add(
            "deep.configuration-recovery",
            "lab.config_extract",
            phase="deep",
            reason="run a selected family extractor only after static evidence identifies a configuration carrier",
            deadline=90,
            arguments={"family": "auto", "timeout": 60},
            fallbacks=[{"tool": "lab.strings", "reason": "retain candidate configuration values"}],
            state="deferred",
            inputs_required=["family marker or configuration carrier identified by prior evidence"],
        )
    _packing_plan(builder, detection)
    builder.selected.sort(key=lambda step: {"triage": 0, "deep": 1}[step["phase"]])

    target_sha256 = path.name.lower() if re.fullmatch(r"[0-9a-fA-F]{64}", path.name) else None
    identity = {
        "target": routed_path,
        "fingerprint": detection["routing_fingerprint"],
        "phase": phase,
        "packing_state": detection["packing"]["state"],
        "selected": builder.selected,
        "skipped": builder.skipped,
    }
    plan_id = hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:16]
    return {
        "schema": PLAN_SCHEMA,
        "plan_id": plan_id,
        "target": {
            "path": routed_path,
            "sha256": target_sha256,
            "sha256_source": "content-addressed filename" if target_sha256 else None,
            "size": detection["size"],
            "routing_fingerprint": detection["routing_fingerprint"],
            "original_name_hint": _name_hint(original_name, path) if original_name else None,
        },
        "phase": phase,
        "detection": {key: value for key, value in detection.items() if key != "size"},
        "selected": builder.selected,
        "skipped": builder.skipped,
        "execution_policy": {
            "ordering": "selected list order; deferred steps wait for inputs_required",
            "deadline_semantics": "orchestration wall-clock budget; an internal timeout argument is included where the tool supports one",
            "on_non_success": "record the normalized gap, try the listed fallback, and continue independent steps",
            "packing_override": "rerun analysis_plan with packed, not_packed, or unknown after DIE evidence",
            "derived_artifacts": "route every unpacked or carved artifact before selecting its analyzers",
        },
        "result_contract": {
            "schema": RESULT_SCHEMA,
            "statuses": list(RESULT_STATUSES),
            "continuable_statuses": [
                "partial", "unsupported", "timeout", "cancelled", "crashed",
                "failed", "skipped", "not_run_redundant",
            ],
        },
    }


def _result_has_evidence(result: dict) -> bool:
    for key in ("evidence", "summary", "stdout", "saved_to", "matches", "strings", "output"):
        value = result.get(key)
        if value not in (None, "", [], {}):
            return True
    return False


def _bounded_message(value: object, limit: int = 1000) -> str | None:
    if value in (None, ""):
        return None
    text = str(value).replace("\0", "")
    return text if len(text) <= limit else text[:limit] + f"... [truncated {len(text) - limit} chars]"


def normalize_result(
    step_id: str,
    tool_name: str,
    *,
    result: dict | None = None,
    error: str | None = None,
) -> dict:
    """Normalize heterogeneous tool outcomes without swallowing useful gaps."""
    if not step_id or len(step_id) > 200 or "\0" in step_id:
        raise ValueError("invalid step_id")
    if not tool_name or len(tool_name) > 200 or "\0" in tool_name:
        raise ValueError("invalid tool_name")
    if result is not None and not isinstance(result, dict):
        raise ValueError("result must be an object or null")
    result = result or {}
    message = _bounded_message(error or result.get("error") or result.get("stderr"))
    lowered = (message or "").lower()
    declared = str(result.get("status", "")).lower().replace("-", "_")
    has_evidence = _result_has_evidence(result)
    failure_signal = bool(
        error
        or result.get("error")
        or result.get("ok") is False
        or result.get("complete") is False
        or result.get("rc") not in (None, 0)
        or result.get("cancelled") is True
        or result.get("crashed") is True
        or declared in {"cancelled", "canceled", "crashed", "error", "failed", "failure"}
    )

    if declared in {"not_run_redundant", "redundant"}:
        status = "not_run_redundant"
    elif declared in {"skipped", "not_run"}:
        status = "skipped"
    elif (
        result.get("timed_out") is True
        or declared in {"timeout", "timed_out"}
        or "timed out" in lowered
        or "timeout" in lowered
        or "deadline exceeded" in lowered
    ):
        status = "timeout"
    elif (
        result.get("cancelled") is True
        or declared in {"cancelled", "canceled"}
        or "cancelled by caller" in lowered
        or "canceled by caller" in lowered
    ):
        status = "cancelled"
    elif (
        result.get("crashed") is True
        or result.get("termination_signal") not in (None, 0)
        or declared == "crashed"
    ):
        status = "crashed"
    elif (
        result.get("unsupported_format") not in (None, False, "")
        or declared in {"unsupported", "unsupported_format"}
        or "unsupported" in lowered
        or "not supported" in lowered
    ):
        status = "unsupported"
    elif (
        result.get("partial") is True
        or result.get("truncated") is True
        or declared in {"partial", "partial_result"}
        or (failure_signal and has_evidence)
    ):
        status = "partial"
    elif failure_signal:
        status = "failed"
    elif not result:
        status = "failed"
        message = message or "tool returned no structured result"
    else:
        status = "success"

    gap = None
    if status not in {"success", "not_run_redundant"}:
        default_messages = {
            "partial": "tool returned usable evidence with an incomplete result",
            "unsupported": "tool does not support the detected input",
            "timeout": "tool exceeded its deadline",
            "cancelled": "tool was cancelled before it completed",
            "crashed": "tool process terminated abnormally",
            "failed": "tool failed before producing a complete result",
            "skipped": "step was not run",
            "not_run_redundant": "step was deliberately not run because equivalent evidence already exists",
        }
        gap = {
            "kind": status,
            "message": message or default_messages[status],
            "retained_evidence": has_evidence,
        }
    return {
        "schema": RESULT_SCHEMA,
        "step_id": step_id,
        "tool": tool_name,
        "status": status,
        "continue_analysis": True,
        "gap": gap,
        "observed": {
            "rc": result.get("rc"),
            "timed_out": bool(result.get("timed_out", False)),
            "cancelled": bool(result.get("cancelled", False)),
            "crashed": bool(result.get("crashed", False)),
            "redundant": status == "not_run_redundant",
            "termination_signal": result.get("termination_signal"),
            "saved_to": _bounded_message(result.get("saved_to"), 500),
            "has_evidence": has_evidence,
        },
    }


def router_self_check() -> dict:
    """Exercise representative inert headers for doctor/CI admission checks."""
    fixtures = {
        "pe": b"MZ" + b"\0" * 58 + b"\x80\0\0\0" + b"\0" * 64 + b"PE\0\0" + b"\x64\x86" + b"\0" * 18 + b"\xf0\0" + b"\0" * 490,
        "elf": b"\x7fELF\x02\x01\x01" + b"\0" * 11 + b"\x3e\0" + b"\0" * 64,
        "apk": b"PK\x03\x04 AndroidManifest.xml classes.dex",
        "javascript": b"const fs = require('fs'); function inspect() { console.log('x'); }",
        "pcapng": b"\x0a\x0d\x0d\x0a" + b"\0" * 32,
        "pdf": b"%PDF-1.7\n1 0 obj\n<<>>",
        "wasm": b"\0asm\x01\0\0\0",
        "sqlite": b"SQLite format 3\0" + b"\0" * 100,
    }
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        observed = {}
        for expected, data in fixtures.items():
            target = root / expected
            target.write_bytes(data)
            detected = detect_format(target)
            observed[expected] = detected["format"]
        target = root / "native"
        target.write_bytes(fixtures["elf"])
        one = build_analysis_plan(target, display_path="original/sample")
        two = build_analysis_plan(target, display_path="original/sample")
    expected = {
        "pe": "pe",
        "elf": "elf",
        "apk": "apk",
        "javascript": "javascript",
        "pcapng": "pcapng",
        "pdf": "pdf",
        "wasm": "wasm",
        "sqlite": "sqlite",
    }
    if observed != expected or one != two:
        raise RuntimeError(f"router self-check failed: {observed}")
    return {
        "schema": PLAN_SCHEMA,
        "formats_checked": sorted(observed),
        "categories": list(FORMAT_CATEGORIES),
        "deterministic": True,
        "read_limits": {
            "head_bytes": HEAD_LIMIT,
            "tail_bytes": TAIL_LIMIT,
            "additional_pe_header_bytes": PE_HEADER_LIMIT,
        },
    }
