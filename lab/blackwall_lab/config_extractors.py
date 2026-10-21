"""Fail-closed registry for family-specific configuration extractors.

Extractors are ordinary package code, never modules or expressions loaded from
the analyzed artifact.  Each extractor must return bounded JSON-compatible
values plus the byte ranges that support its confidence grade.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
import struct
import zlib
from dataclasses import dataclass
from typing import Callable

MAX_CONFIG_BYTES = 1024 * 1024
MAX_CONFIG_FIELDS = 128
CONFIDENCE_TIERS = ("low", "medium", "high")
MAX_STRING_CANDIDATES = 4096
MAX_STRING_LENGTH = 4096


@dataclass(frozen=True)
class ConfigExtractor:
    family: str
    version: str
    description: str
    probe: Callable[[bytes], bool]
    extract: Callable[[bytes], dict]


_REGISTRY: dict[str, ConfigExtractor] = {}


def register(extractor: ConfigExtractor) -> None:
    """Register one statically imported extractor; duplicate families fail."""
    if not extractor.family or extractor.family in _REGISTRY:
        raise ValueError(f"duplicate or empty config extractor: {extractor.family!r}")
    _REGISTRY[extractor.family] = extractor


def inventory() -> list[dict]:
    return [
        {
            "family": item.family,
            "version": item.version,
            "description": item.description,
        }
        for item in sorted(_REGISTRY.values(), key=lambda row: row.family)
    ]


def extract_config(data: bytes, family: str = "auto") -> dict:
    if len(data) > MAX_CONFIG_BYTES:
        raise ValueError(f"configuration input exceeds {MAX_CONFIG_BYTES} bytes")
    if family == "auto":
        candidates = [item for item in _REGISTRY.values() if item.probe(data)]
    else:
        selected = _REGISTRY.get(family)
        if selected is None:
            raise ValueError(
                f"unknown configuration family {family!r}; choose auto or: "
                + ", ".join(sorted(_REGISTRY))
            )
        candidates = [selected] if selected.probe(data) else []

    matches = []
    errors = []
    for extractor in candidates:
        try:
            result = extractor.extract(data)
            confidence = result.get("confidence", {})
            if confidence.get("tier") not in CONFIDENCE_TIERS:
                raise ValueError("extractor returned an invalid confidence tier")
            values = result.get("values")
            if not isinstance(values, dict) or len(values) > MAX_CONFIG_FIELDS:
                raise ValueError("extractor returned an invalid or oversized value map")
            matches.append({
                "family": extractor.family,
                "plugin_version": extractor.version,
                **result,
            })
        except (KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
            errors.append({
                "family": extractor.family,
                "error": f"{type(exc).__name__}: {exc}",
            })
    return {
        "schema": "blackwall.configuration-recovery.v1",
        "requested_family": family,
        "matches": matches,
        "errors": errors,
        "available_extractors": inventory(),
    }


# Inert, versioned fixture family used to admission-test the plugin contract.
# Layout: magic, little-endian JSON size, UTF-8 object, CRC32(JSON).
_FIXTURE_MAGIC = b"BWCFG1\0"


def _fixture_probe(data: bytes) -> bool:
    return data.startswith(_FIXTURE_MAGIC)


def _fixture_extract(data: bytes) -> dict:
    header_size = len(_FIXTURE_MAGIC) + 4
    if len(data) < header_size + 4:
        raise ValueError("truncated fixture configuration")
    size = struct.unpack_from("<I", data, len(_FIXTURE_MAGIC))[0]
    if size > MAX_CONFIG_BYTES - header_size - 4:
        raise ValueError("declared fixture configuration is oversized")
    end = header_size + size
    if end + 4 != len(data):
        raise ValueError("fixture configuration length mismatch")
    payload = data[header_size:end]
    expected_crc = struct.unpack_from("<I", data, end)[0]
    actual_crc = zlib.crc32(payload) & 0xFFFFFFFF
    decoded = json.loads(payload.decode("utf-8"))
    if not isinstance(decoded, dict):
        raise ValueError("fixture configuration payload must be an object")
    values = {}
    for key, value in decoded.items():
        if not isinstance(key, str) or len(key) > 128:
            raise ValueError("fixture configuration contains an invalid key")
        if not isinstance(value, (str, int, float, bool)) and value is not None:
            raise ValueError("fixture configuration contains a non-scalar value")
        if isinstance(value, str) and len(value) > 4096:
            raise ValueError("fixture configuration value is oversized")
        values[key] = value
    checksum_valid = expected_crc == actual_crc
    known = {"endpoint", "campaign"} & set(values)
    tier = "high" if checksum_valid and len(known) == 2 else (
        "medium" if checksum_valid else "low"
    )
    score = {"high": 0.98, "medium": 0.75, "low": 0.35}[tier]
    return {
        "values": values,
        "confidence": {
            "tier": tier,
            "score": score,
            "reasons": [
                "family magic matched",
                "payload CRC32 matched" if checksum_valid else "payload CRC32 did not match",
                f"recognized {len(known)} of 2 expected semantic keys",
            ],
        },
        "validation": {
            "checksum": "valid" if checksum_valid else "invalid",
            "expected_crc32": f"{expected_crc:08x}",
            "actual_crc32": f"{actual_crc:08x}",
        },
        "locations": [
            {"kind": "magic", "offset": 0, "size": len(_FIXTURE_MAGIC)},
            {"kind": "payload", "offset": header_size, "size": size},
            {"kind": "checksum", "offset": end, "size": 4},
        ],
    }


register(ConfigExtractor(
    family="blackwall-inert-v1",
    version="1",
    description="Inert fixture family that admission-tests the extractor plugin ABI",
    probe=_fixture_probe,
    extract=_fixture_extract,
))


# Amadey v4/v5 stores Base64 text after a Vigenere-like substitution over this
# 63-character alphabet. The static extractor also recognizes one reviewed
# loader pattern and reverses its bounded ROR/XOR + RC4 payload layer.
_AMADEY_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
_AMADEY_INDEX = {char: index for index, char in enumerate(_AMADEY_ALPHABET)}
_AMADEY_KEY_RE = re.compile(r"[0-9a-f]{32}")
_AMADEY_ENCODED_RE = re.compile(r"[A-Za-z0-9 ]{4,}={0,2}")
_AMADEY_CAMPAIGN_RE = re.compile(r"[0-9a-f]{6}")
_AMADEY_PHP_RE = re.compile(r"/[A-Za-z0-9_./-]{1,240}\.php")
_AMADEY_VERSION_RE = re.compile(r"\d+\.\d{2}")
_AMADEY_INSTALL_ID_RE = re.compile(r"[0-9a-f]{10}")
_AMADEY_EXE_RE = re.compile(r"[A-Za-z0-9_]{2,100}\.exe", re.IGNORECASE)
_AMADEY_DLL_RE = re.compile(r"[A-Za-z0-9_]{2,100}\.dll", re.IGNORECASE)
_AMADEY_XOR_BASE_RE = re.compile(rb"\xb0(.)\xd2\xe3", re.DOTALL)
_AMADEY_MUL15_RE = re.compile(rb"\xc0\xe1\x04\x0a\xdf\x2a\xca")
_AMADEY_KSA_KEY_RE = re.compile(rb"\x0f\xb6\x89(....)", re.DOTALL)


def _ascii_cstrings(data: bytes) -> list[tuple[int, str]]:
    rows = []
    for match in re.finditer(rb"[\x20-\x7e]{2,}\x00", data):
        value = match.group()[:-1]
        if len(value) > MAX_STRING_LENGTH:
            continue
        rows.append((match.start(), value.decode("ascii")))
        if len(rows) >= MAX_STRING_CANDIDATES:
            break
    return rows


def _amadey_decode(value: str, key: str) -> bytes:
    transformed = []
    for index, char in enumerate(value):
        alphabet_index = _AMADEY_INDEX.get(char)
        if alphabet_index is None:
            transformed.append(char)
            continue
        key_index = _AMADEY_INDEX.get(key[index % len(key)])
        if key_index is None:
            raise ValueError("Amadey string key contains an unsupported character")
        transformed.append(
            _AMADEY_ALPHABET[(alphabet_index - key_index) % len(_AMADEY_ALPHABET)]
        )
    encoded = "".join(transformed).rstrip("=")
    encoded += "=" * ((-len(encoded)) % 4)
    decoded = base64.b64decode(encoded, validate=True)
    if not decoded or len(decoded) > MAX_STRING_LENGTH:
        raise ValueError("decoded Amadey string is empty or oversized")
    if not all(byte in (9, 10, 13) or 32 <= byte < 127 for byte in decoded):
        raise ValueError("decoded Amadey string is not printable ASCII")
    return decoded


def _valid_host(value: str) -> bool:
    host, separator, port = value.rpartition(":")
    if not separator:
        host = value
    elif not port.isdigit() or not 1 <= int(port) <= 65535:
        return False
    try:
        address = ipaddress.ip_address(host)
        return address.version == 4
    except ValueError:
        pass
    if not 4 <= len(host) <= 253 or host.lower() != host:
        return False
    labels = host.rstrip(".").split(".")
    if (
        len(labels) < 2
        or not re.fullmatch(r"[a-z]{2,63}", labels[-1])
        or labels[-1] in {"dll", "exe", "php"}
    ):
        return False
    return all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in labels
    )


def _rc4(key: bytes, data: bytes) -> bytes:
    if not key:
        raise ValueError("empty RC4 key")
    state = list(range(256))
    position = 0
    for index in range(256):
        position = (position + state[index] + key[index % len(key)]) & 0xFF
        state[index], state[position] = state[position], state[index]
    output = bytearray(data)
    first = second = 0
    for index in range(len(output)):
        first = (first + 1) & 0xFF
        second = (second + state[first]) & 0xFF
        state[first], state[second] = state[second], state[first]
        output[index] ^= state[(state[first] + state[second]) & 0xFF]
    return bytes(output)


def _amadey_direct(data: bytes) -> dict | None:
    strings = _ascii_cstrings(data)
    keys = [(offset, value) for offset, value in strings if _AMADEY_KEY_RE.fullmatch(value)]
    encoded = [
        (offset, value) for offset, value in strings
        if _AMADEY_ENCODED_RE.fullmatch(value)
    ]
    if len(keys) < 2 or len(encoded) < 6:
        return None

    best: tuple[int, int, str, list[tuple[int, str]]] | None = None
    for _key_offset, key in keys[:32]:
        decoded = []
        for offset, value in encoded:
            try:
                text = _amadey_decode(value, key).decode("ascii")
            except (UnicodeError, ValueError):
                continue
            decoded.append((offset, text))
        values = {value for _, value in decoded}
        semantic_score = sum((
            any(_valid_host(value) for value in values),
            any(_AMADEY_PHP_RE.fullmatch(value) for value in values),
            any(_AMADEY_VERSION_RE.fullmatch(value) for value in values),
            any(_AMADEY_EXE_RE.fullmatch(value) for value in values),
            any(value.lower() in {"cred.dll", "clip.dll"} for value in values),
            any(value in {"id:", "vs:", "sd:", "<c>", "<d>"} for value in values),
        ))
        candidate = (semantic_score, len(decoded), key, decoded)
        if best is None or candidate[:2] > best[:2]:
            best = candidate
    if best is None or best[0] < 5 or best[1] < 8:
        return None

    semantic_score, decoded_count, string_key, decoded_rows = best
    decoded_values = list(dict.fromkeys(value for _, value in decoded_rows))
    hosts = [value for value in decoded_values if _valid_host(value)][:16]
    paths = [value for value in decoded_values if _AMADEY_PHP_RE.fullmatch(value)][:16]
    versions = [value for value in decoded_values if _AMADEY_VERSION_RE.fullmatch(value)]
    executables = [value for value in decoded_values if _AMADEY_EXE_RE.fullmatch(value)]
    ignored_executables = {"rundll32.exe", "powershell.exe", "vnc.exe", "msiexec.exe"}
    install_name = next(
        (value for value in executables if value.lower() not in ignored_executables), None,
    )
    plugins = sorted({
        value for value in decoded_values
        if _AMADEY_DLL_RE.fullmatch(value)
        and value.lower() not in {"shell32.dll", "kernel32.dll"}
    })[:32]
    campaign_rows = [
        (offset, value) for offset, value in strings
        if _AMADEY_CAMPAIGN_RE.fullmatch(value)
    ]
    install_ids = [
        value for value in decoded_values if _AMADEY_INSTALL_ID_RE.fullmatch(value)
    ]
    other_keys = [value for _, value in keys if value != string_key]
    key_offset = next(offset for offset, value in keys if value == string_key)
    decoded_locations = [
        {"kind": "encoded-string", "offset": offset, "size": len(source) + 1}
        for offset, source in encoded
        if any(decoded_offset == offset for decoded_offset, _ in decoded_rows)
    ][:48]
    tier = "high" if semantic_score == 6 and hosts and paths and versions else "medium"
    score = 0.98 if tier == "high" else 0.82
    values = {
        "family": "Amadey",
        "version": versions[0] if versions else None,
        "campaign": campaign_rows[0][1] if campaign_rows else None,
        "c2_hosts": hosts,
        "c2_paths": paths,
        "c2_urls": [f"http://{host}{path}" for host in hosts for path in paths][:32],
        "string_key": string_key,
        "rc4_key_and_mutex_candidate": other_keys[0] if other_keys else None,
        "other_hex_keys": other_keys[1:16],
        "install_directory_id": install_ids[0] if install_ids else None,
        "install_name": install_name,
        "plugins": plugins,
        "decoded_string_count": decoded_count,
    }
    return {
        "values": values,
        "confidence": {
            "tier": tier,
            "score": score,
            "reasons": [
                "Amadey v4/v5 substitution and Base64 string scheme validated",
                f"{decoded_count} bounded printable strings decoded",
                f"{semantic_score} of 6 family semantic anchor groups matched",
                "C2 host/path and version were recovered" if hosts and paths and versions
                else "one or more primary configuration fields were absent",
            ],
        },
        "validation": {
            "decoder": "amadey-v4-v5-vigenere-base64",
            "semantic_anchor_groups": semantic_score,
            "decoded_strings": decoded_count,
            "derived_from_loader": False,
        },
        "locations": [
            {"kind": "string-key", "offset": key_offset, "size": 33},
            *(
                [{"kind": "campaign", "offset": campaign_rows[0][0], "size": 7}]
                if campaign_rows else []
            ),
            *decoded_locations,
        ],
    }


def _amadey_loader(data: bytes) -> dict | None:
    if not data.startswith(b"MZ") or not (
        _AMADEY_MUL15_RE.search(data) and _AMADEY_KSA_KEY_RE.search(data)
    ):
        return None
    try:
        import pefile
    except ImportError:
        return None
    try:
        pe = pefile.PE(data=data, fast_load=False)
        image = pe.get_memory_mapped_image(max_virtual_address=MAX_CONFIG_BYTES)
        image_base = int(pe.OPTIONAL_HEADER.ImageBase)
        executable = next(
            section for section in pe.sections
            if section.Characteristics & 0x20000000
        )
        code = image[
            executable.VirtualAddress:
            executable.VirtualAddress + executable.Misc_VirtualSize
        ]
        multiplier = _AMADEY_MUL15_RE.search(code)
        if multiplier is None:
            return None
        xor_base = None
        xor_match = None
        for candidate in _AMADEY_XOR_BASE_RE.finditer(
            code, max(0, multiplier.start() - 0x40), multiplier.start(),
        ):
            xor_match = candidate
            xor_base = candidate.group(1)[0]
        key_match = _AMADEY_KSA_KEY_RE.search(
            code, multiplier.end(), multiplier.end() + 0x200,
        )
        if xor_base is None or xor_match is None or key_match is None:
            return None
        key_va = int.from_bytes(key_match.group(1), "little")
        key_rva = key_va - image_base
        if key_rva < 0 or key_rva + 16 > len(image):
            return None
        key = image[key_rva:key_rva + 16]
        candidates = [
            section for section in pe.sections
            if not (section.Characteristics & 0x20000000)
            and 0x10000 < section.SizeOfRawData <= MAX_CONFIG_BYTES
        ]
        if not candidates:
            return None
        section = max(candidates, key=lambda row: (row.get_entropy() > 7.9, row.SizeOfRawData))
        encrypted = bytearray(section.get_data()[:section.Misc_VirtualSize])
        if not encrypted or len(encrypted) > MAX_CONFIG_BYTES:
            return None
        for index, byte in enumerate(encrypted):
            rotation = (index % 7) + 1
            encrypted[index] = (
                ((byte >> rotation) | (byte << (8 - rotation))) & 0xFF
            ) ^ ((xor_base - 15 * index) & 0xFF)
        payload = _rc4(key, bytes(encrypted))
        direct = _amadey_direct(payload)
        if direct is None or not payload.startswith(b"MZ"):
            return None
        key_offset = pe.get_offset_from_rva(key_rva)
    except (OSError, StopIteration, ValueError, pefile.PEFormatError):
        return None

    direct["values"].update({
        "loader_payload_sha256": hashlib.sha256(payload).hexdigest(),
        "loader_section": section.Name.rstrip(b"\0").decode("ascii", errors="replace"),
        "loader_rc4_key": key.hex(),
        "loader_stage1_xor_base": f"0x{xor_base:02x}",
        "payload_is_pe2shc": payload[2:4] == b"ER",
    })
    direct["confidence"]["reasons"].append(
        "reviewed loader instruction patterns produced a PE payload with Amadey configuration"
    )
    direct["validation"].update({
        "derived_from_loader": True,
        "loader_payload_sha256": hashlib.sha256(payload).hexdigest(),
        "loader_section": direct["values"]["loader_section"],
    })
    direct["locations"] = [
        {"kind": "loader-rc4-key", "offset": key_offset, "size": 16},
        {
            "kind": "encrypted-payload-section",
            "offset": int(section.PointerToRawData),
            "size": int(section.SizeOfRawData),
        },
    ]
    return direct


def _amadey_probe(data: bytes) -> bool:
    direct_shape = (
        len(re.findall(rb"[0-9a-f]{32}\x00", data[:MAX_CONFIG_BYTES])) >= 2
        and len(re.findall(rb"[A-Za-z0-9 ]{4,}={0,2}\x00", data[:MAX_CONFIG_BYTES])) >= 6
    )
    loader_shape = (
        data.startswith(b"MZ")
        and _AMADEY_MUL15_RE.search(data) is not None
        and _AMADEY_KSA_KEY_RE.search(data) is not None
    )
    return direct_shape or loader_shape


def _amadey_extract(data: bytes) -> dict:
    result = _amadey_direct(data) or _amadey_loader(data)
    if result is None:
        raise ValueError("Amadey structural and semantic validation failed")
    return result


register(ConfigExtractor(
    family="amadey-v4-v5",
    version="1",
    description=(
        "Static Amadey v4/v5 string/config decoder with a bounded reviewed "
        "ROR/XOR+RC4 loader path"
    ),
    probe=_amadey_probe,
    extract=_amadey_extract,
))
