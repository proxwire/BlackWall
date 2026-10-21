#!/usr/bin/env python3
"""Build BlackWall's deterministic, non-executing benchmark fixtures.

This script never downloads inputs.  It only invokes local compilers/packers
with fixed arguments and writes fixtures whose source is committed beside it.
Compiler and packer versions are recorded in the generated manifest because
binary hashes can legitimately change when those toolchains change.
"""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import tempfile
import zipfile
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "fixtures-src"
FIXTURES = ROOT / "fixtures"
MANIFEST = ROOT / "corpus" / "inert-manifest.json"


def run(
    command: list[str],
    *,
    cwd: Path | None = None,
    environment: dict[str, str] | None = None,
) -> str:
    env = os.environ.copy()
    env.update({"LC_ALL": "C", "SOURCE_DATE_EPOCH": "946684800"})
    env.update(environment or {})
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return completed.stdout.strip()


def require(command: str) -> str:
    resolved = shutil.which(command)
    if resolved is None:
        raise SystemExit(f"required fixture builder not found: {command}")
    return resolved


def zip_member(archive: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(name, date_time=(2000, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED
    info.external_attr = 0o100644 << 16
    info.create_system = 3
    archive.writestr(info, data)


def unsigned_leb(value: int) -> bytes:
    encoded = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        encoded.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(encoded)


def wasm_fixture() -> bytes:
    marker = (
        b"BLACKWALL_INERT_WASM_FIXTURE\0"
        b"https://wasm.fixture.invalid/api\0campaign=wasm-inert\0"
    )

    def section(identifier: int, payload: bytes) -> bytes:
        return bytes([identifier]) + unsigned_leb(len(payload)) + payload

    type_section = section(1, b"\x01\x60\x00\x01\x7f")
    function_section = section(3, b"\x01\x00")
    memory_section = section(5, b"\x01\x00\x01")
    export_name = b"fixture_score"
    memory_name = b"memory"
    exports = (
        b"\x02"
        + unsigned_leb(len(export_name)) + export_name + b"\x00\x00"
        + unsigned_leb(len(memory_name)) + memory_name + b"\x02\x00"
    )
    export_section = section(7, exports)
    body = b"\x00\x41\x2a\x0b"  # no locals; i32.const 42; end
    code_section = section(10, b"\x01" + unsigned_leb(len(body)) + body)
    data = b"\x01\x00\x41\x00\x0b" + unsigned_leb(len(marker)) + marker
    data_section = section(11, data)
    return b"\x00asm\x01\x00\x00\x00" + type_section + function_section + memory_section + export_section + code_section + data_section


def pdf_fixture() -> bytes:
    visible = (
        "BLACKWALL_INERT_PDF_FIXTURE "
        "https://pdf.fixture.invalid/api campaign=pdf-inert"
    )
    stream = f"BT /F1 12 Tf 72 720 Td ({visible}) Tj ET\n".encode("ascii")
    javascript = (
        b'var endpoint = "https://pdf-script.fixture.invalid/api"; '
        b'var command = "cmd.exe /c echo BLACKWALL_INERT_PDF_COMMAND";'
    )
    embedded = (
        b"BLACKWALL_INERT_PDF_EMBEDDED_PAYLOAD\n"
        b"https://pdf-embedded.fixture.invalid/api\n"
    )
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R "
        b"/Names << /EmbeddedFiles << /Names [(inert.txt) 7 0 R] >> >> >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"endstream",
        b"<< /Type /Action /S /JavaScript /JS 9 0 R >>",
        b"<< /Type /Filespec /F (inert.txt) /EF << /F 8 0 R >> >>",
        b"<< /Type /EmbeddedFile /Length " + str(len(embedded)).encode("ascii")
        + b" >>\nstream\n" + embedded + b"endstream",
        b"<< /S /JavaScript /Length " + str(len(javascript)).encode("ascii")
        + b" >>\nstream\n" + javascript + b"\nendstream",
    ]
    output = bytearray(b"%PDF-1.4\n% BlackWall inert benchmark fixture\n")
    offsets = [0]
    for number, value in enumerate(objects, 1):
        offsets.append(len(output))
        output.extend(f"{number} 0 obj\n".encode("ascii"))
        output.extend(value + b"\nendobj\n")
    xref = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("ascii")
    )
    return bytes(output)


def internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    words = struct.unpack(f"!{len(data) // 2}H", data)
    total = sum(words)
    total = (total & 0xFFFF) + (total >> 16)
    total += total >> 16
    return (~total) & 0xFFFF


def pcap_fixture() -> bytes:
    payload = (
        b"BLACKWALL_INERT_PCAP_FIXTURE "
        b"https://pcap.fixture.invalid/api campaign=pcap-inert"
    )
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    source = bytes((192, 0, 2, 10))
    destination = bytes((198, 51, 100, 20))
    udp = struct.pack("!HHHH", 44444, 5300, 8 + len(payload), 0)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 20 + len(udp) + len(payload), 0x4242, 0, 64, 17, 0,
        source, destination,
    )
    header = header[:10] + struct.pack("!H", internet_checksum(header)) + header[12:]
    packet = ethernet + header + udp + payload
    global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    record = struct.pack("<IIII", 946684800, 0, len(packet), len(packet)) + packet
    return global_header + record


def config_fixture(endpoint: str, campaign: str) -> bytes:
    payload = json.dumps({
        "endpoint": endpoint, "campaign": campaign,
    }, sort_keys=True, separators=(",", ":")).encode()
    return (
        b"BWCFG1\0" + struct.pack("<I", len(payload)) + payload
        + struct.pack("<I", zlib.crc32(payload) & 0xFFFFFFFF)
    )


def attributed_mixed_cab_fixture() -> bytes:
    encoded = b"".join(
        (SOURCE / "cabextract-mixed.cab.b64").read_bytes().split()
    )
    cabinet = base64.b64decode(encoded, validate=True)
    expected = "0ce0b55fe705b744d41bb361170c0467db30da0c7f9bdd386d5dade71a78e171"
    if hashlib.sha256(cabinet).hexdigest() != expected:
        raise ValueError("attributed mixed CAB source digest mismatch")
    return cabinet


def amadey_config_fixture() -> bytes:
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
    key = "0123456789abcdef0123456789abcdef"

    def encode(value: str) -> bytes:
        source = base64.b64encode(value.encode("ascii")).decode("ascii")
        transformed = "".join(
            alphabet[(alphabet.index(char) + alphabet.index(key[index % len(key)])) % len(alphabet)]
            if char in alphabet else char
            for index, char in enumerate(source)
        )
        return transformed.encode("ascii") + b"\0"

    values = (
        "c2.amadey.fixture.invalid", "/fixture/index.php", "5.99",
        "0123abc456", "FixtureBot.exe", "cred.dll", "clip.dll", "id:", "vs:", "sd:",
        "<c>", "<d>", "Plugins", "180000", "fixture-value",
    )
    return (
        b"BLACKWALL_INERT_AMADEY_CONFIG\0"
        + key.encode("ascii") + b"\0"
        + b"fedcba9876543210fedcba9876543210\0"
        + b"a1b2c3\0"
        + b"".join(encode(value) for value in values)
    )


def cpio_fixture(name: str, payload: bytes) -> bytes:
    def entry(filename: str, content: bytes, mode: int) -> bytes:
        encoded = filename.encode() + b"\0"
        fields = (
            1, mode, 0, 0, 1, 946684800, len(content),
            0, 0, 0, 0, len(encoded), 0,
        )
        row = b"070701" + b"".join(f"{value:08x}".encode() for value in fields)
        row += encoded + b"\0" * ((-(len(row) + len(encoded))) % 4)
        row += content + b"\0" * ((-len(content)) % 4)
        return row
    return (
        entry(name, payload, stat.S_IFREG | 0o644)
        + entry("TRAILER!!!", b"", 0)
    )


def uimage_fixture(payload: bytes) -> bytes:
    compressed = gzip.compress(payload, mtime=0)
    header = bytearray(struct.pack(
        ">7I4B32s", 0x27051956, 0, 946684800, len(compressed),
        0x8000, 0x8000, zlib.crc32(compressed) & 0xFFFFFFFF,
        5, 2, 2, 1, b"BlackWall inert firmware".ljust(32, b"\0"),
    ))
    struct.pack_into(">I", header, 4, zlib.crc32(header) & 0xFFFFFFFF)
    return bytes(header) + compressed


def cab_fixture(name: str, payload: bytes) -> bytes:
    encoded = name.encode() + b"\0"
    files_offset = 36 + 8
    data_offset = files_offset + 16 + len(encoded)
    cabinet_size = data_offset + 8 + len(payload)
    return (
        struct.pack(
            "<4sIIIII BB HHHHH", b"MSCF", 0, cabinet_size, 0,
            files_offset, 0, 3, 1, 1, 1, 0, 0, 0,
        )
        + struct.pack("<IHH", data_offset, 1, 0)
        + struct.pack("<IIHHHH", len(payload), 0, 0, 0, 0, 0) + encoded
        + struct.pack("<IHH", 0, len(payload), len(payload)) + payload
    )


def elf_core_fixture() -> bytes:
    owner = b"CORE\0" + b"\0" * 3
    status = bytearray(336)
    struct.pack_into("<H", status, 12, 11)
    struct.pack_into("<i", status, 32, 4242)
    # pwntools' x86-64 register window begins at descriptor offset 112.
    struct.pack_into("<Q", status, 112 + 16 * 8, 0x401000)
    note = struct.pack("<III", 5, len(status), 1) + owner + status
    marker = (
        b"BLACKWALL_INERT_ELF_CORE_FIXTURE\0"
        b"https://core.fixture.invalid/api\0campaign=core-inert\0"
    )
    note_offset = 64 + 2 * 56
    marker_offset = note_offset + len(note)
    ident = b"\x7fELF\x02\x01\x01\x00" + b"\0" * 8
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH", 4, 62, 1, 0, 64, 0, 0,
        64, 56, 2, 64, 0, 0,
    )
    note_header = struct.pack(
        "<IIQQQQQQ", 4, 0, note_offset, 0, 0, len(note), len(note), 4,
    )
    load_header = struct.pack(
        "<IIQQQQQQ", 1, 4, marker_offset, 0x400000, 0,
        len(marker), len(marker), 0x1000,
    )
    return header + note_header + load_header + note + marker


def macho_fixture() -> bytes:
    objc = (
        b"fixtureSelector:\0FixtureClass\0"
        b"BLACKWALL_INERT_MACHO_FIXTURE\0"
        b"https://macho.fixture.invalid/api\0campaign=macho-inert\0"
    )
    swift = b"\x01\x02\x03\x04"
    dylib_name = b"/usr/lib/libobjc.A.dylib\0"
    dylib_size = (24 + len(dylib_name) + 7) & ~7
    segment_size = 72 + 2 * 80
    command_bytes = segment_size + 24 + dylib_size + 16
    data_offset = 32 + command_bytes
    objc_offset = data_offset
    swift_offset = objc_offset + len(objc)
    symoff = swift_offset + len(swift)
    strings = b"\0_puts\0_$sFixtureSymbol\0"
    symbols = (
        struct.pack("<IBBHQ", 1, 0x01, 0, 0, 0)
        + struct.pack("<IBBHQ", 7, 0x0F, 2, 0, 0x1000)
    )
    stroff = symoff + len(symbols)
    identifier = b"invalid.fixture.blackwall\0"
    directory_size = 40 + len(identifier)
    directory = struct.pack(
        ">9I4B", 0xFADE0C02, directory_size, 0x20400, 0,
        directory_size, 40, 0, 0, data_offset, 32, 2, 0, 12,
    ) + identifier
    signature = (
        struct.pack(">III", 0xFADE0CC0, 20 + len(directory), 1)
        + struct.pack(">II", 0, 20) + directory
    )
    signature_offset = stroff + len(strings)
    header = struct.pack(
        "<IIIIIIII", 0xFEEDFACF, 0x01000007, 3, 1, 4,
        command_bytes, 0, 0,
    )
    segment = struct.pack(
        "<II16sQQQQiiII", 0x19, segment_size,
        b"__TEXT".ljust(16, b"\0"), 0x1000, len(objc) + len(swift),
        data_offset, len(objc) + len(swift), 7, 5, 2, 0,
    )
    segment += struct.pack(
        "<16s16sQQIIIIIIII", b"__objc_methname".ljust(16, b"\0"),
        b"__TEXT".ljust(16, b"\0"), 0x1000, len(objc), objc_offset,
        0, 0, 0, 2, 0, 0, 0,
    )
    segment += struct.pack(
        "<16s16sQQIIIIIIII", b"__swift5_types".ljust(16, b"\0"),
        b"__TEXT".ljust(16, b"\0"), 0x1000 + len(objc), len(swift),
        swift_offset, 0, 0, 0, 0, 0, 0, 0,
    )
    symtab = struct.pack("<IIIIII", 2, 24, symoff, 2, stroff, len(strings))
    dylib = struct.pack("<IIIIII", 0xC, dylib_size, 24, 0, 0, 0)
    dylib += dylib_name + b"\0" * (dylib_size - 24 - len(dylib_name))
    signature_command = struct.pack(
        "<IIII", 0x1D, 16, signature_offset, len(signature),
    )
    return (
        header + segment + symtab + dylib + signature_command
        + objc + swift + symbols + strings + signature
    )


def patch_dotnet_corflags(path: Path, *, clear: int = 0, set_bits: int = 0) -> None:
    """Patch only IMAGE_COR20_HEADER.Flags in an inert managed PE fixture."""
    data = bytearray(path.read_bytes())
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    optional = pe_offset + 24
    magic = struct.unpack_from("<H", data, optional)[0]
    directory = optional + (112 if magic == 0x20B else 96)
    clr_rva, clr_size = struct.unpack_from("<II", data, directory + 14 * 8)
    if not clr_rva or clr_size < 0x48:
        raise ValueError("fixture has no valid CLR header")
    sections = optional + optional_size
    clr_offset = None
    for index in range(section_count):
        header = sections + index * 40
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
            "<IIII", data, header + 8,
        )
        if virtual_address <= clr_rva < virtual_address + max(virtual_size, raw_size):
            clr_offset = raw_offset + (clr_rva - virtual_address)
            break
    if clr_offset is None or clr_offset + 20 > len(data):
        raise ValueError("CLR header is outside fixture sections")
    flags = struct.unpack_from("<I", data, clr_offset + 16)[0]
    struct.pack_into("<I", data, clr_offset + 16, (flags & ~clear) | set_bits)
    path.write_bytes(data)


def tool_version(command: list[str]) -> str:
    try:
        return run(command).splitlines()[0][:200]
    except (OSError, subprocess.CalledProcessError, IndexError):
        return "unknown"


def fixture_entry(
    fixture_id: str,
    filename: str,
    router_format: str,
    raw_workflow: str,
    marker: str,
    url: str,
    config: str,
    labels: list[str],
    *,
    packing_state: str | None = None,
) -> dict:
    path = FIXTURES / filename
    expected = {
        "router_format": router_format,
        "useful_evidence": [{"id": "fixture-marker", "terms": [marker]}],
        "iocs": [url] if url else [],
        "configuration": [config] if config else [],
        "report_claims": [
            row for row in (
                {"id": "fixture-identity", "terms": [marker]} if marker else None,
                {"id": "endpoint", "terms": [url]} if url else None,
                {"id": "configuration", "terms": [config]} if config else None,
            ) if row is not None
        ],
    }
    if packing_state:
        expected["packing_state"] = packing_state
    return {
        "id": fixture_id,
        "path": f"../fixtures/{filename}",
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "size": path.stat().st_size,
        "format": router_format,
        "labels": labels,
        "raw_rea": {"workflow": raw_workflow},
        "expected": expected,
    }


def build() -> None:
    mingw = require("x86_64-w64-mingw32-gcc")
    windres = require("x86_64-w64-mingw32-windres")
    gcc = require("gcc")
    dotnet = require("dotnet")
    upx = require("upx")
    smali = require("smali")
    FIXTURES.mkdir(parents=True, exist_ok=True)
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    for name in (
        "native-pe.pe", "packed-pe.pe", "dotnet.pe", "dotnet-mixed.pe",
        "dotnet-obfuscated.pe", "dotnet-resource.pe", "native-elf.elf",
        "fixture.apk", "javascript.js", "powershell.ps1", "vbscript.vbs",
        "vba.bas", "module.wasm", "office.docx", "office-macro.xlsm",
        "document.rtf", "document.pdf", "capture.pcap", "native-macho.macho",
        "recorded-core.elf", "nested-firmware.zip", "installer.cab",
        "installer-lzx.cab", "iexpress-cab.pe", "family-config.bin",
        "amadey-config.pe",
    ):
        (FIXTURES / name).unlink(missing_ok=True)

    with tempfile.TemporaryDirectory(prefix="blackwall-corpus-") as temporary:
        temp = Path(temporary)
        unpacked_pe = temp / "native-pe.pe"
        run([
            mingw, "-Os", "-s", "-fno-ident", "-Wl,--no-insert-timestamp",
            str(SOURCE / "native.c"), "-o", str(unpacked_pe),
        ])
        shutil.copyfile(unpacked_pe, FIXTURES / "native-pe.pe")
        (FIXTURES / "amadey-config.pe").write_bytes(
            unpacked_pe.read_bytes() + amadey_config_fixture()
        )
        mixed_cab = attributed_mixed_cab_fixture()
        embedded_cab = temp / "embedded-mixed.cab"
        embedded_cab.write_bytes(mixed_cab)
        resource_script = temp / "iexpress-fixture.rc"
        resource_script.write_text(
            f'CABINET RCDATA "{embedded_cab.as_posix()}"\n', encoding="utf-8",
        )
        resource_object = temp / "iexpress-fixture.o"
        run([windres, str(resource_script), "-O", "coff", "-o", str(resource_object)])
        run([
            mingw, "-Os", "-s", "-fno-ident", "-Wl,--no-insert-timestamp",
            str(SOURCE / "native.c"), str(resource_object),
            "-o", str(FIXTURES / "iexpress-cab.pe"),
        ])
        (FIXTURES / "iexpress-cab.pe").chmod(0o644)
        run([upx, "--best", "--no-progress", "-o", str(FIXTURES / "packed-pe.pe"), str(unpacked_pe)])

        run([
            gcc, "-Os", "-s", "-fno-ident", "-Wl,--build-id=none",
            str(SOURCE / "native.c"), "-o", str(FIXTURES / "native-elf.elf"),
        ])

        dotnet_home = temp / "dotnet-home"
        sdk_listing = run([dotnet, "--list-sdks"])
        sdk_match = re.search(r"^(\S+) \[([^]]+)]$", sdk_listing.splitlines()[-1])
        if sdk_match is None:
            raise SystemExit("could not locate the installed .NET SDK")
        sdk_version, sdk_root = sdk_match.groups()
        compiler = Path(sdk_root) / sdk_version / "Roslyn" / "bincore" / "csc.dll"
        dotnet_root = Path(dotnet).resolve().parent
        reference_roots = sorted(
            (dotnet_root / "packs" / "Microsoft.NETCore.App.Ref").glob("*/ref/net6.0")
        )
        if not compiler.is_file() or not reference_roots:
            raise SystemExit("the local .NET 6 compiler/reference pack is incomplete")
        references = reference_roots[-1]
        compiler_environment = {
            "DOTNET_CLI_HOME": str(dotnet_home),
            "DOTNET_NOLOGO": "1",
            "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1",
            "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
        }

        def compile_dotnet(source: Path, output: Path, *extra: str) -> None:
            run([
                dotnet, str(compiler), "-nologo", "-noconfig", "-nostdlib+",
                "-target:exe", f"-out:{output}", "-deterministic+",
                "-debug-", "-optimize+", str(source),
                f"-r:{references / 'mscorlib.dll'}",
                f"-r:{references / 'System.Runtime.dll'}",
                f"-r:{references / 'System.Console.dll'}",
                *extra,
            ], environment=compiler_environment)

        dotnet_output = temp / "BlackWallFixture.dll"
        compile_dotnet(SOURCE / "dotnet" / "Program.cs", dotnet_output)
        shutil.copyfile(dotnet_output, FIXTURES / "dotnet.pe")
        shutil.copyfile(dotnet_output, FIXTURES / "dotnet-mixed.pe")
        patch_dotnet_corflags(FIXTURES / "dotnet-mixed.pe", clear=0x1)

        compile_dotnet(
            SOURCE / "dotnet" / "Obfuscated.cs",
            FIXTURES / "dotnet-obfuscated.pe",
        )
        compile_dotnet(
            SOURCE / "dotnet" / "Program.cs",
            FIXTURES / "dotnet-resource.pe",
            f"-resource:{SOURCE / 'dotnet' / 'embedded.txt'},BlackWallFixture.Payload.txt",
        )

        dex = temp / "classes.dex"
        run([smali, "assemble", str(SOURCE / "android"), "-o", str(dex)])
        with zipfile.ZipFile(FIXTURES / "fixture.apk", "w") as archive:
            zip_member(archive, "AndroidManifest.xml", (SOURCE / "android" / "AndroidManifest.xml").read_bytes())
            zip_member(archive, "classes.dex", dex.read_bytes())
            zip_member(archive, "res/values/strings.xml", b"""<?xml version="1.0" encoding="utf-8"?>
<resources><string name="fixture_endpoint">https://apk.fixture.invalid/api</string><string name="fixture_campaign">campaign=apk-inert</string></resources>""")
            zip_member(archive, "assets/fixture-config.txt", b"BLACKWALL_INERT_APK_RESOURCE\ncampaign=apk-inert\n")

    shutil.copyfile(SOURCE / "javascript.js", FIXTURES / "javascript.js")
    shutil.copyfile(SOURCE / "powershell.ps1", FIXTURES / "powershell.ps1")
    shutil.copyfile(SOURCE / "vbscript.vbs", FIXTURES / "vbscript.vbs")
    shutil.copyfile(SOURCE / "vba.bas", FIXTURES / "vba.bas")
    (FIXTURES / "module.wasm").write_bytes(wasm_fixture())

    with zipfile.ZipFile(FIXTURES / "office.docx", "w") as archive:
        zip_member(archive, "[Content_Types].xml", b"""<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
 <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
 <Default Extension="xml" ContentType="application/xml"/>
 <Default Extension="bin" ContentType="application/octet-stream"/>
 <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>""")
        zip_member(archive, "_rels/.rels", b"""<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
 <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
 <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="https://relationships.fixture.invalid/template" TargetMode="External"/>
</Relationships>""")
        zip_member(archive, "word/document.xml", b"""<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>BLACKWALL_INERT_OFFICE_FIXTURE https://office.fixture.invalid/api campaign=office-inert</w:t></w:r></w:p></w:body></w:document>""")
        zip_member(
            archive,
            "word/embeddings/payload.bin",
            b"BLACKWALL_INERT_OFFICE_EMBEDDED_PAYLOAD "
            b"https://office-embedded.fixture.invalid/api",
        )

    vba_project = base64.b64decode(
        b"".join((SOURCE / "vbaProject.bin.b64").read_bytes().split()), validate=True,
    )
    expected_vba_project = "0ced1464b3677e98f5e3a8c5d80135e18dc98dca39299f1a8cfd2a00999fbf9f"
    if hashlib.sha256(vba_project).hexdigest() != expected_vba_project:
        raise ValueError("vbaProject.bin source digest mismatch")
    with zipfile.ZipFile(FIXTURES / "office-macro.xlsm", "w") as archive:
        zip_member(archive, "[Content_Types].xml", b"""<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
 <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
 <Default Extension="xml" ContentType="application/xml"/>
 <Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>
 <Override PartName="/xl/workbook.xml" ContentType="application/vnd.ms-excel.sheet.macroEnabled.main+xml"/>
 <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>""")
        zip_member(archive, "_rels/.rels", b"""<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
 <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>""")
        zip_member(archive, "xl/workbook.xml", b"""<?xml version="1.0" encoding="UTF-8"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Fixture" sheetId="1" r:id="rId1"/></sheets></workbook>""")
        zip_member(archive, "xl/_rels/workbook.xml.rels", b"""<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
 <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
 <Relationship Id="rId2" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="vbaProject.bin"/>
</Relationships>""")
        zip_member(archive, "xl/worksheets/sheet1.xml", b"""<?xml version="1.0" encoding="UTF-8"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>BLACKWALL_INERT_MACRO_OFFICE_FIXTURE https://macro-office.fixture.invalid/api campaign=macro-office-inert</t></is></c></row></sheetData></worksheet>""")
        zip_member(archive, "xl/vbaProject.bin", vba_project)

    rtf_payload = (
        b"BLACKWALL_INERT_RTF_EMBEDDED_PAYLOAD "
        b"https://rtf-embedded.fixture.invalid/api"
    )
    (FIXTURES / "document.rtf").write_bytes(
        b"{\\rtf1\\ansi BLACKWALL_INERT_RTF_FIXTURE "
        b"https://rtf.fixture.invalid/api campaign=rtf-inert "
        b"{\\object\\objemb{\\*\\objclass Package}{\\*\\objdata "
        + rtf_payload.hex().encode("ascii")
        + b"}}}"
    )
    (FIXTURES / "document.pdf").write_bytes(pdf_fixture())
    (FIXTURES / "capture.pcap").write_bytes(pcap_fixture())
    (FIXTURES / "native-macho.macho").write_bytes(macho_fixture())
    (FIXTURES / "recorded-core.elf").write_bytes(elf_core_fixture())

    family_config = config_fixture(
        "https://config.fixture.invalid/api", "config-inert",
    )
    (FIXTURES / "family-config.bin").write_bytes(family_config)
    (FIXTURES / "installer.cab").write_bytes(cab_fixture(
        "payload/config.bin",
        config_fixture("https://cab.fixture.invalid/api", "cab-inert"),
    ))
    (FIXTURES / "installer-lzx.cab").write_bytes(attributed_mixed_cab_fixture())
    nested_cpio = cpio_fixture(
        "etc/blackwall/config.bin",
        config_fixture("https://firmware.fixture.invalid/api", "firmware-inert"),
    )
    with zipfile.ZipFile(FIXTURES / "nested-firmware.zip", "w") as archive:
        zip_member(archive, "images/firmware.uimg", uimage_fixture(nested_cpio))

    entries = [
        fixture_entry("native-pe", "native-pe.pe", "pe", "native_overview", "BLACKWALL_INERT_NATIVE_FIXTURE", "https://native.fixture.invalid/api", "campaign=native-inert", ["windows", "native"]),
        fixture_entry("packed-pe", "packed-pe.pe", "pe", "native_overview", "BLACKWALL_INERT_NATIVE_FIXTURE", "https://native.fixture.invalid/api", "campaign=native-inert", ["windows", "native", "upx"], packing_state="likely_packed"),
        fixture_entry("dotnet", "dotnet.pe", "dotnet", "managed", "BLACKWALL_INERT_DOTNET_FIXTURE", "https://dotnet.fixture.invalid/api", "campaign=dotnet-inert", ["windows", "managed"]),
        fixture_entry("dotnet-mixed", "dotnet-mixed.pe", "dotnet", "managed", "BLACKWALL_INERT_DOTNET_FIXTURE", "https://dotnet.fixture.invalid/api", "campaign=dotnet-inert", ["windows", "managed", "mixed-mode-marker"]),
        fixture_entry("dotnet-obfuscated", "dotnet-obfuscated.pe", "dotnet", "managed", "BLACKWALL_INERT_DOTNET_OBFUSCATED_FIXTURE", "https://dotnet-obfuscated.fixture.invalid/api", "campaign=dotnet-obfuscated-inert", ["windows", "managed", "obfuscated-identifiers"]),
        fixture_entry("dotnet-resource", "dotnet-resource.pe", "dotnet", "managed", "BLACKWALL_INERT_DOTNET_RESOURCE_FIXTURE", "https://dotnet-resource.fixture.invalid/api", "campaign=dotnet-resource-inert", ["windows", "managed", "embedded-resource"]),
        fixture_entry("elf", "native-elf.elf", "elf", "native_overview", "BLACKWALL_INERT_NATIVE_FIXTURE", "https://native.fixture.invalid/api", "campaign=native-inert", ["linux", "native"]),
        fixture_entry("apk", "fixture.apk", "apk", "android", "BLACKWALL_INERT_APK_FIXTURE", "https://apk.fixture.invalid/api", "campaign=apk-inert", ["android", "mobile"]),
        fixture_entry("javascript", "javascript.js", "javascript", "javascript", "BLACKWALL_INERT_JAVASCRIPT_FIXTURE", "https://javascript.fixture.invalid/api", "campaign: \"javascript-inert\"", ["script"]),
        fixture_entry("powershell", "powershell.ps1", "powershell", "artifact", "BLACKWALL_INERT_POWERSHELL_FIXTURE", "https://powershell.fixture.invalid/api", "campaign=powershell-inert", ["script", "safe-deobfuscation", "encoded-command"]),
        fixture_entry("vbscript", "vbscript.vbs", "vbscript", "artifact", "BLACKWALL_INERT_VBSCRIPT_FIXTURE", "https://vbscript.fixture.invalid/api", "campaign=vbscript-inert", ["script", "safe-deobfuscation", "embedded-payload"]),
        fixture_entry("vba-source", "vba.bas", "vba", "artifact", "BLACKWALL_INERT_VBA_FIXTURE", "https://vba.fixture.invalid/api", "campaign=vba-inert", ["script", "vba", "safe-deobfuscation"]),
        fixture_entry("wasm", "module.wasm", "wasm", "wasm", "BLACKWALL_INERT_WASM_FIXTURE", "https://wasm.fixture.invalid/api", "campaign=wasm-inert", ["bytecode"]),
        fixture_entry("office", "office.docx", "ooxml-word", "artifact", "BLACKWALL_INERT_OFFICE_FIXTURE", "https://office.fixture.invalid/api", "campaign=office-inert", ["document", "office"]),
        fixture_entry("office-macro", "office-macro.xlsm", "ooxml-spreadsheet", "artifact", "BLACKWALL_INERT_MACRO_OFFICE_FIXTURE", "https://macro-office.fixture.invalid/api", "campaign=macro-office-inert", ["document", "office", "vba-macro"]),
        fixture_entry("rtf", "document.rtf", "rtf", "artifact", "BLACKWALL_INERT_RTF_FIXTURE", "https://rtf.fixture.invalid/api", "campaign=rtf-inert", ["document", "embedded-object"]),
        fixture_entry("pdf", "document.pdf", "pdf", "artifact", "BLACKWALL_INERT_PDF_FIXTURE", "https://pdf.fixture.invalid/api", "campaign=pdf-inert", ["document", "embedded-object", "javascript-action"]),
        fixture_entry("pcap", "capture.pcap", "pcap", "pcap", "BLACKWALL_INERT_PCAP_FIXTURE", "https://pcap.fixture.invalid/api", "campaign=pcap-inert", ["capture", "network"]),
        fixture_entry("macho", "native-macho.macho", "mach-o", "native_overview", "BLACKWALL_INERT_MACHO_FIXTURE", "https://macho.fixture.invalid/api", "campaign=macho-inert", ["apple", "native", "objc", "swift", "code-signature"]),
        fixture_entry("recorded-core", "recorded-core.elf", "elf-core", "recorded_crash", "BLACKWALL_INERT_ELF_CORE_FIXTURE", "https://core.fixture.invalid/api", "campaign=core-inert", ["linux", "recorded-core"]),
        fixture_entry("nested-firmware", "nested-firmware.zip", "zip", "artifact", "blackwall-inert-v1", "https://firmware.fixture.invalid/api", "firmware-inert", ["archive", "firmware", "cpio", "recursive", "config"]),
        fixture_entry("installer-cab", "installer.cab", "cab", "artifact", "BWCFG1", "https://cab.fixture.invalid/api", "cab-inert", ["installer", "cab", "recursive", "config"]),
        fixture_entry("installer-lzx", "installer-lzx.cab", "cab", "artifact", "lzx.txt", "", "", ["installer", "cab", "lzx", "quantum", "recursive"]),
        fixture_entry("iexpress-cab", "iexpress-cab.pe", "pe", "native_overview", "BLACKWALL_INERT_NATIVE_FIXTURE", "https://native.fixture.invalid/api", "campaign=native-inert", ["windows", "native", "iexpress", "embedded-cab", "lzx"]),
        fixture_entry("family-config", "family-config.bin", "blackwall-config", "artifact", "BWCFG1", "https://config.fixture.invalid/api", "config-inert", ["config", "family-extractor"]),
        fixture_entry("amadey-config", "amadey-config.pe", "pe", "native_overview", "BLACKWALL_INERT_AMADEY_CONFIG", "c2.amadey.fixture.invalid", "a1b2c3", ["windows", "native", "config", "family-extractor", "amadey", "reconstructed"]),
    ]
    manifest = {
        "schema": "blackwall.benchmark-corpus.v1",
        "id": "blackwall-inert-v1",
        "kind": "inert",
        "description": "Source-built fixtures that are never executed; script sources only assign constants, and the attributed third-party VBA sample is inspected statically.",
        "network_policy": "offline",
        "generated_by": "benchmarks/build_corpus.py",
        "toolchain": {
            "mingw": tool_version([mingw, "--version"]),
            "windres": tool_version([windres, "--version"]),
            "gcc": tool_version([gcc, "--version"]),
            "dotnet": tool_version([dotnet, "--version"]),
            "upx": tool_version([upx, "--version"]),
            "smali": tool_version([smali, "--version"]),
        },
        "fixtures": entries,
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


def verify() -> None:
    manifest = json.loads(MANIFEST.read_text())
    failed = []
    expected_paths = []
    for fixture in manifest["fixtures"]:
        path = (MANIFEST.parent / fixture["path"]).resolve()
        expected_paths.append(path.relative_to(ROOT.parent).as_posix())
        digest = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else "missing"
        if digest != fixture["sha256"]:
            failed.append(f"{fixture['id']}: expected {fixture['sha256']}, got {digest}")

    # A developer's ignored file can satisfy the hash check locally while being
    # absent from a clean checkout.  Verify Git coverage when a worktree exists;
    # release images intentionally omit .git and still verify the file hashes.
    if (ROOT.parent / ".git").exists():
        tracked = set(
            run(
                ["git", "-C", str(ROOT.parent), "ls-files", "--", "benchmarks/fixtures"],
            ).splitlines()
        )
        for path in expected_paths:
            if path not in tracked:
                failed.append(f"untracked corpus fixture: {path}")
    if failed:
        raise SystemExit("fixture verification failed:\n" + "\n".join(failed))
    print(f"verified {len(manifest['fixtures'])} inert fixtures")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify", action="store_true", help="verify committed fixture hashes only")
    args = parser.parse_args()
    verify() if args.verify else build()


if __name__ == "__main__":
    main()
