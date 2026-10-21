#!/usr/bin/env python3
"""Build BlackWall's deterministic, non-executing benchmark fixtures.

This script never downloads inputs.  It only invokes local compilers/packers
with fixed arguments and writes fixtures whose source is committed beside it.
Compiler and packer versions are recorded in the generated manifest because
binary hashes can legitimately change when those toolchains change.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import tempfile
import zipfile
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
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"endstream",
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
        "iocs": [url],
        "configuration": [config],
        "report_claims": [
            {"id": "fixture-identity", "terms": [marker]},
            {"id": "endpoint", "terms": [url]},
            {"id": "configuration", "terms": [config]},
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
    gcc = require("gcc")
    dotnet = require("dotnet")
    upx = require("upx")
    smali = require("smali")
    FIXTURES.mkdir(parents=True, exist_ok=True)
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    for name in (
        "native-pe.pe", "packed-pe.pe", "dotnet.pe", "native-elf.elf",
        "fixture.apk", "javascript.js", "module.wasm", "office.docx",
        "document.rtf", "document.pdf", "capture.pcap",
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
        dotnet_output = temp / "BlackWallFixture.dll"
        run([
            dotnet, str(compiler), "-nologo", "-noconfig", "-nostdlib+",
            "-target:exe", f"-out:{dotnet_output}", "-deterministic+",
            "-debug-", "-optimize+", str(SOURCE / "dotnet" / "Program.cs"),
            f"-r:{references / 'mscorlib.dll'}",
            f"-r:{references / 'System.Runtime.dll'}",
            f"-r:{references / 'System.Console.dll'}",
        ], environment={
            "DOTNET_CLI_HOME": str(dotnet_home),
            "DOTNET_NOLOGO": "1",
            "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1",
            "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
        })
        shutil.copyfile(dotnet_output, FIXTURES / "dotnet.pe")

        dex = temp / "classes.dex"
        run([smali, "assemble", str(SOURCE / "android"), "-o", str(dex)])
        with zipfile.ZipFile(FIXTURES / "fixture.apk", "w") as archive:
            zip_member(archive, "AndroidManifest.xml", (SOURCE / "android" / "AndroidManifest.xml").read_bytes())
            zip_member(archive, "classes.dex", dex.read_bytes())

    shutil.copyfile(SOURCE / "javascript.js", FIXTURES / "javascript.js")
    (FIXTURES / "module.wasm").write_bytes(wasm_fixture())

    with zipfile.ZipFile(FIXTURES / "office.docx", "w") as archive:
        zip_member(archive, "[Content_Types].xml", b"""<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
 <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
 <Default Extension="xml" ContentType="application/xml"/>
 <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>""")
        zip_member(archive, "_rels/.rels", b"""<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
 <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>""")
        zip_member(archive, "word/document.xml", b"""<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>BLACKWALL_INERT_OFFICE_FIXTURE https://office.fixture.invalid/api campaign=office-inert</w:t></w:r></w:p></w:body></w:document>""")

    (FIXTURES / "document.rtf").write_bytes(
        b"{\\rtf1\\ansi BLACKWALL_INERT_RTF_FIXTURE "
        b"https://rtf.fixture.invalid/api campaign=rtf-inert}"
    )
    (FIXTURES / "document.pdf").write_bytes(pdf_fixture())
    (FIXTURES / "capture.pcap").write_bytes(pcap_fixture())

    entries = [
        fixture_entry("native-pe", "native-pe.pe", "pe", "native_overview", "BLACKWALL_INERT_NATIVE_FIXTURE", "https://native.fixture.invalid/api", "campaign=native-inert", ["windows", "native"]),
        fixture_entry("packed-pe", "packed-pe.pe", "pe", "native_overview", "BLACKWALL_INERT_NATIVE_FIXTURE", "https://native.fixture.invalid/api", "campaign=native-inert", ["windows", "native", "upx"], packing_state="likely_packed"),
        fixture_entry("dotnet", "dotnet.pe", "dotnet", "managed", "BLACKWALL_INERT_DOTNET_FIXTURE", "https://dotnet.fixture.invalid/api", "campaign=dotnet-inert", ["windows", "managed"]),
        fixture_entry("elf", "native-elf.elf", "elf", "native_overview", "BLACKWALL_INERT_NATIVE_FIXTURE", "https://native.fixture.invalid/api", "campaign=native-inert", ["linux", "native"]),
        fixture_entry("apk", "fixture.apk", "apk", "android", "BLACKWALL_INERT_APK_FIXTURE", "https://apk.fixture.invalid/api", "campaign=apk-inert", ["android", "mobile"]),
        fixture_entry("javascript", "javascript.js", "javascript", "javascript", "BLACKWALL_INERT_JAVASCRIPT_FIXTURE", "https://javascript.fixture.invalid/api", "campaign: \"javascript-inert\"", ["script"]),
        fixture_entry("wasm", "module.wasm", "wasm", "wasm", "BLACKWALL_INERT_WASM_FIXTURE", "https://wasm.fixture.invalid/api", "campaign=wasm-inert", ["bytecode"]),
        fixture_entry("office", "office.docx", "ooxml-word", "artifact", "BLACKWALL_INERT_OFFICE_FIXTURE", "https://office.fixture.invalid/api", "campaign=office-inert", ["document", "office"]),
        fixture_entry("rtf", "document.rtf", "rtf", "artifact", "BLACKWALL_INERT_RTF_FIXTURE", "https://rtf.fixture.invalid/api", "campaign=rtf-inert", ["document"]),
        fixture_entry("pdf", "document.pdf", "pdf", "artifact", "BLACKWALL_INERT_PDF_FIXTURE", "https://pdf.fixture.invalid/api", "campaign=pdf-inert", ["document"]),
        fixture_entry("pcap", "capture.pcap", "pcap", "pcap", "BLACKWALL_INERT_PCAP_FIXTURE", "https://pcap.fixture.invalid/api", "campaign=pcap-inert", ["capture", "network"]),
    ]
    manifest = {
        "schema": "blackwall.benchmark-corpus.v1",
        "id": "blackwall-inert-v1",
        "kind": "inert",
        "description": "Source-built fixtures that contain no executable behavior beyond returning constants.",
        "network_policy": "offline",
        "generated_by": "benchmarks/build_corpus.py",
        "toolchain": {
            "mingw": tool_version([mingw, "--version"]),
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
    for fixture in manifest["fixtures"]:
        path = (MANIFEST.parent / fixture["path"]).resolve()
        digest = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else "missing"
        if digest != fixture["sha256"]:
            failed.append(f"{fixture['id']}: expected {fixture['sha256']}, got {digest}")
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
