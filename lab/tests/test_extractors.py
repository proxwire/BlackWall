import base64
import gzip
import io
import json
import stat
import struct
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path
from unittest.mock import patch

from blackwall_lab import config_extractors, extractors, native

# cabextract 1.11's inert mixed-compression fixture (MSZIP, LZX, Quantum).
# Source and licensing are recorded in benchmarks/fixtures-src/CABEXTRACT_NOTICE.md.
MIXED_CAB = base64.b64decode(
    "TVNDRgAAAAB7AQAAAAAAADwAAAAAAAAAAwEDAAMAAAAAAAAAhgAAAAEAAQDJAAAAAQADEkMBAAAB"
    "ACISOQAAAAAAAAAAAGwiulkgAG1zemlwLnR4dAC7AAAAAAAAAAEAbCK6WSAAbHp4LnR4dAA7AAAA"
    "AAAAAAIAbCK6WSAAcXRtLnR4dAA2eZKJOwA5AENL80xTqMwvVUhOzFMoSk1MUSjJyCzWAZKpCr7B"
    "UZ4BCimpyfm5BUWpxcX5RQqZxQrl+UXZmXnpilwA6QYIInIAuwBbgICNABCyCwAAAAAiAABVDkPA"
    "UvI+jItzQfAIXpERppe8R6h/fyAsAAAAADACAwB4IDGNjWBfE36/QBAAAAAAAACGCIohL+Nz0b7v"
    "l52XmtEBOdgUs7wmWVc/JhkEYabj5I/fIdp20PU5U9oKjpe5ALb9LexLMAA7ANYGaQvLR/AsKjqP"
    "LKu7PLkzAYvYWEt7AbpvbVFuOsNnQkvrAjZD1mZWyp5yzDAAAA==",
    validate=True,
)


def config_fixture(*, valid_crc: bool = True) -> bytes:
    payload = json.dumps({
        "endpoint": "https://config.fixture.invalid/api",
        "campaign": "config-inert",
    }, sort_keys=True, separators=(",", ":")).encode()
    checksum = zlib.crc32(payload) & 0xFFFFFFFF
    if not valid_crc:
        checksum ^= 1
    return b"BWCFG1\0" + struct.pack("<I", len(payload)) + payload + struct.pack("<I", checksum)


def amadey_fixture(*, corrupt: bool = False, truncate: bool = False) -> bytes:
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
    key = "0123456789abcdef0123456789abcdef"

    def encode(value: str) -> bytes:
        source = base64.b64encode(value.encode()).decode()
        transformed = "".join(
            alphabet[(alphabet.index(char) + alphabet.index(key[index % len(key)])) % len(alphabet)]
            if char in alphabet else char
            for index, char in enumerate(source)
        )
        return transformed.encode() + b"\0"

    values = [
        "c2.amadey.fixture.invalid", "/fixture/index.php", "5.99",
        "0123abc456", "FixtureBot.exe", "cred.dll", "clip.dll", "id:", "vs:", "sd:",
        "<c>", "<d>", "Plugins", "180000", "fixture-value",
    ]
    body = (
        b"MZBLACKWALL_INERT_AMADEY_CONFIG\0"
        + key.encode() + b"\0"
        + b"fedcba9876543210fedcba9876543210\0"
        + b"a1b2c3\0"
        + b"".join(encode(value) for value in values)
    )
    if corrupt:
        body = body.replace(b"/fixture/index.php", b"/missing/not-encoded", 1)
        body = body.replace(key.encode(), b"z" * 32, 1)
    return body[:48] if truncate else body


def cpio_fixture(name: str, payload: bytes) -> bytes:
    def entry(filename: str, data: bytes, mode: int) -> bytes:
        encoded = filename.encode() + b"\0"
        fields = (1, mode, 0, 0, 1, 946684800, len(data), 0, 0, 0, 0, len(encoded), 0)
        header = b"070701" + b"".join(f"{value:08x}".encode() for value in fields)
        result = header + encoded
        result += b"\0" * ((-len(result)) % 4)
        result += data
        result += b"\0" * ((-len(result)) % 4)
        return result
    return entry(name, payload, stat.S_IFREG | 0o644) + entry("TRAILER!!!", b"", 0)


def uimage_fixture(payload: bytes) -> bytes:
    name = b"BlackWall inert firmware".ljust(32, b"\0")
    header = bytearray(struct.pack(
        ">7I4B32s", 0x27051956, 0, 946684800, len(payload),
        0x8000, 0x8000, zlib.crc32(payload) & 0xFFFFFFFF,
        5, 2, 2, 0, name,
    ))
    struct.pack_into(">I", header, 4, zlib.crc32(header) & 0xFFFFFFFF)
    return bytes(header) + payload


def cab_fixture(name: str, payload: bytes, *, mszip: bool = False) -> bytes:
    block_payload = payload
    compression = 0
    if mszip:
        encoder = zlib.compressobj(level=9, wbits=-15)
        block_payload = b"CK" + encoder.compress(payload) + encoder.flush()
        compression = 1
    encoded = name.encode() + b"\0"
    folder_offset = 36
    files_offset = folder_offset + 8
    data_offset = files_offset + 16 + len(encoded)
    cabinet_size = data_offset + 8 + len(block_payload)
    header = struct.pack(
        "<4sIIIII BB HHHHH", b"MSCF", 0, cabinet_size, 0,
        files_offset, 0, 3, 1, 1, 1, 0, 0, 0,
    )
    folder = struct.pack("<IHH", data_offset, 1, compression)
    file_row = struct.pack("<IIHHHH", len(payload), 0, 0, 0, 0, 0) + encoded
    block = struct.pack(
        "<IHH", 0, len(block_payload), len(payload),
    ) + block_payload
    return header + folder + file_row + block


def macho_fixture() -> bytes:
    objc = b"fixtureSelector:\0FixtureClass\0"
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
    code_directory = struct.pack(
        ">9I4B", 0xFADE0C02, directory_size, 0x20400, 0,
        directory_size, 40, 0, 0, data_offset, 32, 2, 0, 12,
    ) + identifier
    signature = struct.pack(">III", 0xFADE0CC0, 20 + len(code_directory), 1)
    signature += struct.pack(">II", 0, 20) + code_directory
    signature_offset = stroff + len(strings)
    header = struct.pack(
        "<IIIIIIII", 0xFEEDFACF, 0x01000007, 3, 1, 4,
        command_bytes, 0, 0,
    )
    segment = struct.pack(
        "<II16sQQQQiiII", 0x19, segment_size, b"__TEXT".ljust(16, b"\0"),
        0x1000, len(objc) + len(swift), data_offset,
        len(objc) + len(swift), 7, 5, 2, 0,
    )
    segment += struct.pack(
        "<16s16sQQIIIIIIII", b"__objc_methname".ljust(16, b"\0"),
        b"__TEXT".ljust(16, b"\0"), 0x1000, len(objc), objc_offset,
        0, 0, 0, 2, 0, 0, 0,
    )
    segment += struct.pack(
        "<16s16sQQIIIIIIII", b"__swift5_types".ljust(16, b"\0"),
        b"__TEXT".ljust(16, b"\0"), 0x1000 + len(objc), len(swift), swift_offset,
        0, 0, 0, 0, 0, 0, 0,
    )
    symtab = struct.pack("<IIIIII", 2, 24, symoff, 2, stroff, len(strings))
    dylib = struct.pack("<IIIIII", 0xC, dylib_size, 24, 0, 0, 0)
    dylib += dylib_name + b"\0" * (dylib_size - 24 - len(dylib_name))
    code_signature = struct.pack("<IIII", 0x1D, 16, signature_offset, len(signature))
    return header + segment + symtab + dylib + code_signature + objc + swift + symbols + strings + signature


class ConfigExtractorTests(unittest.TestCase):
    def test_registry_is_static_and_confidence_is_graded(self):
        families = {item["family"] for item in config_extractors.inventory()}
        self.assertEqual(families, {"amadey-v4-v5", "blackwall-inert-v1"})
        high = config_extractors.extract_config(config_fixture())
        low = config_extractors.extract_config(config_fixture(valid_crc=False))
        self.assertEqual(high["matches"][0]["confidence"]["tier"], "high")
        self.assertEqual(low["matches"][0]["confidence"]["tier"], "low")
        self.assertEqual(high["matches"][0]["values"]["campaign"], "config-inert")

    def test_amadey_plugin_accepts_reconstructed_config_and_rejects_bad_shapes(self):
        recovered = config_extractors.extract_config(
            amadey_fixture(), family="amadey-v4-v5",
        )
        self.assertEqual(len(recovered["matches"]), 1)
        match = recovered["matches"][0]
        self.assertEqual(match["confidence"]["tier"], "high")
        self.assertEqual(match["values"]["family"], "Amadey")
        self.assertEqual(match["values"]["version"], "5.99")
        self.assertEqual(
            match["values"]["c2_urls"],
            ["http://c2.amadey.fixture.invalid/fixture/index.php"],
        )
        self.assertEqual(match["values"]["install_directory_id"], "0123abc456")
        for bad in (
            amadey_fixture(corrupt=True),
            amadey_fixture(truncate=True),
            b"MZ" + b"a" * 32 + b"\0" + b"QUFBQQ==\0" * 20,
        ):
            with self.subTest(size=len(bad)):
                rejected = config_extractors.extract_config(
                    bad, family="amadey-v4-v5",
                )
                self.assertEqual(rejected["matches"], [])


class BoundedExtractorTests(unittest.TestCase):
    def run_extract(self, payload: bytes, **kwargs):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "input"
            output = root / "output"
            source.write_bytes(payload)
            result = extractors.extract(
                source, output, kwargs.get("max_artifacts", 16),
                kwargs.get("max_artifact_bytes", 1024 * 1024),
                kwargs.get("max_total_bytes", 4 * 1024 * 1024),
            )
            contents = [
                (output / row["file"]).read_bytes() for row in result["artifacts"]
            ]
            names = [row["file"] for row in result["artifacts"]]
        return result, contents, names

    def test_zip_never_materializes_attacker_names(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("../escape.bin", b"escape")
            archive.writestr("safe/payload.bin", b"payload")
        result, contents, names = self.run_extract(stream.getvalue())
        self.assertEqual(contents, [b"payload"])
        self.assertEqual(names, ["artifact-0000.bin"])
        self.assertTrue(any("traverse" in row["reason"] for row in result["rejections"]))

    def test_cab_cpio_and_uimage_extractors(self):
        config = config_fixture()
        cabinet, cab_contents, _ = self.run_extract(cab_fixture("config.bin", config))
        self.assertEqual(cabinet["extractor"], "cab")
        self.assertEqual(cab_contents, [config])
        mszip, mszip_contents, _ = self.run_extract(
            cab_fixture("config.bin", config, mszip=True),
        )
        self.assertEqual(mszip["extractor"], "cab")
        self.assertEqual(mszip_contents, [config])

        cpio = cpio_fixture("etc/config.bin", config)
        cpio_result, cpio_contents, _ = self.run_extract(cpio)
        self.assertEqual(cpio_result["extractor"], "cpio-newc")
        self.assertEqual(cpio_contents, [config])

        image, image_contents, _ = self.run_extract(uimage_fixture(cpio))
        self.assertEqual(image["extractor"], "uimage")
        self.assertEqual(image_contents, [cpio])

    def test_pinned_cabextract_decodes_lzx_without_member_paths(self):
        cabextract = Path(extractors.CABEXTRACT)
        if not cabextract.is_file():
            cabextract = Path("/usr/bin/cabextract")
        if not cabextract.is_file():
            self.skipTest("host cabextract is unavailable; image admission always runs this")
        with patch.object(extractors, "CABEXTRACT", str(cabextract)):
            result, contents, names = self.run_extract(MIXED_CAB)
        self.assertEqual(result["details"]["decoder"], "cabextract-1.11/libmspack")
        self.assertEqual(result["details"]["compression_methods"], [1, 2, 3])
        self.assertEqual([len(value) for value in contents], [57, 187, 59])
        self.assertEqual(names, [
            "artifact-0000.bin", "artifact-0001.bin", "artifact-0002.bin",
        ])
        self.assertIn(b"LZX", contents[1])

    def test_expansion_ratio_rejects_zip_bomb_shape(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("large.bin", b"A" * 1024 * 1024)
        result, contents, _ = self.run_extract(stream.getvalue(), max_total_bytes=2 * 1024 * 1024)
        self.assertEqual(contents, [])
        self.assertTrue(any("ratio" in row["reason"] for row in result["rejections"]))

    def test_expansion_ratio_stops_stream_before_full_inflation(self):
        payload = gzip.compress(b"A" * 1024 * 1024)
        result, contents, _ = self.run_extract(
            payload, max_total_bytes=2 * 1024 * 1024,
        )
        self.assertEqual(contents, [])
        self.assertTrue(any("ratio" in row["reason"] for row in result["rejections"]))
        self.assertLess(
            result["details"]["expanded_bytes_at_least"], 1024 * 1024,
        )


class NativeWorkerTests(unittest.TestCase):
    def test_macho_metadata_covers_imports_signature_objc_and_swift(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "fixture.macho"
            target.write_bytes(macho_fixture())
            result = native.macho_metadata(target)
        self.assertEqual(result["architecture"]["name"], "x86_64")
        self.assertIn("_puts", {row["name"] for row in result["imports"]})
        self.assertTrue(result["code_signature"]["present"])
        self.assertEqual(result["code_signature"]["cryptographic_verification"], "not_performed")
        self.assertTrue(result["objective_c"]["present"])
        self.assertTrue(result["swift"]["present"])


if __name__ == "__main__":
    unittest.main()
