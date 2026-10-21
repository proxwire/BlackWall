"""Bounded, non-executing archive/firmware extraction worker.

The worker never materializes attacker-controlled member names.  Every output
uses a generated name in a caller-created private directory, and the parent
MCP process verifies each size and digest before lineage admission.
"""

from __future__ import annotations

import argparse
import bz2
import gzip
import hashlib
import io
import json
import lzma
import os
import re
import resource
import stat
import struct
import subprocess
import tarfile
import tempfile
import zipfile
import zlib
from pathlib import Path, PurePosixPath

from .config_extractors import MAX_CONFIG_BYTES, extract_config, inventory

MAX_INPUT_BYTES = 256 * 1024 * 1024
MAX_MEMBER_SCAN = 8192
MAX_ARCHIVE_RATIO = 100
MAX_NAME_BYTES = 1024
CHUNK = 64 * 1024
CABEXTRACT = "/opt/tools/bin/cabextract"


def _bounded_file(path: Path, limit: int = MAX_INPUT_BYTES) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError("target must be a regular, non-symlink file")
    size = path.stat().st_size
    if size > limit:
        raise ValueError(f"input exceeds {limit} byte limit ({size} bytes)")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"input exceeds {limit} byte limit")
    return data


def _display(value: object, limit: int = 512) -> str:
    text = str(value).replace("\x00", "\\0")
    text = "".join(char if char >= " " else "�" for char in text)
    return text if len(text) <= limit else text[:limit] + "…"


def _member_name(name: str) -> tuple[str, str | None]:
    if not name or len(name.encode("utf-8", errors="replace")) > MAX_NAME_BYTES:
        return _display(name), "empty or oversized member name"
    normalized = name.replace("\\", "/")
    if "\x00" in normalized or any(ord(char) < 32 for char in normalized):
        return _display(name), "member name contains NUL/control bytes"
    path = PurePosixPath(normalized)
    if path.is_absolute() or ".." in path.parts or re.match(r"^[A-Za-z]:", normalized):
        return _display(name), "member name would traverse outside an extraction root"
    return _display(name), None


class ArtifactWriter:
    def __init__(self, output: Path, max_artifacts: int,
                 max_artifact_bytes: int, max_total_bytes: int):
        self.output = output.resolve()
        self.output.mkdir(parents=False, exist_ok=True)
        if self.output.is_symlink() or not self.output.is_dir():
            raise ValueError("output must be a real directory")
        self.max_artifacts = max_artifacts
        self.max_artifact_bytes = max_artifact_bytes
        self.max_total_bytes = max_total_bytes
        self.total = 0
        self.artifacts: list[dict] = []
        self.rejections: list[dict] = []

    @property
    def remaining(self) -> int:
        return min(self.max_artifact_bytes, self.max_total_bytes - self.total)

    def reject(self, source: str, reason: str) -> None:
        if len(self.rejections) < 512:
            self.rejections.append({"source": _display(source), "reason": _display(reason)})

    def add(self, data: bytes, *, kind: str, source: str, metadata: dict | None = None) -> bool:
        if len(self.artifacts) >= self.max_artifacts:
            self.reject(source, f"artifact count limit reached ({self.max_artifacts})")
            return False
        if not data:
            self.reject(source, "empty artifacts are not admitted")
            return False
        if len(data) > self.max_artifact_bytes:
            self.reject(source, f"artifact exceeds {self.max_artifact_bytes} bytes")
            return False
        if len(data) > self.max_total_bytes - self.total:
            self.reject(source, f"aggregate output exceeds {self.max_total_bytes} bytes")
            return False
        filename = f"artifact-{len(self.artifacts):04d}.bin"
        path = self.output / filename
        with path.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        digest = hashlib.sha256(data).hexdigest()
        self.artifacts.append({
            "file": filename,
            "kind": _display(kind, 120),
            "source": _display(source, 500),
            "size": len(data),
            "sha256": digest,
            **(metadata or {}),
        })
        self.total += len(data)
        return True


def _read_bounded(stream, limit: int) -> bytes:
    output = bytearray()
    while True:
        chunk = stream.read(min(CHUNK, limit + 1 - len(output)))
        if not chunk:
            break
        output.extend(chunk)
        if len(output) > limit:
            raise ValueError(f"expanded member exceeds {limit} bytes")
    return bytes(output)


def _zip_extract(path: Path, writer: ArtifactWriter, *, android_only: bool = False) -> dict:
    scanned = 0
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        for info in infos[:MAX_MEMBER_SCAN]:
            scanned += 1
            display, name_error = _member_name(info.filename)
            if name_error:
                writer.reject(display, name_error)
                continue
            if info.is_dir():
                continue
            mode = info.external_attr >> 16
            if mode and stat.S_ISLNK(mode):
                writer.reject(display, "symbolic-link member rejected")
                continue
            if info.flag_bits & 1:
                writer.reject(display, "encrypted member rejected")
                continue
            lowered = info.filename.lower()
            if android_only and not (
                lowered in {"androidmanifest.xml", "resources.arsc"}
                or lowered.startswith(("res/", "assets/"))
            ):
                continue
            if info.file_size > writer.remaining:
                writer.reject(display, "declared expanded size exceeds remaining budget")
                continue
            if info.file_size and info.compress_size == 0:
                writer.reject(display, "non-empty member declares zero compressed bytes")
                continue
            if info.compress_size and info.file_size > info.compress_size * MAX_ARCHIVE_RATIO:
                writer.reject(display, f"declared expansion ratio exceeds {MAX_ARCHIVE_RATIO}:1")
                continue
            try:
                with archive.open(info) as stream:
                    # Stop at the declared member size as well as the global
                    # budget.  A forged tiny size must not make us inflate all
                    # the way to the aggregate ceiling before detecting the
                    # metadata mismatch.
                    value = _read_bounded(stream, min(writer.remaining, info.file_size))
            except (OSError, RuntimeError, ValueError, zipfile.BadZipFile, zlib.error) as exc:
                writer.reject(display, f"member read failed: {type(exc).__name__}: {exc}")
                continue
            if len(value) != info.file_size:
                writer.reject(display, "expanded size differs from ZIP metadata")
                continue
            writer.add(
                value,
                kind="android-resource" if android_only else "zip-member",
                source=display,
                metadata={
                    "compressed_size": info.compress_size,
                    "declared_size": info.file_size,
                    "crc32": f"{info.CRC:08x}",
                },
            )
    if len(infos) > MAX_MEMBER_SCAN:
        writer.reject("zip", f"member scan limit reached ({MAX_MEMBER_SCAN})")
    return {"member_count": len(infos), "members_scanned": scanned}


def _tar_extract(data: bytes, writer: ArtifactWriter) -> dict:
    scanned = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        members = archive.getmembers()
        for member in members[:MAX_MEMBER_SCAN]:
            scanned += 1
            display, name_error = _member_name(member.name)
            if name_error:
                writer.reject(display, name_error)
                continue
            if not member.isfile():
                if member.issym() or member.islnk():
                    writer.reject(display, "link member rejected")
                elif member.isdev():
                    writer.reject(display, "device member rejected")
                continue
            if member.size > writer.remaining:
                writer.reject(display, "declared member size exceeds remaining budget")
                continue
            stream = archive.extractfile(member)
            if stream is None:
                writer.reject(display, "regular member has no readable stream")
                continue
            try:
                value = _read_bounded(stream, min(writer.remaining, member.size))
            except (OSError, ValueError) as exc:
                writer.reject(display, f"member read failed: {type(exc).__name__}: {exc}")
                continue
            if len(value) != member.size:
                writer.reject(display, "expanded size differs from TAR metadata")
                continue
            writer.add(value, kind="tar-member", source=display,
                       metadata={"declared_size": member.size})
    if len(members) > MAX_MEMBER_SCAN:
        writer.reject("tar", f"member scan limit reached ({MAX_MEMBER_SCAN})")
    return {"member_count": len(members), "members_scanned": scanned}


def _stream_extract(data: bytes, writer: ArtifactWriter, kind: str) -> dict:
    if kind == "gzip":
        stream = gzip.GzipFile(fileobj=io.BytesIO(data))
    elif kind == "bzip2":
        stream = bz2.BZ2File(io.BytesIO(data))
    elif kind == "xz":
        stream = lzma.LZMAFile(io.BytesIO(data))
    else:  # pragma: no cover - internal dispatch invariant
        raise ValueError(f"unknown compression stream: {kind}")
    ratio_budget = len(data) * MAX_ARCHIVE_RATIO
    read_limit = min(writer.remaining, ratio_budget)
    try:
        with stream:
            value = _read_bounded(stream, read_limit)
    except ValueError:
        reason = (
            f"expansion ratio exceeds {MAX_ARCHIVE_RATIO}:1"
            if ratio_budget <= writer.remaining
            else "expanded stream exceeds remaining aggregate budget"
        )
        writer.reject(kind, reason)
        return {
            "compressed_bytes": len(data),
            "expanded_bytes_at_least": read_limit + 1,
        }
    writer.add(value, kind=f"{kind}-stream", source=f"{kind} payload",
               metadata={"compressed_size": len(data)})
    return {"compressed_bytes": len(data), "expanded_bytes": len(value)}


def _cpio_extract(data: bytes, writer: ArtifactWriter) -> dict:
    cursor = 0
    scanned = 0
    trailer = False
    while cursor < len(data) and scanned < MAX_MEMBER_SCAN:
        if cursor + 110 > len(data) or data[cursor:cursor + 6] not in {b"070701", b"070702"}:
            raise ValueError(f"invalid newc CPIO header at offset {cursor:#x}")
        magic = data[cursor:cursor + 6]
        try:
            fields = [int(data[cursor + 6 + index * 8:cursor + 14 + index * 8], 16)
                      for index in range(13)]
        except ValueError as exc:
            raise ValueError(f"invalid newc CPIO integer at offset {cursor:#x}") from exc
        mode, file_size, name_size, checksum = fields[1], fields[6], fields[11], fields[12]
        if not 1 <= name_size <= MAX_NAME_BYTES + 1:
            raise ValueError(f"invalid CPIO name length at offset {cursor:#x}")
        name_start = cursor + 110
        name_end = name_start + name_size
        if name_end > len(data) or data[name_end - 1] != 0:
            raise ValueError(f"truncated or unterminated CPIO name at offset {cursor:#x}")
        name = data[name_start:name_end - 1].decode("utf-8", errors="replace")
        body_start = (name_end + 3) & ~3
        body_end = body_start + file_size
        if body_end > len(data):
            raise ValueError(f"CPIO member exceeds input at offset {cursor:#x}")
        cursor = (body_end + 3) & ~3
        scanned += 1
        if name == "TRAILER!!!":
            trailer = True
            break
        display, name_error = _member_name(name)
        if name_error:
            writer.reject(display, name_error)
            continue
        value = data[body_start:body_end]
        if magic == b"070702" and (sum(value) & 0xFFFFFFFF) != checksum:
            writer.reject(display, "CPIO checksum mismatch")
            continue
        if stat.S_ISREG(mode):
            writer.add(value, kind="cpio-member", source=display,
                       metadata={"mode": f"0{mode:o}", "offset": body_start})
        elif stat.S_ISLNK(mode):
            writer.reject(display, "symbolic-link member rejected")
        elif not stat.S_ISDIR(mode):
            writer.reject(display, "non-regular CPIO member rejected")
    if scanned >= MAX_MEMBER_SCAN and not trailer:
        writer.reject("cpio", f"member scan limit reached ({MAX_MEMBER_SCAN})")
    return {"members_scanned": scanned, "trailer_seen": trailer}


def _cab_cstring(data: bytes, cursor: int) -> tuple[str, int]:
    end = data.find(b"\0", cursor, min(len(data), cursor + MAX_NAME_BYTES + 1))
    if end < 0:
        raise ValueError("CAB string is missing a bounded terminator")
    return data[cursor:end].decode("utf-8", errors="replace"), end + 1


def _cab_external_extract(
    path: Path,
    data: bytes,
    writer: ArtifactWriter,
    files: list[dict],
    folders: list[dict],
) -> dict:
    """Decode LZX/Quantum CAB folders without materializing member names.

    The pinned cabextract/libmspack binary writes the concatenated member
    stream to a private, size-limited file.  BlackWall then splits that stream
    using the already range-checked CFFILE table and admits each member through
    ``ArtifactWriter``, which always chooses a generated output name.
    """
    if not Path(CABEXTRACT).is_file():
        raise ValueError("pinned cabextract decoder is unavailable")
    if any(row["folder"] >= 0xFFFD for row in files):
        raise ValueError("split/multi-cabinet LZX members are not admitted")
    total_declared = sum(row["size"] for row in files)
    if total_declared > writer.max_total_bytes:
        raise ValueError("CAB declared output exceeds aggregate output budget")
    if total_declared > len(data) * MAX_ARCHIVE_RATIO:
        raise ValueError(
            f"CAB declared expansion ratio exceeds {MAX_ARCHIVE_RATIO}:1"
        )
    with tempfile.TemporaryDirectory(prefix="blackwall-cabextract-") as temporary:
        output = Path(temporary) / "members.bin"
        try:
            with output.open("xb") as stream:
                run = subprocess.run(
                    [CABEXTRACT, "-s", "-q", "-p", str(path)],
                    stdin=subprocess.DEVNULL,
                    stdout=stream,
                    stderr=subprocess.PIPE,
                    timeout=120,
                    check=False,
                    env={"PATH": "/opt/tools/bin:/usr/bin:/bin", "LANG": "C.UTF-8"},
                )
        except subprocess.TimeoutExpired as exc:
            raise ValueError("cabextract exceeded its 120 second worker deadline") from exc
        if run.returncode != 0:
            message = run.stderr.decode("utf-8", errors="replace")[:1000]
            raise ValueError(f"cabextract rejected the cabinet: {message}")
        with output.open("rb") as stream:
            decoded = stream.read(total_declared + 1)
        if len(decoded) != total_declared:
            raise ValueError(
                "cabextract output length does not match the validated CFFILE table"
            )

    cursor = 0
    for row in files:
        value = decoded[cursor:cursor + row["size"]]
        cursor += row["size"]
        display, name_error = _member_name(row["name"])
        if name_error:
            writer.reject(display, name_error)
            continue
        folder = folders[row["folder"]]
        writer.add(
            value,
            kind="cab-member",
            source=display,
            metadata={
                "folder": row["folder"],
                "folder_offset": row["offset"],
                "compression": {2: "quantum", 3: "lzx"}.get(
                    folder["compression"], "mixed"
                ),
                "decoder": "cabextract-1.11/libmspack",
            },
        )
    return {
        "folder_count": len(folders),
        "member_count": len(files),
        "decoder": "cabextract-1.11/libmspack",
        "compression_methods": sorted({row["compression"] for row in folders}),
    }


def _cab_extract(path: Path, data: bytes, writer: ArtifactWriter) -> dict:
    if len(data) < 36 or data[:4] != b"MSCF":
        raise ValueError("invalid CAB header")
    cabinet_size = struct.unpack_from("<I", data, 8)[0]
    files_offset = struct.unpack_from("<I", data, 16)[0]
    folder_count, file_count, flags = struct.unpack_from("<HHH", data, 26)
    if cabinet_size > len(data) or not 36 <= files_offset <= cabinet_size:
        raise ValueError("CAB declares an invalid cabinet or file-table range")
    if folder_count > 256 or file_count > MAX_MEMBER_SCAN:
        raise ValueError("CAB folder/file count exceeds parser limits")
    cursor = 36
    folder_reserved = data_reserved = 0
    if flags & 0x0004:
        if cursor + 4 > len(data):
            raise ValueError("truncated CAB reserve header")
        header_reserved, folder_reserved, data_reserved = struct.unpack_from("<HBB", data, cursor)
        cursor += 4 + header_reserved
    for flag in (0x0001, 0x0002):
        if flags & flag:
            _, cursor = _cab_cstring(data, cursor)
            _, cursor = _cab_cstring(data, cursor)
    folders = []
    for index in range(folder_count):
        if cursor + 8 + folder_reserved > len(data):
            raise ValueError("truncated CAB folder table")
        offset, blocks, compression_raw = struct.unpack_from("<IHH", data, cursor)
        cursor += 8 + folder_reserved
        folders.append({"index": index, "offset": offset, "blocks": blocks,
                        "compression": compression_raw & 0x000F,
                        "compression_raw": compression_raw})
    cursor = files_offset
    files = []
    for _ in range(file_count):
        if cursor + 16 > len(data):
            raise ValueError("truncated CAB file table")
        size, folder_offset, folder_index, date, file_time, attributes = struct.unpack_from(
            "<IIHHHH", data, cursor,
        )
        cursor += 16
        name, cursor = _cab_cstring(data, cursor)
        files.append({
            "name": name, "size": size, "offset": folder_offset,
            "folder": folder_index, "date": date, "time": file_time,
            "attributes": attributes,
        })
    compression_methods = {folder["compression"] for folder in folders}
    unknown = compression_methods - {0, 1, 2, 3}
    if unknown:
        raise ValueError(
            "CAB compression type(s) are unsupported: "
            + ", ".join(str(value) for value in sorted(unknown))
        )
    if compression_methods & {2, 3}:
        return _cab_external_extract(path, data, writer, files, folders)

    folder_streams: dict[int, bytes] = {}
    cabinet_expanded = 0
    for folder in folders:
        cursor = folder["offset"]
        output = bytearray()
        dictionary = b""
        for _ in range(folder["blocks"]):
            if cursor + 8 + data_reserved > cabinet_size:
                raise ValueError("truncated CAB data-block header")
            _checksum, compressed, expanded = struct.unpack_from("<IHH", data, cursor)
            cursor += 8 + data_reserved
            end = cursor + compressed
            if end > cabinet_size:
                raise ValueError("CAB data block exceeds cabinet")
            block = data[cursor:end]
            cursor = end
            if expanded > writer.max_total_bytes - cabinet_expanded:
                raise ValueError("CAB expansion exceeds aggregate output budget")
            if expanded and compressed == 0:
                raise ValueError("non-empty CAB block declares zero compressed bytes")
            if folder["compression"] == 0 and compressed != expanded:
                raise ValueError("uncompressed CAB block has mismatched sizes")
            if (
                folder["compression"] != 0
                and expanded > compressed * MAX_ARCHIVE_RATIO
            ):
                raise ValueError(
                    f"CAB block expansion ratio exceeds {MAX_ARCHIVE_RATIO}:1"
                )
            if folder["compression"] == 0:
                decoded = block
            elif folder["compression"] == 1:
                if not block.startswith(b"CK"):
                    raise ValueError("MSZIP block is missing CK signature")
                decoder = zlib.decompressobj(-15, zdict=dictionary) if dictionary else zlib.decompressobj(-15)
                # Supply one byte beyond the declared output length so forged
                # CFDATA metadata cannot make zlib allocate an unbounded
                # buffer before the length mismatch is noticed.
                decoded = decoder.decompress(block[2:], expanded + 1)
                if len(decoded) > expanded:
                    raise ValueError("CAB MSZIP block exceeds declared expanded length")
                if decoder.unconsumed_tail or decoder.unused_data or not decoder.eof:
                    raise ValueError("CAB MSZIP block has trailing or incomplete compressed data")
                dictionary = (dictionary + decoded)[-32768:]
            else:  # pragma: no cover - external methods dispatched above
                raise ValueError(f"unexpected CAB compression type {folder['compression']}")
            if len(decoded) != expanded:
                raise ValueError("CAB data block expanded length mismatch")
            output.extend(decoded)
            cabinet_expanded += len(decoded)
        folder_streams[folder["index"]] = bytes(output)
    for row in files:
        display, name_error = _member_name(row["name"])
        if name_error:
            writer.reject(display, name_error)
            continue
        if row["folder"] >= 0xFFFD or row["folder"] not in folder_streams:
            writer.reject(display, "split/multi-cabinet member rejected")
            continue
        folder_data = folder_streams[row["folder"]]
        start, end = row["offset"], row["offset"] + row["size"]
        if end > len(folder_data):
            writer.reject(display, "file range exceeds expanded CAB folder")
            continue
        writer.add(folder_data[start:end], kind="cab-member", source=display,
                   metadata={"folder": row["folder"], "folder_offset": start})
    return {
        "folder_count": folder_count,
        "member_count": file_count,
        "decoder": "blackwall-builtin",
        "compression_methods": sorted(compression_methods),
    }


def _uimage_extract(data: bytes, writer: ArtifactWriter) -> dict:
    if len(data) < 64 or data[:4] != b"'\x05\x19V":
        raise ValueError("invalid legacy U-Boot uImage header")
    values = struct.unpack_from(">7I4B32s", data, 0)
    magic, header_crc, timestamp, size, load, entry, data_crc, os_id, arch, image_type, compression, raw_name = values
    end = 64 + size
    if end > len(data):
        raise ValueError("uImage payload exceeds input")
    header = bytearray(data[:64])
    header[4:8] = b"\0" * 4
    header_valid = (zlib.crc32(header) & 0xFFFFFFFF) == header_crc
    payload = data[64:end]
    data_valid = (zlib.crc32(payload) & 0xFFFFFFFF) == data_crc
    if not header_valid or not data_valid:
        raise ValueError("uImage header or payload CRC32 mismatch")
    compression_names = {0: "none", 1: "gzip", 2: "bzip2", 3: "lzma", 4: "lzo", 5: "lz4", 6: "zstd"}
    compression_name = compression_names.get(compression, f"id-{compression}")
    name = raw_name.split(b"\0", 1)[0].decode("utf-8", errors="replace")
    value = payload
    decoded = False
    if compression in {1, 2, 3}:
        if compression == 1:
            stream = gzip.GzipFile(fileobj=io.BytesIO(payload))
        elif compression == 2:
            stream = bz2.BZ2File(io.BytesIO(payload))
        else:
            stream = lzma.LZMAFile(io.BytesIO(payload))
        ratio_budget = len(payload) * MAX_ARCHIVE_RATIO
        read_limit = min(writer.remaining, ratio_budget)
        try:
            with stream:
                value = _read_bounded(stream, read_limit)
        except ValueError:
            reason = (
                f"uImage expansion ratio exceeds {MAX_ARCHIVE_RATIO}:1"
                if ratio_budget <= writer.remaining
                else "uImage payload exceeds remaining aggregate budget"
            )
            writer.reject(f"uImage {name or '<unnamed>'}", reason)
            return {
                "name": _display(name), "compression": compression_name,
                "header_crc_valid": True, "data_crc_valid": True,
                "expanded_bytes_at_least": read_limit + 1,
            }
        decoded = True
    writer.add(
        value,
        kind="uimage-decoded-payload" if decoded else "uimage-payload",
        source=f"uImage {name or '<unnamed>'}",
        metadata={
            "compression": compression_name,
            "declared_size": size,
            "load_address": hex(load),
            "entry_address": hex(entry),
            "os_id": os_id,
            "architecture_id": arch,
            "image_type_id": image_type,
            "timestamp": timestamp,
            "header_crc32": f"{header_crc:08x}",
            "data_crc32": f"{data_crc:08x}",
        },
    )
    return {"name": _display(name), "compression": compression_name,
            "header_crc_valid": True, "data_crc_valid": True}


def _upx_extract(path: Path, writer: ArtifactWriter) -> dict:
    with tempfile.TemporaryDirectory(prefix="blackwall-upx-") as temporary:
        output = Path(temporary) / "unpacked.bin"
        try:
            run = subprocess.run(
                ["/opt/tools/bin/upx", "-d", "-o", str(output), str(path)],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=120, check=False, env={"PATH": "/opt/tools/bin:/usr/bin:/bin", "LANG": "C.UTF-8"},
            )
        except subprocess.TimeoutExpired as exc:
            raise ValueError("UPX exceeded its 120 second worker deadline") from exc
        if run.returncode != 0 or not output.is_file() or output.is_symlink():
            message = (run.stdout + run.stderr).decode("utf-8", errors="replace")[:1000]
            raise ValueError(f"UPX did not produce a regular output: {message}")
        with output.open("rb") as stream:
            value = stream.read(writer.max_artifact_bytes + 1)
        if len(value) > writer.max_artifact_bytes:
            raise ValueError("UPX output exceeds the per-artifact byte limit")
        writer.add(value, kind="upx-unpacked", source="UPX compressed executable")
        return {"upx_returncode": run.returncode}


def _pe_rcdata_cabs(path: Path, data: bytes, writer: ArtifactWriter) -> dict:
    """Carve validated CABs from PE RCDATA resources into generated names."""
    try:
        import pefile
    except ImportError as exc:  # pragma: no cover - image admission invariant
        raise ValueError("PE resource parser is unavailable") from exc
    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
        ])
    except pefile.PEFormatError as exc:
        raise ValueError(f"invalid PE resource directory: {exc}") from exc
    root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if root is None:
        return {"resources_scanned": 0, "cab_resources": 0}

    scanned = 0
    cabinets = 0
    for type_entry in root.entries[:MAX_MEMBER_SCAN]:
        type_id = getattr(type_entry, "id", None)
        if type_id != 10:  # RT_RCDATA
            continue
        type_directory = getattr(type_entry, "directory", None)
        if type_directory is None:
            continue
        for name_entry in type_directory.entries[:MAX_MEMBER_SCAN - scanned]:
            name = str(name_entry.name) if name_entry.name is not None else str(name_entry.id)
            name_directory = getattr(name_entry, "directory", None)
            if name_directory is None:
                continue
            for language_entry in name_directory.entries[:MAX_MEMBER_SCAN - scanned]:
                scanned += 1
                resource_data = getattr(language_entry, "data", None)
                structure = getattr(resource_data, "struct", None)
                if structure is None:
                    writer.reject(f"RCDATA/{name}", "resource leaf has no data entry")
                    continue
                size = int(structure.Size)
                if size <= 0 or size > min(MAX_INPUT_BYTES, writer.remaining):
                    writer.reject(
                        f"RCDATA/{name}",
                        "resource size is empty or exceeds the remaining extraction budget",
                    )
                    continue
                blob = pe.get_data(int(structure.OffsetToData), size)
                offset = 0
                admitted = False
                while True:
                    offset = blob.find(b"MSCF", offset)
                    if offset < 0:
                        break
                    if offset + 36 <= len(blob):
                        cabinet_size = struct.unpack_from("<I", blob, offset + 8)[0]
                        if 36 <= cabinet_size <= len(blob) - offset:
                            admitted = writer.add(
                                blob[offset:offset + cabinet_size],
                                kind="pe-rcdata-cab",
                                source=f"RCDATA/{_display(name, 200)}",
                                metadata={
                                    "resource_rva": hex(int(structure.OffsetToData)),
                                    "resource_size": size,
                                    "cab_offset_in_resource": offset,
                                    "declared_cabinet_size": cabinet_size,
                                    "language_id": getattr(language_entry, "id", None),
                                },
                            )
                            if admitted:
                                cabinets += 1
                            break
                    offset += 4
                if not admitted and b"MSCF" in blob:
                    writer.reject(
                        f"RCDATA/{name}", "CAB signature has an invalid declared range",
                    )
    return {"resources_scanned": scanned, "cab_resources": cabinets}


def _sniff(data: bytes) -> str | None:
    if data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "zip"
    if len(data) > 262 and data[257:262] == b"ustar":
        return "tar"
    if data.startswith(b"\x1f\x8b"):
        return "gzip"
    if data.startswith(b"BZh"):
        return "bzip2"
    if data.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if data.startswith(b"MSCF"):
        return "cab"
    if data.startswith((b"070701", b"070702")):
        return "cpio-newc"
    if data.startswith(b"'\x05\x19V"):
        return "uimage"
    if data.startswith((b"MZ", b"\x7fELF")) and b"UPX!" in data[:1024 * 1024]:
        return "upx"
    if data.startswith(b"MZ"):
        return "pe-rcdata"
    return None


def extract(path: Path, output: Path, max_artifacts: int,
            max_artifact_bytes: int, max_total_bytes: int,
            *, android_only: bool = False) -> dict:
    data = _bounded_file(path)
    writer = ArtifactWriter(output, max_artifacts, max_artifact_bytes, max_total_bytes)
    kind = "android-zip" if android_only else _sniff(data)
    details: dict = {}
    if android_only:
        if _sniff(data) != "zip":
            raise ValueError("Android resource extraction requires a ZIP-backed APK")
        details = _zip_extract(path, writer, android_only=True)
    elif kind == "zip":
        details = _zip_extract(path, writer)
    elif kind == "tar":
        details = _tar_extract(data, writer)
    elif kind in {"gzip", "bzip2", "xz"}:
        details = _stream_extract(data, writer, kind)
    elif kind == "cab":
        details = _cab_extract(path, data, writer)
    elif kind == "cpio-newc":
        details = _cpio_extract(data, writer)
    elif kind == "uimage":
        details = _uimage_extract(data, writer)
    elif kind == "upx":
        details = _upx_extract(path, writer)
    elif kind == "pe-rcdata":
        details = _pe_rcdata_cabs(path, data, writer)
    else:
        return {
            "schema": "blackwall.bounded-extraction.v1",
            "target": str(path),
            "supported": False,
            "extractor": None,
            "artifacts": [],
            "rejections": [],
            "total_bytes": 0,
        }
    return {
        "schema": "blackwall.bounded-extraction.v1",
        "target": str(path),
        "supported": True,
        "extractor": kind,
        "details": details,
        "artifacts": writer.artifacts,
        "rejections": writer.rejections,
        "count": len(writer.artifacts),
        "total_bytes": writer.total,
        "limits": {
            "max_artifacts": max_artifacts,
            "max_artifact_bytes": max_artifact_bytes,
            "max_total_bytes": max_total_bytes,
            "max_archive_ratio": MAX_ARCHIVE_RATIO,
            "generated_output_names": True,
        },
    }


def _apply_limits(max_artifact_bytes: int, max_total_bytes: int) -> None:
    def tighten(kind: int, value: int) -> None:
        soft, hard = resource.getrlimit(kind)
        ceiling = value if hard == resource.RLIM_INFINITY else min(value, hard)
        resource.setrlimit(kind, (ceiling, ceiling))

    tighten(resource.RLIMIT_AS, 1024 * 1024 * 1024)
    tighten(resource.RLIMIT_FSIZE, max(max_total_bytes, 1024 * 1024))
    tighten(resource.RLIMIT_NOFILE, 128)
    tighten(resource.RLIMIT_CORE, 0)
    # A child UPX process inherits this CPU ceiling. Parent supervision remains
    # the authoritative wall-clock deadline.
    tighten(resource.RLIMIT_CPU, 180)


def extractor_self_check(fixtures: Path) -> dict:
    """Admission-test the external CAB, PE resource, and family lanes."""
    fixtures = fixtures.resolve()
    expected_cab = "0ce0b55fe705b744d41bb361170c0467db30da0c7f9bdd386d5dade71a78e171"
    with tempfile.TemporaryDirectory(prefix="blackwall-extractor-check-") as temporary:
        root = Path(temporary)
        lzx = extract(
            fixtures / "installer-lzx.cab", root / "lzx", 8,
            1024 * 1024, 4 * 1024 * 1024,
        )
        if lzx.get("details", {}).get("decoder") != "cabextract-1.11/libmspack":
            raise RuntimeError("LZX/Quantum cabinet did not use the pinned decoder")
        if lzx.get("details", {}).get("compression_methods") != [1, 2, 3]:
            raise RuntimeError("mixed CAB compression methods were not recovered")
        if lzx.get("count") != 3:
            raise RuntimeError("mixed CAB fixture did not produce three members")
        resource = extract(
            fixtures / "iexpress-cab.pe", root / "resource", 8,
            1024 * 1024, 4 * 1024 * 1024,
        )
        if [row.get("sha256") for row in resource.get("artifacts", [])] != [expected_cab]:
            raise RuntimeError("PE RCDATA did not reproduce the expected CAB")
    config = extract_config(
        _bounded_file(fixtures / "amadey-config.pe", MAX_CONFIG_BYTES),
        "amadey-v4-v5",
    )
    matches = config.get("matches", [])
    if len(matches) != 1 or matches[0].get("confidence", {}).get("tier") != "high":
        raise RuntimeError("reconstructed Amadey configuration was not recovered")
    values = matches[0].get("values", {})
    if values.get("campaign") != "a1b2c3" or values.get("c2_hosts") != [
        "c2.amadey.fixture.invalid"
    ]:
        raise RuntimeError("reconstructed Amadey values drifted")
    return {
        "ok": True,
        "cab_decoder": lzx["details"]["decoder"],
        "cab_members": lzx["count"],
        "pe_rcdata_sha256": expected_cab,
        "amadey_confidence": matches[0]["confidence"]["tier"],
    }


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="BlackWall bounded extraction worker")
    sub = parser.add_subparsers(dest="command", required=True)
    extract_parser = sub.add_parser("extract")
    extract_parser.add_argument("path", type=Path)
    extract_parser.add_argument("output", type=Path)
    extract_parser.add_argument("--max-artifacts", type=int, required=True)
    extract_parser.add_argument("--max-artifact-bytes", type=int, required=True)
    extract_parser.add_argument("--max-total-bytes", type=int, required=True)
    extract_parser.add_argument("--android-only", action="store_true")
    config_parser = sub.add_parser("config")
    config_parser.add_argument("path", type=Path)
    config_parser.add_argument("--family", default="auto")
    sub.add_parser("list-configs")
    check_parser = sub.add_parser("self-check")
    check_parser.add_argument(
        "--fixtures", type=Path,
        default=Path("/opt/blackwall/benchmarks/fixtures"),
    )
    args = parser.parse_args(argv)

    try:
        if args.command == "list-configs":
            result = {"schema": "blackwall.config-extractor-registry.v1",
                      "extractors": inventory()}
        elif args.command == "self-check":
            _apply_limits(64 * 1024 * 1024, 512 * 1024 * 1024)
            result = extractor_self_check(args.fixtures)
        elif args.command == "config":
            _apply_limits(MAX_CONFIG_BYTES, MAX_CONFIG_BYTES)
            data = _bounded_file(args.path, MAX_CONFIG_BYTES)
            result = extract_config(data, args.family)
            result["target"] = str(args.path)
            result["sha256"] = hashlib.sha256(data).hexdigest()
        else:
            for name, lower, upper in (
                ("max_artifacts", 1, 512),
                ("max_artifact_bytes", 1, 64 * 1024 * 1024),
                ("max_total_bytes", 1, 512 * 1024 * 1024),
            ):
                value = getattr(args, name)
                if not lower <= value <= upper:
                    raise ValueError(f"{name} must be between {lower} and {upper}")
            _apply_limits(args.max_artifact_bytes, args.max_total_bytes)
            result = extract(
                args.path, args.output, args.max_artifacts,
                args.max_artifact_bytes, args.max_total_bytes,
                android_only=args.android_only,
            )
        print(json.dumps(result, sort_keys=True, ensure_ascii=False))
    except Exception as exc:
        print(json.dumps({
            "schema": "blackwall.worker-error.v1",
            "error": f"{type(exc).__name__}: {exc}",
            "artifacts": [],
        }, sort_keys=True))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
