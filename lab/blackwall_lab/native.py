"""Hostile-input worker for Mach-O parsing and bounded ELF emulation.

The ELF lane maps file-backed segments into Unicorn and stops before system
calls.  It never launches the target as a host process and does not provide a
host filesystem, network stack, loader, or syscall implementation.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import resource
import struct
from pathlib import Path

MAX_NATIVE_INPUT = 256 * 1024 * 1024
MAX_MACHO_COMMANDS = 4096
MAX_MACHO_SYMBOLS = 100_000
MAX_RESULT_ROWS = 2000
MAX_MAPPED_BYTES = 64 * 1024 * 1024
STACK_BYTES = 2 * 1024 * 1024
PAGE = 4096

_MACHO_CPUS = {
    7: "x86", 12: "arm", 0x01000007: "x86_64", 0x0100000C: "aarch64",
}
_MACHO_FILE_TYPES = {
    1: "object", 2: "executable", 3: "fixed-vm-library", 4: "core",
    5: "preload", 6: "dylib", 7: "dylinker", 8: "bundle",
    9: "dylib-stub", 10: "dsym", 11: "kext-bundle", 12: "fileset",
}


def _bounded_file(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError("target must be a regular, non-symlink file")
    size = path.stat().st_size
    if size > MAX_NATIVE_INPUT:
        raise ValueError(f"input exceeds {MAX_NATIVE_INPUT} bytes")
    with path.open("rb") as stream:
        data = stream.read(MAX_NATIVE_INPUT + 1)
    if len(data) > MAX_NATIVE_INPUT:
        raise ValueError(f"input exceeds {MAX_NATIVE_INPUT} bytes")
    return data


def _cstr(data: bytes, start: int, end: int, limit: int = 4096) -> str:
    if not 0 <= start <= end <= len(data) or end - start > limit:
        return ""
    stop = data.find(b"\0", start, end)
    if stop < 0:
        stop = end
    return data[start:stop].decode("utf-8", errors="replace")


def _range(offset: int, size: int, length: int) -> bool:
    return 0 <= offset <= length and 0 <= size <= length - offset


def _macho_code_signature(data: bytes, offset: int, size: int) -> dict:
    result = {
        "present": True,
        "offset": offset,
        "size": size,
        "sha256": None,
        "container": "unknown",
        "code_directories": [],
        "cryptographic_verification": "not_performed",
    }
    if not _range(offset, size, len(data)):
        result["error"] = "LC_CODE_SIGNATURE range lies outside the file"
        return result
    blob = data[offset:offset + size]
    result["sha256"] = hashlib.sha256(blob).hexdigest()
    if len(blob) < 8:
        result["error"] = "truncated code-signature blob"
        return result

    directories: list[tuple[int, bytes]] = []
    magic, declared = struct.unpack_from(">II", blob, 0)
    cd_magics = {0xFADE0C02, 0xFADE0C05, 0xFADE0C06, 0xFADE0C07}
    if magic == 0xFADE0CC0 and len(blob) >= 12:
        result["container"] = "embedded-signature-superblob"
        count = struct.unpack_from(">I", blob, 8)[0]
        if declared > len(blob) or count > 256 or 12 + count * 8 > min(declared, len(blob)):
            result["error"] = "invalid SuperBlob length or slot count"
            return result
        result["slot_count"] = count
        for index in range(count):
            slot_type, slot_offset = struct.unpack_from(">II", blob, 12 + index * 8)
            if slot_offset + 8 > min(declared, len(blob)):
                continue
            child_magic, child_size = struct.unpack_from(">II", blob, slot_offset)
            if child_magic in cd_magics and _range(slot_offset, child_size, min(declared, len(blob))):
                directories.append((slot_type, blob[slot_offset:slot_offset + child_size]))
    elif magic in cd_magics and declared <= len(blob):
        result["container"] = "code-directory"
        directories.append((0, blob[:declared]))
    else:
        result["magic"] = f"0x{magic:08x}"

    for slot_type, directory in directories[:32]:
        if len(directory) < 44:
            continue
        fields = struct.unpack_from(">9I4B", directory, 0)
        (_magic, length, version, flags, hash_offset, ident_offset,
         special_slots, code_slots, code_limit, hash_size, hash_type,
         platform, page_size) = fields
        identifier = _cstr(directory, ident_offset, min(length, len(directory)), 1024)
        result["code_directories"].append({
            "slot_type": slot_type,
            "length": length,
            "version": f"0x{version:08x}",
            "flags": f"0x{flags:08x}",
            "identifier": identifier or None,
            "hash_offset": hash_offset,
            "hash_size": hash_size,
            "hash_type": hash_type,
            "platform": platform,
            "page_size_log2": page_size,
            "special_slot_count": special_slots,
            "code_slot_count": code_slots,
            "code_limit": code_limit,
        })
    return result


def _macho_thin(data: bytes, base_offset: int = 0) -> dict:
    magics = {
        b"\xce\xfa\xed\xfe": ("little", 32),
        b"\xcf\xfa\xed\xfe": ("little", 64),
        b"\xfe\xed\xfa\xce": ("big", 32),
        b"\xfe\xed\xfa\xcf": ("big", 64),
    }
    if data[:4] not in magics:
        raise ValueError("unsupported Mach-O magic")
    endian_name, bits = magics[data[:4]]
    endian = "<" if endian_name == "little" else ">"
    header_size = 32 if bits == 64 else 28
    if len(data) < header_size:
        raise ValueError("truncated Mach-O header")
    cpu, subtype, file_type, command_count, command_bytes, flags = struct.unpack_from(
        endian + "IIIIII", data, 4,
    )
    if command_count > MAX_MACHO_COMMANDS or command_bytes > len(data) - header_size:
        raise ValueError("Mach-O load-command bounds are invalid")
    architecture = _MACHO_CPUS.get(cpu, f"cpu-{cpu:#x}")
    segments = []
    sections = []
    dylibs = []
    symbols = []
    imports = []
    exports = []
    uuid = None
    entryoff = None
    build_versions = []
    signature = {"present": False, "cryptographic_verification": "not_applicable"}
    symtab = None
    cursor = header_size
    for _index in range(command_count):
        if cursor + 8 > header_size + command_bytes:
            raise ValueError("truncated Mach-O load command")
        command, size = struct.unpack_from(endian + "II", data, cursor)
        if size < 8 or cursor + size > header_size + command_bytes:
            raise ValueError("invalid Mach-O load-command size")
        base_command = command & 0x7FFFFFFF
        if base_command in {1, 0x19}:
            is_64 = base_command == 0x19
            minimum = 72 if is_64 else 56
            section_size = 80 if is_64 else 68
            if size < minimum:
                raise ValueError("truncated Mach-O segment command")
            segment_name = _cstr(data, cursor + 8, cursor + 24, 16)
            if is_64:
                vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, segflags = struct.unpack_from(
                    endian + "QQQQiiII", data, cursor + 24,
                )
            else:
                vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, segflags = struct.unpack_from(
                    endian + "IIIIiiII", data, cursor + 24,
                )
            if nsects > 4096 or minimum + nsects * section_size > size:
                raise ValueError("Mach-O section table exceeds its load command")
            segments.append({
                "name": segment_name, "virtual_address": hex(vmaddr),
                "virtual_size": vmsize, "file_offset": fileoff,
                "file_size": filesize, "maximum_protection": maxprot,
                "initial_protection": initprot, "flags": f"0x{segflags:08x}",
            })
            section_cursor = cursor + minimum
            for section_index in range(nsects):
                section_offset = section_cursor + section_index * section_size
                section_name = _cstr(data, section_offset, section_offset + 16, 16)
                section_segment = _cstr(data, section_offset + 16, section_offset + 32, 16)
                if is_64:
                    address, section_bytes, file_offset, align, reloc_offset, reloc_count, section_flags, reserved1, reserved2, reserved3 = struct.unpack_from(
                        endian + "QQIIIIIIII", data, section_offset + 32,
                    )
                else:
                    address, section_bytes, file_offset, align, reloc_offset, reloc_count, section_flags, reserved1, reserved2 = struct.unpack_from(
                        endian + "IIIIIIIII", data, section_offset + 32,
                    )
                    reserved3 = None
                sections.append({
                    "index": len(sections) + 1, "name": section_name,
                    "segment": section_segment, "address": hex(address),
                    "size": section_bytes, "file_offset": file_offset,
                    "alignment_power": align, "relocation_offset": reloc_offset,
                    "relocation_count": reloc_count, "flags": f"0x{section_flags:08x}",
                    "reserved1": reserved1, "reserved2": reserved2,
                    **({"reserved3": reserved3} if reserved3 is not None else {}),
                })
        elif base_command == 2 and size >= 24:
            symtab = struct.unpack_from(endian + "IIII", data, cursor + 8)
        elif base_command in {0xC, 0xD, 0x18, 0x1F, 0x20, 0x23} and size >= 24:
            name_offset, timestamp, current_version, compatibility_version = struct.unpack_from(
                endian + "IIII", data, cursor + 8,
            )
            name = _cstr(data, cursor + name_offset, cursor + size)
            dylibs.append({
                "command": f"0x{command:08x}", "name": name,
                "timestamp": timestamp, "current_version": current_version,
                "compatibility_version": compatibility_version,
            })
        elif base_command == 0x1B and size >= 24:
            raw = data[cursor + 8:cursor + 24]
            uuid = "-".join((raw[:4].hex(), raw[4:6].hex(), raw[6:8].hex(), raw[8:10].hex(), raw[10:].hex()))
        elif base_command == 0x1D and size >= 16:
            offset, blob_size = struct.unpack_from(endian + "II", data, cursor + 8)
            signature = _macho_code_signature(data, offset, blob_size)
        elif base_command == 0x28 and size >= 24:
            entryoff, stacksize = struct.unpack_from(endian + "QQ", data, cursor + 8)
        elif base_command == 0x32 and size >= 24:
            platform, minimum_os, sdk, tool_count = struct.unpack_from(endian + "IIII", data, cursor + 8)
            build_versions.append({
                "platform": platform, "minimum_os": f"0x{minimum_os:08x}",
                "sdk": f"0x{sdk:08x}", "tool_count": tool_count,
            })
        cursor += size

    if symtab is not None:
        symoff, count, stroff, strsize = symtab
        entry_size = 16 if bits == 64 else 12
        if count > MAX_MACHO_SYMBOLS:
            raise ValueError("Mach-O symbol count exceeds parser limit")
        if not _range(symoff, count * entry_size, len(data)) or not _range(stroff, strsize, len(data)):
            raise ValueError("Mach-O symbol or string table lies outside the file")
        for index in range(count):
            offset = symoff + index * entry_size
            if bits == 64:
                string_index, symbol_type, section_index, descriptor, value = struct.unpack_from(
                    endian + "IBBHQ", data, offset,
                )
            else:
                string_index, symbol_type, section_index, descriptor, value = struct.unpack_from(
                    endian + "IBBHI", data, offset,
                )
            name = _cstr(data, stroff + string_index, stroff + strsize) if string_index < strsize else ""
            if symbol_type & 0xE0:  # stab/debug symbol
                continue
            type_bits = symbol_type & 0x0E
            external = bool(symbol_type & 0x01)
            row = {
                "name": name, "type": f"0x{symbol_type:02x}",
                "section_index": section_index, "descriptor": f"0x{descriptor:04x}",
                "value": hex(value), "external": external,
            }
            if len(symbols) < MAX_RESULT_ROWS:
                symbols.append(row)
            if external and type_bits == 0 and value == 0 and name:
                if len(imports) < MAX_RESULT_ROWS:
                    imports.append(row)
            elif external and type_bits != 0 and name:
                if len(exports) < MAX_RESULT_ROWS:
                    exports.append(row)

    objc_sections = [row for row in sections if row["name"].startswith("__objc_")]
    swift_sections = [row for row in sections if row["name"].startswith("__swift")]
    objc_symbols = [row["name"] for row in symbols if "OBJC_" in row["name"] or row["name"].startswith("_objc_")]
    swift_symbols = [row["name"] for row in symbols if row["name"].startswith(("$s", "_$s", "__swift"))]
    objc_strings = []
    for section in sections:
        if section["name"] not in {"__objc_methname", "__objc_classname", "__objc_methtype"}:
            continue
        offset, size = section["file_offset"], section["size"]
        if not _range(offset, size, len(data)) or size > 8 * 1024 * 1024:
            continue
        for raw in data[offset:offset + size].split(b"\0"):
            if raw and len(objc_strings) < MAX_RESULT_ROWS:
                objc_strings.append(raw[:512].decode("utf-8", errors="replace"))
    objc_present = bool(objc_sections or objc_symbols or any("libobjc" in row["name"] for row in dylibs))
    swift_present = bool(swift_sections or swift_symbols or any("libswift" in row["name"] for row in dylibs))
    return {
        "schema": "blackwall.macho-metadata.v1",
        "format": "mach-o",
        "slice_offset": base_offset,
        "architecture": {"name": architecture, "bits": bits, "endianness": endian_name,
                         "cpu_type": f"0x{cpu:08x}", "cpu_subtype": f"0x{subtype:08x}"},
        "file_type": _MACHO_FILE_TYPES.get(file_type, f"type-{file_type}"),
        "flags": f"0x{flags:08x}",
        "load_commands": {"count": command_count, "bytes": command_bytes},
        "segments": segments[:MAX_RESULT_ROWS],
        "sections": sections[:MAX_RESULT_ROWS],
        "linked_libraries": dylibs[:MAX_RESULT_ROWS],
        "symbols": {"reported": len(symbols), "items": symbols, "truncated": count > len(symbols) if symtab else False},
        "imports": imports,
        "exports": exports,
        "code_signature": signature,
        "uuid": uuid,
        "entry_file_offset": entryoff,
        "build_versions": build_versions,
        "objective_c": {
            "present": objc_present,
            "sections": [row["name"] for row in objc_sections],
            "symbols": objc_symbols[:MAX_RESULT_ROWS],
            "strings": objc_strings[:MAX_RESULT_ROWS],
        },
        "swift": {
            "present": swift_present,
            "sections": [row["name"] for row in swift_sections],
            "symbols": swift_symbols[:MAX_RESULT_ROWS],
        },
        "limitations": [
            "code-signature structure and digest are reported, but trust-chain and notarization verification are not performed",
            "Objective-C and Swift discovery is based on static sections, symbols, linked libraries, and bounded string tables",
        ],
    }


def macho_metadata(path: Path) -> dict:
    data = _bounded_file(path)
    if data[:4] in {b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf", b"\xbe\xba\xfe\xca", b"\xbf\xba\xfe\xca"}:
        little = data[:4] in {b"\xbe\xba\xfe\xca", b"\xbf\xba\xfe\xca"}
        is_64 = data[:4] in {b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"}
        endian = "<" if little else ">"
        count = struct.unpack_from(endian + "I", data, 4)[0]
        entry_size = 32 if is_64 else 20
        if count > 32 or 8 + count * entry_size > len(data):
            raise ValueError("invalid universal Mach-O architecture table")
        slices = []
        primary = None
        for index in range(count):
            offset = 8 + index * entry_size
            if is_64:
                cpu, subtype, file_offset, size, align, _reserved = struct.unpack_from(endian + "IIQQII", data, offset)
            else:
                cpu, subtype, file_offset, size, align = struct.unpack_from(endian + "IIIII", data, offset)
            valid = _range(file_offset, size, len(data))
            row = {"index": index, "architecture": _MACHO_CPUS.get(cpu, f"cpu-{cpu:#x}"),
                   "cpu_type": f"0x{cpu:08x}", "cpu_subtype": f"0x{subtype:08x}",
                   "offset": file_offset, "size": size, "alignment_power": align, "valid": valid}
            slices.append(row)
            if primary is None and valid:
                primary = _macho_thin(data[file_offset:file_offset + size], file_offset)
        if primary is None:
            raise ValueError("universal Mach-O has no valid slice")
        primary["format"] = "mach-o-universal"
        primary["universal"] = {"slice_count": count, "slices": slices,
                                "analyzed_slice": primary["slice_offset"]}
        result = primary
    else:
        result = _macho_thin(data)
    result["target"] = str(path)
    result["sha256"] = hashlib.sha256(data).hexdigest()
    result["size"] = len(data)
    return result


def _elf_layout(data: bytes) -> dict:
    if len(data) < 52 or data[:4] != b"\x7fELF":
        raise ValueError("target is not an ELF object")
    bits = {1: 32, 2: 64}.get(data[4])
    endian_name = {1: "little", 2: "big"}.get(data[5])
    if bits is None or endian_name is None:
        raise ValueError("unsupported ELF class or byte order")
    endian = "<" if endian_name == "little" else ">"
    object_type, machine = struct.unpack_from(endian + "HH", data, 16)
    if bits == 64:
        if len(data) < 64:
            raise ValueError("truncated ELF64 header")
        entry, phoff = struct.unpack_from(endian + "QQ", data, 24)
        phentsize, phnum = struct.unpack_from(endian + "HH", data, 54)
        expected_ph = 56
    else:
        entry, phoff = struct.unpack_from(endian + "II", data, 24)
        phentsize, phnum = struct.unpack_from(endian + "HH", data, 42)
        expected_ph = 32
    if object_type not in {2, 3}:
        raise ValueError("emulation accepts only ELF executable/shared objects")
    if not entry:
        raise ValueError("ELF has no nonzero entry point")
    if phnum > 1024 or phentsize < expected_ph or not _range(phoff, phentsize * phnum, len(data)):
        raise ValueError("ELF program-header table is invalid")
    segments = []
    total = 0
    for index in range(phnum):
        offset = phoff + index * phentsize
        if bits == 64:
            p_type, flags, file_offset, vaddr, _paddr, file_size, memory_size, align = struct.unpack_from(
                endian + "IIQQQQQQ", data, offset,
            )
        else:
            p_type, file_offset, vaddr, _paddr, file_size, memory_size, flags, align = struct.unpack_from(
                endian + "IIIIIIII", data, offset,
            )
        if p_type != 1:
            continue
        if memory_size < file_size or not _range(file_offset, file_size, len(data)):
            raise ValueError("ELF load segment has invalid file bounds")
        if memory_size > MAX_MAPPED_BYTES or total + memory_size > MAX_MAPPED_BYTES:
            raise ValueError("ELF mapped bytes exceed emulator limit")
        total += memory_size
        segments.append({"index": index, "offset": file_offset, "address": vaddr,
                         "file_size": file_size, "memory_size": memory_size,
                         "flags": flags, "alignment": align})
    if not segments or not any(row["address"] <= entry < row["address"] + row["memory_size"] for row in segments):
        raise ValueError("ELF entry point is not inside a loadable segment")
    return {"bits": bits, "endianness": endian_name, "endian": endian,
            "object_type": object_type, "machine": machine, "entry": entry,
            "segments": segments, "mapped_bytes": total}


def emulate_elf(path: Path, max_instructions: int, timeout_ms: int) -> dict:
    data = _bounded_file(path)
    layout = _elf_layout(data)
    import unicorn
    from unicorn import (
        UC_HOOK_CODE,
        UC_HOOK_MEM_INVALID,
        UC_PROT_EXEC,
        UC_PROT_READ,
        UC_PROT_WRITE,
        Uc,
        UcError,
        arm64_const,
        arm_const,
        mips_const,
        x86_const,
    )

    machine, bits, byteorder = layout["machine"], layout["bits"], layout["endianness"]
    if machine == 3 and bits == 32:
        arch, mode, stack_register, arch_name = unicorn.UC_ARCH_X86, unicorn.UC_MODE_32, x86_const.UC_X86_REG_ESP, "x86"
    elif machine == 62 and bits == 64:
        arch, mode, stack_register, arch_name = unicorn.UC_ARCH_X86, unicorn.UC_MODE_64, x86_const.UC_X86_REG_RSP, "x86_64"
    elif machine == 40 and bits == 32:
        mode = unicorn.UC_MODE_THUMB if layout["entry"] & 1 else unicorn.UC_MODE_ARM
        mode |= unicorn.UC_MODE_BIG_ENDIAN if byteorder == "big" else unicorn.UC_MODE_LITTLE_ENDIAN
        arch, stack_register, arch_name = unicorn.UC_ARCH_ARM, arm_const.UC_ARM_REG_SP, "arm"
    elif machine == 183 and bits == 64 and byteorder == "little":
        arch, mode, stack_register, arch_name = unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM, arm64_const.UC_ARM64_REG_SP, "aarch64"
    elif machine == 8 and bits in {32, 64}:
        mode = unicorn.UC_MODE_MIPS32 if bits == 32 else unicorn.UC_MODE_MIPS64
        mode |= unicorn.UC_MODE_BIG_ENDIAN if byteorder == "big" else unicorn.UC_MODE_LITTLE_ENDIAN
        arch, stack_register, arch_name = unicorn.UC_ARCH_MIPS, mips_const.UC_MIPS_REG_SP, f"mips{bits}"
    else:
        raise ValueError(f"unsupported emulation architecture: ELF machine {machine}, {bits}-bit {byteorder}")

    emulator = Uc(arch, mode)
    pages: dict[int, int] = {}
    for segment in layout["segments"]:
        start = segment["address"] & ~(PAGE - 1)
        end = (segment["address"] + segment["memory_size"] + PAGE - 1) & ~(PAGE - 1)
        permissions = 0
        if segment["flags"] & 4:
            permissions |= UC_PROT_READ
        if segment["flags"] & 2:
            permissions |= UC_PROT_WRITE
        if segment["flags"] & 1:
            permissions |= UC_PROT_EXEC
        for address in range(start, end, PAGE):
            pages[address] = pages.get(address, 0) | permissions | UC_PROT_READ
    for address in sorted(pages):
        emulator.mem_map(address, PAGE, pages[address])
    for segment in layout["segments"]:
        if segment["file_size"]:
            emulator.mem_write(segment["address"], data[
                segment["offset"]:segment["offset"] + segment["file_size"]
            ])

    stack_top = 0x7FFF0000 if bits == 32 else 0x7FFFFFF00000
    stack_base = stack_top - STACK_BYTES
    while any(not (stack_top <= page or stack_base >= page + PAGE) for page in pages):
        stack_top -= STACK_BYTES + PAGE
        stack_base = stack_top - STACK_BYTES
    emulator.mem_map(stack_base, STACK_BYTES, UC_PROT_READ | UC_PROT_WRITE)
    emulator.reg_write(stack_register, stack_top - 16)

    state = {"instructions": 0, "stop_reason": None, "fault": None}
    trace = []

    def is_syscall(code: bytes) -> bool:
        if arch_name in {"x86", "x86_64"}:
            return code.startswith((b"\x0f\x05", b"\xcd\x80", b"\x0f\x34"))
        word = int.from_bytes(code[:4].ljust(4, b"\0"), byteorder)
        if arch_name == "aarch64":
            return (word & 0xFFE0001F) == 0xD4000001
        if arch_name == "arm":
            if mode & unicorn.UC_MODE_THUMB:
                return len(code) >= 2 and code[1] == 0xDF
            return (word & 0xFF000000) == 0xEF000000
        if arch_name.startswith("mips"):
            return (word & 0xFC00003F) == 0x0000000C
        return False

    def on_code(uc, address, size, _user):
        state["instructions"] += 1
        try:
            code = bytes(uc.mem_read(address, min(size, 16)))
        except UcError:
            code = b""
        if len(trace) < 256:
            trace.append({"address": hex(address), "size": size, "bytes": code.hex()})
        if is_syscall(code):
            state["stop_reason"] = "syscall_boundary"
            uc.emu_stop()

    def on_invalid(_uc, access, address, size, value, _user):
        state["stop_reason"] = "invalid_memory"
        state["fault"] = {"access": access, "address": hex(address), "size": size, "value": hex(value)}
        return False

    emulator.hook_add(UC_HOOK_CODE, on_code)
    emulator.hook_add(UC_HOOK_MEM_INVALID, on_invalid)
    error = None
    entry = layout["entry"] & ~1 if arch_name == "arm" and mode & unicorn.UC_MODE_THUMB else layout["entry"]
    try:
        emulator.emu_start(entry, 0, timeout=timeout_ms * 1000, count=max_instructions)
    except UcError as exc:
        error = str(exc)
        if state["stop_reason"] is None:
            state["stop_reason"] = "emulation_error"
    if state["stop_reason"] is None:
        state["stop_reason"] = "instruction_limit" if state["instructions"] >= max_instructions else "completed_or_timeout"
    return {
        "schema": "blackwall.bounded-elf-emulation.v1",
        "target": str(path),
        "sha256": hashlib.sha256(data).hexdigest(),
        "engine": {"name": "Unicorn", "version": importlib.metadata.version("unicorn")},
        "architecture": {"name": arch_name, "bits": bits, "endianness": byteorder},
        "entry": hex(layout["entry"]),
        "segments": layout["segments"],
        "mapped_bytes": layout["mapped_bytes"],
        "stack": {"base": hex(stack_base), "size": STACK_BYTES},
        "instruction_count": state["instructions"],
        "stop_reason": state["stop_reason"],
        "fault": state["fault"],
        "error": error,
        "trace": trace,
        "limits": {
            "max_instructions": max_instructions,
            "timeout_ms": timeout_ms,
            "max_mapped_bytes": MAX_MAPPED_BYTES,
            "trace_rows": 256,
        },
        "execution_boundary": {
            "native_execution": False,
            "syscalls_implemented": False,
            "filesystem": False,
            "network": False,
            "dynamic_loader": False,
        },
    }


def _apply_limits() -> None:
    def tighten(kind: int, value: int) -> None:
        _soft, hard = resource.getrlimit(kind)
        ceiling = value if hard == resource.RLIM_INFINITY else min(value, hard)
        resource.setrlimit(kind, (ceiling, ceiling))
    # Unicorn 2.1 reserves a roughly 1 GiB translator arena before mapping the
    # bounded guest segments.  Leave measured headroom for that arena while
    # retaining a hard worker ceiling.
    tighten(resource.RLIMIT_AS, 1536 * 1024 * 1024)
    tighten(resource.RLIMIT_FSIZE, 16 * 1024 * 1024)
    tighten(resource.RLIMIT_NOFILE, 128)
    tighten(resource.RLIMIT_CORE, 0)
    tighten(resource.RLIMIT_CPU, 120)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="BlackWall bounded native worker")
    sub = parser.add_subparsers(dest="command", required=True)
    macho = sub.add_parser("macho")
    macho.add_argument("path", type=Path)
    emulate = sub.add_parser("emulate-elf")
    emulate.add_argument("path", type=Path)
    emulate.add_argument("--max-instructions", type=int, required=True)
    emulate.add_argument("--timeout-ms", type=int, required=True)
    args = parser.parse_args(argv)
    _apply_limits()
    try:
        if args.command == "macho":
            result = macho_metadata(args.path)
        else:
            if not 1 <= args.max_instructions <= 1_000_000:
                raise ValueError("max_instructions must be between 1 and 1000000")
            if not 1 <= args.timeout_ms <= 60_000:
                raise ValueError("timeout_ms must be between 1 and 60000")
            result = emulate_elf(args.path, args.max_instructions, args.timeout_ms)
        print(json.dumps(result, sort_keys=True, ensure_ascii=False))
    except Exception as exc:
        print(json.dumps({
            "schema": "blackwall.worker-error.v1",
            "error": f"{type(exc).__name__}: {exc}",
        }, sort_keys=True))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
