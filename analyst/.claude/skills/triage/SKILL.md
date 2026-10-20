---
name: triage
description: First-pass triage of a malware sample in a BlackWall case. Identify the file type, packer, capabilities, strings, and IOCs, check reputation, and decide where to dig. Use at the start of every case.
---

# Triage

Goal: within about 15 tool calls, know what you're holding and plan the deep dive.

1. `lab.list_samples`, then `lab.file_overview` on the original. Note the type,
   the DIE verdict (compiler, packer, protector, installer), and the entropy.
2. Format details:
   - PE: `lab.pe_info`. Look at compile time, imphash, sections (high entropy,
     RWX, odd names), sparse imports (a packer sign), TLS callbacks, overlay,
     large or high-entropy resources, and the `dotnet` flag (if set, also run
     `lab.dotnet_info`, `lab.rea_static_analysis(workflow="managed")`,
     `lab.rea_managed_members`, and
     `lab.rea_static_analysis(workflow="managed_native_boundaries")`). Use the
     REA `pe_resources` workflow when resource identity, exact byte ranges, or
     payload hashes matter. Use `lab.rea_objdump(operation="file_headers" or
     "section_headers")` when an evidence-wrapped second view of native headers
     is useful; `pe_info` remains the richer PE triage result.
     For an unusual native image or when independent evidence will help, add
     `lab.rea_native_overview`; use `lab.rea_native_load_image` before trusting
     addresses in malformed or heavily packed files. These enhance rather than
     replace BlackWall's persistent Ghidra analysis.
   - ELF: `lab.elf_info`. Check arch, static/stripped, and the UPX marker.
     If DIE/compiler evidence indicates Go or Rust, add the matching REA `go`
     or `rust` workflow. `lab.rea_objdump` can retain a second static header,
     section, symbol, relocation, DWARF, or disassembly view.
   - APK: REA `android`, then `lab.rea_android_search`,
     `lab.rea_android_class`, and `lab.rea_android_method` to follow relevant
     code without installing the package.
   - JavaScript/Electron: REA `javascript`; add `electron_fuses` for Electron.
   - WASM, Flutter/Dart AOT, PCAP, and SQLite: use the matching
     `rea_static_analysis` workflow. Use
     `lab.rea_evm_interface` for EVM bytecode and `lab.rea_web_capture` for
     retained HAR/mitmproxy/SAZ/qlog evidence because their encoding/format
     must be explicit.
   - Apple archives and app bundles: the portable `interface_builder`,
     `keyed_archive`, and `dylib_resolution` workflows work in this Linux lab;
     do not claim macOS-only signature/plist tooling is available.
   - Firmware: use `lab.binwalk_scan` for signature hypotheses and
     `lab.carve_embedded` for bounded extraction. REA's Binwalk 3 adapter is
     not enabled because this image currently carries BlackWall's Binwalk 2
     workflow.
   - For a supported archive or unfamiliar application package, try REA
     `artifact`; an explicit unsupported-format result is not evidence that the
     file is malformed. Raw CAB files are handled by BlackWall's existing 7z/
     resource workflow rather than REA 6.7.0.
   - Anything else: `lab.shell` with `file`, `xxd | head`, `binwalk`. Never
     invoke REA's raw CLI; use only the allowlisted `lab.rea_*` tools.
3. `intel.malwarebazaar_hash` and `intel.virustotal_file` on the sha256. Known
   family names are hypotheses to verify, not conclusions.
4. `lab.capa` gives capabilities with addresses; these are your Ghidra entry
   points. `lab.floss` gives decoded and stack strings. Then `lab.extract_iocs`.
5. `lab.yara_scan`.
6. Packing verdict. If packed or obfuscated (entropy > 7.2 in code, few imports,
   capa mostly empty, DIE packer hit), switch to the **unpacking** skill before
   deep analysis.
7. In Ghidra: `ghidra.list_project_binaries` (analysis may still be running;
   retry if needed), then decompile the entry point / `main` / `DllMain` to
   confirm the program's shape.

Write `notes/findings.md` → `## Triage` with:
- an identity table (hashes, type, size, compiler or packer, compile time, imphash)
- the reputation summary
- the top capa capabilities with ATT&CK IDs
- notable strings and candidate IOCs, marked *unverified*
- your hypothesis and a prioritized list of functions or areas for deep analysis
