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
     `lab.dotnet_info`).
   - ELF: `lab.elf_info`. Check arch, static/stripped, and the UPX marker.
   - Anything else: `lab.shell` with `file`, `xxd | head`, `binwalk`. Say what
     the format is and pick tools to match.
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
