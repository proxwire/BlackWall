---
name: triage
description: First-pass triage of a malware sample in a BlackWall case. Identify the file type, packer, capabilities, strings, and IOCs, check reputation, and decide where to dig. Use at the start of every case.
---

# Triage

Goal: within about 15 tool calls, know what you're holding and plan the deep dive.

1. Call `lab.list_samples`, then `lab.analysis_plan(path=<original>,
   phase="full")` before invoking an analyzer. Read its detection evidence,
   architecture, packing state, selected steps, skipped tools, deadlines, and
   fallbacks. If this is a resumed plan, execute only
   `checkpoint.remaining_ready_steps`; do not rebuild `completed` work or
   automatically retry `recorded_gap` work. Execute pending **triage** steps in
   list order. Keep deferred steps for deep analysis after their required
   procedure, class, or feature is known. Do not run a skipped engine merely
   because it is available.
2. `lab.file_overview` is normally the first selected analyzer. Compare its
   libmagic and Detect-It-Easy evidence with the router. If DIE supplies a
   stronger packing verdict, call `lab.analysis_plan` again with
   `packing_state="packed"`, `"not_packed"`, or `"unknown"`; otherwise retain
   the deterministic original plan. Treat disagreement as a finding, not a
   reason to silently switch formats.
3. Follow the format route rather than running every engine:
   - Native PE/ELF/Mach-O stays in BlackWall's persistent Ghidra workspace.
     Also retain the ready REA ELF-layout or `macho_info` metadata step selected
     by the plan; a supplied ELF core takes the recorded-crash route and is not
     imported as an executable. Use capa addresses or Ghidra findings to satisfy deferred
     `rea_native_function`, `rea_native_trace`, or `rea_native_value_flow`
     inputs. A broad REA native overview is intentionally skipped unless the
     image is unusual or evidence conflicts.
   - Managed PE uses the bounded dnfile/ILSpy inventory and resource steps,
     followed by token-selected C# and call analysis plus independent REA
     managed workflows. A mixed-mode verdict additionally keeps Ghidra for the
     native half. APK starts with bounded JADX-backed resources/package evidence
     and defers focused Java/Kotlin source until a class or method is selected.
     Packaged JavaScript/Electron, WASM, EVM, packet/web captures, and SQLite
     use the focused REA operation and explicit format/encoding selected by the
     plan.
   - Office/OLE/OOXML/RTF/PDF routes use `document_triage`, optional
     `document_vba`, and `document_extract_artifacts`. JavaScript/JScript,
     VBScript, VBA source, and PowerShell use `script_analyze` and
     `script_extract_payloads`; these are static and do not invoke native
     interpreters. Use `recursive_unpack` for supported archive, CAB, UPX,
     U-Boot uImage, and newc CPIO layers; it registers and reroutes every child
     under global graph budgets. Route individually extracted children only
     from their returned lineage. Unknown data stays on conservative metadata/
     signature steps. Unsupported format is a coverage gap, not proof
     that a file is malformed or benign.
   - Never invoke REA's raw CLI. Use only the allowlisted `lab.rea_*` tools.
4. After every planned call—including success—call
   `lab.normalize_analysis_result(step_id, tool_name, result=<result>,
   plan_id=<plan_id>, findings=[...])` (or pass `error=<message>` for a tool
   exception). Use finding objects with `subject`, `value`, and optional
   `location`/`confidence`. This retains exact output and advances the durable
   checkpoint. For partial, unsupported, timeout, cancellation, parser crash,
   skipped, or failed results, record the normalized gap, try the listed
   fallback, and continue independent steps. When normalizing a fallback, keep
   the original `step_id`, use the fallback's tool name, and pass the exact
   `command_arguments` used. Do not rewrite failure as success or omit it from
   notes.
5. `intel.malwarebazaar_hash` and `intel.virustotal_file` on the sha256. Known
   family names are hypotheses to verify, not conclusions.
6. Packing verdict. If packed or obfuscated (entropy > 7.2 in code, few imports,
   capa mostly empty, DIE packer hit), switch to the **unpacking** skill before
   deep analysis.
7. For a native route, use `ghidra.list_project_binaries` to record the ready
   program name and semantic-index state, then decompile the entry point /
   `main` / `DllMain` to confirm the program's shape. The MCP connection itself
   is gated on completed Ghidra analysis; record an unexpected non-ready state
   as a failure rather than sleeping and retrying blindly.

Write `notes/findings.md` → `## Triage` with:
- an identity table (hashes, type, size, compiler or packer, compile time, imphash)
- the reputation summary
- the top capa capabilities with ATT&CK IDs
- notable strings and candidate IOCs, marked *unverified*
- your hypothesis and a prioritized list of functions or areas for deep analysis
