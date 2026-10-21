---
name: deep-analysis
description: Systematic function-level reverse engineering of a (unpacked) malware sample with Ghidra MCP — map components, resolve obfuscation, annotate the Ghidra project, and document behaviour with evidence.
---

# Deep analysis

## 1. Map, then dive
- Start from the entry point / `main` / exports / TLS callbacks and walk the
  call graph (`ghidra.gen_callgraph`) two or three levels deep. Draft a
  component map in `notes/findings.md`: init, anti-analysis, persistence,
  config, C2 loop, command handlers, payload logic.
- Seed priorities from the capa addresses and from xrefs to key imports and
  strings (`ghidra.list_xrefs`, `ghidra.search_strings`, `ghidra.search_code`).
- After identifying a high-value native function, use
  `lab.rea_native_function` for a second, evidence-oriented dossier. Use
  `lab.rea_native_trace` for visible feature strings/symbols and
  `lab.rea_native_value_flow` selectively for crypto, config, C2, persistence,
  injection, or command dispatch. Feed useful conclusions back into the
  persistent Ghidra project; REA's temporary Ghidra project is not a substitute
  for BlackWall annotations.
- For .NET, use MethodDef tokens from `lab.dotnet_inventory`, locate relevant
  bodies with `lab.dotnet_search`, map static callers/callees with
  `lab.dotnet_call_references`, and send only selected tokens to
  `lab.dotnet_decompile`. Use `lab.rea_managed_members` as an independent CIL
  view and native-boundary cross-check. Reflection, delegates, and runtime
  dispatch remain explicit gaps. For APK targets, start from
  `lab.android_resources`, use `lab.rea_android_*` to identify relevant classes
  and methods, then call `lab.android_decompile` for the selected Java/Kotlin
  scope. Never call REA's runtime commands or install an APK.
- For documents, pivot from `lab.document_triage` provenance into each
  lineage-linked result from `lab.document_extract_artifacts`; use
  `lab.document_vba` source/deobfuscation and relationships to connect macros,
  commands, URLs, and dropped content. For scripts, prioritize high-severity
  `lab.script_analyze` rules and decoded transform layers, then recursively
  route children from `lab.script_extract_payloads`. Recovered text is static
  evidence, not proof of execution.
- For Mach-O, use `lab.macho_info` to seed dylib, import, Objective-C, and Swift
  pivots into persistent Ghidra. Treat code-signature structure and hashes as
  metadata, not trust verification. For ELF, use the exact-profile layout pass
  as a static cross-check and invoke `lab.emulate_elf` only when the plan's
  deferred justification is met. Its trace stops at syscalls and is not native
  execution or a substitute for operating-system behavior.

## 2. Per function

For IL-only .NET, substitute the token-selected `lab.dotnet_decompile` and
`lab.dotnet_call_references` operations for the Ghidra steps below. Normalize
their output and cite its evidence, but do not attempt Ghidra renames on CLR
metadata. Mixed-mode plans expose Ghidra for the native half.

1. `ghidra.decompile_function` (include callees/xrefs when useful).
2. Work out its purpose, then **write it back**:
   - retain an unplanned decompile/trace with `lab.normalize_analysis_result`,
     passing the content-addressed `artifact_path` and exact
     `command_arguments`, so it has an evidence ID
   - `rename_function` with verb-first names (`decrypt_config`, `c2_send_beacon`)
   - `rename_variable`, `set_variable_type`, `set_function_prototype`
   - `set_comment` with a one-line summary plus anything non-obvious
   - call `lab.link_evidence_claim` with `claim_type="annotation"`, the address
     as `location`, and the evidence IDs that support the conclusion; include
     its `[evidence:claim_…]` token in the comment
3. Move bottom-up: annotating leaf helpers first makes their callers readable.
4. Skip CRT/compiler/library code once you recognize it; give it a name like
   `lib_memcpy` and move on.

## 3. Obfuscation playbook
- **String encryption.** Find the decrypt routine. In expert mode, reimplement
  it in `lab.run_python`, decrypt every call site's arguments (collect them
  from xrefs), and add each plaintext as a comment at its call site. In strict
  mode, rely on Ghidra, FLOSS, Speakeasy, and bounded byte reads; document a
  custom-decryptor blocker instead of trying to obtain code execution.
- **API hashing.** Identify the algorithm (ROR13, CRC32, djb2, FNV-1a, custom),
  then reuse the Speakeasy trace or other static evidence. Expert mode may hash
  export names from common DLLs in `run_python`. Rename resolved
  function-pointer globals only when the mapping is supported by evidence.
- **Control-flow flattening / opaque predicates.** Note them, focus on the
  data flow, and cross-check with REA's focused native tools when the
  decompiler struggles. The expert profile can additionally use radare2.
- **Crypto.** Identify algorithms by constants (AES S-box, RC4 KSA, ChaCha
  `expand 32-byte k`, CRC tables, RSA/BCrypt/CryptoAPI imports). Record the
  key's origin.

## 4. Behaviour checklist (report confirmed / likely / not seen)
Execution flow and anti-analysis · persistence · privilege escalation ·
defense evasion · injection · credential access · discovery · lateral movement ·
collection · C2 (protocol, encoding, beacon format, commands) ·
exfiltration · impact (encryption, wiping, mining) · self-deletion/update.

## 5. Checkpoints
After each component, append to `notes/findings.md` with addresses and evidence
IDs. If your context gets long, summarize there before moving on.
