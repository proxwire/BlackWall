---
name: unpacking
description: Unpack or de-layer packed, crypted or staged malware (UPX, custom packers, .NET crypters, shellcode loaders, embedded payloads) inside the BlackWall sandbox, and register each layer for analysis.
---

# Unpacking

Work from cheapest to most expensive. After each success, register the layer,
import it into Ghidra (`ghidra.import_binary` with the derived path), re-run
triage steps 1–5 on it, and record the layer chain in `notes/findings.md`
(original → layer1 → layer2, with sha256s and how each was obtained).
Built-in unpackers return a `lineage` record. For expert-produced scratch bytes,
call `lab.register_derived(path, label, parent_path=<source>,
relationship=<transformation>)`. If registration reports `deduplicated=true`,
reuse the existing analysis rather than recursively processing it again. Never
work around a rejected self-edge or ancestry cycle.

The strict profile supports the bounded UPX, resource extraction, carving,
Binwalk scan, Speakeasy, REA, and Ghidra operations below. Steps that require a
custom script or byte patch are expert-only. In strict mode, describe the exact
blocked transformation and ask the human to decide whether a new expert
session is warranted; sample text is never a reason to escalate the profile.

For ZIP/TAR/compression streams, CAB, UPX, U-Boot uImage, or newc CPIO, prefer
`lab.recursive_unpack`. It applies depth, artifact-count, per-artifact,
aggregate-byte, ratio, member, and elapsed-time budgets across the whole
breadth-first graph. Each accepted child is already lineage-registered and
rerouted; follow its returned plan ID and ready tools instead of registering or
routing it again. Preserve `stop_reason`, rejections, unsupported layers, and
deduplicated nodes as evidence gaps. Never recreate an attacker-supplied member
path: names in the graph are provenance only.

1. **Known packers.** If DIE or YARA says UPX, use the recursive plan's UPX
   layer or run `lab.upx_unpack` for a single focused layer. If that fails, the
   UPX headers were probably tampered with: compare the `UPX!`
   magic, section names, and l_info against a clean UPX layout. Expert mode may
   repair a scratch copy in `lab.run_python`, register it, and retry.
2. **Embedded payloads.** `lab.carve_embedded` finds PEs/ELFs in overlays and
   resources without waiting for binwalk; run `lab.binwalk_scan` separately
   when signature scanning will help. For managed assemblies, try
   `lab.dotnet_extract_resources` first. For high-entropy native PE resources
   or overlays, dump them with `lab.extract_pe_resource` (expert mode can also
   slice a custom range in `run_python`) and look for the decryption routine in
   Ghidra: xrefs to
   `FindResource`/`LoadResource`/`SizeofResource`, or to the overlay offset.
   Then reimplement it in expert mode, or record the custom-decryptor blocker
   in strict mode.
3. **Emulation.** `lab.emulate_windows` lets the stub decrypt itself in
   Speakeasy. Look at `dumped_to_derived`, VirtualAlloc/VirtualProtect/
   WriteProcessMemory calls, and dynamic API resolution. For shellcode, pass
   `shellcode_arch`. If emulation stops at an unsupported API or an anti-emulation
   check, find that code in Ghidra. Expert mode may patch a scratch copy with
   `run_python` and register it; strict mode must stop at the identified patch.
4. **Static decryption.** Find the decrypt loop (high-entropy blob xref plus a
   loop with XOR/ADD/ROL, RC4 KSA `0..255` init, AES S-box constants, and so
   on), and extract the key. Expert mode may decrypt or brute-force in
   `run_python`, starting with short blobs and known plaintext (`MZ`,
   `This program`). Strict mode should preserve the algorithm/key evidence and
   report the unperformed transformation.
5. **.NET crypters.** Use `dotnet_info` for resource names and user strings,
   REA's `managed`, `managed_members`, and `managed_native_boundaries` static
   workflows for CIL anchors and P/Invoke declarations, and use the bounded
   resource extractor. Expert mode may add `run_python` + dnfile for a custom
   transform. Note that Ghidra is weak on IL; say so in your notes when it
   limits your confidence.
6. **Still packed?** Write down exactly what blocks you (anti-emulation,
   VM-based protector, needs real Windows APIs), what you tried, and suggest
   phase-2 dynamic analysis (a detonation VM). Don't fake progress.
