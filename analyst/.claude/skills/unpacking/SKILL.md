---
name: unpacking
description: Unpack or de-layer packed, crypted or staged malware (UPX, custom packers, .NET crypters, shellcode loaders, embedded payloads) inside the BlackWall sandbox, and register each layer for analysis.
---

# Unpacking

Work from cheapest to most expensive. After each success, register the layer,
import it into Ghidra (`ghidra.import_binary` with the derived path), re-run
triage steps 1–5 on it, and record the layer chain in `notes/findings.md`
(original → layer1 → layer2, with sha256s and how each was obtained).

1. **Known packers.** If DIE or YARA says UPX, run `lab.upx_unpack`. If that
   fails, the UPX headers were probably tampered with: compare the `UPX!`
   magic, section names, and l_info against a clean UPX layout, repair them in
   `lab.run_python`, then retry.
2. **Embedded payloads.** `lab.carve_embedded` finds PEs/ELFs in overlays and
   resources without waiting for binwalk; run `lab.binwalk_scan` separately
   when signature scanning will help. For managed assemblies, try
   `lab.dotnet_extract_resources` first. For high-entropy native PE resources
   or overlays, dump them (`lab.extract_pe_resource` or slice in `run_python`)
   and look for the decryption routine in Ghidra: xrefs to
   `FindResource`/`LoadResource`/`SizeofResource`, or to the overlay offset.
   Then reimplement it.
3. **Emulation.** `lab.emulate_windows` lets the stub decrypt itself in
   Speakeasy. Look at `dumped_to_derived`, VirtualAlloc/VirtualProtect/
   WriteProcessMemory calls, and dynamic API resolution. For shellcode, pass
   `shellcode_arch`. If emulation stops at an unsupported API or an anti-emulation
   check, find that code in Ghidra and patch or skip it (patch bytes in a
   scratch copy with `run_python`, then register it).
4. **Static decryption.** Find the decrypt loop (high-entropy blob xref plus a
   loop with XOR/ADD/ROL, RC4 KSA `0..255` init, AES S-box constants, and so
   on), extract the key, and decrypt in `run_python`. Try simple XOR/rolling-XOR
   brute force first on short blobs with known plaintext (`MZ`,
   `This program`).
5. **.NET crypters.** Use `dotnet_info` for resource names and user strings,
   REA's `managed`, `managed_members`, and `managed_native_boundaries` static
   workflows for CIL anchors and P/Invoke declarations, and parse/decrypt
   resources with `run_python` + dnfile. Note that Ghidra is weak on IL; say so
   in your notes when it limits your confidence.
6. **Still packed?** Write down exactly what blocks you (anti-emulation,
   VM-based protector, needs real Windows APIs), what you tried, and suggest
   phase-2 dynamic analysis (a detonation VM). Don't fake progress.
