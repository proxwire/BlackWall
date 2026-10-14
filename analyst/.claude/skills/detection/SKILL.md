---
name: detection
description: Write and validate YARA detection rules (and hunting notes) for the analyzed malware family, testing them against the sample and its derived layers in the BlackWall sandbox.
---

# Detection engineering

1. Build signatures from **code**, not just strings: unique decrypt loops,
   API-hash constants, config-parsing routines, and protocol constants. Pull
   the bytes with `ghidra.read_bytes` or `lab.hexdump` and wildcard
   operand/address bytes (`??`).
2. Add strong strings: decrypted strings are better as hunting notes, but
   unique PDB paths, mutexes, and user agents can be rule strings.
3. Write at least:
   - one **family rule** that targets the unpacked payload and should survive
     recompiles
   - one **loader/packed rule** if a packer layer is distinctive
   Use a `meta:` block with author `BlackWall/AI-assisted`, date, sha256 of the
   reference sample, description, and confidence.
4. Validate with `lab.yara_test(rule, save_as=...)`. It must match the
   intended layers. Keep conditions tight (`uint16(0)==0x5A4D`, filesize
   bounds, `N of` sets) to avoid false positives on generic code. Note FP risk
   in the rule's meta.
5. List host and network hunting indicators in `notes/findings.md`: file paths,
   registry keys, mutexes, scheduled tasks, services, user agents, URI
   patterns, and JA3/TLS details if known.
