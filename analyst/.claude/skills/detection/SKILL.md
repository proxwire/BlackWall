---
name: detection
description: Generate evidence-linked YARA, Sigma, Suricata, and ATT&CK detection candidates for analyzed malware and validate them against the evidence and available fixtures.
---

# Detection engineering

1. Build signatures from **code**, not just strings: unique decrypt loops,
   API-hash constants, config-parsing routines, and protocol constants. Pull
   the bytes with `ghidra.read_bytes` or `lab.hexdump` and wildcard
   operand/address bytes (`??`).
2. Add strong strings: decrypted strings are better as hunting notes, but
   unique PDB paths, mutexes, and user agents can be rule strings.
3. Generate at least:
   - one **family rule** that targets the unpacked payload and should survive
     recompiles
   - one **loader/packed rule** if a packer layer is distinctive
   Use a `meta:` block with author `BlackWall/AI-assisted`, date, sha256 of the
   reference sample, description, and confidence.
4. Prefer `lab.generate_yara_candidate` with the evidence IDs, strong literal
   or byte/wildcard anchors, and every intended positive layer. It compiles the
   rule and tests all positives plus the bundled inert negative corpus before
   export. Use `lab.yara_test` only for a manually authored condition and state
   that it did not receive the generator's negative-set validation claim.
5. When evidence includes suitable telemetry, use
   `lab.generate_sigma_candidate` or `lab.generate_suricata_candidate`; never
   invent fields that the selected telemetry cannot observe.
6. Select ATT&CK behaviors only from `lab.attack_behavior_catalog`, then call
   `lab.attack_map_behavior` with exact evidence and confidence. DLL
   side-loading is `T1574.002`, not `T1574.001`.
7. List host and network hunting indicators in `notes/findings.md`: file paths,
   registry keys, mutexes, scheduled tasks, services, user agents, URI
   patterns, and JA3/TLS details if known.
