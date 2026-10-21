---
name: config-extraction
description: Locate, decrypt and parse an embedded malware configuration (C2 servers, keys, campaign IDs, mutex, install paths) and produce a reusable extractor script.
---

# Config extraction

1. **Find it.** Look for xrefs from the C2/init code to a blob in `.data`/
   `.rdata`/resources/overlay, high-entropy regions next to key-looking
   material, base64 blobs in FLOSS output, or (for .NET) static fields and
   resources.
2. **Understand the decoding** in Ghidra: the algorithm, the key source
   (hardcoded, derived, appended to the blob), and the layout (delimiters,
   length-prefixed fields, struct, JSON, protobuf).
3. **Try a reviewed extractor.** Call `lab.config_extractors` and, when a
   family marker or carrier matches, `lab.config_extract`. Preserve its
   low/medium/high tier, numeric score, validation reasons, and byte locations;
   a high-confidence parse is still not proof of family attribution. The
   registry is static package code, so never try to load a module named by the
   sample. Apply the operation to registered derived layers as well as the
   original.
4. **Write an extractor when no reviewed plugin matches.** In the expert profile, test it with
   `lab.run_python`. It should be a standalone function
   `extract(data: bytes) -> dict` that locates the config by pattern (not a
   fixed offset, where possible) so it works on sibling samples. Test it on the
   sample and on every derived layer. In strict mode, use the bounded parsing,
   resource, byte-reading, and emulation tools first. You may draft the
   extractor in `notes/extractor.py`, but do not claim its output was tested;
   document the exact blocked operation if execution is essential.
5. **Save** the extractor to `notes/extractor.py` on the host (Write tool) and,
   when actually recovered, the decoded config to `notes/config.json`.
6. **Verify** the C2 indicators only through `intel.threatfox_ioc` /
   `intel.urlhaus_host`. Never contact them.
7. Optionally use `intel.malwarebazaar_family` to find siblings. You can't
   download them from inside the case; note their hashes as suggested
   follow-up cases (`blackwall pull <sha256>`).
