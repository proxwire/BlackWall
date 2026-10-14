---
name: report
description: Write the final malware analysis report (report.md) for a BlackWall case from notes/findings.md, Ghidra annotations and tool outputs.
---

# Report

Write `report.md` in the case root. Base it on `notes/findings.md` and
re-verify anything uncertain. Use evidence labels (**confirmed / likely /
speculative**) throughout.

```markdown
# <Family or "Unknown"> — <one-line description>

## Executive summary
3–6 sentences: what it is, what it does, impact, confidence.

## Sample
| field | value |  (sha256, sha1, md5, ssdeep/tlsh, imphash, type, size, compile time, original name, first seen)
Layer chain: original → … → final payload (sha256 + how each was obtained)

## Classification
Family/attribution and the evidence for it. Distinguish vendor labels from your own findings.

## Capabilities & behaviour
Per component: what it does, how (key function names/addresses), evidence.
Include short decompiled snippets only where they prove a point.

## Anti-analysis & obfuscation
## Configuration
Decoded config table plus extractor location (notes/extractor.py).

## Network / C2
Protocol, encoding, beacon format, commands table.

## MITRE ATT&CK
| tactic | technique ID | evidence |

## IOCs
Hashes / network / host, each marked verified-in-code or string-only.

## Detections
YARA rules in detections/ with what each one matches.

## Gaps & next steps
What you couldn't determine and why; what dynamic analysis (phase 2) should confirm.
```

Finally, tell the human where the report is and give the 3–5 most important
findings in chat.
