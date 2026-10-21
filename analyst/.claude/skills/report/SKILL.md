---
name: report
description: Write the final malware analysis report (report.md) for a BlackWall case from notes/findings.md, Ghidra annotations and tool outputs.
---

# Report

Write `report.md` in the case root. Base it on `notes/findings.md` and
re-verify anything uncertain. Use evidence labels (**confirmed / likely /
speculative**) throughout.

Before writing, call `lab.evidence_status` and resolve any material finding
that has no evidence record. Preserve any returned engine disagreement in the
relevant section or in Gaps; do not choose a variant silently. For each
material conclusion, call
`lab.link_evidence_claim` with `claim_type="report"`, the report section as
`location`, and every supporting evidence ID. Put the returned
`[evidence:claim_…]` token next to that conclusion. Multiple nearby facts may
share one claim only when the same evidence supports the complete statement.

```markdown
# <Family or "Unknown"> — <one-line description>

## Executive summary
3–6 sentences: what it is, what it does, impact, confidence.

## Sample
| field | value |
|---|---|
| analysis profile | strict or expert (copy `analysis_profile.name` from case.json and state whether custom process tools were available) |
| analysis plan | plan ID, detected format/architecture, packing verdict |
Include sha256, sha1, md5, ssdeep/tlsh, imphash, type, size, compile time,
original name, and first seen when available.
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
List every normalized partial, unsupported, timeout, skipped, or failed plan
step and whether its fallback succeeded. Then state what you couldn't determine
and why, and what dynamic analysis (phase 2) should confirm.
```

Add an `## Evidence audit` section with the counts and result from
`lab.audit_evidence`. Run the whole-case audit after the report links are
created. Do not present the report as complete if retained output, artifact
hashes, lineage, or claim references fail verification; document the exact
audit issue instead.

Finally, tell the human where the report is and give the 3–5 most important
findings in chat.
