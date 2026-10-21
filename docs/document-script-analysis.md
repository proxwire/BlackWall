# Bounded document and script analysis

BlackWall routes Office, OLE, OOXML, RTF, PDF, JavaScript/JScript, VBScript,
VBA source, and PowerShell to static-only tools in the strict profile. No
Office application, PDF renderer, PowerShell host, Windows Script Host, or
JavaScript engine is installed or invoked by this lane.

## Operations

| tool | purpose |
|---|---|
| `lab.document_triage` | Inventory bounded document structure and report active content, external relationships, URLs, commands, DDE fields, PDF actions, and parser gaps with part/stream/object provenance. |
| `lab.document_vba` | Run pinned `oletools==0.60.2` `olevba` JSON extraction with decoding, expression deobfuscation, and revealed VBA source. P-code extraction is disabled to keep this source-oriented pass bounded. |
| `lab.document_extract_artifacts` | Extract selected OOXML active parts, OLE package/VBA streams, RTF `objdata`, and PDF embedded/active streams under generated names, then register their bytes as `document-embedded-artifact` children. |
| `lab.script_analyze` | Detect script-specific behavior and statically decode literal concatenation, JS `String.fromCharCode`, VB/VBA `Chr` chains and `StrReverse`, Base64/hex, escapes, and PowerShell encoded commands. |
| `lab.script_extract_payloads` | Admit only useful encoded payload candidates to the derived store as `script-decoded-payload` children, retaining the transform, source offset, digest, and depth. |

The router makes triage and safe extraction ready steps. It keeps REA's
directory/ASAR JavaScript workflow for packaged Electron applications but
does not send standalone scripts or documents to an incompatible native
workflow. Broad Binwalk scanning is no longer the default document parser.

## Bounds and containment

Document input is capped at 128 MiB and script input at 8 MiB. The default
document triage inventories at most 1,024 container members and decodes at
most 2 MiB per member and 16 MiB of content in aggregate. Extraction defaults
to 32 artifacts, 8 MiB each, 32 MiB total, and two nested OOXML levels. ZIP
expansion greater than 100:1 is rejected. RTF group depth is reported and a
depth over 64 is a parser gap; PDF and result inventories have fixed
object/finding caps. Structural parsing may inspect the bounded raw document
beyond the decoded-content budget, but it cannot emit or extract those bytes.

The purpose-built worker runs in its own supervised process group with a
wall-clock deadline and an 8 MiB combined-output cap. It also applies a 768
MiB address-space limit, a 64 MiB file limit, a 128-descriptor limit, and no
core dumps while preserving any stricter inherited ceiling. Container-wide
memory, CPU, process, filesystem, and network restrictions still apply.

Archive and document names are evidence only. Extracted files are named
`artifact-NNNN.bin` in a fresh private temporary directory. The MCP process
rechecks that each result is a regular non-symlink beneath that directory,
matches its reported size and SHA-256, and stays inside caller-selected count
and byte budgets before registering it. Attacker-controlled names never become
paths. Complete parser JSON is retained under `/work/out`; the bounded MCP
response is secret-redacted and points back to that file for evidence capture.

## Evidence and limitations

Recovered values record their source part, OLE stream, RTF byte offset, PDF
object, or script transform layer. Document relationships retain relationship
type, target, mode, and whether the target is external. Extracted bytes receive
normal parent/child lineage and are routed like any other derived artifact.

This is triage, not a complete Office or PDF implementation. The OOXML reader
does not render fields; the PDF scanner follows bounded object bodies and only
inflates Flate streams; malformed cross-reference tables, uncommon filters,
encrypted documents, XLM behavior, VBA stomping, and runtime-generated script
values can remain invisible. `olevba --no-pcode` is a deliberate source-code
tradeoff, so suspicious source/P-code divergence requires a separate expert
review. Regex-based script detections can produce false positives and decoded
commands are evidence of content, not proof they ran. Microsoft Script Encoder
`.jse`/`.vbe` bodies and values requiring runtime evaluation are not decoded by
this lane.

The inert corpus exercises external OOXML relationships, a macro-enabled
spreadsheet, OOXML/RTF/PDF embedded data, a PDF JavaScript action, concatenated
JavaScript, PowerShell encoded commands, VBScript/VBA character chains, and
Base64-carried payloads. The attributed XlsxWriter VBA project is never
executed; its BSD-2-Clause notice is committed beside the source representation.
