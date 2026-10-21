# Evidence, lineage, and resume model

BlackWall keeps the audit state for each case under `/work/state` in the case's
persistent analysis volume. The state is written atomically under a case-wide
file lock. Sample bytes and retained tool output never leave the networkless
analysis container through this mechanism.

## Versioned records

The ledger uses these JSON schemas:

| schema | purpose |
|---|---|
| `blackwall.evidence-record.v1` | One planned tool outcome, including tool/version, command identity and arguments, source artifact and parents, timestamps, confidence, truncation state, normalized status/gap, and cryptographic references to retained output. |
| `blackwall.artifact-lineage.v1` | Content-addressed originals and derived artifacts plus parent → child transformation edges. |
| `blackwall.finding-index.v1` | Canonical finding groups, equivalent-value provenance, and non-destructive disagreement variants. |
| `blackwall.analysis-checkpoint.v1` | Stable plan steps and their immutable evidence attempts, used to resume a plan. |
| `blackwall.evidence-claim.v1` | A report statement, note, or analyst annotation linked to one or more evidence records. |
| `blackwall.evidence-audit.v1` | Hash and reference validation results for a claim or the full case ledger. |

Evidence IDs and claim IDs are hashes of their stable identity fields. The
result snapshot is always retained under `/work/state/outputs`; when a tool
also writes full output under `/work/out`, its bytes are copied to an immutable,
content-addressed file under `/work/state/outputs` and the original path is kept
as provenance. The snapshot records the normalized call result.
`audit_evidence` re-hashes both, the source artifact, and every lineage artifact.

## Planned analysis and resume

`lab.analysis_plan` still returns the router's deterministic `plan_id`. It also
creates or opens the matching checkpoint and annotates each selected step with
one of:

- `pending`: ready and not previously attempted;
- `deferred`: waiting for the inputs listed by the plan;
- `completed`: its most recent recorded outcome was successful;
- `recorded_gap`: its most recent partial, unsupported, timed-out, cancelled,
  crashed, failed, or skipped outcome is preserved.

Automation should run only `checkpoint.remaining_ready_steps`. Every planned
outcome—including success—must be passed to
`lab.normalize_analysis_result(..., plan_id=<plan_id>)`. The call snapshots the
result, creates an evidence record, and advances the checkpoint. Retrying the
same exact result is idempotent. A later explicit retry may add a new attempt;
it never erases the earlier gap.
If interruption lands after the immutable evidence write but before the
checkpoint update, reopening the plan reconciles that record by plan and step
identity and marks the attempt recovered instead of rerunning the analyzer.

A planned fallback is recorded against the original step ID with the fallback
tool name and its exact `command_arguments`. Unlisted tools are rejected for
that step, so a checkpoint cannot silently attribute unrelated output to the
planned command.

Focused Ghidra work and other useful observations may be outside a router step.
They use the same normalizer without a plan ID, supplying the content-addressed
`artifact_path` and exact `command_arguments`. These standalone evidence
records are auditable and claim-linkable but do not change a plan checkpoint.

The .NET route follows the same contract. ILSpy inventory, resource listings,
full bounded C#/CIL output, method search, and call-reference results expose a
`saved_to` path that normalization copies into immutable content-addressed
storage. Deferred method operations record their exact MethodDef token or
literal as command arguments. `dotnet_extract_resources` also registers each
blob as a child before returning it, so normalizing the planned extraction
links both the tool output and every `dotnet-manifest-resource` lineage edge.

The document/script route retains complete bounded worker or `olevba` JSON in
the same way. Document parts record container member, OLE stream, RTF offset,
or PDF object provenance; decoded script values record their transform and
layer. `document_extract_artifacts` and `script_extract_payloads` validate
generated temporary paths, size, and digest before registering
`document-embedded-artifact` or `script-decoded-payload` edges. A recursively
routed child therefore preserves both its byte identity and the exact static
transformation that produced it.

The Android/native lanes use the same retained-result contract. JADX package
evidence and selected class/method source identify the canonical APK even when
a content-addressed `.apk` staging name is required by the provider. Extracted
manifest, resource, and asset bytes receive `android-resource` parent edges.
Mach-O metadata and bounded ELF-emulation traces retain worker status and full
bounded JSON, while REA ELF-layout and recorded-core results preserve their
exact command and isolated-provider evidence.

`recursive_unpack` additionally retains a versioned breadth-first graph. Every
accepted member records its parent digest, extraction relationship, depth,
generated derived path, and the deterministic format route calculated for that
child. Content deduplication can suppress repeated expansion but never removes
the already-recorded parent edge. Limit stops, unsupported layers, unsafe
member names, codec gaps, parser failures, and registration rejections remain
visible beside successful children. Configuration matches record their source
artifact digest, byte locations, validation details, and graded confidence.

## Artifact lineage

All built-in carving, unpacking, resource extraction, and emulation-dump tools
register output by SHA-256 and record the source artifact, transformation,
producer, label, and depth. `lab.register_derived` requires `parent_path` and
`relationship` for analyst-created output. Repeated bytes and repeated edges
are deduplicated. A child identical to its parent and any edge that would close
an ancestry cycle are rejected before routing can recurse into it.

The authoritative graph is `/work/state/artifacts.json`. The existing
`/work/samples/derived/.index.json` remains as a compatibility inventory.
`lab.list_samples` returns a bounded view of the authoritative parent graph.
An artifact left by a pre-ledger case is reported as `legacy_unlinked` and
fails the audit until it is re-registered with its real parent; BlackWall does
not invent provenance during migration.

## Findings and disagreements

Structured findings contain a `subject` and `value`, with optional `location`
and `confidence`. They can be supplied while normalizing a result or later via
`lab.record_findings`. Canonically equivalent values share a variant and merge
their evidence IDs and engine names. A different value for the same subject
and location creates another variant and marks the group as a disagreement;
no engine's observation is overwritten.
`lab.evidence_status` returns bounded disagreement details as well as counts so
the report can state which conclusions remain contested.

## Claims and audit

Call `lab.link_evidence_claim` for each material report conclusion and each
high-value analyst/Ghidra annotation. Put its returned
`[evidence:claim_<id>]` citation next to the statement or in the annotation.
The claim preserves the statement, confidence, optional report section or
code address, and exact evidence IDs.

Before finishing, call `lab.audit_evidence`. A claim audit walks from the
statement to its evidence record, retained tool result, source artifact, and
lineage. The whole-case form also checks every retained record and rejects
missing parents, cycles, changed bytes, and broken identities.

`bw-lab-mcp --check-evidence` performs an inert end-to-end admission test for
checkpoint resume, finding reconciliation, artifact deduplication, loop
prevention, claim linking, and hash audit. `blackwall doctor` and CI run it.

## Recovery boundary

`blackwall diagnose <id>` may count and parse retained ledger records, but it
opens stopped-case volumes read-only and never rewrites or discards them.
Corrupt state remains part of the audit trail until an operator copies the
volume and chooses an explicit repair. See the
[reliability and recovery model](reliability.md).
