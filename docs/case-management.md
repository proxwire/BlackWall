# Case lifecycle, reports, and comparison

BlackWall separates host metadata from sample-bearing analysis state. A case
directory owns the encrypted `sample.zip`, notes, reports, detections, and
exports. Its `bw-work-<sha12>` named volume owns the unpacked original,
content-addressed derivatives, Ghidra project, checkpoints, and evidence.

## Lifecycle commands

```text
blackwall list
blackwall status <id> [--json]
blackwall resume <id> [--profile strict|expert] [--gui]
blackwall cancel <id>
blackwall report <id> [--plan-id <16-hex-id>]
blackwall compare <left> <right> [--left-plan <id>] [--right-plan <id>]
blackwall archive <id> [output.7z]
blackwall import <bundle.7z>
blackwall clean <id> --scratch
```

`status` combines checkpoint progress with live Docker CPU, memory, and PID
usage. `cancel` stops the container and records a lifecycle event without
removing the volume. `resume` starts the normal automatic analyst flow, which
receives completed/gap/redundant/pending checkpoint state.

Cleanup is deliberately narrow: the command requires the literal `--scratch`
flag, refuses an active sandbox, and removes only `/work/scratch` and
`/work/tmp`. Evidence, samples, rules, and Ghidra state are protected. The
separate destructive `rm` command remains explicit.

## Reproducible report and comparison

`report` writes `evidence-report.json` (`blackwall.case-report.v1`) and a
deterministic Markdown rendering. It normalizes volume/case paths, audits every
retained evidence payload and artifact hash, and derives its report ID from
canonical content rather than wall-clock time.

`compare` accepts two cases, or two plan IDs for run-to-run comparison. Its
`blackwall.case-comparison.v1` result reports added/removed/unchanged artifacts,
code findings, strings, IOCs, configurations, and detection IDs. It compares
stored structured evidence rather than prose reports.

## Portable archives

`archive` stops a running case for a consistent snapshot, rebuilds the report,
then creates a 7z archive with encrypted filenames and content. The default
password is `infected`; set `BLACKWALL_BUNDLE_PASSWORD` before archive and
import for private transport.

The bundle includes only allowlisted case and volume roots. Symlinks are
rejected. `manifest.json` records every path, SHA-256, size, file count, total
bytes, case SHA-256, and a deterministic manifest ID. Import first lists and
validates member paths in an isolated container, extracts to private tmpfs,
checks the complete manifest, and copies into a new empty case/volume. The raw
original is never unzipped onto the host.
