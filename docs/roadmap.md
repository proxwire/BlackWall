# BlackWall roadmap

Last reviewed: 2026-10-21.

The current baseline is the REA 6.7.0 integration plus roadmap items 1–12:
the P0 foundation, P1 static/emulated format-depth milestones and their field
follow-ups, and the P3 analyst/release workflow. REA is an additional
static-analysis engine inside BlackWall, not a replacement for BlackWall's
malware triage, persistent Ghidra workspace, unpacking, emulation, or security
boundary. The only remaining roadmap milestone is the hardware-isolated
dynamic-analysis plane, which is not built.

This roadmap is ordered by dependency and risk. Preserve the completed P0
admission checks while adding broader P1 tool coverage.

## Product rules

- Keep static analysis as the safe default. Never execute a native sample in
  the Docker analysis container.
- Do not expose REA's process, debugger, Frida, ADB, browser, or unrestricted
  runtime commands as MCP tools.
- Treat every parser and decompiler as hostile-input code. New tools need
  bounded input, output, time, memory, and artifact handling.
- Keep live malware and extracted artifacts out of Git, CI, issue attachments,
  and logs. Regression manifests may contain hashes and provenance only.
- Prefer evidence with provenance over unsupported conclusions. Every finding
  should identify its tool, arguments, source artifact, and retained output.
- Do not claim support for "all malware." Publish the tested format and
  architecture matrix instead.

## P0: safe, measurable hybrid analysis — complete

### 1. Split the default and expert tool profiles

The expert lab includes scriptable Python and shell tools. They are useful for
advanced analysis, but they make the no-execution rule a policy boundary.

- [x] Make a strict static profile the default for `analyze` and
  `analyze --auto`.
- [x] Remove unrestricted shell and Python from that default profile while
  retaining intent-level tools for parsing, carving, hashing, and querying.
- [x] Put scriptable tools behind an explicit, conspicuous expert opt-in and
  record the selected profile in the case metadata and report.
- [x] Add regression tests proving that runtime-capable REA commands and
  arbitrary process execution are absent from the strict profile.
- [x] Make `doctor` report the active profile and fail closed when its expected
  restrictions are missing.

Done when a prompt-injected sample cannot ask the default analyst to invoke an
arbitrary executable, while normal static triage, Ghidra, REA, unpacking, and
Speakeasy emulation still work.

### 2. Add a format-aware analysis router

Do not run every engine against every sample. Route work according to file
type, architecture, packing state, and analysis phase.

- [x] Detect container, executable, managed-runtime, script, capture, document,
  mobile, and bytecode formats before building the analysis plan.
- [x] Keep BlackWall/Ghidra as the primary native PE and ELF path; invoke REA
  for an independent overview or focused function, feature, and value-flow
  questions after high-value targets are known.
- [x] Prefer REA's focused workflows for managed code, APK, JavaScript,
  Electron, WASM, EVM, captures, and SQLite where they add coverage.
- [x] Return a visible plan containing selected tools, skipped tools, reasons,
  deadlines, and fallbacks.
- [x] Normalize timeout, unsupported-format, partial-result, and tool-failure
  states so `--auto` can continue without hiding gaps.

Done when the same sample produces a deterministic plan and redundant or
low-value REA passes no longer make native analysis slower or noisier.

### 3. Build a repeatable evaluation corpus and benchmark

- [x] Turn the initial
  [standalone REA Windows check](benchmarks/rea-standalone-windows-2026-10-20.md)
  into an automated harness.
- [x] Commit inert fixtures for unit and integration tests.
- [x] Keep a separate, opt-in malware manifest containing SHA-256 hashes,
  source references, family/type labels, and expected coarse findings; never
  commit or fetch live samples in CI.
- [x] Cover at least native PE, packed PE, .NET, ELF, APK, JavaScript, WASM,
  Office/RTF/PDF, and one network-capture format.
- [x] Compare core BlackWall, raw REA, and the hybrid router on tool success,
  wall time, timeouts, useful evidence, IOCs, configuration recovery, and
  analyst-report accuracy.
- [x] Save machine-readable results and a short Markdown summary so regressions
  can be reviewed between releases.

Done when claims about REA improving BlackWall are supported by reproducible
per-format results rather than individual demonstrations. The retained
[`inert execution baseline`](benchmarks/cross-format-inert-2026-10-20.md) and
its [machine-readable result](benchmarks/cross-format-inert-2026-10-20.json)
cover all required formats; absent analyst reports remain explicitly
`not_measured` rather than receiving a synthetic score.

### 4. Unify evidence, lineage, and resumability

- [x] Define a versioned evidence schema for tool, version, command identity,
  artifact hash, parent artifact, timestamps, confidence, truncation, and
  retained-output path.
- [x] Track every carved, unpacked, or extracted artifact as a content-addressed
  child of its source and prevent recursive extraction loops.
- [x] Deduplicate equivalent findings while preserving disagreements between
  engines.
- [x] Checkpoint the analysis plan so interrupted sessions resume completed
  work instead of rebuilding it.
- [x] Link report statements and analyst annotations back to retained evidence.

Done when a report can be audited from conclusion to exact artifact and tool
output, and an interrupted automatic run can safely resume. The shared
[`evidence and resume model`](evidence.md) is exercised by an inert admission
self-check plus unit tests for tampering, lineage cycles, finding disagreement,
and stop/restart behavior.

### 5. Remove known reliability and dependency exceptions

- [x] Add an explicit Ghidra readiness probe instead of relying on a retry after
  the current startup race.
- [x] Monitor `pyghidra-mcp`/ChromaDB releases and remove the four documented
  audit exceptions as soon as a compatible fixed version exists.
- [x] Exercise timeout, cancellation, stale-container recreation, full disks,
  corrupt archives, and parser crashes in integration tests.
- [x] Produce actionable cleanup diagnostics without deleting a case's
  retained evidence.

Done via the shared [reliability model](reliability.md): Ghidra is admitted by
an MCP-level program-status probe, parser process groups have distinct timeout,
cancellation, and crash outcomes, and `blackwall diagnose` is read-only. CI
exercises every listed failure path with inert inputs. The four ChromaDB
exceptions remain narrowly scoped because no fixed release exists as of the
2026-10-20 review; a live PyPI/OSV gate fails on new releases, changed advisory
coverage, or a review older than 30 days so the ignores cannot silently become
permanent.

## P1: deeper static and emulated format coverage

### 6. Full .NET analysis

- [x] Add a pinned and checksum-verified ILSpy command-line integration.
- [x] Expose assembly/type/method listing, C# decompilation, call references,
  resources, and method-level search through bounded MCP operations.
- [x] Connect decompiled methods and resources to the shared evidence schema.
- [x] Add mixed-mode, obfuscated, and resource-embedded test fixtures.

Done via the [bounded .NET lane](dotnet-analysis.md): checksum-verified
ILSpyCmd and .NET runtime pins provide token-selected C#, static call
references, literal method search, and safe resource handling. Full bounded
output is evidence-retained, extracted resources receive lineage, mixed-mode
CorFlags retain a native Ghidra route, and the inert benchmark corpus exercises
ordinary, mixed-mode-marker, obfuscated, and resource-bearing assemblies.

### 7. Malicious documents and scripts

- [x] Add static Office, OLE, OOXML, RTF, and PDF triage using pinned tools such
  as oletools and purpose-built bounded extractors.
- [x] Extract and deobfuscate VBA, JavaScript/JScript, VBScript, and PowerShell
  without invoking their native interpreters.
- [x] Recover URLs, commands, dropped payloads, and document relationships with
  provenance and size/depth limits.
- [x] Add script-specific detections and safe deobfuscation fixtures.

Done via the [bounded document/script lane](document-script-analysis.md):
`oletools==0.60.2` supplies VBA/OLE parsing, while a supervised static worker
handles relationships, active content, embedded objects, script detections,
and bounded decoding. Generated extraction names are revalidated before
content-addressed lineage admission. The 26-fixture inert corpus covers the
four script languages, macro-enabled OOXML, external relationships, RTF/PDF
objects, PDF JavaScript, and decoded payloads without invoking native
interpreters.

### 8. Android, Apple, and native parity

- [x] Add pinned JADX-backed APK resource and Java/Kotlin decompilation to
  complement REA's current APK workflows.
- [x] Add Mach-O metadata, imports, symbols, code-signing, Objective-C/Swift
  discovery, and Ghidra routing.
- [x] Supply and test the exact pwntools provider profile needed for REA's ELF
  binary-layout and recorded-core workflows before advertising them.
- [x] Add Qiling or another emulator for bounded ELF/other-architecture
  emulation; keep it distinct from native execution.
- [x] Add IL2CPP and desktop-application workflows only when their actual
  dependencies and smoke tests exist; do not advertise absent REA commands.

Done via the [native and mobile lanes](native-mobile-extraction.md): pinned
JADX supplies bounded APK resource/source workflows; a supervised Mach-O
parser and persistent Ghidra route cover Apple binaries; REA's ELF layout/core
commands use their exact isolated, hash-locked pwntools profile; and Unicorn
performs instruction- and time-bounded syscall-blocked ELF emulation. The
installed REA manifest proves that desktop-application and IL2CPP commands are
absent, so BlackWall exposes neither placeholder.

### 9. Recursive unpacking and configuration recovery

- [x] Make unpacking a bounded graph traversal with maximum depth, artifact
  count, expanded bytes, and elapsed time.
- [x] Add common installer/archive, packer, firmware, and embedded-filesystem
  extractors with path-traversal and decompression-bomb protection.
- [x] Provide a plugin interface for family-specific configuration extractors
  with fixtures and confidence grading.
- [x] Feed validated derived binaries back through the format router while
  preserving lineage.

Done via the [recursive extraction and configuration lanes](native-mobile-extraction.md):
breadth-first traversal enforces independent depth, count, per-artifact,
aggregate-byte, ratio, member, and elapsed-time budgets; generated-name
extractors cover ZIP/TAR/compression streams, CAB, UPX, U-Boot uImage, and newc
CPIO; a static reviewed-plugin registry returns graded configuration evidence;
and every validated child receives a parent edge plus a fresh deterministic
route before it can be expanded again.

### P1 field-validation follow-ups

The
[2026-10-21 same-sample comparison](benchmarks/same-sample-strict-2026-10-21.md)
confirmed the item 9 framework and its safety properties, but also found these
production-depth gaps. These are post-delivery follow-ups; the checked item 9
scope above records the bounded framework and inert admission coverage that
already exist.

- [x] Add a pinned, checksum-verified, bounded LZX CAB decoder while preserving
  member-count, expanded-byte, ratio, path, memory, and deadline limits.
- [x] Discover IExpress CAB data in PE `RCDATA` automatically and feed it into
  the recursive extraction graph without an analyst-managed intermediate step.
- [x] Add a reviewed Amadey configuration extractor with reconstructed/inert
  positive, corrupt, truncated, and false-positive fixtures; never commit live
  sample bytes.
- [x] Represent deliberately skipped duplicate work as `not_run_redundant`
  instead of collapsing it into failure or timeout.
- [x] Add an ATT&CK mapping regression for DLL side-loading (`T1574.002`) so a
  report cannot silently substitute the DLL search-order-hijacking sub-technique.

## P2: hardware-isolated dynamic analysis

**Status: not implemented.** The existing Docker analysis sandbox is a static
parsing and bounded-emulation workspace. It is not this native-detonation
boundary and must never be used as one.

Implement the fail-closed design in [`safe-execution.md`](safe-execution.md).
This is intentionally a separate execution plane, not another Docker tool.

- [ ] Build disposable Windows KVM overlays with immutable base-image hashes.
- [ ] Enforce no host mounts/devices and no network by default.
- [ ] Add an optional isolated INetSim/FakeNet network with independently
  verified denial of Internet, LAN, and management-plane access.
- [ ] Start Procmon/Sysmon/ETW, packet, process, registry, and filesystem
  collectors before detonation.
- [ ] Add guest and host watchdogs, forced stop, bounded artifact egress, and
  verified overlay/network destruction on every exit path.
- [ ] Expose only intent-level operations such as `detonate_pe` and
  `collect_trace`; never expose an unrestricted guest shell to the analyst.
- [ ] Gate release on every admission test listed in the safe-execution design.

After Windows detonation is proven, evaluate separate Linux and Android guests;
do not generalize the Windows boundary without equivalent tests.

## P3: analyst workflow and release engineering

### 10. Case management and comparison — complete

- [x] Add `list`, `status`, `resume`, `archive`, `import`, and safe cleanup
  commands with clear case/volume ownership.
- [x] Add sample-to-sample and run-to-run comparison for code, strings, IOCs,
  configurations, and detections.
- [x] Make reports reproducible from stored evidence and export a portable,
  password-protected case bundle with a manifest.
- [x] Add progress, cancellation, and resource-usage visibility for long runs.

Done via the [case lifecycle and comparison model](case-management.md): host
commands operate on explicit case directories and named volumes, deterministic
reports rebuild from retained evidence, comparisons use stable categories, and
encrypted 7z bundles validate a hash/size manifest before import. Cancellation
preserves checkpoints; cleanup can delete only documented scratch trees.

### 11. Detection output — complete

- [x] Generate evidence-linked YARA candidates and test them against positive
  and negative fixture sets before export.
- [x] Add Sigma and Suricata candidate generation where telemetry supports it.
- [x] Map behaviors to ATT&CK with explicit evidence and confidence rather than
  model-only assertions.
- [x] Export a stable machine-readable report format for downstream tooling.

Done via the [detection-output contract](detection-output.md): constrained YARA
candidates must compile and clear positive/negative validation before export;
Sigma and Suricata use fixed telemetry schemas/templates; and ATT&CK mappings
come only from a reviewed evidence-linked catalog. Case JSON uses the stable
`blackwall.case-report.v1` schema.

### 12. Releases and supply-chain metadata — complete

- [x] Publish versioned release notes and a supported-platform matrix.
- [x] Generate SBOMs for the image and both dependency ecosystems.
- [x] Sign release tags and published images, attach provenance, and document
  verification.
- [x] Add controlled dependency-update automation that regenerates locks and
  runs the full fixture suite.
- [x] Decide whether to publish a prebuilt image after reviewing redistribution
  terms and the security consequences of shipping the full toolchain.

Done via the [signed release process](release.md): verified signed version tags
gate GHCR publication, keyless Cosign and GitHub attestations bind the amd64
image digest, deterministic CycloneDX files cover Python, npm, and the installed
image, and allowlisted update workflows regenerate locks before running the
complete inert image suite. The reviewed choice is to publish a signed amd64
image while preserving direct-tool notices and making its parser-risk boundary
explicit.

## Remaining implementation order

1. Build and admission-test the hardware-isolated dynamic-analysis plane.

Each feature should include tests, `doctor` coverage where applicable, analyst
documentation, threat-model changes, and an entry in the benchmark matrix.
