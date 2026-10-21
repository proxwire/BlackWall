# BlackWall

Lets AI drive malware reverse engineering. Pull a sample, and seconds later
Claude Code is reversing it with persistent Ghidra, capa, FLOSS, YARA, REA's
cross-format static analyzers, ILSpy .NET decompilation, oletools-backed
document/script analysis, pinned JADX, Mach-O/ELF tooling, recursive extraction,
configuration recovery, and bounded emulation. The sample stays sealed inside
a container with no network access. Arbitrary shell, Python, and radare2 access
require an explicit expert-profile opt-in.

The existing Docker **analysis sandbox** is for static parsing and bounded
emulation; it does not execute native samples. The separate hardware-isolated
KVM **detonation sandbox** is still unbuilt and is the next major roadmap
milestone.

```
blackwall setup                      # once: build the image (~3 GB) and check the host
blackwall pull <sha256>              # from MalwareBazaar   (or: blackwall add ./suspicious.exe)
blackwall analyze <id> [--auto]      # strict profile (default) + Claude Code
blackwall analyze <id> --profile expert  # explicit scriptable-tool opt-in
blackwall status <id>                # checkpoints + live CPU/memory/PIDs
blackwall resume <id>                # continue only pending checkpoint work
blackwall compare <left> <right>     # stable artifact/finding/detection diff
blackwall archive <id>               # encrypted, manifested portable case
```

## How it's isolated

```
 host                                     │  static-analysis container  bw-<sha12>
                                          │  --network none, cap-drop ALL, no-new-privileges,
 ~/BlackWall-cases/<sha256>/              │  read-only rootfs, non-root, mem/cpu/pids limits
   sample.zip  (pw: infected) ──ro mount──┼─▶ /case/sample.zip ──bw-init──▶ /work/samples/original/<sha>
   CLAUDE.md, .claude/ (playbook)         │                                  (named volume bw-work-<sha12>)
   notes/ report.md                       │
   detections/ ◀──────────────rw mount────┼── YARA rules you validated
   exports/    ◀──────────────rw mount────┼── password-zipped artifacts (only on request)
                                          │
 claude (case dir) ══ docker exec -i ═════╪═▶ ghidra   pyghidra-mcp (headless Ghidra 12.1.4, persistent project)
   Bash, WebFetch/Search denied           │   strict: bounded lab tools only
   --strict-mcp-config: no other MCPs     │   lab      triage / REA static / capa / floss / unpack / emulate
                                          │   expert: adds lab shell/Python + radare2 MCP
                     ══ docker run ═══════╪═▶ intel    separate networked container; no sample; bounded lookup inputs only
```

- On the host, the sample is never unzipped. `add` zips local files inside a
  sandbox too.
- The analysis session only sees BlackWall's MCP servers, not your other MCP
  servers or claude.ai connectors. Host Bash, WebFetch, and WebSearch are
  denied. Networked intelligence tools accept only schema- and length-validated
  hashes, indicators, and family names, and run in a separate container with no
  sample or case mounts. This narrows the egress surface but is not semantic
  DLP: every lookup value is still disclosed to the named provider.
- The analyst permission policy denies edits to its own MCP configuration,
  permission settings, analyst brief, and profile-bearing `case.json`.
- Ghidra state, unpacked layers, and tool outputs live in the per-case
  volume. `blackwall rm <id>` destroys it.
- `analyze` and `analyze --auto` use the `strict` profile unless
  `--profile expert` is present. Strict mode does not register `lab.shell` or
  `lab.run_python` and does not configure the radare2 MCP server. The selected
  profile is recorded in `case.json`, shown by `list`, and stamped into a
  generated report.
- REA 6.7.0 is pinned behind BlackWall's `lab` MCP. Only an explicit static
  workflow allowlist is exposed; REA's process, debugger, Frida, ADB, browser,
  and other runtime commands are not MCP tools, and optional Frida is not
  installed. Full Evidence JSON is retained under `/work/out` while bounded,
  secret-redacted results are returned to the analyst.
- ILSpyCmd 11.1.0.9782 and its .NET 10.0.13 runtime are separately pinned and
  checksum-verified. The strict profile exposes only bounded assembly/type/
  method inventory, token-selected C# decompilation and call references,
  literal method search, and path-safe resource operations. See the
  [full .NET lane](docs/dotnet-analysis.md).
- `oletools==0.60.2` and BlackWall's isolated static worker cover OLE/OOXML,
  RTF, PDF, VBA, JavaScript/JScript, VBScript, and PowerShell. Member counts,
  expansion, decoded bytes, depth, output, memory, and time are bounded;
  extracted payloads use generated names and content-addressed lineage. No
  native document or script interpreter is invoked. See the
  [document/script lane](docs/document-script-analysis.md).
- The Android lane uses checksum-verified `jadx-headless-mcp` 0.7.1 with JADX
  1.5.6 for package/resource evidence and focused Java/Kotlin class or method
  decompilation. Mach-O gets supervised metadata, import/export, signature-
  structure, and Objective-C/Swift discovery plus the persistent Ghidra route.
- REA's ELF layout and recorded-core workflows run through a separate,
  hash-locked `pwntools==4.15.0` provider environment. Bounded ELF entry-point
  emulation uses Unicorn 2.1.4 in the main environment, stops at syscalls, and
  has no loader, host filesystem, network, or native execution.
- `lab.recursive_unpack` walks ZIP/TAR/compression, uncompressed/MSZIP/Quantum/LZX CAB,
  UPX, U-Boot uImage, and newc CPIO layers under global depth/count/byte/time
  limits. Every output has a generated name, is independently revalidated,
  receives parent lineage, and is immediately rerouted. PE `RCDATA` CABs are
  automatically carved; reviewed static configuration-extractor plugins,
  including Amadey v4/v5, return source ranges and graded confidence. See the
  [native/mobile/extraction lanes](docs/native-mobile-extraction.md).
- Before analysis, `lab.analysis_plan` performs bounded, non-extracting format
  detection and writes a deterministic plan with selected and skipped tools,
  reasons, deadlines, deferred inputs, and fallbacks. Native PE/ELF work stays
  Ghidra-first; managed code, APK, JavaScript/Electron, WASM, EVM, captures,
  and SQLite take focused REA routes. Non-success outcomes use a versioned
  normalizer so automation records the gap and continues independent work.
- Each plan also has a durable `/work/state` checkpoint. Every normalized
  result becomes a versioned evidence record with tool/version, stable command
  identity, artifact ancestry, confidence, truncation state, timestamps, and
  hashes for its retained output. Reopening the same plan exposes only pending
  steps; completed work and recorded gaps are not silently rebuilt.
- Carved, unpacked, extracted, and emulation-produced bytes are SHA-256-addressed
  children of their source. Equivalent findings merge provenance while engine
  disagreements remain visible. Reports and Ghidra annotations can carry
  claim citations that `lab.audit_evidence` verifies back to exact tool output.
  See the [evidence and resume model](docs/evidence.md).
- Host lifecycle commands expose checkpoint/resource status, resume and cancel
  without losing state, rebuild deterministic evidence reports, compare cases
  or individual runs, and export/import encrypted manifest-verified bundles.
  See [case management](docs/case-management.md).
- Evidence-linked YARA candidates must pass positive and inert-negative tests
  before export. Fixed-schema Sigma/Suricata candidates and reviewed ATT&CK
  mappings are included in the stable JSON case report. See
  [detection output](docs/detection-output.md).
- The workflow instructs the analyst never to execute samples. Dynamic
  behaviour comes from Speakeasy *emulation* (Windows APIs, filesystem,
  registry, and network are all emulated). The expert profile deliberately
  restores scriptable Python, shell, and radare2 access, so its no-execution
  rule is a policy boundary. BlackWall currently has no native-detonation
  command; the required KVM execution boundary remains a design in
  [`docs/safe-execution.md`](docs/safe-execution.md).

## What the AI gets

| server | profile | tools |
|---|---|---|
| `ghidra` | strict + expert | decompile, xrefs, call graphs, strings, imports/exports, semantic code search, read bytes, disassemble, import new layers, **rename / retype / set prototypes / comment** (persisted in the project) |
| `lab` | strict + expert | Deterministic resumable plans; evidence, lineage, finding reconciliation, claim audit; bounded ILSpy, document/script, JADX Android, Mach-O, ELF/core, recursive extraction, configuration recovery, Unicorn/Speakeasy emulation, REA static workflows, capa, FLOSS, Binwalk, and YARA |
| `radare2` | expert | r2mcp second-opinion disassembly/analysis and any architecture r2 supports |
| `lab` script tools | expert | Arbitrary `run_python` and `shell` operations inside the networkless sample container |
| `intel` | strict + expert | MalwareBazaar (hash, family), ThreatFox, URLhaus, VirusTotal (lookup only) |

Skills (in `analyst/.claude/skills`, copied into each case): **triage →
unpacking → deep-analysis → config-extraction → detection → report**. The
analyst brief (`analyst/CLAUDE.md`) sets the safety rules and the
evidence standard.

## Usage notes

- `analyze --auto` starts by opening the visible format-aware plan, follows only
  its checkpoint's remaining ready steps, and retains every result plus
  normalized parser/tool gaps while continuing independent work. Restarting it
  resumes the same checkpoint. Without it you get an interactive session; try
  "triage this" or "/triage".
- Use `--profile expert` only when a task genuinely needs a custom decryptor,
  parser, or low-level radare2 operation. BlackWall prints a conspicuous
  warning each time and never remembers expert as the default for a later run.
- `blackwall doctor` reports the profile it is auditing and exits nonzero if
  the MCP server set, lab-tool allowlist, REA static-command boundary, pinned
  ILSpy/JADX and exact pwntools providers, native/extraction workers, or host
  permission policy have drifted. It also verifies the inert cross-format
  corpus and runs deterministic router, evidence/resume, benchmark, Ghidra
  readiness, and failure-supervision admission checks.
- After `blackwall setup` rebuilds the image, the next `start` or `analyze`
  recreates any stale or policy-mismatched case container while retaining its
  named analysis volume. The recreation path verifies the case, volume, image,
  and sandbox-spec labels rather than trusting a same-named container.
- `blackwall diagnose <id>` inspects container drift, disk pressure, corrupt
  state, retained-record counts, and scratch/temporary cleanup candidates. It
  is read-only: `/work/state`, `/work/samples`, and `/work/ghidra` are protected
  and no cleanup happens automatically.
- `analyze --gui` also opens the Ghidra GUI (X11) on the same project, so you
  can watch the AI's renames and comments appear and annotate alongside it.
  This mounts the X11 socket into the sandbox, which is weaker isolation.
- To open the sandbox yourself: `blackwall shell <id>`.
- API keys go in `.env` (see `.env.example`). `pull`/`intel` need a free abuse.ch
  key; VirusTotal is optional.
- Add your own YARA rules under `rules/yara/` and rebuild.

## Current limitations

- One Ghidra session per case at a time (Ghidra takes an exclusive project
  lock). BlackWall keeps one loopback-only service in the networkless case and
  cleanly replaces it when switching between headless and GUI modes. The stdio
  bridge is exposed only after an MCP readiness probe confirms that all
  imported programs have completed Ghidra analysis. Code/string semantic
  indexes may finish later and remain separately visible in the status.
- Static .NET call references cannot resolve reflection, delegates, generated
  code, or runtime dispatch. ILSpy provides focused C# while REA supplies an
  independent managed-code view; mixed-mode native boundaries additionally
  route into persistent Ghidra. Obfuscated output still requires analyst
  reconciliation across those evidence sources.
- Document parsing is triage rather than rendering: encrypted content,
  malformed/uncommon PDF filters, XLM behavior, VBA stomping, and values
  assembled only at runtime may remain invisible. Script detections and
  bounded deobfuscation are heuristic; a recovered command is not proof it
  executed. Exact bounds and parser tradeoffs are documented in the
  [document/script lane](docs/document-script-analysis.md).
- JADX output can be incomplete under malformed or heavily obfuscated DEX.
  Mach-O signature reporting is structural and does not verify Apple trust or
  notarization. ELF emulation models instructions and memory, not an operating
  system. Recursive extraction supports a finite format set and reports every
  unsupported codec or layer as a gap. Exact bounds and coverage are in the
  [native/mobile/extraction guide](docs/native-mobile-extraction.md).
- REA 6.7.0's desktop-application and IL2CPP commands are not present in its
  published CLI. BlackWall verifies that manifest fact and does not advertise
  those workflows; they need real upstream commands, dependencies, and smoke
  tests before they can be added.

## How REA enhances BlackWall

REA is an additive analysis engine, not a replacement or a competing pipeline.
It broadens BlackWall's format coverage for managed code, APKs,
JavaScript/Electron, WASM, captures, and SQLite. For native malware, BlackWall
first performs malware-specific triage, unpacking, emulation, and persistent
Ghidra work; the analyst can then feed high-value addresses and features into
REA for an independent overview, a complete evidence-oriented function dossier,
feature tracing, or bounded value-flow analysis. The resulting Evidence JSON is
kept alongside the case.

BlackWall still owns the security and analyst-facing surface: persistent Ghidra
annotations remain the primary reversing workspace, REA receives no separate
MCP server, every exposed command uses an argument-safe static workflow, and
REA's native provider is forced to the in-container Ghidra installation. This
preserves REA's useful breadth and evidence model without exposing its much
larger runtime-capable command set as an accidental sample-execution path.

Native detonation is intentionally not part of this integration. A container
is not a sufficient malware execution boundary; the required fail-closed KVM
design is documented in [`docs/safe-execution.md`](docs/safe-execution.md).

The complete security model, disclosure process, and narrowly scoped ChromaDB
advisory exception are documented in [`SECURITY.md`](SECURITY.md).

## Development and release checks

GitHub Actions builds the complete image, checks the shell and Python sources,
runs the lab regression suite, validates the REA command manifest, and audits
both dependency ecosystems. Image integration tests use inert inputs to cover
Ghidra readiness, timeout/cancellation process groups, parser crashes, a full
tmpfs, corrupt archives, and stale-container volume retention. CI never pulls
or stores malware samples.

Signed semantic-version tags run the separate release workflow. It publishes
the tested Linux/amd64 image to GHCR by digest, signs it with keyless Cosign,
attaches GitHub provenance and SBOM attestations, and uploads deterministic
CycloneDX inventories for Python, npm, and the installed image. See the
[release/verification guide](docs/release.md), the
[supported-platform matrix](docs/supported-platforms.md), and
[third-party notices](THIRD_PARTY_NOTICES.md).

The temporary ChromaDB exceptions are governed by
`.github/dependency-exceptions.json`. CI queries the official PyPI and OSV APIs,
fails on an unreviewed `pyghidra-mcp` or ChromaDB release, fails when an ignored
advisory no longer affects the pin, and requires a fresh review every 30 days.
Run the same check with:

```bash
python3 scripts/check_dependency_exceptions.py --online
```

The source-built benchmark corpus and three-lane harness are documented in
[`benchmarks/README.md`](benchmarks/README.md). A quick integrity/route check is
available on the host with:

```bash
PYTHONPATH=lab python -m blackwall_lab.benchmark --self-check
```

Run the full tool comparison only in the networkless image. It writes both
versioned JSON and a reviewable Markdown summary; analyst-report scoring is
opt-in and never guessed from tool output. The separate malware manifest is
hash-only, cannot fetch anything, requires `--allow-malware`, and is rejected
whenever `CI` is set.

Python's direct dependency inputs are in `lab/requirements.txt`; the image
installs the fully resolved, hash-locked `lab/requirements.lock`. Regenerate it
with the pinned resolver after changing the inputs:

```bash
uv pip compile lab/requirements.txt \
  --python-version 3.12 \
  --python-platform x86_64-unknown-linux-gnu \
  --generate-hashes --no-emit-index-url \
  --output-file lab/requirements.lock
```

REA's deliberately isolated pwntools provider uses
`rea-runtime/pwntools-requirements.txt` and its own hash lock. Regenerate that
lock independently so its Unicorn 2.1.2 requirement cannot change the main
BlackWall Unicorn 2.1.4 environment:

```bash
uv pip compile rea-runtime/pwntools-requirements.txt \
  --python-version 3.12 \
  --python-platform x86_64-manylinux_2_39 \
  --generate-hashes \
  --output-file rea-runtime/pwntools-requirements.lock
```

Before a release, run `./blackwall setup` (or build the image directly),
`./blackwall doctor`, optionally audit the opt-in surface with
`./blackwall doctor --profile expert`, and confirm `git diff --check` is clean.
The project does not commit API keys, case directories, extracted samples, or
analysis output.

## License

BlackWall is available under the permissive [MIT License](LICENSE). The
analysis image contains independently licensed tools; see
[third-party notices](THIRD_PARTY_NOTICES.md).

## Roadmap

The prioritized implementation plan is in [`docs/roadmap.md`](docs/roadmap.md).
Roadmap items 1–12 and the production-depth follow-ups found by the
[same-sample validation](docs/benchmarks/same-sample-strict-2026-10-21.md) are
delivered. The only remaining implementation target is the separately
isolated dynamic-analysis plane. Native detonation remains unimplemented and
gated on the fail-closed KVM design in
[`docs/safe-execution.md`](docs/safe-execution.md).
