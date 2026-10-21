# BlackWall

Lets AI drive malware reverse engineering. Pull a sample, and seconds later
Claude Code is reversing it with persistent Ghidra, capa, FLOSS, YARA, REA's
cross-format static analyzers, bounded unpacking, and Speakeasy emulation. The
sample stays sealed inside a container with no network access. Arbitrary shell,
Python, and radare2 access require an explicit expert-profile opt-in.

```
blackwall setup                      # once: build the image (~3 GB) and check the host
blackwall pull <sha256>              # from MalwareBazaar   (or: blackwall add ./suspicious.exe)
blackwall analyze <id> [--auto]      # strict profile (default) + Claude Code
blackwall analyze <id> --profile expert  # explicit scriptable-tool opt-in
```

## How it's isolated

```
 host                                     │  sandbox container  bw-<sha12>
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
- The workflow instructs the analyst never to execute samples. Dynamic
  behaviour comes from Speakeasy *emulation* (Windows APIs, filesystem,
  registry, and network are all emulated). The expert profile deliberately
  restores scriptable Python, shell, and radare2 access, so its no-execution
  rule is a policy boundary; use a stronger isolation runtime for samples
  outside your container threat model.

## What the AI gets

| server | profile | tools |
|---|---|---|
| `ghidra` | strict + expert | decompile, xrefs, call graphs, strings, imports/exports, semantic code search, read bytes, disassemble, import new layers, **rename / retype / set prototypes / comment** (persisted in the project) |
| `lab` | strict + expert | Deterministic resumable plans; evidence, lineage, finding reconciliation, claim audit; core triage plus REA cross-format workflows and static Ghidra-backed native function dossiers, feature tracing, and bounded value-flow analysis; focused managed-code, Android, EVM, HAR/SAZ/qlog, GNU objdump, capa, FLOSS, Binwalk, YARA, bounded unpacking/carving, and Speakeasy emulation |
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
  the MCP server set, lab-tool allowlist, REA static-command boundary, or host
  permission policy has drifted. It also verifies the inert cross-format
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
- Ghidra is weak on .NET IL. `dotnet_info` covers metadata and
  `dotnet_extract_resources` safely extracts embedded CLR resources. REA adds
  static PE/CLI member, CIL-anchor, string-literal, and native-boundary
  inspection, but it is not a full interactive IL decompiler.
- REA 6.7.0's desktop-application and IL2CPP commands are not present in its
  published CLI. Its ELF binary-layout and recorded-core workflows require a
  separate exact pwntools provider profile. BlackWall does not advertise those
  lanes until their dependencies and smoke tests are present.

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

Before a release, run `./blackwall setup` (or build the image directly),
`./blackwall doctor`, optionally audit the opt-in surface with
`./blackwall doctor --profile expert`, and confirm `git diff --check` is clean.
The project does not commit API keys, case directories, extracted samples, or
analysis output.

## License

BlackWall is available under the permissive [MIT License](LICENSE).

## Roadmap

The prioritized implementation plan is in [`docs/roadmap.md`](docs/roadmap.md).
The P0 foundation (roadmap items 1–5) is complete. The next implementation
target is item 6, full .NET analysis. Document, script, Android, Mach-O, and
emulation support follows.
Native detonation remains gated on the fail-closed KVM design in
[`docs/safe-execution.md`](docs/safe-execution.md).
