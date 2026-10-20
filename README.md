# BlackWall

Lets AI drive malware reverse engineering. Pull a sample, and seconds later
Claude Code is reversing it with persistent Ghidra, radare2, capa, FLOSS,
YARA, REA's cross-format static analyzers, Speakeasy emulation, and a
scriptable sandbox. The sample stays sealed inside a container with no network
access.

```
blackwall setup                      # once: build the image (~3 GB) and check the host
blackwall pull <sha256>              # from MalwareBazaar   (or: blackwall add ./suspicious.exe)
blackwall analyze <id> [--auto]      # sandbox up + Claude Code in the case folder
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
   Bash, WebFetch/Search denied           │   radare2  r2mcp
   --strict-mcp-config: no other MCPs     │   lab      triage / REA static / capa / floss / unpack / emulate / python
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
- Ghidra state, unpacked layers, and tool outputs live in the per-case
  volume. `blackwall rm <id>` destroys it.
- REA 6.7.0 is pinned behind BlackWall's `lab` MCP. Only an explicit static
  workflow allowlist is exposed; REA's process, debugger, Frida, ADB, browser,
  and other runtime commands are not MCP tools, and optional Frida is not
  installed. Full Evidence JSON is retained under `/work/out` while bounded,
  secret-redacted results are returned to the analyst.
- The workflow instructs the analyst never to execute samples. Dynamic
  behaviour comes from Speakeasy *emulation* (Windows APIs, filesystem,
  registry, and network are all emulated). Because the lab deliberately offers
  scriptable Python and shell access, this is a policy boundary rather than a
  technical execution-prevention guarantee; use a stronger isolation runtime
  for samples outside your container threat model.

## What the AI gets

| server | tools |
|---|---|
| `ghidra` | decompile, xrefs, call graphs, strings, imports/exports, semantic code search, read bytes, disassemble, import new layers, **rename / retype / set prototypes / comment** (persisted in the project) |
| `radare2` | r2mcp: second-opinion disassembly/analysis, any arch r2 supports |
| `lab` | Core triage plus REA cross-format workflows and static Ghidra-backed native overview, function dossiers, feature tracing, and bounded value-flow analysis; focused managed-code, Android, EVM, HAR/SAZ/qlog, GNU objdump, capa, FLOSS, Binwalk, YARA, unpacking, Speakeasy emulation, Python and shell |
| `intel` | MalwareBazaar (hash, family), ThreatFox, URLhaus, VirusTotal (lookup only) |

Skills (in `analyst/.claude/skills`, copied into each case): **triage →
unpacking → deep-analysis → config-extraction → detection → report**. The
analyst brief (`analyst/CLAUDE.md`) sets the safety rules and the
evidence standard.

## Usage notes

- `analyze --auto` runs the whole pipeline on its own. Without it you get an
  interactive session; try "triage this" or "/triage".
- After `blackwall setup` rebuilds the image, the next `start` or `analyze`
  recreates any stale case container while retaining its named analysis volume.
- `analyze --gui` also opens the Ghidra GUI (X11) on the same project, so you
  can watch the AI's renames and comments appear and annotate alongside it.
  This mounts the X11 socket into the sandbox, which is weaker isolation.
- To open the sandbox yourself: `blackwall shell <id>`.
- API keys go in `.env` (see `.env.example`). `pull`/`intel` need a free abuse.ch
  key; VirusTotal is optional.
- Add your own YARA rules under `rules/yara/` and rebuild.

## Known issues

- One Ghidra session per case at a time (Ghidra takes an exclusive project
  lock). A new session cleanly stops a stale one.
- In the first seconds after the Ghidra MCP starts, a decompile can time out
  (a pyghidra-mcp startup race). Retrying after ~30s works; the analyst brief
  tells the AI this.
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
both dependency ecosystems. CI uses only inert system binaries; it never pulls
or stores malware samples.

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
`./blackwall doctor`, and confirm `git diff --check` is clean. The project does
not commit API keys, case directories, extracted samples, or analysis output.

## License

BlackWall is available under the permissive [MIT License](LICENSE).

## Roadmap

- **Phase 2: dynamic.** A KVM Windows detonation VM on an isolated libvirt
  network with INetSim/FakeNet, snapshot revert, x64dbg MCP, and
  Procmon/Sysmon capture.
- **More formats.** Full .NET IL decompilation, maldocs (oletools), PowerShell/
  VBA deobfuscation, and Mach-O workflows beyond REA's current static coverage.
- Qiling for ELF/other-arch emulation, plus more YARA rule packs.
