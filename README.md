# BlackWall

Lets AI drive malware reverse engineering. Pull a sample, and seconds later
Claude Code is reversing it with Ghidra, radare2, capa, FLOSS, YARA, Speakeasy
emulation, and a scriptable sandbox. The sample stays sealed inside a container
with no network access.

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
   Bash, WebFetch denied                  │   radare2  r2mcp
   --strict-mcp-config: no other MCPs     │   lab      triage / capa / floss / yara / unpack / emulate / python / shell
                     ══ docker run ═══════╪═▶ intel    separate throwaway container WITH network, no sample, hashes/IOCs only
```

- On the host, the sample is never unzipped. `add` zips local files inside a
  sandbox too.
- The analysis session only sees BlackWall's MCP servers, not your other MCP
  servers or claude.ai connectors. Host Bash and WebFetch are denied, so the
  AI can't reach C2 infrastructure or exfiltrate data, even if a sample carries
  a prompt injection.
- Ghidra state, unpacked layers, and tool outputs live in the per-case
  volume. `blackwall rm <id>` destroys it.
- The sample is never executed. Dynamic behaviour comes from Speakeasy
  *emulation* (Windows APIs, filesystem, registry, and network are all
  emulated).

## What the AI gets

| server | tools |
|---|---|
| `ghidra` | decompile, xrefs, call graphs, strings, imports/exports, semantic code search, read bytes, disassemble, import new layers, **rename / retype / set prototypes / comment** (persisted in the project) |
| `radare2` | r2mcp: second-opinion disassembly/analysis, any arch r2 supports |
| `lab` | `file_overview` (hashes, ssdeep/tlsh, DIE), `pe_info`, `elf_info`, `dotnet_info`, `capa`, `floss`, `strings`, `extract_iocs`, `yara_scan`, `yara_test`, `upx_unpack`, `carve_embedded`, `extract_pe_resource`, `emulate_windows` (Speakeasy, dumps unpacked PEs), `hexdump`, `run_python`, `shell`, `register_derived`, `export_to_host` |
| `intel` | MalwareBazaar (hash, family), ThreatFox, URLhaus, VirusTotal (lookup only) |

Skills (in `analyst/.claude/skills`, copied into each case): **triage →
unpacking → deep-analysis → config-extraction → detection → report**. The
analyst brief (`analyst/CLAUDE.md`) sets the safety rules and the
evidence standard.

## Usage notes

- `analyze --auto` runs the whole pipeline on its own. Without it you get an
  interactive session; try "triage this" or "/triage".
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
- Ghidra is weak on .NET IL. `dotnet_info` covers metadata, but full .NET
  decompilation (ILSpy) is on the roadmap.

## Roadmap

- **Phase 2: dynamic.** A KVM Windows detonation VM on an isolated libvirt
  network with INetSim/FakeNet, snapshot revert, x64dbg MCP, and
  Procmon/Sysmon capture.
- **More formats.** .NET (ILSpy CLI), maldocs (oletools), scripts
  (JS/PS/VBA deobfuscation), APK (jadx), Mach-O.
- Qiling for ELF/other-arch emulation, plus more YARA rule packs.
