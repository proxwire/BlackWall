# Standalone REA 6.7.0 Windows malware check

Date: 2026-10-20

## Question

How does ordinary upstream REA perform on Windows malware when used by itself,
without BlackWall's `lab` MCP wrappers, malware-specific triage, unpacking,
emulation, intelligence lookups, or analyst playbooks?

## Method

- REA: `rea-agents` 6.7.0, invoked through its upstream CLI.
- Native provider: Ghidra 12.1.4.
- Targets: two existing password-zipped Windows samples.
- Containment: separate disposable containers, no network, read-only root,
  dropped capabilities, `no-new-privileges`, bounded CPU/memory/processes, and
  a `noexec` temporary workspace.
- The host copies remained zipped. Each sample was extracted into container
  memory, its SHA-256 was verified, and the container was destroyed afterward.
- Only static commands were used. No sample process, debugger, Frida workflow,
  or native runtime command was invoked.

This is a capability comparison, not a time-matched contest. The existing
BlackWall Amadey report is a deep analyst session across several derived layers;
REA's CLI runs below are individual static probes.

## Samples

| kind | SHA-256 | reference label |
|---|---|---|
| Native x64 PE / IExpress delivery chain | `52ebd649910eac2754dd5631d388dfdcf25e200be19918d1c94999225729a73c` | Amadey |
| x64 PE/CLI assembly | `9741e24cffbf4549bf5f5d3aa20ee691c1bcb1b5fbe45274cee257b310c70257` | WailsLoader / WebSocket RAT |

The labels come from the existing case metadata and BlackWall investigation;
they were not supplied to REA as analysis hints.

## Native PE result

REA's generic native analysis was fast and structurally precise:

- `analyze --provider ghidra` completed in 11.4 seconds and reported eight
  segments, 256 procedures, and 474 Ghidra-defined strings.
- `inspect-native-load-image` recovered image base `0x140000000` and entry point
  `0x140008460`.
- `function` returned a complete entry-point dossier with pseudocode, assembly,
  callees, references, CFG, API-boundary evidence, and high-pcode value flow.
- Targeted searches exposed the expected WEXTRACT/IExpress imports and strings.
- `inspect-pe-resources` inventoried 57 resources and identified a resource
  named `CABINET` at file offset 176240, length 535784. Its SHA-256,
  `d8ec222e3f18df2fb6e70f01e3a374ca8cd26c49cbdff20c23a34f14d2ab02a8`,
  exactly matched the cabinet later recorded by BlackWall.

The analysis then stopped at the delivery wrapper:

- Generic `extract-artifact` rejected PE as an unsupported extraction target.
- The offset-driven `extract-firmware` path required a separately configured
  `unblob` provider, which the standard installation did not supply.
- REA did not extract the cabinet, reach `g2m.dll`, decrypt the embedded
  payload, identify Amadey, recover its configuration/C2, emulate it, or create
  detections.

BlackWall's existing analysis crossed all of those boundaries: IExpress/CAB
extraction, signed-host DLL sideloading, loader reverse engineering, two-stage
payload decryption, Amadey 5.92 identification, C2/configuration recovery,
Speakeasy validation, intelligence corroboration, ATT&CK mapping, and tested
YARA rules.

Verdict: raw REA is a strong evidence-oriented native query engine, but its
default overview is not a malware-unpacking pipeline. On this layered native
sample, BlackWall was dramatically more complete.

## Managed .NET result

The default command and the format-specific commands behaved very differently.

`rea analyze` completed in 9.0 seconds but selected a generic Ghidra overview.
It returned four segments, 30 procedures, and 26 strings—correct but too shallow
for useful malware classification.

REA's dedicated managed-static commands were the standout:

- Each completed in roughly 1.1–1.5 seconds.
- `inspect-managed-artifact` correctly classified x64 CIL and recovered module,
  assembly, MVID, references, and complete metadata coverage.
- `inspect-managed-members` recovered three types, 29 methods, four fields,
  127 member references, 360 call edges, 37 field accesses, and 81 user strings.
- It exposed the `ConsoleApp2.WsClient` WebSocket implementation and the
  `ConsoleApp2.Program` command, discovery, persistence, and process-launch
  methods without loading the assembly.
- Static evidence revealed a hard-coded `wss://` Cloudflare Workers endpoint,
  named-pipe handling, `download`, `check`, `subscr`, `info`, and `launch`
  commands, WMI system/process/user/service/network discovery, and a permanent
  `__EventFilter` + `ActiveScriptEventConsumer` +
  `__FilterToConsumerBinding` JScript persistence chain.
- `inspect-managed-native-boundaries` found the single `kernel32.dll`
  `WaitNamedPipe` P/Invoke and correctly reported no ReadyToRun or mixed-mode
  native boundary.

REA still did not produce C# decompilation, a malware verdict, an IOC report,
behavior confidence synthesis, or detections by itself. Those require an agent
to interpret the Evidence or another decompiler/reporting layer.

Verdict: on unobfuscated .NET, standalone REA is excellent at fast, safe,
structured discovery. BlackWall's integrated REA lane uses these same upstream
operations, so the underlying managed evidence is effectively parity; BlackWall
adds routing, retained case evidence, other analyzers, and report synthesis.

## Comparison

| capability | standalone REA | BlackWall without REA | BlackWall + REA |
|---|---|---|---|
| Native PE structure/function evidence | Strong when queried | Strong, persistent Ghidra plus malware tools | Strongest combination |
| Layered PE unpacking | Weak/manual on this sample | Strong | Strong |
| .NET metadata/CIL graph | Strong with explicit managed commands | Basic metadata only | Strong, using REA's engine |
| Automatic format routing | Default `analyze` was too generic | Malware-oriented but narrower formats | Deterministic bounded router implemented and covered by the retained inert benchmark |
| Emulation and behavior validation | Not used; raw runtime tools are unsafe for this test | Speakeasy available | Speakeasy plus REA static evidence |
| IOC/config/detection workflow | Evidence primitives only | Strong analyst workflow | Strong analyst workflow with broader evidence |
| Persistent case state and report | Ephemeral unless the caller manages Evidence | Built in | Built in |

## Conclusion

The earlier result that made REA appear "worse" was real for a layered native
malware sample, but it was not a general verdict on REA. REA is strongest when
an agent selects a format-specific or question-specific operation. Its generic
native overview deliberately returns evidence rather than performing the
malware-specific unpack/decrypt/emulate/report loop that BlackWall supplies.

This validates the integration strategy:

1. BlackWall should classify and unpack first.
2. It should route .NET and other supported formats to REA's focused static
   workflows.
3. It should use REA's native function and value-flow tools after triage has
   identified high-value addresses or features.
4. It should not present raw REA runtime capabilities as safe malware tools.

The format-aware router described in [`../roadmap.md`](../roadmap.md) is now
implemented and covered by the source-built cross-format corpus. The retained
[`inert benchmark summary`](cross-format-inert-2026-10-20.md) and
[`machine-readable result`](cross-format-inert-2026-10-20.json) supersede this
two-sample demonstration for regression claims. That run also caused concrete
router corrections: standalone JavaScript no longer enters REA's directory/
ASAR-only workflow, known UPX goes directly to the focused unpacker, and broad
document scans wait for suspicious evidence. PE resource extraction and full
ILSpy-backed C# decompilation remain the clearest Windows-specific gaps exposed
by the original live-sample check.
