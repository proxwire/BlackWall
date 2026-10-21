# .NET static-analysis lane

BlackWall routes PE/CLI assemblies to a dedicated static lane. Ghidra remains
available for the native half of a mixed-mode image, but IL-only code is
handled by CLR metadata parsing, ILSpyCmd, and REA's independent managed-code
workflows. None of these operations loads the target assembly for execution.

## Pinned toolchain

The image installs ILSpyCmd `11.1.0.9782` from its official NuGet package and
runs it on Microsoft .NET runtime `10.0.13`. The Docker build verifies these
SHA-256 values before extraction:

| artifact | SHA-256 |
|---|---|
| `ilspycmd.11.1.0.9782.nupkg` | `74c07facaf1850c78a779fc509031f756e1c0de24b1a536f3363d7ef81ce001f` |
| `dotnet-runtime-10.0.13-linux-x64.tar.gz` | `958c952691d2c3f8ce21f717f4e911c02b5da0e21ead21bd576368c454b79c77` |

`bw-ilspy` disables update checks and .NET diagnostics and gives the runtime a
1 GiB managed-heap ceiling. The surrounding BlackWall process supervisor adds
wall-clock and combined-output limits and kills the complete process group on
timeout, cancellation, or output overflow.

## Analyst operations

| operation | purpose | important bounds |
|---|---|---|
| `dotnet_info` | Independent dnfile assembly, name, string, and manifest-resource inventory | 256 MiB input; bounded type, method, string, and resource scans |
| `dotnet_inventory` | ILSpy assembly/reference/type/MethodDef-token listing and CLR mixed-mode flags | literal filter, offset/limit pagination, 4 MiB per metadata table |
| `dotnet_decompile` | C# for exactly one MethodDef token or fully-qualified type | one selector; 8 MiB output; full result retained, preview returned |
| `dotnet_search` | Literal search attributed to decoded IL method bodies | no attacker-controlled regex; at most 2,000 indexed methods and 500 returned hits |
| `dotnet_call_references` | Static incoming/outgoing `call`, `callvirt`, `newobj`, `jmp`, and function-pointer references | exact MethodDef token; bounded method index and result count |
| `dotnet_list_resources` | ILSpy resource names, including entries visible inside `.resources` containers | literal filter and pagination; no paths are written |
| `dotnet_extract_resources` | Raw manifest-resource extraction into the derived-artifact store | exact optional name; 64 resources, 32 MiB each, 64 MiB aggregate by default |

All selectors are passed as argument-vector values. Method decompilation and
call analysis use MethodDef tokens from `dotnet_inventory`, avoiding ambiguous
or option-like attacker-controlled names. Resource names are never used as
filesystem destinations: dnfile reads each raw blob, a temporary anonymous
name receives the bytes, and the evidence store assigns the SHA-256 path.
Linked/external resources are reported but never followed.

## Plan and evidence flow

The managed route first records PE and dnfile metadata, ILSpy inventory,
resource names, strings, and IOCs. Bounded resource extraction is a ready deep
step. C# decompilation, call references, and literal method search remain
deferred until the analyst supplies a token or search term from earlier
evidence. REA's managed overview, member, and native-boundary passes remain
independent cross-checks.

Every tool writes its complete bounded result under `/work/out`. Passing the
planned result to `normalize_analysis_result` copies that output into the
content-addressed evidence store and records the exact arguments, source hash,
tool version, truncation state, and plan step. Extracted resources additionally
receive a `dotnet-manifest-resource` lineage edge before they are routed as new
artifacts.

CLR CorFlags are decoded by the bounded router and checked again by dnfile. An
IL-only assembly skips native Ghidra work. A mixed-mode marker adds the
persistent Ghidra workspace plus a deferred focused native-function step while
keeping ILSpy primary for managed methods.

## Coverage and limits

The committed corpus includes ordinary IL, an inert image with the IL-only
CorFlag cleared, short/confusable obfuscation identifiers, and a manifest
resource. Image integration tests exercise inventory, C# decompilation,
method search, call references, mixed-mode recognition, obfuscation hints,
resource listing, extraction, and lineage.

Static call references do not resolve reflection, delegates, dynamically
generated code, or runtime dispatch. Overloaded incoming calls are associated
by type and method name when ILSpy does not decode a signature blob in its
metadata-table output, and the result states that limitation. Obfuscation can
also make decompiled C# incomplete or misleading; retain CIL, metadata, REA,
and native-boundary disagreements rather than forcing one conclusion.
