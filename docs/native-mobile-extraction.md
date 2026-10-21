# Native, mobile, and recursive-extraction lanes

BlackWall's roadmap items 8 and 9 add static Android and Mach-O depth, exact
REA ELF/core providers, syscall-blocked ELF emulation, and bounded recursive
extraction. These capabilities remain inside the networkless case container.
They do not install or launch an APK, execute a native sample, attach a
debugger, or provide a guest operating system.

## Android

The image pins and SHA-256-verifies `jadx-headless-mcp` `0.7.1`, whose bundled
JADX engine reports version `1.5.6`. `lab.android_resources` combines REA's
JADX-backed package/manifest overview with raw extraction of
`AndroidManifest.xml`, `resources.arsc`, `res/`, and `assets/`. Raw entries use
generated output names and become `android-resource` lineage children only
after the parent process rechecks their path, size, and SHA-256.

`lab.android_decompile` accepts exactly one class and, optionally, one method
and overload index. The existing `rea_android_search`, `rea_android_class`, and
`rea_android_method` operations remain useful for selecting that target. The
router makes resource/package inspection ready and keeps source decompilation
deferred until earlier evidence identifies a class or method. The APK is
copied to a content-addressed, read-only `.apk` staging name only because JADX
requires the suffix; the canonical sample and evidence identity do not change.

Resource extraction defaults to 128 artifacts, 8 MiB per resource, and 32 MiB
in aggregate. The caller may lower those values or raise them only to the
operation's fixed ceilings. Encrypted entries, links, traversing names, more
than 8,192 scanned members, and declared expansion above 100:1 are rejected.

## Mach-O

`lab.macho_info` runs a purpose-built parser in a supervised worker. It reports
thin or universal headers, architecture, segments, sections, dylibs, symbols,
imports, exports, UUID, entry-file offset, build-version commands, and bounded
Objective-C/Swift section, symbol, and string evidence. Universal binaries
list every validated slice and analyze the first valid slice in detail.

`LC_CODE_SIGNATURE` data is range-checked and hashed, and bounded SuperBlob and
CodeDirectory metadata is decoded. BlackWall deliberately reports
`cryptographic_verification: not_performed`: it does not claim certificate
trust, entitlement correctness, notarization, or Apple service validation.
Mach-O executables also route to the persistent Ghidra project for actual code
analysis; this metadata pass is complementary.

The worker accepts at most 256 MiB, 4,096 load commands, 100,000 symbols, and
2,000 returned rows per large result class. A 1.5 GiB address-space ceiling,
16 MiB file-write ceiling, descriptor limit, no-core policy, output cap, and
parent wall deadline contain parser failures.

## ELF layout, recorded cores, and emulation

REA `6.7.0` requires an exact provider environment for
`inspect-binary-layout` and `inspect-recorded-crash`. BlackWall installs that
environment in `/opt/rea/pwntools`, hash-locking `pwntools==4.15.0`,
`pyelftools==0.33`, and `unicorn==2.1.2` plus every transitive dependency. It
is separate from the main Python environment and is selected only through
`REA_PWNTOOLS_PYTHON`. The image build, `doctor`, command-manifest check, and
integration suite all smoke-test it. The layout adapter supports the upstream
ELF64 x86-64 contract; the recorded-core adapter supports the upstream ELF64
amd64/AArch64 contract. Both parse supplied bytes and launch neither a target
nor a debugger.

`lab.emulate_elf` is a separate BlackWall operation using Unicorn `2.1.4` from
the main runtime. It accepts executable/shared ELF entry points for x86,
x86-64, ARM, AArch64, and MIPS, maps no more than 64 MiB of file-backed load
segments, creates a 2 MiB synthetic stack, and records at most 256 trace rows.
The default instruction ceiling is 100,000 and the default Unicorn wall timer
is five seconds; hard API ceilings are one million instructions and 60
seconds. A syscall instruction stops the probe. There is no syscall forwarding,
dynamic loader, host filesystem, network, or native process execution.

REA `6.7.0` does not publish the desktop-application or IL2CPP commands named
in earlier upstream plans. BlackWall checks their absence and does not register
or advertise placeholder tools. They remain future work unless a release
provides the commands, exact dependencies, and passing inert smoke tests.

## Recursive extraction graph

`lab.recursive_unpack` performs breadth-first traversal and returns
`blackwall.recursive-extraction-graph.v1`. Its default global limits are:

| limit | default | hard caller ceiling |
|---|---:|---:|
| nesting depth | 3 | 8 |
| derived artifacts | 64 | 256 |
| bytes per artifact | 32 MiB | 64 MiB |
| aggregate expanded bytes | 128 MiB | 512 MiB |
| elapsed wall time | 300 s | 900 s |

Every content digest is expanded at most once. Each accepted child is copied
into the content-addressed derived store, linked to its exact parent and
transformation, and immediately passed through the deterministic format router.
The root input is capped at 256 MiB and hashed incrementally before traversal.
The graph records the child's detection, ready/deferred tools, plan ID, depth,
worker outcome, rejection reason, and stop reason. A duplicate, self-edge, or
ancestry cycle never creates more recursive work.

The worker currently handles ZIP/APK, TAR, gzip, bzip2, XZ, CAB (uncompressed,
MSZIP, Quantum, and LZX), newc CPIO, legacy U-Boot uImage (uncompressed, gzip,
bzip2, or LZMA), and UPX. This covers archive, installer,
embedded-filesystem, firmware, and packer layers without executing their
contents. Split/multi-cabinet CAB members and unknown compression methods are
explicit rejections. The checksum-pinned cabextract/libmspack lane decodes
Quantum/LZX into a private bounded stream, after which BlackWall splits the
prevalidated member sizes and admits only generated output names. PE
`RT_RCDATA` resources are scanned structurally for CABs and automatically fed
back into the recursive graph.

Archive names are evidence only. Absolute paths, drive prefixes, `..`, control
bytes, NULs, symlinks, hard links, devices, and encrypted ZIP entries are
rejected. Outputs are always named `artifact-NNNN.bin` in a new private
directory. Expansion is bounded by declared sizes, a 100:1 ratio, per-output
and aggregate byte budgets, a member-scan ceiling, worker resource limits, and
the parent deadline. The parent then independently validates location, file
type, size, digest, count, and aggregate bytes before lineage admission.

## Configuration extractor plugins

`lab.config_extractors` lists a static registry of reviewed package code;
sample bytes cannot choose a Python import path. `lab.config_extract` runs a
selected family or probes the registry in an isolated worker with a 1 MiB
input ceiling. Each match must return a bounded scalar value map, source byte
ranges, validation details, and a `low`, `medium`, or `high` confidence tier
with a numeric score and reasons. Returned values pass through BlackWall's
secret redactor while the complete bounded result remains under `/work/out`.

The built-in `blackwall-inert-v1` plugin and fixture admission-test magic,
length, JSON decoding, CRC validation, semantic-key grading, and recursive
recovery. Production family plugins must be added as reviewed source with
their own positive, corrupt, truncated, and false-positive fixtures; runtime
plugin loading is intentionally unsupported. The reviewed `amadey-v4-v5`
plugin statically reverses its substitution/Base64 strings and one bounded
ROR/XOR+RC4 loader shape; reconstructed positive, corrupt, truncated, and
false-positive fixtures keep live malware bytes out of the repository.

## Coverage and known limits

The 26-fixture inert corpus adds a signed-structure Mach-O, an ELF core,
nested ZIP → uImage → CPIO layers, a CAB installer, and a graded configuration
carrier. Unit tests cover traversal names and bomb ratios as well as format
parsers. Production-image admission tests exercise the exact REA profile,
JADX resource/source paths, Mach-O/Ghidra routing, bounded ELF emulation,
recursive lineage/rerouting, CAB, and configuration confidence.

These lanes are static or emulated evidence sources. JADX can lose semantics
under obfuscation or malformed DEX; the Mach-O parser does not validate Apple
trust; the ELF emulator does not model an operating system; and the extractor
set is deliberately finite. Preserve each unsupported, partial, timeout,
limit, and parser failure as an evidence gap rather than inferring benignness.
