# Supported platforms and analysis matrix

Last reviewed: 2026-10-21.

“Supported” means exercised by a committed inert fixture and the release image
suite. It does not mean every malformed, packed, encrypted, or obfuscated input
will parse successfully; gaps remain visible in the evidence ledger.

## Host and image

| Layer | Supported | Notes |
|---|---|---|
| Host | Ubuntu 24.04, x86-64, Docker Engine | Release and CI admission platform |
| Image | Linux/amd64 | Published as `ghcr.io/<owner>/blackwall:<version>` on signed releases |
| Other Linux hosts | Best effort when Docker supports Linux/amd64 | Not release-gated |
| macOS/Windows Docker Desktop | Best effort via Linux/amd64 virtualization | GUI/X11 path is not tested |
| arm64 host/image | Not supported | Several pinned upstream tools are amd64-only |
| Native detonation | Not supported | The KVM plane remains unbuilt; never execute samples in Docker |

## Static and emulated targets

| Target | Tested lane | Important boundary |
|---|---|---|
| PE x86/x64 | Ghidra, PE metadata/resources, capa/FLOSS, REA, bounded Speakeasy | Emulation is not native execution |
| .NET PE | ILSpy inventory/decompile/resources plus REA; mixed mode also routes native | Reflection/runtime dispatch can remain unresolved |
| ELF x86/x64 | Ghidra, metadata, REA layout/core, bounded Unicorn entry emulation | No OS loader, syscalls, filesystem, or network |
| Mach-O x86-64 | Metadata/imports/symbols/signature structure, ObjC/Swift discovery, Ghidra | Signature trust/notarization is not verified |
| APK/DEX | Pinned JADX resources and focused Java/Kotlin decompile plus REA | No app execution or ADB |
| Office/OLE/OOXML, RTF, PDF | oletools and bounded structural/active-content extraction | No rendering or native Office/reader execution |
| JavaScript, VBScript, PowerShell, VBA | Static parsing, heuristics, bounded decoding | No native interpreter is invoked |
| ZIP, TAR, gzip, bzip2, xz, CAB | Generated-name recursive extraction | LZX, Quantum, MSZIP and uncompressed CAB are covered |
| CPIO newc, U-Boot uImage, UPX | Bounded extraction/unpacking and rerouting | Unsupported codecs are explicit gaps |
| WASM, EVM, SQLite, PCAP/web captures | Focused REA workflows | Static/recorded inputs only |
| Recorded ELF core | Exact isolated pwntools/REA provider | A core file is parsed, never resumed |

The source-built fixture manifest in `benchmarks/corpus/inert-manifest.json` is
the machine-readable coverage authority. See `benchmarks/README.md` for how to
rebuild and verify it.
