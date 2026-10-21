# BlackWall evaluation corpus

This directory contains a source-built, inert cross-format corpus and the
offline harness used to compare three analysis lanes:

- `core`: bounded BlackWall lab probes, without REA or the persistent Ghidra
  MCP workspace;
- `raw-rea`: one format-specific upstream REA workflow selected by the corpus
  manifest;
- `hybrid`: the ready steps selected by BlackWall's deterministic router.

The 26 committed fixtures cover native PE, UPX-packed PE, four .NET PE/CLI
shapes (ordinary IL, a mixed-mode CorFlags marker, obfuscated identifiers, and
an embedded resource), ELF, an ELF core, Mach-O, APK, JavaScript, PowerShell,
VBScript, VBA source, WASM, ordinary and macro-enabled OOXML/Office, RTF, PDF,
PCAP, nested firmware/archive layers, uncompressed and mixed-codec CAB,
PE-embedded IExpress CAB, and inert graded configuration carriers (including a
reconstructed Amadey v4/v5 shape).
Document fixtures include external relationships, active content, and embedded
payloads; script fixtures include inert concatenation, character-code,
encoded-command, and Base64 shapes. The nested fixture follows ZIP → U-Boot
uImage → newc CPIO so graph depth, rerouting, and lineage are measurable.
Fixtures are generated from source in this directory, contain stable
`.invalid`/TEST-NET indicators, and are never executed. The attributed
XlsxWriter VBA example and its BSD-2-Clause notice are stored beside the
sources. Hashes and builder versions are locked in
[`corpus/inert-manifest.json`](corpus/inert-manifest.json).

## Run it

The default plan mode verifies every hash, checks the expected format and
packing verdict, and records all three lane plans without executing tools:

```bash
PYTHONPATH=lab python -m blackwall_lab.benchmark \
  --mode plan --output /tmp/blackwall-plan
```

The complete image adds the installed analyzers. Keep it offline when running
the executable benchmark:

```bash
docker run --rm --network none \
  -v "$PWD/benchmark-output:/work/out" blackwall:latest \
  bw-benchmark --mode execute --output /work/out/inert
```

Both modes write a versioned JSON result and a short Markdown table when
`--output PREFIX` is supplied. Execute mode records each tool outcome, wall
time, timeout, retained-evidence digest, useful-evidence recall, IOC recall,
and configuration recovery. Times are single-run observations, not stable
performance estimates. Persistent Ghidra is MCP-only and remains visibly
`not_run` in this CLI harness.

Analyst reports are deliberately not inferred from analyzer output. To score
them, put each independently produced report at
`REPORTS/<fixture-id>/<lane>.md` (or `.json`) and add
`--reports-dir REPORTS`. Missing reports remain `not_measured`.

The committed 2026-10-20 image run is available as a
[`Markdown summary`](../docs/benchmarks/cross-format-inert-2026-10-20.md) and
[`machine-readable result`](../docs/benchmarks/cross-format-inert-2026-10-20.json).
It is a reproducibility baseline, not a universal performance claim.
The focused 2026-10-21 native/mobile/extraction run is likewise available as
a [`Markdown summary`](../docs/benchmarks/native-extraction-inert-2026-10-21.md)
and [`machine-readable result`](../docs/benchmarks/native-extraction-inert-2026-10-21.json).
It covers ELF, APK, Mach-O, recorded-core, nested firmware, CAB, and graded
configuration fixtures; the unsupported raw-REA CAB/config outcomes remain
visible rather than being converted into successes.
The separate
[`same-sample operational comparison`](../docs/benchmarks/same-sample-strict-2026-10-21.md)
records what changed between the initial unrestricted/expert-equivalent report
and the current strict default on one real IExpress/Amadey sample. It contains
only hashes and findings, not sample bytes, and is not a controlled model or
timing benchmark.
Operational failure-path coverage (readiness, cancellation, crashes, disk
pressure, corrupt archives, and stale containers) is a separate admission
suite documented in [`docs/reliability.md`](../docs/reliability.md).

Use `python benchmarks/build_corpus.py --verify` for a dependency-free hash
check. Rebuilding fixtures requires local MinGW, GCC, .NET 6 reference packs,
UPX, and Smali:

```bash
python benchmarks/build_corpus.py
git diff -- benchmarks/fixtures benchmarks/corpus/inert-manifest.json
```

Compiler or packer upgrades may change bytes, so review both the toolchain
record and hashes rather than silently accepting regenerated artifacts.

## Malware corpus boundary

[`corpus/malware-manifest.json`](corpus/malware-manifest.json) is hash-only. It
contains labels, source references, and coarse expectations, but no sample
path, archive, or download URL. The harness contains no fetching or extraction
logic. A malware run requires all of the following:

1. a caller-supplied, container-local directory containing files named by their
   full SHA-256;
2. `--manifest .../malware-manifest.json --allow-malware --samples-dir ...`;
3. an environment where `CI` is unset.

The harness verifies every byte against the manifest before routing it. Keep
real samples inside BlackWall's hardened, networkless analysis boundary; never
place them in this repository or a CI artifact.
