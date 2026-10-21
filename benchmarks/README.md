# BlackWall evaluation corpus

This directory contains a source-built, inert cross-format corpus and the
offline harness used to compare three analysis lanes:

- `core`: bounded BlackWall lab probes, without REA or the persistent Ghidra
  MCP workspace;
- `raw-rea`: one format-specific upstream REA workflow selected by the corpus
  manifest;
- `hybrid`: the ready steps selected by BlackWall's deterministic router.

The committed fixtures cover native PE, UPX-packed PE, .NET PE/CLI, ELF, APK,
JavaScript, WASM, OOXML/Office, RTF, PDF, and PCAP. Every fixture is generated
from source in this directory, contains stable `.invalid`/TEST-NET indicators,
and performs no I/O or other behavior. Hashes and builder versions are locked
in [`corpus/inert-manifest.json`](corpus/inert-manifest.json).

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
