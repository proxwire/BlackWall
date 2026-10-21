# Changelog

All notable user-facing changes are recorded here. BlackWall uses semantic
version tags; release dates are UTC.

## Unreleased

- No unreleased changes.

## 0.1.0 — 2026-10-21

- Added strict and expert analysis profiles, deterministic format routing,
  durable evidence/lineage/checkpoints, and reliability admission checks.
- Added inert cross-format benchmarks and bounded static lanes for .NET,
  documents/scripts, Android, Mach-O, ELF/core, firmware, archives, and
  configuration recovery.
- Added recursive extraction with pinned LZX/Quantum CAB decoding, automatic
  PE `RCDATA` CAB discovery, and a reviewed Amadey v4/v5 extractor.
- Added case status/resume/cancel/archive/import/cleanup, deterministic reports,
  and sample/run comparison without moving raw sample bytes onto the host.
- Added evidence-linked YARA, Sigma, Suricata, and reviewed ATT&CK candidate
  generation. DLL side-loading maps to `T1574.002` by regression contract.
- Added CycloneDX SBOM generation, signed-release automation, keyless image
  signing and attestations, and controlled Python/npm lock-update pull requests.

The hardware-isolated KVM detonation plane is not included. Docker remains a
static-analysis and bounded-emulation boundary only.
