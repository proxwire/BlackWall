# Security policy

BlackWall processes hostile files and should be treated as security-sensitive
software. It substantially reduces routine exposure; it does not turn Docker
into a malware detonation boundary.

## Reporting a vulnerability

Please use the repository's private **Security → Report a vulnerability** flow.
Do not attach live malware, credentials, private indicators, or exploit code to
a public issue. Include the affected commit, the violated boundary, and a
minimal inert reproducer when possible.

Only the current `main` branch is supported before the first tagged release.

## Threat model

The default sample container has no network namespace connectivity, a read-only
root filesystem, all Linux capabilities dropped, `no-new-privileges`, resource
limits, and a per-case volume. Samples stay password-zipped on the host and are
extracted only inside that container. The analyst session uses a strict MCP
configuration and cannot access unrelated connectors. Its default `strict`
tool profile omits arbitrary shell/Python execution and the radare2 MCP bridge;
only bounded intent-level analysis and emulation operations are exposed. The
analyst is also denied edits to its MCP configuration, permission settings,
analyst brief, and profile-bearing case metadata.

Important limits:

- The format router reads at most a 1 MiB head window, a 256 KiB tail window,
  and (for an unusually displaced PE header) one additional 512-byte window.
  It never extracts archive members, and strong content signatures outrank
  file-name hints. Classification is still heuristic and is not a security
  gate: a wrong or unknown route must remain visible, and every downstream
  parser is still treated as hostile-input code. Result normalization records
  timeout, cancellation, parser crash, unsupported, partial, skipped, and
  failed states; it does not turn incomplete evidence into a successful
  analysis.
- The evidence ledger uses atomic writes, a case-local lock, content hashes,
  and explicit parent edges. It prevents accidental recursion and detects
  changed retained bytes; it is not a cryptographic trust anchor against an
  attacker who controls the case volume and can rewrite both data and hashes.
  The default analyst reaches it only through bounded MCP operations.
- Ghidra admission requires an MCP-level readiness result rather than a timed
  retry. Parser and bridge descendants run in supervised process groups, while
  `blackwall diagnose` mounts stopped-case volumes read-only and reports repair
  candidates without deleting retained samples, evidence, or the Ghidra
  project. These controls reduce operational failure modes; they do not make
  hostile native parsing memory-safe.
- Static parsers, decompilers, the container runtime, and the host kernel can
  still contain vulnerabilities. Use a dedicated analysis host or VM for
  samples outside your container threat model.
- `--profile expert` deliberately restores scriptable shell/Python tools and
  radare2. In that profile the no-execution rule is a policy boundary: do not
  launch native samples. Speakeasy is API emulation, not native execution.
- The selected profile is per invocation and recorded in case metadata and the
  report. Expert is never remembered as the default for a subsequent session.
- `--gui` mounts the host X11 socket and intentionally weakens isolation.
- Intelligence lookups run in a separate networked container with no sample or
  case mounts, but every submitted hash, IOC, or family name is disclosed to
  the selected provider.
- Native detonation requires the fail-closed KVM design in
  [`docs/safe-execution.md`](docs/safe-execution.md); it is not implemented by
  the current Docker sandbox.

## Dependency audits

Python dependencies are transitively pinned with hashes, npm dependencies use
a committed lockfile, and downloadable tool archives are versioned and
SHA-256-verified where publishers provide digests. CI fails on newly reported
Python or npm vulnerabilities, except for the explicit temporary exception
below.

### ChromaDB 1.5.9 exception

Reviewed: 2026-10-20.

`pyghidra-mcp==0.2.7` requires `chromadb>=1.3.5`; 1.5.9 is the newest published
release and currently has four advisory IDs reported by `pip-audit`:

- [PYSEC-2026-311 / CVE-2026-45829](https://osv.dev/vulnerability/PYSEC-2026-311)
- [PYSEC-2026-3814 / CVE-2026-45833](https://osv.dev/vulnerability/PYSEC-2026-3814)
- [PYSEC-2026-3815 / CVE-2026-45831](https://osv.dev/vulnerability/PYSEC-2026-3815)
- [PYSEC-2026-3813 / CVE-2026-45830](https://osv.dev/vulnerability/PYSEC-2026-3813)

The first two concern Chroma server paths that can load attacker-selected model
repositories; the latter two concern Chroma's server authorization and tenant
isolation. BlackWall does not start or expose a Chroma server, accept Chroma
clients, enable Chroma authentication, or use multiple Chroma tenants.
`pyghidra-mcp` constructs an embedded `PersistentClient` with anonymized
telemetry disabled. Its fixed ONNX model is cached while the image is built,
before any sample is mounted; analysis runs with `--network none`.

Those facts remove the affected remote-server and tenant boundaries from this
deployment, so CI ignores only these advisory IDs. The package remains present
and should be upgraded—and the exceptions removed—as soon as a compatible
fixed release exists. Reusing this image as a Chroma server invalidates this
assessment.

This is an actively enforced exception, not a permanent allowlist. The
machine-readable policy in `.github/dependency-exceptions.json` records both
reviewed pins and all four IDs. On every CI run,
`scripts/check_dependency_exceptions.py --online` queries the official PyPI
package metadata and OSV records and fails if:

- either project publishes a version that has not been reviewed;
- an ignored advisory stops affecting the pinned ChromaDB version;
- the published `pyghidra-mcp` metadata drops or changes the known ChromaDB
  dependency relationship; or
- 30 days pass without another explicit review.

As of the review date, PyPI still reports `pyghidra-mcp==0.2.7` and
`chromadb==1.5.9` as the latest releases, and OSV lists 1.5.9 as affected by
all four advisories. A release alert therefore requires a compatibility and
audit review rather than a policy-file refresh by itself.
