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
configuration and cannot access unrelated connectors.

Important limits:

- Static parsers, decompilers, the container runtime, and the host kernel can
  still contain vulnerabilities. Use a dedicated analysis host or VM for
  samples outside your container threat model.
- Scriptable shell/Python tools make the no-execution rule a policy boundary.
  Do not launch native samples. Speakeasy is API emulation, not native
  execution.
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
