# Pinned REA runtime

This directory is the reproducible npm input for BlackWall's in-container REA
static-analysis adapter.

- `rea-agents` is pinned exactly to 6.7.0 and all transitive package integrities
  are committed in `package-lock.json`.
- The Docker build pins and verifies Node 24.18.0 and the separate JADX MCP
  bridge 0.7.1 by SHA-256. It also verifies the publisher-built WABT 1.0.42
  archive by SHA-256 and supplies Wireshark 4.x `tshark`/`capinfos` for offline
  packet-capture inspection.
- Installation uses `--ignore-scripts --omit=optional`; REA's optional Frida
  dependency remains represented in the lockfile but is not installed.
- The raw REA MCP server is not registered. `blackwall_lab.server` exposes an
  explicit list of static CLI workflows and retains their Evidence JSON. The
  image health check compares that allowlist with the installed release's real
  command manifest so nonexistent or renamed commands fail validation.

REA is MIT-licensed; its published package includes its `LICENSE` and
third-party notices. When updating REA, review the source/tag and published
tarball, refresh the lockfile with the pinned Node/npm version, update all
checksums, audit newly added dependencies and lifecycle scripts, and rerun the
Docker smoke tests before changing the allowlist. Also rerun the inert benchmark
and reliability admission suite because a parser or provider update can change
routing outcomes, timeouts, and descendant-process behavior.
