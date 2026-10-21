# BlackWall (development)

This repo builds the lab. It does not analyze malware. Analyst sessions run in
case folders (default `~/BlackWall-cases/<sha256>/`, outside this repo) with
`analyst/CLAUDE.md` as their brief.

## Layout
- `blackwall`: host CLI (bash). Cases, sandbox lifecycle, `.mcp.json`
  generation, launching Claude with `--strict-mcp-config`.
- `docker/Dockerfile`: the analysis image. Tool versions and sha256s are
  pinned as ARGs; bump them together.
- `docker/bin/`: in-container entrypoints (`bw-init`, `bw-*-mcp`,
  `bw-stdio-guard`).
- `lab/blackwall_lab/`: the `lab` MCP server (`server.py`), deterministic
  format router (`router.py`), durable evidence/checkpoint ledger
  (`evidence.py`), process and volume reliability checks (`reliability.py`),
  Ghidra readiness client (`ghidra_ready.py`), evaluation harness
  (`benchmark.py`), the `intel` MCP server (`intel.py`), bounded ILSpy .NET
  operations, isolated document/script (`documents.py`), archive/configuration
  (`extractors.py`, `config_extractors.py`), native (`native.py`), case/report
  (`casework.py`), and detection (`detections.py`) workers, and the Speakeasy
  runner (`emu_speakeasy.py`, which runs in a subprocess).
- `analyst/`: the playbook copied into every case on `analyze` (CLAUDE.md,
  skills, permission settings).
- `benchmarks/`: source-built inert fixtures, manifests, and reproducible
  three-lane evaluation inputs. Never add live malware bytes here.
- `docs/`: roadmap, evidence/recovery contracts, benchmark results, and the
  design-only native-execution boundary.
- `tests/`: host lifecycle/profile tests and image reliability integration.
- `rules/yara/`: bundled YARA rules.

## Roadmap handoff

Roadmap items 1–12 and all field-validation follow-ups are complete. The only
remaining roadmap work is the hardware-isolated dynamic-analysis plane.
Preserve every existing admission check. See `docs/roadmap.md` for acceptance
criteria.

## Invariants (don't break these)
- Sample bytes never exist unzipped on the host. Anything that parses the
  sample runs in the sandbox.
- Sandbox containers: `--network none`, `--cap-drop ALL`, `no-new-privileges`,
  read-only rootfs, non-root. Only the `intel` container has network access,
  and it never mounts case data.
- Analyst sessions launch with `--strict-mcp-config` and host Bash/WebFetch
  denied.
- `analyze` defaults to the strict profile. Its MCP surface must not include
  arbitrary process execution; shell, Python, and radare2 remain behind the
  explicit `--profile expert` opt-in.
- Format detection must remain bounded and deterministic. Native PE/ELF plans
  keep persistent Ghidra primary, broad duplicate REA passes stay opt-in, and
  every non-success state remains explicit and continuable.
- Every planned result is evidence-recorded against its stable plan ID. Derived
  bytes require a parent lineage edge, and material report/annotation claims
  require evidence links that pass the case audit.
- Parser descendants must remain in a supervised process group. Timeout,
  cancellation, and signal crash are distinct continuable evidence gaps.
  Diagnostics may identify scratch cleanup candidates but never remove retained
  state, samples, or the persistent Ghidra project.
- Document and script analysis must stay interpreter-free. Preserve the worker
  memory/time/output ceilings, archive and decoding budgets, generated output
  names, and parent-process path/size/hash validation before lineage admission.
- Android and native parity must remain static or explicitly emulated. Preserve
  the pinned JADX bridge, isolated exact REA pwntools profile, Mach-O signature
  verification disclaimer, Unicorn syscall boundary, and absence of untested
  desktop/IL2CPP tools.
- Recursive extraction is a globally bounded graph, not an unbounded loop.
  Preserve generated output names, traversal/bomb controls, content
  deduplication, parent validation, lineage, and deterministic rerouting.
  Configuration extractors must remain statically registered reviewed code.
- Case exports remain encrypted and manifest-verified; import must never unpack
  the raw original on the host. Scratch cleanup must not touch state, samples,
  rules, or Ghidra. Detection candidates require retained evidence and their
  type-specific validation gate before export.
- Releases require a verified signed version tag. Published image digests must
  remain signed and attested, SBOM generation must cover image/Python/npm, and
  automated dependency changes must stay inside the explicit allowlist.

## Dev loop
- `docker build --build-arg UID=$(id -u) --build-arg GID=$(id -g) -t blackwall:latest -f docker/Dockerfile .`
  (the lab/bin layers are last, so rebuilds are fast).
- `./blackwall doctor`; use `./blackwall doctor --profile expert` when changing
  the opt-in surface.
- Run `bash tests/test_profiles.sh`, `bash tests/test_reliability.sh`, and the
  Python unit suite before an image build. Run
  `bash tests/test_image_reliability.sh blackwall:latest` after rebuilding.
- Test with benign binaries (e.g. UPX-pack something from
  `/usr/share/windows-resources/binaries`), using `blackwall add` and then
  `blackwall analyze`.
- `start` and `analyze` automatically replace a stale container while retaining
  the named volume. Use `blackwall diagnose <id>` first when recovery is
  unclear; diagnostics never clean up evidence automatically.
