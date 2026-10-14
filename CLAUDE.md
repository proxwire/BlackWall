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
- `lab/blackwall_lab/`: the `lab` MCP server (`server.py`), the `intel` MCP
  server (`intel.py`), and the Speakeasy runner (`emu_speakeasy.py`, which runs
  in a subprocess).
- `analyst/`: the playbook copied into every case on `analyze` (CLAUDE.md,
  skills, permission settings).
- `rules/yara/`: bundled YARA rules.

## Invariants (don't break these)
- Sample bytes never exist unzipped on the host. Anything that parses the
  sample runs in the sandbox.
- Sandbox containers: `--network none`, `--cap-drop ALL`, `no-new-privileges`,
  read-only rootfs, non-root. Only the `intel` container has network access,
  and it never mounts case data.
- Analyst sessions launch with `--strict-mcp-config` and host Bash/WebFetch
  denied.

## Dev loop
- `docker build --build-arg UID=$(id -u) --build-arg GID=$(id -g) -t blackwall:latest -f docker/Dockerfile .`
  (the lab/bin layers are last, so rebuilds are fast).
- `blackwall doctor`.
- Test with benign binaries (e.g. UPX-pack something from
  `/usr/share/windows-resources/binaries`), using `blackwall add` and then
  `blackwall analyze`.
- An existing sandbox keeps the old image: `docker rm -f bw-<id>` (the volume
  survives) and start again.
