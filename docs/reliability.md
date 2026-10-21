# Reliability, readiness, and recovery

BlackWall treats parser availability and case recovery as explicit state. It
does not hide startup timing behind retries and does not delete retained case
material while diagnosing a failure.

## Ghidra readiness

Each case has one `pyghidra-mcp` service bound to `127.0.0.1` inside its
`--network none` container. `bw-ghidra-mcp` serializes startup with a case-local
lock, cleanly evicts a server from the wrong headless/GUI mode, and launches
the replacement with `--wait-for-analysis`. Before opening the stdio bridge it
uses a real MCP session to call `list_project_binaries` and requires every
listed program to report `analysis_complete: true`.

The probe records its last bounded status in
`/work/state/ghidra-readiness.json`. An empty project is ready because some
case formats are intentionally not importable by Ghidra. Code and string index
readiness are reported separately; they do not block decompilation readiness.
A bounded probe failure closes the server, keeps the project, and points the
operator to the case log and `blackwall diagnose`.

## Supervised parser outcomes

Every lab subprocess starts in a new process group. The supervisor kills the
whole group on its deadline, supports cooperative cancellation, and also tears
down descendants if its own caller is interrupted. Results distinguish:

- `timeout`: the command exceeded its wall-clock budget;
- `cancelled`: the caller deliberately stopped pending work;
- `crashed`: the parser terminated on a signal; and
- `output_limit`: the parser crossed its operation-specific combined stdout/
  stderr cap and its process group was stopped; and
- `failed`: a normal nonzero exit without usable complete output.

All are continuable normalized gaps. Stdio server bridges use the same group
principle and escalate EOF through SIGINT, SIGTERM, and SIGKILL so a cancelled
client cannot strand bridge or parser descendants. The separately supervised
per-case Ghidra HTTP service intentionally remains available for the next MCP
connection.

## Non-destructive diagnosis

Run `blackwall diagnose <id>` after an extraction, parser, or storage failure.
It reports:

- stale image, case, sandbox-spec, or analysis-volume container wiring;
- free space and the minimum safe write reserve;
- retained evidence/output/checkpoint/claim counts and corrupt JSON state; and
- bounded scratch and abandoned temporary-file cleanup candidates.

The command is diagnostic only. It never removes a case container or volume,
and the in-volume inspection never writes or deletes files. `/work/state`,
`/work/samples`, and `/work/ghidra` are explicitly protected. If a stale
container is recreated by `start` or `analyze`, Docker receives the same named
volume and no volume-removal operation.

`bw-init` checks free space and validates the encrypted archive before writing
sample bytes. Extraction uses a trapped temporary directory. Corrupt archives,
hash mismatches, multiple-file archives, and disk pressure exit with a recovery
action while prior evidence remains intact.

Use `blackwall start <id>` or `blackwall analyze <id>` to recreate a reported
stale container while preserving its named volume. Review any scratch paths
reported by `diagnose` in a case shell before removing them manually. Do not use
`blackwall rm <id>` as a repair command: it intentionally deletes the analysis
volume, and `--purge` can additionally delete the host case directory after
confirmation.

## Integration coverage

CI exercises the production paths with inert data:

| failure path | assertion |
|---|---|
| Ghidra startup | a real stdio client is not connected until an inert system binary is analyzed |
| timeout | a delayed descendant is killed and cannot write its marker |
| cancellation | EOF/cooperative cancellation kills the complete process group |
| parser crash | signal termination is classified and the supervisor remains alive |
| parser output overflow | retained stdout/stderr stays at the configured cap and the child is stopped |
| .NET hostile-shape coverage | pinned ILSpy inventories/decompiles inert mixed-mode-marker, obfuscated, and resource-bearing fixtures under the production bounds |
| document/script hostile-shape coverage | pinned oletools extracts a benign macro project; bounded workers recover external relationships, OOXML/RTF/PDF objects, deobfuscated scripts, and lineage-linked payloads without native interpreters |
| Android/JADX coverage | the pinned bridge reports JADX 1.5.6, extracts generated-name resources with lineage, and decompiles one inert selected class without installing the APK |
| native-format coverage | the exact REA pwntools profile parses ELF layout and a recorded core; Mach-O metadata/signature/Objective-C/Swift evidence and syscall-blocked Unicorn emulation pass their production workers |
| recursive extraction | nested ZIP → uImage → CPIO and CAB fixtures preserve every parent edge, reroute each child, recover a graded config, and stop under graph budgets |
| hostile archive names/bombs | traversal names and excessive expansion are rejected without materializing attacker-selected paths or exceeding caller byte budgets |
| stale container | the container is replaced with the same named volume and no volume deletion |
| full disk | an actually full tmpfs fails preflight while an evidence sentinel survives |
| corrupt archive | validation fails, extraction scratch is removed, and retained evidence survives |

The dependency-exception monitor is complementary: it verifies the local pins
and exact CI ignores offline, then checks official PyPI and OSV metadata online.
It fails on unreviewed releases, changed affected-version data, or an expired
30-day review window.
