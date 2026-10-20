# Safe native-execution boundary

Status: design only. BlackWall does not currently expose native sample
execution. `lab.emulate_windows` is API emulation, not detonation.

## Why the analysis container is not enough

The container is intentionally useful: it contains complex native parsers and
offers Python and shell access. Those properties also mean it should be treated
as a strong static-analysis workspace, not as a malware detonation boundary.
`--network none`, a non-root user, dropped capabilities, a read-only root, and
resource limits reduce risk but do not make executing a hostile kernel-facing
program safe.

REA's runtime-capable process, debugger, Frida, ADB, and browser commands are
therefore not exposed by BlackWall. Installing REA does not change the sample
execution policy.

## Required architecture

A future `detonate` tool must fail closed behind a separate hardware-virtualized
guest with all of these properties:

1. A reviewed, immutable base image and a fresh disposable qcow2 overlay for
   every run. No reuse of a guest after a sample starts.
2. KVM available and writable. If hardware virtualization, snapshot creation,
   or isolation checks fail, execution does not begin.
3. No host directories, Docker socket, clipboard, USB devices, or shared
   filesystem mounted in the guest. Sample ingress and result egress use a
   small authenticated control channel with explicit size and file-type limits.
4. Networking defaults to no NIC. An optional simulation network may contain
   only INetSim/FakeNet services on a dedicated libvirt network with host
   forwarding, bridging, routing, DNS recursion, and Internet egress denied by
   independently verified firewall rules.
5. Guest-side Procmon/Sysmon/ETW, packet capture, process-tree, registry, and
   filesystem collectors start before the sample. Execution has both guest and
   host watchdog deadlines.
6. On completion or timeout, the VM is forcibly stopped. Only bounded telemetry
   and explicitly selected artifacts are exported; binary artifacts remain
   password-protected. The overlay and transient network are then destroyed.
7. Cleanup is verified before a result is reported. A cleanup failure marks
   the run unsafe and blocks another detonation.

The control API should expose intent-level operations such as `detonate_pe`
and `collect_trace`, not an unrestricted REA MCP server or arbitrary guest
shell. REA runtime adapters may be used behind that API only when they operate
inside or exclusively against the disposable guest.

## Admission checks

Before this lane can be enabled, automated tests must prove:

- `/dev/kvm` access and the expected QEMU/libvirt versions;
- no route from the guest network to the Internet, host LAN, or management
  services;
- no host mount or device passthrough in the generated VM definition;
- overlay creation and destruction on success, timeout, crash, and forced
  cancellation;
- watchdog termination of a deliberately hanging benign fixture;
- artifact export limits and rejection of unexpected paths and symlinks; and
- a clean base-image hash before every run.

Until those checks exist and pass, BlackWall must continue to report native
execution as unavailable rather than falling back to Docker.
