#!/usr/bin/env bash
set -euo pipefail

image=${1:-blackwall:latest}
fixture_root=$(mktemp -d)
trap 'rm -rf "$fixture_root"' EXIT
printf 'this is not a zip archive\n' > "$fixture_root/corrupt.zip"
sha=$(printf 'c%.0s' {1..64})

docker run --rm --network none --read-only \
  --tmpfs /tmp:rw,exec,nosuid,nodev,size=32m \
  --tmpfs /work:rw,exec,nosuid,nodev,size=512m,mode=1777 \
  -v "$fixture_root/corrupt.zip":/case/sample.zip:ro \
  "$image" sh -eu -c '
    mkdir -p /work/state/evidence
    printf retained > /work/state/evidence/sentinel
    if bw-init "$1" >/tmp/init.out 2>/tmp/init.err; then
      echo "corrupt archive unexpectedly initialized" >&2
      exit 1
    fi
    grep -q "sample.zip is corrupt" /tmp/init.err
    test "$(cat /work/state/evidence/sentinel)" = retained
    test -z "$(find /work/scratch -maxdepth 1 -name "extract.*" -print -quit)"
  ' sh "$sha"

docker run --rm --network none --read-only \
  --tmpfs /tmp:rw,exec,nosuid,nodev,size=32m \
  --tmpfs /work:rw,exec,nosuid,nodev,size=2m,mode=1777 \
  -v "$fixture_root/corrupt.zip":/case/sample.zip:ro \
  -e BW_MIN_FREE_BYTES=1 \
  "$image" sh -eu -c '
    mkdir -p /work/home/.cache /work/samples/original /work/samples/derived \
      /work/out /work/state/evidence /work/ghidra /work/scratch
    ln -s "$CHROMA_CACHE" /work/home/.cache/chroma
    printf retained > /work/state/evidence/sentinel
    dd if=/dev/zero of=/work/full-volume bs=65536 2>/dev/null || true
    test "$(df -Pk /work | awk "NR == 2 {print \$4}")" -eq 0
    if bw-init "$1" >/tmp/init.out 2>/tmp/init.err; then
      echo "full-volume preflight unexpectedly initialized" >&2
      exit 1
    fi
    grep -q "insufficient free space" /tmp/init.err
    test "$(cat /work/state/evidence/sentinel)" = retained
  ' sh "$sha"

docker run --rm --network none --read-only \
  --tmpfs /tmp:rw,exec,nosuid,nodev,size=32m \
  --tmpfs /work:rw,exec,nosuid,nodev,size=64m,mode=1777 \
  "$image" sh -eu -c '
    mkdir -p /work/home /work/state /work/out
    BW_STDIO_EOF_GRACE=0.05 BW_STDIO_INT_GRACE=0.05 \
      BW_STDIO_TERM_GRACE=0.05 BW_STDIO_KILL_GRACE=0.05 \
      bw-stdio-guard sh -c "trap \"\" INT TERM; (sleep 1; touch /work/orphan) & wait" \
      </dev/null || true
    sleep 1.1
    test ! -e /work/orphan
    bw-reliability --self-check
  '

docker run --rm --network none --read-only \
  --tmpfs /tmp:rw,exec,nosuid,nodev,size=32m \
  --tmpfs /work:rw,exec,nosuid,nodev,size=128m,mode=1777 \
  -e GHIDRA_INSTALL_DIR=/not-a-ghidra-install \
  "$image" sh -eu -c '
    mkdir -p /work/home/.cache /work/samples/original /work/state /work/out /work/ghidra
    ln -s "$CHROMA_CACHE" /work/home/.cache/chroma
    digest=$(sha256sum /bin/true | cut -d" " -f1)
    cp /bin/true "/work/samples/original/$digest"
    started=$(date +%s)
    if BW_GHIDRA_READY_TIMEOUT=60 bw-ghidra-mcp </dev/null \
        >/tmp/ghidra.out 2>/tmp/ghidra.err; then
      echo "invalid Ghidra install unexpectedly became ready" >&2
      exit 1
    fi
    elapsed=$(( $(date +%s) - started ))
    test "$elapsed" -lt 10
    grep -q "exited during startup" /tmp/ghidra.err
    test -d /work/ghidra
  '

docker run --rm --network none --read-only \
  --tmpfs /tmp:rw,exec,nosuid,nodev,size=128m \
  --tmpfs /work:rw,exec,nosuid,nodev,size=256m,mode=1777 \
  "$image" python -c '
import hashlib
import shutil
from pathlib import Path
from blackwall_lab import server

for directory in (server.SAMPLES / "original", server.DERIVED, server.OUT):
    directory.mkdir(parents=True, exist_ok=True)

def stage(name):
    source = Path("/opt/blackwall/benchmarks/fixtures") / name
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    shutil.copyfile(source, server.SAMPLES / "original" / digest)
    return f"original/{digest}"

managed = stage("dotnet.pe")
inventory = server.dotnet_inventory(managed)
methods = inventory["methods"]["items"]
score = next(row for row in methods if row["Name"] == "Score")
assert "Score" in server.dotnet_decompile(managed, method=score["Token"])["source_preview"]
assert server.dotnet_search(managed, "EndpointValue")["matched_methods"] >= 1
assert server.dotnet_call_references(managed, score["Token"])["incoming_total"] >= 1

mixed = server.dotnet_inventory(stage("dotnet-mixed.pe"))
assert mixed["characteristics"]["mixed_mode"] is True
obfuscated = server.dotnet_inventory(stage("dotnet-obfuscated.pe"))
assert obfuscated["obfuscation_indicators"]
resource = stage("dotnet-resource.pe")
listed = server.dotnet_list_resources(resource)
assert listed["resources"]["items"][0]["name"] == "BlackWallFixture.Payload.txt"
extracted = server.dotnet_extract_resources(resource)
assert extracted["count"] == 1 and extracted["total_bytes"] > 0
'

docker run --rm --network none --read-only \
  --tmpfs /tmp:rw,exec,nosuid,nodev,size=128m \
  --tmpfs /work:rw,exec,nosuid,nodev,size=256m,mode=1777 \
  "$image" python -c '
import hashlib
import json
import shutil
from pathlib import Path
from blackwall_lab import server

for directory in (server.SAMPLES / "original", server.DERIVED, server.OUT):
    directory.mkdir(parents=True, exist_ok=True)

def stage(name):
    source = Path("/opt/blackwall/benchmarks/fixtures") / name
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    shutil.copyfile(source, server.SAMPLES / "original" / digest)
    (server.SAMPLES / "original" / ".meta.json").write_text(json.dumps({
        "sha256": digest, "original_name": name,
    }))
    return f"original/{digest}"

office = stage("office.docx")
triage = server.document_triage(office)
assert any(row["external"] for row in triage["relationships"])
embedded = server.document_extract_artifacts(office)
assert embedded["count"] == 1
assert embedded["artifacts"][0]["lineage"]["relationship"] == "document-embedded-artifact"

macro = server.document_vba(stage("office-macro.xlsm"))
assert macro["tool_version"] == "0.60.2"
assert macro["macro_count"] >= 1
assert "say_hello" in Path(macro["saved_to"]).read_text()

pdf = stage("document.pdf")
pdf_triage = server.document_triage(pdf)
assert any("cmd.exe" in row["value"] for row in pdf_triage["commands"])
assert server.document_extract_artifacts(pdf)["count"] == 2

power = server.script_analyze(stage("powershell.ps1"))
assert power["interpreter_used"] is False
assert any("powershell-decoded.fixture.invalid" in row["value"] for row in power["urls"])
vb_payloads = server.script_extract_payloads(stage("vbscript.vbs"))
assert vb_payloads["count"] == 1
assert vb_payloads["artifacts"][0]["lineage"]["relationship"] == "script-decoded-payload"
'

docker run --rm --network none --read-only \
  --tmpfs /tmp:rw,exec,nosuid,nodev,size=512m \
  --tmpfs /work:rw,exec,nosuid,nodev,size=1g,mode=1777 \
  "$image" python -c '
import hashlib
import json
import shutil
from importlib.metadata import version
from pathlib import Path
from blackwall_lab import server

for directory in (server.SAMPLES / "original", server.DERIVED, server.OUT):
    directory.mkdir(parents=True, exist_ok=True)

def stage(name):
    source = Path("/opt/blackwall/benchmarks/fixtures") / name
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    shutil.copyfile(source, server.SAMPLES / "original" / digest)
    (server.SAMPLES / "original" / ".meta.json").write_text(json.dumps({
        "sha256": digest, "original_name": name,
    }))
    return f"original/{digest}"

assert version("unicorn") == "2.1.4"
manifest = server._validate_rea_command_manifest()
assert set(manifest["unadvertised_optional_absent"]) == {
    "inspect-desktop-application", "inspect-il2cpp-metadata",
}

elf = stage("native-elf.elf")
layout = server.rea_elf_layout(elf, timeout=120)
assert layout["rc"] == 0 and layout["command"] == "inspect-binary-layout"
emulation = server.emulate_elf(
    elf, max_instructions=2000, emulation_timeout_ms=1000, timeout=20,
)
assert emulation["engine"]["version"] == "2.1.4"
assert emulation["execution_boundary"]["native_execution"] is False
assert emulation["instruction_count"] > 0

core = server.rea_recorded_crash(stage("recorded-core.elf"), timeout=120)
assert core["rc"] == 0 and core["command"] == "inspect-recorded-crash"

macho = server.macho_info(stage("native-macho.macho"), timeout=30)
assert macho["objective_c"]["present"] is True
assert macho["swift"]["present"] is True
assert macho["code_signature"]["present"] is True
assert any(row["name"] == "_puts" for row in macho["imports"])

apk = stage("fixture.apk")
resources = server.android_resources(
    apk, max_resources=16, max_resource_bytes=1024 * 1024,
    max_total_bytes=4 * 1024 * 1024, timeout=120,
)
assert resources["engine"]["name"] == "JADX"
assert resources["jadx_evidence"]["rc"] == 0
assert resources["count"] >= 3
assert all(row["lineage"]["relationship"] == "android-resource" for row in resources["artifacts"])
decompiled = server.android_decompile(apk, "com.blackwall.fixture.Main", timeout=120)
assert decompiled["rc"] == 0 and decompiled["engine"]["version"] == "1.5.6"

nested = server.recursive_unpack(
    stage("nested-firmware.zip"), max_depth=3, max_artifacts=16,
    max_artifact_bytes=4 * 1024 * 1024,
    max_expanded_bytes=16 * 1024 * 1024,
    max_elapsed_seconds=60,
)
assert nested["counts"]["artifacts"] == 3
assert nested["counts"]["configuration_matches"] == 1
assert nested["stop_reason"] == "complete"
assert {row["depth"] for row in nested["artifacts"]} == {1, 2, 3}

cab = server.recursive_unpack(
    stage("installer.cab"), max_depth=2, max_artifacts=8,
    max_artifact_bytes=1024 * 1024, max_expanded_bytes=4 * 1024 * 1024,
    max_elapsed_seconds=30,
)
assert cab["counts"]["artifacts"] == 1
assert cab["counts"]["configuration_matches"] == 1

configuration = server.config_extract(
    stage("family-config.bin"), family="auto", timeout=30,
)
assert configuration["matches"][0]["confidence"]["tier"] == "high"
'

docker run --rm --network none --read-only \
  --tmpfs /tmp:rw,exec,nosuid,nodev,size=1g \
  --tmpfs /work:rw,exec,nosuid,nodev,size=1g,mode=1777 \
  "$image" sh -eu -c '
    mkdir -p /work/home/.cache /work/samples/original /work/state /work/out /work/ghidra
    ln -s "$CHROMA_CACHE" /work/home/.cache/chroma
    digest=$(sha256sum /bin/true | cut -d" " -f1)
    cp /bin/true "/work/samples/original/$digest"
    bw-ghidra-ready --integration-check
  '

echo "image reliability integration tests passed"
