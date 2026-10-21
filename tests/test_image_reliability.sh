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
