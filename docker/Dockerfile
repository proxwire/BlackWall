# BlackWall analysis image.
#
# Everything that touches sample bytes runs inside this image. Containers are
# started with --network none, all capabilities dropped and a read-only root
# filesystem; the only writable places are /work (a per-case named volume)
# and /tmp (tmpfs).
FROM ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55

ARG UID=1000
ARG GID=1000
ARG GHIDRA_VERSION=12.1.4
ARG GHIDRA_DATE=20260921
ARG GHIDRA_SHA256=ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db
ARG R2_VERSION=6.2.4
ARG R2_SHA256=7019eedc0e0e87d1f53d6b8f5fc62b898567679c5efdce7fbfc557c9e7655e90
ARG R2MCP_VERSION=1.8.8
ARG R2MCP_SHA256=1de404fd88881fd2a543c6c4e552a688f2120966c809da4bbfec9594ec669000
ARG DIE_VERSION=3.21
ARG DIE_SHA256=96e8e82e822e3ca8a829536312b92e8b241147fe38c8ab29c9dbfc1ab21aa25d
ARG CAPA_VERSION=9.4.0
ARG CAPA_SHA256=07800a1d20a21eb18fc98716e2ae81b668e0c9a04defd588c8aa17ea3d3281e4
ARG FLOSS_VERSION=3.1.1
ARG FLOSS_SHA256=40c05a869f34f7e2417b17ca290cc54bd3671ee1f0a2d9bd5103284c01a54666
ARG UPX_VERSION=5.2.1
ARG UPX_SHA256=402162aad30af47e60dbd767fb2e64ca394ace9727ba1f40283641f1d1b91657
ARG NODE_VERSION=24.18.0
ARG NODE_SHA256=55aa7153f9d88f28d765fcdad5ae6945b5c0f98a36881703817e4c450fa76742
ARG REA_VERSION=6.7.0
ARG JADX_MCP_VERSION=0.7.1
ARG JADX_MCP_SHA256=6e5eacf500b64292bfb73c49797c1958f6ee44646e43e868039ae7feb573ff75
ARG WABT_VERSION=1.0.42
ARG WABT_SHA256=84895407a6bbb80e918f33b16b2fb2206021c150b6bc9ff6f761263a745ab131
ARG PIP_VERSION=26.2.1

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    GHIDRA_INSTALL_DIR=/opt/ghidra \
    REA_JADX_MCP_JAR=/opt/rea/providers/jadx-headless-mcp.jar \
    REA_JADX_HEAP_MIB=4096 \
    REA_JADX_ACTIVE_PROCESSOR_COUNT=2 \
    REA_WABT_BIN_DIRECTORY=/opt/rea/providers/wabt/bin \
    REA_TSHARK_COMMAND=/usr/bin/tshark \
    REA_CAPINFOS_COMMAND=/usr/bin/capinfos \
    PATH=/opt/venv/bin:/opt/blackwall/bin:/opt/tools/bin:/opt/node/bin:$PATH

RUN apt-get update && apt-get install -y --no-install-recommends \
        openjdk-21-jdk-headless \
        python3 python3-venv python3-dev build-essential \
        ca-certificates curl unzip zip p7zip-full xz-utils \
        file binutils xxd jq less ripgrep ssdeep binwalk procps tshark \
        libxext6 libxrender1 libxtst6 libxi6 fontconfig fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp/dl

# fetch URL SHA256 OUT   (SHA256 "-" skips verification for assets without a published digest)
RUN printf '#!/bin/sh\nset -e\ncurl -fsSL --retry 3 -o "$3" "$1"\n[ "$2" = "-" ] || echo "$2  $3" | sha256sum -c -\n' > /usr/local/bin/fetch \
    && chmod +x /usr/local/bin/fetch

# Ghidra
RUN fetch https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip ${GHIDRA_SHA256} ghidra.zip \
    && unzip -q ghidra.zip -d /opt \
    && mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC /opt/ghidra \
    && rm ghidra.zip

# radare2 + r2mcp, Detect It Easy
RUN fetch https://github.com/radareorg/radare2/releases/download/${R2_VERSION}/radare2_${R2_VERSION}_amd64.deb ${R2_SHA256} r2.deb \
    && fetch https://github.com/radareorg/radare2-mcp/releases/download/${R2MCP_VERSION}/r2mcp_${R2MCP_VERSION}_amd64.deb ${R2MCP_SHA256} r2mcp.deb \
    && fetch https://github.com/horsicq/DIE-engine/releases/download/${DIE_VERSION}/die_${DIE_VERSION}_Ubuntu_24.04_amd64.deb ${DIE_SHA256} die.deb \
    && apt-get update && apt-get install -y --no-install-recommends ./r2.deb ./r2mcp.deb ./die.deb \
    && rm -rf /var/lib/apt/lists/* *.deb

# capa / FLOSS standalone builds (rules + FLIRT sigs embedded), UPX
RUN mkdir -p /opt/tools/bin \
    && fetch https://github.com/mandiant/capa/releases/download/v${CAPA_VERSION}/capa-v${CAPA_VERSION}-linux.zip ${CAPA_SHA256} capa.zip \
    && fetch https://github.com/mandiant/flare-floss/releases/download/v${FLOSS_VERSION}/floss-v${FLOSS_VERSION}-linux.zip ${FLOSS_SHA256} floss.zip \
    && fetch https://github.com/upx/upx/releases/download/v${UPX_VERSION}/upx-${UPX_VERSION}-amd64_linux.tar.xz ${UPX_SHA256} upx.tar.xz \
    && unzip -q capa.zip -d /opt/tools/bin && unzip -q floss.zip -d /opt/tools/bin \
    && tar -xJf upx.tar.xz && mv upx-${UPX_VERSION}-amd64_linux/upx /opt/tools/bin/ \
    && chmod +x /opt/tools/bin/* && rm -rf /tmp/dl/*

# REA's published runtime is installed from a committed lockfile with lifecycle
# scripts and optional Frida support disabled. BlackWall exposes a small static
# allowlist through its own lab MCP rather than REA's execution-capable MCP.
RUN fetch https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz ${NODE_SHA256} node.tar.xz \
    && mkdir -p /opt/node \
    && tar -xJf node.tar.xz --strip-components=1 -C /opt/node \
    && rm node.tar.xz
COPY rea-runtime/package.json rea-runtime/package-lock.json /opt/rea/runtime/
RUN npm ci --prefix /opt/rea/runtime --omit=dev --omit=optional --ignore-scripts --no-audit --no-fund \
    && test "$(/opt/rea/runtime/node_modules/.bin/rea --version)" = "${REA_VERSION}" \
    && test ! -d /opt/rea/runtime/node_modules/frida \
    && rm -rf /root/.npm

# REA's Android adapter requires its separately released, pinned JADX bridge.
RUN mkdir -p /opt/rea/providers \
    && fetch https://github.com/1013503897/jadx-headless-mcp/releases/download/v${JADX_MCP_VERSION}/jadx-headless-mcp-${JADX_MCP_VERSION}-all.jar ${JADX_MCP_SHA256} /opt/rea/providers/jadx-headless-mcp.jar \
    && chmod 0444 /opt/rea/providers/jadx-headless-mcp.jar

# REA's WASM adapter accepts the pinned, publisher-built WABT tool profile.
RUN fetch https://github.com/WebAssembly/wabt/releases/download/${WABT_VERSION}/wabt-${WABT_VERSION}-linux-x64.tar.gz ${WABT_SHA256} wabt.tar.gz \
    && mkdir -p /opt/rea/providers/wabt \
    && tar -xzf wabt.tar.gz --strip-components=1 -C /opt/rea/providers/wabt \
    && test "$(/opt/rea/providers/wabt/bin/wasm-validate --version)" = "${WABT_VERSION}" \
    && test "$(/opt/rea/providers/wabt/bin/wasm-objdump --version)" = "${WABT_VERSION}" \
    && test "$(/opt/rea/providers/wabt/bin/wasm2wat --version)" = "${WABT_VERSION}" \
    && rm wabt.tar.gz

# Python toolchain: Ghidra MCP, MCP proxy (GUI mode bridge), emulation, format parsers.
# The resolved runtime lock pins dependency versions and artifact hashes so the
# selected distributions cannot drift or be replaced between builds.
COPY lab/requirements.txt lab/requirements.lock /opt/blackwall/
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir "pip==${PIP_VERSION}" \
    && /opt/venv/bin/pip install --no-cache-dir --require-hashes \
         -r /opt/blackwall/requirements.lock

# pyghidra-mcp's semantic code search uses chromadb's default ONNX embedding
# model, which it would otherwise download on first use (and fail: no network).
ENV CHROMA_CACHE=/opt/cache/chroma
RUN HOME=/opt/cache/home /opt/venv/bin/python -c \
      "from chromadb.utils.embedding_functions import DefaultEmbeddingFunction as D; D()(['warmup'])" \
    && mkdir -p /opt/cache && mv /opt/cache/home/.cache/chroma $CHROMA_CACHE && rm -rf /opt/cache/home \
    && chmod -R a+rX /opt/cache

COPY rules /opt/blackwall/rules
COPY lab /opt/blackwall/lab
COPY benchmarks /opt/blackwall/benchmarks
COPY docker/bin /opt/blackwall/bin
RUN /opt/venv/bin/pip install --no-cache-dir --no-deps --no-build-isolation \
         /opt/blackwall/lab \
    && chmod +x /opt/blackwall/bin/*

# Home is on the /work volume: Java/Ghidra take user.home from passwd, not $HOME.
# UID/GID match the host user so files written to the case dir (reports,
# exports) are owned by you, and so X11 SI:localuser auth works in GUI mode.
RUN (userdel -r ubuntu 2>/dev/null || true) \
    && groupadd -g ${GID} analyst \
    && useradd -M -d /work/home -u ${UID} -g ${GID} -s /bin/bash analyst \
    && mkdir -p /work /case && chown ${UID}:${GID} /work /case

USER analyst
ENV HOME=/work/home
WORKDIR /work
CMD ["sleep", "infinity"]
