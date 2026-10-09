# syntax=docker/dockerfile:1.7
# Pitangus image: web panel, API and scan queue.
# Built from the repository root:  make build   (or docker compose build)
#
# Two stages: Node builds the panel and only its static files reach the final image,
# which is Python slim + the Docker client (to start the engines) + dig (DNS TXT).
# Base images are pinned by digest.

# ---------- 1. web panel ----------
# Static files are the same on every architecture: build them natively (no emulation in multi-arch builds).
FROM --platform=$BUILDPLATFORM node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402 AS web
WORKDIR /src/web
# pnpm at the exact version (and hash) of package.json's packageManager, through Node's corepack. pnpm-workspace.yaml
# holds the supply-chain settings: no install scripts, no release younger than a week, no trust downgrades.
RUN corepack enable
COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml ./
# The pnpm store and pip's wheels stay in BuildKit cache mounts between local builds (never in the image).
RUN --mount=type=cache,id=pitangus-pnpm,target=/root/.local/share/pnpm/store COREPACK_ENABLE_DOWNLOAD_PROMPT=0 pnpm install --frozen-lockfile
COPY web/ ./
# vite.config writes to ../pitangus/app/static: keep the repository layout.
RUN mkdir -p /src/pitangus/app && pnpm run build

# ---------- 2. runtime ----------
FROM python:3.12-slim-bookworm@sha256:54c85f3c47607a77f32adec749d3c81d1348bf25833671f512b26a9b6d778cb3 AS app
ARG VERSION=dev
ARG DOCKER_CLI_VERSION=29.8.2
ARG DOCKER_CLI_SHA_AMD64=995d1ef289677f74fd58d8d2c35727b6a4ee389c69db8638a3e42d0487aa5b0f
ARG DOCKER_CLI_SHA_ARM64=76a624e4a8e5da654d1150e808175125efb5a6f1b6aa1cbd9caee18f51047a50
LABEL org.opencontainers.image.title="Pitangus" \
      org.opencontainers.image.description="Self-hosted application security: SAST, secrets, dependencies, PRs and CVE tracker" \
      org.opencontainers.image.source="https://github.com/Pitangus-Dev/pitangus" \
      org.opencontainers.image.documentation="https://github.com/Pitangus-Dev/pitangus/tree/main/docs" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.version="${VERSION}"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 LANG=C.UTF-8 \
    PITANGUS_BIND=0.0.0.0 PITANGUS_DATA_DIR=/data PITANGUS_CONFIG_DIR=/config
# The pinned base is upgraded at build time too: Debian's security fixes released after the digest are taken in, so the
# published image doesn't carry vulnerabilities that already have a fix. The Docker CLI is checked against its SHA-256.
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends ca-certificates curl dnsutils git \
 && ARCH="$(dpkg --print-architecture)" && case "$ARCH" in amd64) A=x86_64; SHA="$DOCKER_CLI_SHA_AMD64" ;; arm64) A=aarch64; SHA="$DOCKER_CLI_SHA_ARM64" ;; *) echo "unsupported architecture: $ARCH" && exit 1 ;; esac \
 && curl -fsSL --proto '=https' --tlsv1.2 "https://download.docker.com/linux/static/stable/${A}/docker-${DOCKER_CLI_VERSION}.tgz" -o /tmp/docker.tgz \
 && echo "${SHA}  /tmp/docker.tgz" | sha256sum -c - \
 && tar -xzf /tmp/docker.tgz -C /tmp && install -m 0755 /tmp/docker/docker /usr/local/bin/docker \
 && rm -rf /tmp/docker /tmp/docker.tgz && apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt ./
RUN --mount=type=cache,id=pitangus-pip,target=/root/.cache/pip pip install --disable-pip-version-check --require-hashes --only-binary :all: -r requirements.txt
COPY pitangus/ ./pitangus/
COPY rules/ ./rules/
COPY --from=web /src/pitangus/app/static ./pitangus/app/static
# The exact release (the tag without the v, 0.12.1) for /api/health, the panel and the reports; pitangus/version.py
# ignores a value that doesn't belong to its VERSION (the default "dev").
RUN printf '%s\n' "${VERSION}" > pitangus/RELEASE
# Unprivileged user; compose aligns its UID/GID with the host's so data/ and config/ are yours.
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin pitangus \
 && mkdir -p /data /config && chown -R pitangus:pitangus /data /config
USER pitangus
VOLUME ["/data", "/config"]
EXPOSE 8766
# The Host header is the first allowed origin's: behind a proxy (public domain only) 127.0.0.1 is refused.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["python", "-c", "import os,sys,urllib.parse as p,urllib.request as r; h=p.urlsplit((os.environ.get('PITANGUS_ALLOWED_ORIGINS') or 'http://127.0.0.1:8766').split(',')[0].strip()).netloc; sys.exit(0 if r.urlopen(r.Request('http://127.0.0.1:8766/api/health', headers={'Host': h}), timeout=4).status == 200 else 1)"]
CMD ["python", "-m", "pitangus", "--data-dir", "/data", "serve", "--port", "8766"]

# ---------- 3. worker with the engines inside (no Docker socket) ----------
# For platforms that can't hand a container the Docker socket (Railway, Render, Fly.io, Kubernetes, a PaaS):
#   docker build --target worker-standalone -f docker/app/Dockerfile .
# The same pinned engines as the Docker runner (scanning/engines.py IMAGES), copied from their official images by digest,
# and run as processes of the worker (PITANGUS_ENGINE_RUNNER=local). Opengrep is the SHA-256-verified release binary.
# tests/test_packaging.py checks that these digests and versions match IMAGES and the Opengrep Dockerfile.
FROM aquasec/trivy@sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa AS trivy
FROM ghcr.io/google/osv-scanner@sha256:afd838850ac1a0fcc15ff4a041dc9ba11123c3f0d2666217a5f0fcf9222b55fa AS osv-scanner
FROM ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f AS gitleaks
FROM anchore/grype@sha256:5c88961f4130e830542d441c7ed6c78baa28e799163abac53d2be4923fb5ab7d AS grype
FROM ghcr.io/zizmorcore/zizmor@sha256:a2eb396d886c053073405c7a980f2139ba2248ec172243cfa3841e57196e8101 AS zizmor

FROM --platform=$BUILDPLATFORM debian:12-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251 AS opengrep
ARG TARGETARCH
ARG OPENGREP_VERSION=1.30.0
ARG SHA_AMD64=35779bdd72e92129c8df2a77f0c55e8c08356801ea92591ef32108d6b28d564c
ARG SHA_ARM64=a5d5a4a58ba5d46ff51e921663da1c2bba38f4b03987f4aeec87f16c6ad3ecae
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    case "${TARGETARCH:-$(dpkg --print-architecture)}" in \
      amd64) artifact=opengrep_manylinux_x86; sha="$SHA_AMD64" ;; \
      arm64) artifact=opengrep_manylinux_aarch64; sha="$SHA_ARM64" ;; \
      *) echo "unsupported architecture" >&2; exit 1 ;; \
    esac; \
    curl -fsSL --proto '=https' --tlsv1.2 -o /opengrep "https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/${artifact}"; \
    echo "${sha}  /opengrep" | sha256sum -c -

FROM app AS worker-standalone
ARG CHECKOV_VERSION=3.3.19
USER root
COPY docker/checkov/requirements.txt /tmp/checkov-requirements.txt
COPY --from=trivy --chmod=0755 /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=osv-scanner --chmod=0755 /osv-scanner /usr/local/bin/osv-scanner
COPY --from=gitleaks --chmod=0755 /usr/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=grype --chmod=0755 /grype /usr/local/bin/grype
COPY --from=zizmor --chmod=0755 /usr/bin/zizmor /usr/local/bin/zizmor
COPY --from=opengrep --chmod=0755 /opengrep /usr/local/bin/opengrep
# Checkov is Python: its image's interpreter (3.11, Debian 13) can't be copied here, so it gets its own virtual
# environment. It and every dependency are pinned with their hashes (docker/checkov/requirements.txt), wheels only:
# nothing is built from source.
RUN python -m venv /opt/checkov \
 && /opt/checkov/bin/pip install --no-cache-dir --disable-pip-version-check --require-hashes --no-deps --only-binary :all: \
      -r /tmp/checkov-requirements.txt \
 && rm /tmp/checkov-requirements.txt \
 && /opt/checkov/bin/checkov --version | grep -qx "${CHECKOV_VERSION}" \
 && ln -s /opt/checkov/bin/checkov /usr/local/bin/checkov \
 && trivy --version >/dev/null && osv-scanner --version >/dev/null && gitleaks version >/dev/null && grype version >/dev/null \
 && zizmor --version >/dev/null && opengrep --version >/dev/null && checkov --version >/dev/null
ENV PITANGUS_ENGINE_RUNNER=local PYTHONUTF8=1
USER pitangus
HEALTHCHECK --interval=60s --timeout=15s --start-period=60s --retries=3 \
  CMD ["python", "-m", "pitangus", "--data-dir", "/data", "worker", "--check"]
CMD ["python", "-m", "pitangus", "--data-dir", "/data", "worker"]
