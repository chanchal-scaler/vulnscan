# Scanner image: every runtime and scanner is baked in at a pinned version and checksum,
# so nothing is installed at scan time. Builds on amd64 and arm64.
# To upgrade a tool, bump its version and both of its checksums together.
FROM python:3.12-slim-trixie

ARG GO_VERSION=1.27.3
ARG CLAUDE_VERSION=2.1.311
ARG OSV_SCANNER_VERSION=2.7.0
ARG GITLEAKS_VERSION=8.30.1
ARG GOSEC_VERSION=2.30.0
ARG SEMGREP_VERSION=1.183.0
ARG CHECKOV_VERSION=3.4.3
ARG BANDIT_VERSION=1.9.4
ARG BRAKEMAN_VERSION=8.1.0

# apt over HTTPS: the EC2 instance only allows outbound 443.
RUN sed -i 's#http://deb.debian.org#https://deb.debian.org#g' /etc/apt/sources.list.d/debian.sources \
 && apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git ruby \
 && rm -rf /var/lib/apt/lists/*

RUN set -eu; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) go_sha=65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40; \
             claude_platform=linux-x64; claude_sha=86dc1fcc69498159eaf15f446613e847010f9036bfbbdffd4c49350be8489ada; \
             osv_sha=160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b; \
             gitleaks_arch=x64; gitleaks_sha=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb; \
             gosec_sha=3fcce2c4e802ff4169217874602a7df355e9a37bcb6ffaa34b08f3d5f336cdfb ;; \
      arm64) go_sha=a06e99309dbcbdca1a8ccd2282c3ee146e55930886e26b4f1193269587165f49; \
             claude_platform=linux-arm64; claude_sha=2e2496c9a8065df93acb0fca2d341f59a6b8777649b2e025ab8c9bcd5eef61f3; \
             osv_sha=4061ef4c021ed3c47f203b818f337e351336cc5cd67c0274fc36bd1dfc728dd7; \
             gitleaks_arch=arm64; gitleaks_sha=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080; \
             gosec_sha=0867994920453070a5d6a713e35921a3058473e5c3bf777fdd5a2d6f95313fda ;; \
      *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
    esac; \
    fetch() { curl -fsSL -o "$1" "$2"; echo "$3  $1" | sha256sum -c -; }; \
    cd /tmp; \
    fetch go.tgz "https://go.dev/dl/go${GO_VERSION}.linux-${arch}.tar.gz" "$go_sha"; \
    tar -C /usr/local -xzf go.tgz; \
    fetch /usr/local/bin/claude "https://downloads.claude.ai/claude-code-releases/${CLAUDE_VERSION}/${claude_platform}/claude" "$claude_sha"; \
    fetch /usr/local/bin/osv-scanner "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_${arch}" "$osv_sha"; \
    fetch gitleaks.tgz "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${gitleaks_arch}.tar.gz" "$gitleaks_sha"; \
    tar -C /usr/local/bin -xzf gitleaks.tgz gitleaks; \
    fetch gosec.tgz "https://github.com/securego/gosec/releases/download/v${GOSEC_VERSION}/gosec_${GOSEC_VERSION}_linux_${arch}.tar.gz" "$gosec_sha"; \
    tar -C /usr/local/bin -xzf gosec.tgz gosec; \
    chmod 755 /usr/local/bin/claude /usr/local/bin/osv-scanner /usr/local/bin/gitleaks /usr/local/bin/gosec; \
    rm -f /tmp/*.tgz

# Each Python scanner gets its own virtualenv so their dependencies can't conflict.
RUN set -eu; \
    for spec in "semgrep==${SEMGREP_VERSION}" "checkov==${CHECKOV_VERSION}" "bandit==${BANDIT_VERSION}"; do \
      name="${spec%%==*}"; \
      python -m venv "/opt/tools/$name"; \
      "/opt/tools/$name/bin/pip" install --no-cache-dir "$spec"; \
      ln -s "/opt/tools/$name/bin/$name" "/usr/local/bin/$name"; \
    done; \
    gem install --no-document brakeman -v "$BRAKEMAN_VERSION"

COPY pyproject.toml /opt/vulnscan-src/
COPY vulnscan /opt/vulnscan-src/vulnscan
RUN python -m venv /opt/vulnscan \
 && /opt/vulnscan/bin/pip install --no-cache-dir /opt/vulnscan-src \
 && ln -s /opt/vulnscan/bin/vulnscan /usr/local/bin/vulnscan

RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin scanner \
 && install -d -o scanner -g scanner -m 700 /var/lib/vulnscan

# CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC also turns off Claude Code's auto-updater and telemetry.
ENV PATH=/usr/local/go/bin:$PATH \
    VULNSCAN_HOME=/var/lib/vulnscan \
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1

USER scanner
WORKDIR /home/scanner
ENTRYPOINT ["vulnscan"]
CMD ["--help"]
