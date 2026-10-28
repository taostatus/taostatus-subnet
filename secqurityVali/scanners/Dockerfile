# Offline multi-language static-security scanner image (Layer 1 of the audit).
#
#   Semgrep  -> code SAST across 30+ languages (injection, XSS, SSRF, path
#               traversal, weak crypto, insecure config, auth bugs, ...)
#   Trivy    -> dependency CVEs + hardcoded secrets + IaC/Docker misconfig
#
# Rules and the Trivy vuln DB are baked in at BUILD time (build has network). At
# RUN time the scanners are invoked with NO network (they run inside the same
# zero-egress gVisor sandbox as everything else), against a READ-ONLY /repo mount.
# Nothing here ever executes the target's code -- both tools only parse it.
#
# Pinned versions + a pinned rules commit keep scans deterministic and make the
# supply chain auditable. Rebuild periodically to refresh the Trivy DB and rules.
FROM python:3.12-slim

ARG TRIVY_VERSION=0.75.0
ARG SEMGREP_VERSION=1.97.0

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git \
 && rm -rf /var/lib/apt/lists/*

# --- Semgrep (code SAST) ---
RUN pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}"

# --- Trivy (deps / secrets / misconfig) ---
# Pull the release tarball directly (the install.sh script is flaky) and extract
# just the binary. amd64 host -> the "Linux-64bit" asset.
RUN arch="$(dpkg --print-architecture)" \
 && case "$arch" in amd64) asset=64bit;; arm64) asset=ARM64;; *) asset=64bit;; esac \
 && curl -sfL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${asset}.tar.gz" -o /tmp/trivy.tar.gz \
 && tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy \
 && rm -f /tmp/trivy.tar.gz \
 && trivy --version

# --- Bake Semgrep community rules (offline at runtime) ---
# The full OSS ruleset, organised by language/category. Shallow clone, .git
# dropped. At run time we point `--config /opt/semgrep-rules`.
RUN git clone --depth 1 https://github.com/semgrep/semgrep-rules /opt/semgrep-rules \
 && rm -rf /opt/semgrep-rules/.git

# --- Bake Trivy DBs so --skip-db-update works offline ---
ENV TRIVY_CACHE_DIR=/opt/trivy-cache
RUN trivy --cache-dir /opt/trivy-cache fs --download-db-only . \
 && trivy --cache-dir /opt/trivy-cache fs --download-java-db-only . || true

# Curate the ruleset so Semgrep loads fast and stays SECURITY-focused:
#   1. drop non-rule YAMLs (CI config, templates) -- no top-level `rules:` key,
#      which `--config <dir>` would otherwise abort on;
#   2. keep only SECURITY rules (category: security, or a CWE/OWASP tag). The full
#      community repo is mostly correctness/style rules that just slow the load and
#      add noise to a security audit. This cuts thousands of rules to hundreds.
# (Late layer -> clone/Trivy layers stay cached.)
RUN find /opt/semgrep-rules -type f \( -name '*.yaml' -o -name '*.yml' \) \
      ! -exec grep -qE '^rules:' {} \; -delete \
 && find /opt/semgrep-rules -type f \( -name '*.yaml' -o -name '*.yml' \) \
      ! -exec grep -qiE 'category:[[:space:]]*security|cwe:|owasp:' {} \; -delete \
 && find /opt/semgrep-rules -type f \( -name '*.yaml' -o -name '*.yml' \) \
      -exec grep -qiE 'confidence:[[:space:]]*low' {} \; -delete \
 && rm -rf /opt/semgrep-rules/.github /opt/semgrep-rules/stats \
           /opt/semgrep-rules/scripts /opt/semgrep-rules/libsonnet 2>/dev/null; true

# Semgrep's deps still import the deprecated `pkg_resources`, which setuptools
# 81+ removed. Pin setuptools back to a version that ships it. (Last layer, so the
# cached Semgrep/Trivy/DB layers above are untouched on rebuild.)
RUN pip install --no-cache-dir "setuptools<81"

# Semgrep needs a writable home for its (metrics-off) run; give the non-root user one.
ENV SEMGREP_SETTINGS_FILE=/tmp/semgrep_settings.yml \
    XDG_CACHE_HOME=/tmp/.cache \
    HOME=/tmp

# Non-root scanner. /repo is where the (read-only) target source is mounted.
RUN useradd -u 10002 -m scanner \
 && chmod -R a+rX /opt/semgrep-rules /opt/trivy-cache
USER 10002
WORKDIR /repo
