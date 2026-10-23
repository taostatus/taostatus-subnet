# The admission sandbox base image.
#
# This is the ONE image the validator runs for every miner. It is built once,
# audited once, and contains ONLY the audited agent SDK + the sandbox entrypoint
# -- never any miner code. At run time the miner's single `agent.py` is mounted
# read-only at /sandbox/agent.py; the entrypoint loads its `agent_main(ctx)` and
# runs it under the SDK's scope / rate / time caps. Because no miner-controlled
# image is ever loaded, there is nothing to vet or scan per submission: the attack
# surface is a few hundred bytes of Python behind an identical, locked-down
# sandbox (gVisor + zero-egress proxy, applied by the orchestrator, not here).
#
# Build (from the repo root):
#   docker build -t masxai-sandbox:base -f secqurityVali/sandbox/Dockerfile .
FROM python:3.12-slim

# httpx is the only runtime dependency of the SDK's runner. Pinned; no cache.
# (Browser recon's playwright is intentionally NOT installed -- it is an optional
# dependency the runner imports lazily, so deterministic/static agents stay light.
# Add it to a separate browser-enabled image when a run needs USE_BROWSER.)
RUN pip install --no-cache-dir "httpx==0.27.2"

WORKDIR /app

# Only the audited code is baked in: the SDK package and the entrypoint. The
# miner's agent.py is NEVER copied here -- it arrives as a read-only mount.
COPY secqurityVali/__init__.py        /app/secqurityVali/__init__.py
COPY secqurityVali/agent_sdk          /app/secqurityVali/agent_sdk
COPY secqurityVali/sandbox_entry.py   /app/secqurityVali/sandbox_entry.py

# /app on the path so `from secqurityVali...` resolves; /sandbox is deliberately
# NOT on the path. No .pyc writes (root is read-only at run time anyway).
ENV PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Run as an unprivileged user (defence in depth on top of gVisor + cap-drop).
RUN useradd --no-create-home --uid 10001 sandbox
USER sandbox

ENTRYPOINT ["python", "-B", "/app/secqurityVali/sandbox_entry.py"]
