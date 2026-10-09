#!/usr/bin/env bash
# Operational audit worker (Step 3). Like the security miner, it re-execs under
# `sg docker` so this one process can reach the docker socket while every other
# pm2 app is left alone. Config comes from the environment (set by pm2 at start):
#   MASXAI_MARKETPLACE_URL, MASXAI_MARKETPLACE_TOKEN, MASXAI_SECURITY_AGENT_IMAGE
# No secrets are baked into this script.
set -euo pipefail
cd /home/aman/taostatus-subnet
# The customer-audit worker runs a LOCAL-ONLY white-box agent image (self-analyses
# mounted source). A local tag (no registry) is used on purpose: the registry tag
# the miner serves (ghcr.io/...) gets re-pulled and would clobber local rebuilds,
# so the worker pins its own tag that nothing pulls over. Rebuild with:
#   docker build -t secval-ref-agent:wb secqurityVali/agents/reference_sqli/
export MASXAI_SECURITY_AGENT_IMAGE="${MASXAI_SECURITY_AGENT_IMAGE_OVERRIDE:-secval-ref-agent:wb}"
exec sg docker -c '/home/aman/taostatus-subnet/.venv/bin/python neurons/audit_worker.py'
