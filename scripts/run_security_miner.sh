#!/usr/bin/env bash
# pm2 entrypoint for the security-track miner.
#
# The pm2 daemon on this host was started without the `docker` supplementary
# group, so any process it spawns cannot reach the docker socket -- and the v2
# miner needs docker (`docker save` to build the encrypted agent blob). Rather
# than restart the whole pm2 daemon (which would also bounce the untouched
# LLM-key validator), this wrapper re-execs the miner under `sg docker`, which
# switches the effective group to `docker` while keeping the others. That gives
# just this app docker access, leaving every other pm2 app alone.
set -euo pipefail

cd /home/aman/taostatus-subnet

export MASXAI_SECURITY_AGENT_ENABLED=true
export MASXAI_SECURITY_AGENT_IMAGE=ghcr.io/adtao26/secval-ref-agent:v1

exec sg docker -c '/home/aman/taostatus-subnet/.venv/bin/python neurons/miner.py \
  --netuid 501 --subtensor.network test \
  --subtensor.chain_endpoint wss://test.finney.opentensor.ai:443 \
  --wallet.name aman-test --wallet.hotkey miner1 \
  --axon.port 8911 --axon.external_ip 169.58.6.18 \
  --logging.debug'
