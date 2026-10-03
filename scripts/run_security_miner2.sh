#!/usr/bin/env bash
# pm2 entrypoint for a SECOND security-track miner on this host (hotkey miner2).
# Same as run_security_miner.sh but a distinct hotkey and distinct ports so it
# does not collide with miner1 (axon 8911 / blob 8912).
set -euo pipefail

cd /home/aman/taostatus-subnet

export MASXAI_SECURITY_AGENT_ENABLED=true
export MASXAI_SECURITY_AGENT_IMAGE=ghcr.io/adtao26/secval-ref-agent:v1
export MASXAI_SECURITY_BLOB_PORT=8914

exec sg docker -c '/home/aman/taostatus-subnet/.venv/bin/python neurons/security_miner.py \
  --netuid 501 --subtensor.network test \
  --subtensor.chain_endpoint wss://test.finney.opentensor.ai:443 \
  --wallet.name aman-test --wallet.hotkey miner2 \
  --axon.port 8913 --axon.external_ip 169.58.6.18 \
  --logging.debug'
