#!/usr/bin/env bash
# pm2 entrypoint for the security-track validator.
#
# Same reason as run_security_miner.sh: the pm2 daemon lacks the `docker`
# supplementary group, and the validator needs docker (run_job spins up the
# target + agent containers under gVisor). `sg docker` switches the effective
# group so just this app can reach the docker socket, without restarting the
# pm2 daemon (which would bounce the untouched LLM-key validator).
#
# MASXAI_QUERY_VALIDATOR_UIDS=true is required on testnet: our own miner holds a
# validator permit (from test-net stake), and without this it would be excluded
# from the query set, giving empty rounds.
set -euo pipefail

cd /home/aman/taostatus-subnet

export MASXAI_QUERY_VALIDATOR_UIDS=true

exec sg docker -c '/home/aman/taostatus-subnet/.venv/bin/python neurons/security_validator.py \
  --netuid 501 --subtensor.network test \
  --subtensor.chain_endpoint wss://test.finney.opentensor.ai:443 \
  --wallet.name aman-test --wallet.hotkey validator1 \
  --neuron.disable_set_weights True \
  --logging.debug'
