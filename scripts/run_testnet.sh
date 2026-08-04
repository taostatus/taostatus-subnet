#!/usr/bin/env bash
#
# scripts/run_testnet.sh — one-stop launcher for the MASXAI v1 subnet on
# testnet netuid 501. Wraps the register / stake / run / overview commands and,
# critically, exports BT_NO_PARSE_CLI_ARGS=false.
#
# Why the env var: bittensor >=10 defaults BT_NO_PARSE_CLI_ARGS=true, which makes
# bt.Config IGNORE every CLI flag (--netuid, --wallet.name, --axon.port, ...).
# Without this export the neurons would silently fall back to finney/netuid-1
# defaults. This script guarantees the flags are honored.
#
# Usage:
#   scripts/run_testnet.sh register-miner
#   scripts/run_testnet.sh register-validator
#   scripts/run_testnet.sh stake --amount 1
#   scripts/run_testnet.sh miner
#   scripts/run_testnet.sh validator
#   scripts/run_testnet.sh overview
#
# Override defaults via env vars, e.g.:
#   MINER_WALLET=my-miner VALIDATOR_WALLET=my-val MINER_AXON_PORT=8902 \
#     scripts/run_testnet.sh miner
#
set -euo pipefail

# --- the one line that makes CLI flags work on bittensor >=10 ---
export BT_NO_PARSE_CLI_ARGS=false

# --- config (override via environment) ---
NETUID="${NETUID:-501}"
NETWORK="${NETWORK:-test}"
MINER_WALLET="${MINER_WALLET:-masxai-miner}"
VALIDATOR_WALLET="${VALIDATOR_WALLET:-masxai-validator}"
HOTKEY="${HOTKEY:-default}"
MINER_AXON_PORT="${MINER_AXON_PORT:-8901}"
STAKE_AMOUNT="${STAKE_AMOUNT:-1}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

# repo root = parent of this script's dir, so the script works from anywhere
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$REPO_ROOT"

usage() {
  cat <<EOF
MASXAI v1 testnet launcher (netuid ${NETUID}, network ${NETWORK})

Commands:
  register-miner       Register the miner hotkey on the subnet
  register-validator   Register the validator hotkey on the subnet
  stake [--amount N]   Stake TAO to the validator (needed for a validator permit)
  miner                Run the miner neuron (axon on :${MINER_AXON_PORT})
  validator            Run the validator neuron (deferred-resolution loop)
  overview             Show wallet overview / emission / incentive on the subnet

Effective config (override with env vars):
  NETUID=${NETUID}  NETWORK=${NETWORK}  HOTKEY=${HOTKEY}
  MINER_WALLET=${MINER_WALLET}  VALIDATOR_WALLET=${VALIDATOR_WALLET}
  MINER_AXON_PORT=${MINER_AXON_PORT}  STAKE_AMOUNT=${STAKE_AMOUNT}
  PYTHON_BIN=${PYTHON_BIN}
EOF
}

# Activate the local venv if present and not already active.
if [[ -z "${VIRTUAL_ENV:-}" && -f "$REPO_ROOT/.venv/bin/activate" ]]; then
  # shellcheck disable=SC1091
  source "$REPO_ROOT/.venv/bin/activate"
elif [[ -z "${VIRTUAL_ENV:-}" && -f "$REPO_ROOT/venv/bin/activate" ]]; then
  # shellcheck disable=SC1091
  source "$REPO_ROOT/venv/bin/activate"
fi

cmd="${1:-help}"
shift || true

case "$cmd" in
  register-miner)
    btcli subnet register \
      --netuid "$NETUID" --subtensor.network "$NETWORK" \
      --wallet.name "$MINER_WALLET" --wallet.hotkey "$HOTKEY"
    ;;

  register-validator)
    btcli subnet register \
      --netuid "$NETUID" --subtensor.network "$NETWORK" \
      --wallet.name "$VALIDATOR_WALLET" --wallet.hotkey "$HOTKEY"
    ;;

  stake)
    # allow `stake --amount 5`
    if [[ "${1:-}" == "--amount" ]]; then STAKE_AMOUNT="${2:?--amount needs a value}"; fi
    btcli stake add \
      --netuid "$NETUID" --subtensor.network "$NETWORK" \
      --wallet.name "$VALIDATOR_WALLET" --wallet.hotkey "$HOTKEY" \
      --amount "$STAKE_AMOUNT"
    ;;

  miner)
    exec "$PYTHON_BIN" neurons/miner.py \
      --netuid "$NETUID" --subtensor.network "$NETWORK" \
      --wallet.name "$MINER_WALLET" --wallet.hotkey "$HOTKEY" \
      --axon.port "$MINER_AXON_PORT" --logging.debug
    ;;

  validator)
    exec "$PYTHON_BIN" neurons/validator.py \
      --netuid "$NETUID" --subtensor.network "$NETWORK" \
      --wallet.name "$VALIDATOR_WALLET" --wallet.hotkey "$HOTKEY" \
      --logging.debug
    ;;

  overview)
    btcli wallet overview \
      --netuid "$NETUID" --subtensor.network "$NETWORK" \
      --wallet.name "$VALIDATOR_WALLET"
    ;;

  help|-h|--help)
    usage
    ;;

  *)
    echo "Unknown command: $cmd" >&2
    echo >&2
    usage
    exit 1
    ;;
esac
