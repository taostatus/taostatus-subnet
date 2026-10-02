# The MIT License (MIT)
# Copyright © 2023 Yuma Rao

# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
# documentation files (the “Software”), to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all copies or substantial portions of
# the Software.

# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

import copy
import typing

import bittensor as bt

from abc import ABC, abstractmethod

try:
    from async_substrate_interface.errors import SubstrateRequestException
except ImportError:
    SubstrateRequestException = None

TRANSIENT_REGISTRATION_EXCEPTIONS = tuple(
    exc
    for exc in (
        SubstrateRequestException,
        ConnectionError,
        TimeoutError,
    )
    if exc is not None
)

# Sync calls set weights and also resyncs the metagraph.
from template.utils.config import check_config, add_args, config
from template.utils.misc import ttl_get_block
from template import __spec_version__ as spec_version
from template.mock import MockSubtensor, MockMetagraph

# bittensor >=10 relocated the mock wallet out of the top-level `bt` namespace.
from bittensor_wallet.mock import get_mock_wallet


class BaseNeuron(ABC):
    """
    Base class for Bittensor miners. This class is abstract and should be inherited by a subclass. It contains the core logic for all neurons; validators and miners.

    In addition to creating a wallet, subtensor, and metagraph, this class also handles the synchronization of the network state via a basic checkpointing mechanism based on epoch length.
    """

    neuron_type: str = "BaseNeuron"

    @classmethod
    def check_config(cls, config: "bt.Config"):
        check_config(cls, config)

    @classmethod
    def add_args(cls, parser):
        add_args(cls, parser)

    @classmethod
    def config(cls):
        return config(cls)

    subtensor: "bt.Subtensor"
    wallet: "bt.Wallet"
    metagraph: "bt.Metagraph"
    spec_version: int = spec_version

    # The subnet mechanism this neuron belongs to. Registration, UIDs, stake and
    # validator permits are subnet-wide, but each mechanism keeps its own weight
    # matrix, consensus and LastUpdate. A validator subclass sets this so its
    # weights land on its own mechanism's matrix. 0 is the primary mechanism.
    mechid: int = 0

    @property
    def block(self):
        return ttl_get_block(self)

    def __init__(self, config=None):
        base_config = copy.deepcopy(config or self.__class__.config())
        self.config = self.__class__.config()
        self.config.merge(base_config)
        self.check_config(self.config)

        # Set up logging with the provided configuration.
        bt.logging.set_config(config=self.config.logging)

        # If a gpu is required, set the device to cuda:N (e.g. cuda:0)
        self.device = self.config.neuron.device

        # Log the configuration for reference.
        bt.logging.info(self.config)

        # Build Bittensor objects
        # These are core Bittensor classes to interact with the network.
        bt.logging.info("Setting up bittensor objects.")

        # The wallet holds the cryptographic key pairs for the miner.
        if self.config.mock:
            self.wallet = get_mock_wallet()
            self.subtensor = MockSubtensor(
                self.config.netuid, wallet=self.wallet
            )
            self.metagraph = MockMetagraph(
                self.config.netuid, subtensor=self.subtensor
            )
        else:
            self.wallet = bt.Wallet(config=self.config)
            self.subtensor = bt.Subtensor(config=self.config)
            self.metagraph = self.subtensor.metagraph(
                self.config.netuid, mechid=int(self.mechid)
            )

        bt.logging.info(f"Wallet: {self.wallet}")
        bt.logging.info(f"Subtensor: {self.subtensor}")
        bt.logging.info(f"Metagraph: {self.metagraph}")

        # Check if the miner is registered on the Bittensor network before proceeding further.
        self.check_registered()

        # Each miner gets a unique identity (UID) in the network for differentiation.
        self.uid = self.metagraph.hotkeys.index(
            self.wallet.hotkey.ss58_address
        )
        bt.logging.info(
            f"Running neuron on subnet: {self.config.netuid} with uid {self.uid} using network: {self.subtensor.chain_endpoint}"
        )
        self.step = 0
        self._last_metagraph_sync_block = self._metagraph_block()

    @abstractmethod
    async def forward(self, synapse: bt.Synapse) -> bt.Synapse:
        ...

    @abstractmethod
    def run(self):
        ...

    def sync(self):
        """
        Wrapper for synchronizing the state of the network for the given miner or validator.
        """
        # Ensure miner or validator hotkey is still registered on the network.
        self.check_registered()

        current_block = self.block
        if self.should_sync_metagraph(current_block=current_block):
            self.resync_metagraph()
            self._last_metagraph_sync_block = max(
                current_block,
                self._metagraph_block(),
            )

        if self.should_set_weights():
            self.set_weights()

        # Always save state.
        self.save_state()

    def check_registered(self):
        # --- Check for registration.
        hotkey_ss58 = self.wallet.hotkey.ss58_address
        try:
            is_registered = self.subtensor.is_hotkey_registered(
                netuid=self.config.netuid,
                hotkey_ss58=hotkey_ss58,
            )
        except Exception as exc:
            if not (
                isinstance(exc, TRANSIENT_REGISTRATION_EXCEPTIONS)
                and hotkey_ss58 in getattr(self.metagraph, "hotkeys", [])
            ):
                raise

            bt.logging.warning(
                "Subtensor registration check failed, but hotkey is present in "
                f"the local metagraph; continuing. error={exc}"
            )
            return

        if not is_registered:
            bt.logging.error(
                f"Wallet: {self.wallet} is not registered on netuid {self.config.netuid}."
                f" Please register the hotkey using `btcli subnets register` before trying again"
            )
            exit()

    def should_sync_metagraph(self, current_block: typing.Optional[int] = None):
        """
        Check if enough epoch blocks have elapsed since the last checkpoint to sync.
        """
        current_block = self.block if current_block is None else current_block
        last_sync_block = getattr(
            self,
            "_last_metagraph_sync_block",
            self._metagraph_block(),
        )
        return (current_block - last_sync_block) > self.config.neuron.epoch_length

    def _metagraph_block(self) -> int:
        block = getattr(self.metagraph, "block", 0)
        try:
            return int(block.item()) if hasattr(block, "item") else int(block)
        except (TypeError, ValueError):
            return 0

    def should_set_weights(self) -> bool:
        # Miners never set weights. Checked first so a miner never pays for the
        # chain read below.
        if self.neuron_type == "MinerNeuron":
            return False

        # Don't set weights on initialization.
        if self.step == 0:
            return False

        # Check if enough epoch blocks have elapsed since the last epoch.
        if self.config.neuron.disable_set_weights:
            return False

        return (
            self.block - self._last_weight_update_block()
        ) > self.config.neuron.epoch_length

    def _last_weight_update_block(self) -> int:
        """The block at which this hotkey last set weights on ITS mechanism.

        The SDK's metagraph fills `last_update` from neurons_lite(netuid), which
        is mechanism 0's slot whatever mechid the metagraph was built with. For
        mechanism 0 that is correct and is kept as-is. For any other mechanism
        the chain keeps a separate LastUpdate row (keyed by the mechanism's
        storage index), so it is read directly -- otherwise the security
        validator would pace itself on the LLM-key validator's weight sets.

        An unreadable or empty row returns 0 ("never set"), which only means we
        attempt a set; the chain's own per-mechanism rate limit still applies.
        """
        mechid = int(getattr(self, "mechid", 0) or 0)
        if mechid == 0 or getattr(self.config, "mock", False):
            return int(self.metagraph.last_update[self.uid])
        try:
            from bittensor.utils import get_mechid_storage_index

            index = get_mechid_storage_index(self.config.netuid, mechid)
            row = self.subtensor.substrate.query(
                "SubtensorModule", "LastUpdate", [index]
            ).value or []
            return int(row[self.uid]) if self.uid < len(row) else 0
        except Exception as exc:  # noqa: BLE001 - pacing must never crash the loop
            bt.logging.debug(f"mech{mechid} LastUpdate unreadable, assuming never set: {exc}")
            return 0

    def save_state(self):
        bt.logging.trace(
            "save_state() not implemented for this neuron. You can implement this function to save model checkpoints or other useful data."
        )

    def load_state(self):
        bt.logging.trace(
            "load_state() not implemented for this neuron. You can implement this function to load model checkpoints or other useful data."
        )
