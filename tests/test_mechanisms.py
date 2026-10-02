"""Two mechanisms on one subnet: LLM-key on 0, security on 1.

Pins the three things that keep the tracks from bleeding into each other:
  * each neuron class is bound to its own mechid;
  * weights go to the validator's own mechanism (mechanism 0 keeps its
    original Subtensor.set_weights path; mechanism 1 goes straight to the
    extrinsic with mechid=1);
  * weight pacing reads the validator's own mechanism's LastUpdate row, not
    mechanism 0's.
No chain, no docker: the subtensor is faked.
"""

import sys
import types

import pytest

import neurons.miner as llm_miner
import neurons.security_miner as sec_miner
import neurons.security_validator as sec_validator
import neurons.validator as llm_validator
from bittensor.utils import get_mechid_storage_index
from masxai import constants as C
from template.utils.config import neuron_dir_name

NETUID = 501
UID = 3


# --- class binding ----------------------------------------------------------

def test_each_neuron_is_pinned_to_its_mechanism():
    assert llm_validator.Validator.mechid == C.LLM_KEY_MECHID == 0
    assert llm_miner.Miner.mechid == C.LLM_KEY_MECHID
    assert sec_validator.SecurityValidator.mechid == C.SECURITY_MECHID == 1
    assert sec_miner.SecurityMiner.mechid == C.SECURITY_MECHID


def test_mechanism_count_covers_both_tracks():
    assert C.LLM_KEY_MECHID != C.SECURITY_MECHID
    assert max(C.LLM_KEY_MECHID, C.SECURITY_MECHID) < C.MECHANISM_COUNT


def test_state_dirs_do_not_collide_across_mechanisms():
    # mechanism 0 keeps its historical directory; mechanism 1 is suffixed, so
    # two validators on one hotkey never share state.npz / the events log.
    assert neuron_dir_name("validator", 0) == "validator"
    assert neuron_dir_name("validator", 1) == "validator_mech1"
    assert neuron_dir_name("validator", 0) != neuron_dir_name("validator", 1)


# --- fakes ------------------------------------------------------------------

class FakeSubstrate:
    def __init__(self, rows, fail=False):
        self.rows = rows            # {storage_index: [last_update per uid]}
        self.fail = fail
        self.queries = []

    def query(self, module, storage, params):
        self.queries.append((module, storage, tuple(params)))
        if self.fail:
            raise ConnectionError("chain unreachable")
        return types.SimpleNamespace(value=self.rows.get(params[0], []))


class FakeSubtensor:
    def __init__(self, *, commit_reveal=True, rows=None, fail_query=False):
        self.commit_reveal = commit_reveal
        self.substrate = FakeSubstrate(rows or {}, fail=fail_query)
        self.set_weights_calls = []

    def set_weights(self, **kwargs):
        self.set_weights_calls.append(kwargs)
        return types.SimpleNamespace(success=True, message="")

    def commit_reveal_enabled(self, netuid):
        return self.commit_reveal


def make_validator(cls, subtensor, *, mg_last_update=0, block=10_000):
    v = cls.__new__(cls)
    v.subtensor = subtensor
    v.wallet = object()
    v.spec_version = 7
    v.uid = UID
    v.step = 5
    v.config = types.SimpleNamespace(
        netuid=NETUID,
        mock=False,
        neuron=types.SimpleNamespace(epoch_length=100, disable_set_weights=False),
    )
    # the SDK metagraph's last_update is always mechanism 0's row
    v.metagraph = types.SimpleNamespace(last_update=[mg_last_update] * 16)
    v._test_block = block
    return v


@pytest.fixture
def fixed_block(monkeypatch):
    from template.base.neuron import BaseNeuron
    monkeypatch.setattr(BaseNeuron, "block", property(lambda self: self._test_block))


# --- weight submission targets the right mechanism -------------------------

def test_llm_key_validator_keeps_subtensor_set_weights_on_mech0():
    sub = FakeSubtensor()
    v = make_validator(llm_validator.Validator, sub)
    resp = v._submit_weights([1, 2], [100, 200])
    assert resp.success
    assert len(sub.set_weights_calls) == 1
    call = sub.set_weights_calls[0]
    assert call["mechid"] == 0 and call["netuid"] == NETUID
    assert call["uids"] == [1, 2] and call["weights"] == [100, 200]


def test_security_validator_commits_to_mech1_without_the_mech0_precheck(monkeypatch):
    import bittensor.core.extrinsics.weights as w

    seen = {}

    def fake_commit(**kwargs):
        seen.update(kwargs)
        return types.SimpleNamespace(success=True, message="")

    def must_not_run(**kwargs):
        raise AssertionError("commit-reveal is on; direct set must not be used")

    monkeypatch.setattr(w, "commit_timelocked_weights_extrinsic", fake_commit)
    monkeypatch.setattr(w, "set_weights_extrinsic", must_not_run)

    sub = FakeSubtensor(commit_reveal=True)
    v = make_validator(sec_validator.SecurityValidator, sub)
    assert v._submit_weights([4], [65535]).success
    assert seen["mechid"] == 1 and seen["netuid"] == NETUID
    assert seen["uids"] == [4] and seen["weights"] == [65535]
    # Subtensor.set_weights (whose rate-limit guard reads mechanism 0's row)
    # is never used for mechanism 1.
    assert sub.set_weights_calls == []


def test_security_validator_sets_directly_when_commit_reveal_is_off(monkeypatch):
    import bittensor.core.extrinsics.weights as w

    seen = {}
    monkeypatch.setattr(w, "set_weights_extrinsic",
                        lambda **kw: seen.update(kw) or types.SimpleNamespace(success=True))
    monkeypatch.setattr(w, "commit_timelocked_weights_extrinsic",
                        lambda **kw: (_ for _ in ()).throw(AssertionError("no commit")))

    v = make_validator(sec_validator.SecurityValidator, FakeSubtensor(commit_reveal=False))
    assert v._submit_weights([4], [65535]).success
    assert seen["mechid"] == 1


# --- pacing reads the validator's own mechanism ----------------------------

def test_mech1_pacing_reads_mech1_lastupdate_not_mech0(fixed_block):
    idx1 = get_mechid_storage_index(NETUID, 1)
    # mechanism 0 set weights 10 blocks ago (LLM-key validator, same hotkey);
    # mechanism 1 last set 500 blocks ago -> the security validator is due.
    sub = FakeSubtensor(rows={idx1: [0] * UID + [9_500]})
    v = make_validator(sec_validator.SecurityValidator, sub, mg_last_update=9_990)
    assert v._last_weight_update_block() == 9_500
    assert sub.substrate.queries == [("SubtensorModule", "LastUpdate", (idx1,))]
    assert v.should_set_weights() is True


def test_mech1_not_due_when_its_own_row_is_recent(fixed_block):
    idx1 = get_mechid_storage_index(NETUID, 1)
    sub = FakeSubtensor(rows={idx1: [0] * UID + [9_950]})
    v = make_validator(sec_validator.SecurityValidator, sub, mg_last_update=0)
    assert v.should_set_weights() is False


def test_mech1_never_set_or_unreadable_counts_as_due(fixed_block):
    # empty row (mechanism never weighted) and a failed read both mean "try";
    # the chain's own per-mechanism rate limit still applies.
    v = make_validator(sec_validator.SecurityValidator, FakeSubtensor(rows={}))
    assert v._last_weight_update_block() == 0
    v = make_validator(sec_validator.SecurityValidator, FakeSubtensor(fail_query=True))
    assert v._last_weight_update_block() == 0
    assert v.should_set_weights() is True


def test_mech0_pacing_is_unchanged(fixed_block):
    sub = FakeSubtensor(fail_query=True)   # would blow up if mech 0 queried
    v = make_validator(llm_validator.Validator, sub, mg_last_update=9_950)
    assert v._last_weight_update_block() == 9_950
    assert v.should_set_weights() is False
    assert sub.substrate.queries == []


def test_miner_never_sets_weights_and_never_reads_chain(fixed_block):
    sub = FakeSubtensor(fail_query=True)
    m = make_validator(sec_miner.SecurityMiner, sub)
    assert m.neuron_type == "MinerNeuron"
    assert m.should_set_weights() is False
    assert sub.substrate.queries == []


# --- owner setup script -----------------------------------------------------

def _run_setup(monkeypatch, argv, *, count=1):
    import scripts.setup_mechanisms as setup

    sent = []

    class Sub:
        def __init__(self, network):
            self.count = count

        def get_mechanism_count(self, netuid):
            return self.count

        def get_mechanism_emission_split(self, netuid):
            return None

    def fake_sudo(**kwargs):
        sent.append(kwargs)
        return types.SimpleNamespace(success=True, message="")

    monkeypatch.setattr(setup.bt, "Subtensor", Sub)
    monkeypatch.setattr(setup.bt, "Wallet", lambda name: f"wallet:{name}")
    monkeypatch.setattr(setup, "sudo_call_extrinsic", fake_sudo)
    monkeypatch.setattr(sys, "argv", ["setup_mechanisms.py", *argv])
    return setup.main(), sent


def test_setup_is_read_only_without_apply(monkeypatch):
    code, sent = _run_setup(monkeypatch, ["--wallet.name", "owner"])
    assert code == 0 and sent == []


def test_setup_sends_owner_calls_unwrapped(monkeypatch):
    code, sent = _run_setup(
        monkeypatch, ["--wallet.name", "owner", "--split", "50,50", "--apply"]
    )
    assert code == 0
    assert [c["call_function"] for c in sent] == [
        "sudo_set_mechanism_count", "sudo_set_mechanism_emission_split",
    ]
    assert sent[0]["call_params"] == {"netuid": C.NETUID, "mechanism_count": 2}
    # root_call=True is what skips the Sudo.sudo wrapper (root-only); the
    # subnet owner must send the AdminUtils call unwrapped.
    assert all(c["root_call"] is True for c in sent)


def test_setup_rejects_a_split_of_the_wrong_length(monkeypatch):
    code, sent = _run_setup(monkeypatch, ["--wallet.name", "o", "--split", "100", "--apply"])
    assert code == 2 and sent == []
