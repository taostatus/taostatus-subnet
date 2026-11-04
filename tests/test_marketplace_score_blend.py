"""Marketplace DISPLAY-score blend: the agent-card overall_score shows
benchmark base + confirmed-audit bonus, WITHOUT touching the listing gate or
on-chain emission.

card overall_score = (1 - w) * benchmark + w * confirmed-audit usage, so a
benchmark-perfect agent with no real audits reads (1 - w) (e.g. 0.95) and real,
replay-confirmed audits lift the card to 1.0. The listing gate (should_publish)
stays on the plain benchmark aggregate -- an audit bonus can never buy a listing.
"""

import types

import neurons.security_validator as sv
from secqurityVali.category_scores import CategoryScores


class _Job:
    """Minimal JobResult build_agent_payload can read (all via getattr)."""
    task = types.SimpleNamespace(score=1.0)
    agent_name = "agent"
    agent_version = "1"
    run_id = "run1"
    category = "sqli"
    variant = "basic"


def _outcome(agent_id="agent1"):
    return types.SimpleNamespace(agent_id=agent_id, job=_Job())


def _validator(*, blend, w=0.05, cells=None):
    v = sv.SecurityValidator.__new__(sv.SecurityValidator)
    v._marketplace = object()          # non-None: feature on
    v._listed_agents = set()
    v._marketplace_min_score = 0.8
    v._marketplace_tolerance = 0.0
    v._marketplace_score_blend = blend
    v._audit_bonus_weight = w
    v._active_categories = ["sqli", "cmdi"]
    if cells is None:
        cells = {"HK_A": {c: {"score": 1.0, "updated_at": 0.0} for c in ("sqli", "cmdi")}}
    v._cat_scores = CategoryScores(alpha=0.5, cells=cells)
    v.config = types.SimpleNamespace(netuid=104)
    v.mechid = 1
    v.wallet = types.SimpleNamespace(hotkey=types.SimpleNamespace(ss58_address="VALI"))
    return v


def _push(v, *, aggregate, usage_map):
    pending: list[dict] = []
    v._queue_marketplace_push(
        pending, uid=0, hotkey="HK_A", outcome=_outcome(),
        aggregate=aggregate, now=1000.0, usage_map=usage_map,
    )
    return pending


def test_blend_off_card_shows_plain_benchmark():
    v = _validator(blend=False)
    pending = _push(v, aggregate=1.0, usage_map={0: 1.0})   # usage ignored
    assert pending[0]["overall_score"] == 1.0


def test_blend_on_no_audit_caps_card_at_one_minus_w():
    v = _validator(blend=True)
    pending = _push(v, aggregate=1.0, usage_map={})          # no audit row
    assert pending[0]["overall_score"] == 0.95


def test_blend_on_full_audit_reaches_one():
    v = _validator(blend=True)
    pending = _push(v, aggregate=1.0, usage_map={0: 1.0})
    assert pending[0]["overall_score"] == 1.0


def test_blend_on_half_audit_is_additive():
    v = _validator(blend=True)
    pending = _push(v, aggregate=1.0, usage_map={0: 0.5})
    assert abs(pending[0]["overall_score"] - (0.95 + 0.05 * 0.5)) < 1e-9


def test_listing_gate_stays_on_benchmark_not_the_bonus():
    # Benchmark 0 (not listed) + full audit -> still NOT published: the audit
    # bonus is display-only and can never buy a listing.
    v = _validator(blend=True, cells={})
    pending = _push(v, aggregate=0.0, usage_map={0: 1.0})
    assert pending == []
