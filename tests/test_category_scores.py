"""Tests for secqurityVali/category_scores.py -- the per-category capability matrix.

The key behaviours: an EMA per (hotkey, category) cell, and a mean-across-active
-categories aggregate that rewards breadth and remembers failures (so a one-trick
agent cannot look like an all-rounder).
"""

from secqurityVali.category_scores import CategoryScores

CATS = ("sqli", "xss", "ssrf")


def test_first_observation_seeds_the_cell():
    cs = CategoryScores(alpha=0.5)
    cs.update("m", "sqli", 1.0, now=0.0)
    assert cs.category_score("m", "sqli") == 1.0


def test_ema_moves_by_alpha():
    cs = CategoryScores(alpha=0.5)
    cs.update("m", "sqli", 1.0, now=0.0)
    cs.update("m", "sqli", 0.0, now=1.0)   # 0.5*0 + 0.5*1.0
    assert cs.category_score("m", "sqli") == 0.5


def test_untested_category_is_none():
    cs = CategoryScores(alpha=0.5)
    cs.update("m", "sqli", 1.0, now=0.0)
    assert cs.category_score("m", "xss") is None


def test_one_trick_agent_is_held_down_by_breadth():
    # Solves only sqli; xss and ssrf never solved -> mean = 1/3.
    cs = CategoryScores(alpha=0.5)
    cs.update("one_trick", "sqli", 1.0, now=0.0)
    assert abs(cs.aggregate("one_trick", CATS) - (1.0 / 3.0)) < 1e-9


def test_all_rounder_approaches_one():
    cs = CategoryScores(alpha=0.5)
    for c in CATS:
        cs.update("all_rounder", c, 1.0, now=0.0)
    assert cs.aggregate("all_rounder", CATS) == 1.0


def test_failure_is_remembered_distinct_from_untested():
    # "solved sqli, FAILED xss" must score below "solved sqli, xss untested",
    # even though a blind EMA would treat both the same on average.
    failed = CategoryScores(alpha=0.5)
    failed.update("m", "sqli", 1.0, now=0.0)
    failed.update("m", "xss", 0.0, now=1.0)          # known-weak

    untested = CategoryScores(alpha=0.5)
    untested.update("m", "sqli", 1.0, now=0.0)        # xss simply untested

    # Over the two categories that exist here, both average the same by mean,
    # but the distinction is visible per-cell:
    assert failed.category_score("m", "xss") == 0.0
    assert untested.category_score("m", "xss") is None


def test_aggregate_ignores_stale_cells():
    # A cell older than the freshness window counts as 0 (F4).
    cs = CategoryScores(alpha=0.5)
    cs.update("m", "sqli", 1.0, now=0.0)                       # solved at t=0
    assert cs.aggregate("m", ("sqli",), now=100.0, freshness_s=1000.0) == 1.0   # fresh
    assert cs.aggregate("m", ("sqli",), now=5000.0, freshness_s=1000.0) == 0.0  # stale


def test_aggregate_without_freshness_counts_all():
    cs = CategoryScores(alpha=0.5)
    cs.update("m", "sqli", 1.0, now=0.0)
    assert cs.aggregate("m", ("sqli",), now=1e9) == 1.0   # no freshness_s -> always counts


def test_aggregate_empty_categories_is_zero():
    cs = CategoryScores(alpha=0.5)
    cs.update("m", "sqli", 1.0, now=0.0)
    assert cs.aggregate("m", ()) == 0.0


def test_unknown_hotkey_aggregates_to_zero():
    cs = CategoryScores(alpha=0.5)
    assert cs.aggregate("never-seen", CATS) == 0.0


def test_prune_drops_absent_hotkeys():
    cs = CategoryScores(alpha=0.5)
    cs.update("keep", "sqli", 1.0, now=0.0)
    cs.update("drop", "sqli", 1.0, now=0.0)
    cs.prune({"keep"})
    assert "keep" in cs.cells and "drop" not in cs.cells


def test_save_and_load_roundtrip(tmp_path):
    path = str(tmp_path / "cat.json")
    cs = CategoryScores(alpha=0.3)
    cs.update("m", "sqli", 0.8, now=5.0)
    cs.save(path)

    back = CategoryScores.load(path, alpha=0.3)
    assert back.category_score("m", "sqli") == 0.8


def test_load_missing_file_is_empty(tmp_path):
    cs = CategoryScores.load(str(tmp_path / "nope.json"), alpha=0.4)
    assert cs.cells == {} and cs.alpha == 0.4
