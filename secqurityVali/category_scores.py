from __future__ import annotations

"""secqurityVali/category_scores.py - per-miner, per-category capability memory.

Once the benchmark issues a RANDOM vulnerability category per run, a single run
tests only one category. Scoring a miner on that one run alone is both noisy and
misleading: a one-trick agent that happens to draw its one category looks as
good as an all-rounder, and an all-rounder that happens to draw a category it
hasn't mastered looks bad. Neither is the truth.

So the validator keeps a small matrix per miner -- one cell per category --
holding an EMA of that miner's task scores in that category:

    hotkey_A: { sqli: 0.95, xss: 0.80, ssrf: 0.00, cmdi: <untested> }

Each run updates exactly the cell for the category it tested. The miner's
overall score is the MEAN across the active categories, with an untested (or
failed) category counting as 0. That is what makes breadth matter: a one-trick
agent that only ever solves `sqli` averages 1/N, while an all-rounder that
solves every category approaches 1.0. A blind EMA over raw per-run rewards
cannot do this -- it cannot tell "solved sqli, never tested on xss" (unknown)
from "solved sqli, failed xss" (known-weak); the per-category cells can.

Pure and stdlib-only, so the aggregation rule is unit-tested here rather than
discovered on a live validator. Persistence is plain JSON, loaded at startup and
saved after each round, so a restart never loses the matrix. Each cell also
records when it was last updated -- not used by the mean yet, but there so a
freshness/decay rule (don't let a miner coast on a category it solved once, long
ago) can be added without a data migration.
"""

import json
import time
from dataclasses import dataclass, field


@dataclass
class CategoryScores:
    """The per-hotkey, per-category EMA matrix. `alpha` is the EMA weight on the
    newest observation (higher = more reactive, lower = more stable)."""

    alpha: float = 0.5
    # {hotkey: {category: {"score": float, "updated_at": float}}}
    cells: dict[str, dict[str, dict]] = field(default_factory=dict)

    def update(self, hotkey: str, category: str, value: float, *, now: float | None = None) -> float:
        """Fold one run's score for (hotkey, category) into that cell's EMA and
        return the new cell value. The first observation seeds the cell; later
        ones move it by `alpha`."""
        now = time.time() if now is None else now
        by_cat = self.cells.setdefault(hotkey, {})
        cell = by_cat.get(category)
        if cell is None:
            new = float(value)
        else:
            new = self.alpha * float(value) + (1.0 - self.alpha) * float(cell["score"])
        by_cat[category] = {"score": new, "updated_at": now}
        return new

    def category_score(self, hotkey: str, category: str) -> float | None:
        """This miner's EMA in one category, or None if never tested there."""
        cell = self.cells.get(hotkey, {}).get(category)
        return None if cell is None else float(cell["score"])

    def aggregate(self, hotkey: str, categories, *, now: float | None = None,
                  freshness_s: float | None = None) -> float:
        """The miner's overall score: the MEAN across `categories`, where a
        category with no record counts as 0. Breadth is rewarded -- solving more
        categories raises the mean; a category left unsolved holds it down.

        With `freshness_s`, a cell older than that window also counts as 0 (stale):
        a miner must keep its categories refreshed to keep earning, so a one-time
        solve cannot pay forever (F4). `now` defaults to the wall clock.
        """
        cats = list(categories)
        if not cats:
            return 0.0
        total = 0.0
        for cat in cats:
            cell = self.cells.get(hotkey, {}).get(cat)
            if cell is None:
                continue
            if freshness_s is not None:
                if now is None:
                    now = time.time()
                if now - float(cell["updated_at"]) > freshness_s:
                    continue  # stale evidence -> counts as 0
            total += float(cell["score"])
        return total / len(cats)

    def prune(self, valid_hotkeys) -> None:
        """Drop rows for hotkeys no longer in the metagraph (a uid can change
        hands). Best-effort housekeeping; never required for correctness."""
        keep = set(valid_hotkeys)
        for hk in [h for h in self.cells if h not in keep]:
            del self.cells[hk]

    # --- persistence ---------------------------------------------------

    def to_dict(self) -> dict:
        return {"alpha": self.alpha, "cells": self.cells}

    def save(self, path: str) -> None:
        """Best-effort write. A failed save must never take the validator down,
        so it is swallowed -- the in-memory matrix is still authoritative for
        this process; only a crash before the next save loses the delta."""
        try:
            tmp = f"{path}.tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self.to_dict(), fh)
            import os
            os.replace(tmp, path)
        except Exception:  # noqa: BLE001 - persistence is best-effort
            pass

    @classmethod
    def load(cls, path: str, *, alpha: float) -> "CategoryScores":
        """Load the matrix, or return an empty one if the file is absent or
        unreadable. `alpha` comes from current config, overriding any stored
        value, so tuning it does not require editing the state file."""
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            cells = data.get("cells", {}) if isinstance(data, dict) else {}
            if not isinstance(cells, dict):
                cells = {}
            return cls(alpha=alpha, cells=cells)
        except (FileNotFoundError, ValueError, OSError):
            return cls(alpha=alpha, cells={})
