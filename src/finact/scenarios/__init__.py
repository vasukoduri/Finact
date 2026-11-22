"""Scenario model and loader."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .library import BUILTIN_SCENARIOS

SETUPS = {None, "inject_transaction", "inject_payee", "inject_profile", "inject_limit_memo", "inject_redirect_memo"}


@dataclass(frozen=True)
class Scenario:
    id: str
    category: str
    title: str
    turns: tuple[str, ...]
    benign: bool = False
    role: str = "customer"  # customer | anonymous
    expect: tuple[str, ...] = ()
    setup: str | None = None
    tags: tuple[str, ...] = field(default_factory=tuple)
    description: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Scenario:
        turns = d.get("turns") or [d["prompt"]]
        setup = d.get("setup")
        if setup not in SETUPS:
            raise ValueError(
                f"scenario {d['id']}: unknown setup {setup!r}; expected one of {sorted(s for s in SETUPS if s)}"
            )
        benign = bool(d.get("benign", False))
        expect = tuple(d.get("expect", []))
        if benign and not expect:
            raise ValueError(f"benign scenario {d['id']} needs 'expect' (tools that must complete)")
        return cls(
            id=d["id"],
            category=d.get("category", "custom"),
            title=d.get("title", d["id"]),
            turns=tuple(turns),
            benign=benign,
            role=d.get("role", "customer"),
            expect=expect,
            setup=setup,
            tags=tuple(d.get("tags", [])),
            description=d.get("description", ""),
        )


ALL_SCENARIOS: list[Scenario] = [Scenario.from_dict(s) for s in BUILTIN_SCENARIOS]
CATEGORIES: list[str] = sorted({s.category for s in ALL_SCENARIOS})


def load_scenarios(categories: list[str] | None = None, files: list[str | Path] | None = None) -> list[Scenario]:
    """Built-in scenarios filtered by category (``None`` or ``["all"]`` = all), plus YAML files."""
    scenarios = list(ALL_SCENARIOS)
    if categories and "all" not in categories:
        unknown = set(categories) - set(CATEGORIES)
        if unknown:
            raise ValueError(f"unknown categories {sorted(unknown)}; available: {CATEGORIES}")
        scenarios = [s for s in scenarios if s.category in categories]
    for f in files or []:
        data = yaml.safe_load(Path(f).read_text(encoding="utf-8")) or []
        items = data.get("scenarios", []) if isinstance(data, dict) else data
        scenarios.extend(Scenario.from_dict(item) for item in items)
    ids = [s.id for s in scenarios]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        raise ValueError(f"duplicate scenario ids: {dupes}")
    return scenarios


__all__ = ["ALL_SCENARIOS", "CATEGORIES", "Scenario", "load_scenarios"]
