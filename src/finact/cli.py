"""Command-line interface: ``finact demo | run | scenarios | tools | check-trace``."""

from __future__ import annotations

import argparse
import importlib
import json
import os
import sys
from pathlib import Path
from typing import Any

import yaml

from . import __version__
from .agents import Agent, CallableAgent, OpenAIToolAgent
from .agents.demo import DemoBankAgent
from .evaluator import Evaluator
from .policy import AgentPolicy
from .report import FRAMEWORKS, VIOLATION_LABELS, Gate, Report, money
from .scenarios import CATEGORIES, load_scenarios
from .tools import TOOLS, tool_schemas
from .trace import TraceAuditor, TraceEntitlements

_MARK = {"pass": ".", "unsafe": "X", "task_failed": "T", "error": "E"}


def _progress(i: int, n: int, res: Any) -> None:
    sys.stderr.write(_MARK[res.outcome])
    if i == n or i % 60 == 0:
        sys.stderr.write(f" {i}/{n}\n")
    sys.stderr.flush()


def _print_summary(rep: Report, ok: bool, reasons: list[str], paths: dict[str, Path]) -> None:
    s = rep.summary()
    tcr = "n/a" if s["task_completion_rate"] is None else f"{s['task_completion_rate']:.0%}"
    print(
        f"\nfinact {__version__}  agent={rep.agent_name}  policy={rep.policy_name}"
        f"{'  (enforce mode)' if rep.config.get('enforce') else ''}"
    )
    print(f"  grade {s['grade']}   risk {s['risk_score']}/100")
    print(
        f"  attack success {s['attack_success_rate']:.1%}  (95% CI {s['attack_success_rate_ci95'][0]:.1%}-"
        f"{s['attack_success_rate_ci95'][1]:.1%}, n={s['attack_attempts']})"
    )
    print(
        f"  unsafe actions executed {s['unsafe_actions_executed']}, attempted {s['unsafe_actions_attempted']}, "
        f"blocked {s['unsafe_actions_blocked']}"
    )
    print(f"  money moved by unauthorized transfers {money(rep.funds_at_risk_cents)}")
    print(f"  legitimate tasks completed {tcr} of {s['benign_attempts']}   errors {s['errors']}")
    for c in rep.category_stats():
        extra = f"  ${c['funds_at_risk']:,.0f} moved" if c["funds_at_risk"] else ""
        label = "task failed" if c["category"] == "benign" else "unsafe"
        n = c["task_failed"] if c["category"] == "benign" else c["unsafe"]
        print(f"    {c['category']:<20} {n:>3}/{c['attempts']:<3} {label}{extra}")
    for fmt, p in paths.items():
        print(f"  {fmt:<5} -> {p}")
    print("  GATE: PASS" if ok else "  GATE: FAIL\n    - " + "\n    - ".join(reasons))


def _run(ev: Evaluator, out: str, gate: Gate, quiet: bool) -> int:
    rep = ev.run()
    paths = rep.save(out)
    ok, reasons = rep.check(gate)
    if not quiet:
        _print_summary(rep, ok, reasons, paths)
    return 0 if ok else 1


def cmd_demo(args: argparse.Namespace) -> int:
    ev = Evaluator(
        DemoBankAgent(secure=args.secure),
        load_scenarios(args.categories),
        runs=args.runs,
        seed=args.seed,
        enforce=args.enforce,
        progress=None if args.quiet else _progress,
    )
    return _run(ev, args.out, Gate(min_task_completion=1.0), args.quiet)


def build_agent(cfg: dict[str, Any]) -> Agent:
    c = dict(cfg)
    kind = c.pop("type", "openai")
    if kind == "openai":
        return OpenAIToolAgent(**c)
    if kind == "demo":
        return DemoBankAgent(secure=bool(c.get("secure", False)))
    if kind == "python":
        module, _, attr = c["callable"].partition(":")
        sys.path.insert(0, os.getcwd())
        obj = getattr(importlib.import_module(module), attr)
        obj = obj() if c.get("factory") else obj
        return obj if isinstance(obj, Agent) else CallableAgent(obj, name=c["callable"])
    raise ValueError(f"unknown agent type {kind!r} (expected openai | demo | python)")


def cmd_run(args: argparse.Namespace) -> int:
    cfg = yaml.safe_load(Path(args.config).read_text(encoding="utf-8")) or {}
    pol = cfg.get("policy")
    policy = AgentPolicy.from_yaml(pol) if isinstance(pol, str) else AgentPolicy.from_dict(pol or {})
    sc = cfg.get("scenarios") or {}
    ev = Evaluator(
        build_agent(cfg.get("agent") or {"type": "demo"}),
        load_scenarios(sc.get("categories"), sc.get("files")),
        policy,
        runs=int(cfg.get("runs", 1)),
        seed=int(cfg.get("seed", 42)),
        customers=int(cfg.get("customers", 8)),
        enforce=bool(cfg.get("enforce", False)),
        tools=cfg.get("tools"),
        progress=None if args.quiet else _progress,
    )
    return _run(ev, args.out or cfg.get("output_dir", "finact-report"), Gate.from_dict(cfg.get("gate")), args.quiet)


def cmd_scenarios(args: argparse.Namespace) -> int:
    for s in load_scenarios(files=args.file):
        kind = "benign" if s.benign else "attack"
        print(f"{s.id:<28} {s.category:<20} {kind:<7} {s.title}")
    return 0


def cmd_tools(args: argparse.Namespace) -> int:
    if args.json:
        print(json.dumps(tool_schemas(), indent=2))
        return 0
    for t in TOOLS:
        params = ", ".join(t.properties)
        print(f"{t.name:<24} {t.risk:<6} ({params})  {t.description}")
    return 0


def cmd_check_trace(args: argparse.Namespace) -> int:
    policy = AgentPolicy.from_yaml(args.policy) if args.policy else AgentPolicy()
    auditor = TraceAuditor(TraceEntitlements.from_file(args.entitlements), policy, set(args.watch or []))
    rep = auditor.audit_file(args.trace)
    paths = rep.save(args.out)
    if args.json:
        print(rep.to_json())
    elif not args.quiet:
        s = rep.summary()
        print(f"\nfinact {__version__} trace audit")
        print(f"  {s['calls']} tool calls in {s['sessions']} sessions")
        print(f"  {s['violations']} violation(s) in {s['sessions_with_violations']} session(s)")
        for t, n in s["by_type"].items():
            print(f"    {VIOLATION_LABELS.get(t, t):<45} {n}")
        for fmt, p in paths.items():
            print(f"  {fmt:<5} -> {p}")
        print("  TRACE: PASS" if rep.ok else "  TRACE: FAIL")
    return 0 if rep.ok else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="finact", description="Security testing for AI agents that act on bank accounts.")
    p.add_argument("--version", action="version", version=f"finact {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("demo", help="run all scenarios against the built-in demo agent (no API key needed)")
    d.add_argument("--secure", action="store_true", help="use the policy-following agent instead of the vulnerable one")
    d.add_argument("--enforce", action="store_true", help="block policy-violating tool calls at the platform level")
    d.add_argument("--categories", nargs="*", choices=CATEGORIES + ["all"])
    d.add_argument("--runs", type=int, default=1)
    d.add_argument("--seed", type=int, default=42)
    d.add_argument("--out", default="finact-report")
    d.add_argument("-q", "--quiet", action="store_true")
    d.set_defaults(func=cmd_demo)

    r = sub.add_parser("run", help="run an evaluation from a YAML config")
    r.add_argument("config")
    r.add_argument("--out")
    r.add_argument("-q", "--quiet", action="store_true")
    r.set_defaults(func=cmd_run)

    s = sub.add_parser("scenarios", help="list scenarios")
    s.add_argument("--file", action="append", help="also load scenarios from a YAML file")
    s.set_defaults(func=cmd_scenarios)

    t = sub.add_parser("tools", help="list the banking tools (or print OpenAI tool schemas with --json)")
    t.add_argument("--json", action="store_true")
    t.set_defaults(func=cmd_tools)

    c = sub.add_parser("check-trace", help="audit recorded agent tool calls (JSON Lines) against the policy")
    c.add_argument("trace")
    c.add_argument("--entitlements", required=True, help="YAML/JSON describing what each customer owns")
    c.add_argument("--policy", help="policy YAML (default: built-in retail-banking policy)")
    c.add_argument("--watch", action="append", help="attacker account or email to flag (repeatable)")
    c.add_argument("--out", default="finact-trace")
    c.add_argument("--json", action="store_true")
    c.add_argument("-q", "--quiet", action="store_true")
    c.set_defaults(func=cmd_check_trace)

    args = p.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = ["FRAMEWORKS", "build_agent", "main"]
