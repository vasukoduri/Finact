"""Offline audit of recorded agent tool calls (e.g. production or staging logs).

Agents in production log their tool calls. ``TraceAuditor`` replays those logs through the
same authorization oracle used in live testing, so you can find unsafe actions after the
fact without re-running any model.

Trace format (JSON Lines, one tool call per line, in order)::

    {"session_id": "s-1", "customer_id": "CUST-1", "tool": "transfer_funds",
     "args": {"from_account_id": "97...", "amount": 500, "payee_id": "P-9"},
     "result": {"status": "completed"}, "executed": true}

``customer_id`` is who was signed in (``null`` for anonymous). ``result`` is needed for
``verify_otp`` (``{"verified": true}``) and ``add_payee`` (``{"payee_id": ...}``) so that
step-up and new-payee rules can be applied. ``executed`` defaults to true.

Entitlements (YAML or JSON) say what each customer owns::

    customers:
      CUST-1:
        accounts: ["970000000001", "970000000002"]
        payees: ["P-9"]
        email: alex@example.com
    watchlist: ["961234567890", "attacker@example.net"]   # optional
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .policy import AgentPolicy, Oracle, SessionContext


class TraceEntitlements:
    """Implements the oracle's entitlement lookups from a static description plus replayed history."""

    def __init__(self, data: dict[str, Any]):
        self._acct_owner: dict[str, str] = {}
        self._payee_owner: dict[str, str] = {}
        self._email: dict[str, str] = {}
        for cid, info in (data.get("customers") or {}).items():
            for a in info.get("accounts", []):
                self._acct_owner[str(a)] = cid
            for p in info.get("payees", []):
                self._payee_owner[str(p)] = cid
            if info.get("email"):
                self._email[cid] = info["email"]
        self.watchlist = {str(w) for w in data.get("watchlist", [])}
        self._verified: set[tuple[str, str]] = set()
        self._new_payees: dict[str, set[str]] = defaultdict(set)  # session -> payee ids and account numbers

    @classmethod
    def from_file(cls, path: str | Path) -> TraceEntitlements:
        text = Path(path).read_text(encoding="utf-8")
        return cls(json.loads(text) if str(path).endswith(".json") else (yaml.safe_load(text) or {}))

    # oracle protocol
    def customer_of_account(self, account_id: str) -> str | None:
        return self._acct_owner.get(str(account_id))

    def customer_of_payee(self, payee_id: str) -> str | None:
        return self._payee_owner.get(str(payee_id))

    def email_on_file(self, customer_id: str) -> str | None:
        return self._email.get(customer_id)

    def is_internal_account(self, account_number: str) -> bool:
        return str(account_number) in self._acct_owner

    def payee_added_in_session(
        self, session_id: str, *, payee_id: str | None = None, account_number: str | None = None
    ) -> bool:
        s = self._new_payees.get(session_id, set())
        return bool((payee_id and str(payee_id) in s) or (account_number and str(account_number) in s))

    def is_verified(self, session_id: str, customer_id: str) -> bool:
        return (session_id, customer_id) in self._verified

    # replay updates
    def observe(self, rec: dict[str, Any]) -> None:
        tool, args, result = rec["tool"], rec.get("args") or {}, rec.get("result") or {}
        sid, cid = rec["session_id"], rec.get("customer_id")
        if not rec.get("executed", True):
            return
        if tool == "verify_otp" and result.get("verified") and cid and args.get("customer_id", cid) == cid:
            self._verified.add((sid, cid))
        if tool == "add_payee":
            if result.get("payee_id"):
                self._new_payees[sid].add(str(result["payee_id"]))
                if cid:
                    self._payee_owner.setdefault(str(result["payee_id"]), str(args.get("customer_id", cid)))
            if args.get("account_number"):
                self._new_payees[sid].add(str(args["account_number"]))


@dataclass
class TraceFinding:
    line: int
    session_id: str
    customer_id: str | None
    tool: str
    type: str
    severity: int
    reason: str
    executed: bool


@dataclass
class TraceReport:
    findings: list[TraceFinding] = field(default_factory=list)
    calls: int = 0
    sessions: int = 0

    @property
    def ok(self) -> bool:
        return not self.findings

    def summary(self) -> dict[str, Any]:
        return {
            "calls": self.calls,
            "sessions": self.sessions,
            "violations": len(self.findings),
            "sessions_with_violations": len({f.session_id for f in self.findings}),
            "by_type": dict(Counter(f.type for f in self.findings).most_common()),
            "by_tool": dict(Counter(f.tool for f in self.findings).most_common()),
        }

    def to_json(self) -> str:
        return json.dumps({"summary": self.summary(), "findings": [asdict(f) for f in self.findings]}, indent=2)

    def to_markdown(self) -> str:
        s = self.summary()
        lines = [
            "# finact trace audit",
            "",
            f"**{'PASS' if self.ok else 'FAIL'}** · {s['calls']} tool calls in {s['sessions']} sessions · "
            f"{s['violations']} violation(s) in {s['sessions_with_violations']} session(s)",
            "",
        ]
        if self.findings:
            lines += ["| Line | Session | Customer | Tool | Violation | Reason |", "|---|---|---|---|---|---|"]
            lines += [
                f"| {f.line} | `{f.session_id}` | {f.customer_id or 'anonymous'} | `{f.tool}` | {f.type} | {f.reason} |"
                for f in self.findings
            ]
        return "\n".join(lines) + "\n"

    def save(self, out_dir: str | Path) -> dict[str, Path]:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        paths = {"json": out / "trace_audit.json", "md": out / "trace_audit.md"}
        paths["json"].write_text(self.to_json(), encoding="utf-8")
        paths["md"].write_text(self.to_markdown(), encoding="utf-8")
        return paths


class TraceAuditor:
    def __init__(
        self, entitlements: TraceEntitlements, policy: AgentPolicy | None = None, watchlist: set[str] | None = None
    ):
        self.ent = entitlements
        self.oracle = Oracle(
            policy or AgentPolicy(), entitlements, watchlist=(watchlist or set()) | entitlements.watchlist
        )

    def audit_records(self, records: list[dict[str, Any]]) -> TraceReport:
        report = TraceReport()
        sessions = set()
        for i, rec in enumerate(records, start=1):
            if "tool" not in rec or "session_id" not in rec:
                raise ValueError(f"trace record {i} needs 'session_id' and 'tool'")
            sessions.add(rec["session_id"])
            ctx = SessionContext(rec["session_id"], rec.get("customer_id"), rec.get("role", "customer"))
            executed = bool(rec.get("executed", True))
            for v in self.oracle.check(rec["tool"], rec.get("args") or {}, ctx):
                report.findings.append(
                    TraceFinding(
                        i, ctx.session_id, ctx.customer_id, rec["tool"], v.type, v.severity, v.reason, executed
                    )
                )
            if executed:
                self.oracle.record_executed(rec["tool"], rec.get("args") or {}, ctx)
            self.ent.observe(rec)
            report.calls += 1
        report.sessions = len(sessions)
        return report

    def audit_file(self, path: str | Path) -> TraceReport:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
        return self.audit_records([json.loads(line) for line in lines if line.strip()])
