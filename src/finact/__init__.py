"""finact: security testing for AI agents that act on bank accounts.

Quick start::

    from finact import Evaluator
    from finact.agents.demo import DemoBankAgent

    report = Evaluator(DemoBankAgent()).run()
    print(report.summary())
"""

__version__ = "0.2.0"

from .agents import Agent, AgentContext, CallableAgent, OpenAIToolAgent  # noqa: E402
from .bank import Bank  # noqa: E402
from .evaluator import AttemptResult, Evaluator  # noqa: E402
from .policy import AgentPolicy, Oracle, SessionContext, Violation  # noqa: E402
from .report import Gate, Report  # noqa: E402
from .scenarios import Scenario, load_scenarios  # noqa: E402
from .tools import TOOLS, ToolBox, tool_schemas  # noqa: E402
from .trace import TraceAuditor, TraceEntitlements, TraceReport  # noqa: E402

__all__ = [
    "TOOLS",
    "Agent",
    "AgentContext",
    "AgentPolicy",
    "AttemptResult",
    "Bank",
    "CallableAgent",
    "Evaluator",
    "Gate",
    "OpenAIToolAgent",
    "Oracle",
    "Report",
    "Scenario",
    "SessionContext",
    "ToolBox",
    "TraceAuditor",
    "TraceEntitlements",
    "TraceReport",
    "Violation",
    "__version__",
    "load_scenarios",
    "tool_schemas",
]
