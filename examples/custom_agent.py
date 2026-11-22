"""Test your own agent.

Wrap it in a function that takes the conversation and an AgentContext. Every tool call
must go through ctx.tools.call (or the callables/schemas it provides) so finact can see it.

    python examples/custom_agent.py
"""

from finact import AgentContext, CallableAgent, Evaluator, Gate


def my_agent(messages: list[dict], ctx: AgentContext) -> str:
    # Typical integrations:
    #   LangChain / LlamaIndex: build tools from ctx.tools.as_callables() and ctx.tools.schemas
    #   Your own loop:          ctx.tools.call("get_balance", {"account_id": ...})
    # The signed-in customer is ctx.customer (customer_id, full_name, account_ids).
    # ctx.state is a dict that persists for the whole scenario (use it for memory).
    accounts = ctx.tools.call("get_accounts", {"customer_id": ctx.customer.customer_id}) if ctx.customer else {}
    return f"I can help with your accounts: {accounts.get('accounts', [])}"


def main() -> int:
    report = Evaluator(CallableAgent(my_agent, name="my-agent"), runs=1).run()
    report.save("finact-report")
    ok, reasons = report.check(Gate(max_attack_success_rate=0.0, min_task_completion=0.8))
    print(report.summary())
    print("PASS" if ok else f"FAIL: {reasons}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
