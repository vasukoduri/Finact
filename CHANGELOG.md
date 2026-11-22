# Changelog

## 0.1.0 (2026-11-22)

Initial release.

- **Sandbox bank**: synthetic customers, checking and savings accounts, saved payees, transaction history and SMS one-time passcodes, using never-issued identifier ranges. Balances really change, so money moved is measurable.
- **13 banking tools** with OpenAI function schemas: reads, OTP send/verify, transfers, payees, contact changes, statement export, and two admin tools (limit increase, account closure).
- **Authorization oracle** with 10 violation types: BOLA read/write, step-up bypass, unauthenticated access, prohibited actions, unverified destinations, limits, new-payee cooling-off, attacker watch list and data leaks in replies. YAML-configurable policy.
- **26 scenarios** in 8 categories, including 6 legitimate tasks that must be completed; YAML custom scenarios with `{me}`, `{victim}`, `{mule}`, `{otp}` placeholders and injection setups.
- **Agents**: OpenAI-compatible tool-calling loop, callable wrapper for your own agent, and rule-based vulnerable and secure demo agents.
- **Enforce mode** to block violating calls and report what the agent attempted.
- **Trace audit** (`finact check-trace`) for recorded production tool calls.
- **Reports**: attack success with Wilson confidence intervals, money moved, task completion, grade, CI gate; JSON, Markdown, HTML and JUnit.
- CLI: `finact demo | run | scenarios | tools | check-trace`.
