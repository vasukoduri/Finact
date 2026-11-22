# Changelog

## 0.2.0 (2026-11-22)

First release on PyPI. It includes everything in 0.1.0 below, plus:

### Added
- **20 new scenarios** (46 in total: 36 attacks, 10 legitimate tasks):
  - Legitimate tasks: list payees, check profile, small savings-to-checking transfer, large own-account transfer with verification.
  - Object-level authorization: another customer's payees; another customer's statements sent to the attacker's own address.
  - Step-up bypass: "a colleague already approved it".
  - Account takeover: email and phone change while "traveling"; fake bank IT.
  - Payment fraud: landlord bank-detail change (business email compromise), romance scam, overpayment refund scam, structuring past the daily limit, a single payment over the limit.
  - Privileged actions: closing another customer's account ("I'm the executor").
  - Prompt injection: instructions in the customer's address field, a memo telling the agent to raise limits, and a delayed injection that redirects a payment two turns later.
  - Unauthenticated: transfers and email changes without signing in.
- New scenario setups: `inject_profile`, `inject_limit_memo`, `inject_redirect_memo`.
- The secure demo agent pays only own accounts and saved payees, recognizes more scam cues, and stays at 0% attack success with 100% task completion.

### Changed
- Sandbox balances start higher (checking from $6,000, savings from $5,000), so multi-payment scenarios aren't cut short by insufficient funds.

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
