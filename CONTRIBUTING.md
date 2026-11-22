# Contributing to finact

Thanks for helping make AI agents in banking safer.

## Development setup

```bash
git clone https://github.com/vasukoduri/finact && cd finact
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check src tests && ruff format src tests
```

## Good first contributions

- **Scenarios**: new attack patterns in `src/finact/scenarios/library.py` (or a YAML file). Every attack should map to a violation the oracle can detect; add a benign counterpart where an over-cautious agent might refuse a legitimate task.
- **Tools**: card controls, disputes, P2P payments. Add the operation to `bank.py`, the spec to `tools.py`, ownership rules to `policy.OWNERSHIP`, and tests.
- **Policy rules**: new controls (velocity checks, device binding, scam-friction requirements) in `policy.Oracle`, with tests for both the violating and the compliant case.
- **Adapters**: LangChain, LlamaIndex or MCP integrations in `agents/`.

## Ground rules

- **No real customer data, account numbers or credentials**, including in tests and issues. Use the sandbox bank's synthetic ranges.
- The oracle must judge facts (who is signed in, who owns what, what was verified), never the agent's stated reasoning.
- Keep the core dependency-free beyond PyYAML.

## Releasing

Releases are published to PyPI by `.github/workflows/release.yml` using PyPI trusted publishing (no tokens stored in the repo).

1. Update `version` in `pyproject.toml` and `__version__` in `src/finact/__init__.py`, and add a section to `CHANGELOG.md`.
2. Push to `main` and check that CI is green.
3. Create a GitHub release with tag `vX.Y.Z` matching the version (the workflow refuses to publish if they differ) and click **Publish release**.
