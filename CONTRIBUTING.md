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

Releases are published by `.github/workflows/release.yml`, using PyPI trusted publishing (no tokens are stored in the repo).

1. Update `version` in `pyproject.toml` and `__version__` in `src/finact/__init__.py`, and add a `## X.Y.Z` section to `CHANGELOG.md`.
2. Push to `main` and check that CI is green.
3. Either push a tag (`git tag vX.Y.Z && git push origin vX.Y.Z`), or open **Actions → Release → Run workflow** on `main`, which creates the `vX.Y.Z` tag from the package version.

The workflow refuses to publish if the tag and the version differ. It then runs the tests, builds the package, uploads it to https://pypi.org/project/finact/ and creates the GitHub release, using that version's CHANGELOG section as the notes and attaching the built files.
