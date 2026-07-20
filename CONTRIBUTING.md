# Contributing

Contributions to Defender Hunt MCP are welcome. Keep changes focused, document security implications, and never include real tenant data or credentials.

## Development setup

Prerequisites:

- Python 3.12
- `uv`
- Docker for container changes
- PowerShell 7 for deployment script changes

Set up the locked environment:

```bash
uv sync --frozen
cp .env.example .env
```

Use only placeholders or dedicated non-production credentials in `.env`. The file is ignored by Git.

## Making changes

1. Create a branch from the current default branch.
2. Keep each change scoped to one behavior or concern.
3. Add or update tests for behavior changes.
4. Update README and `docs/` when contracts, configuration, tools, deployment, or limitations change.
5. Do not add a parallel `requirements.txt`; manage dependencies through `uv add`, `uv remove`, and `uv.lock`.
6. Do not commit `.env`, tokens, client secrets, certificates, tenant exports, logs, `.venv`, or Python caches.

When editing KQL:

- verify table and column names against the current Defender schema;
- filter by time before joins or aggregations;
- bound results and project only required columns;
- validate and escape all caller-provided values;
- document external feeds and failure semantics.

## Required checks

```bash
uv lock --check
uv run ruff check config.py server.py server_http.py
uv run python -m py_compile config.py server.py server_http.py
uv run pytest
docker compose --env-file .env.example config --quiet
docker build -t defender-hunt-mcp:review .
```

When no automated test exists for a changed path, document the manual validation performed.

## Pull requests

A pull request should include:

- the problem and intended behavior;
- implementation and security tradeoffs;
- validation commands and results;
- documentation changes;
- any Microsoft Graph permissions, licensing, or schema requirements;
- sanitized screenshots or output only when necessary.

Do not report vulnerabilities in a public pull request. Follow [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the repository's [MIT License](LICENSE).
