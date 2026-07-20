# Development

## Prerequisites

- Python 3.12
- [uv](https://docs.astral.sh/uv/)
- Docker Desktop for container validation
- Microsoft Graph credentials for live integration testing

The project is an application rather than an installable Python package. Runtime dependencies and development groups are declared in `pyproject.toml`; exact versions are committed in `uv.lock`.

## Environment setup

```bash
uv sync --frozen
cp .env.example .env
```

`uv` uses the Python version selected by `.python-version` and creates `.venv` automatically.

Run the HTTP server:

```bash
uv run server_http.py
```

The endpoints are:

- MCP: `http://localhost:8000/mcp`
- Health: `http://localhost:8000/health`
- Information: `http://localhost:8000/info`

## Dependency workflow

Add or remove dependencies through `uv` so `pyproject.toml` and `uv.lock` remain synchronized:

```bash
uv add <runtime-package>
uv add --dev <development-package>
uv remove <package>
uv lock --check
```

Do not add a parallel `requirements.txt`; `pyproject.toml` and `uv.lock` are the single dependency source of truth.

## Quality checks

```bash
uv lock --check
uv run ruff check config.py server.py server_http.py
uv run python -m py_compile config.py server.py server_http.py
uv run pytest
```

The repository includes unit and contract tests for query safety, schemas, partial failures, Entra JWT classification, auth middleware/policies, OBO/Managed Identity routing, Redis/cache isolation, workflows, and beta governance adapters.

## MCP smoke test

Acquire a delegated or application access token for the configured MCP audience, then send an initialize request:

```bash
curl --fail --silent \
  -X POST http://localhost:8000/mcp \
  -H 'Authorization: Bearer <entra-access-token-for-mcp>' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  --data '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
      "protocolVersion": "2025-03-26",
      "capabilities": {},
      "clientInfo": {"name": "smoke-test", "version": "1.0"}
    }
  }'
```

This verifies the MCP transport and authentication only. Tool calls require valid Graph credentials, permissions, licensing, and tenant data.

## Project layout

| Path | Purpose |
|---|---|
| `server.py` | FastMCP resources, atomic tools, workflows, governance tools, and KQL queries. |
| `server_http.py` | Starlette/Uvicorn gateway, Entra middleware, CORS, health and information routes. |
| `config.py` | Environment loading and required-variable validation. |
| `query_safety.py` | Central validation and quoting for caller-provided KQL/OData literals. |
| `entra_auth.py`, `auth_context.py`, `auth_policy.py` | JWT validation, request identity, and per-capability authorization. |
| `graph_clients.py` | Delegated OBO and autonomous Managed Identity Graph routing. |
| `cache_backend.py`, `cache_runtime.py` | Redis/in-memory backends, identity-isolated keys, cache-aside, and Azure Managed Redis credentials. |
| `workflow_engine.py` | Bounded concurrent orchestration and compact result normalization. |
| `agent_governance.py` | Feature-flagged Microsoft Graph beta adapter and permission analysis. |
| `infra/main.bicep` | Managed Identity, ACR, Container Apps, Azure Managed Redis, and role-assignment infrastructure. |
| `pyproject.toml` | Project metadata, dependencies, pytest and Ruff configuration. |
| `uv.lock` | Reproducible dependency lockfile. |
| `Dockerfile` | Multi-stage, non-root production image. |
| `compose.yaml` | Hardened local container runtime defaults. |
| `deploy.ps1` | Build/push/update flow for existing Azure resources. |
| `deploy-full.ps1` | Infrastructure provisioning plus deployment to Azure Container Apps. |

## KQL development rules

- Filter large tables by time before aggregation or joins.
- Bound result sets with `limit`/`top` and project only needed columns.
- Validate table columns against the current Defender Advanced Hunting schema.
- Cast dynamic values before grouping, sorting, or joining.
- Treat public `externaldata()` feeds as untrusted, mutable dependencies.
- Never interpolate unvalidated user input into a KQL literal.

`validate_kql_query` currently performs only a basic known-table reference check. It does not parse KQL or submit a syntax-only request to Defender.
