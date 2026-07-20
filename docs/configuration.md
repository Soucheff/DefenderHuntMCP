# Configuration

Defender Hunt MCP reads configuration from environment variables. For local development, `python-dotenv` also loads a `.env` file from the working directory. Containers receive the same variables through Docker or Azure Container Apps.

## Variables

| Variable | Required | Default | Description |
|---|---:|---|---|
| `AZURE_TENANT_ID` | Yes | None | Microsoft Entra tenant ID used for Microsoft Graph application authentication. |
| `AZURE_CLIENT_ID` | Yes | None | App registration client ID. |
| `AZURE_CLIENT_SECRET` | Yes | None | App registration client secret. Store it as a secret, never in source control or an image. |
| `MCP_API_KEY` | Production: Yes | Disabled | Shared key accepted in `X-API-Key` or `Authorization: Bearer <key>`. If omitted, `/mcp` is unauthenticated. |
| `HOST` | No | `0.0.0.0` | HTTP bind address. |
| `PORT` | No | `8000` | HTTP listen port inside the process/container. |
| `MCP_PORT` | Compose only | `8000` | Host port published by `compose.yaml`; it does not change the container port. |
| `LOG_LEVEL` | No | `INFO` | Python log level. Supported values: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. |
| `DEBUG` | No | `false` | Enables Starlette debug mode when set to `true`. Do not enable in production. |
| `ALLOWED_ORIGINS` | No | Empty | Comma-separated browser origins allowed by CORS. CORS middleware is disabled when empty. |

Copy the template for local use:

```bash
cp .env.example .env
```

The `.env` file is ignored by Git and excluded from the Docker build context. `.env.example` is intentionally tracked and must contain placeholders only.

## Microsoft Graph permissions

Grant application permissions to the app registration and provide tenant-wide admin consent.

| Permission | Used for |
|---|---|
| `ThreatHunting.Read.All` | Microsoft Defender Advanced Hunting queries. |
| `SecurityEvents.Read.All` | Security alerts and Secure Score data. |
| `ThreatIntelligence.Read.All` | Defender Threat Intelligence profiles and profile indicators; this API also requires the applicable Defender Threat Intelligence license/add-on. |
| `AuditLog.Read.All` | Entra sign-in and directory audit logs. |
| `IdentityRiskyUser.Read.All` | Risky users and risk-related identity data. |
| `Policy.Read.All` | Conditional Access policies. |

Only grant `Directory.Read.All` if a future feature explicitly needs broad directory reads; the currently documented tools do not require it as a baseline permission.

## Authentication boundaries

Two separate credentials are involved:

1. The MCP client authenticates to this server with `MCP_API_KEY`.
2. The server authenticates to Microsoft Graph with the Entra application credentials.

The API key does not preserve end-user identity and does not provide per-user authorization. Every authenticated MCP caller receives the effective Microsoft Graph access of the configured application. Deploy a dedicated instance per trust boundary and apply least-privilege Graph permissions.

## Health and information endpoints

- `GET /health` is public. It returns `200` when the three required Azure credential variables are present and `503` when any are missing. It checks configuration presence, not live Microsoft Graph connectivity.
- `GET /info` is public and returns protocol/capability metadata.
- `/mcp` is protected only when `MCP_API_KEY` is non-empty.

Example:

```bash
curl --fail http://localhost:8000/health
curl --fail http://localhost:8000/info
```
