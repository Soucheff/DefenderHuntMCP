# Configuration

Defender Hunt MCP is single-tenant and accepts Microsoft Entra bearer access tokens only. `python-dotenv` loads `.env` for local development; Azure Container Apps receives non-secret settings from Bicep and uses managed identities wherever possible.

## Authentication variables

| Variable | Required | Description |
|---|---:|---|
| `AZURE_TENANT_ID` | Yes | Single Microsoft Entra tenant accepted by inbound JWT validation and Graph clients. |
| `AZURE_CLIENT_ID` | Yes | Client ID of the MCP resource/API app registration and confidential OBO client. |
| `ENTRA_MCP_AUDIENCE` | Yes | JWT audience, normally `api://<AZURE_CLIENT_ID>`. |
| `ENTRA_MCP_ISSUER` | Yes | Expected v2 issuer, normally `https://login.microsoftonline.com/<tenant>/v2.0`. |
| `ENTRA_MCP_USER_SCOPE` | No | Required delegated scope. Default: `Mcp.Access`. |
| `ENTRA_MCP_AGENT_ROLE` | No | Required base app role. Default: `Mcp.Invoke`. |
| `AZURE_CLIENT_SECRET` | Local OBO | Local confidential credential. Do not use as the Azure production default. |
| `AZURE_CLIENT_CERTIFICATE_PATH` | Production OBO | Certificate used by `OnBehalfOfCredential`; provision from Key Vault/secret volume. |
| `AZURE_MANAGED_IDENTITY_CLIENT_ID` | Azure agents | User-assigned identity used for autonomous Graph calls and Azure Managed Redis. |

Inbound actors:

- delegated user tokens must contain `Mcp.Access` in `scp`; Graph access uses OBO and remains bounded by both user and delegated app permissions;
- autonomous app tokens must contain `Mcp.Invoke` in `roles`; Advanced Hunting also requires `Mcp.Hunt`; agent governance requires `Mcp.AgentGovernance`;
- there is no API-key fallback and no automatic OBO-to-app-only fallback.

## Cache variables

| Variable | Default | Description |
|---|---|---|
| `CACHE_BACKEND` | `none` | `none`, `memory` (tests only), `redis`, or `azure-managed-redis`. |
| `REDIS_URL` | `redis://localhost:6379/0` | Local Redis URL. Compose uses `redis://redis:6379/0`. |
| `REDIS_KEY_PREFIX` | `defender-hunt` | Namespace prefix; values remain identity/permission isolated. |
| `REDIS_HOST` | None | Azure Managed Redis hostname. |
| `REDIS_PORT` | `10000` | Azure Managed Redis TLS port; Compose host port is also configurable. |
| `REDIS_ENTRA_USERNAME` | None | Managed-identity object/principal ID used as Redis Entra username. |

Local Compose runs the official Redis image with bounded memory, LRU eviction, no persistence, and a health check. Azure uses `redis-py` async credentials backed by `ManagedIdentityCredential` and scope `https://redis.azure.com/.default`.

## Feature and runtime variables

| Variable | Default | Description |
|---|---|---|
| `ENABLE_AGENT_GOVERNANCE_BETA` | `false` | Enables isolated Microsoft Graph beta Agent Identity tools. |
| `HOST` | `0.0.0.0` | HTTP bind address. |
| `PORT` | `8000` | HTTP listen port. |
| `MCP_PORT` | `8000` | Host port published by Compose. |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`, or `CRITICAL`. |
| `DEBUG` | `false` | Starlette debug mode; never enable in production. |
| `ALLOWED_ORIGINS` | Empty | Comma-separated browser origins. CORS middleware is disabled when empty. |

## Microsoft Graph permissions

Delegated permissions belong to the confidential MCP resource app and are used through OBO. Application permissions belong to the runtime managed identity and are used only for autonomous agents. Assign only permissions required by enabled tools.

Baseline families include:

- `ThreatHunting.Read.All` for Advanced Hunting;
- `SecurityEvents.Read.All` for alerts and Secure Score controls;
- `ThreatIntelligence.Read.All` for Defender Threat Intelligence;
- `AuditLog.Read.All` for sign-ins and directory audit logs;
- `IdentityRiskyUser.Read.All` for identity risk;
- `Policy.Read.All` for Conditional Access;
- directory/application read permissions for agent-governance role analysis, subject to tenant approval and beta API requirements.

Application roles for a managed identity are assigned to its service principal through Microsoft Graph. Bicep creates the identity; `deploy-full.ps1` can apply tenant-approved Graph app-role GUIDs after deployment.

## Public endpoints and health

- `GET /health` and `GET /info` are public.
- `/mcp` always requires a valid Entra bearer token.
- Health validates required configuration presence, not live JWT metadata, Graph consent, Redis connectivity, licensing, or KQL execution.
- `defender://capabilities` exposes stable/beta/disabled capabilities and operational limits to authenticated MCP clients.
