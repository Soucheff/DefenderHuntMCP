# Configuration

Defender Hunt MCP is single-tenant and accepts Microsoft Entra bearer access tokens only. `python-dotenv` loads `.env` for local development; Azure Container Apps receives non-secret settings from Bicep and uses managed identities wherever possible.

## Authentication variables

| Variable | Required | Description |
|---|---:|---|
| `AZURE_TENANT_ID` | Yes | Single Microsoft Entra tenant accepted by inbound JWT validation and Graph clients. |
| `AZURE_CLIENT_ID` | Yes | Client ID of the MCP resource/API app registration and confidential OBO client. |
| `ENTRA_MCP_AUDIENCE` | Yes | JWT audience. With `requestedAccessTokenVersion=2`, use the MCP app client ID GUID. Clients still request the exposed scope as `api://<client-id>/<scope>`. |
| `ENTRA_MCP_ISSUER` | Yes | Expected v2 issuer, normally `https://login.microsoftonline.com/<tenant>/v2.0`. |
| `ENTRA_MCP_USER_SCOPE` | No | Required delegated scope. Default: `Mcp.Access`. |
| `ENTRA_MCP_AGENT_ROLE` | No | Required base app role. Default: `Mcp.Invoke`. |
| `ENTRA_AGENT_CLIENT_IDS` | Agent ID | Comma-separated allowlist of Entra Agent Identity client IDs. Required to distinguish delegated agents from ordinary delegated clients without relying on undocumented preview claims. |
| `AZURE_CLIENT_SECRET` | Local OBO | Local confidential credential. Do not use as the Azure production default. |
| `AZURE_CLIENT_CERTIFICATE_PATH` | Production OBO | Certificate used by `OnBehalfOfCredential`; provision from Key Vault/secret volume. |
| `AZURE_MANAGED_IDENTITY_CLIENT_ID` | Azure | User-assigned identity used for Azure Managed Redis, ACR/Key Vault access, and the temporary legacy app-caller Graph path. |

Inbound actors:

- delegated user tokens must contain `Mcp.Access` in `scp`; Graph access uses standard OBO;
- delegated Agent ID tokens are acquired by the agent workload for the MCP audience, contain the required user scope, and have a client ID in `ENTRA_AGENT_CLIENT_IDS`; the MCP validates that token and uses its assertion in the standard downstream Graph OBO flow;
- autonomous Agent ID tokens are acquired by the agent workload for the MCP audience, contain `Mcp.Invoke` in `roles`, and have a client ID in `ENTRA_AGENT_CLIENT_IDS`; the MCP validates the caller and uses its runtime Managed Identity for downstream app-only Graph access;
- unknown application callers with valid MCP roles use the same Managed Identity downstream route during migration;
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

Delegated permissions belong to the MCP confidential client and are used for ordinary users and delegated Agent IDs through OBO. Application permissions for autonomous Graph operations belong to the MCP runtime Managed Identity. Agent Identities receive MCP application roles, not Graph permissions, unless the agent calls Graph directly outside the MCP. Assign only permissions required by enabled tools.

Baseline families include:

- `ThreatHunting.Read.All` for Advanced Hunting;
- `SecurityEvents.Read.All` for alerts and Secure Score controls;
- `ThreatIntelligence.Read.All` for Defender Threat Intelligence;
- `AuditLog.Read.All` for sign-ins and directory audit logs;
- `IdentityRiskyUser.Read.All` for identity risk;
- `Policy.Read.All` for Conditional Access;
- `RoleManagement.Read.Directory` for active directory-role assignments;
- `RoleEligibilitySchedule.Read.Directory` for PIM eligibility reads;
- `Group.Read.All` for group inventory and full group properties;
- `GroupMember.Read.All` for owners and direct/transitive membership;
- `Member.Read.Hidden` only when hidden-membership groups must be analyzed;
- `User.Read.All` for user profiles and organizational relationships;
- `LicenseAssignment.Read.All` for license details where a broader approved permission is absent;
- `UserAuthenticationMethod.Read.All` for another user's authentication methods;
- `RoleAssignmentSchedule.Read.Directory` for PIM activation history;
- `SecurityAlert.Read.All` for Defender XDR identity-alert correlation;
- `Application.Read.All` for app-role resource resolution and OAuth grant review;
- `DelegatedPermissionGrant.Read.All` for delegated OAuth2 permission grants;
- directory/application read permissions for agent-governance role analysis, subject to tenant approval and beta API requirements.

MCP application roles are assigned to each autonomous Agent Identity service principal. Graph application roles required by MCP tools are assigned to the runtime Managed Identity through `deploy-full.ps1`.

For delegated OBO calls, Graph evaluates both the application's delegated consent and the signed-in user's Entra privileges. Directory-role reads support Directory Readers, Global Reader, or Privileged Role Administrator for active assignments; PIM eligibility and group reads have their own supported-role requirements. A token containing the MCP app role `Mcp.Invoke` does not grant Microsoft Graph directory-role visibility.

## Public endpoints and health

- `GET /health` and `GET /info` are public.
- `/mcp` always requires a valid Entra bearer token.
- Health validates required configuration presence, not live JWT metadata, Graph consent, Redis connectivity, licensing, or KQL execution.
- `defender://capabilities` exposes stable/beta/disabled capabilities and operational limits to authenticated MCP clients.
