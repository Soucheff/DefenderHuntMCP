# Deployment

## Local Docker Compose

Create `.env`, replace placeholders, and start the MCP plus official Redis image:

```bash
cp .env.example .env
docker compose up --build -d
docker compose ps
curl --fail http://localhost:8000/health
```

Compose applies a read-only root filesystem, drops Linux capabilities, enables `no-new-privileges`, provides bounded tmpfs storage, and waits for Redis health. Redis is development-only data: no persistence, 256 MiB max memory, and `allkeys-lru` eviction.

Use a real Entra access token issued for `ENTRA_MCP_AUDIENCE` when calling `/mcp`.

## Azure architecture

`infra/main.bicep` provisions:

- user-assigned managed identity;
- ACR with admin credentials disabled and identity-based `AcrPull`;
- Log Analytics and Container Apps environment;
- Azure Managed Redis and encrypted database;
- identity-based Redis role assignment when an approved role definition ID is supplied;
- Container App with external TLS ingress, health probes, Entra settings, and Managed Identity.

The runtime identity has independent least-privilege uses:

1. pull images from ACR through `AcrPull`;
2. authenticate passwordlessly to Azure Managed Redis;
3. acquire app-only Microsoft Graph tokens for autonomous Agent ID and other approved application calls.

The Agent ID sidecar, when used, runs with the calling agent and acquires a token for the MCP audience. The MCP validates that inbound token. Ordinary users and delegated Agent IDs then use standard downstream OBO; autonomous Agent IDs use the MCP runtime Managed Identity for downstream Graph access. OBO never falls back automatically to app-only access.

## Deploy

Prerequisites:

- PowerShell 7+
- Azure CLI with Bicep and `az login`
- permission to deploy the resource group and assign roles
- MCP resource/API app registration with `Mcp.Access`, `Mcp.Invoke`, `Mcp.Hunt`, and `Mcp.AgentGovernance` as applicable
- tenant-approved delegated Graph permissions, runtime Managed Identity Graph application permissions, and MCP roles assigned to Agent Identities

```powershell
./deploy-full.ps1 `
  -TenantId '<tenant-id>' `
  -McpClientId '<mcp-resource-app-client-id>' `
  -GraphAppRoleIds @('<ThreatHunting.Read.All-role-id>')
```

The script deploys a bootstrap image, builds the immutable application image through ACR, updates the Container App, and can assign temporary Graph app roles to the runtime identity for legacy callers. It never enables the ACR admin account.

`deploy.ps1` remains a thin rollout script for existing resources.

## Production completion checklist

The checked-in Bicep compiles locally, but tenant deployment still requires environment-specific completion and live validation:

- approve the exact Azure Managed Redis data-plane role and pass its full role definition ID;
- add Private Endpoint, private DNS, and VNet integration for Redis before production traffic;
- provision the OBO certificate in Key Vault and grant the runtime identity least-privilege read access without exposing secret material;
- configure `agentClientIds` after the approved Agent Identities exist and assign each identity only the required MCP app roles;
- approve delegated Graph permissions for MCP OBO and assign autonomous Graph application permissions to the runtime Managed Identity;
- enable Agent Identity beta only in a test tenant before production;
- configure diagnostic settings, authentication/429/cache alerts, budgets, revision traffic, rollback, and SLOs;
- execute live user OBO, delegated Agent ID OBO, autonomous Agent ID through Managed Identity, Redis token refresh, claims-challenge, and revocation tests.

## Cache warm-up

A future Container Apps Job should warm only tenant-stable data: Conditional Access, Secure Score control profiles, threat-intelligence metadata, approved mirrored feeds, and agent inventory/permission catalogs. Do not warm user-specific sign-ins, risky users/sign-ins, alerts, incident evidence, raw hunting results, or arbitrary KQL.
