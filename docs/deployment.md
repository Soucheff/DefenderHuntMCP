# Deployment

## Local Docker Compose

Create `.env`, replace all placeholders, and start the service:

```bash
cp .env.example .env
docker compose up --build -d
docker compose ps
curl --fail http://localhost:8000/health
```

`compose.yaml` applies these runtime controls:

- read-only root filesystem;
- all Linux capabilities dropped;
- `no-new-privileges` enabled;
- writable `/tmp` provided as a 16 MiB `tmpfs`;
- init process enabled;
- restart policy `unless-stopped`.

Change only the published host port with `MCP_PORT`:

```bash
MCP_PORT=8080 docker compose up --build -d
```

Stop and remove the service:

```bash
docker compose down
```

## Direct Docker execution

```bash
docker build -t defender-hunt-mcp:local .
docker run --rm --name defender-hunt-mcp \
  --env-file .env \
  --read-only \
  --tmpfs /tmp:size=16m,mode=1777 \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  -p 8000:8000 \
  defender-hunt-mcp:local
```

The multi-stage image uses Python 3.12 slim and a pinned `uv` binary. Dependencies are installed with `uv sync --frozen --no-dev`; development tools and `uv` are not copied into the runtime image. The process runs as the unprivileged `app` user.

## Azure Container Apps

Two PowerShell scripts are provided:

- `deploy-full.ps1` provisions a resource group, ACR, Log Analytics workspace, Container Apps environment, then creates or updates the app.
- `deploy.ps1` builds and pushes a new image, then updates an existing Container App.

Prerequisites:

- PowerShell 7+
- Azure CLI authenticated with `az login`
- Docker Desktop/Engine
- permissions to manage the target subscription/resource group

Full deployment example:

```powershell
./deploy-full.ps1 `
  -AppName defenderhuntmcp `
  -Location eastus `
  -MCP_API_KEY '<long-random-key>' `
  -AZURE_TENANT_ID '<tenant-id>' `
  -AZURE_CLIENT_ID '<client-id>' `
  -AZURE_CLIENT_SECRET '<client-secret>'
```

Redeploy into resources discovered in the existing resource group:

```powershell
./deploy-full.ps1 -AppName defenderhuntmcp -SkipInfra
```

Update an explicitly named existing app/registry:

```powershell
./deploy.ps1 `
  -AcrName myacr `
  -AppName defenderhuntmcp-app `
  -ResourceGroup rg-defenderhuntmcp
```

## Current Azure script security model

The provisioning script currently:

- creates external ingress;
- allows scale-to-zero with zero to three replicas;
- enables the ACR administrative account and supplies registry username/password;
- passes Graph credentials and the MCP API key as Container App environment values;
- permits deployment without `MCP_API_KEY`.

These defaults are suitable for controlled evaluation, not a hardened production deployment. Before production use:

1. Require authentication and refuse startup/deployment without `MCP_API_KEY`, or replace shared-key authentication with Entra ID token validation.
2. Store secrets as Container Apps secrets or Azure Key Vault references.
3. Use a managed identity with `AcrPull` instead of ACR admin credentials.
4. Prefer workload identity/managed identity for Microsoft Graph where supported; otherwise rotate the client secret and scope it narrowly.
5. Configure IP restrictions, private networking, API Management, or another trusted ingress boundary.
6. Add rate limiting, monitoring alerts, and an explicit minimum replica/SLO decision.
7. Configure revision traffic and rollback policy for production releases.

The MCP transport is configured as stateless HTTP, so it can scale horizontally without session affinity.

## Verification

After deployment:

```bash
curl --fail https://<fqdn>/health
curl --fail https://<fqdn>/info
```

For `/mcp`, send `X-API-Key` or a bearer value matching `MCP_API_KEY`. A bare POST should return HTTP `401` when authentication is enabled.

The health endpoint verifies only that required environment values are present. It does not prove that Microsoft Graph credentials, consent, licenses, or network access are valid; execute a low-impact tool call as a separate dependency check.
