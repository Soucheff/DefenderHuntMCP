<#
.SYNOPSIS
    Provision Azure infrastructure and deploy Defender Hunt MCP.

.DESCRIPTION
    End-to-end script that:
      1. Creates a Resource Group
      2. Creates an Azure Container Registry (ACR)
      3. Creates a Container App Environment + Log Analytics workspace
      4. Builds and pushes the Docker image to ACR
      5. Creates or updates the Container App with environment variables
      6. Outputs the live FQDN

    Re-running reuses the first ACR and Container Apps environment discovered
    in the resource group and updates the named Container App when it exists.

    This script is intended for controlled evaluation. It enables the ACR
    administrative account, configures external ingress, and passes application
    secrets as Container App environment values. Review docs/deployment.md and
    docs/security.md before adapting it for production.

    Prerequisites: PowerShell 7+, Azure CLI authenticated with az login,
    Docker, and permission to manage the target Azure subscription/resources.

.PARAMETER AppName
    Base name for all resources (lowercase, no special chars). Default: "defenderhuntmcp"

.PARAMETER Location
    Azure region. Default: "eastus"

.PARAMETER MCP_API_KEY
    API key clients must send in X-API-Key / Authorization: Bearer headers.
    If omitted, the externally reachable MCP endpoint starts without
    authentication. Always provide a long random value outside isolated testing.

.PARAMETER AZURE_TENANT_ID
    Microsoft Entra ID (Azure AD) Tenant ID for Microsoft Graph access.

.PARAMETER AZURE_CLIENT_ID
    App registration Client ID for Microsoft Graph access.

.PARAMETER AZURE_CLIENT_SECRET
    App registration Client Secret for Microsoft Graph access. The script
    currently supplies it as a Container App environment value.

.PARAMETER ImageTag
    Docker image tag. Defaults to a local-time timestamp (yyyyMMdd-HHmmss).

.PARAMETER SkipInfra
    If set, skip infrastructure provisioning, discover existing resources in
    the derived resource group, and build/push/deploy the image. Pass credential
    parameters again when environment values must be created or updated.

.EXAMPLE
    # Full provision + deploy
    .\deploy-full.ps1 `
        -AppName defenderhuntmcp `
        -Location eastus `
        -MCP_API_KEY "my-secret-api-key" `
        -AZURE_TENANT_ID "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -AZURE_CLIENT_ID "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -AZURE_CLIENT_SECRET "your-client-secret"

.EXAMPLE
    # Re-deploy only (infra already exists)
    .\deploy-full.ps1 -AppName defenderhuntmcp -SkipInfra

.NOTES
    The application uses stateless Streamable HTTP and can scale horizontally.
    The health endpoint validates configuration presence only; it does not test
    Microsoft Graph connectivity, admin consent, licensing, or query execution.
#>

[CmdletBinding()]
param(
    [string]$AppName        = "defenderhuntmcp",
    [string]$Location       = "eastus",
    [string]$MCP_API_KEY    = "",
    [string]$AZURE_TENANT_ID    = "",
    [string]$AZURE_CLIENT_ID    = "",
    [string]$AZURE_CLIENT_SECRET = "",
    [string]$ImageTag       = (Get-Date -Format "yyyyMMdd-HHmmss"),
    [switch]$SkipInfra
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Derive resource names from AppName
# ---------------------------------------------------------------------------
$suffix         = -join ((0..7) | ForEach-Object { [char](Get-Random -Minimum 97 -Maximum 123) })
$ResourceGroup  = "rg-$AppName"
$AcrName        = "acr$AppName$suffix".Replace("-", "").ToLower()
$EnvName        = "$AppName-env"
$ContainerApp   = "$AppName-app"
$LogAnalytics   = "$AppName-logs"
$ImageName      = "defender-hunt-mcp"


# Check if resources already exist and reuse names
function Get-ExistingAcr {
    $existing = az acr list --resource-group $ResourceGroup --query "[0].name" -o tsv 2>$null
    if ($LASTEXITCODE -eq 0 -and $existing) { return $existing }
    return $null
}

function Get-ExistingEnv {
    $existing = az containerapp env list --resource-group $ResourceGroup --query "[0].name" -o tsv 2>$null
    if ($LASTEXITCODE -eq 0 -and $existing) { return $existing }
    return $null
}

function Get-ExistingApp {
    $existing = az containerapp list --resource-group $ResourceGroup --query "[?name=='$ContainerApp'].name" -o tsv 2>$null
    if ($LASTEXITCODE -eq 0 -and $existing) { return $existing }
    return $null
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Defender Hunt MCP - Full Azure Deployment"                        -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  App Name:       $AppName"
Write-Host "  Location:       $Location"
Write-Host "  Resource Group: $ResourceGroup"
Write-Host "  Auth Enabled:   $([bool]$MCP_API_KEY)"
Write-Host ""

# ---------------------------------------------------------------------------
# Pre-flight: check required CLIs
# ---------------------------------------------------------------------------
Write-Host "[Pre-flight] Checking required tools..." -ForegroundColor Yellow
foreach ($cmd in @("az", "docker")) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        throw "Required tool '$cmd' is not installed or not in PATH."
    }
}
# Ensure logged in
$account = az account show -o json 2>$null | ConvertFrom-Json
if (-not $account) { throw "Not logged in to Azure. Run 'az login' first." }
Write-Host "  Signed in as: $($account.user.name) (subscription: $($account.name))" -ForegroundColor Gray

# ===================================================================
# INFRASTRUCTURE PROVISIONING
# ===================================================================
if (-not $SkipInfra) {
    # --- 1. Resource Group ------------------------------------------------
    Write-Host ""
    Write-Host "[1/5] Resource Group: $ResourceGroup" -ForegroundColor Yellow
    $rgExists = az group exists --name $ResourceGroup -o tsv
    if ($rgExists -eq "true") {
        Write-Host "  Already exists — skipping." -ForegroundColor Gray
    } else {
        az group create --name $ResourceGroup --location $Location -o none
        Write-Host "  Created." -ForegroundColor Green
    }

    # --- 2. Azure Container Registry --------------------------------------
    Write-Host "[2/5] Azure Container Registry" -ForegroundColor Yellow
    $existingAcr = Get-ExistingAcr
    if ($existingAcr) {
        $AcrName = $existingAcr
        Write-Host "  Reusing existing ACR: $AcrName" -ForegroundColor Gray
    } else {
        Write-Host "  Creating ACR: $AcrName ..."
        az acr create `
            --resource-group $ResourceGroup `
            --name $AcrName `
            --sku Basic `
            --admin-enabled true `
            --location $Location `
            -o none
        Write-Host "  Created: $AcrName" -ForegroundColor Green
    }

    # --- 3. Log Analytics Workspace ----------------------------------------
    Write-Host "[3/5] Log Analytics Workspace: $LogAnalytics" -ForegroundColor Yellow
    $laExists = az monitor log-analytics workspace show `
        --resource-group $ResourceGroup `
        --workspace-name $LogAnalytics `
        -o tsv --query "name" 2>$null
    if ($laExists) {
        Write-Host "  Already exists — skipping." -ForegroundColor Gray
    } else {
        az monitor log-analytics workspace create `
            --resource-group $ResourceGroup `
            --workspace-name $LogAnalytics `
            --location $Location `
            -o none
        Write-Host "  Created." -ForegroundColor Green
    }

    $LOG_ID  = az monitor log-analytics workspace show `
        --resource-group $ResourceGroup `
        --workspace-name $LogAnalytics `
        --query "customerId" -o tsv
    $LOG_KEY = az monitor log-analytics workspace get-shared-keys `
        --resource-group $ResourceGroup `
        --workspace-name $LogAnalytics `
        --query "primarySharedKey" -o tsv

    # --- 4. Container App Environment -------------------------------------
    Write-Host "[4/5] Container App Environment: $EnvName" -ForegroundColor Yellow
    $existingEnv = Get-ExistingEnv
    if ($existingEnv) {
        $EnvName = $existingEnv
        Write-Host "  Reusing existing environment: $EnvName" -ForegroundColor Gray
    } else {
        az containerapp env create `
            --resource-group $ResourceGroup `
            --name $EnvName `
            --location $Location `
            --logs-workspace-id $LOG_ID `
            --logs-workspace-key $LOG_KEY `
            -o none
        Write-Host "  Created." -ForegroundColor Green
    }

    # --- 5. Grant Container App Environment access to ACR ------------------
    Write-Host "[5/5] Configuring ACR access..." -ForegroundColor Yellow
    $acrLoginServer = az acr show --name $AcrName --query "loginServer" -o tsv
    $acrUsername = az acr credential show --name $AcrName --query "username" -o tsv
    $acrPassword = az acr credential show --name $AcrName --query "passwords[0].value" -o tsv
    Write-Host "  ACR Login Server: $acrLoginServer" -ForegroundColor Gray

} else {
    Write-Host "[SkipInfra] Skipping infrastructure provisioning." -ForegroundColor Gray
    # Discover existing resources
    $existingAcr = Get-ExistingAcr
    if ($existingAcr) { $AcrName = $existingAcr }
    $existingEnv = Get-ExistingEnv
    if ($existingEnv) { $EnvName = $existingEnv }
    $acrLoginServer = az acr show --name $AcrName --query "loginServer" -o tsv
    $acrUsername = az acr credential show --name $AcrName --query "username" -o tsv
    $acrPassword = az acr credential show --name $AcrName --query "passwords[0].value" -o tsv
}

# ===================================================================
# BUILD & PUSH DOCKER IMAGE
# ===================================================================
$FullImage   = "$acrLoginServer/${ImageName}:${ImageTag}"
$LatestImage = "$acrLoginServer/${ImageName}:latest"

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Building & Pushing Docker Image"                                -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Image: $FullImage"
Write-Host ""

Write-Host "[Build] Logging in to ACR..." -ForegroundColor Yellow
az acr login --name $AcrName
if ($LASTEXITCODE -ne 0) { throw "ACR login failed." }

Write-Host "[Build] Building Docker image..." -ForegroundColor Yellow
docker build -t $FullImage -t $LatestImage .
if ($LASTEXITCODE -ne 0) { throw "Docker build failed." }

Write-Host "[Build] Pushing to ACR..." -ForegroundColor Yellow
docker push $FullImage
if ($LASTEXITCODE -ne 0) { throw "Docker push (tagged) failed." }
docker push $LatestImage
if ($LASTEXITCODE -ne 0) { throw "Docker push (latest) failed." }

# ===================================================================
# CREATE / UPDATE CONTAINER APP
# ===================================================================
Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Deploying Container App"                                        -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

# Build environment variables list
$envVars = @(
    "PORT=8000",
    "LOG_LEVEL=INFO"
)
if ($AZURE_TENANT_ID)    { $envVars += "AZURE_TENANT_ID=$AZURE_TENANT_ID" }
if ($AZURE_CLIENT_ID)    { $envVars += "AZURE_CLIENT_ID=$AZURE_CLIENT_ID" }
if ($AZURE_CLIENT_SECRET){ $envVars += "AZURE_CLIENT_SECRET=$AZURE_CLIENT_SECRET" }
if ($MCP_API_KEY)         { $envVars += "MCP_API_KEY=$MCP_API_KEY" }

$existingApp = Get-ExistingApp
if ($existingApp) {
    Write-Host "[Deploy] Updating existing Container App: $ContainerApp ..." -ForegroundColor Yellow
    az containerapp update `
        --name $ContainerApp `
        --resource-group $ResourceGroup `
        --image $FullImage `
        --set-env-vars @envVars
    if ($LASTEXITCODE -ne 0) { throw "Container App update failed." }
} else {
    Write-Host "[Deploy] Creating Container App: $ContainerApp ..." -ForegroundColor Yellow
    az containerapp create `
        --name $ContainerApp `
        --resource-group $ResourceGroup `
        --environment $EnvName `
        --image $FullImage `
        --registry-server $acrLoginServer `
        --registry-username $acrUsername `
        --registry-password $acrPassword `
        --target-port 8000 `
        --ingress external `
        --min-replicas 0 `
        --max-replicas 3 `
        --cpu 0.5 `
        --memory 1.0Gi `
        --env-vars @envVars `
        --query "properties.configuration.ingress.fqdn" `
        -o tsv
    if ($LASTEXITCODE -ne 0) { throw "Container App creation failed." }
}

# ===================================================================
# OUTPUT
# ===================================================================
$fqdn = az containerapp show `
    --name $ContainerApp `
    --resource-group $ResourceGroup `
    --query "properties.configuration.ingress.fqdn" `
    -o tsv

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  Deployment Complete!"                                           -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  App URL:        https://$fqdn"                                  -ForegroundColor White
Write-Host "  MCP Endpoint:   https://$fqdn/mcp"                             -ForegroundColor White
Write-Host "  Health Check:   https://$fqdn/health"                           -ForegroundColor White
Write-Host "  Server Info:    https://$fqdn/info"                             -ForegroundColor White
Write-Host ""
Write-Host "  Resource Group: $ResourceGroup"
Write-Host "  ACR:            $AcrName"
Write-Host "  Container App:  $ContainerApp"
Write-Host "  Image:          $FullImage"
Write-Host ""

if ($MCP_API_KEY) {
    Write-Host "  Auth:           Enabled (X-API-Key header required)"         -ForegroundColor Yellow
} else {
    Write-Host "  Auth:           DISABLED (set -MCP_API_KEY to secure)"       -ForegroundColor Red
}

Write-Host ""
Write-Host "  To test:"
Write-Host "    curl https://$fqdn/health"
if ($MCP_API_KEY) {
    Write-Host "    curl -H 'X-API-Key: <key>' -X POST https://$fqdn/mcp"
} else {
    Write-Host "    curl -X POST https://$fqdn/mcp"
}
Write-Host ""
