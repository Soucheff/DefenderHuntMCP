<#
.SYNOPSIS
    Deploy Defender Hunt MCP infrastructure and image to Azure Container Apps.

.DESCRIPTION
    Creates the resource group, deploys Bicep-managed infrastructure with a
    user-assigned managed identity, builds/pushes the image through ACR, and
    updates the Container App to an immutable image tag.

    The managed identity is used for ACR pull, Azure resource access, and
    Microsoft Graph application calls. Approved Agent Identities authenticate
    before calling the MCP. The script never enables the ACR admin account and
    does not accept an MCP API key.

.PARAMETER NamePrefix
    Lowercase resource prefix. Default: defenderhuntmcp.

.PARAMETER Location
    Azure region. Default: eastus.

.PARAMETER TenantId
    Single Microsoft Entra tenant accepted by the MCP.

.PARAMETER McpClientId
    Client ID of the MCP resource/API app registration.

.PARAMETER ImageTag
    Immutable image tag. Defaults to local timestamp yyyyMMdd-HHmmss.

.PARAMETER RedisDataRoleDefinitionId
    Optional full role definition resource ID approved for Azure Managed Redis
    data access. When omitted, deploy infrastructure first and assign the
    product-specific Redis data role before enabling production traffic.

.PARAMETER GraphAppRoleIds
    Microsoft Graph application role GUIDs to assign to the runtime managed
    identity for legacy callers during migration. Admin privileges are required.

.PARAMETER AgentClientIds
    Approved Microsoft Entra Agent Identity client IDs.

.EXAMPLE
    ./deploy-full.ps1 `
      -TenantId '<tenant-id>' `
      -McpClientId '<mcp-resource-app-client-id>' `
      -GraphAppRoleIds @('<ThreatHunting.Read.All-role-id>')
#>

[CmdletBinding()]
param(
    [string]$NamePrefix = "defenderhuntmcp",
    [string]$Location = "eastus",
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$McpClientId,
    [string]$ImageTag = (Get-Date -Format "yyyyMMdd-HHmmss"),
    [string]$RedisDataRoleDefinitionId = "",
    [string[]]$GraphAppRoleIds = @(),
    [string[]]$AgentClientIds = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

foreach ($command in @("az", "docker")) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "Required command '$command' is not installed."
    }
}

$account = az account show -o json 2>$null | ConvertFrom-Json
if (-not $account) { throw "Not logged in to Azure. Run 'az login'." }

$resourceGroup = "rg-$NamePrefix"
$deploymentName = "$NamePrefix-infra"
$bootstrapImage = "mcr.microsoft.com/azuredocs/containerapps-helloworld:latest"
$agentClientIdsValue = $AgentClientIds -join ","

az group create --name $resourceGroup --location $Location -o none
if ($LASTEXITCODE -ne 0) { throw "Resource group deployment failed." }

$deployment = az deployment group create `
    --name $deploymentName `
    --resource-group $resourceGroup `
    --template-file infra/main.bicep `
    --parameters `
        namePrefix=$NamePrefix `
        location=$Location `
        containerImage=$bootstrapImage `
        tenantId=$TenantId `
        mcpClientId=$McpClientId `
        agentClientIds=$agentClientIdsValue `
        redisDataRoleDefinitionId=$RedisDataRoleDefinitionId `
    -o json | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw "Bicep deployment failed." }

$outputs = $deployment.properties.outputs
$registryName = $outputs.registryName.value
$registryServer = $outputs.registryLoginServer.value
$containerAppName = $outputs.containerAppName.value
$cacheWarmupJobName = $outputs.cacheWarmupJobName.value
$runtimePrincipalId = $outputs.runtimeIdentityPrincipalId.value
$image = "$registryServer/defender-hunt-mcp:$ImageTag"

az acr build --registry $registryName --image "defender-hunt-mcp:$ImageTag" .
if ($LASTEXITCODE -ne 0) { throw "ACR build failed." }

az containerapp update `
    --name $containerAppName `
    --resource-group $resourceGroup `
    --image $image `
    -o none
if ($LASTEXITCODE -ne 0) { throw "Container App update failed." }

az containerapp job update `
    --name $cacheWarmupJobName `
    --resource-group $resourceGroup `
    --image $image `
    -o none
if ($LASTEXITCODE -ne 0) { throw "Cache warm-up Job update failed." }

$graphServicePrincipalId = az ad sp show `
    --id "00000003-0000-0000-c000-000000000000" `
    --query id -o tsv
foreach ($appRoleId in $GraphAppRoleIds) {
    $body = @{
        principalId = $runtimePrincipalId
        resourceId = $graphServicePrincipalId
        appRoleId = $appRoleId
    } | ConvertTo-Json -Compress
    az rest `
        --method POST `
        --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$runtimePrincipalId/appRoleAssignments" `
        --headers "Content-Type=application/json" `
        --body $body `
        --output none
    if ($LASTEXITCODE -ne 0) {
        throw "Graph app-role assignment failed for role $appRoleId."
    }
}

$fqdn = az containerapp show `
    --name $containerAppName `
    --resource-group $resourceGroup `
    --query properties.configuration.ingress.fqdn -o tsv

Write-Host "Deployment complete" -ForegroundColor Green
Write-Host "MCP endpoint: https://$fqdn/mcp"
Write-Host "Health:      https://$fqdn/health"
Write-Host "Identity:    $runtimePrincipalId"
Write-Host "Image:       $image"
