<#
.SYNOPSIS
    Build, push to Azure Container Registry, and update an Azure Container App.

.DESCRIPTION
    This script builds the Docker image, pushes it to ACR, and updates
    an existing Container App revision with the new image. It does not
    provision infrastructure or change application environment variables,
    ingress, secrets, scaling, or registry authentication.

    Prerequisites: PowerShell 7+, Azure CLI authenticated with az login,
    Docker, an existing ACR, and an existing Azure Container App.

.PARAMETER AcrName
    The name of your Azure Container Registry (e.g. "myacr", not the full .azurecr.io address).

.PARAMETER AppName
    The name of the Azure Container App.

.PARAMETER ResourceGroup
    The Azure resource group containing the Container App.

.PARAMETER ImageTag
    Optional image tag. Defaults to a local-time timestamp (yyyyMMdd-HHmmss).

.EXAMPLE
    .\deploy.ps1 -AcrName myacr -AppName defenderhuntmcp-app -ResourceGroup rg-defenderhuntmcp

    Builds two tags (the timestamp and latest), pushes both, and updates the
    existing Container App to the immutable timestamp tag.

.NOTES
    The script relies on the Container App's existing registry credentials or
    managed identity. It does not configure MCP_API_KEY or Microsoft Graph
    credentials. Use deploy-full.ps1 for initial evaluation infrastructure,
    then apply the production hardening documented in docs/deployment.md.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$AcrName,
    [Parameter(Mandatory)][string]$AppName,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [string]$ImageTag = (Get-Date -Format "yyyyMMdd-HHmmss")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ImageName   = "defender-hunt-mcp"
$FullImage   = "$AcrName.azurecr.io/${ImageName}:${ImageTag}"
$LatestImage = "$AcrName.azurecr.io/${ImageName}:latest"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host " Defender Hunt MCP - Build & Deploy to Azure"  -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  ACR:            $AcrName.azurecr.io"
Write-Host "  Image:          $FullImage"
Write-Host "  Container App:  $AppName"
Write-Host "  Resource Group: $ResourceGroup"
Write-Host ""

# --- 1. Login to ACR --------------------------------------------------
Write-Host "[1/4] Logging in to ACR..." -ForegroundColor Yellow
az acr login --name $AcrName
if ($LASTEXITCODE -ne 0) { throw "ACR login failed." }

# --- 2. Build the Docker image ----------------------------------------
Write-Host "[2/4] Building Docker image..." -ForegroundColor Yellow
docker build -t $FullImage -t $LatestImage .
if ($LASTEXITCODE -ne 0) { throw "Docker build failed." }

# --- 3. Push to ACR ---------------------------------------------------
Write-Host "[3/4] Pushing image to ACR..." -ForegroundColor Yellow
docker push $FullImage
docker push $LatestImage
if ($LASTEXITCODE -ne 0) { throw "Docker push failed." }

# --- 4. Update the Container App with the new image -------------------
Write-Host "[4/4] Updating Container App..." -ForegroundColor Yellow
az containerapp update `
    --name $AppName `
    --resource-group $ResourceGroup `
    --image $FullImage
if ($LASTEXITCODE -ne 0) { throw "Container App update failed." }

Write-Host ""
Write-Host "Deploy complete!  Image: $FullImage" -ForegroundColor Green
Write-Host "Container App '$AppName' is now running the new revision." -ForegroundColor Green
