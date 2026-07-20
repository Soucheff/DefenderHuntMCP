targetScope = 'resourceGroup'

@description('Base name used for Azure resources.')
@minLength(3)
@maxLength(20)
param namePrefix string = 'defenderhuntmcp'

@description('Azure region for regional resources.')
param location string = resourceGroup().location

@description('Container image including registry host and immutable tag.')
param containerImage string

@description('Microsoft Entra tenant accepted by the MCP.')
param tenantId string = tenant().tenantId

@description('Client ID of the MCP resource/API app registration used for JWT audience and OBO.')
param mcpClientId string

@description('Issuer expected in inbound Entra access tokens.')
param mcpIssuer string = '${environment().authentication.loginEndpoint}${tenantId}/v2.0'

@description('Optional Redis data-plane role definition resource ID. Leave empty until the tenant-approved Azure Managed Redis role is selected.')
param redisDataRoleDefinitionId string = ''

@description('Minimum Container App replicas.')
@minValue(0)
@maxValue(10)
param minReplicas int = 1

@description('Maximum Container App replicas.')
@minValue(1)
@maxValue(30)
param maxReplicas int = 3

var normalizedPrefix = toLower(replace(namePrefix, '-', ''))
var registryName = take('${normalizedPrefix}${uniqueString(subscription().id, resourceGroup().id)}', 50)
var identityName = '${namePrefix}-runtime-mi'
var environmentName = '${namePrefix}-env'
var appName = '${namePrefix}-app'
var redisName = '${namePrefix}-redis'
var logsName = '${namePrefix}-logs'
var acrPullRoleDefinitionId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '7f951dda-4ed3-4680-a7ca-43fe172d538d'
)

resource runtimeIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: identityName
  location: location
}

resource registry 'Microsoft.ContainerRegistry/registries@2023-11-01-preview' = {
  name: registryName
  location: location
  sku: {
    name: 'Basic'
  }
  properties: {
    adminUserEnabled: false
    publicNetworkAccess: 'Enabled'
  }
}

resource acrPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(registry.id, runtimeIdentity.id, acrPullRoleDefinitionId)
  scope: registry
  properties: {
    principalId: runtimeIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: acrPullRoleDefinitionId
  }
}

resource logs 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: logsName
  location: location
  properties: {
    retentionInDays: 30
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
  }
}

resource managedEnvironment 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: environmentName
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logs.properties.customerId
        sharedKey: logs.listKeys().primarySharedKey
      }
    }
  }
}

resource managedRedis 'Microsoft.Cache/redisEnterprise@2025-05-01-preview' = {
  name: redisName
  location: location
  sku: {
    name: 'Balanced_B0'
  }
  properties: {
    highAvailability: 'Enabled'
  }
}

resource redisDatabase 'Microsoft.Cache/redisEnterprise/databases@2025-05-01-preview' = {
  parent: managedRedis
  name: 'default'
  properties: {
    clientProtocol: 'Encrypted'
    clusteringPolicy: 'OSSCluster'
    evictionPolicy: 'AllKeysLRU'
    persistence: {
      aofEnabled: false
      rdbEnabled: false
    }
  }
}

resource redisRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(redisDataRoleDefinitionId)) {
  name: guid(managedRedis.id, runtimeIdentity.id, redisDataRoleDefinitionId)
  scope: managedRedis
  properties: {
    principalId: runtimeIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: redisDataRoleDefinitionId
  }
}

resource containerApp 'Microsoft.App/containerApps@2024-03-01' = {
  name: appName
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${runtimeIdentity.id}': {}
    }
  }
  properties: {
    managedEnvironmentId: managedEnvironment.id
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: true
        targetPort: 8000
        transport: 'auto'
        allowInsecure: false
      }
      registries: [
        {
          server: registry.properties.loginServer
          identity: runtimeIdentity.id
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'defender-hunt-mcp'
          image: containerImage
          env: [
            {
              name: 'AZURE_TENANT_ID'
              value: tenantId
            }
            {
              name: 'AZURE_CLIENT_ID'
              value: mcpClientId
            }
            {
              name: 'ENTRA_MCP_AUDIENCE'
              value: 'api://${mcpClientId}'
            }
            {
              name: 'ENTRA_MCP_ISSUER'
              value: mcpIssuer
            }
            {
              name: 'AZURE_MANAGED_IDENTITY_CLIENT_ID'
              value: runtimeIdentity.properties.clientId
            }
            {
              name: 'CACHE_BACKEND'
              value: 'azure-managed-redis'
            }
            {
              name: 'REDIS_HOST'
              value: managedRedis.properties.hostName
            }
            {
              name: 'REDIS_PORT'
              value: '10000'
            }
            {
              name: 'REDIS_ENTRA_USERNAME'
              value: runtimeIdentity.properties.principalId
            }
            {
              name: 'ENABLE_AGENT_GOVERNANCE_BETA'
              value: 'false'
            }
            {
              name: 'PORT'
              value: '8000'
            }
          ]
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
          probes: [
            {
              type: 'Liveness'
              httpGet: {
                path: '/health'
                port: 8000
                scheme: 'HTTP'
              }
              initialDelaySeconds: 15
              periodSeconds: 30
            }
            {
              type: 'Readiness'
              httpGet: {
                path: '/health'
                port: 8000
                scheme: 'HTTP'
              }
              initialDelaySeconds: 5
              periodSeconds: 10
            }
          ]
        }
      ]
      scale: {
        minReplicas: minReplicas
        maxReplicas: maxReplicas
      }
    }
  }
  dependsOn: [
    acrPull
    redisDatabase
  ]
}

resource cacheWarmupJob 'Microsoft.App/jobs@2024-03-01' = {
  name: '${namePrefix}-cache-warmup'
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${runtimeIdentity.id}': {}
    }
  }
  properties: {
    environmentId: managedEnvironment.id
    configuration: {
      triggerType: 'Schedule'
      replicaTimeout: 600
      replicaRetryLimit: 1
      scheduleTriggerConfig: {
        cronExpression: '*/15 * * * *'
        parallelism: 1
        replicaCompletionCount: 1
      }
      registries: [
        {
          server: registry.properties.loginServer
          identity: runtimeIdentity.id
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'cache-warmup'
          image: containerImage
          command: [
            'python'
          ]
          args: [
            'cache_warmup.py'
          ]
          env: [
            {
              name: 'AZURE_TENANT_ID'
              value: tenantId
            }
            {
              name: 'AZURE_CLIENT_ID'
              value: mcpClientId
            }
            {
              name: 'AZURE_MANAGED_IDENTITY_CLIENT_ID'
              value: runtimeIdentity.properties.clientId
            }
            {
              name: 'AZURE_MANAGED_IDENTITY_PRINCIPAL_ID'
              value: runtimeIdentity.properties.principalId
            }
            {
              name: 'CACHE_BACKEND'
              value: 'azure-managed-redis'
            }
            {
              name: 'REDIS_HOST'
              value: managedRedis.properties.hostName
            }
            {
              name: 'REDIS_PORT'
              value: '10000'
            }
            {
              name: 'REDIS_ENTRA_USERNAME'
              value: runtimeIdentity.properties.principalId
            }
          ]
          resources: {
            cpu: json('0.25')
            memory: '0.5Gi'
          }
        }
      ]
    }
  }
  dependsOn: [
    acrPull
    redisDatabase
  ]
}

output containerAppName string = containerApp.name
output containerAppFqdn string = containerApp.properties.configuration.ingress.fqdn
output runtimeIdentityClientId string = runtimeIdentity.properties.clientId
output runtimeIdentityPrincipalId string = runtimeIdentity.properties.principalId
output registryName string = registry.name
output registryLoginServer string = registry.properties.loginServer
output managedRedisHost string = managedRedis.properties.hostName
output cacheWarmupJobName string = cacheWarmupJob.name
