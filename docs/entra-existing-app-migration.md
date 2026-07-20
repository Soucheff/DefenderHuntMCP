# Existing Entra app migration

This guide applies to the existing single-tenant app registration:

- display name: `MCPServer-Defender`
- application/client ID: `2378e46b-853c-4079-bf4b-95eafc7ca333`
- identifier URI: `api://2378e46b-853c-4079-bf4b-95eafc7ca333`
- requested access token version: `2`

The app can be reused for Defender Hunt MCP 3.0. Keep its application/client ID and identifier URI. Transform it into the MCP resource API and confidential OBO client; move autonomous Graph application permissions to the Container Apps runtime Managed Identity. Agent Identities receive MCP roles and obtain tokens for the MCP audience from their own workloads.

## Immediate credential action

Two password credentials expire on **2026-07-22** and the remaining credential expires on **2026-08-26**. Add and test a certificate credential before removing the passwords. Production OBO should use the certificate through Key Vault rather than create another long-lived client secret.

Do not place certificate private material or secret values in the manifest, repository, Container App environment variables, or deployment output.

## Inbound MCP audience and scope

Because `requestedAccessTokenVersion` is `2`, configure:

```dotenv
AZURE_TENANT_ID=<tenant-id>
AZURE_CLIENT_ID=2378e46b-853c-4079-bf4b-95eafc7ca333
ENTRA_MCP_AUDIENCE=2378e46b-853c-4079-bf4b-95eafc7ca333
ENTRA_MCP_ISSUER=https://login.microsoftonline.com/<tenant-id>/v2.0
```

Clients request an access token for an exposed scope such as:

```text
api://2378e46b-853c-4079-bf4b-95eafc7ca333/access_as_user
```

The resulting v2 access token is validated with the client ID GUID in `aud`.

The existing app exposes both `access_as_user` and `user_impersonation`. Use one canonical scope. For a no-break migration, keep `access_as_user` enabled and configure:

```dotenv
ENTRA_MCP_USER_SCOPE=access_as_user
```

After all clients migrate, disable the unused scope first, wait through the compatibility window, and remove it in a later change. Renaming an exposed scope breaks clients that request the old scope.

## Autonomous caller app roles

The current manifest has no `appRoles`, so autonomous callers cannot obtain the roles enforced by Defender Hunt MCP 3.0. Add three application roles with new stable GUIDs:

| Value | Allowed member type | Purpose |
|---|---|---|
| `Mcp.Invoke` | `Application` | Base access to the MCP. |
| `Mcp.Hunt` | `Application` | Advanced Hunting and threat-suite execution. |
| `Mcp.AgentGovernance` | `Application` | Agent Identity governance tools. |

Assign these roles only to approved autonomous service principals or Agent Identities. Human delegated access continues through the exposed OAuth scope, not these application roles.

## Delegated Graph permissions for OBO

OBO uses delegated Graph permissions (`type: Scope`). The existing Graph entries are all application roles (`type: Role`) and do not grant delegated OBO access.

Add only delegated permissions required by enabled user-facing tools. Candidate baseline:

| Delegated permission | ID | Used by |
|---|---|---|
| `AuditLog.Read.All` | `e4c9e354-4dc5-45b8-9e7c-e1393b0b1a20` | Sign-ins and directory audits. |
| `SecurityAlert.Read.All` | `bc257fb8-46b4-4b15-8713-01e91bfbe4ea` | Alert v2 tools. |
| `SecurityEvents.Read.All` | `64733abd-851e-478a-bffb-e47a14b18235` | Secure Score and supported security data. |
| `ThreatHunting.Read.All` | `b152eca8-ea73-4a48-8c98-1a6742673d99` | Advanced Hunting. |
| `ThreatIntelligence.Read.All` | `f266d9c0-ccb9-4fb8-a228-01ac0d8d6627` | Intelligence profile indicators. |
| `IdentityRiskyUser.Read.All` | `d04bb851-cb7c-4146-97c7-ca3e71baf56c` | Risky users/sign-ins. |
| `Policy.Read.ConditionalAccess` | `633e0fce-8c58-4cfb-9495-12bbd5a24f7c` | Conditional Access tools. |
| `Application.Read.All` | `c79f8feb-a9db-4090-85f9-90d820caa0eb` | Service-principal and app-role governance reads. |
| `AgentIdentity.Read.All` | `5e850691-d86a-4b24-bfa6-8a52fb37a0c1` | Agent Identity inventory, subject to API availability/licensing. |
| `IdentityRiskyAgent.Read.All` | `3215c57f-3faa-4295-95c2-6f14a5bc6124` | Future risky-agent reads when enabled. |
| `IdentityRiskyServicePrincipal.Read.All` | `ea5c4ab0-5a73-4f35-8272-5d5337884e5d` | Future workload-risk reads when enabled. |

Grant tenant admin consent after review. Effective OBO authorization remains the intersection of these delegated permissions and the signed-in user's privileges.

Do not add broad directory/group/device permissions unless a concrete tool and endpoint require them.

## Application permissions and runtime Managed Identity

The existing manifest declares these Microsoft Graph application permissions:

| Application permission ID | Permission | Recommendation |
|---|---|---|
| `b0afded3-3588-46d8-8b3d-9842eff778da` | `AuditLog.Read.All` | Assign to the runtime Managed Identity if autonomous identity tools need it. |
| `7438b122-aefc-4978-80ed-43db9fcc7715` | `Device.Read.All` | Remove unless a direct Graph device endpoint is introduced. Current device telemetry is Advanced Hunting. |
| `ae73097b-cb2a-4447-b064-5d80f6093921` | `DirectoryRecommendations.Read.All` | Remove; current tool uses Secure Score control profiles. |
| `5b567255-7703-4780-807c-7be8301ae99b` | `Group.Read.All` | Remove unless a documented group-governance tool requires it. |
| `98830695-27a2-44f7-8c18-0c3ebc9698f6` | `GroupMember.Read.All` | Remove unless a documented membership tool requires it. |
| `6e472fd1-ad78-48da-a0f0-97ab2c6b769e` | `IdentityRiskEvent.Read.All` | Remove unless risk-detection APIs are added. |
| `4aadfb66-d49a-414a-a883-d8c240b6fa33` | `IdentityRiskyAgent.Read.All` | Assign to the runtime Managed Identity only if risky-agent tools are enabled. |
| `607c7344-0eed-41e5-823a-9695ebe1b7b0` | `IdentityRiskyServicePrincipal.Read.All` | Assign to the runtime Managed Identity only if workload-risk tools are enabled. |
| `dc5007c0-2d7d-4c42-879c-2dab87571379` | `IdentityRiskyUser.Read.All` | Assign to the runtime Managed Identity for autonomous user-risk workflows. |
| `37730810-e9ba-4e46-b07e-8ca78d182097` | `Policy.Read.ConditionalAccess` | Assign to the runtime Managed Identity for autonomous policy reads. |
| `2a6baefd-edea-4ff6-b24e-bebcaa27a50d` | `RiskPreventionProviders.Read.All` | Remove; not used by current tools. |
| `bf394140-e372-4bf9-a898-299cfc7564e5` | `SecurityEvents.Read.All` | Assign to the runtime Managed Identity where required. |
| `f8f035bb-2cce-47fb-8bf5-7baf3ecbee48` | `ThreatAssessment.Read.All` | Remove; not used by current tools. |
| `dd98c7f5-2d42-42d3-a0e4-633161547251` | `ThreatHunting.Read.All` | Assign to the runtime Managed Identity for autonomous hunting. |
| `197ee4e9-b993-4066-898f-d6aecc55125b` | `ThreatIndicators.Read.All` | Remove unless legacy TI indicator APIs are added; current profile-indicator tool uses `ThreatIntelligence.Read.All`. |
| `e0b77adb-e790-44a3-b0a0-257d06303687` | `ThreatIntelligence.Read.All` | Assign to the runtime Managed Identity for autonomous TI reads. |
| `86632667-cd15-4845-ad89-48a88e8412e1` | `ThreatSubmission.Read.All` | Remove; not used by current tools. |
| `df021288-bdef-4463-88db-98f22de89214` | `User.Read.All` | Remove unless a direct Graph user-profile tool is added. |

Also assign `SecurityAlert.Read.All`, `Application.Read.All`, and `AgentIdentity.Read.All` to the runtime Managed Identity when autonomous MCP tools require them. Agent-specific authorization remains enforced by MCP app roles on the inbound token.

Removing entries from `requiredResourceAccess` changes what the application requests, but verify and remove existing service-principal `appRoleAssignments` as a separate step. Do not assume editing the manifest automatically revokes already granted permissions.

## Self-reference and preauthorization

The app currently lists its own API in `requiredResourceAccess` with `user_impersonation`. A resource API does not need to request its own delegated scope for OBO to Graph. Remove this self-reference unless the app also acts as a client of its own API for a documented scenario.

`preAuthorizedApplications` contains client ID `fe053c5f-3692-4f14-aef2-ee34fc081cae`. It was verified in the target tenant as the Microsoft first-party service principal **Azure API Connections** (`servicePrincipalType: Application`). Retain this preauthorization only if an active Azure API Connection still invokes the MCP:

```bash
az login
az ad sp show --id fe053c5f-3692-4f14-aef2-ee34fc081cae \
  --query '{appId:appId,displayName:displayName,id:id}' -o json
```

Preauthorize only trusted clients and only the canonical MCP delegated scope. Remove the preauthorization if Azure API Connections is no longer a caller. `knownClientApplications` is not required when preauthorization is deliberately used; bundled-consent scenarios should be evaluated separately.

## Redirect URIs

OBO itself does not require a redirect URI.

- Keep `https://securitycopilot.microsoft.com/auth/v1/callback` only while an active Security Copilot plugin/auth flow uses this app.
- Remove or replace the old Container Apps `/.auth/login/aad/callback` URI if App Service Authentication/Easy Auth is no longer used. Defender Hunt MCP 3.0 validates JWTs in its own middleware.
- Do not add the MCP `/mcp` endpoint as an OAuth redirect URI.

## Service-principal lock

The manifest enables `servicePrincipalLockConfiguration`. Treat this as a protective control. Do not disable it preemptively. Test the planned app/certificate/role changes in a controlled window; relax only the specific lock property if Microsoft Entra rejects a required operation, then restore and verify the lock.

## Migration sequence

1. Add a certificate to the existing app and validate confidential-client/OBO token exchange before the July secrets expire.
2. Configure the runtime with the existing client ID, v2 issuer/audience, and `ENTRA_MCP_USER_SCOPE=access_as_user`.
3. Add `Mcp.Invoke`, `Mcp.Hunt`, and `Mcp.AgentGovernance` application roles.
4. Add reviewed delegated Graph scopes and grant admin consent.
5. Verify the preauthorized client and reduce it to the canonical MCP scope.
6. Create approved Agent Identities, assign least-privilege MCP app roles to each one, and add their client IDs to `agentClientIds`.
7. Assign approved Graph application roles to the runtime Managed Identity.
8. Exercise delegated user -> MCP -> OBO -> Graph, delegated Agent ID -> MCP -> OBO -> Graph, and autonomous Agent ID -> MCP -> Managed Identity -> Graph in a test tenant.
9. Remove/revoke Graph application role assignments from the old app service principal after runtime Managed Identity validation.
10. Remove unused Graph permissions, the self-reference, stale redirect URI, redundant scope, and expiring secrets.
11. Re-export the manifest and service-principal role assignments; compare against the approved least-privilege baseline.
