# Security

Defender Hunt MCP exposes tenant security and identity telemetry. Treat it as a privileged security service, not a general public API.

## Trust model

- MCP clients authenticate with single-tenant Microsoft Entra access tokens for the MCP audience.
- Delegated users require `Mcp.Access` and call Graph through OBO.
- Autonomous applications require MCP app roles and call Graph through the Container App managed identity.
- Advanced Hunting for autonomous callers requires `Mcp.Hunt`; beta governance requires `Mcp.AgentGovernance`.
- Request identity is propagated with `contextvars`; there is no fallback between delegated and app-only Graph access.
- `/health` and `/info` are intentionally public.

The service is intentionally single-tenant. Cache keys include actor identity and a permission fingerprint to prevent delegated users or agents from sharing over-broad cached responses.

## Required production controls

1. Validate issuer, audience, tenant, signature, expiry, delegated scopes, and application roles for every `/mcp` request.
2. Grant delegated Graph permissions to the OBO app and application permissions to the Managed Identity separately through change control.
3. Keep `.env`, client secrets, API keys, certificates, logs, and exported hunting data out of source control.
4. Terminate TLS at managed ingress and never send bearer assertions over plaintext networks.
5. Restrict ingress through private networking, source allow-lists, API Management, or another gateway where possible.
6. Rotate/revoke the OBO certificate and caller identities after suspected disclosure; prefer Key Vault certificate lifecycle over client secrets.
7. Monitor unauthorized requests, Graph failures, unusual query volume, container restarts, and secret changes.
8. Add rate limits and request-size limits before exposing the service to multiple clients.

## Input and query risks

Tool inputs used as KQL or OData literals pass through centralized validation and language-specific quoting. Shared day/result limits and high-use alert/sign-in/risk filters are also enforced in the published MCP schema. Some specialized categorical parameters still require migration to enum-backed schemas. Until that migration is complete:

- expose the service only to trusted MCP clients;
- do not treat tool descriptions as input validation;
- review custom KQL before execution;
- avoid passing untrusted text as IoCs, UPNs, device names, alert filters, or audit filters.

`run_hunting_query` intentionally allows arbitrary read-only Advanced Hunting KQL supported by Microsoft Graph. The configured Graph permission and Defender service limits are the ultimate authorization boundary.

## Error and data handling

Some tools currently return upstream exception text to the client, which can expose Graph or schema details. Logs and MCP responses may contain sensitive device names, users, IP addresses, command lines, alert evidence, and investigation results. Apply organizational retention, access-control, and incident-response policies to both stdout logs and client transcripts.

## Third-party threat feeds

The ransomware and threat-intelligence hunting modules use public URLs through KQL `externaldata()`. These feeds are mutable third-party dependencies and can become unavailable, malformed, or compromised. Production deployments should mirror approved feeds into controlled storage, validate format and size, record provenance, and update on a reviewed schedule.

## Known functional limitations

- `validate_kql_query` checks for a known table reference only; it is not a syntax validator.
- `get_threat_indicators` uses the Graph intelligence-profile-indicators collection; tenant licensing and API availability still apply.
- `get_security_recommendations` uses Secure Score control profiles and exposes remediation guidance.
- Data-exfiltration transfer heuristics use connection counts because documented `DeviceNetworkEvents` does not expose byte totals; these are indicators, not proof of exfiltrated volume.
- Advanced multi-query tools expose `success`, `partial_success`, or `error`, plus `failed_queries` and per-query status. Consumers must treat `partial_success` as incomplete coverage.
- `get_risky_signins` applies both `risk_level` and `risk_state` to the Graph filter.
- Shared day/result limits and high-use filters use Pydantic bounds/enums; specialized hunt subtype parameters are not all enum-backed yet.
- Atomic legacy tools still return JSON encoded inside MCP text results; new workflow/governance tools return structured objects. All tools publish read-only/non-destructive annotations.

These limitations should be resolved before using the service as an unattended detection or compliance control. It is currently best suited to analyst-assisted investigation in a controlled environment.

## Secret history

The repository previously tracked `.env`. Removing it from the index prevents future commits but does not remove older blobs. If real credentials were ever committed, rotate them and, when policy requires, rewrite repository history with an approved tool and coordinate the forced update with all clones.

## Reporting

Do not include real tenant identifiers, secrets, user data, or hunting results in public issue reports. Provide sanitized reproduction steps and the relevant tool/query category.
