# Security policy

Defender Hunt MCP handles privileged Microsoft Defender and Microsoft Entra telemetry. Please report suspected vulnerabilities privately and avoid including tenant data, credentials, access tokens, API keys, or hunting results in any report.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting feature on the public repository after it is created:

1. Open the repository's **Security** tab.
2. Select **Report a vulnerability**.
3. Provide sanitized reproduction steps, affected versions/commits, impact, and any proposed mitigation.

If private vulnerability reporting is not yet enabled, contact the repository owner through a private channel before opening an issue. Do not create a public issue for an unpatched vulnerability.

## Response expectations

Maintainers will aim to:

- acknowledge a report within five business days;
- validate impact and affected versions;
- coordinate remediation and disclosure timing with the reporter;
- publish a security advisory when users need to take action.

These are response targets, not a service-level agreement.

## Supported versions

Until formal releases are published, only the latest commit on the default branch is supported. After releases begin, supported versions will be listed here.

## Scope

Security-sensitive areas include:

- MCP authentication and authorization boundaries;
- Microsoft Graph credentials, scopes, and token handling;
- KQL and OData input validation;
- disclosure of tenant telemetry or internal errors;
- container and Azure deployment configuration;
- third-party threat feed integrity;
- dependency and build-chain compromise.

For deployment risks and known functional limitations, see [docs/security.md](docs/security.md).
