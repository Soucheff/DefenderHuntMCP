# Security

Defender Hunt MCP exposes tenant security and identity telemetry. Treat it as a privileged security service, not a general public API.

## Trust model

- MCP clients authenticate with one shared API key when `MCP_API_KEY` is configured.
- The server uses one Entra application identity for every Microsoft Graph request.
- There is no caller-specific authorization, role mapping, delegated identity, or tenant isolation.
- `/health` and `/info` are intentionally public.

Anyone who knows the shared API key can exercise the configured application's effective Graph permissions. Use a dedicated deployment and credential set for each operational trust boundary.

## Required production controls

1. Set a long, randomly generated `MCP_API_KEY`; never expose `/mcp` without authentication.
2. Grant only the Graph application permissions required by enabled tools and obtain admin consent through change control.
3. Keep `.env`, client secrets, API keys, certificates, logs, and exported hunting data out of source control.
4. Terminate TLS at the managed ingress or trusted reverse proxy; never send the API key over plaintext networks.
5. Restrict ingress through private networking, source allow-lists, API Management, or another gateway where possible.
6. Rotate both `MCP_API_KEY` and `AZURE_CLIENT_SECRET` regularly and immediately after suspected disclosure.
7. Monitor unauthorized requests, Graph failures, unusual query volume, container restarts, and secret changes.
8. Add rate limits and request-size limits before exposing the service to multiple clients.

## Input and query risks

Several tools construct KQL or OData filters from caller-provided strings. The current implementation does not consistently enforce enums, ranges, format validation, or escaping. Until centralized validation is implemented:

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
- `get_threat_indicators` currently queries Defender Threat Intelligence profiles rather than traversing each profile's `/indicators` relationship. Treat its output as profile metadata, not a complete IoC feed.
- `get_security_recommendations` currently reads Secure Score records, which represent historical score data rather than a recommendation catalog.
- The large-transfer and cloud-upload branches of `hunt_data_exfiltration` reference fields not present in the current documented `DeviceNetworkEvents` schema. Those branches can fail until reworked against suitable telemetry.
- Advanced multi-query tools currently convert individual query failures to empty result lists. A zero count does not necessarily prove that no activity occurred; inspect server logs for warnings.
- `get_risky_signins` accepts `risk_state`, but the current Graph filter does not apply it.
- Tool schemas describe options and maxima but do not yet enforce all values with Pydantic enums/ranges.
- Tools return JSON encoded inside MCP text results and do not currently publish MCP read-only annotations.

These limitations should be resolved before using the service as an unattended detection or compliance control. It is currently best suited to analyst-assisted investigation in a controlled environment.

## Secret history

The repository previously tracked `.env`. Removing it from the index prevents future commits but does not remove older blobs. If real credentials were ever committed, rotate them and, when policy requires, rewrite repository history with an approved tool and coordinate the forced update with all clones.

## Reporting

Do not include real tenant identifiers, secrets, user data, or hunting results in public issue reports. Provide sanitized reproduction steps and the relevant tool/query category.
