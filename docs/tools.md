# MCP tools and resources

The live server currently registers 38 tools and eight resources. All tools are read-oriented, but they execute against external Microsoft services and can expose sensitive tenant data.

## Core hunting

| Tool | Behavior |
|---|---|
| `run_hunting_query` | Executes caller-supplied Advanced Hunting KQL through Microsoft Graph. Defender limits results to 10,000 rows and a 30-day maximum query window. |
| `validate_kql_query` | Performs a local, basic check that the text references a known Advanced Hunting table. It does not validate KQL syntax with Defender. |

## Alerts

| Tool | Behavior |
|---|---|
| `get_security_alerts` | Lists alert v2 records with optional severity/status filters and a requested top value capped in code at 100. |
| `get_alert_details` | Retrieves one alert v2 record by ID, including evidence rendered as strings. |
| `get_alert_statistics` | Aggregates `AlertInfo` and `AlertEvidence` over `1h`, `24h`, `7d`, or `30d`. The current join can count an alert more than once when it has multiple evidence rows. |

## Threat intelligence and IoC hunting

| Tool | Behavior |
|---|---|
| `get_threat_indicators` | Lists Defender Threat Intelligence profile indicators through the Graph collection endpoint. |
| `enrich_ioc` | Builds a hunting query for an IP, domain, URL, or hash and summarizes matching Defender telemetry. |
| `hunt_by_ioc` | Searches relevant Advanced Hunting tables for IP, domain, URL, hash, or process values over at most 30 days. |

The Defender Threat Intelligence profile APIs require `ThreatIntelligence.Read.All` and the applicable Defender Threat Intelligence license/add-on.

## Security posture

| Tool | Behavior |
|---|---|
| `get_security_recommendations` | Retrieves Secure Score control profiles with categories, impact, threats, and remediation guidance. |
| `get_device_info` | Returns the most recent matching `DeviceInfo` row by device name or ID. |
| `investigate_user_logon` | Summarizes `IdentityLogonEvents` for a username or UPN, including protocols, devices, IPs, and failures. |
| `get_environment_dashboard` | Runs sequential alert, authentication, device, and network summary queries. |
| `analyze_security_posture` | Runs selected identity, device, and network summaries and emits static recommendations. The `applications` focus currently has no dedicated query. |

## Microsoft Entra ID

| Tool | Behavior |
|---|---|
| `get_signin_logs` | Lists sign-ins with optional UPN prefix, application, success/failure, and risk-level filters. |
| `get_audit_logs` | Lists directory audits with category/activity filters, then applies initiator and target filters in memory. |
| `get_risky_users` | Lists Identity Protection risky users with level/state filters. |
| `get_risky_signins` | Lists risky sign-ins with escaped UPN, risk-level, and risk-state filters. |
| `get_conditional_access_policies` | Lists Conditional Access policies and selected conditions/grant controls. |
| `analyze_user_risk_profile` | Combines risky-user status and up to 500 sign-in records into a textual profile. |

## Advanced threat hunting

| Tool | Detection families |
|---|---|
| `hunt_ransomware_indicators` | Extensions, ransom notes, shadow-copy deletion, double extensions. Some branches use public external feeds. |
| `hunt_suspicious_powershell` | Encoded commands, web requests, Defender preference tampering, AMSI events. |
| `hunt_lolbin_activity` | Certutil, mshta, regsvr32, rundll32, WMIC, bitsadmin. |
| `hunt_lateral_movement` | PsExec, SMB, WMI, RDP, DCOM. |
| `hunt_credential_access` | LSASS, NTDS, SAM, Mimikatz patterns, DCSync. |
| `hunt_persistence_mechanisms` | Run keys, scheduled tasks, services, Startup folder, WMI subscriptions. |
| `hunt_suspicious_child_processes` | Browser, Office, Explorer, and Outlook child processes. |
| `hunt_remote_access_tools` | Commercial RMM, known RAT names, and tunneling utilities. |
| `hunt_defense_evasion` | Security-tool stopping, log clearing, timestomping, injection events. |
| `hunt_threat_intel_feeds` | Public domain, IP, and hash feeds loaded through `externaldata()`. |
| `hunt_data_exfiltration` | High-volume connection patterns, cloud storage, DNS tunneling, and archives using documented fields. Connection counts do not prove byte volume. |
| `get_asr_events` | ASR blocked/audited events and a small static rule-description map. |

Advanced hunt tools currently execute selected subqueries sequentially. Each branch returns status, row count, results, and a sanitized error when it fails. The top-level response reports `success`, `partial_success`, or `error` and includes `failed_queries`, so a clean result can be distinguished from incomplete coverage.

## Resources

| URI | Content |
|---|---|
| `defender://hunting/examples` | Example Advanced Hunting KQL. |
| `defender://hunting/tables` | Concise table-name reference. |
| `defender://hunting/ioc-queries` | IoC hunting guidance. |
| `defender://soc/playbooks` | High-level SOC playbook list. |
| `entra://identity/signin-investigation` | Sign-in investigation guidance. |
| `entra://identity/risk-investigation` | Risk investigation guidance. |
| `entra://identity/conditional-access` | Conditional Access guidance. |
| `defender://capabilities` | Auth modes, stable/beta capabilities, cache backends, contract version, and limits. |

## Token-efficient workflows

| Tool | Behavior |
|---|---|
| `investigate_user` | Runs sign-in, risky-sign-in, and audit steps concurrently with bounded evidence. |
| `investigate_alert` | Combines one alert with environment alert statistics. |
| `hunt_iocs_batch` | Deduplicates and enriches up to 20 IoCs with bounded concurrency. |
| `run_threat_hunt_suite` | Executes selected hunt modules with an explicit concurrency budget and partial-failure reporting. |

Workflow tools return structured objects with `contract_version`, status, failed steps, and compacted evidence.

## Agent governance (beta)

| Tool | Behavior |
|---|---|
| `list_agent_identities` | Feature-flagged beta inventory of Agent Identity service principals. |
| `get_agent_identity_profile` | Agent profile plus bounded application-role assignments. |
| `analyze_agent_permissions` | Explainable heuristic prioritization of app-role assignments. |

These contracts are marked beta and return `unavailable` when disabled, unsupported, or unauthorized. Permission recommendations are heuristic and must be verified against effective Graph role definitions.

## Result interpretation

Most tools return a JSON string as MCP text content; dashboard/profile tools return formatted text. Errors are generally represented in the tool result rather than as protocol errors. Some upstream exception messages are currently returned verbatim.

Tool output is investigative evidence, not a final incident verdict. Validate findings against source telemetry, tenant schema, licensing, retention, and analyst context.
