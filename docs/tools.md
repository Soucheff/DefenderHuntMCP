# MCP tools and resources

The live server currently registers 31 tools and seven resources. All tools are read-oriented, but they execute against external Microsoft services and can expose sensitive tenant data.

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
| `get_threat_indicators` | Currently lists Defender Threat Intelligence profiles. Despite the historical name, it does not yet traverse profile indicator collections and should not be treated as a complete IoC list. |
| `enrich_ioc` | Builds a hunting query for an IP, domain, URL, or hash and summarizes matching Defender telemetry. |
| `hunt_by_ioc` | Searches relevant Advanced Hunting tables for IP, domain, URL, hash, or process values over at most 30 days. |

The Defender Threat Intelligence profile APIs require `ThreatIntelligence.Read.All` and the applicable Defender Threat Intelligence license/add-on.

## Security posture

| Tool | Behavior |
|---|---|
| `get_security_recommendations` | Currently retrieves Secure Score records. Secure Score records are historical tenant/control scores, not a standalone recommendation catalog. |
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
| `get_risky_signins` | Lists risky sign-ins with UPN and risk-level filters. The accepted `risk_state` argument is not currently applied. |
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
| `hunt_data_exfiltration` | Large transfers, cloud storage, DNS tunneling, archives. The large-transfer/cloud branches currently rely on undocumented `DeviceNetworkEvents` fields and may fail. |
| `get_asr_events` | ASR blocked/audited events and a small static rule-description map. |

Advanced hunt tools execute selected subqueries sequentially. `_multi_hunt` currently logs an individual query failure and returns an empty list for that branch, so `total_findings: 0` can mean either no findings or a failed subquery. Review server logs before concluding that a detection is clean.

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

## Result interpretation

Most tools return a JSON string as MCP text content; dashboard/profile tools return formatted text. Errors are generally represented in the tool result rather than as protocol errors. Some upstream exception messages are currently returned verbatim.

Tool output is investigative evidence, not a final incident verdict. Validate findings against source telemetry, tenant schema, licensing, retention, and analyst context.
