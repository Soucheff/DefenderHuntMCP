# MCP tools and resources

The live server currently registers 59 tools and eight resources. All tools are read-oriented, but they execute against external Microsoft services and can expose sensitive tenant data.

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
| `investigate_user_logon` | Summarizes Defender `EntraIdSignInEvents` for a username or UPN, including apps, devices, IPs, risk, Conditional Access, and failures; falls back to Graph when unavailable. |
| `get_environment_dashboard` | Runs sequential alert, authentication, device, and network summary queries. |
| `analyze_security_posture` | Runs selected identity, device, and network summaries and emits static recommendations. The `applications` focus currently has no dedicated query. |

## Microsoft Entra ID

| Tool | Behavior |
|---|---|
| `get_identity_context` | Consolidates user profile, group membership, active/eligible directory roles, app roles, licenses, manager, direct reports, and owned directory objects. Exactly one of user ID or UPN is required; relation failures produce `partial_success`. |
| `get_authentication_posture` | Combines per-user authentication methods with registration reporting. `mfa_enabled` means MFA registered, not enforced by Conditional Access. |
| `get_signin_activity` | Lists bounded sign-ins by user object ID and aggregates applications, devices, locations, IPs, failures, and risk signals. |
| `analyze_signin_risk` | Computes a transparent 0-100 investigative score from Identity Protection level, risky-sign-in count, and failure ratio. It is not an Entra risk score. |
| `get_applied_conditional_access` | Reads the policies and controls actually evaluated on one sign-in; it does not simulate future access. |
| `get_identity_alerts` | Scans a bounded Defender XDR alert page and matches `userStates` or user evidence to an ID/UPN. |
| `get_privileged_access` | Combines active/eligible directory roles with transitive role-assignable group membership. Criticality is a documented name-based heuristic. |
| `get_pim_eligibility` | Returns active and eligible directory roles with assignment scope and expiration. |
| `get_pim_activations` | Returns recent `selfActivate` PIM schedule requests with role, status, justification, duration, and expiration. |
| `get_user_app_role_assignments` | Lists enterprise application (app role) assignments granted directly to a user, with resource names. |
| `list_privileged_role_assignments` | Single-page tenant snapshot of active `roleAssignments` with expanded principal and role definition. `only_privileged` applies a documented built-in-role name heuristic. |
| `get_authentication_methods_policy` | Reads the tenant authentication methods policy and flags SMS/Voice/Email enabled as weak methods. |
| `find_user_oauth_grants` | Lists a user's delegated `oauth2PermissionGrants` and flags high-risk scopes (mail, files, directory, offline_access). |
| `summarize_signin_failures` | Aggregates one page of failed sign-ins by error code, targeted user, and source IP; the spray flag is a coarse heuristic. |
| `get_users_by_directory_role` | Resolves an exact role display name or template ID, then lists active assignments, PIM eligibility, or both. Role-assignable groups are expanded transitively by default and inherited users include the source group. Role definitions are cached for one hour. |
| `list_identity_groups` | Lists bounded group metadata with optional display-name prefix and security, Microsoft 365, or role-assignable filtering. |
| `analyze_identity_group` | Returns one group's properties, owners, and bounded direct or transitive membership with principal-type counts. |
| `get_signin_logs` | Lists sign-ins with optional UPN prefix, application, success/failure, and risk-level filters. |
| `get_audit_logs` | Lists directory audits with category/activity filters, then applies initiator and target filters in memory. |
| `get_risky_users` | Lists Identity Protection risky users with level/state filters. |
| `get_risky_signins` | Lists risky sign-ins with escaped UPN, risk-level, and risk-state filters. |
| `get_conditional_access_policies` | Lists Conditional Access policies and selected conditions/grant controls. |
| `analyze_user_risk_profile` | Combines risky-user status and up to 500 sign-in records into a textual profile. |

Role assignments require `RoleManagement.Read.Directory`. PIM eligibility additionally requires `RoleEligibilitySchedule.Read.Directory`; activation history requires `RoleAssignmentSchedule.Read.Directory` or an approved higher privilege. Authentication methods require `UserAuthenticationMethod.Read.All`, the authentication methods policy requires `Policy.Read.All`, and registration reporting and sign-ins require `AuditLog.Read.All`; applied CA details also require `Policy.Read.All` or `Policy.Read.ConditionalAccess`. App-role assignment resource names and OAuth grant review use `Application.Read.All`, and delegated OAuth2 grants require `DelegatedPermissionGrant.Read.All`. Group owners and membership require `GroupMember.Read.All`; full group properties use `Group.Read.All`; hidden-membership groups also require `Member.Read.Hidden`. In delegated OBO calls, the signed-in user must also hold a supported Entra role. Results are bounded to one Graph page and expose `truncated` where applicable.

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

Advanced hunt tools currently execute selected subqueries with bounded concurrency (up to four in flight). Each branch returns status, row count, results, and a sanitized error when it fails. The top-level response reports `success`, `partial_success`, or `error` and includes `failed_queries`, so a clean result can be distinguished from incomplete coverage.

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
| `investigate_identity` | Runs identity context, authentication posture, sign-in risk, identity alerts, and privilege analysis concurrently with bounded evidence. |
| `recommend_next_investigation_steps` | Uses deterministic evidence keywords and missing sections to recommend registered tools with reasons and confidence. It does not invoke an AI model. |
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
| `evaluate_agent_risk` | Beta heuristic score for one agent based on assignment volume/priority and app-role requirement state. |
| `list_agents_with_excessive_permissions` | Concurrent bounded scan of beta agents that meet a configurable heuristic threshold. |

These contracts are marked beta and return `unavailable` when disabled, unsupported, or unauthorized. Permission recommendations are heuristic and must be verified against effective Graph role definitions.

## Suggested-tool coverage

| Suggestion | Decision |
|---|---|
| Identity context, authentication posture, sign-in activity/risk, applied CA, identity alerts, investigation, privileged access, PIM eligibility/activations, agent risk/excess, next-step recommendation | Added as dedicated tools. |
| `get_agent_identity`, `get_agent_permissions` | Already covered by `get_agent_identity_profile` and `analyze_agent_permissions`; aliases were not added. |
| `evaluate_conditional_access` | Not added. Actual sign-in policy results are supported, but generic What If simulation is not exposed by the stable adapter used here. |
| `get_identity_attack_path` | Not added. Requires a licensed Exposure Management/attack-path source and a separate contract. |
| `get_identity_exposure` | Not added. Secure Score is tenant/control scoped and must not be presented as a per-user score. |
| Incident explanation and remediation/summary generation | Not added. This server has no incident aggregation or configured model, so generated business impact or remediation would be unsupported inference. |

## Result interpretation

Most tools return a JSON string as MCP text content; dashboard/profile tools return formatted text. Errors are generally represented in the tool result rather than as protocol errors. Some upstream exception messages are currently returned verbatim.

Tool output is investigative evidence, not a final incident verdict. Validate findings against source telemetry, tenant schema, licensing, retention, and analyst context.

## Performance characteristics

- Advanced Hunting sub-queries run with bounded concurrency (up to four in flight) rather than serially.
- Delegated Graph clients are memoized per request, so multi-tool workflows reuse one OBO credential and token acquisition instead of rebuilding per call.
- Directory role definitions are cached for one hour behind the configured cache backend, degrading to a live read when the backend is disabled or unavailable.
- Microsoft Graph JSON `$batch` is intentionally not used: it bypasses the SDK per-request retry/throttling middleware, caps at 20 sub-requests, and shifts partial-429 handling to the caller. Independent reads are instead issued concurrently with `asyncio.gather`, which keeps per-request resilience.
