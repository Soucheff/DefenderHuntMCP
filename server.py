#!/usr/bin/env python3
"""
MCP Server for Microsoft Defender Advanced Hunting — FastMCP Edition.

Provides KQL query execution, alert management, threat hunting, and
Microsoft Entra ID identity investigation via Microsoft Graph API.
"""

import asyncio
import json
import logging
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from dotenv import load_dotenv
from kiota_abstractions.api_error import APIError
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from msgraph.generated.security.microsoft_graph_security_run_hunting_query.run_hunting_query_post_request_body import (
    RunHuntingQueryPostRequestBody,
)
from msgraph.graph_service_client import GraphServiceClient
from pydantic import Field

from agent_governance import (
    AgentGovernanceClient,
    AgentGovernanceUnavailable,
    analyze_permission_assignments,
)
from auth_context import get_request_identity
from auth_policy import authorize_current_identity
from cache_runtime import cached_operation
from config import Config
from graph_clients import GraphClientFactory
from query_safety import quote_kql_string, quote_odata_string
from workflow_engine import run_workflow

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
load_dotenv()
logging.basicConfig(
    level=getattr(logging, Config.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Shared MCP input contracts
# ---------------------------------------------------------------------------
DaysBack30 = Annotated[int, Field(ge=1, le=30, description="Days back (1-30)")]
DaysBack90 = Annotated[int, Field(ge=1, le=90, description="Days back (1-90)")]
ResultLimit100 = Annotated[int, Field(ge=1, le=100, description="Maximum results (1-100)")]
ResultLimit200 = Annotated[int, Field(ge=1, le=200, description="Maximum results (1-200)")]
ResultLimit500 = Annotated[int, Field(ge=1, le=500, description="Maximum results (1-500)")]

AlertSeverity = Literal["informational", "low", "medium", "high", "unknown"]
AlertStatus = Literal["new", "inProgress", "resolved", "unknown"]
SignInStatus = Literal["success", "failure", "all"]
RiskLevel = Literal["none", "low", "medium", "high", "all"]
RiskState = Literal["atRisk", "confirmedCompromised", "remediated", "dismissed", "all"]
RoleAssignmentState = Literal["active", "eligible", "all"]
IdentityGroupType = Literal["all", "security", "microsoft365", "role_assignable"]
GroupMembershipScope = Literal["direct", "transitive"]
IdentityTimeRange = Literal["1h", "24h", "7d", "30d", "90d"]
DetailLevel = Literal["summary", "standard", "evidence"]
MaxEvidence = Annotated[int, Field(ge=1, le=50, description="Maximum evidence items (1-50)")]
WorkflowConcurrency = Annotated[int, Field(ge=1, le=8, description="Concurrent steps (1-8)")]
BatchIoCs = Annotated[list[str], Field(min_length=1, max_length=20)]
ThreatModule = Literal[
    "ransomware",
    "powershell",
    "lolbins",
    "lateral_movement",
    "credential_access",
    "persistence",
    "child_processes",
    "remote_access",
    "defense_evasion",
    "threat_intel",
    "data_exfiltration",
    "asr",
]

# ---------------------------------------------------------------------------
# FastMCP server
# ---------------------------------------------------------------------------
mcp = FastMCP(
    "defender_hunt_mcp",
    instructions=(
        "MCP server for Microsoft Defender and Entra ID security operations. "
        "Provides atomic and workflow tools for KQL Advanced Hunting, alert management, threat intelligence "
        "enrichment, IoC hunting, identity investigation (sign-in/audit logs, risky users, "
        "Conditional Access), security posture dashboards, and advanced threat detection "
        "modules covering ransomware, LOLBIN abuse, lateral movement, credential dumping, "
        "persistence, defense evasion, RATs, data exfiltration, and ASR events. "
        "To list who holds an administrative role such as Global Administrator, use "
        "get_users_by_directory_role; for a tenant-wide privileged snapshot use "
        "list_privileged_role_assignments. "
        "All queries run against the Microsoft Graph Security API."
    ),
    host="0.0.0.0",
    stateless_http=True,
)

READ_ONLY_TOOL_ANNOTATIONS = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=True,
)


def read_only_tool():
    """Register a read-only tool with consistent MCP behavioral hints."""
    return mcp.tool(annotations=READ_ONLY_TOOL_ANNOTATIONS)


# ---------------------------------------------------------------------------
# Microsoft Graph client factory (lazy singleton)
# ---------------------------------------------------------------------------
_graph_client_factory: GraphClientFactory | None = None


def get_graph_client() -> GraphServiceClient:
    """Return a Graph client authorized for the current user or autonomous agent."""
    global _graph_client_factory
    if _graph_client_factory is None:
        _graph_client_factory = GraphClientFactory.from_environment()
    return _graph_client_factory.get_client(get_request_identity())


async def _get_graph_access_token() -> str:
    global _graph_client_factory
    if _graph_client_factory is None:
        _graph_client_factory = GraphClientFactory.from_environment()
    return await _graph_client_factory.get_access_token(get_request_identity())


async def _run_hunting(query: str, timespan: str | None = None) -> dict:
    """Execute a KQL hunting query and return raw result dict."""
    authorize_current_identity(agent_role="Mcp.Hunt")
    client = get_graph_client()
    body = RunHuntingQueryPostRequestBody()
    body.query = query
    if timespan:
        body.timespan = timespan
    logger.debug("Hunting query:\n%s", query)
    result = await client.security.microsoft_graph_security_run_hunting_query.post(body=body)
    logger.debug(
        "Hunting response — type=%s, has_results=%s, results_len=%s, additional_data=%s",
        type(result).__name__,
        hasattr(result, "results") and result.results is not None,
        len(result.results) if result and hasattr(result, "results") and result.results else 0,
        list(result.additional_data.keys())
        if result and hasattr(result, "additional_data") and result.additional_data
        else "none",
    )
    if result and hasattr(result, "results") and result.results:
        return {
            "status": "success",
            "rowCount": len(result.results),
            "schema": result.schema if hasattr(result, "schema") else None,
            "results": result.results,
        }
    return {"status": "success", "message": "Query returned no results", "rowCount": 0}


def _json(obj: Any) -> str:
    return json.dumps(obj, indent=2, default=str)


def _error_response(operation: str, error: Exception) -> str:
    """Log an internal exception and return a stable client-safe response."""
    logger.error("%s failed: %s", operation, error, exc_info=True)
    return _json(
        {
            "status": "error",
            "error": "Operation failed",
            "error_code": "UPSTREAM_OR_INTERNAL_ERROR",
        }
    )


def _build_alert_statistics_query(kql_time: str) -> str:
    return f"""
let Alerts = AlertInfo
| where Timestamp > ago({kql_time})
| summarize
    TotalAlerts = dcount(AlertId),
    HighSeverity = dcountif(AlertId, Severity == "High"),
    MediumSeverity = dcountif(AlertId, Severity == "Medium"),
    LowSeverity = dcountif(AlertId, Severity == "Low"),
    TopCategories = make_set(Category, 10)
| extend JoinKey = 1;
let Evidence = AlertEvidence
| where Timestamp > ago({kql_time}) and isnotempty(DeviceId)
| summarize UniqueDevices = dcount(DeviceId)
| extend JoinKey = 1;
Alerts
| join kind=leftouter Evidence on JoinKey
| project-away JoinKey, JoinKey1
"""


def _conditional_access_state_matches(actual_state: Any, requested_state: str) -> bool:
    if requested_state == "all":
        return True
    return str(actual_state).lower() == requested_state.lower()


def _audit_target_matches(target_resources: list[Any] | None, target: str | None) -> bool:
    if not target:
        return True
    if not target_resources:
        return False
    target_lower = target.lower()
    return any(
        target_lower in (resource.display_name or "").lower() for resource in target_resources
    )


def _build_data_exfiltration_queries(days: int, exfil_type: str) -> dict[str, str]:
    queries: dict[str, str] = {}
    if exfil_type in ("all", "large_transfers"):
        queries["large_transfers"] = f"""
DeviceNetworkEvents | where Timestamp > ago({days}d) | where ActionType == "ConnectionSuccess"
| where RemoteIPType == "Public"
| summarize Connections=count(), RemotePorts=dcount(RemotePort)
  by DeviceName, InitiatingProcessAccountName, RemoteIP, InitiatingProcessFileName
| where Connections > 100 or RemotePorts > 20
| order by Connections desc | limit 100"""
    if exfil_type in ("all", "cloud_storage"):
        queries["cloud_storage"] = f"""
let CS=dynamic(['dropbox.com','drive.google.com','onedrive.live.com','box.com','wetransfer.com','mega.nz','mediafire.com','sendspace.com']);
DeviceNetworkEvents | where Timestamp > ago({days}d) | where RemoteUrl has_any (CS) | where ActionType == "ConnectionSuccess"
| summarize Connections=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
  by DeviceName, InitiatingProcessAccountName, RemoteUrl, InitiatingProcessFileName
| where Connections > 10 | order by Connections desc | limit 100"""
    if exfil_type in ("all", "dns_tunneling"):
        queries["dns_tunneling"] = f"""
DeviceNetworkEvents | where Timestamp > ago({days}d) | where RemotePort == 53
| extend QLen=strlen(RemoteUrl) | where QLen > 50
| summarize Cnt=count(), Avg=avg(QLen), Max=max(QLen) by DeviceName, RemoteIP
| where Cnt > 100 and Avg > 40 | order by Cnt desc | limit 100"""
    if exfil_type in ("all", "archives"):
        queries["archives"] = f"""
DeviceProcessEvents | where Timestamp > ago({days}d)
| where FileName in~ ("7z.exe","rar.exe","zip.exe","tar.exe","winrar.exe","winzip.exe")
    or ProcessCommandLine has_any ("Compress-Archive","System.IO.Compression")
| where ProcessCommandLine has_any ("-p","-password","SecureString","ConvertTo-SecureString")
    or InitiatingProcessFileName in~ ("powershell.exe","cmd.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine | limit 100"""
    return queries


# =========================================================================
# RESOURCES
# =========================================================================

EXAMPLE_KQL = """# Example KQL Queries for Microsoft Defender Advanced Hunting

## 1. Find processes with suspicious command lines
DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_any ("powershell", "cmd.exe")
| where ProcessCommandLine has_any ("-enc", "-w hidden", "bypass")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| limit 100

## 2. Detect file downloads from suspicious domains
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any ("download", "payload")
| where ActionType == "ConnectionSuccess"
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessFileName
| limit 100

## 3. Find registry modifications
DeviceRegistryEvents
| where Timestamp > ago(1d)
| where RegistryKey has "Run"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
| limit 100

## 4. Authentication failures
DeviceLogonEvents
| where Timestamp > ago(1d)
| where ActionType == "LogonFailed"
| summarize FailedAttempts = count() by DeviceName, AccountName
| where FailedAttempts > 5
| order by FailedAttempts desc

## 5. Suspicious file creations
DeviceFileEvents
| where Timestamp > ago(1d)
| where FolderPath has_any ("Temp", "AppData")
| where FileName endswith ".exe" or FileName endswith ".dll"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256
| limit 100
"""

TABLES_REF = """# Microsoft Defender Advanced Hunting Tables

## Device Tables
- DeviceProcessEvents · DeviceNetworkEvents · DeviceFileEvents
- DeviceRegistryEvents · DeviceLogonEvents · DeviceImageLoadEvents
- DeviceEvents · DeviceFileCertificateInfo · DeviceInfo · DeviceNetworkInfo

## Email Tables
- EmailEvents · EmailAttachmentInfo · EmailUrlInfo · EmailPostDeliveryEvents

## Identity Tables
- IdentityLogonEvents · IdentityQueryEvents · IdentityDirectoryEvents

## Cloud App Tables
- CloudAppEvents

## Alert Tables
- AlertEvidence · AlertInfo
"""


@mcp.resource("defender://capabilities")
def resource_capabilities() -> str:
    """Versioned runtime capability and integration metadata."""
    return _json(
        {
            "server": "defender_hunt_mcp",
            "server_version": "3.0.0",
            "contract_version": "1.0.0",
            "auth_modes": [
                "entra_user_obo",
                "entra_agent_id_delegated_obo",
                "entra_agent_id_autonomous",
                "entra_application_managed_identity_legacy",
            ],
            "capabilities": {
                "atomic_tools": {"status": "stable"},
                "workflow_tools": {"status": "beta"},
                "agent_governance": {
                    "status": "beta"
                    if AgentGovernanceClient.enabled_from_environment()
                    else "disabled",
                    "feature_flag": "ENABLE_AGENT_GOVERNANCE_BETA",
                },
                "cache": {
                    "local_backend": "redis",
                    "azure_backend": "azure_managed_redis",
                },
            },
            "limits": {
                "ioc_batch": 20,
                "workflow_concurrency": 8,
                "evidence_items": 50,
                "advanced_hunting_days": 30,
            },
        }
    )


@mcp.resource("defender://hunting/examples")
def resource_example_queries() -> str:
    """Collection of example KQL queries for Advanced Hunting."""
    return EXAMPLE_KQL


@mcp.resource("defender://hunting/tables")
def resource_hunting_tables() -> str:
    """List of available Advanced Hunting tables."""
    return TABLES_REF


@mcp.resource("defender://hunting/ioc-queries")
def resource_ioc_queries() -> str:
    """KQL queries for hunting based on IoCs (IP, domain, hash, URL)."""
    return (
        "# IoC-Based Threat Hunting Queries\n\n"
        "Use the `hunt_by_ioc` or `enrich_ioc` tools for automated IoC hunting.\n"
        "Alternatively run custom KQL with `run_hunting_query`."
    )


@mcp.resource("defender://soc/playbooks")
def resource_soc_playbooks() -> str:
    """Incident response playbooks and investigation workflows."""
    return (
        "# SOC Investigation Playbooks\n\n"
        "Available playbooks:\n"
        "- Ransomware Investigation\n"
        "- Phishing Investigation\n"
        "- Malware Outbreak\n"
        "- Insider Threat Investigation\n\n"
        "Use the dedicated hunt_* tools for automated detection."
    )


@mcp.resource("entra://identity/signin-investigation")
def resource_signin_investigation() -> str:
    """Guide for investigating user sign-in activity."""
    return (
        "# Sign-in Investigation Guide\n\n"
        "Use `get_signin_logs`, `get_risky_signins`, or `analyze_user_risk_profile` tools."
    )


@mcp.resource("entra://identity/risk-investigation")
def resource_risk_investigation() -> str:
    """Guide for investigating risky users and sign-ins."""
    return (
        "# Identity Risk Investigation\n\n"
        "Use `get_risky_users`, `get_risky_signins`, or `analyze_user_risk_profile` tools."
    )


@mcp.resource("entra://identity/conditional-access")
def resource_conditional_access() -> str:
    """Reference for Conditional Access policies."""
    return (
        "# Conditional Access Reference\n\n"
        "Use `get_conditional_access_policies` tool to list and inspect policies."
    )


# =========================================================================
# TOOLS — Core Hunting
# =========================================================================


@read_only_tool()
async def run_hunting_query(
    query: Annotated[
        str,
        Field(
            description=(
                "KQL query to execute. Must reference valid Advanced Hunting tables "
                "(e.g. DeviceProcessEvents, DeviceNetworkEvents, EmailEvents). "
                "Use 'ago()' for time ranges, 'project' to select columns, "
                "and 'limit' to control result size."
            )
        ),
    ],
    timespan: Annotated[
        str | None,
        Field(
            description=(
                "Optional ISO 8601 duration (e.g. 'P1D', 'P7D', 'P30D'). "
                "Defaults to the query's own time filter."
            )
        ),
    ] = None,
) -> str:
    """Execute a KQL query against Microsoft Defender Advanced Hunting.

    Returns security telemetry from devices, emails, identities, and cloud apps.
    Results limited to 10 000 rows / 30 days of data.
    """
    if not query:
        return _json({"status": "error", "error": "'query' parameter is required"})
    try:
        logger.info("Executing hunting query: %s…", query[:100])
        result = await _run_hunting(query, timespan)
        return _json(result)
    except APIError as e:
        return _error_response("run_hunting_query", e)
    except Exception as e:
        return _error_response("run_hunting_query", e)


@read_only_tool()
async def validate_kql_query(
    query: Annotated[str, Field(description="KQL query to validate")],
) -> str:
    """Validate KQL query syntax without executing it."""
    if not query:
        return _json({"status": "error", "error": "'query' parameter is required"})

    known_tables = [
        "deviceprocessevents",
        "devicenetworkevents",
        "devicefileevents",
        "deviceregistryevents",
        "devicelogonevents",
        "deviceimageloadevents",
        "deviceevents",
        "emailevents",
        "emailattachmentinfo",
        "emailurlinfo",
        "identitylogonevents",
        "entraidsigninevents",
        "identityqueryevents",
        "identitydirectoryevents",
        "cloudappevents",
        "alertevidence",
        "alertinfo",
        "deviceinfo",
        "devicenetworkinfo",
        "emailpostdeliveryevents",
    ]
    q_lower = query.lower().strip()
    errors: list[str] = []
    if not any(t in q_lower for t in known_tables):
        errors.append("Query must reference at least one valid Advanced Hunting table")
    if errors:
        return _json({"status": "invalid", "valid": False, "errors": errors})
    return _json(
        {
            "status": "valid",
            "valid": True,
            "message": "Query syntax appears valid (basic validation)",
        }
    )


# =========================================================================
# TOOLS — Alerts
# =========================================================================


@read_only_tool()
async def get_security_alerts(
    severity: Annotated[AlertSeverity | None, Field(description="Alert severity filter")] = None,
    status: Annotated[AlertStatus | None, Field(description="Alert status filter")] = None,
    top: ResultLimit100 = 50,
) -> str:
    """Retrieve security alerts from Microsoft Defender."""
    try:
        from msgraph.generated.security.alerts_v2.alerts_v2_request_builder import (
            Alerts_v2RequestBuilder,
        )

        client = get_graph_client()
        filters = []
        if severity:
            filters.append(f"severity eq {quote_odata_string(severity)}")
        if status:
            filters.append(f"status eq {quote_odata_string(status)}")
        filter_query = " and ".join(filters) if filters else None

        query_params = Alerts_v2RequestBuilder.Alerts_v2RequestBuilderGetQueryParameters(
            top=min(top, 100),
            filter=filter_query,
        )
        request_config = Alerts_v2RequestBuilder.Alerts_v2RequestBuilderGetRequestConfiguration(
            query_parameters=query_params,
        )
        alerts = await client.security.alerts_v2.get(request_configuration=request_config)
        if alerts and alerts.value:
            alert_list = [
                {
                    "id": a.id,
                    "title": a.title,
                    "severity": a.severity,
                    "status": a.status,
                    "category": a.category,
                    "createdDateTime": str(a.created_date_time),
                    "classification": a.classification,
                    "determination": a.determination,
                    "assignedTo": a.assigned_to,
                }
                for a in alerts.value
            ]
            return _json({"status": "success", "count": len(alert_list), "alerts": alert_list})
        return _json({"status": "success", "count": 0, "alerts": [], "message": "No alerts found"})
    except Exception as e:
        return _error_response("get_security_alerts", e)


@read_only_tool()
async def get_alert_details(
    alert_id: Annotated[str, Field(description="Unique alert identifier")],
) -> str:
    """Get detailed information about a specific security alert."""
    if not alert_id:
        return _json({"status": "error", "error": "alert_id is required"})
    try:
        client = get_graph_client()
        alert = await client.security.alerts_v2.by_alert_id(alert_id).get()
        if alert:
            details = {
                "id": alert.id,
                "title": alert.title,
                "description": alert.description,
                "severity": alert.severity,
                "status": alert.status,
                "category": alert.category,
                "createdDateTime": str(alert.created_date_time),
                "lastUpdateDateTime": str(alert.last_update_date_time),
                "classification": alert.classification,
                "determination": alert.determination,
                "assignedTo": alert.assigned_to,
                "detectorId": alert.detector_id,
                "threatFamilyName": alert.threat_family_name,
                "evidence": [str(e) for e in alert.evidence] if alert.evidence else [],
            }
            return _json({"status": "success", "alert": details})
        return _json({"status": "error", "error": "Alert not found"})
    except Exception as e:
        return _error_response("get_alert_details", e)


@read_only_tool()
async def get_alert_statistics(
    time_range: Annotated[str, Field(description="Time range: 1h|24h|7d|30d")] = "24h",
) -> str:
    """Get statistical summary of security alerts."""
    kql_time = {"1h": "1h", "24h": "1d", "7d": "7d", "30d": "30d"}.get(time_range, "1d")
    try:
        result = await _run_hunting(_build_alert_statistics_query(kql_time))
        stats = result.get("results", [{}])[0] if result.get("results") else {}
        return _json({"status": "success", "time_range": time_range, "statistics": stats})
    except Exception as e:
        return _error_response("get_alert_statistics", e)


# =========================================================================
# TOOLS — Threat Intelligence
# =========================================================================


@read_only_tool()
async def get_threat_indicators(
    top: ResultLimit100 = 50,
) -> str:
    """Retrieve Threat Intelligence Indicators (IoCs) from Microsoft Defender."""
    try:
        from msgraph.generated.security.threat_intelligence.intelligence_profile_indicators.intelligence_profile_indicators_request_builder import (
            IntelligenceProfileIndicatorsRequestBuilder,
        )

        client = get_graph_client()

        query_params = IntelligenceProfileIndicatorsRequestBuilder.IntelligenceProfileIndicatorsRequestBuilderGetQueryParameters(
            top=min(top, 100),
            select=["id", "source", "firstSeenDateTime", "lastSeenDateTime", "artifact"],
        )
        request_config = IntelligenceProfileIndicatorsRequestBuilder.IntelligenceProfileIndicatorsRequestBuilderGetRequestConfiguration(
            query_parameters=query_params,
        )
        indicators = await client.security.threat_intelligence.intelligence_profile_indicators.get(
            request_configuration=request_config
        )
        if indicators and indicators.value:
            lst = [
                {
                    "id": i.id,
                    "source": i.source,
                    "firstSeenDateTime": str(i.first_seen_date_time),
                    "lastSeenDateTime": str(i.last_seen_date_time),
                    "artifact": str(i.artifact) if i.artifact else None,
                }
                for i in indicators.value
            ]
            return _json({"status": "success", "count": len(lst), "indicators": lst})
        return _json({"status": "success", "count": 0, "indicators": []})
    except Exception as e:
        return _error_response("get_threat_indicators", e)


@read_only_tool()
async def enrich_ioc(
    ioc_value: Annotated[str, Field(description="The IoC value (IP, domain, URL, or file hash)")],
    ioc_type: Annotated[str, Field(description="Type: ip|domain|url|hash")],
) -> str:
    """Enrich an Indicator of Compromise with threat intelligence from Defender data."""
    if not ioc_value or not ioc_type:
        return _json({"status": "error", "error": "ioc_value and ioc_type are required"})
    ioc_literal = quote_kql_string(ioc_value)
    queries = {
        "hash": f"""
let iocHash = {ioc_literal};
union DeviceFileEvents, DeviceProcessEvents, DeviceImageLoadEvents
| where SHA256 =~ iocHash or SHA1 =~ iocHash or MD5 =~ iocHash
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp),
            Occurrences=count(), AffectedDevices=dcount(DeviceName),
            Devices=make_set(DeviceName,10) by SHA256, FileName""",
        "ip": f"""
let iocIP = {ioc_literal};
DeviceNetworkEvents
| where RemoteIP == iocIP or LocalIP == iocIP
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp),
            Connections=count(), AffectedDevices=dcount(DeviceName),
            Devices=make_set(DeviceName,10), Ports=make_set(RemotePort,20) by RemoteIP""",
        "domain": f"""
let iocDomain = {ioc_literal};
DeviceNetworkEvents
| where RemoteUrl has iocDomain
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp),
            Connections=count(), AffectedDevices=dcount(DeviceName),
            Devices=make_set(DeviceName,10), URLs=make_set(RemoteUrl,10) by RemoteUrl""",
        "url": f"""
let iocUrl = {ioc_literal};
union DeviceNetworkEvents, EmailUrlInfo
| where RemoteUrl =~ iocUrl or Url =~ iocUrl
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Occurrences=count()""",
    }
    query = queries.get(ioc_type)
    if not query:
        return _json({"status": "error", "error": f"Invalid ioc_type: {ioc_type}"})
    try:
        result = await _run_hunting(query)
        return _json(
            {
                "status": "success",
                "data": {
                    "ioc_value": ioc_value,
                    "ioc_type": ioc_type,
                    "enrichment": result.get("results", []),
                    "query_used": query,
                },
            }
        )
    except Exception as e:
        return _error_response("enrich_ioc", e)


@read_only_tool()
async def hunt_by_ioc(
    ioc_value: Annotated[str, Field(description="The IoC to hunt (IP, domain, URL, or hash)")],
    ioc_type: Annotated[str, Field(description="Type: ip|domain|url|hash|process")],
    days_back: DaysBack30 = 30,
) -> str:
    """Automatically hunt for an IoC across all relevant Defender tables."""
    if not ioc_value or not ioc_type:
        return _json({"status": "error", "error": "ioc_value and ioc_type required"})
    days = min(days_back, 30)
    ioc_literal = quote_kql_string(ioc_value)
    queries = {
        "hash": f"""
let ioc = {ioc_literal}; let tr = {days}d;
union
  (DeviceProcessEvents | where Timestamp > ago(tr) | where SHA256 =~ ioc or SHA1 =~ ioc or MD5 =~ ioc
   | project Timestamp, Table="Process", DeviceName, FileName, ProcessCommandLine, AccountName, SHA256),
  (DeviceFileEvents | where Timestamp > ago(tr) | where SHA256 =~ ioc or SHA1 =~ ioc or MD5 =~ ioc
   | project Timestamp, Table="File", DeviceName, FileName, FolderPath, ActionType, SHA256),
  (DeviceImageLoadEvents | where Timestamp > ago(tr) | where SHA256 =~ ioc or SHA1 =~ ioc or MD5 =~ ioc
   | project Timestamp, Table="ImageLoad", DeviceName, FileName, FolderPath, InitiatingProcessFileName, SHA256)
| sort by Timestamp desc | limit 1000""",
        "ip": f"""
let ioc = {ioc_literal};
DeviceNetworkEvents | where Timestamp > ago({days}d)
| where RemoteIP == ioc or LocalIP == ioc
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, LocalIP, LocalPort, Protocol, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp desc | limit 1000""",
        "domain": f"""
let ioc = {ioc_literal};
DeviceNetworkEvents | where Timestamp > ago({days}d) | where RemoteUrl has ioc
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine, ActionType
| sort by Timestamp desc | limit 1000""",
        "process": f"""
let ioc = {ioc_literal};
DeviceProcessEvents | where Timestamp > ago({days}d)
| where FileName =~ ioc or ProcessCommandLine has ioc
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName, InitiatingProcessFileName, SHA256
| sort by Timestamp desc | limit 1000""",
        "url": f"""
let ioc = {ioc_literal};
union DeviceNetworkEvents, EmailUrlInfo
| where Timestamp > ago({days}d)
| where RemoteUrl =~ ioc or Url =~ ioc
| project Timestamp, DeviceName, RemoteUrl, RemoteIP
| sort by Timestamp desc | limit 1000""",
    }
    query = queries.get(ioc_type)
    if not query:
        return _json({"status": "error", "error": f"Invalid ioc_type: {ioc_type}"})
    try:
        result = await _run_hunting(query)
        return _json(
            {
                "status": "success",
                "hunt_results": {
                    "ioc_value": ioc_value,
                    "ioc_type": ioc_type,
                    "days_searched": days,
                    "findings_count": result.get("rowCount", 0),
                    "findings": result.get("results", []),
                    "query_used": query,
                },
            }
        )
    except Exception as e:
        return _error_response("hunt_by_ioc", e)


# =========================================================================
# TOOLS — Security Posture
# =========================================================================


@read_only_tool()
async def get_security_recommendations(
    recommendation_category: Annotated[
        str | None, Field(description="Category: application|identity|data|device|network")
    ] = None,
    top: ResultLimit100 = 50,
) -> str:
    """Retrieve security recommendations from Microsoft Defender."""
    try:
        result, cache_metadata = await cached_operation(
            "secure_score_control_profiles",
            {"category": recommendation_category, "top": top},
            3600,
            lambda: _fetch_security_recommendations(recommendation_category, top),
        )
        return _json({**result, **cache_metadata})
    except Exception as e:
        return _error_response("get_security_recommendations", e)


async def _fetch_security_recommendations(
    recommendation_category: str | None,
    top: int,
) -> dict[str, Any]:
    from msgraph.generated.security.secure_score_control_profiles.secure_score_control_profiles_request_builder import (
        SecureScoreControlProfilesRequestBuilder,
    )

    query_params = SecureScoreControlProfilesRequestBuilder.SecureScoreControlProfilesRequestBuilderGetQueryParameters(
        top=min(top, 100),
        filter=f"controlCategory eq {quote_odata_string(recommendation_category)}"
        if recommendation_category
        else None,
    )
    request_config = SecureScoreControlProfilesRequestBuilder.SecureScoreControlProfilesRequestBuilderGetRequestConfiguration(
        query_parameters=query_params,
    )
    recs = await get_graph_client().security.secure_score_control_profiles.get(
        request_configuration=request_config
    )
    recommendations = [
        {
            "id": item.id,
            "title": item.title,
            "category": item.control_category,
            "service": item.service,
            "rank": item.rank,
            "maxScore": item.max_score,
            "implementationCost": str(item.implementation_cost),
            "userImpact": str(item.user_impact),
            "remediation": item.remediation,
            "remediationImpact": item.remediation_impact,
            "threats": [str(threat) for threat in (item.threats or [])],
            "lastModifiedDateTime": str(item.last_modified_date_time),
        }
        for item in (recs.value if recs and recs.value else [])
    ]
    return {
        "status": "success",
        "count": len(recommendations),
        "recommendations": recommendations,
    }


@read_only_tool()
async def get_device_info(
    device_name: Annotated[str, Field(description="Name or ID of the device")],
) -> str:
    """Get detailed information about a device/machine."""
    if not device_name:
        return _json({"status": "error", "error": "device_name is required"})
    try:
        device_literal = quote_kql_string(device_name)
        result = await _run_hunting(f"""
DeviceInfo
| where DeviceName =~ {device_literal} or DeviceId =~ {device_literal}
| top 1 by Timestamp desc
| project Timestamp, DeviceName, DeviceId, OSPlatform, OSVersion,
          OSArchitecture, IsAzureADJoined, MachineGroup, PublicIP, OnboardingStatus""")
        if result.get("results"):
            return _json({"status": "success", "device": result["results"][0]})
        return _json({"status": "error", "error": "Device not found"})
    except Exception as e:
        return _error_response("get_device_info", e)


@read_only_tool()
async def investigate_user_logon(
    username: Annotated[str, Field(description="Username or UPN to investigate")],
    days_back: DaysBack90 = 30,
) -> str:
    """Investigate Microsoft Entra sign-ins from Defender Advanced Hunting."""
    if not username:
        return "Error: username parameter is required"
    days = min(days_back, 90)
    hunting_days = min(days, 30)
    username_literal = quote_kql_string(username)
    if "@" in username:
        kql_filter_user = f"| where AccountUpn =~ {username_literal}"
    else:
        kql_filter_user = (
            f'| where tostring(split(AccountUpn, "@")[0]) =~ {username_literal} '
            f"or AccountDisplayName =~ {username_literal}"
        )
    try:
        kql = f"""
EntraIdSignInEvents
| where Timestamp > ago({hunting_days}d)
{kql_filter_user}
| project Timestamp, AccountDisplayName, AccountObjectId, AccountUpn,
          Application, ResourceDisplayName, ClientAppUsed, LogonType,
          DeviceName, OSPlatform, IPAddress, City, Country, ErrorCode,
          RiskLevelAggregated, RiskLevelDuringSignIn, RiskState,
          ConditionalAccessStatus
| sort by Timestamp desc
| limit 500"""
        result = await _run_hunting(kql)
        events = result.get("results", [])
        if not events:
            return await _investigate_entra_signins(username, min(days, 30))

        applications: dict[str, int] = {}
        resources: dict[str, int] = {}
        client_apps: dict[str, int] = {}
        logon_types: dict[str, int] = {}
        devices: dict[str, int] = {}
        ips: dict[str, int] = {}
        failed_logins: list[dict] = []
        recent_signins: list[dict] = []
        successful = 0
        failed = 0
        risky = 0

        for ev in events:
            d = (
                ev.additional_data
                if hasattr(ev, "additional_data")
                else ev
                if isinstance(ev, dict)
                else {}
            )
            error_code = int(d.get("ErrorCode") or 0)
            if error_code == 0:
                successful += 1
            else:
                failed += 1
                failed_logins.append(d)
            risk_values = (
                d.get("RiskLevelAggregated"),
                d.get("RiskLevelDuringSignIn"),
                d.get("RiskState"),
            )
            if any(
                str(value).casefold() not in {"", "0", "none", "unknown", "null"}
                for value in risk_values
            ):
                risky += 1

            for counts, value in (
                (applications, d.get("Application")),
                (resources, d.get("ResourceDisplayName")),
                (client_apps, d.get("ClientAppUsed")),
                (logon_types, d.get("LogonType")),
                (devices, d.get("DeviceName")),
                (ips, d.get("IPAddress")),
            ):
                if value:
                    key = str(value)
                    counts[key] = counts.get(key, 0) + 1
            if len(recent_signins) < 20:
                recent_signins.append(d)

        def top_counts(values: dict[str, int], limit: int = 10) -> list[dict[str, object]]:
            return [
                {"value": value, "count": count}
                for value, count in sorted(
                    values.items(), key=lambda item: item[1], reverse=True
                )[:limit]
            ]

        return _json(
            {
                "status": "success",
                "source": "defender_advanced_hunting_EntraIdSignInEvents",
                "username": username,
                "requestedDays": days,
                "analyzedDays": hunting_days,
                "count": len(events),
                "resultLimit": 500,
                "truncated": len(events) == 500,
                "successful": successful,
                "failed": failed,
                "risky": risky,
                "applications": top_counts(applications),
                "resources": top_counts(resources),
                "clientApps": top_counts(client_apps),
                "logonTypes": top_counts(logon_types),
                "devices": top_counts(devices),
                "ipAddresses": top_counts(ips),
                "failedSignIns": failed_logins[:20],
                "recentSignIns": recent_signins,
            }
        )
    except Exception as e:
        return _error_response("investigate_user_logon", e)


async def _investigate_entra_signins(username: str, days: int) -> str:
    """Analyze Entra sign-ins when Defender for Identity has no logon telemetry."""
    raw_result = await get_signin_logs(
        user_principal_name=username,
        status="all",
        risk_level="all",
        days_back=days,
        top=500,
    )
    payload = json.loads(raw_result)
    if payload.get("status") != "success":
        return raw_result

    normalized_username = username.casefold()
    logs = [
        log
        for log in payload.get("logs", [])
        if str(log.get("userPrincipalName", "")).casefold() == normalized_username
    ]
    if not logs:
        return _json(
            {
                "status": "success",
                "source": "microsoft_graph_auditLogs_signIns",
                "coverage": "IdentityLogonEvents had no matching telemetry; Entra sign-ins queried",
                "username": username,
                "days": days,
                "count": 0,
                "message": "No Microsoft Entra sign-ins found in the requested period",
            }
        )

    applications: dict[str, int] = {}
    client_apps: dict[str, int] = {}
    ip_addresses: dict[str, int] = {}
    locations: dict[str, int] = {}
    successful = 0
    failed = 0
    risky = 0
    for log in logs:
        status = log.get("status") or {}
        if status.get("errorCode") == 0:
            successful += 1
        else:
            failed += 1
        if log.get("riskLevel") and "none" not in str(log["riskLevel"]).casefold():
            risky += 1
        for counts, value in (
            (applications, log.get("appDisplayName")),
            (client_apps, log.get("clientAppUsed")),
            (ip_addresses, log.get("ipAddress")),
        ):
            if value:
                counts[str(value)] = counts.get(str(value), 0) + 1
        location = log.get("location") or {}
        location_name = ", ".join(
            str(location[key]) for key in ("city", "state", "country") if location.get(key)
        )
        if location_name:
            locations[location_name] = locations.get(location_name, 0) + 1

    def top_counts(values: dict[str, int], limit: int = 10) -> list[dict[str, object]]:
        return [
            {"value": value, "count": count}
            for value, count in sorted(values.items(), key=lambda item: item[1], reverse=True)[
                :limit
            ]
        ]

    return _json(
        {
            "status": "success",
            "source": "microsoft_graph_auditLogs_signIns",
            "coverage": "IdentityLogonEvents had no matching telemetry; Entra sign-ins queried",
            "username": username,
            "days": days,
            "count": len(logs),
            "successful": successful,
            "failed": failed,
            "risky": risky,
            "applications": top_counts(applications),
            "clientApps": top_counts(client_apps),
            "ipAddresses": top_counts(ip_addresses),
            "locations": top_counts(locations),
            "recentSignIns": logs[:20],
        }
    )


@read_only_tool()
async def get_environment_dashboard(
    time_range: Annotated[str, Field(description="Time range: 1h|24h|7d|30d")] = "24h",
) -> str:
    """Get comprehensive security dashboard overview of the environment."""
    kql_time = {"1h": "1h", "24h": "1d", "7d": "7d", "30d": "30d"}.get(time_range, "1d")
    lines = [
        "=" * 80,
        f"  SECURITY ENVIRONMENT DASHBOARD  |  Time Range: {time_range}",
        "=" * 80,
    ]
    try:
        # Alerts
        r = await _run_hunting(f"""
AlertInfo | where Timestamp > ago({kql_time})
| join kind=leftouter (AlertEvidence | where Timestamp > ago({kql_time}) | where isnotempty(DeviceId) | project AlertId, DeviceId) on AlertId
| summarize TotalAlerts=count(), HighSeverity=countif(Severity=="High"),
  MediumSeverity=countif(Severity=="Medium"), LowSeverity=countif(Severity=="Low"),
  UniqueDevices=dcount(DeviceId)""")
        if r.get("results"):
            d = (
                r["results"][0]
                if isinstance(r["results"][0], dict)
                else (
                    r["results"][0].additional_data
                    if hasattr(r["results"][0], "additional_data")
                    else {}
                )
            )
            lines.append(
                f"\n[ALERTS] Total: {d.get('TotalAlerts', 0)} | High: {d.get('HighSeverity', 0)} | Medium: {d.get('MediumSeverity', 0)} | Low: {d.get('LowSeverity', 0)} | Devices: {d.get('UniqueDevices', 0)}"
            )

        # Auth
        r = await _run_hunting(f"""
IdentityLogonEvents | where Timestamp > ago({kql_time})
| summarize TotalLogins=count(), Successful=countif(ActionType=="LogonSuccess"),
  Failed=countif(ActionType=="LogonFailed"), UniqueUsers=dcount(AccountName),
  Kerberos=countif(Protocol=="Kerberos"), NTLM=countif(Protocol=="Ntlm")""")
        if r.get("results"):
            d = (
                r["results"][0]
                if isinstance(r["results"][0], dict)
                else (
                    r["results"][0].additional_data
                    if hasattr(r["results"][0], "additional_data")
                    else {}
                )
            )
            lines.append(
                f"\n[AUTH] Logins: {d.get('TotalLogins', 0)} | OK: {d.get('Successful', 0)} | Failed: {d.get('Failed', 0)} | Users: {d.get('UniqueUsers', 0)} | Kerberos: {d.get('Kerberos', 0)} | NTLM: {d.get('NTLM', 0)}"
            )

        # Devices
        r = await _run_hunting(f"""
DeviceInfo | where Timestamp > ago({kql_time})
| summarize TotalDevices=dcount(DeviceName), Windows=dcountif(DeviceName, OSPlatform=="Windows"),
  Onboarded=dcountif(DeviceName, OnboardingStatus=="Onboarded")""")
        if r.get("results"):
            d = (
                r["results"][0]
                if isinstance(r["results"][0], dict)
                else (
                    r["results"][0].additional_data
                    if hasattr(r["results"][0], "additional_data")
                    else {}
                )
            )
            lines.append(
                f"\n[DEVICES] Total: {d.get('TotalDevices', 0)} | Windows: {d.get('Windows', 0)} | Onboarded: {d.get('Onboarded', 0)}"
            )

        # Network
        r = await _run_hunting(f"""
DeviceNetworkEvents | where Timestamp > ago({kql_time})
| summarize Total=count(), External=countif(RemoteIPType=="Public"), UniqueIPs=dcount(RemoteIP)""")
        if r.get("results"):
            d = (
                r["results"][0]
                if isinstance(r["results"][0], dict)
                else (
                    r["results"][0].additional_data
                    if hasattr(r["results"][0], "additional_data")
                    else {}
                )
            )
            lines.append(
                f"\n[NETWORK] Connections: {d.get('Total', 0)} | External: {d.get('External', 0)} | Unique IPs: {d.get('UniqueIPs', 0)}"
            )

        lines.append("\n" + "=" * 80)
        lines.append("Dashboard generated successfully")
        return "\n".join(lines)
    except Exception as e:
        return _error_response("get_environment_dashboard", e)


@read_only_tool()
async def analyze_security_posture(
    focus_area: Annotated[
        str, Field(description="Focus: all|identity|devices|network|applications")
    ] = "all",
) -> str:
    """Analyse overall security posture with actionable insights."""
    lines = ["=" * 80, f"  SECURITY POSTURE ANALYSIS | Focus: {focus_area.upper()}", "=" * 80]
    try:
        if focus_area in ("all", "identity"):
            r = await _run_hunting("""
IdentityLogonEvents | where Timestamp > ago(7d) | where ActionType == "LogonFailed"
| summarize Failed=count(), Users=dcount(AccountName), Devices=dcount(DeviceName)
| extend Risk = case(Failed > 100, "High", Failed > 50, "Medium", "Low")""")
            d = (r.get("results") or [{}])[0]
            d = (
                d
                if isinstance(d, dict)
                else (d.additional_data if hasattr(d, "additional_data") else {})
            )
            lines.append(
                f"\n[IDENTITY] Failed logins (7d): {d.get('Failed', 0)} | Risk: {d.get('Risk', 'Low')}"
            )

        if focus_area in ("all", "devices"):
            r = await _run_hunting("""
DeviceInfo | where Timestamp > ago(1d)
| summarize Total=dcount(DeviceName), Onboarded=dcountif(DeviceName, OnboardingStatus=="Onboarded")""")
            d = (r.get("results") or [{}])[0]
            d = (
                d
                if isinstance(d, dict)
                else (d.additional_data if hasattr(d, "additional_data") else {})
            )
            lines.append(
                f"\n[DEVICES] Total: {d.get('Total', 0)} | Onboarded: {d.get('Onboarded', 0)}"
            )

        if focus_area in ("all", "network"):
            r = await _run_hunting("""
DeviceNetworkEvents | where Timestamp > ago(24h) | where RemoteIPType == "Public"
| where RemotePort in (22,23,3389,445,135)
| summarize HighRisk=count(), UniqueIPs=dcount(RemoteIP)""")
            d = (r.get("results") or [{}])[0]
            d = (
                d
                if isinstance(d, dict)
                else (d.additional_data if hasattr(d, "additional_data") else {})
            )
            risky = d.get("HighRisk", 0)
            lines.append(f"\n[NETWORK] High-risk port connections (24h): {risky}")
            if risky:
                lines.append("  -> Review firewall rules and restrict exposure")

        lines += [
            "\n--- RECOMMENDATIONS ---",
            "  1. Enable MFA for all users",
            "  2. Keep all devices on latest security updates",
            "  3. Monitor failed logins regularly",
            "  4. Migrate NTLM -> Kerberos",
            "  5. Minimise high-risk port exposure",
            "=" * 80,
        ]
        return "\n".join(lines)
    except Exception as e:
        return _error_response("analyze_security_posture", e)


# =========================================================================
# TOOLS — Microsoft Entra ID
# =========================================================================


async def _fetch_directory_role_definitions() -> list[dict[str, Any]]:
    """Return compact, JSON-serializable directory role definitions for caching."""
    from msgraph.generated.role_management.directory.role_definitions.role_definitions_request_builder import (
        RoleDefinitionsRequestBuilder,
    )

    qp = RoleDefinitionsRequestBuilder.RoleDefinitionsRequestBuilderGetQueryParameters(
        select=["id", "displayName", "templateId", "isBuiltIn"], top=500
    )
    cfg = RoleDefinitionsRequestBuilder.RoleDefinitionsRequestBuilderGetRequestConfiguration(
        query_parameters=qp
    )
    result = await get_graph_client().role_management.directory.role_definitions.get(
        request_configuration=cfg
    )
    return [
        {
            "id": item.id,
            "displayName": item.display_name,
            "templateId": item.template_id,
            "isBuiltIn": item.is_built_in,
        }
        for item in (result.value if result and result.value else [])
    ]


@read_only_tool()
async def get_users_by_directory_role(
    role: Annotated[
        str,
        Field(
            min_length=2,
            max_length=256,
            description="Exact directory role display name or template ID, for example Global Administrator",
        ),
    ],
    assignment_state: Annotated[
        RoleAssignmentState,
        Field(description="active|eligible|all; eligible includes PIM eligibility"),
    ] = "active",
    expand_group_members: Annotated[
        bool,
        Field(description="Resolve users inherited through role-assignable groups"),
    ] = True,
    top: ResultLimit200 = 100,
) -> str:
    """List who holds an admin role: users, groups, and service principals assigned or PIM-eligible for a Microsoft Entra directory role such as Global Administrator. Use this to answer "who are the global admins / role members"."""
    top = min(top, 200)
    try:
        client = get_graph_client()
        definitions, _ = await cached_operation(
            "directory_role_definitions",
            {},
            3600,
            _fetch_directory_role_definitions,
        )
        normalized_role = role.casefold()
        definition = next(
            (
                item
                for item in definitions
                if normalized_role
                in {
                    (item["displayName"] or "").casefold(),
                    (item["templateId"] or "").casefold(),
                }
            ),
            None,
        )
        if definition is None:
            return _json(
                {
                    "status": "success",
                    "count": 0,
                    "message": f"Directory role not found: {role}",
                }
            )

        assignments: list[tuple[str, Any]] = []
        assignment_filter = f"roleDefinitionId eq {quote_odata_string(definition['id'])}"
        if assignment_state in {"active", "all"}:
            from msgraph.generated.role_management.directory.role_assignments.role_assignments_request_builder import (
                RoleAssignmentsRequestBuilder,
            )

            active_qp = RoleAssignmentsRequestBuilder.RoleAssignmentsRequestBuilderGetQueryParameters(
                filter=assignment_filter, expand=["principal"], top=top
            )
            active_cfg = RoleAssignmentsRequestBuilder.RoleAssignmentsRequestBuilderGetRequestConfiguration(
                query_parameters=active_qp
            )
            active = await client.role_management.directory.role_assignments.get(
                request_configuration=active_cfg
            )
            assignments.extend(
                ("active", item) for item in (active.value if active and active.value else [])
            )

        if assignment_state in {"eligible", "all"}:
            from msgraph.generated.role_management.directory.role_eligibility_schedule_instances.role_eligibility_schedule_instances_request_builder import (
                RoleEligibilityScheduleInstancesRequestBuilder,
            )

            eligible_qp = RoleEligibilityScheduleInstancesRequestBuilder.RoleEligibilityScheduleInstancesRequestBuilderGetQueryParameters(
                filter=assignment_filter, expand=["principal"], top=top
            )
            eligible_cfg = RoleEligibilityScheduleInstancesRequestBuilder.RoleEligibilityScheduleInstancesRequestBuilderGetRequestConfiguration(
                query_parameters=eligible_qp
            )
            eligible = await client.role_management.directory.role_eligibility_schedule_instances.get(
                request_configuration=eligible_cfg
            )
            assignments.extend(
                ("eligible", item)
                for item in (eligible.value if eligible and eligible.value else [])
            )

        principals: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for state, assignment in assignments:
            principal = assignment.principal
            if principal is None or not principal.id or (principal.id, state) in seen:
                continue
            seen.add((principal.id, state))
            principal_type = type(principal).__name__.removesuffix("able")
            principals.append(
                {
                    "id": principal.id,
                    "displayName": getattr(principal, "display_name", None),
                    "userPrincipalName": getattr(principal, "user_principal_name", None),
                    "principalType": principal_type,
                    "assignmentState": state,
                    "assignmentVia": "direct",
                    "directoryScopeId": getattr(assignment, "directory_scope_id", None),
                }
            )

        group_resolution_errors: list[dict[str, str]] = []
        inherited_users: list[dict[str, Any]] = []
        if expand_group_members:
            from msgraph.generated.groups.item.transitive_members.transitive_members_request_builder import (
                TransitiveMembersRequestBuilder,
            )

            group_query = TransitiveMembersRequestBuilder.TransitiveMembersRequestBuilderGetQueryParameters(
                top=top
            )
            group_config = TransitiveMembersRequestBuilder.TransitiveMembersRequestBuilderGetRequestConfiguration(
                query_parameters=group_query
            )
            for group in (item for item in principals if item["principalType"] == "Group"):
                try:
                    group_members = await client.groups.by_group_id(
                        group["id"]
                    ).transitive_members.get(request_configuration=group_config)
                    for member in (
                        group_members.value if group_members and group_members.value else []
                    ):
                        if type(member).__name__.removesuffix("able") != "User":
                            continue
                        inherited_users.append(
                            {
                                "id": member.id,
                                "displayName": getattr(member, "display_name", None),
                                "userPrincipalName": getattr(member, "user_principal_name", None),
                                "principalType": "User",
                                "assignmentState": group["assignmentState"],
                                "assignmentVia": {
                                    "groupId": group["id"],
                                    "groupDisplayName": group["displayName"],
                                },
                                "directoryScopeId": group["directoryScopeId"],
                            }
                        )
                except Exception as error:
                    logger.warning(
                        "Directory role group expansion failed for %s: %s", group["id"], error
                    )
                    group_resolution_errors.append(
                        {"groupId": group["id"], "error": "Group members unavailable"}
                    )

        users = [item for item in principals if item["principalType"] == "User"]
        user_keys = {(item["id"], item["assignmentState"]) for item in users}
        for inherited_user in inherited_users:
            key = (inherited_user["id"], inherited_user["assignmentState"])
            if key not in user_keys:
                user_keys.add(key)
                users.append(inherited_user)

        return _json(
            {
                "status": "success",
                "role": {
                    "id": definition["id"],
                    "displayName": definition["displayName"],
                    "templateId": definition["templateId"],
                    "isBuiltIn": definition["isBuiltIn"],
                },
                "assignmentState": assignment_state,
                "count": len(principals),
                "userCount": len(users),
                "users": users,
                "groupAssignments": [
                    item for item in principals if item["principalType"] == "Group"
                ],
                "groupResolutionErrors": group_resolution_errors,
                "otherPrincipals": [
                    item
                    for item in principals
                    if item["principalType"] not in {"User", "Group"}
                ],
            }
        )
    except Exception as e:
        return _error_response("get_users_by_directory_role", e)


@read_only_tool()
async def list_identity_groups(
    display_name_prefix: Annotated[
        str | None,
        Field(
            min_length=1,
            max_length=256,
            description="Optional case-insensitive display name prefix",
        ),
    ] = None,
    group_type: Annotated[
        IdentityGroupType,
        Field(description="all|security|microsoft365|role_assignable"),
    ] = "all",
    top: ResultLimit200 = 100,
) -> str:
    """List Microsoft Entra groups for identity and access analysis."""
    top = min(top, 200)
    try:
        client = get_graph_client()
        from msgraph.generated.groups.groups_request_builder import GroupsRequestBuilder

        filters = []
        if display_name_prefix:
            filters.append(
                f"startswith(displayName, {quote_odata_string(display_name_prefix)})"
            )
        if group_type == "security":
            filters.append("securityEnabled eq true")
        elif group_type == "microsoft365":
            filters.append("groupTypes/any(value:value eq 'Unified')")
        elif group_type == "role_assignable":
            filters.append("isAssignableToRole eq true")

        query = GroupsRequestBuilder.GroupsRequestBuilderGetQueryParameters(
            filter=" and ".join(filters) if filters else None,
            select=[
                "id",
                "displayName",
                "description",
                "mail",
                "mailEnabled",
                "securityEnabled",
                "groupTypes",
                "membershipRule",
                "membershipRuleProcessingState",
                "isAssignableToRole",
            ],
            top=top,
        )
        config = GroupsRequestBuilder.GroupsRequestBuilderGetRequestConfiguration(
            query_parameters=query
        )
        result = await client.groups.get(request_configuration=config)
        groups = [
            {
                "id": group.id,
                "displayName": group.display_name,
                "description": group.description,
                "mail": group.mail,
                "mailEnabled": group.mail_enabled,
                "securityEnabled": group.security_enabled,
                "groupTypes": group.group_types or [],
                "membershipType": "dynamic" if group.membership_rule else "assigned",
                "membershipRule": group.membership_rule,
                "membershipRuleProcessingState": str(group.membership_rule_processing_state)
                if group.membership_rule_processing_state
                else None,
                "isAssignableToRole": group.is_assignable_to_role,
            }
            for group in (result.value if result and result.value else [])
        ]
        return _json(
            {
                "status": "success",
                "count": len(groups),
                "truncated": len(groups) == top,
                "groupType": group_type,
                "groups": groups,
            }
        )
    except Exception as e:
        return _error_response("list_identity_groups", e)


def _directory_principal_summary(principal: Any) -> dict[str, Any]:
    principal_type = type(principal).__name__.removesuffix("able")
    return {
        "id": principal.id,
        "displayName": getattr(principal, "display_name", None),
        "principalType": principal_type,
        "userPrincipalName": getattr(principal, "user_principal_name", None),
        "mail": getattr(principal, "mail", None),
        "accountEnabled": getattr(principal, "account_enabled", None),
    }


def _authentication_method_summary(method: Any) -> dict[str, Any]:
    method_type = type(method).__name__.removesuffix("able")
    return {
        "id": method.id,
        "type": method_type,
        "displayName": getattr(method, "display_name", None),
        "createdDateTime": str(getattr(method, "created_date_time", None) or "") or None,
        "model": getattr(method, "model", None),
        "phoneType": str(getattr(method, "phone_type", None) or "") or None,
        "keyStrength": str(getattr(method, "key_strength", None) or "") or None,
    }


def _identity_key(user_id: str | None, upn: str | None) -> str:
    if bool(user_id) == bool(upn):
        raise ValueError("Provide exactly one of user_id or upn")
    return user_id or upn or ""


def _directory_object_summary(value: Any) -> dict[str, Any]:
    return {
        "id": value.id,
        "type": type(value).__name__.removesuffix("able"),
        "displayName": getattr(value, "display_name", None),
        "userPrincipalName": getattr(value, "user_principal_name", None),
        "appId": getattr(value, "app_id", None),
        "mail": getattr(value, "mail", None),
    }


def _role_assignment_summary(assignment: Any, state: str) -> dict[str, Any]:
    definition = getattr(assignment, "role_definition", None)
    return {
        "id": assignment.id,
        "assignmentState": state,
        "roleDefinitionId": getattr(assignment, "role_definition_id", None),
        "roleDisplayName": getattr(definition, "display_name", None),
        "roleTemplateId": getattr(definition, "template_id", None),
        "directoryScopeId": getattr(assignment, "directory_scope_id", None),
        "memberType": str(getattr(assignment, "member_type", None) or "") or None,
        "startDateTime": str(getattr(assignment, "start_date_time", None) or "") or None,
        "endDateTime": str(getattr(assignment, "end_date_time", None) or "") or None,
    }


async def _fetch_user_directory_roles(
    client: GraphServiceClient,
    user_id: str,
    top: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    from msgraph.generated.role_management.directory.role_assignments.role_assignments_request_builder import (
        RoleAssignmentsRequestBuilder,
    )
    from msgraph.generated.role_management.directory.role_eligibility_schedule_instances.role_eligibility_schedule_instances_request_builder import (
        RoleEligibilityScheduleInstancesRequestBuilder,
    )

    role_filter = f"principalId eq {quote_odata_string(user_id)}"
    active_query = RoleAssignmentsRequestBuilder.RoleAssignmentsRequestBuilderGetQueryParameters(
        filter=role_filter,
        expand=["roleDefinition"],
        top=top,
    )
    active_config = RoleAssignmentsRequestBuilder.RoleAssignmentsRequestBuilderGetRequestConfiguration(
        query_parameters=active_query
    )
    eligible_query = RoleEligibilityScheduleInstancesRequestBuilder.RoleEligibilityScheduleInstancesRequestBuilderGetQueryParameters(
        filter=role_filter,
        expand=["roleDefinition"],
        top=top,
    )
    eligible_config = RoleEligibilityScheduleInstancesRequestBuilder.RoleEligibilityScheduleInstancesRequestBuilderGetRequestConfiguration(
        query_parameters=eligible_query
    )
    active_result, eligible_result = await asyncio.gather(
        client.role_management.directory.role_assignments.get(
            request_configuration=active_config
        ),
        client.role_management.directory.role_eligibility_schedule_instances.get(
            request_configuration=eligible_config
        ),
    )
    active = [
        _role_assignment_summary(item, "active")
        for item in (active_result.value if active_result and active_result.value else [])
    ]
    eligible = [
        _role_assignment_summary(item, "eligible")
        for item in (eligible_result.value if eligible_result and eligible_result.value else [])
    ]
    return active, eligible


@read_only_tool()
async def get_identity_context(
    user_id: Annotated[
        str | None,
        Field(min_length=1, max_length=256, description="Microsoft Entra user object ID"),
    ] = None,
    upn: Annotated[
        str | None,
        Field(min_length=3, max_length=320, description="User principal name"),
    ] = None,
    top: ResultLimit200 = 100,
) -> dict[str, Any]:
    """Return consolidated user, organization, group, role, license, and ownership context."""
    try:
        identity_key = _identity_key(user_id, upn)
    except ValueError as error:
        return {"status": "error", "error": str(error), "error_code": "INVALID_IDENTITY_KEY"}

    client = get_graph_client()
    user_request = client.users.by_user_id(identity_key)
    from msgraph.generated.users.item.user_item_request_builder import UserItemRequestBuilder

    user_query = UserItemRequestBuilder.UserItemRequestBuilderGetQueryParameters(
        select=[
            "id",
            "displayName",
            "userPrincipalName",
            "mail",
            "accountEnabled",
            "userType",
            "jobTitle",
            "department",
            "companyName",
            "officeLocation",
            "employeeId",
            "createdDateTime",
        ]
    )
    user_config = UserItemRequestBuilder.UserItemRequestBuilderGetRequestConfiguration(
        query_parameters=user_query
    )
    source_names = (
        "profile",
        "manager",
        "direct_reports",
        "groups",
        "ownerships",
        "licenses",
        "app_roles",
    )
    calls = (
        user_request.get(request_configuration=user_config),
        user_request.manager.get(),
        user_request.direct_reports.get(),
        user_request.member_of.get(),
        user_request.owned_objects.get(),
        user_request.license_details.get(),
        user_request.app_role_assignments.get(),
    )
    values = await asyncio.gather(*calls, return_exceptions=True)
    results = dict(zip(source_names, values, strict=True))
    errors = [
        {"source": name, "error": "Source unavailable"}
        for name, value in results.items()
        if isinstance(value, Exception)
    ]
    profile = results["profile"]
    if isinstance(profile, Exception):
        logger.error("Identity profile lookup failed: %s", profile)
        return {
            "status": "error",
            "error": "Identity profile unavailable",
            "error_code": "IDENTITY_NOT_FOUND_OR_UNAUTHORIZED",
        }

    try:
        active_roles, eligible_roles = await _fetch_user_directory_roles(
            client, profile.id, min(top, 200)
        )
    except Exception as error:
        logger.warning("Directory role context lookup failed: %s", error)
        active_roles, eligible_roles = [], []
        errors.append({"source": "directory_roles", "error": "Source unavailable"})

    def collection(name: str) -> list[Any]:
        value = results[name]
        return [] if isinstance(value, Exception) or not value else value.value or []

    manager = results["manager"]
    license_details = collection("licenses")
    app_role_assignments = collection("app_roles")
    return {
        "status": "success" if not errors else "partial_success",
        "profile": {
            "id": profile.id,
            "displayName": profile.display_name,
            "userPrincipalName": profile.user_principal_name,
            "mail": profile.mail,
            "accountEnabled": profile.account_enabled,
            "userType": str(profile.user_type) if profile.user_type else None,
            "jobTitle": profile.job_title,
            "department": profile.department,
            "companyName": profile.company_name,
            "officeLocation": profile.office_location,
            "employeeId": profile.employee_id,
            "createdDateTime": str(profile.created_date_time)
            if profile.created_date_time
            else None,
        },
        "groups": [
            _directory_object_summary(item)
            for item in collection("groups")
            if type(item).__name__.removesuffix("able") == "Group"
        ],
        "directory_roles": {
            "active": active_roles,
            "eligible": eligible_roles,
        },
        "app_roles": [
            {
                "id": item.id,
                "appRoleId": item.app_role_id,
                "resourceId": item.resource_id,
                "resourceDisplayName": item.resource_display_name,
                "createdDateTime": str(item.created_date_time)
                if item.created_date_time
                else None,
            }
            for item in app_role_assignments
        ],
        "licenses": [
            {
                "id": item.id,
                "skuId": item.sku_id,
                "skuPartNumber": item.sku_part_number,
                "servicePlans": [
                    {
                        "servicePlanName": plan.service_plan_name,
                        "provisioningStatus": str(plan.provisioning_status)
                        if plan.provisioning_status
                        else None,
                    }
                    for plan in (item.service_plans or [])
                ],
            }
            for item in license_details
        ],
        "manager": None
        if isinstance(manager, Exception) or manager is None
        else _directory_object_summary(manager),
        "direct_reports": [
            _directory_object_summary(item) for item in collection("direct_reports")
        ][:top],
        "ownerships": [
            _directory_object_summary(item) for item in collection("ownerships")
        ][:top],
        "errors": errors,
    }


@read_only_tool()
async def get_authentication_posture(
    user_id: Annotated[
        str,
        Field(
            min_length=1,
            max_length=320,
            description="Microsoft Entra user object ID or user principal name",
        ),
    ],
) -> dict[str, Any]:
    """Assess registered authentication methods and passwordless readiness for one user."""
    client = get_graph_client()
    user_request = client.users.by_user_id(user_id)
    methods_call = user_request.authentication.methods.get()
    registration_call = client.reports.authentication_methods.user_registration_details.by_user_registration_details_id(
        user_id
    ).get()
    methods_result, registration = await asyncio.gather(
        methods_call,
        registration_call,
        return_exceptions=True,
    )

    errors: list[dict[str, str]] = []
    methods: list[dict[str, Any]] = []
    if isinstance(methods_result, Exception):
        logger.warning("Authentication method lookup failed: %s", methods_result)
        errors.append({"source": "authentication_methods", "error": "Methods unavailable"})
    else:
        methods = [
            _authentication_method_summary(method)
            for method in (
                methods_result.value
                if methods_result and methods_result.value
                else []
            )
        ]

    registration_available = not isinstance(registration, Exception)
    if not registration_available:
        logger.warning("Authentication registration report lookup failed: %s", registration)
        errors.append(
            {"source": "user_registration_details", "error": "Registration report unavailable"}
        )
        registration = None

    method_types = {method["type"] for method in methods}
    fido2_registered = "Fido2AuthenticationMethod" in method_types
    whfb_enabled = "WindowsHelloForBusinessAuthenticationMethod" in method_types
    methods_registered = [
        str(value) for value in (getattr(registration, "methods_registered", None) or [])
    ]
    passwordless_capable = (
        getattr(registration, "is_passwordless_capable", None)
        if registration_available
        else fido2_registered or whfb_enabled
    )
    return {
        "status": "success" if not errors else "partial_success",
        "user_id": getattr(registration, "id", None) or user_id,
        "mfa_enabled": getattr(registration, "is_mfa_registered", None),
        "mfa_capable": getattr(registration, "is_mfa_capable", None),
        "authentication_methods": methods,
        "methods_registered": methods_registered,
        "fido2_registered": fido2_registered,
        "passkeys_registered": fido2_registered,
        "whfb_enabled": whfb_enabled,
        "passwordless_status": {
            "capable": passwordless_capable,
            "systemPreferredEnabled": getattr(
                registration, "is_system_preferred_authentication_method_enabled", None
            ),
            "defaultMfaMethod": str(
                getattr(registration, "default_mfa_method", None) or ""
            )
            or None,
        },
        "assessment_basis": (
            "mfa_enabled represents Entra MFA registration, not Conditional Access enforcement"
        ),
        "errors": errors,
    }


def _time_range_start(time_range: IdentityTimeRange) -> datetime:
    delta = {
        "1h": timedelta(hours=1),
        "24h": timedelta(days=1),
        "7d": timedelta(days=7),
        "30d": timedelta(days=30),
        "90d": timedelta(days=90),
    }[time_range]
    return datetime.now(UTC) - delta


@read_only_tool()
async def get_signin_activity(
    user_id: Annotated[str, Field(min_length=1, max_length=256)],
    time_range: IdentityTimeRange = "7d",
    top: ResultLimit500 = 100,
) -> dict[str, Any]:
    """Return recent sign-ins and compact identity authentication aggregates."""
    from msgraph.generated.audit_logs.sign_ins.sign_ins_request_builder import (
        SignInsRequestBuilder,
    )

    start = _time_range_start(time_range).strftime("%Y-%m-%dT%H:%M:%SZ")
    query = SignInsRequestBuilder.SignInsRequestBuilderGetQueryParameters(
        filter=(
            f"userId eq {quote_odata_string(user_id)} and createdDateTime ge {start}"
        ),
        orderby=["createdDateTime desc"],
        top=min(top, 500),
    )
    config = SignInsRequestBuilder.SignInsRequestBuilderGetRequestConfiguration(
        query_parameters=query
    )
    result = await get_graph_client().audit_logs.sign_ins.get(request_configuration=config)
    signins = []
    applications: set[str] = set()
    devices: set[str] = set()
    locations: set[str] = set()
    ip_addresses: set[str] = set()
    risk_indicators: list[dict[str, Any]] = []
    for signin in (result.value if result and result.value else []):
        location = signin.location
        device = signin.device_detail
        status = signin.status
        location_name = ", ".join(
            part
            for part in (
                getattr(location, "city", None),
                getattr(location, "state", None),
                getattr(location, "country_or_region", None),
            )
            if part
        )
        device_name = getattr(device, "display_name", None) or getattr(
            device, "device_id", None
        )
        entry = {
            "id": signin.id,
            "createdDateTime": str(signin.created_date_time),
            "appId": signin.app_id,
            "appDisplayName": signin.app_display_name,
            "ipAddress": signin.ip_address,
            "location": location_name or None,
            "device": {
                "id": getattr(device, "device_id", None),
                "displayName": getattr(device, "display_name", None),
                "operatingSystem": getattr(device, "operating_system", None),
                "isManaged": getattr(device, "is_managed", None),
                "isCompliant": getattr(device, "is_compliant", None),
            }
            if device
            else None,
            "result": {
                "errorCode": getattr(status, "error_code", None),
                "failureReason": getattr(status, "failure_reason", None),
            },
            "riskLevel": str(signin.risk_level_during_sign_in)
            if signin.risk_level_during_sign_in
            else None,
            "riskState": str(signin.risk_state) if signin.risk_state else None,
            "conditionalAccessStatus": str(signin.conditional_access_status)
            if signin.conditional_access_status
            else None,
        }
        signins.append(entry)
        if signin.app_display_name:
            applications.add(signin.app_display_name)
        if device_name:
            devices.add(device_name)
        if location_name:
            locations.add(location_name)
        if signin.ip_address:
            ip_addresses.add(signin.ip_address)
        if entry["riskLevel"] not in {None, "none", "unknownFutureValue"}:
            risk_indicators.append(
                {
                    "signinId": signin.id,
                    "riskLevel": entry["riskLevel"],
                    "riskState": entry["riskState"],
                }
            )
    return {
        "status": "success",
        "user_id": user_id,
        "time_range": time_range,
        "count": len(signins),
        "truncated": len(signins) == min(top, 500),
        "signins": signins,
        "applications": sorted(applications),
        "devices": sorted(devices),
        "locations": sorted(locations),
        "ip_addresses": sorted(ip_addresses),
        "risk_indicators": risk_indicators,
    }


@read_only_tool()
async def get_applied_conditional_access(
    signin_id: Annotated[str, Field(min_length=1, max_length=256)],
) -> dict[str, Any]:
    """Return Conditional Access policies evaluated for one Entra sign-in."""
    signin = await get_graph_client().audit_logs.sign_ins.by_sign_in_id(signin_id).get()
    policies = [
        {
            "id": policy.id,
            "displayName": policy.display_name,
            "result": str(policy.result) if policy.result else None,
            "enforcedGrantControls": policy.enforced_grant_controls or [],
            "enforcedSessionControls": policy.enforced_session_controls or [],
        }
        for policy in (signin.applied_conditional_access_policies or [])
    ]
    return {
        "status": "success",
        "signin_id": signin.id,
        "user_id": signin.user_id,
        "conditional_access_status": str(signin.conditional_access_status)
        if signin.conditional_access_status
        else None,
        "policies": policies,
        "evaluation_results": [
            {"policyId": policy["id"], "result": policy["result"]} for policy in policies
        ],
        "controls_applied": sorted(
            {
                control
                for policy in policies
                for control in (
                    policy["enforcedGrantControls"] + policy["enforcedSessionControls"]
                )
            }
        ),
    }


@read_only_tool()
async def get_pim_eligibility(
    user_id: Annotated[str, Field(min_length=1, max_length=256)],
    top: ResultLimit200 = 100,
) -> dict[str, Any]:
    """Return active and eligible Entra directory-role assignments for one user."""
    active, eligible = await _fetch_user_directory_roles(
        get_graph_client(), user_id, min(top, 200)
    )
    return {
        "status": "success",
        "user_id": user_id,
        "eligible_roles": eligible,
        "active_roles": active,
        "assignment_type": {
            "active": len(active),
            "eligible": len(eligible),
        },
        "expiration": [
            {"role": item["roleDisplayName"], "endDateTime": item["endDateTime"]}
            for item in [*active, *eligible]
            if item["endDateTime"]
        ],
    }


@read_only_tool()
async def get_privileged_access(
    user_id: Annotated[str, Field(min_length=1, max_length=256)],
    top: ResultLimit200 = 100,
) -> dict[str, Any]:
    """List directory roles and role-assignable groups held by one identity."""
    client = get_graph_client()
    active, eligible = await _fetch_user_directory_roles(client, user_id, min(top, 200))
    memberships = await client.users.by_user_id(user_id).transitive_member_of.get()
    privileged_groups = [
        _directory_object_summary(group)
        for group in (memberships.value if memberships and memberships.value else [])
        if type(group).__name__.removesuffix("able") == "Group"
        and getattr(group, "is_assignable_to_role", False)
    ][:top]
    critical_terms = ("global", "privileged", "security", "authentication", "exchange")
    critical_permissions = [
        role
        for role in [*active, *eligible]
        if any(
            term in str(role.get("roleDisplayName") or "").casefold()
            for term in critical_terms
        )
    ]
    return {
        "status": "success",
        "user_id": user_id,
        "privileged_roles": {"active": active, "eligible": eligible},
        "privileged_groups": privileged_groups,
        "critical_permissions": critical_permissions,
        "analysis_basis": "Name-based prioritization; verify custom role actions and scoped assignments",
    }


def _pim_activation_summary(request: Any) -> dict[str, Any]:
    definition = getattr(request, "role_definition", None)
    schedule = getattr(request, "schedule_info", None)
    expiration = getattr(schedule, "expiration", None)
    return {
        "id": request.id,
        "action": str(getattr(request, "action", None) or "") or None,
        "status": str(getattr(request, "status", None) or "") or None,
        "roleDefinitionId": getattr(request, "role_definition_id", None),
        "roleDisplayName": getattr(definition, "display_name", None),
        "directoryScopeId": getattr(request, "directory_scope_id", None),
        "justification": getattr(request, "justification", None),
        "createdDateTime": str(getattr(request, "created_date_time", None) or "") or None,
        "activationDuration": str(getattr(expiration, "duration", None) or "") or None,
        "expirationDateTime": str(getattr(expiration, "end_date_time", None) or "") or None,
    }


@read_only_tool()
async def get_pim_activations(
    user_id: Annotated[str, Field(min_length=1, max_length=256)],
    time_range: IdentityTimeRange = "30d",
    top: ResultLimit200 = 100,
) -> dict[str, Any]:
    """Return bounded PIM self-activation request history for one user."""
    from msgraph.generated.role_management.directory.role_assignment_schedule_requests.role_assignment_schedule_requests_request_builder import (
        RoleAssignmentScheduleRequestsRequestBuilder,
    )

    start = _time_range_start(time_range).strftime("%Y-%m-%dT%H:%M:%SZ")
    query = RoleAssignmentScheduleRequestsRequestBuilder.RoleAssignmentScheduleRequestsRequestBuilderGetQueryParameters(
        filter=(
            f"principalId eq {quote_odata_string(user_id)} and action eq 'selfActivate' "
            f"and createdDateTime ge {start}"
        ),
        expand=["roleDefinition"],
        orderby=["createdDateTime desc"],
        top=min(top, 200),
    )
    config = RoleAssignmentScheduleRequestsRequestBuilder.RoleAssignmentScheduleRequestsRequestBuilderGetRequestConfiguration(
        query_parameters=query
    )
    result = await get_graph_client().role_management.directory.role_assignment_schedule_requests.get(
        request_configuration=config
    )
    activations = [
        _pim_activation_summary(item)
        for item in (result.value if result and result.value else [])
    ]
    return {
        "status": "success",
        "user_id": user_id,
        "time_range": time_range,
        "count": len(activations),
        "truncated": len(activations) == min(top, 200),
        "activations": activations,
        "activated_roles": sorted(
            {item["roleDisplayName"] for item in activations if item["roleDisplayName"]}
        ),
    }


_PRIVILEGED_ROLE_TERMS = (
    "global administrator",
    "privileged role",
    "privileged authentication",
    "security administrator",
    "exchange administrator",
    "application administrator",
    "cloud application administrator",
    "user administrator",
    "conditional access",
    "intune administrator",
    "sharepoint administrator",
    "helpdesk administrator",
    "authentication administrator",
    "hybrid identity",
    "domain name administrator",
    "partner tier2 support",
)
_WEAK_AUTH_METHOD_IDS = {"Sms", "Voice", "Email"}
_HIGH_RISK_OAUTH_SCOPE_TERMS = (
    "mail.read",
    "mail.readwrite",
    "mail.send",
    "files.read",
    "files.readwrite",
    "mailboxsettings",
    "offline_access",
    "directory.read",
    "directory.readwrite",
    "user.read.all",
    "full_access_as_user",
)


@read_only_tool()
async def get_user_app_role_assignments(
    user_id: Annotated[str, Field(min_length=1, max_length=256)],
    top: ResultLimit200 = 100,
) -> dict[str, Any]:
    """List enterprise application (app role) assignments granted to one user."""
    from msgraph.generated.users.item.app_role_assignments.app_role_assignments_request_builder import (
        AppRoleAssignmentsRequestBuilder,
    )

    query = AppRoleAssignmentsRequestBuilder.AppRoleAssignmentsRequestBuilderGetQueryParameters(
        top=min(top, 200)
    )
    config = AppRoleAssignmentsRequestBuilder.AppRoleAssignmentsRequestBuilderGetRequestConfiguration(
        query_parameters=query
    )
    result = (
        await get_graph_client()
        .users.by_user_id(user_id)
        .app_role_assignments.get(request_configuration=config)
    )
    assignments = [
        {
            "id": item.id,
            "appRoleId": str(item.app_role_id) if item.app_role_id else None,
            "principalId": item.principal_id,
            "principalDisplayName": item.principal_display_name,
            "resourceId": item.resource_id,
            "resourceDisplayName": item.resource_display_name,
            "createdDateTime": str(item.created_date_time) if item.created_date_time else None,
        }
        for item in (result.value if result and result.value else [])
    ]
    return {
        "status": "success",
        "user_id": user_id,
        "count": len(assignments),
        "truncated": len(assignments) == min(top, 200),
        "resources": sorted(
            {item["resourceDisplayName"] for item in assignments if item["resourceDisplayName"]}
        ),
        "app_role_assignments": assignments,
    }


@read_only_tool()
async def list_privileged_role_assignments(
    only_privileged: Annotated[
        bool, Field(description="Filter to sensitive built-in directory roles")
    ] = True,
    top: ResultLimit500 = 200,
) -> dict[str, Any]:
    """List all privileged admins at once: a tenant-wide snapshot of active directory-role assignments (Global Administrator and other sensitive roles) with the assigned principals."""
    from msgraph.generated.role_management.directory.role_assignments.role_assignments_request_builder import (
        RoleAssignmentsRequestBuilder,
    )

    query = RoleAssignmentsRequestBuilder.RoleAssignmentsRequestBuilderGetQueryParameters(
        expand=["principal", "roleDefinition"],
        top=min(top, 500),
    )
    config = RoleAssignmentsRequestBuilder.RoleAssignmentsRequestBuilderGetRequestConfiguration(
        query_parameters=query
    )
    result = await get_graph_client().role_management.directory.role_assignments.get(
        request_configuration=config
    )
    raw = result.value if result and result.value else []
    rows: list[dict[str, Any]] = []
    for item in raw:
        role_definition = getattr(item, "role_definition", None)
        role_name = getattr(role_definition, "display_name", None)
        if only_privileged and not any(
            term in (role_name or "").casefold() for term in _PRIVILEGED_ROLE_TERMS
        ):
            continue
        principal = getattr(item, "principal", None)
        rows.append(
            {
                "assignmentId": item.id,
                "roleDisplayName": role_name,
                "roleTemplateId": getattr(role_definition, "template_id", None),
                "directoryScopeId": getattr(item, "directory_scope_id", None),
                "principalId": getattr(principal, "id", None),
                "principalType": type(principal).__name__.removesuffix("able")
                if principal
                else None,
                "principalDisplayName": getattr(principal, "display_name", None),
                "principalUpn": getattr(principal, "user_principal_name", None),
            }
        )
    by_role: dict[str, int] = {}
    for row in rows:
        key = row["roleDisplayName"] or "unknown"
        by_role[key] = by_role.get(key, 0) + 1
    return {
        "status": "success",
        "only_privileged": only_privileged,
        "count": len(rows),
        "scanned": len(raw),
        "truncated": len(raw) == min(top, 500),
        "assignments_by_role": by_role,
        "assignments": rows,
        "analysis_basis": "Privileged filter is a documented built-in-role name heuristic",
    }


@read_only_tool()
async def get_authentication_methods_policy() -> dict[str, Any]:
    """Report the tenant authentication methods policy and flag weak enabled methods."""
    policy = await get_graph_client().policies.authentication_methods_policy.get()
    configurations = []
    weak_enabled = []
    for configuration in getattr(policy, "authentication_method_configurations", None) or []:
        state = str(getattr(configuration, "state", None) or "")
        config_id = getattr(configuration, "id", None)
        configurations.append({"id": config_id, "state": state})
        if state.casefold() == "enabled" and config_id in _WEAK_AUTH_METHOD_IDS:
            weak_enabled.append(config_id)
    return {
        "status": "success",
        "policyId": getattr(policy, "id", None),
        "displayName": getattr(policy, "display_name", None),
        "method_configurations": configurations,
        "weak_methods_enabled": weak_enabled,
        "assessment_basis": "Weak = SMS, Voice, or Email enabled as authentication methods",
    }


@read_only_tool()
async def find_user_oauth_grants(
    user_id: Annotated[str, Field(min_length=1, max_length=256)],
    top: ResultLimit200 = 100,
) -> dict[str, Any]:
    """List delegated OAuth2 permission grants for a user and flag high-risk scopes."""
    from msgraph.generated.oauth2_permission_grants.oauth2_permission_grants_request_builder import (
        Oauth2PermissionGrantsRequestBuilder,
    )

    query = Oauth2PermissionGrantsRequestBuilder.Oauth2PermissionGrantsRequestBuilderGetQueryParameters(
        filter=f"principalId eq {quote_odata_string(user_id)}",
        top=min(top, 200),
    )
    config = Oauth2PermissionGrantsRequestBuilder.Oauth2PermissionGrantsRequestBuilderGetRequestConfiguration(
        query_parameters=query
    )
    result = await get_graph_client().oauth2_permission_grants.get(request_configuration=config)
    grants = []
    for grant in result.value if result and result.value else []:
        scopes = [scope for scope in (grant.scope or "").split(" ") if scope]
        risky = sorted(
            {
                scope
                for scope in scopes
                if any(term in scope.casefold() for term in _HIGH_RISK_OAUTH_SCOPE_TERMS)
            }
        )
        grants.append(
            {
                "id": grant.id,
                "clientId": grant.client_id,
                "resourceId": grant.resource_id,
                "consentType": str(grant.consent_type) if grant.consent_type else None,
                "scopes": scopes,
                "highRiskScopes": risky,
            }
        )
    return {
        "status": "success",
        "user_id": user_id,
        "count": len(grants),
        "high_risk_count": sum(1 for grant in grants if grant["highRiskScopes"]),
        "grants": grants,
        "assessment_basis": "Delegated grants only; verify client application legitimacy",
    }


@read_only_tool()
async def summarize_signin_failures(
    user_principal_name: Annotated[
        str | None, Field(description="Optional UPN prefix filter")
    ] = None,
    time_range: IdentityTimeRange = "24h",
    top: ResultLimit500 = 500,
) -> dict[str, Any]:
    """Aggregate failed sign-ins by error code, user, and IP to surface spray/lockout."""
    from msgraph.generated.audit_logs.sign_ins.sign_ins_request_builder import (
        SignInsRequestBuilder,
    )

    start = _time_range_start(time_range).strftime("%Y-%m-%dT%H:%M:%SZ")
    filters = [f"createdDateTime ge {start}", "status/errorCode ne 0"]
    if user_principal_name:
        filters.append(
            f"startswith(userPrincipalName, {quote_odata_string(user_principal_name)})"
        )
    query = SignInsRequestBuilder.SignInsRequestBuilderGetQueryParameters(
        filter=" and ".join(filters),
        orderby=["createdDateTime desc"],
        top=min(top, 500),
    )
    config = SignInsRequestBuilder.SignInsRequestBuilderGetRequestConfiguration(
        query_parameters=query
    )
    result = await get_graph_client().audit_logs.sign_ins.get(request_configuration=config)
    by_error: dict[str, dict[str, Any]] = {}
    by_user: dict[str, int] = {}
    by_ip: dict[str, int] = {}
    scanned = 0
    for signin in result.value if result and result.value else []:
        scanned += 1
        status = getattr(signin, "status", None)
        code = getattr(status, "error_code", None)
        key = str(code)
        entry = by_error.setdefault(
            key,
            {
                "errorCode": code,
                "failureReason": getattr(status, "failure_reason", None),
                "count": 0,
            },
        )
        entry["count"] += 1
        if signin.user_principal_name:
            by_user[signin.user_principal_name] = by_user.get(signin.user_principal_name, 0) + 1
        if signin.ip_address:
            by_ip[signin.ip_address] = by_ip.get(signin.ip_address, 0) + 1

    def top_counts(values: dict[str, int]) -> list[dict[str, Any]]:
        return [
            {"value": value, "count": count}
            for value, count in sorted(values.items(), key=lambda item: item[1], reverse=True)[:15]
        ]

    return {
        "status": "success",
        "time_range": time_range,
        "scanned": scanned,
        "truncated": scanned == min(top, 500),
        "by_error_code": sorted(
            by_error.values(), key=lambda item: item["count"], reverse=True
        ),
        "top_targeted_users": top_counts(by_user),
        "top_source_ips": top_counts(by_ip),
        "possible_password_spray": len(by_user) >= 10 and scanned >= 20,
        "assessment_basis": "Bounded to one Graph page; spray flag is a coarse heuristic",
    }


def _alert_identity_values(alert: Any) -> set[str]:
    values: set[str] = set()
    for state in getattr(alert, "user_states", None) or []:
        for value in (
            getattr(state, "aad_user_id", None),
            getattr(state, "user_principal_name", None),
            getattr(state, "account_name", None),
        ):
            if value:
                values.add(str(value).casefold())
    for evidence in getattr(alert, "evidence", None) or []:
        account = getattr(evidence, "user_account", None)
        for value in (
            getattr(account, "azure_ad_user_id", None),
            getattr(account, "user_principal_name", None),
            getattr(account, "account_name", None),
        ):
            if value:
                values.add(str(value).casefold())
    return values


@read_only_tool()
async def get_identity_alerts(
    user_id: Annotated[str, Field(min_length=1, max_length=320)],
    top: ResultLimit100 = 50,
) -> dict[str, Any]:
    """Return Defender XDR alerts whose user evidence matches an identity ID or UPN."""
    from msgraph.generated.security.alerts_v2.alerts_v2_request_builder import (
        Alerts_v2RequestBuilder,
    )

    query = Alerts_v2RequestBuilder.Alerts_v2RequestBuilderGetQueryParameters(
        expand=["evidence"],
        top=min(top, 100),
    )
    config = Alerts_v2RequestBuilder.Alerts_v2RequestBuilderGetRequestConfiguration(
        query_parameters=query
    )
    result = await get_graph_client().security.alerts_v2.get(request_configuration=config)
    identity = user_id.casefold()
    matched = [
        alert
        for alert in (result.value if result and result.value else [])
        if identity in _alert_identity_values(alert)
    ]
    alerts = [
        {
            "id": alert.id,
            "title": alert.title,
            "severity": str(alert.severity) if alert.severity else None,
            "status": str(alert.status) if alert.status else None,
            "category": alert.category,
            "attackStage": alert.category,
            "createdDateTime": str(alert.created_date_time)
            if alert.created_date_time
            else None,
            "serviceSource": str(alert.service_source) if alert.service_source else None,
            "affectedAssets": [str(evidence) for evidence in (alert.evidence or [])][:20],
        }
        for alert in matched
    ]
    return {
        "status": "success",
        "user_id": user_id,
        "count": len(alerts),
        "alerts": alerts,
        "severity": {
            level: sum(
                str(alert.get("severity") or "").casefold() == level for alert in alerts
            )
            for level in ("high", "medium", "low", "informational")
        },
        "attack_stage": sorted(
            {alert["attackStage"] for alert in alerts if alert["attackStage"]}
        ),
        "affected_assets": [
            asset for alert in alerts for asset in alert["affectedAssets"]
        ][:100],
        "scan_limit": min(top, 100),
        "analysis_basis": "Client-side match against alert userStates and user evidence",
    }


@read_only_tool()
async def analyze_signin_risk(
    user_id: Annotated[str, Field(min_length=1, max_length=256)],
    time_range: IdentityTimeRange = "30d",
    top: ResultLimit500 = 100,
) -> dict[str, Any]:
    """Correlate recent sign-ins with Entra Identity Protection user risk."""
    activity_call = get_signin_activity(user_id, time_range, top)
    risky_user_call = get_graph_client().identity_protection.risky_users.by_risky_user_id(
        user_id
    ).get()
    activity, risky_user = await asyncio.gather(
        activity_call,
        risky_user_call,
        return_exceptions=True,
    )
    if isinstance(activity, Exception):
        raise activity
    errors: list[dict[str, str]] = []
    if isinstance(risky_user, Exception):
        logger.warning("Risky user lookup failed: %s", risky_user)
        risky_user = None
        errors.append({"source": "risky_user", "error": "Identity Protection unavailable"})

    level = str(getattr(risky_user, "risk_level", None) or "none").casefold()
    score = {"high": 60, "medium": 35, "low": 15}.get(level, 0)
    signins = activity["signins"]
    failed = sum(
        int((signin.get("result") or {}).get("errorCode") or 0) != 0 for signin in signins
    )
    risky_signins = activity["risk_indicators"]
    score += min(len(risky_signins) * 10, 30)
    if signins:
        score += min(round((failed / len(signins)) * 20), 20)
    score = min(score, 100)
    anomalies = []
    if failed:
        anomalies.append({"type": "failed_signins", "count": failed})
    if len(activity["locations"]) >= 3:
        anomalies.append(
            {"type": "location_variance", "distinct_locations": len(activity["locations"])}
        )
    if risky_signins:
        anomalies.append({"type": "risky_signins", "count": len(risky_signins)})
    recommendations = []
    if score >= 60:
        recommendations.extend(
            ["Review risky sign-ins immediately", "Require secure password reset and revoke sessions"]
        )
    elif score >= 30:
        recommendations.extend(
            ["Validate recent locations and devices", "Review authentication posture and MFA methods"]
        )
    elif failed:
        recommendations.append("Review repeated authentication failures")
    return {
        "status": "success" if not errors else "partial_success",
        "user_id": user_id,
        "risk_level": "high" if score >= 60 else "medium" if score >= 30 else "low",
        "risk_score": score,
        "detections": risky_signins,
        "anomalies": anomalies,
        "recommendations": recommendations,
        "identity_protection": {
            "riskLevel": level,
            "riskState": str(getattr(risky_user, "risk_state", None) or "") or None,
            "riskDetail": str(getattr(risky_user, "risk_detail", None) or "") or None,
            "lastUpdatedDateTime": str(
                getattr(risky_user, "risk_last_updated_date_time", None) or ""
            )
            or None,
        },
        "metrics": {
            "signins": len(signins),
            "failed": failed,
            "risky": len(risky_signins),
            "locations": len(activity["locations"]),
        },
        "scoring_basis": "Identity Protection level + risky sign-ins + failed-sign-in ratio",
        "errors": errors,
    }


@read_only_tool()
async def analyze_identity_group(
    group_id: Annotated[
        str,
        Field(min_length=1, max_length=256, description="Microsoft Entra group object ID"),
    ],
    membership_scope: Annotated[
        GroupMembershipScope,
        Field(description="direct members or transitive members including nested groups"),
    ] = "direct",
    top: ResultLimit500 = 100,
) -> str:
    """Analyze one Microsoft Entra group, its owners, and bounded membership."""
    top = min(top, 500)
    try:
        client = get_graph_client()
        group_request = client.groups.by_group_id(group_id)

        from msgraph.generated.groups.item.group_item_request_builder import (
            GroupItemRequestBuilder,
        )
        from msgraph.generated.groups.item.owners.owners_request_builder import (
            OwnersRequestBuilder,
        )

        group_query = GroupItemRequestBuilder.GroupItemRequestBuilderGetQueryParameters(
            select=[
                "id",
                "displayName",
                "description",
                "mail",
                "mailEnabled",
                "securityEnabled",
                "groupTypes",
                "membershipRule",
                "membershipRuleProcessingState",
                "isAssignableToRole",
                "visibility",
            ]
        )
        group_config = GroupItemRequestBuilder.GroupItemRequestBuilderGetRequestConfiguration(
            query_parameters=group_query
        )
        owner_query = OwnersRequestBuilder.OwnersRequestBuilderGetQueryParameters(top=100)
        owner_config = OwnersRequestBuilder.OwnersRequestBuilderGetRequestConfiguration(
            query_parameters=owner_query
        )
        if membership_scope == "transitive":
            from msgraph.generated.groups.item.transitive_members.transitive_members_request_builder import (
                TransitiveMembersRequestBuilder,
            )

            member_query = TransitiveMembersRequestBuilder.TransitiveMembersRequestBuilderGetQueryParameters(
                top=top
            )
            member_config = TransitiveMembersRequestBuilder.TransitiveMembersRequestBuilderGetRequestConfiguration(
                query_parameters=member_query
            )
            member_call = group_request.transitive_members.get(
                request_configuration=member_config
            )
        else:
            from msgraph.generated.groups.item.members.members_request_builder import (
                MembersRequestBuilder,
            )

            member_query = MembersRequestBuilder.MembersRequestBuilderGetQueryParameters(top=top)
            member_config = MembersRequestBuilder.MembersRequestBuilderGetRequestConfiguration(
                query_parameters=member_query
            )
            member_call = group_request.members.get(request_configuration=member_config)

        group, owners_result, members_result = await asyncio.gather(
            group_request.get(request_configuration=group_config),
            group_request.owners.get(request_configuration=owner_config),
            member_call,
        )
        owners = [
            _directory_principal_summary(owner)
            for owner in (owners_result.value if owners_result and owners_result.value else [])
        ]
        members = [
            _directory_principal_summary(member)
            for member in (members_result.value if members_result and members_result.value else [])
        ]
        member_types: dict[str, int] = {}
        for member in members:
            principal_type = member["principalType"]
            member_types[principal_type] = member_types.get(principal_type, 0) + 1

        return _json(
            {
                "status": "success",
                "group": {
                    "id": group.id,
                    "displayName": group.display_name,
                    "description": group.description,
                    "mail": group.mail,
                    "mailEnabled": group.mail_enabled,
                    "securityEnabled": group.security_enabled,
                    "groupTypes": group.group_types or [],
                    "visibility": str(group.visibility) if group.visibility else None,
                    "membershipType": "dynamic" if group.membership_rule else "assigned",
                    "membershipRule": group.membership_rule,
                    "membershipRuleProcessingState": str(group.membership_rule_processing_state)
                    if group.membership_rule_processing_state
                    else None,
                    "isAssignableToRole": group.is_assignable_to_role,
                },
                "membershipScope": membership_scope,
                "ownerCount": len(owners),
                "owners": owners,
                "returnedMemberCount": len(members),
                "memberTypes": member_types,
                "truncated": len(members) == top,
                "members": members,
            }
        )
    except Exception as e:
        return _error_response("analyze_identity_group", e)


@read_only_tool()
async def get_signin_logs(
    user_principal_name: Annotated[
        str | None, Field(description="Filter by UPN (partial match)")
    ] = None,
    app_display_name: Annotated[str | None, Field(description="Filter by application name")] = None,
    status: Annotated[SignInStatus, Field(description="Sign-in result filter")] = "all",
    risk_level: Annotated[RiskLevel, Field(description="Risk level filter")] = "all",
    days_back: DaysBack30 = 7,
    top: ResultLimit500 = 100,
) -> str:
    """Retrieve Microsoft Entra ID sign-in logs."""
    days = min(days_back, 30)
    top = min(top, Config.MAX_SIGNIN_LOGS)
    try:
        client = get_graph_client()
        start = (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        filters = [f"createdDateTime ge {start}"]
        if user_principal_name:
            filters.append(
                f"startswith(userPrincipalName, {quote_odata_string(user_principal_name)})"
            )
        if app_display_name:
            filters.append(f"contains(appDisplayName, {quote_odata_string(app_display_name)})")
        if status == "success":
            filters.append("status/errorCode eq 0")
        elif status == "failure":
            filters.append("status/errorCode ne 0")
        if risk_level != "all":
            filters.append(f"riskLevelDuringSignIn eq {quote_odata_string(risk_level)}")

        from msgraph.generated.audit_logs.sign_ins.sign_ins_request_builder import (
            SignInsRequestBuilder,
        )

        qp = SignInsRequestBuilder.SignInsRequestBuilderGetQueryParameters(
            top=top,
            filter=" and ".join(filters),
            orderby=["createdDateTime desc"],
        )
        cfg = SignInsRequestBuilder.SignInsRequestBuilderGetRequestConfiguration(
            query_parameters=qp
        )
        result = await client.audit_logs.sign_ins.get(request_configuration=cfg)
        if not result or not result.value:
            return _json({"status": "success", "count": 0, "message": "No sign-in logs found"})
        logs = [
            {
                "id": signin_log.id,
                "createdDateTime": str(signin_log.created_date_time),
                "userPrincipalName": signin_log.user_principal_name,
                "userDisplayName": signin_log.user_display_name,
                "appDisplayName": signin_log.app_display_name,
                "ipAddress": signin_log.ip_address,
                "clientAppUsed": signin_log.client_app_used,
                "status": {
                    "errorCode": signin_log.status.error_code,
                    "failureReason": signin_log.status.failure_reason,
                }
                if signin_log.status
                else None,
                "location": {
                    "city": signin_log.location.city,
                    "state": signin_log.location.state,
                    "country": signin_log.location.country_or_region,
                }
                if signin_log.location
                else None,
                "riskLevel": str(signin_log.risk_level_during_sign_in)
                if signin_log.risk_level_during_sign_in
                else None,
                "riskState": str(signin_log.risk_state) if signin_log.risk_state else None,
                "conditionalAccessStatus": str(signin_log.conditional_access_status)
                if signin_log.conditional_access_status
                else None,
                "isInteractive": signin_log.is_interactive,
            }
            for signin_log in result.value
        ]
        return _json({"status": "success", "count": len(logs), "logs": logs})
    except Exception as e:
        return _error_response("get_signin_logs", e)


@read_only_tool()
async def get_audit_logs(
    category: Annotated[
        str,
        Field(
            description="UserManagement|GroupManagement|ApplicationManagement|RoleManagement|DirectoryManagement|Policy|all"
        ),
    ] = "all",
    activity_display_name: Annotated[
        str | None, Field(description="Filter by activity name")
    ] = None,
    initiated_by: Annotated[str | None, Field(description="Filter by initiator")] = None,
    target_resource: Annotated[
        str | None, Field(description="Filter by target resource name")
    ] = None,
    days_back: DaysBack30 = 7,
    top: ResultLimit500 = 100,
) -> str:
    """Retrieve Microsoft Entra ID audit logs."""
    days = min(days_back, 30)
    top = min(top, Config.MAX_AUDIT_LOGS)
    try:
        client = get_graph_client()
        start = (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        filters = [f"activityDateTime ge {start}"]
        if category != "all":
            filters.append(f"category eq {quote_odata_string(category)}")
        if activity_display_name:
            filters.append(
                f"contains(activityDisplayName, {quote_odata_string(activity_display_name)})"
            )

        from msgraph.generated.audit_logs.directory_audits.directory_audits_request_builder import (
            DirectoryAuditsRequestBuilder,
        )

        qp = DirectoryAuditsRequestBuilder.DirectoryAuditsRequestBuilderGetQueryParameters(
            top=top,
            filter=" and ".join(filters),
            orderby=["activityDateTime desc"],
        )
        cfg = DirectoryAuditsRequestBuilder.DirectoryAuditsRequestBuilderGetRequestConfiguration(
            query_parameters=qp
        )
        result = await client.audit_logs.directory_audits.get(request_configuration=cfg)
        if not result or not result.value:
            return _json({"status": "success", "count": 0, "message": "No audit logs found"})
        logs = []
        for log in result.value:
            if initiated_by:
                name = ""
                if log.initiated_by and log.initiated_by.user:
                    name = (
                        log.initiated_by.user.user_principal_name
                        or log.initiated_by.user.display_name
                        or ""
                    )
                elif log.initiated_by and log.initiated_by.app:
                    name = log.initiated_by.app.display_name or ""
                if initiated_by.lower() not in name.lower():
                    continue
            if not _audit_target_matches(log.target_resources, target_resource):
                continue
            logs.append(
                {
                    "id": log.id,
                    "activityDateTime": str(log.activity_date_time),
                    "activityDisplayName": log.activity_display_name,
                    "category": log.category,
                    "result": str(log.result) if log.result else None,
                    "initiatedBy": {
                        "user": {
                            "displayName": log.initiated_by.user.display_name,
                            "upn": log.initiated_by.user.user_principal_name,
                        }
                        if log.initiated_by and log.initiated_by.user
                        else None,
                        "app": {"displayName": log.initiated_by.app.display_name}
                        if log.initiated_by and log.initiated_by.app
                        else None,
                    }
                    if log.initiated_by
                    else None,
                    "targetResources": [
                        {"displayName": t.display_name, "type": t.type}
                        for t in (log.target_resources or [])
                    ],
                }
            )
        return _json({"status": "success", "count": len(logs), "logs": logs})
    except Exception as e:
        return _error_response("get_audit_logs", e)


@read_only_tool()
async def get_risky_users(
    risk_level: Annotated[RiskLevel, Field(description="Risk level filter")] = "all",
    risk_state: Annotated[RiskState, Field(description="Risk state filter")] = "atRisk",
    top: ResultLimit200 = 50,
) -> str:
    """Retrieve users flagged as risky by Entra ID Identity Protection."""
    top = min(top, Config.MAX_RISKY_USERS)
    try:
        client = get_graph_client()
        filters = []
        if risk_state != "all":
            filters.append(f"riskState eq {quote_odata_string(risk_state)}")
        if risk_level != "all":
            filters.append(f"riskLevel eq {quote_odata_string(risk_level)}")

        from msgraph.generated.identity_protection.risky_users.risky_users_request_builder import (
            RiskyUsersRequestBuilder,
        )

        qp = RiskyUsersRequestBuilder.RiskyUsersRequestBuilderGetQueryParameters(
            top=top,
            filter=" and ".join(filters) if filters else None,
        )
        cfg = RiskyUsersRequestBuilder.RiskyUsersRequestBuilderGetRequestConfiguration(
            query_parameters=qp
        )
        result = await client.identity_protection.risky_users.get(request_configuration=cfg)
        if not result or not result.value:
            return _json({"status": "success", "count": 0, "message": "No risky users found"})
        users = [
            {
                "id": u.id,
                "userPrincipalName": u.user_principal_name,
                "userDisplayName": u.user_display_name,
                "riskLevel": str(u.risk_level) if u.risk_level else None,
                "riskState": str(u.risk_state) if u.risk_state else None,
                "riskDetail": str(u.risk_detail) if u.risk_detail else None,
                "riskLastUpdatedDateTime": str(u.risk_last_updated_date_time)
                if u.risk_last_updated_date_time
                else None,
            }
            for u in result.value
        ]
        order = {"high": 0, "medium": 1, "low": 2}
        users.sort(key=lambda x: order.get((x["riskLevel"] or "").lower(), 9))
        return _json(
            {
                "status": "success",
                "count": len(users),
                "summary": {
                    lvl: sum(1 for u in users if u["riskLevel"] and lvl in u["riskLevel"].lower())
                    for lvl in ("high", "medium", "low")
                },
                "users": users,
            }
        )
    except Exception as e:
        return _error_response("get_risky_users", e)


def _build_risky_signins_filter(
    start: str,
    user_principal_name: str | None,
    risk_level: RiskLevel,
    risk_state: RiskState,
) -> str:
    filters = [f"createdDateTime ge {start}", "riskLevelDuringSignIn ne 'none'"]
    if user_principal_name:
        filters.append(f"userPrincipalName eq {quote_odata_string(user_principal_name)}")
    if risk_level != "all":
        filters.append(f"riskLevelDuringSignIn eq {quote_odata_string(risk_level)}")
    if risk_state != "all":
        filters.append(f"riskState eq {quote_odata_string(risk_state)}")
    return " and ".join(filters)


@read_only_tool()
async def get_risky_signins(
    user_principal_name: Annotated[str | None, Field(description="Filter by UPN")] = None,
    risk_level: Annotated[RiskLevel, Field(description="Risk level filter")] = "all",
    risk_state: Annotated[RiskState, Field(description="Risk state filter")] = "all",
    days_back: DaysBack30 = 7,
    top: ResultLimit500 = 100,
) -> str:
    """Retrieve risky sign-in events from Entra ID Identity Protection."""
    days = min(days_back, 30)
    top = min(top, Config.MAX_SIGNIN_LOGS)
    try:
        client = get_graph_client()
        start = (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        risk_filter = _build_risky_signins_filter(
            start,
            user_principal_name,
            risk_level,
            risk_state,
        )

        from msgraph.generated.audit_logs.sign_ins.sign_ins_request_builder import (
            SignInsRequestBuilder,
        )

        qp = SignInsRequestBuilder.SignInsRequestBuilderGetQueryParameters(
            top=top,
            filter=risk_filter,
            orderby=["createdDateTime desc"],
        )
        cfg = SignInsRequestBuilder.SignInsRequestBuilderGetRequestConfiguration(
            query_parameters=qp
        )
        result = await client.audit_logs.sign_ins.get(request_configuration=cfg)
        if not result or not result.value:
            return _json({"status": "success", "count": 0, "message": "No risky sign-ins found"})
        signins = [
            {
                "id": s.id,
                "createdDateTime": str(s.created_date_time),
                "userPrincipalName": s.user_principal_name,
                "appDisplayName": s.app_display_name,
                "ipAddress": s.ip_address,
                "location": {"city": s.location.city, "country": s.location.country_or_region}
                if s.location
                else None,
                "riskLevel": str(s.risk_level_during_sign_in)
                if hasattr(s, "risk_level_during_sign_in") and s.risk_level_during_sign_in
                else None,
                "riskState": str(s.risk_state)
                if hasattr(s, "risk_state") and s.risk_state
                else None,
            }
            for s in result.value
        ]
        return _json(
            {
                "status": "success",
                "count": len(signins),
                "summary": {
                    lvl: sum(1 for s in signins if s["riskLevel"] and lvl in s["riskLevel"].lower())
                    for lvl in ("high", "medium", "low")
                },
                "signins": signins,
            }
        )
    except Exception as e:
        return _error_response("get_risky_signins", e)


@read_only_tool()
async def get_conditional_access_policies(
    state: Annotated[
        str, Field(description="enabled|disabled|enabledForReportingButNotEnforced|all")
    ] = "all",
    include_details: Annotated[bool, Field(description="Include full policy details")] = True,
) -> str:
    """Retrieve Conditional Access policies and their configurations."""
    try:
        result, cache_metadata = await cached_operation(
            "conditional_access_policies",
            {"state": state, "include_details": include_details},
            1800,
            lambda: _fetch_conditional_access_policies(state, include_details),
        )
        return _json({**result, **cache_metadata})
    except Exception as e:
        return _error_response("get_conditional_access_policies", e)


async def _fetch_conditional_access_policies(
    state: str,
    include_details: bool,
) -> dict[str, Any]:
    result = await get_graph_client().identity.conditional_access.policies.get()
    policies = []
    for policy in result.value if result and result.value else []:
        if not _conditional_access_state_matches(policy.state, state):
            continue
        entry: dict[str, Any] = {
            "id": policy.id,
            "displayName": policy.display_name,
            "state": str(policy.state) if policy.state else None,
        }
        if include_details and policy.conditions:
            entry["conditions"] = {
                "users": {
                    "include": policy.conditions.users.include_users,
                    "exclude": policy.conditions.users.exclude_users,
                }
                if policy.conditions.users
                else None,
                "applications": {"include": policy.conditions.applications.include_applications}
                if policy.conditions.applications
                else None,
                "signInRiskLevels": [
                    str(risk) for risk in (policy.conditions.sign_in_risk_levels or [])
                ]
                if policy.conditions.sign_in_risk_levels
                else None,
            }
        if include_details and policy.grant_controls:
            entry["grantControls"] = {
                "operator": policy.grant_controls.operator,
                "builtInControls": [
                    str(control) for control in (policy.grant_controls.built_in_controls or [])
                ],
            }
        policies.append(entry)
    return {"status": "success", "count": len(policies), "policies": policies}


@read_only_tool()
async def analyze_user_risk_profile(
    user_principal_name: Annotated[str, Field(description="User principal name (email)")],
    days_back: DaysBack90 = 30,
) -> str:
    """Comprehensive risk profile analysis combining sign-in, risk, and audit data."""
    if not user_principal_name:
        return "Error: 'user_principal_name' parameter is required"
    days = min(days_back, 90)
    lines = [
        "=" * 80,
        f"USER RISK PROFILE: {user_principal_name}",
        f"Analysis Period: Last {days} days",
        f"Generated: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S')} UTC",
        "=" * 80,
    ]
    try:
        client = get_graph_client()
        start = (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Identity Protection status
        lines.append("\n--- IDENTITY PROTECTION ---")
        try:
            from msgraph.generated.identity_protection.risky_users.risky_users_request_builder import (
                RiskyUsersRequestBuilder,
            )

            qp = RiskyUsersRequestBuilder.RiskyUsersRequestBuilderGetQueryParameters(
                filter=f"userPrincipalName eq {quote_odata_string(user_principal_name)}",
            )
            cfg = RiskyUsersRequestBuilder.RiskyUsersRequestBuilderGetRequestConfiguration(
                query_parameters=qp
            )
            ru = await client.identity_protection.risky_users.get(request_configuration=cfg)
            if ru and ru.value:
                u = ru.value[0]
                lines.append(
                    f"  Risk Level: {u.risk_level}  |  State: {u.risk_state}  |  Detail: {u.risk_detail}"
                )
            else:
                lines.append("  OK — User NOT flagged as risky")
        except Exception as ex:
            logger.warning("Risk status lookup failed: %s", ex)
            lines.append("  Risk status unavailable")

        # Sign-in analysis
        lines.append("\n--- SIGN-IN ACTIVITY ---")
        try:
            from msgraph.generated.audit_logs.sign_ins.sign_ins_request_builder import (
                SignInsRequestBuilder,
            )

            qp2 = SignInsRequestBuilder.SignInsRequestBuilderGetQueryParameters(
                filter=(
                    f"userPrincipalName eq {quote_odata_string(user_principal_name)} "
                    f"and createdDateTime ge {start}"
                ),
                top=500,
                orderby=["createdDateTime desc"],
            )
            cfg2 = SignInsRequestBuilder.SignInsRequestBuilderGetRequestConfiguration(
                query_parameters=qp2
            )
            si = await client.audit_logs.sign_ins.get(request_configuration=cfg2)
            if si and si.value:
                total = len(si.value)
                ok = sum(1 for s in si.value if s.status and s.status.error_code == 0)
                fail = total - ok
                locs = {}
                for s in si.value:
                    if s.location and s.location.country_or_region:
                        locs[s.location.country_or_region] = (
                            locs.get(s.location.country_or_region, 0) + 1
                        )
                lines.append(f"  Total: {total}  | OK: {ok}  | Failed: {fail}")
                if locs:
                    lines.append(
                        f"  Locations: {', '.join(f'{k} ({v})' for k, v in sorted(locs.items(), key=lambda x: x[1], reverse=True)[:5])}"
                    )
            else:
                lines.append("  No sign-in activity in period")
        except Exception as ex:
            logger.warning("Sign-in lookup failed: %s", ex)
            lines.append("  Sign-in activity unavailable")

        lines += [
            "\n--- RECOMMENDATIONS ---",
            "  1. Review risky sign-ins and confirm legitimacy",
            "  2. If risk elevated, require MFA re-registration",
            "  3. Check unexpected geographic access",
            "  4. For high-risk, require password reset",
            "=" * 80,
        ]
        return "\n".join(lines)
    except Exception as e:
        return _error_response("analyze_user_risk_profile", e)


# =========================================================================
# TOOLS — Advanced Threat Hunting
# =========================================================================

# Bounded fan-out for Advanced Hunting sub-queries. Kept modest so nested use
# inside run_threat_hunt_suite stays within Defender Advanced Hunting throttles.
_HUNT_QUERY_CONCURRENCY = 4


async def _multi_hunt(queries: dict[str, str]) -> dict[str, dict[str, Any]]:
    """Run hunting queries with bounded concurrency and preserve each outcome."""
    semaphore = asyncio.Semaphore(_HUNT_QUERY_CONCURRENCY)

    async def run_one(key: str, query: str) -> tuple[str, dict[str, Any]]:
        async with semaphore:
            try:
                r = await _run_hunting(query)
                results = r.get("results", [])
                return key, {
                    "status": "success",
                    "row_count": r.get("rowCount", len(results)),
                    "results": results,
                }
            except Exception as e:
                logger.warning("Hunt query '%s' failed: %s", key, e)
                return key, {
                    "status": "error",
                    "row_count": 0,
                    "results": [],
                    "error": "Query execution failed",
                }

    entries = await asyncio.gather(*(run_one(key, q) for key, q in queries.items()))
    return dict(entries)


def _count_hunt_findings(results: dict[str, dict[str, Any]]) -> int:
    """Return the number of findings from successful hunt queries."""
    return sum(result["row_count"] for result in results.values() if result["status"] == "success")


def _count_hunt_errors(results: dict[str, dict[str, Any]]) -> int:
    """Return the number of failed hunt queries."""
    return sum(result["status"] == "error" for result in results.values())


def _hunt_response_status(results: dict[str, dict[str, Any]]) -> str:
    """Summarize the overall outcome of a multi-query hunt."""
    error_count = _count_hunt_errors(results)
    if error_count == 0:
        return "success"
    if error_count == len(results):
        return "error"
    return "partial_success"


@read_only_tool()
async def hunt_ransomware_indicators(
    days_back: DaysBack30 = 7,
    detection_type: Annotated[
        str, Field(description="all|extensions|notes|shadow_copy|double_extension")
    ] = "all",
) -> str:
    """Hunt for ransomware indicators including file extensions, ransom notes, shadow copy deletion."""
    d = min(days_back, 30)
    queries: dict[str, str] = {}
    if detection_type in ("all", "extensions"):
        queries["ransomware_extensions"] = f"""
let Ext = externaldata(Extension:string)[@"https://raw.githubusercontent.com/eshlomo1/Ransomware-NOTE/main/ransomware-extension-list.txt"] with (format="txt", ignoreFirstRecord=True);
let RE = materialize(Ext | distinct Extension | extend Raw=substring(Extension,1,string_size(Extension)));
DeviceFileEvents | where Timestamp > ago({d}d) | where FileName has_any (RE)
| summarize arg_max(Timestamp,*), Files=make_set(FileName,100) by DeviceName
| extend Total=array_length(Files) | project Timestamp, DeviceName, Total, Files | order by Total desc | limit 100"""
    if detection_type in ("all", "notes"):
        queries["ransomware_notes"] = f"""
let Notes = externaldata(N:string)[@"https://raw.githubusercontent.com/eshlomo1/Ransomware-NOTE/main/ransomware-notes.txt"] with (format="txt", ignoreFirstRecord=True);
let NR = Notes | extend NR=replace_string(N,"*","") | distinct NR;
DeviceFileEvents | where Timestamp > ago({d}d) | where FileName has_any (NR)
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine | limit 100"""
    if detection_type in ("all", "shadow_copy"):
        queries["shadow_copy_deletion"] = f"""
DeviceProcessEvents | where Timestamp > ago({d}d)
| where ProcessCommandLine has_any ("vssadmin","wmic","bcdedit","wbadmin")
| where ProcessCommandLine has_any ("delete","shadowcopy","catalog","recoveryenabled")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine | limit 100"""
    if detection_type in ("all", "double_extension"):
        queries["double_extension"] = f"""
let Orig = dynamic(['.pdf','.docx','.jpg','.xlsx','.pptx','.txt','.doc','.xls']);
DeviceFileEvents | where Timestamp > ago({d}d) | where ActionType == "FileRenamed"
| extend PrevExt=extract(@"\\.([a-z])*",0,PreviousFileName), NewExt=extract(@'\\.(.*)',0,FileName)
| where PrevExt != NewExt | where PrevExt has_any (Orig)
| extend Chk=strcat(PrevExt,".") | where NewExt contains Chk
| summarize Cnt=count(), Files=make_list(FileName,50) by DeviceName, InitiatingProcessFileName
| where Cnt > 10 | limit 100"""
    results = await _multi_hunt(queries)
    total = _count_hunt_findings(results)
    return _json(
        {
            "status": _hunt_response_status(results),
            "detection_type": detection_type,
            "days_searched": d,
            "total_findings": total,
            "failed_queries": _count_hunt_errors(results),
            "results": results,
        }
    )


@read_only_tool()
async def hunt_suspicious_powershell(
    days_back: DaysBack30 = 7,
    detection_type: Annotated[
        str, Field(description="all|encoded|web_requests|defender_tampering|amsi")
    ] = "all",
) -> str:
    """Hunt for suspicious PowerShell: encoded commands, web requests, Defender tampering, AMSI."""
    d = min(days_back, 30)
    queries: dict[str, str] = {}
    if detection_type in ("all", "encoded"):
        queries["encoded_powershell"] = f"""
let Enc = dynamic(['-encodedcommand','-enc','-e']);
DeviceProcessEvents | where Timestamp > ago({d}d)
| where ProcessCommandLine contains "powershell" or InitiatingProcessCommandLine contains "powershell"
| where ProcessCommandLine has_any (Enc) or InitiatingProcessCommandLine has_any (Enc)
| extend b64=extract(@'\\s+([A-Za-z0-9+/]{{20}}\\S+$)',1,ProcessCommandLine)
| extend Decoded=replace_string(base64_decode_tostring(b64),'\\u0000','')
| where isnotempty(b64) and isnotempty(Decoded)
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, Decoded | limit 100"""
    if detection_type in ("all", "web_requests"):
        queries["web_requests"] = f"""
DeviceProcessEvents | where Timestamp > ago({d}d)
| where ProcessCommandLine has_any ("Invoke-WebRequest","iwr","wget","curl","DownloadString","DownloadFile","Net.WebClient")
| where ProcessCommandLine has_any ("http://","https://")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine | limit 100"""
    if detection_type in ("all", "defender_tampering"):
        queries["defender_tampering"] = f"""
DeviceProcessEvents | where Timestamp > ago({d}d) | where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("Add-MpPreference","Set-MpPreference")
| where ProcessCommandLine has_any ("ExclusionProcess","ExclusionPath","ExclusionExtension","DisableRealtimeMonitoring")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine | limit 100"""
    if detection_type in ("all", "amsi"):
        queries["amsi_detections"] = f"""
DeviceEvents | where Timestamp > ago({d}d) | where ActionType == "AmsiScriptDetection"
| extend Desc=tostring(parse_json(AdditionalFields).Description)
| project Timestamp, DeviceName, InitiatingProcessCommandLine, Desc | limit 100"""
    results = await _multi_hunt(queries)
    total = _count_hunt_findings(results)
    return _json(
        {
            "status": _hunt_response_status(results),
            "detection_type": detection_type,
            "days_searched": d,
            "total_findings": total,
            "failed_queries": _count_hunt_errors(results),
            "results": results,
        }
    )


@read_only_tool()
async def hunt_lolbin_activity(
    days_back: DaysBack30 = 7,
    lolbin_type: Annotated[
        str, Field(description="all|certutil|mshta|regsvr32|rundll32|wmic|bitsadmin")
    ] = "all",
) -> str:
    """Hunt for Living Off The Land Binary (LOLBIN) abuse."""
    d = min(days_back, 30)
    queries: dict[str, str] = {}
    if lolbin_type in ("all", "certutil"):
        queries["certutil"] = f"""
DeviceProcessEvents | where Timestamp > ago({d}d) | where FileName =~ "certutil.exe"
| where ProcessCommandLine has_any ("-urlcache","-decode","-encode","-f","http://","https://")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine | limit 100"""
    if lolbin_type in ("all", "mshta"):
        queries["mshta"] = f"""
DeviceProcessEvents | where Timestamp > ago({d}d)
| where InitiatingProcessFileName =~ 'mshta.exe' or FileName =~ 'mshta.exe'
| where ProcessCommandLine has_any ("http://","https://","javascript:","vbscript:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine | limit 100"""
    if lolbin_type in ("all", "regsvr32"):
        queries["regsvr32"] = f"""
DeviceProcessEvents | where Timestamp > ago({d}d) | where FileName =~ "regsvr32.exe"
| where ProcessCommandLine has_any ("/s","/u","/i:","scrobj.dll","http://","https://")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine | limit 100"""
    if lolbin_type in ("all", "rundll32"):
        queries["rundll32"] = f"""
DeviceProcessEvents | where Timestamp > ago({d}d) | where FileName =~ "rundll32.exe"
| where ProcessCommandLine has_any ("javascript:","http://","https://","shell32.dll,ShellExec_RunDLL")
   or ProcessCommandLine matches regex @'rundll32\\.exe\\s+[^,]+\\.dll,\\#\\d+'
| project Timestamp, DeviceName, AccountName, ProcessCommandLine | limit 100"""
    if lolbin_type in ("all", "wmic"):
        queries["wmic"] = f"""
DeviceProcessEvents | where Timestamp > ago({d}d) | where FileName =~ "WMIC.exe"
| where ProcessCommandLine has_any ("/node:","process call create","AntiVirusProduct")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine | limit 100"""
    if lolbin_type in ("all", "bitsadmin"):
        queries["bitsadmin"] = f"""
DeviceProcessEvents | where Timestamp > ago({d}d) | where FileName =~ "bitsadmin.exe"
| where ProcessCommandLine has_any ("/transfer","/create","/addfile","http://","https://")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine | limit 100"""
    results = await _multi_hunt(queries)
    total = _count_hunt_findings(results)
    return _json(
        {
            "status": _hunt_response_status(results),
            "lolbin_type": lolbin_type,
            "days_searched": d,
            "total_findings": total,
            "failed_queries": _count_hunt_errors(results),
            "results": results,
        }
    )


@read_only_tool()
async def hunt_lateral_movement(
    days_back: DaysBack30 = 7,
    movement_type: Annotated[str, Field(description="all|psexec|smb|wmi|rdp|dcom")] = "all",
) -> str:
    """Hunt for lateral movement indicators (PsExec, SMB, WMI, RDP, DCOM)."""
    d = min(days_back, 30)
    queries: dict[str, str] = {}
    if movement_type in ("all", "psexec"):
        queries["psexec"] = f"""
DeviceProcessEvents | where Timestamp > ago({d}d) | where ProcessCommandLine contains "psexec"
| extend Remote=extract(@'\\\\\\\\(.*)\\\\',1,ProcessCommandLine)
| summarize Targets=dcount(Remote), TargetList=make_set(Remote,20), Cmds=make_set(ProcessCommandLine,20) by DeviceName, AccountName
| order by Targets desc | limit 100"""
    if movement_type in ("all", "smb"):
        queries["smb"] = f"""
DeviceNetworkEvents | where Timestamp > ago({d}d) | where RemotePort in (445,139) | where ActionType == "ConnectionSuccess"
| summarize Cnt=count(), Targets=dcount(RemoteIP), IPs=make_set(RemoteIP,20) by DeviceName, InitiatingProcessFileName
| where Cnt > 5 | order by Cnt desc | limit 100"""
    if movement_type in ("all", "wmi"):
        queries["wmi"] = f"""
DeviceProcessEvents | where Timestamp > ago({d}d) | where FileName in~ ("wmic.exe","wmiprvse.exe")
| where ProcessCommandLine has "/node:" or ProcessCommandLine has "process call create"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine | limit 100"""
    if movement_type in ("all", "rdp"):
        queries["rdp"] = f"""
DeviceLogonEvents | where Timestamp > ago({d}d) | where LogonType == "RemoteInteractive"
| summarize Cnt=count(), Dests=dcount(DeviceName), DevList=make_set(DeviceName,20) by AccountName, RemoteIP
| where Dests > 3 | order by Dests desc | limit 100"""
    if movement_type in ("all", "dcom"):
        queries["dcom"] = f"""
DeviceProcessEvents | where Timestamp > ago({d}d)
| where InitiatingProcessFileName =~ "mmc.exe" or InitiatingProcessFileName =~ "dllhost.exe"
| where FileName in~ ("powershell.exe","cmd.exe","mshta.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine | limit 100"""
    results = await _multi_hunt(queries)
    total = _count_hunt_findings(results)
    return _json(
        {
            "status": _hunt_response_status(results),
            "movement_type": movement_type,
            "days_searched": d,
            "total_findings": total,
            "failed_queries": _count_hunt_errors(results),
            "results": results,
        }
    )


@read_only_tool()
async def hunt_credential_access(
    days_back: DaysBack30 = 7,
    credential_type: Annotated[
        str, Field(description="all|lsass|ntds|sam|mimikatz|dcsync")
    ] = "all",
) -> str:
    """Hunt for credential access/dumping (LSASS, NTDS, SAM, mimikatz, DCSync)."""
    d = min(days_back, 30)
    queries: dict[str, str] = {}
    if credential_type in ("all", "lsass"):
        queries["lsass"] = f"""
DeviceProcessEvents | where Timestamp > ago({d}d)
| where ProcessCommandLine has_any ("lsass","procdump","comsvcs.dll","MiniDump")
| where not(InitiatingProcessFileName in~ ("MsSense.exe","MsMpEng.exe"))
| project Timestamp, DeviceName, AccountName, ProcessCommandLine | limit 100"""
    if credential_type in ("all", "ntds"):
        queries["ntds"] = f"""
DeviceFileEvents | where Timestamp > ago({d}d)
| where FileName =~ "ntds.dit" or FolderPath has "NTDS"
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName | limit 100"""
    if credential_type in ("all", "sam"):
        queries["sam"] = f"""
DeviceProcessEvents | where Timestamp > ago({d}d)
| where ProcessCommandLine has_any ("reg save","sam","security","system")
| where ProcessCommandLine has "hklm" or ProcessCommandLine has "HKEY_LOCAL_MACHINE"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine | limit 100"""
    if credential_type in ("all", "mimikatz"):
        queries["mimikatz"] = f"""
DeviceProcessEvents | where Timestamp > ago({d}d)
| where ProcessCommandLine has_any ("sekurlsa","kerberos::","lsadump::","privilege::debug","token::elevate","mimikatz")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, FileName, SHA256 | limit 100"""
    if credential_type in ("all", "dcsync"):
        queries["dcsync"] = f"""
IdentityDirectoryEvents | where Timestamp > ago({d}d)
| where ActionType == "Replication request" | where AccountName !endswith "$"
| project Timestamp, AccountName, DeviceName, DestinationDeviceName | limit 100"""
    results = await _multi_hunt(queries)
    total = _count_hunt_findings(results)
    return _json(
        {
            "status": _hunt_response_status(results),
            "credential_type": credential_type,
            "days_searched": d,
            "total_findings": total,
            "failed_queries": _count_hunt_errors(results),
            "results": results,
        }
    )


@read_only_tool()
async def hunt_persistence_mechanisms(
    days_back: DaysBack30 = 7,
    persistence_type: Annotated[
        str, Field(description="all|registry|scheduled_tasks|services|startup|wmi")
    ] = "all",
) -> str:
    """Hunt for persistence mechanisms (registry, tasks, services, startup, WMI)."""
    d = min(days_back, 30)
    queries: dict[str, str] = {}
    if persistence_type in ("all", "registry"):
        queries["registry"] = f"""
DeviceRegistryEvents | where Timestamp > ago({d}d)
| where RegistryKey has_any ("Run","RunOnce","RunServices") | where ActionType == "RegistryValueSet"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName | limit 100"""
    if persistence_type in ("all", "scheduled_tasks"):
        queries["scheduled_tasks"] = f"""
DeviceProcessEvents | where Timestamp > ago({d}d) | where FileName =~ "schtasks.exe" | where ProcessCommandLine has "/create"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine | limit 100"""
    if persistence_type in ("all", "services"):
        queries["services"] = f"""
DeviceProcessEvents | where Timestamp > ago({d}d) | where FileName =~ "sc.exe"
| where ProcessCommandLine has_any ("create","config") | where ProcessCommandLine has_any ("binpath","start")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine | limit 100"""
    if persistence_type in ("all", "startup"):
        queries["startup"] = f"""
DeviceFileEvents | where Timestamp > ago({d}d)
| where FolderPath has_any ("Startup","Start Menu\\\\Programs\\\\Startup")
| where ActionType in ("FileCreated","FileModified")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName | limit 100"""
    if persistence_type in ("all", "wmi"):
        queries["wmi"] = f"""
DeviceProcessEvents | where Timestamp > ago({d}d)
| where ProcessCommandLine has_any ("__EventFilter","__EventConsumer","__FilterToConsumerBinding","ActiveScriptEventConsumer","CommandLineEventConsumer")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine | limit 100"""
    results = await _multi_hunt(queries)
    total = _count_hunt_findings(results)
    return _json(
        {
            "status": _hunt_response_status(results),
            "persistence_type": persistence_type,
            "days_searched": d,
            "total_findings": total,
            "failed_queries": _count_hunt_errors(results),
            "results": results,
        }
    )


@read_only_tool()
async def hunt_suspicious_child_processes(
    days_back: DaysBack30 = 7,
    parent_type: Annotated[str, Field(description="all|browser|office|explorer|outlook")] = "all",
) -> str:
    """Hunt for suspicious child processes from browsers, Office, explorer, Outlook."""
    d = min(days_back, 30)
    children = "dynamic(['cmd.exe','powershell.exe','bash.exe','cscript.exe','wscript.exe','mshta.exe','msiexec.exe','rundll32.exe','regsvr32.exe'])"
    queries: dict[str, str] = {}
    if parent_type in ("all", "browser"):
        queries["browser"] = f"""
let B=dynamic(['chrome.exe','firefox.exe','msedge.exe','brave.exe','iexplore.exe']); let S={children};
DeviceProcessEvents | where Timestamp > ago({d}d) | where InitiatingProcessFileName in~ (B) | where FileName in~ (S)
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine | limit 100"""
    if parent_type in ("all", "office"):
        queries["office"] = f"""
let O=dynamic(['winword.exe','excel.exe','powerpnt.exe','msaccess.exe','mspub.exe','visio.exe']); let S={children};
DeviceProcessEvents | where Timestamp > ago({d}d) | where InitiatingProcessFileName in~ (O) | where FileName in~ (S)
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine | limit 100"""
    if parent_type in ("all", "explorer"):
        queries["explorer"] = f"""
let P=dynamic(['http','https','Encoded','EncodedCommand','-e','-eC','-enc','-w','://']); let S={children};
DeviceProcessEvents | where Timestamp > ago({d}d) | where InitiatingProcessFileName =~ "explorer.exe"
| where FileName in~ (S) | where ProcessCommandLine has_any (P)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine | limit 100"""
    if parent_type in ("all", "outlook"):
        queries["outlook"] = f"""
let S={children};
DeviceProcessEvents | where Timestamp > ago({d}d) | where InitiatingProcessFileName =~ "outlook.exe"
| where FileName in~ (S)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine | limit 100"""
    results = await _multi_hunt(queries)
    total = _count_hunt_findings(results)
    return _json(
        {
            "status": _hunt_response_status(results),
            "parent_type": parent_type,
            "days_searched": d,
            "total_findings": total,
            "failed_queries": _count_hunt_errors(results),
            "results": results,
        }
    )


@read_only_tool()
async def hunt_remote_access_tools(
    days_back: DaysBack30 = 7,
    tool_category: Annotated[
        str, Field(description="all|commercial_rmm|known_rats|tunneling")
    ] = "all",
) -> str:
    """Hunt for RATs and RMM tools (TeamViewer, AnyDesk, ConnectWise, known RATs, tunnelling)."""
    d = min(days_back, 30)
    queries: dict[str, str] = {}
    if tool_category in ("all", "commercial_rmm"):
        queries["commercial_rmm"] = f"""
let R=dynamic(['TeamViewer','AnyDesk','LogMeIn','ConnectWise','ScreenConnect','Splashtop','Bomgar','DameWare','RemotePC','GoToAssist','Datto','Atera','NinjaRMM']);
DeviceProcessEvents | where Timestamp > ago({d}d)
| where ProcessVersionInfoCompanyName has_any (R) or ProcessVersionInfoProductName has_any (R) or FileName has_any (R)
| summarize count() by DeviceName, FileName, ProcessVersionInfoProductName | limit 100"""
    if tool_category in ("all", "known_rats"):
        queries["known_rats"] = f"""
let R=dynamic(['NetSupport','Remcos','AsyncRAT','njRAT','DarkComet','QuasarRAT','Orcus','NanoCore','Gh0st','PoisonIvy']);
DeviceProcessEvents | where Timestamp > ago({d}d)
| where ProcessCommandLine has_any (R) or ProcessVersionInfoProductName has_any (R) or FileName has_any (R)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, SHA256 | limit 100"""
    if tool_category in ("all", "tunneling"):
        queries["tunneling"] = f"""
let T=dynamic(['ngrok','plink','putty','chisel','frp','ligolo','socat','netcat','nc.exe','ncat']);
DeviceProcessEvents | where Timestamp > ago({d}d) | where FileName has_any (T) or ProcessCommandLine has_any (T)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine | limit 100"""
    results = await _multi_hunt(queries)
    total = _count_hunt_findings(results)
    return _json(
        {
            "status": _hunt_response_status(results),
            "tool_category": tool_category,
            "days_searched": d,
            "total_findings": total,
            "failed_queries": _count_hunt_errors(results),
            "results": results,
        }
    )


@read_only_tool()
async def hunt_defense_evasion(
    days_back: DaysBack30 = 7,
    evasion_type: Annotated[
        str, Field(description="all|security_tools|log_clearing|timestomp|injection")
    ] = "all",
) -> str:
    """Hunt for defense evasion (security tool tampering, log clearing, timestomping, injection)."""
    d = min(days_back, 30)
    queries: dict[str, str] = {}
    if evasion_type in ("all", "security_tools"):
        queries["security_tools"] = f"""
DeviceProcessEvents | where Timestamp > ago({d}d)
| where ProcessCommandLine has_any ("Stop-Service","sc stop","net stop","taskkill")
| where ProcessCommandLine has_any ("MsMpSvc","WinDefend","Sense","SecurityHealthService","wscsvc","Sophos","McAfee","Symantec","ESET","Kaspersky","Avast","AVG","Bitdefender","CrowdStrike","Carbon Black","Cylance","SentinelOne")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine | limit 100"""
    if evasion_type in ("all", "log_clearing"):
        queries["log_clearing"] = f"""
DeviceProcessEvents | where Timestamp > ago({d}d)
| where ProcessCommandLine has_any ("wevtutil","Clear-EventLog","Remove-EventLog")
| where ProcessCommandLine has_any ("cl","clear","Security","System","Application")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine | limit 100"""
    if evasion_type in ("all", "timestomp"):
        queries["timestomp"] = f"""
DeviceProcessEvents | where Timestamp > ago({d}d)
| where ProcessCommandLine has_any ("timestomp","SetFileTime","touch -t","$(Get-Item","LastWriteTime","CreationTime")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine | limit 100"""
    if evasion_type in ("all", "injection"):
        queries["injection"] = f"""
DeviceEvents | where Timestamp > ago({d}d)
| where ActionType in ("CreateRemoteThreadApiCall","QueueUserApcRemoteApiCall","SetThreadContextRemoteApiCall","NtAllocateVirtualMemoryRemoteApiCall","NtMapViewOfSectionRemoteApiCall")
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine, InitiatingProcessFileName | limit 100"""
    results = await _multi_hunt(queries)
    total = _count_hunt_findings(results)
    return _json(
        {
            "status": _hunt_response_status(results),
            "evasion_type": evasion_type,
            "days_searched": d,
            "total_findings": total,
            "failed_queries": _count_hunt_errors(results),
            "results": results,
        }
    )


@read_only_tool()
async def hunt_threat_intel_feeds(
    days_back: DaysBack30 = 7,
    feed_type: Annotated[
        str, Field(description="all|malicious_domains|malicious_ips|malicious_hashes")
    ] = "all",
) -> str:
    """Hunt for indicators from public threat intelligence feeds."""
    d = min(days_back, 30)
    queries: dict[str, str] = {}
    if feed_type in ("all", "malicious_domains"):
        queries["malicious_domains"] = f"""
let Feed=externaldata(Domain:string)[@"https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt"] with (format="txt",ignoreFirstRecord=True);
DeviceNetworkEvents | where Timestamp > ago({d}d) | where RemoteUrl has_any (Feed)
| project Timestamp, RemoteUrl, RemoteIP, DeviceName, InitiatingProcessFileName | limit 100"""
    if feed_type in ("all", "malicious_ips"):
        queries["malicious_ips"] = f"""
let Feed=externaldata(IP:string)[@"https://threatview.io/Downloads/IP-High-Confidence-Feed.txt"] with (format="txt",ignoreFirstRecord=True);
let IPRegex='[0-9]{{1,3}}\\\\.[0-9]{{1,3}}\\\\.[0-9]{{1,3}}\\\\.[0-9]{{1,3}}';
let Mal=materialize(Feed | where IP matches regex IPRegex | distinct IP);
DeviceNetworkEvents | where Timestamp > ago({d}d) | where RemoteIP in (Mal)
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName | limit 100"""
    if feed_type in ("all", "malicious_hashes"):
        queries["malicious_hashes"] = f"""
let Feed=externaldata(SHA1:string, threatid:string)["https://misp.cert.ssi.gouv.fr/feed-misp/hashes.csv"];
DeviceFileEvents | where Timestamp > ago({d}d) | join kind=inner Feed on SHA1
| extend Link=strcat("https://misp.cert.ssi.gouv.fr/feed-misp/",threatid,".json")
| project Timestamp, SHA1, Link, DeviceName, FileName, FolderPath | limit 100"""
    results = await _multi_hunt(queries)
    total = _count_hunt_findings(results)
    return _json(
        {
            "status": _hunt_response_status(results),
            "feed_type": feed_type,
            "days_searched": d,
            "total_findings": total,
            "failed_queries": _count_hunt_errors(results),
            "results": results,
        }
    )


@read_only_tool()
async def hunt_data_exfiltration(
    days_back: DaysBack30 = 7,
    exfil_type: Annotated[
        str, Field(description="all|large_transfers|cloud_storage|dns_tunneling|archives")
    ] = "all",
) -> str:
    """Hunt for data exfiltration (large transfers, cloud storage, DNS tunnelling, archives)."""
    d = min(days_back, 30)
    queries = _build_data_exfiltration_queries(d, exfil_type)
    results = await _multi_hunt(queries)
    total = _count_hunt_findings(results)
    return _json(
        {
            "status": _hunt_response_status(results),
            "exfil_type": exfil_type,
            "days_searched": d,
            "total_findings": total,
            "failed_queries": _count_hunt_errors(results),
            "results": results,
        }
    )


@read_only_tool()
async def get_asr_events(
    days_back: DaysBack30 = 7,
    event_type: Annotated[str, Field(description="all|blocked|audited")] = "all",
) -> str:
    """Retrieve Attack Surface Reduction (ASR) rule events."""
    d = min(days_back, 30)
    filt = ""
    if event_type == "blocked":
        filt = '| where ActionType endswith "Blocked"'
    elif event_type == "audited":
        filt = '| where ActionType endswith "Audited"'
    try:
        result = await _run_hunting(f"""
DeviceEvents | where Timestamp > ago({d}d) | where ActionType startswith "Asr" {filt}
| summarize Total=count(), Files=make_set(FileName,50), Procs=make_set(InitiatingProcessCommandLine,20)
  by DeviceName, AccountName, ActionType
| order by Total desc | limit 100""")
        asr_descs = {
            "AsrOfficeChildProcess": "Block Office from creating child processes",
            "AsrOfficeCreateExecutable": "Block Office from creating executables",
            "AsrObfuscatedScript": "Block obfuscated scripts",
            "AsrCredentialStealing": "Block credential stealing from lsass.exe",
            "AsrRansomware": "Advanced ransomware protection",
            "AsrPsexecWmiChildProcess": "Block PSExec/WMI child processes",
        }
        return _json(
            {
                "status": "success",
                "event_type": event_type,
                "days_searched": d,
                "total_findings": result.get("rowCount", 0),
                "asr_rule_descriptions": asr_descs,
                "results": result.get("results", []),
            }
        )
    except Exception as e:
        return _error_response("get_asr_events", e)


# =========================================================================
# WORKFLOW TOOLS — Token-efficient orchestration
# =========================================================================


def _workflow_evidence_limit(detail_level: DetailLevel, max_evidence: int) -> int:
    if detail_level == "summary":
        return min(max_evidence, 3)
    if detail_level == "standard":
        return min(max_evidence, 10)
    return max_evidence


@read_only_tool()
async def investigate_user(
    user_principal_name: Annotated[str, Field(min_length=3, max_length=320)],
    days_back: DaysBack90 = 30,
    detail_level: DetailLevel = "standard",
    max_evidence: MaxEvidence = 10,
) -> dict[str, Any]:
    """Investigate one user's sign-ins, risky sign-ins, and directory audit activity."""
    evidence_limit = _workflow_evidence_limit(detail_level, max_evidence)
    result = await run_workflow(
        {
            "sign_ins": lambda: get_signin_logs(
                user_principal_name=user_principal_name,
                days_back=min(days_back, 30),
                top=min(max_evidence, 500),
            ),
            "risky_sign_ins": lambda: get_risky_signins(
                user_principal_name=user_principal_name,
                days_back=min(days_back, 30),
                top=min(max_evidence, 500),
            ),
            "audit_activity": lambda: get_audit_logs(
                initiated_by=user_principal_name,
                days_back=min(days_back, 30),
                top=min(max_evidence, 500),
            ),
        },
        max_concurrency=3,
        max_items=evidence_limit,
    )
    return {
        "contract_version": "1.0.0",
        "workflow": "investigate_user",
        "subject": user_principal_name,
        "days_back": days_back,
        "detail_level": detail_level,
        **result,
    }


@read_only_tool()
async def investigate_identity(
    user_id: Annotated[str, Field(min_length=1, max_length=256)],
    time_range: IdentityTimeRange = "30d",
    detail_level: DetailLevel = "standard",
    max_evidence: MaxEvidence = 10,
) -> dict[str, Any]:
    """Investigate identity context, authentication, risk, alerts, and privileges."""
    result = await run_workflow(
        {
            "identity_context": lambda: get_identity_context(
                user_id=user_id, top=min(max_evidence, 50)
            ),
            "authentication_posture": lambda: get_authentication_posture(user_id),
            "signin_risk": lambda: analyze_signin_risk(
                user_id, time_range, min(max_evidence, 500)
            ),
            "identity_alerts": lambda: get_identity_alerts(
                user_id, min(max_evidence, 100)
            ),
            "privileged_access": lambda: get_privileged_access(
                user_id, min(max_evidence, 200)
            ),
        },
        max_concurrency=4,
        max_items=_workflow_evidence_limit(detail_level, max_evidence),
    )
    return {
        "contract_version": "1.0.0",
        "workflow": "investigate_identity",
        "user_id": user_id,
        "time_range": time_range,
        "detail_level": detail_level,
        **result,
    }


@read_only_tool()
async def recommend_next_investigation_steps(
    investigation_context: Annotated[
        dict[str, Any],
        Field(description="Current structured investigation findings and completed steps"),
    ],
) -> dict[str, Any]:
    """Recommend evidence-gathering tools from structured investigation findings."""
    context_text = json.dumps(investigation_context, default=str).casefold()
    recommendations: list[dict[str, Any]] = []

    def add(tool: str, reason: str, confidence: float) -> None:
        if not any(item["tool"] == tool for item in recommendations):
            recommendations.append(
                {"tool": tool, "reasoning": reason, "confidence": confidence}
            )

    if not investigation_context.get("profile") and "identity_context" not in context_text:
        add(
            "get_identity_context",
            "Identity profile and organizational relationships are not present",
            0.95,
        )
    if any(term in context_text for term in ("high", "atrisk", "risky_signins")):
        add(
            "get_authentication_posture",
            "Elevated identity or sign-in risk requires authentication-method review",
            0.9,
        )
        add(
            "get_signin_activity",
            "Review recent applications, devices, locations, and failures behind the risk signal",
            0.9,
        )
    if any(term in context_text for term in ("privileged", "global administrator", "role")):
        add(
            "get_privileged_access",
            "Privileged relationships require active, eligible, and group-derived access review",
            0.88,
        )
        add(
            "get_pim_activations",
            "Review recent privilege activations and their justification",
            0.82,
        )
    if any(term in context_text for term in ("alert", "incident", "compromised")):
        add(
            "get_identity_alerts",
            "Correlate the identity with Defender XDR user evidence",
            0.9,
        )
    if any(term in context_text for term in ("conditionalaccess", "conditional_access")):
        add(
            "get_applied_conditional_access",
            "Inspect the actual policy evaluation for a relevant sign-in ID",
            0.85,
        )
    if not recommendations:
        add(
            "investigate_identity",
            "No decisive signal is present; run the bounded identity investigation workflow",
            0.75,
        )
    return {
        "status": "success",
        "recommended_tools": [item["tool"] for item in recommendations],
        "recommendations": recommendations,
        "reasoning": "Deterministic routing based on supplied evidence keywords and missing sections",
        "confidence": max(item["confidence"] for item in recommendations),
    }


@read_only_tool()
async def investigate_alert(
    alert_id: Annotated[str, Field(min_length=1, max_length=256)],
    time_range: Literal["1h", "24h", "7d", "30d"] = "24h",
    detail_level: DetailLevel = "standard",
    max_evidence: MaxEvidence = 10,
) -> dict[str, Any]:
    """Investigate an alert and provide bounded environment alert context."""
    result = await run_workflow(
        {
            "alert": lambda: get_alert_details(alert_id),
            "alert_context": lambda: get_alert_statistics(time_range),
        },
        max_concurrency=2,
        max_items=_workflow_evidence_limit(detail_level, max_evidence),
    )
    return {
        "contract_version": "1.0.0",
        "workflow": "investigate_alert",
        "alert_id": alert_id,
        "detail_level": detail_level,
        **result,
    }


@read_only_tool()
async def hunt_iocs_batch(
    iocs: BatchIoCs,
    ioc_type: Literal["ip", "domain", "url", "hash"],
    detail_level: DetailLevel = "summary",
    max_evidence: MaxEvidence = 5,
    max_concurrency: WorkflowConcurrency = 4,
) -> dict[str, Any]:
    """Enrich up to 20 IoCs in one bounded, deduplicated workflow call."""
    unique_iocs = list(dict.fromkeys(iocs))
    result = await run_workflow(
        {
            f"ioc_{index}": lambda value=value: enrich_ioc(value, ioc_type)
            for index, value in enumerate(unique_iocs)
        },
        max_concurrency=max_concurrency,
        max_items=_workflow_evidence_limit(detail_level, max_evidence),
    )
    return {
        "contract_version": "1.0.0",
        "workflow": "hunt_iocs_batch",
        "ioc_type": ioc_type,
        "requested_count": len(iocs),
        "unique_count": len(unique_iocs),
        "detail_level": detail_level,
        **result,
    }


@read_only_tool()
async def run_threat_hunt_suite(
    modules: Annotated[list[ThreatModule], Field(min_length=1, max_length=12)],
    days_back: DaysBack30 = 7,
    detail_level: DetailLevel = "summary",
    max_evidence: MaxEvidence = 5,
    max_concurrency: WorkflowConcurrency = 3,
) -> dict[str, Any]:
    """Run selected threat-hunting modules with bounded concurrency and explicit failures."""
    authorize_current_identity(agent_role="Mcp.Hunt")
    module_loaders = {
        "ransomware": lambda: hunt_ransomware_indicators(days_back),
        "powershell": lambda: hunt_suspicious_powershell(days_back),
        "lolbins": lambda: hunt_lolbin_activity(days_back),
        "lateral_movement": lambda: hunt_lateral_movement(days_back),
        "credential_access": lambda: hunt_credential_access(days_back),
        "persistence": lambda: hunt_persistence_mechanisms(days_back),
        "child_processes": lambda: hunt_suspicious_child_processes(days_back),
        "remote_access": lambda: hunt_remote_access_tools(days_back),
        "defense_evasion": lambda: hunt_defense_evasion(days_back),
        "threat_intel": lambda: hunt_threat_intel_feeds(days_back),
        "data_exfiltration": lambda: hunt_data_exfiltration(days_back),
        "asr": lambda: get_asr_events(days_back),
    }
    selected_modules = list(dict.fromkeys(modules))
    result = await run_workflow(
        {module: module_loaders[module] for module in selected_modules},
        max_concurrency=max_concurrency,
        max_items=_workflow_evidence_limit(detail_level, max_evidence),
    )
    return {
        "contract_version": "1.0.0",
        "workflow": "run_threat_hunt_suite",
        "modules": selected_modules,
        "days_back": days_back,
        "detail_level": detail_level,
        **result,
    }


# =========================================================================
# AGENT GOVERNANCE — Microsoft Graph beta (read-only, feature flagged)
# =========================================================================


async def _agent_governance_client() -> AgentGovernanceClient:
    authorize_current_identity(agent_role="Mcp.AgentGovernance")
    return AgentGovernanceClient(
        _get_graph_access_token,
        enabled=AgentGovernanceClient.enabled_from_environment(),
    )


@read_only_tool()
async def list_agent_identities(
    top: ResultLimit100 = 50,
) -> dict[str, Any]:
    """List Microsoft Entra Agent Identities using a feature-flagged Graph beta adapter."""
    client = await _agent_governance_client()
    try:
        agents = await client.list_agent_identities(top)
        return {
            "status": "success",
            "contract_version": "1.0.0-beta.1",
            "capability_status": "beta",
            "count": len(agents),
            "agents": agents,
        }
    except AgentGovernanceUnavailable:
        return {
            "status": "unavailable",
            "contract_version": "1.0.0-beta.1",
            "capability_status": "beta",
            "error": "Agent governance beta is unavailable",
        }
    finally:
        await client.close()


@read_only_tool()
async def get_agent_identity_profile(
    agent_id: Annotated[str, Field(min_length=1, max_length=256)],
    max_assignments: ResultLimit100 = 50,
) -> dict[str, Any]:
    """Get one Agent Identity and its bounded application-role assignments."""
    client = await _agent_governance_client()
    try:
        profile, assignments = await asyncio.gather(
            client.get_agent_identity(agent_id),
            client.list_agent_app_roles(agent_id),
        )
        return {
            "status": "success",
            "contract_version": "1.0.0-beta.1",
            "capability_status": "beta",
            "agent": profile,
            "permission_analysis": analyze_permission_assignments(assignments[:max_assignments]),
        }
    except AgentGovernanceUnavailable:
        return {
            "status": "unavailable",
            "contract_version": "1.0.0-beta.1",
            "capability_status": "beta",
            "error": "Agent governance beta is unavailable",
        }
    finally:
        await client.close()


@read_only_tool()
async def analyze_agent_permissions(
    agent_id: Annotated[str, Field(min_length=1, max_length=256)],
    max_assignments: ResultLimit100 = 100,
) -> dict[str, Any]:
    """Analyze one Agent Identity's application-role assignments using explainable heuristics."""
    client = await _agent_governance_client()
    try:
        assignments = await client.list_agent_app_roles(agent_id)
        return {
            "status": "success",
            "contract_version": "1.0.0-beta.1",
            "capability_status": "beta",
            "agent_id": agent_id,
            **analyze_permission_assignments(assignments[:max_assignments]),
        }
    except AgentGovernanceUnavailable:
        return {
            "status": "unavailable",
            "contract_version": "1.0.0-beta.1",
            "capability_status": "beta",
            "error": "Agent governance beta is unavailable",
        }
    finally:
        await client.close()


def _agent_risk_assessment(
    profile: dict[str, Any], assignments: list[dict[str, Any]]
) -> dict[str, Any]:
    permission_analysis = analyze_permission_assignments(assignments)
    high_priority = permission_analysis["high_priority_count"]
    assignment_count = permission_analysis["assignment_count"]
    score = min(high_priority * 25 + assignment_count * 5, 100)
    findings = []
    if high_priority:
        findings.append(
            {
                "type": "high_priority_assignments",
                "count": high_priority,
                "severity": "high",
            }
        )
    if assignment_count >= 10:
        findings.append(
            {
                "type": "broad_assignment_surface",
                "count": assignment_count,
                "severity": "medium",
            }
        )
    if profile.get("enabled") and not profile.get("app_role_assignment_required"):
        score = min(score + 10, 100)
        findings.append(
            {
                "type": "app_role_assignment_not_required",
                "severity": "medium",
            }
        )
    recommendations = []
    if high_priority:
        recommendations.append("Resolve and review high-priority app role definitions")
    if assignment_count >= 10:
        recommendations.append("Remove unused assignments after activity validation")
    if not recommendations:
        recommendations.append("Continue periodic owner, sponsor, and assignment review")
    return {
        "risk_score": score,
        "risk_level": "high" if score >= 70 else "medium" if score >= 35 else "low",
        "findings": findings,
        "recommendations": recommendations,
        "permission_analysis": permission_analysis,
        "analysis_basis": (
            "Heuristic assignment review; owner, sponsor, activity, and resolved permission values "
            "are not available in this beta adapter"
        ),
    }


@read_only_tool()
async def evaluate_agent_risk(
    agent_id: Annotated[str, Field(min_length=1, max_length=256)],
    max_assignments: ResultLimit100 = 100,
) -> dict[str, Any]:
    """Evaluate beta Agent Identity assignment risk using bounded explainable heuristics."""
    client = await _agent_governance_client()
    try:
        profile, assignments = await asyncio.gather(
            client.get_agent_identity(agent_id),
            client.list_agent_app_roles(agent_id),
        )
        return {
            "status": "success",
            "contract_version": "1.0.0-beta.1",
            "capability_status": "beta",
            "agent": profile,
            **_agent_risk_assessment(profile, assignments[:max_assignments]),
        }
    except AgentGovernanceUnavailable:
        return {
            "status": "unavailable",
            "contract_version": "1.0.0-beta.1",
            "capability_status": "beta",
            "error": "Agent governance beta is unavailable",
        }
    finally:
        await client.close()


@read_only_tool()
async def list_agents_with_excessive_permissions(
    top: ResultLimit100 = 50,
    risk_threshold: Annotated[int, Field(ge=0, le=100)] = 35,
    max_concurrency: WorkflowConcurrency = 4,
) -> dict[str, Any]:
    """List beta Agent Identities whose heuristic permission risk meets a threshold."""
    client = await _agent_governance_client()
    try:
        agents = await client.list_agent_identities(top)
        semaphore = asyncio.Semaphore(max_concurrency)

        async def assess(agent: dict[str, Any]) -> dict[str, Any]:
            async with semaphore:
                assignments = await client.list_agent_app_roles(str(agent["id"]))
            return {
                "agent": agent,
                **_agent_risk_assessment(agent, assignments[:100]),
            }

        assessments = await asyncio.gather(*(assess(agent) for agent in agents))
        excessive = [
            assessment
            for assessment in assessments
            if assessment["risk_score"] >= risk_threshold
        ]
        excessive.sort(key=lambda item: item["risk_score"], reverse=True)
        return {
            "status": "success",
            "contract_version": "1.0.0-beta.1",
            "capability_status": "beta",
            "scanned": len(agents),
            "count": len(excessive),
            "risk_threshold": risk_threshold,
            "agents": excessive,
            "excessive_permissions": [
                {
                    "agent_id": item["agent"]["id"],
                    "findings": item["findings"],
                }
                for item in excessive
            ],
            "recommendations": sorted(
                {
                    recommendation
                    for item in excessive
                    for recommendation in item["recommendations"]
                }
            ),
        }
    except AgentGovernanceUnavailable:
        return {
            "status": "unavailable",
            "contract_version": "1.0.0-beta.1",
            "capability_status": "beta",
            "error": "Agent governance beta is unavailable",
        }
    finally:
        await client.close()
