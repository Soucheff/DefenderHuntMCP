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


async def _multi_hunt(queries: dict[str, str]) -> dict[str, dict[str, Any]]:
    """Run hunting queries and preserve the outcome of each query."""
    out: dict[str, dict[str, Any]] = {}
    for key, q in queries.items():
        try:
            r = await _run_hunting(q)
            results = r.get("results", [])
            out[key] = {
                "status": "success",
                "row_count": r.get("rowCount", len(results)),
                "results": results,
            }
        except Exception as e:
            logger.warning("Hunt query '%s' failed: %s", key, e)
            out[key] = {
                "status": "error",
                "row_count": 0,
                "results": [],
                "error": "Query execution failed",
            }
    return out


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
