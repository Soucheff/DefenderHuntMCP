import os
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

TokenProvider = Callable[[], Awaitable[str]]


class AgentGovernanceUnavailable(RuntimeError):
    """Raised when beta agent governance is disabled or unavailable."""


class AgentGovernanceClient:
    """Minimal Microsoft Graph beta adapter isolated from stable Graph SDK models."""

    def __init__(
        self,
        token_provider: TokenProvider,
        *,
        enabled: bool,
        base_url: str = "https://graph.microsoft.com/beta",
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._token_provider = token_provider
        self._enabled = enabled
        self._base_url = base_url.rstrip("/")
        self._client = client or httpx.AsyncClient(timeout=20)
        self._owns_client = client is None

    @classmethod
    def enabled_from_environment(cls) -> bool:
        return os.getenv("ENABLE_AGENT_GOVERNANCE_BETA", "false").lower() == "true"

    async def list_agent_identities(self, top: int = 50) -> list[dict[str, Any]]:
        data = await self._get(
            "/servicePrincipals",
            params={
                "$filter": "servicePrincipalType eq 'AgentIdentity'",
                "$select": (
                    "id,appId,displayName,accountEnabled,servicePrincipalType,"
                    "createdDateTime,alternativeNames"
                ),
                "$top": str(top),
            },
        )
        values = data.get("value")
        if not isinstance(values, list):
            raise AgentGovernanceUnavailable("Unexpected Agent Identity response schema")
        return [self._project_agent(value) for value in values if isinstance(value, dict)]

    async def get_agent_identity(self, agent_id: str) -> dict[str, Any]:
        data = await self._get(
            f"/servicePrincipals/{agent_id}",
            params={
                "$select": (
                    "id,appId,displayName,accountEnabled,servicePrincipalType,"
                    "createdDateTime,alternativeNames,appRoleAssignmentRequired"
                )
            },
        )
        if not isinstance(data, dict) or not data.get("id"):
            raise AgentGovernanceUnavailable("Unexpected Agent Identity response schema")
        return self._project_agent(data)

    async def list_agent_app_roles(self, agent_id: str) -> list[dict[str, Any]]:
        data = await self._get(
            f"/servicePrincipals/{agent_id}/appRoleAssignments",
            params={"$select": "id,appRoleId,resourceId,resourceDisplayName,createdDateTime"},
        )
        values = data.get("value")
        if not isinstance(values, list):
            raise AgentGovernanceUnavailable("Unexpected app role response schema")
        return [value for value in values if isinstance(value, dict)]

    async def _get(self, path: str, params: dict[str, str]) -> dict[str, Any]:
        if not self._enabled:
            raise AgentGovernanceUnavailable("Agent governance beta is disabled")
        token = await self._token_provider()
        response = await self._client.get(
            f"{self._base_url}{path}",
            params=params,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            },
        )
        if response.status_code in {401, 403, 404}:
            raise AgentGovernanceUnavailable("Agent governance beta is unavailable")
        response.raise_for_status()
        return response.json()

    @staticmethod
    def _project_agent(value: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": value.get("id"),
            "app_id": value.get("appId"),
            "display_name": value.get("displayName"),
            "enabled": value.get("accountEnabled"),
            "service_principal_type": value.get("servicePrincipalType"),
            "created_at": value.get("createdDateTime"),
            "alternative_names": value.get("alternativeNames") or [],
            "app_role_assignment_required": value.get("appRoleAssignmentRequired"),
        }

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()


def analyze_permission_assignments(assignments: list[dict[str, Any]]) -> dict[str, Any]:
    high_privilege_terms = ("write", "readwrite", "manage", "full", "all")
    findings = []
    for assignment in assignments:
        resource = str(assignment.get("resourceDisplayName") or "")
        normalized = resource.lower()
        findings.append(
            {
                "assignment_id": assignment.get("id"),
                "app_role_id": assignment.get("appRoleId"),
                "resource": resource,
                "created_at": assignment.get("createdDateTime"),
                "review_priority": "high"
                if any(term in normalized for term in high_privilege_terms)
                else "standard",
            }
        )
    return {
        "assignment_count": len(findings),
        "high_priority_count": sum(item["review_priority"] == "high" for item in findings),
        "assignments": findings,
        "analysis_basis": "Heuristic review only; verify effective Graph app role definitions",
    }
