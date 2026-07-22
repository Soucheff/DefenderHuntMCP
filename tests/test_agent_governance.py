import httpx
import pytest

from agent_governance import (
    AgentGovernanceClient,
    AgentGovernanceUnavailable,
    analyze_permission_assignments,
)
from server import _agent_risk_assessment


@pytest.mark.asyncio
async def test_lists_beta_agent_identities_with_compact_projection() -> None:
    async def token_provider() -> str:
        return "token"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer token"
        assert request.url.params["$filter"] == "servicePrincipalType eq 'AgentIdentity'"
        return httpx.Response(
            200,
            json={
                "value": [
                    {
                        "id": "agent-id",
                        "appId": "app-id",
                        "displayName": "SOC Agent",
                        "accountEnabled": True,
                        "servicePrincipalType": "AgentIdentity",
                        "createdDateTime": "2026-01-01T00:00:00Z",
                    }
                ]
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        client = AgentGovernanceClient(
            token_provider,
            enabled=True,
            client=http_client,
        )
        agents = await client.list_agent_identities()

    assert agents == [
        {
            "id": "agent-id",
            "app_id": "app-id",
            "display_name": "SOC Agent",
            "enabled": True,
            "service_principal_type": "AgentIdentity",
            "created_at": "2026-01-01T00:00:00Z",
            "alternative_names": [],
            "app_role_assignment_required": None,
        }
    ]


@pytest.mark.asyncio
async def test_beta_adapter_fails_closed_when_disabled() -> None:
    async def token_provider() -> str:
        raise AssertionError("token provider must not be called")

    client = AgentGovernanceClient(token_provider, enabled=False)
    try:
        with pytest.raises(AgentGovernanceUnavailable, match="disabled"):
            await client.list_agent_identities()
    finally:
        await client.close()


def test_permission_analysis_is_bounded_and_explainable() -> None:
    analysis = analyze_permission_assignments(
        [
            {
                "id": "assignment",
                "appRoleId": "role",
                "resourceDisplayName": "Directory ReadWrite All",
            }
        ]
    )

    assert analysis["assignment_count"] == 1
    assert analysis["high_priority_count"] == 1
    assert "Heuristic" in analysis["analysis_basis"]


def test_agent_risk_assessment_is_explainable_and_bounded() -> None:
    assessment = _agent_risk_assessment(
        {"enabled": True, "app_role_assignment_required": False},
        [
            {
                "id": "assignment",
                "appRoleId": "role",
                "resourceDisplayName": "Directory ReadWrite All",
            }
        ],
    )

    assert assessment["risk_score"] == 40
    assert assessment["risk_level"] == "medium"
    assert {finding["type"] for finding in assessment["findings"]} == {
        "high_priority_assignments",
        "app_role_assignment_not_required",
    }
    assert "Heuristic" in assessment["analysis_basis"]
