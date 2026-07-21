import json
from unittest.mock import AsyncMock

import pytest

import server


@pytest.mark.asyncio
async def test_investigation_prefers_defender_entra_signin_events(monkeypatch) -> None:
    hunting = AsyncMock(
        return_value={
            "status": "success",
            "results": [
                {
                    "Timestamp": "2026-07-20T12:00:00Z",
                    "AccountUpn": "admin@example.com",
                    "Application": "Microsoft Azure CLI",
                    "ResourceDisplayName": "Microsoft Graph",
                    "ClientAppUsed": "Browser",
                    "LogonType": "Interactive",
                    "DeviceName": "workstation",
                    "IPAddress": "203.0.113.10",
                    "ErrorCode": 0,
                    "RiskLevelAggregated": "none",
                    "RiskLevelDuringSignIn": "none",
                    "RiskState": "none",
                },
                {
                    "Timestamp": "2026-07-20T11:00:00Z",
                    "AccountUpn": "admin@example.com",
                    "Application": "MCP Inspector",
                    "ClientAppUsed": "Browser",
                    "IPAddress": "203.0.113.10",
                    "ErrorCode": 50053,
                    "RiskLevelAggregated": "high",
                },
            ],
        }
    )
    graph_fallback = AsyncMock()
    monkeypatch.setattr(server, "_run_hunting", hunting)
    monkeypatch.setattr(server, "_investigate_entra_signins", graph_fallback)

    result = json.loads(await server.investigate_user_logon("admin@example.com", 30))

    assert result["source"] == "defender_advanced_hunting_EntraIdSignInEvents"
    assert result["count"] == 2
    assert result["successful"] == 1
    assert result["failed"] == 1
    assert result["risky"] == 1
    assert result["truncated"] is False
    assert result["ipAddresses"] == [{"value": "203.0.113.10", "count": 2}]
    query = hunting.await_args.args[0]
    assert query.index("where Timestamp") < query.index("where AccountUpn")
    assert "EntraIdSignInEvents" in query
    assert 'AccountUpn =~ "admin@example.com"' in query
    assert "| limit 500" in query
    graph_fallback.assert_not_awaited()


@pytest.mark.asyncio
async def test_entra_signin_fallback_summarizes_exact_user(monkeypatch) -> None:
    signin_lookup = AsyncMock(
        return_value=json.dumps(
            {
                "status": "success",
                "count": 3,
                "logs": [
                    {
                        "userPrincipalName": "Admin.Pedro.Soucheff@sevenkingdoms.com.br",
                        "appDisplayName": "Microsoft Azure CLI",
                        "clientAppUsed": "Browser",
                        "ipAddress": "203.0.113.10",
                        "status": {"errorCode": 0, "failureReason": None},
                        "location": {"city": "Sao Paulo", "state": "SP", "country": "BR"},
                        "riskLevel": "none",
                    },
                    {
                        "userPrincipalName": "admin.pedro.soucheff@sevenkingdoms.com.br",
                        "appDisplayName": "MCP Inspector",
                        "clientAppUsed": "Browser",
                        "ipAddress": "203.0.113.10",
                        "status": {"errorCode": 50053, "failureReason": "Account locked"},
                        "location": None,
                        "riskLevel": "high",
                    },
                    {
                        "userPrincipalName": "admin.pedro.soucheff.other@sevenkingdoms.com.br",
                        "appDisplayName": "Other",
                        "status": {"errorCode": 0},
                    },
                ],
            }
        )
    )
    monkeypatch.setattr(server, "get_signin_logs", signin_lookup)

    result = json.loads(
        await server._investigate_entra_signins(
            "admin.pedro.soucheff@sevenkingdoms.com.br",
            30,
        )
    )

    assert result["source"] == "microsoft_graph_auditLogs_signIns"
    assert result["count"] == 2
    assert result["successful"] == 1
    assert result["failed"] == 1
    assert result["risky"] == 1
    assert result["ipAddresses"] == [{"value": "203.0.113.10", "count": 2}]
    signin_lookup.assert_awaited_once_with(
        user_principal_name="admin.pedro.soucheff@sevenkingdoms.com.br",
        status="all",
        risk_level="all",
        days_back=30,
        top=500,
    )


@pytest.mark.asyncio
async def test_entra_signin_fallback_reports_no_exact_matches(monkeypatch) -> None:
    monkeypatch.setattr(
        server,
        "get_signin_logs",
        AsyncMock(
            return_value=json.dumps(
                {
                    "status": "success",
                    "count": 1,
                    "logs": [{"userPrincipalName": "someone@sevenkingdoms.com.br"}],
                }
            )
        ),
    )

    result = json.loads(await server._investigate_entra_signins("admin@example.com", 7))

    assert result["count"] == 0
    assert result["source"] == "microsoft_graph_auditLogs_signIns"
