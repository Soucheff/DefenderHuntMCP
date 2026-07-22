import asyncio
import json
from types import SimpleNamespace

import pytest

import server


@pytest.mark.asyncio
async def test_get_signin_logs_returns_clean_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server, "GRAPH_QUERY_TIMEOUT_SECONDS", 0.05)

    async def slow_get(**_kwargs):
        await asyncio.sleep(0.5)
        return SimpleNamespace(value=[])

    client = SimpleNamespace(
        audit_logs=SimpleNamespace(sign_ins=SimpleNamespace(get=slow_get))
    )
    monkeypatch.setattr(server, "get_graph_client", lambda: client)

    result = json.loads(await server.get_signin_logs(user_principal_name="admin@example.com"))

    assert result["status"] == "error"
    assert result["error_code"] == "UPSTREAM_TIMEOUT"
    assert "investigate_user_logon" in result["error"]


@pytest.mark.asyncio
async def test_get_signin_logs_uses_exact_match_for_full_upn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured = {}

    async def capture_get(request_configuration):
        captured["filter"] = request_configuration.query_parameters.filter
        return SimpleNamespace(value=[])

    client = SimpleNamespace(
        audit_logs=SimpleNamespace(sign_ins=SimpleNamespace(get=capture_get))
    )
    monkeypatch.setattr(server, "get_graph_client", lambda: client)

    await server.get_signin_logs(user_principal_name="admin@example.com")
    assert "userPrincipalName eq 'admin@example.com'" in captured["filter"]
    assert "startswith(userPrincipalName" not in captured["filter"]

    await server.get_signin_logs(user_principal_name="adm")
    assert "startswith(userPrincipalName, 'adm')" in captured["filter"]
