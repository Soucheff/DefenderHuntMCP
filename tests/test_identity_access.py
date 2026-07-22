from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

import server


@pytest.mark.asyncio
async def test_list_privileged_role_assignments_filters_by_role_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    privileged = SimpleNamespace(
        id="a1",
        directory_scope_id="/",
        role_definition=SimpleNamespace(
            display_name="Global Administrator", template_id="ga-template"
        ),
        principal=SimpleNamespace(
            id="u1", display_name="Root Admin", user_principal_name="root@example.com"
        ),
    )
    ordinary = SimpleNamespace(
        id="a2",
        directory_scope_id="/",
        role_definition=SimpleNamespace(display_name="Message Center Reader", template_id="mc"),
        principal=SimpleNamespace(
            id="u2", display_name="Reader", user_principal_name="reader@example.com"
        ),
    )
    client = SimpleNamespace(
        role_management=SimpleNamespace(
            directory=SimpleNamespace(
                role_assignments=SimpleNamespace(
                    get=AsyncMock(return_value=SimpleNamespace(value=[privileged, ordinary]))
                )
            )
        )
    )
    monkeypatch.setattr(server, "get_graph_client", lambda: client)

    result = await server.list_privileged_role_assignments(only_privileged=True)

    assert result["count"] == 1
    assert result["scanned"] == 2
    assert result["assignments"][0]["roleDisplayName"] == "Global Administrator"
    assert result["assignments_by_role"] == {"Global Administrator": 1}


@pytest.mark.asyncio
async def test_authentication_methods_policy_flags_weak_methods(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = SimpleNamespace(
        id="authenticationMethodsPolicy",
        display_name="Authentication Methods Policy",
        authentication_method_configurations=[
            SimpleNamespace(id="Sms", state="enabled"),
            SimpleNamespace(id="Fido2", state="enabled"),
            SimpleNamespace(id="Voice", state="disabled"),
        ],
    )
    client = SimpleNamespace(
        policies=SimpleNamespace(
            authentication_methods_policy=SimpleNamespace(
                get=AsyncMock(return_value=policy)
            )
        )
    )
    monkeypatch.setattr(server, "get_graph_client", lambda: client)

    result = await server.get_authentication_methods_policy()

    assert result["weak_methods_enabled"] == ["Sms"]
    assert {c["id"] for c in result["method_configurations"]} == {"Sms", "Fido2", "Voice"}


@pytest.mark.asyncio
async def test_find_user_oauth_grants_flags_high_risk_scopes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    grant = SimpleNamespace(
        id="g1",
        client_id="client-app",
        resource_id="graph",
        consent_type="Principal",
        scope="openid Mail.Read offline_access",
    )
    client = SimpleNamespace(
        oauth2_permission_grants=SimpleNamespace(
            get=AsyncMock(return_value=SimpleNamespace(value=[grant]))
        )
    )
    monkeypatch.setattr(server, "get_graph_client", lambda: client)

    result = await server.find_user_oauth_grants("user-id")

    assert result["count"] == 1
    assert result["high_risk_count"] == 1
    assert set(result["grants"][0]["highRiskScopes"]) == {"Mail.Read", "offline_access"}


@pytest.mark.asyncio
async def test_summarize_signin_failures_detects_spray_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def signin(upn: str, ip: str, code: int) -> SimpleNamespace:
        return SimpleNamespace(
            user_principal_name=upn,
            ip_address=ip,
            status=SimpleNamespace(error_code=code, failure_reason="Invalid credentials"),
        )

    events = [signin(f"user{i}@example.com", "10.0.0.1", 50126) for i in range(12)]
    events += [signin(f"user{i}@example.com", "10.0.0.1", 50126) for i in range(12)]
    client = SimpleNamespace(
        audit_logs=SimpleNamespace(
            sign_ins=SimpleNamespace(get=AsyncMock(return_value=SimpleNamespace(value=events)))
        )
    )
    monkeypatch.setattr(server, "get_graph_client", lambda: client)

    result = await server.summarize_signin_failures(time_range="24h")

    assert result["scanned"] == 24
    assert result["by_error_code"][0]["errorCode"] == 50126
    assert result["possible_password_spray"] is True
    assert result["top_source_ips"][0] == {"value": "10.0.0.1", "count": 24}


@pytest.mark.asyncio
async def test_get_user_app_role_assignments_projects_resources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assignment = SimpleNamespace(
        id="ara1",
        app_role_id="role-guid",
        principal_id="user-id",
        principal_display_name="Alex",
        resource_id="sp-id",
        resource_display_name="Salesforce",
        created_date_time=None,
    )
    client = SimpleNamespace(
        users=SimpleNamespace(
            by_user_id=lambda _uid: SimpleNamespace(
                app_role_assignments=SimpleNamespace(
                    get=AsyncMock(return_value=SimpleNamespace(value=[assignment]))
                )
            )
        )
    )
    monkeypatch.setattr(server, "get_graph_client", lambda: client)

    result = await server.get_user_app_role_assignments("user-id")

    assert result["count"] == 1
    assert result["resources"] == ["Salesforce"]
    assert result["app_role_assignments"][0]["resourceDisplayName"] == "Salesforce"
