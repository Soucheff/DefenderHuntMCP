import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

import server


class User:
    def __init__(self, object_id: str, display_name: str, upn: str) -> None:
        self.id = object_id
        self.display_name = display_name
        self.user_principal_name = upn
        self.mail = upn
        self.account_enabled = True


class Group:
    def __init__(self, object_id: str, display_name: str) -> None:
        self.id = object_id
        self.display_name = display_name
        self.user_principal_name = None
        self.mail = None
        self.account_enabled = None


@pytest.mark.asyncio
async def test_get_users_by_global_administrator_role_includes_pim_eligibility(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CACHE_BACKEND", "none")
    role_definition = SimpleNamespace(
        id="global-admin-role-id",
        display_name="Global Administrator",
        template_id="62e90394-69f5-4237-9190-012177145e10",
        is_built_in=True,
    )
    active_assignment = SimpleNamespace(
        principal=User("user-active", "Active Admin", "active@example.com"),
        directory_scope_id="/",
    )
    eligible_assignment = SimpleNamespace(
        principal=User("user-eligible", "Eligible Admin", "eligible@example.com"),
        directory_scope_id="/",
    )
    group_assignment = SimpleNamespace(
        principal=Group("role-group", "Tier 0 Admins"), directory_scope_id="/"
    )
    inherited_user = User("user-inherited", "Inherited Admin", "inherited@example.com")
    group_request = SimpleNamespace(
        transitive_members=SimpleNamespace(
            get=AsyncMock(return_value=SimpleNamespace(value=[inherited_user]))
        )
    )
    client = SimpleNamespace(
        groups=SimpleNamespace(by_group_id=lambda _group_id: group_request),
        role_management=SimpleNamespace(
            directory=SimpleNamespace(
                role_definitions=SimpleNamespace(
                    get=AsyncMock(return_value=SimpleNamespace(value=[role_definition]))
                ),
                role_assignments=SimpleNamespace(
                    get=AsyncMock(
                        return_value=SimpleNamespace(value=[active_assignment, group_assignment])
                    )
                ),
                role_eligibility_schedule_instances=SimpleNamespace(
                    get=AsyncMock(return_value=SimpleNamespace(value=[eligible_assignment]))
                ),
            )
        ),
    )
    monkeypatch.setattr(server, "get_graph_client", lambda: client)

    result = json.loads(
        await server.get_users_by_directory_role(
            "Global Administrator", assignment_state="all"
        )
    )

    assert result["status"] == "success"
    assert result["role"]["templateId"] == "62e90394-69f5-4237-9190-012177145e10"
    assert {user["userPrincipalName"] for user in result["users"]} == {
        "active@example.com",
        "eligible@example.com",
        "inherited@example.com",
    }
    assert result["groupAssignments"][0]["displayName"] == "Tier 0 Admins"
    inherited = next(
        user for user in result["users"] if user["userPrincipalName"] == "inherited@example.com"
    )
    assert inherited["assignmentVia"]["groupDisplayName"] == "Tier 0 Admins"


@pytest.mark.asyncio
async def test_analyze_identity_group_returns_transitive_member_types(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    group = SimpleNamespace(
        id="group-id",
        display_name="Privileged Operations",
        description="Privileged access group",
        mail=None,
        mail_enabled=False,
        security_enabled=True,
        group_types=[],
        visibility=None,
        membership_rule=None,
        membership_rule_processing_state=None,
        is_assignable_to_role=True,
    )
    group_request = SimpleNamespace(
        get=AsyncMock(return_value=group),
        owners=SimpleNamespace(
            get=AsyncMock(
                return_value=SimpleNamespace(
                    value=[User("owner-id", "Group Owner", "owner@example.com")]
                )
            )
        ),
        members=SimpleNamespace(get=AsyncMock()),
        transitive_members=SimpleNamespace(
            get=AsyncMock(
                return_value=SimpleNamespace(
                    value=[
                        User("member-id", "Admin User", "admin@example.com"),
                        Group("nested-id", "Nested Admins"),
                    ]
                )
            )
        ),
    )
    client = SimpleNamespace(groups=SimpleNamespace(by_group_id=lambda _group_id: group_request))
    monkeypatch.setattr(server, "get_graph_client", lambda: client)

    result = json.loads(
        await server.analyze_identity_group("group-id", membership_scope="transitive")
    )

    assert result["status"] == "success"
    assert result["group"]["isAssignableToRole"] is True
    assert result["membershipScope"] == "transitive"
    assert result["memberTypes"] == {"User": 1, "Group": 1}
    assert result["owners"][0]["userPrincipalName"] == "owner@example.com"
    group_request.members.get.assert_not_awaited()