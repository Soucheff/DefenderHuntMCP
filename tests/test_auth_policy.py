import pytest

from auth_context import RequestIdentity
from auth_policy import AuthorizationError, authorize_identity


def test_agent_requires_explicit_hunt_role() -> None:
    identity = RequestIdentity(
        tenant_id="tenant",
        actor_type="agent",
        subject_id="agent",
        client_id="client",
        roles=frozenset({"Mcp.Invoke"}),
    )

    with pytest.raises(AuthorizationError, match="Mcp.Hunt"):
        authorize_identity(identity, agent_role="Mcp.Hunt")


def test_agent_with_hunt_role_is_authorized() -> None:
    identity = RequestIdentity(
        tenant_id="tenant",
        actor_type="agent",
        subject_id="agent",
        client_id="client",
        roles=frozenset({"Mcp.Invoke", "Mcp.Hunt"}),
    )

    authorize_identity(identity, agent_role="Mcp.Hunt")


def test_user_is_not_required_to_have_agent_role() -> None:
    identity = RequestIdentity(
        tenant_id="tenant",
        actor_type="user",
        subject_id="user",
        client_id="client",
        scopes=frozenset({"Mcp.Access"}),
        user_assertion="assertion",
    )

    authorize_identity(identity, agent_role="Mcp.Hunt")
