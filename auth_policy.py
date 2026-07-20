from auth_context import RequestIdentity, get_request_identity


class AuthorizationError(Exception):
    """Raised when an authenticated caller lacks a required MCP capability."""


def authorize_identity(
    identity: RequestIdentity,
    *,
    agent_role: str | None = None,
    user_scope: str | None = None,
) -> None:
    if (
        identity.actor_type == "autonomous_agent"
        and agent_role
        and agent_role not in identity.roles
    ):
        raise AuthorizationError(f"Required application role is missing: {agent_role}")
    if (
        identity.actor_type in {"user", "delegated_agent"}
        and user_scope
        and user_scope not in identity.scopes
    ):
        raise AuthorizationError(f"Required delegated scope is missing: {user_scope}")


def authorize_current_identity(
    *,
    agent_role: str | None = None,
    user_scope: str | None = None,
) -> RequestIdentity:
    identity = get_request_identity()
    authorize_identity(identity, agent_role=agent_role, user_scope=user_scope)
    return identity
