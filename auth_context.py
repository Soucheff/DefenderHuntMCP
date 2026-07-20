from contextvars import ContextVar, Token
from dataclasses import dataclass, field
from typing import Literal

ActorType = Literal["user", "agent"]


@dataclass(frozen=True, slots=True)
class RequestIdentity:
    tenant_id: str
    actor_type: ActorType
    subject_id: str
    client_id: str
    scopes: frozenset[str] = field(default_factory=frozenset)
    roles: frozenset[str] = field(default_factory=frozenset)
    user_assertion: str | None = field(default=None, repr=False, compare=False)


_current_identity: ContextVar[RequestIdentity | None] = ContextVar(
    "defender_hunt_request_identity",
    default=None,
)


def set_request_identity(identity: RequestIdentity) -> Token[RequestIdentity | None]:
    return _current_identity.set(identity)


def reset_request_identity(token: Token[RequestIdentity | None]) -> None:
    _current_identity.reset(token)


def get_request_identity() -> RequestIdentity:
    identity = _current_identity.get()
    if identity is None:
        raise RuntimeError("Authenticated request identity is unavailable")
    return identity
