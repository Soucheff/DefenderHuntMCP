from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from auth_context import RequestIdentity, get_request_identity
from server_http import EntraAuthMiddleware, create_app


class FakeValidator:
    async def validate(self, token: str) -> RequestIdentity:
        assert token == "valid-token"
        return RequestIdentity(
            tenant_id="tenant",
            actor_type="user",
            subject_id="user",
            client_id="client",
            scopes=frozenset({"Mcp.Access"}),
            user_assertion=token,
        )


async def protected(_request: Request) -> JSONResponse:
    identity = get_request_identity()
    return JSONResponse({"actor_type": identity.actor_type, "subject_id": identity.subject_id})


async def health(_request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


def _app(validator=None) -> EntraAuthMiddleware:
    if validator is None:
        validator = FakeValidator()
    app = Starlette(
        routes=[
            Route("/protected", protected),
            Route("/health", health),
        ]
    )
    return EntraAuthMiddleware(app, validator)


def test_requires_bearer_token() -> None:
    with TestClient(_app()) as client:
        response = client.get("/protected")

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_propagates_authenticated_identity() -> None:
    with TestClient(_app()) as client:
        response = client.get("/protected", headers={"Authorization": "Bearer valid-token"})

    assert response.status_code == 200
    assert response.json() == {"actor_type": "user", "subject_id": "user"}


def test_public_health_does_not_require_auth_configuration() -> None:
    app = Starlette(routes=[Route("/health", health)])
    with TestClient(EntraAuthMiddleware(app, validator=None)) as client:
        response = client.get("/health")

    assert response.status_code == 200


def test_authenticated_token_initializes_mcp() -> None:
    with TestClient(create_app(FakeValidator())) as client:
        response = client.post(
            "/mcp",
            headers={
                "Authorization": "Bearer valid-token",
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "auth-test", "version": "1.0"},
                },
            },
        )

    assert response.status_code == 200
    assert "defender_hunt_mcp" in response.text
