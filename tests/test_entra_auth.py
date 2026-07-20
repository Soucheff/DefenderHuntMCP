from datetime import UTC, datetime, timedelta

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from entra_auth import AuthenticationError, EntraAuthSettings, EntraTokenValidator


@pytest.fixture
def signing_material():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def _token(private_key, *, scopes: str = "", roles: list[str] | None = None, tid: str = "tenant"):
    now = datetime.now(UTC)
    claims = {
        "iss": "https://login.microsoftonline.com/tenant/v2.0",
        "aud": "api://defender-hunt",
        "tid": tid,
        "oid": "subject",
        "sub": "subject",
        "azp": "caller-client",
        "iat": now,
        "nbf": now - timedelta(seconds=1),
        "exp": now + timedelta(minutes=5),
    }
    if scopes:
        claims["scp"] = scopes
    if roles is not None:
        claims["roles"] = roles
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": "test"})


def _validator(public_key, *, agent_client_ids: frozenset[str] = frozenset()) -> EntraTokenValidator:
    async def resolve(_token: str):
        return public_key

    return EntraTokenValidator(
        EntraAuthSettings(
            tenant_id="tenant",
            audience="api://defender-hunt",
            issuer="https://login.microsoftonline.com/tenant/v2.0",
            agent_client_ids=agent_client_ids,
        ),
        signing_key_resolver=resolve,
    )


@pytest.mark.asyncio
async def test_validates_delegated_user_token(signing_material) -> None:
    private_key, public_key = signing_material

    identity = await _validator(public_key).validate(
        _token(private_key, scopes="Mcp.Access ThreatHunting.Read.All")
    )

    assert identity.actor_type == "user"
    assert identity.subject_id == "subject"
    assert identity.user_assertion is not None
    assert "Mcp.Access" in identity.scopes


@pytest.mark.asyncio
async def test_validates_autonomous_agent_token(signing_material) -> None:
    private_key, public_key = signing_material

    identity = await _validator(
        public_key,
        agent_client_ids=frozenset({"caller-client"}),
    ).validate(
        _token(private_key, roles=["Mcp.Invoke", "Mcp.Hunt"])
    )

    assert identity.actor_type == "autonomous_agent"
    assert identity.agent_id == "caller-client"
    assert identity.user_assertion is None
    assert "Mcp.Invoke" in identity.roles


@pytest.mark.asyncio
async def test_validates_delegated_agent_token(signing_material) -> None:
    private_key, public_key = signing_material

    identity = await _validator(
        public_key,
        agent_client_ids=frozenset({"caller-client"}),
    ).validate(_token(private_key, scopes="Mcp.Access ThreatHunting.Read.All"))

    assert identity.actor_type == "delegated_agent"
    assert identity.subject_id == "subject"
    assert identity.agent_id == "caller-client"
    assert identity.user_assertion is not None


@pytest.mark.asyncio
async def test_rejects_wrong_tenant_or_missing_permission(signing_material) -> None:
    private_key, public_key = signing_material
    validator = _validator(public_key)

    with pytest.raises(AuthenticationError):
        await validator.validate(_token(private_key, scopes="Mcp.Access", tid="other"))
    with pytest.raises(AuthenticationError):
        await validator.validate(_token(private_key, roles=["Other.Role"]))
