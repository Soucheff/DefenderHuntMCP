import pytest

from auth_context import RequestIdentity, reset_request_identity, set_request_identity
from cache_runtime import cached_operation, close_cache_service


@pytest.mark.asyncio
async def test_cached_operation_returns_identity_isolated_hits(monkeypatch) -> None:
    monkeypatch.setenv("CACHE_BACKEND", "memory")
    await close_cache_service()
    loads = 0

    async def loader() -> dict[str, int]:
        nonlocal loads
        loads += 1
        return {"count": loads}

    user_a = RequestIdentity(
        tenant_id="tenant",
        actor_type="user",
        subject_id="user-a",
        client_id="client",
        scopes=frozenset({"Mcp.Access"}),
        user_assertion="token-a",
    )
    token = set_request_identity(user_a)
    try:
        first, first_meta = await cached_operation("overview", {"range": "1d"}, 60, loader)
        second, second_meta = await cached_operation("overview", {"range": "1d"}, 60, loader)
    finally:
        reset_request_identity(token)

    user_b = RequestIdentity(
        tenant_id="tenant",
        actor_type="user",
        subject_id="user-b",
        client_id="client",
        scopes=frozenset({"Mcp.Access"}),
        user_assertion="token-b",
    )
    token = set_request_identity(user_b)
    try:
        third, third_meta = await cached_operation("overview", {"range": "1d"}, 60, loader)
    finally:
        reset_request_identity(token)
        await close_cache_service()

    assert first == second == {"count": 1}
    assert third == {"count": 2}
    assert first_meta["cache_status"] == "miss"
    assert second_meta["cache_status"] == "hit"
    assert third_meta["cache_status"] == "miss"
