import asyncio

import pytest
from azure.core.credentials import AccessToken

from cache_backend import (
    AzureManagedRedisCredentialProvider,
    CacheIdentity,
    CacheRecord,
    CacheService,
    MemoryCacheBackend,
    build_cache_key,
)


def test_cache_keys_are_deterministic_and_identity_isolated() -> None:
    user_a = CacheIdentity("tenant", "user", "user-a", "scope-a")
    user_b = CacheIdentity("tenant", "user", "user-b", "scope-a")
    parameters = {"status": "new", "severity": "high"}

    key_a = build_cache_key("defender-hunt", user_a, "alerts", parameters)
    key_a_repeat = build_cache_key(
        "defender-hunt",
        user_a,
        "alerts",
        {"severity": "high", "status": "new"},
    )
    key_b = build_cache_key("defender-hunt", user_b, "alerts", parameters)

    assert key_a == key_a_repeat
    assert key_a != key_b
    assert "user-a" not in key_a
    assert "tenant" not in key_a


@pytest.mark.asyncio
async def test_memory_cache_expires_records() -> None:
    now = [100.0]
    backend = MemoryCacheBackend(clock=lambda: now[0])
    record = CacheRecord(value={"count": 1}, created_at=now[0], expires_at=110.0)

    await backend.set("alerts", record, ttl_seconds=10)
    assert await backend.get("alerts") == record

    now[0] = 111.0
    assert await backend.get("alerts") is None


@pytest.mark.asyncio
async def test_cache_service_coalesces_concurrent_loads() -> None:
    backend = MemoryCacheBackend()
    service = CacheService(backend)
    load_count = 0

    async def loader() -> dict[str, int]:
        nonlocal load_count
        load_count += 1
        await asyncio.sleep(0.01)
        return {"count": 5}

    results = await asyncio.gather(
        *[service.get_or_set("dashboard", 60, loader) for _ in range(10)]
    )

    assert load_count == 1
    assert {status for _, status, _ in results} == {"miss", "hit"}
    assert all(value == {"count": 5} for value, _, _ in results)


@pytest.mark.asyncio
async def test_cache_bypass_refreshes_value() -> None:
    backend = MemoryCacheBackend()
    service = CacheService(backend)
    values = iter([1, 2])

    first, first_status, _ = await service.get_or_set("score", 60, lambda: _value(next(values)))
    second, second_status, _ = await service.get_or_set(
        "score",
        60,
        lambda: _value(next(values)),
        bypass=True,
    )

    assert (first, first_status) == (1, "miss")
    assert (second, second_status) == (2, "bypass")


async def _value(value: int) -> int:
    return value


@pytest.mark.asyncio
async def test_azure_redis_provider_uses_managed_identity_token() -> None:
    class FakeCredential:
        def __init__(self) -> None:
            self.scopes = []

        async def get_token(self, scope: str) -> AccessToken:
            self.scopes.append(scope)
            return AccessToken("redis-token", 9999999999)

        async def close(self) -> None:
            return None

    credential = FakeCredential()
    provider = AzureManagedRedisCredentialProvider(
        "managed-identity-object-id",
        credential=credential,
    )

    result = await provider.get_credentials_async()

    assert result == ("managed-identity-object-id", "redis-token")
    assert credential.scopes == ["https://redis.azure.com/.default"]
