import pytest

import cache_warmup


@pytest.mark.asyncio
async def test_warmup_only_loads_stable_shared_data(monkeypatch) -> None:
    monkeypatch.setenv("AZURE_TENANT_ID", "tenant")
    monkeypatch.setenv("AZURE_MANAGED_IDENTITY_CLIENT_ID", "managed-client")
    operations = []

    async def cached_operation(operation, parameters, ttl_seconds, loader):
        operations.append((operation, parameters, ttl_seconds))
        return {}, {"cache_status": "miss"}

    async def no_op() -> None:
        return None

    monkeypatch.setattr(cache_warmup, "cached_operation", cached_operation)
    monkeypatch.setattr(cache_warmup, "close_request_credentials", no_op)
    monkeypatch.setattr(cache_warmup, "close_cache_service", no_op)

    result = await cache_warmup.warm_cache()

    assert result == {
        "conditional_access": "miss",
        "secure_score_controls": "miss",
    }
    assert [operation for operation, _, _ in operations] == [
        "conditional_access_policies",
        "secure_score_control_profiles",
    ]
