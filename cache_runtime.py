import hashlib
import os
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from auth_context import RequestIdentity, get_request_identity
from cache_backend import (
    CacheIdentity,
    CacheService,
    MemoryCacheBackend,
    RedisCacheBackend,
    build_cache_key,
)

_cache_service: CacheService | None = None
_cache_backend_name: str | None = None


def _permission_fingerprint(identity: RequestIdentity) -> str:
    permissions = sorted((*identity.scopes, *identity.roles))
    return hashlib.sha256("\n".join(permissions).encode()).hexdigest()[:24]


def _cache_identity(identity: RequestIdentity) -> CacheIdentity:
    return CacheIdentity(
        tenant_id=identity.tenant_id,
        actor_type=identity.actor_type,
        subject_id=identity.subject_id,
        permission_fingerprint=_permission_fingerprint(identity),
    )


def get_cache_service() -> CacheService | None:
    global _cache_service, _cache_backend_name
    backend_name = os.getenv("CACHE_BACKEND", "none").lower()
    if _cache_backend_name == backend_name:
        return _cache_service

    _cache_backend_name = backend_name
    if backend_name == "none":
        _cache_service = None
    elif backend_name == "memory":
        _cache_service = CacheService(MemoryCacheBackend(max_entries=256))
    elif backend_name == "redis":
        url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        _cache_service = CacheService(RedisCacheBackend.from_url(url))
    elif backend_name == "azure-managed-redis":
        host = os.getenv("REDIS_HOST", "")
        username = os.getenv("REDIS_ENTRA_USERNAME", "")
        if not host or not username:
            raise ValueError("REDIS_HOST and REDIS_ENTRA_USERNAME are required")
        backend = RedisCacheBackend.from_azure_managed_identity(
            host,
            username,
            port=int(os.getenv("REDIS_PORT", "10000")),
            managed_identity_client_id=os.getenv("AZURE_MANAGED_IDENTITY_CLIENT_ID"),
        )
        _cache_service = CacheService(backend)
    else:
        raise ValueError(f"Unsupported CACHE_BACKEND: {backend_name}")
    return _cache_service


async def cached_operation[T](
    operation: str,
    parameters: Mapping[str, Any],
    ttl_seconds: int,
    loader: Callable[[], Awaitable[T]],
) -> tuple[T, dict[str, Any]]:
    service = get_cache_service()
    if service is None:
        return await loader(), {"cache_status": "disabled"}

    identity = get_request_identity()
    key = build_cache_key(
        os.getenv("REDIS_KEY_PREFIX", "defender-hunt"),
        _cache_identity(identity),
        operation,
        parameters,
    )
    try:
        value, status, created_at = await service.get_or_set(
            key,
            ttl_seconds,
            loader,
        )
        return value, {"cache_status": status, "cache_created_at": created_at}
    except Exception:
        return await loader(), {"cache_status": "error_bypass"}


async def close_cache_service() -> None:
    global _cache_service, _cache_backend_name
    if _cache_service is not None:
        await _cache_service.close()
    _cache_service = None
    _cache_backend_name = None
