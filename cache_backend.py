import asyncio
import hashlib
import json
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import asdict, dataclass
from typing import Any, Protocol, TypeVar

import redis.asyncio as redis
from azure.identity.aio import ManagedIdentityCredential
from redis.credentials import CredentialProvider

T = TypeVar("T")
AZURE_REDIS_SCOPE = "https://redis.azure.com/.default"


class AzureManagedRedisCredentialProvider(CredentialProvider):
    """Acquire Redis AUTH credentials from an Azure managed identity."""

    def __init__(
        self,
        username: str,
        managed_identity_client_id: str | None = None,
        credential: ManagedIdentityCredential | None = None,
    ) -> None:
        if not username:
            raise ValueError("Azure Managed Redis username/object ID is required")
        self._username = username
        self._credential = credential or ManagedIdentityCredential(
            client_id=managed_identity_client_id
        )

    def get_credentials(self):
        raise RuntimeError("Azure Managed Redis credentials require the async client")

    async def get_credentials_async(self) -> tuple[str, str]:
        token = await self._credential.get_token(AZURE_REDIS_SCOPE)
        return self._username, token.token

    async def close(self) -> None:
        await self._credential.close()


@dataclass(frozen=True, slots=True)
class CacheIdentity:
    tenant_id: str
    actor_type: str
    subject_id: str
    permission_fingerprint: str


@dataclass(frozen=True, slots=True)
class CacheRecord:
    value: Any
    created_at: float
    expires_at: float


class CacheBackend(Protocol):
    async def get(self, key: str) -> CacheRecord | None: ...

    async def set(self, key: str, record: CacheRecord, ttl_seconds: int) -> None: ...

    async def delete(self, key: str) -> None: ...

    async def close(self) -> None: ...


def build_cache_key(
    namespace: str,
    identity: CacheIdentity,
    operation: str,
    parameters: Mapping[str, Any],
    contract_version: str = "v1",
) -> str:
    """Build an identity- and permission-isolated cache key without exposing raw identifiers."""
    identity_payload = json.dumps(asdict(identity), sort_keys=True, separators=(",", ":"))
    parameter_payload = json.dumps(parameters, sort_keys=True, separators=(",", ":"), default=str)
    identity_hash = hashlib.sha256(identity_payload.encode()).hexdigest()[:24]
    parameter_hash = hashlib.sha256(parameter_payload.encode()).hexdigest()
    return f"{namespace}:{contract_version}:{identity_hash}:{operation}:{parameter_hash}"


class MemoryCacheBackend:
    """Bounded TTL cache for unit tests and local process-only fallback."""

    def __init__(
        self,
        max_entries: int = 256,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be positive")
        self._max_entries = max_entries
        self._clock = clock
        self._records: OrderedDict[str, CacheRecord] = OrderedDict()
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> CacheRecord | None:
        async with self._lock:
            record = self._records.get(key)
            if record is None:
                return None
            if record.expires_at <= self._clock():
                del self._records[key]
                return None
            self._records.move_to_end(key)
            return record

    async def set(self, key: str, record: CacheRecord, ttl_seconds: int) -> None:
        if ttl_seconds < 1:
            raise ValueError("ttl_seconds must be positive")
        async with self._lock:
            self._records[key] = record
            self._records.move_to_end(key)
            while len(self._records) > self._max_entries:
                self._records.popitem(last=False)

    async def delete(self, key: str) -> None:
        async with self._lock:
            self._records.pop(key, None)

    async def close(self) -> None:
        async with self._lock:
            self._records.clear()


class RedisCacheBackend:
    """Shared async Redis cache backend for development and Azure Managed Redis."""

    def __init__(self, client: redis.Redis, max_entry_bytes: int = 1_000_000) -> None:
        self._client = client
        self._max_entry_bytes = max_entry_bytes
        self._credential_provider: AzureManagedRedisCredentialProvider | None = None

    @classmethod
    def from_url(cls, url: str, max_entry_bytes: int = 1_000_000) -> "RedisCacheBackend":
        client = redis.from_url(
            url,
            encoding="utf-8",
            decode_responses=True,
            health_check_interval=30,
            socket_connect_timeout=5,
            socket_timeout=5,
        )
        return cls(client, max_entry_bytes=max_entry_bytes)

    @classmethod
    def from_azure_managed_identity(
        cls,
        host: str,
        username: str,
        *,
        port: int = 10000,
        managed_identity_client_id: str | None = None,
        max_entry_bytes: int = 1_000_000,
    ) -> "RedisCacheBackend":
        provider = AzureManagedRedisCredentialProvider(
            username,
            managed_identity_client_id=managed_identity_client_id,
        )
        client = redis.Redis(
            host=host,
            port=port,
            ssl=True,
            ssl_cert_reqs="required",
            decode_responses=True,
            credential_provider=provider,
            health_check_interval=30,
            socket_connect_timeout=5,
            socket_timeout=5,
        )
        backend = cls(client, max_entry_bytes=max_entry_bytes)
        backend._credential_provider = provider
        return backend

    async def get(self, key: str) -> CacheRecord | None:
        payload = await self._client.get(key)
        if payload is None:
            return None
        data = json.loads(payload)
        return CacheRecord(
            value=data["value"],
            created_at=data["created_at"],
            expires_at=data["expires_at"],
        )

    async def set(self, key: str, record: CacheRecord, ttl_seconds: int) -> None:
        if ttl_seconds < 1:
            raise ValueError("ttl_seconds must be positive")
        payload = json.dumps(
            {
                "value": record.value,
                "created_at": record.created_at,
                "expires_at": record.expires_at,
            },
            separators=(",", ":"),
            default=str,
        )
        if len(payload.encode()) > self._max_entry_bytes:
            raise ValueError("Cache entry exceeds maximum serialized size")
        await self._client.set(key, payload, ex=ttl_seconds)

    async def delete(self, key: str) -> None:
        await self._client.delete(key)

    async def close(self) -> None:
        await self._client.aclose()
        if self._credential_provider is not None:
            await self._credential_provider.close()


class CacheService:
    """Cache-aside coordinator with in-process request coalescing."""

    def __init__(self, backend: CacheBackend, clock: Callable[[], float] = time.time) -> None:
        self._backend = backend
        self._clock = clock
        self._locks: dict[str, asyncio.Lock] = {}
        self._locks_guard = asyncio.Lock()

    async def get_or_set(
        self,
        key: str,
        ttl_seconds: int,
        loader: Callable[[], Awaitable[T]],
        *,
        bypass: bool = False,
    ) -> tuple[T, str, float]:
        if not bypass:
            record = await self._backend.get(key)
            if record is not None:
                return record.value, "hit", record.created_at

        lock = await self._get_lock(key)
        async with lock:
            if not bypass:
                record = await self._backend.get(key)
                if record is not None:
                    return record.value, "hit", record.created_at

            value = await loader()
            created_at = self._clock()
            record = CacheRecord(
                value=value,
                created_at=created_at,
                expires_at=created_at + ttl_seconds,
            )
            try:
                await self._backend.set(key, record, ttl_seconds)
            except Exception:
                return value, "error_bypass", created_at
            return value, "miss" if not bypass else "bypass", created_at

    async def _get_lock(self, key: str) -> asyncio.Lock:
        async with self._locks_guard:
            return self._locks.setdefault(key, asyncio.Lock())

    async def close(self) -> None:
        await self._backend.close()
