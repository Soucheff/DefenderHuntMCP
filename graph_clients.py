import itertools
import os
from contextvars import ContextVar
from pathlib import Path
from typing import Any

from azure.identity.aio import ManagedIdentityCredential, OnBehalfOfCredential
from msgraph import GraphServiceClient

from auth_context import RequestIdentity

GRAPH_SCOPES = ["https://graph.microsoft.com/.default"]
_request_credentials: ContextVar[tuple[OnBehalfOfCredential, ...]] = ContextVar(
    "defender_hunt_obo_credentials",
    default=(),
)
_request_obo_client: ContextVar[tuple[Any, GraphServiceClient] | None] = ContextVar(
    "defender_hunt_obo_client",
    default=None,
)
_factory_token_counter = itertools.count()


class GraphClientFactory:
    """Create Graph clients with delegated OBO or managed-identity credentials."""

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        *,
        client_secret: str | None = None,
        client_certificate: bytes | None = None,
        managed_identity_client_id: str | None = None,
    ) -> None:
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._client_certificate = client_certificate
        self._managed_identity_client_id = managed_identity_client_id
        self._managed_credential: ManagedIdentityCredential | None = None
        self._managed_client: GraphServiceClient | None = None
        self._cache_token = next(_factory_token_counter)

    @classmethod
    def from_environment(cls) -> "GraphClientFactory":
        tenant_id = os.getenv("AZURE_TENANT_ID", "")
        client_id = os.getenv("AZURE_CLIENT_ID", "")
        certificate_path = os.getenv("AZURE_CLIENT_CERTIFICATE_PATH")
        certificate = Path(certificate_path).read_bytes() if certificate_path else None
        if not tenant_id or not client_id:
            raise ValueError("AZURE_TENANT_ID and AZURE_CLIENT_ID are required")
        return cls(
            tenant_id,
            client_id,
            client_secret=os.getenv("AZURE_CLIENT_SECRET"),
            client_certificate=certificate,
            managed_identity_client_id=os.getenv("AZURE_MANAGED_IDENTITY_CLIENT_ID"),
        )

    def get_client(self, identity: RequestIdentity) -> GraphServiceClient:
        if identity.actor_type in {"user", "delegated_agent"}:
            return self._get_obo_client(identity)
        return self._get_managed_client()

    async def get_access_token(self, identity: RequestIdentity) -> str:
        if identity.actor_type in {"user", "delegated_agent"}:
            credential = self._create_obo_credential(identity)
        else:
            credential = self._get_managed_credential()
        token = await credential.get_token(*GRAPH_SCOPES)
        return token.token

    def _get_obo_client(self, identity: RequestIdentity) -> GraphServiceClient:
        key = (
            self._cache_token,
            identity.actor_type,
            identity.subject_id,
            identity.client_id,
            identity.user_assertion,
        )
        cached = _request_obo_client.get()
        if cached is not None and cached[0] == key:
            return cached[1]
        credential = self._create_obo_credential(identity)
        client = GraphServiceClient(credentials=credential, scopes=GRAPH_SCOPES)
        _request_obo_client.set((key, client))
        return client

    def _create_obo_credential(self, identity: RequestIdentity) -> OnBehalfOfCredential:
        if not identity.user_assertion:
            raise RuntimeError("Delegated Graph access requires a user assertion")
        if not self._client_secret and not self._client_certificate:
            raise RuntimeError("OBO client credential is not configured")
        credential = OnBehalfOfCredential(
            tenant_id=self._tenant_id,
            client_id=self._client_id,
            client_secret=self._client_secret,
            client_certificate=self._client_certificate,
            user_assertion=identity.user_assertion,
        )
        _request_credentials.set((*_request_credentials.get(), credential))
        return credential

    def _get_managed_client(self) -> GraphServiceClient:
        if self._managed_client is None:
            self._managed_credential = self._get_managed_credential()
            self._managed_client = GraphServiceClient(
                credentials=self._managed_credential,
                scopes=GRAPH_SCOPES,
            )
        return self._managed_client

    def _get_managed_credential(self) -> ManagedIdentityCredential:
        if self._managed_credential is None:
            self._managed_credential = ManagedIdentityCredential(
                client_id=self._managed_identity_client_id
            )
        return self._managed_credential

    async def close(self) -> None:
        await close_request_credentials()
        if self._managed_credential is not None:
            await self._managed_credential.close()


async def close_request_credentials() -> None:
    _request_obo_client.set(None)
    credentials = _request_credentials.get()
    _request_credentials.set(())
    for credential in credentials:
        await credential.close()
