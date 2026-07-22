from unittest.mock import AsyncMock, MagicMock

import pytest

import graph_clients
from auth_context import RequestIdentity
from graph_clients import GraphClientFactory


@pytest.fixture(autouse=True)
def _reset_request_graph_state():
    graph_clients._request_credentials.set(())
    graph_clients._request_obo_client.set(None)
    yield
    graph_clients._request_credentials.set(())
    graph_clients._request_obo_client.set(None)


def test_user_identity_builds_obo_client(monkeypatch: pytest.MonkeyPatch) -> None:
    credential = MagicMock()
    obo_constructor = MagicMock(return_value=credential)
    graph_constructor = MagicMock(return_value="obo-client")
    monkeypatch.setattr(graph_clients, "OnBehalfOfCredential", obo_constructor)
    monkeypatch.setattr(graph_clients, "GraphServiceClient", graph_constructor)
    factory = GraphClientFactory("tenant", "mcp-client", client_secret="secret")
    identity = RequestIdentity(
        tenant_id="tenant",
        actor_type="user",
        subject_id="user",
        client_id="caller",
        scopes=frozenset({"Mcp.Access"}),
        user_assertion="assertion",
    )

    client = factory.get_client(identity)

    assert client == "obo-client"
    obo_constructor.assert_called_once_with(
        tenant_id="tenant",
        client_id="mcp-client",
        client_secret="secret",
        client_certificate=None,
        user_assertion="assertion",
    )
    graph_constructor.assert_called_once_with(
        credentials=credential,
        scopes=graph_clients.GRAPH_SCOPES,
    )


def test_agent_identity_reuses_managed_identity_client(monkeypatch: pytest.MonkeyPatch) -> None:
    credential = MagicMock()
    managed_constructor = MagicMock(return_value=credential)
    graph_constructor = MagicMock(return_value="managed-client")
    monkeypatch.setattr(graph_clients, "ManagedIdentityCredential", managed_constructor)
    monkeypatch.setattr(graph_clients, "GraphServiceClient", graph_constructor)
    factory = GraphClientFactory(
        "tenant",
        "mcp-client",
        managed_identity_client_id="managed-client-id",
    )
    identity = RequestIdentity(
        tenant_id="tenant",
        actor_type="autonomous_agent",
        subject_id="agent",
        client_id="caller",
        roles=frozenset({"Mcp.Invoke"}),
    )

    first = factory.get_client(identity)
    second = factory.get_client(identity)

    assert first == second == "managed-client"
    managed_constructor.assert_called_once_with(client_id="managed-client-id")
    graph_constructor.assert_called_once_with(
        credentials=credential,
        scopes=graph_clients.GRAPH_SCOPES,
    )


def test_delegated_agent_builds_obo_client(monkeypatch: pytest.MonkeyPatch) -> None:
    credential = MagicMock()
    obo_constructor = MagicMock(return_value=credential)
    graph_constructor = MagicMock(return_value="obo-client")
    monkeypatch.setattr(graph_clients, "OnBehalfOfCredential", obo_constructor)
    monkeypatch.setattr(graph_clients, "GraphServiceClient", graph_constructor)
    factory = GraphClientFactory("tenant", "mcp-client", client_secret="secret")
    identity = RequestIdentity(
        tenant_id="tenant",
        actor_type="delegated_agent",
        subject_id="user",
        client_id="agent-client",
        agent_id="agent-client",
        scopes=frozenset({"Mcp.Access"}),
        user_assertion="assertion",
    )

    client = factory.get_client(identity)

    assert client == "obo-client"
    obo_constructor.assert_called_once_with(
        tenant_id="tenant",
        client_id="mcp-client",
        client_secret="secret",
        client_certificate=None,
        user_assertion="assertion",
    )
    graph_constructor.assert_called_once_with(
        credentials=credential,
        scopes=graph_clients.GRAPH_SCOPES,
    )


def test_user_identity_requires_obo_credential() -> None:
    factory = GraphClientFactory("tenant", "mcp-client")
    identity = RequestIdentity(
        tenant_id="tenant",
        actor_type="user",
        subject_id="user",
        client_id="caller",
        scopes=frozenset({"Mcp.Access"}),
        user_assertion="assertion",
    )

    with pytest.raises(RuntimeError, match="OBO client credential"):
        factory.get_client(identity)


@pytest.mark.asyncio
async def test_obo_client_is_memoized_within_a_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    obo_constructor = MagicMock(return_value=AsyncMock())
    graph_constructor = MagicMock(side_effect=lambda **_: object())
    monkeypatch.setattr(graph_clients, "OnBehalfOfCredential", obo_constructor)
    monkeypatch.setattr(graph_clients, "GraphServiceClient", graph_constructor)
    factory = GraphClientFactory("tenant", "mcp-client", client_secret="secret")
    identity = RequestIdentity(
        tenant_id="tenant",
        actor_type="user",
        subject_id="user",
        client_id="caller",
        scopes=frozenset({"Mcp.Access"}),
        user_assertion="assertion",
    )

    try:
        first = factory.get_client(identity)
        second = factory.get_client(identity)

        assert first is second
        assert graph_constructor.call_count == 1
        assert obo_constructor.call_count == 1
    finally:
        await graph_clients.close_request_credentials()


@pytest.mark.asyncio
async def test_close_request_credentials_resets_memoized_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    obo_constructor = MagicMock(return_value=AsyncMock())
    graph_constructor = MagicMock(side_effect=lambda **_: object())
    monkeypatch.setattr(graph_clients, "OnBehalfOfCredential", obo_constructor)
    monkeypatch.setattr(graph_clients, "GraphServiceClient", graph_constructor)
    factory = GraphClientFactory("tenant", "mcp-client", client_secret="secret")
    identity = RequestIdentity(
        tenant_id="tenant",
        actor_type="user",
        subject_id="user",
        client_id="caller",
        scopes=frozenset({"Mcp.Access"}),
        user_assertion="assertion",
    )

    factory.get_client(identity)
    await graph_clients.close_request_credentials()
    factory.get_client(identity)

    assert graph_constructor.call_count == 2
    await graph_clients.close_request_credentials()
