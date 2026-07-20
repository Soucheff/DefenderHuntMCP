import json

from server import resource_capabilities


def test_capabilities_publish_auth_cache_beta_and_limits(monkeypatch) -> None:
    monkeypatch.setenv("ENABLE_AGENT_GOVERNANCE_BETA", "true")

    capabilities = json.loads(resource_capabilities())

    assert capabilities["auth_modes"] == [
        "entra_user_obo",
        "entra_agent_id_delegated_obo",
        "entra_agent_id_autonomous",
        "entra_application_managed_identity_legacy",
    ]
    assert capabilities["capabilities"]["agent_governance"]["status"] == "beta"
    assert capabilities["capabilities"]["cache"]["azure_backend"] == "azure_managed_redis"
    assert capabilities["limits"]["ioc_batch"] == 20
