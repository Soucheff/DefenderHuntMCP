import asyncio
import logging
import os

from auth_context import RequestIdentity, reset_request_identity, set_request_identity
from cache_runtime import cached_operation, close_cache_service
from graph_clients import close_request_credentials
from server import _fetch_conditional_access_policies, _fetch_security_recommendations

logger = logging.getLogger(__name__)


async def warm_cache() -> dict[str, str]:
    tenant_id = os.environ["AZURE_TENANT_ID"]
    client_id = os.environ["AZURE_MANAGED_IDENTITY_CLIENT_ID"]
    subject_id = os.getenv("AZURE_MANAGED_IDENTITY_PRINCIPAL_ID", client_id)
    identity = RequestIdentity(
        tenant_id=tenant_id,
        actor_type="autonomous_agent",
        subject_id=subject_id,
        client_id=client_id,
        roles=frozenset({"Mcp.Invoke"}),
    )
    context_token = set_request_identity(identity)
    try:
        _, ca_metadata = await cached_operation(
            "conditional_access_policies",
            {"state": "all", "include_details": True},
            1800,
            lambda: _fetch_conditional_access_policies("all", True),
        )
        _, score_metadata = await cached_operation(
            "secure_score_control_profiles",
            {"category": None, "top": 100},
            3600,
            lambda: _fetch_security_recommendations(None, 100),
        )
        return {
            "conditional_access": ca_metadata["cache_status"],
            "secure_score_controls": score_metadata["cache_status"],
        }
    finally:
        await close_request_credentials()
        await close_cache_service()
        reset_request_identity(context_token)


if __name__ == "__main__":
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
    result = asyncio.run(warm_cache())
    logger.info("Cache warm-up completed: %s", result)
