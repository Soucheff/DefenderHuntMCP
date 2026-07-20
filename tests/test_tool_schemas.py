import asyncio
from typing import Any

from server import mcp


def _tool_schemas() -> dict[str, dict[str, Any]]:
    async def load() -> dict[str, dict[str, Any]]:
        tools = await mcp.list_tools()
        return {tool.name: tool.inputSchema for tool in tools}

    return asyncio.run(load())


def _enum_values(schema: dict[str, Any]) -> set[str]:
    if "enum" in schema:
        return set(schema["enum"])
    for option in schema.get("anyOf", []):
        if "enum" in option:
            return set(option["enum"])
    return set()


def test_alert_filters_publish_bounds_and_enums() -> None:
    properties = _tool_schemas()["get_security_alerts"]["properties"]

    assert properties["top"]["minimum"] == 1
    assert properties["top"]["maximum"] == 100
    assert _enum_values(properties["severity"]) == {
        "informational",
        "low",
        "medium",
        "high",
        "unknown",
    }
    assert _enum_values(properties["status"]) == {"new", "inProgress", "resolved", "unknown"}


def test_identity_filters_publish_bounds_and_enums() -> None:
    properties = _tool_schemas()["get_signin_logs"]["properties"]

    assert properties["days_back"]["minimum"] == 1
    assert properties["days_back"]["maximum"] == 30
    assert properties["top"]["minimum"] == 1
    assert properties["top"]["maximum"] == 500
    assert _enum_values(properties["status"]) == {"success", "failure", "all"}
    assert _enum_values(properties["risk_level"]) == {"none", "low", "medium", "high", "all"}


def test_advanced_hunt_days_are_bounded() -> None:
    properties = _tool_schemas()["hunt_lateral_movement"]["properties"]

    assert properties["days_back"]["minimum"] == 1
    assert properties["days_back"]["maximum"] == 30


def test_all_tools_publish_read_only_annotations() -> None:
    async def load_tools():
        return await mcp.list_tools()

    tools = asyncio.run(load_tools())

    assert len(tools) == 38
    for tool in tools:
        assert tool.annotations is not None, tool.name
        assert tool.annotations.readOnlyHint is True, tool.name
        assert tool.annotations.destructiveHint is False, tool.name
        assert tool.annotations.idempotentHint is True, tool.name
        assert tool.annotations.openWorldHint is True, tool.name


def test_workflow_tools_publish_batch_and_concurrency_bounds() -> None:
    schemas = _tool_schemas()
    batch = schemas["hunt_iocs_batch"]["properties"]
    suite = schemas["run_threat_hunt_suite"]["properties"]

    assert batch["iocs"]["minItems"] == 1
    assert batch["iocs"]["maxItems"] == 20
    assert batch["max_concurrency"]["minimum"] == 1
    assert batch["max_concurrency"]["maximum"] == 8
    assert suite["modules"]["maxItems"] == 12
