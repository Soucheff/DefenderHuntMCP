import argparse
import asyncio
import json
from pathlib import Path
from typing import Any

from server import mcp


def _annotations(tool) -> dict[str, Any] | None:
    if tool.annotations is None:
        return None
    return tool.annotations.model_dump(exclude_none=True)


async def build_contract_snapshot() -> dict[str, Any]:
    tools = await mcp.list_tools()
    resources = await mcp.list_resources()
    return {
        "schema_version": "1.0.0",
        "server": "defender_hunt_mcp",
        "server_version": "3.0.0",
        "tools": [
            {
                "name": tool.name,
                "description": tool.description,
                "input_schema": tool.inputSchema,
                "output_schema": tool.outputSchema,
                "annotations": _annotations(tool),
            }
            for tool in sorted(tools, key=lambda item: item.name)
        ],
        "resources": [
            {
                "uri": str(resource.uri),
                "name": resource.name,
                "description": resource.description,
                "mime_type": resource.mimeType,
            }
            for resource in sorted(resources, key=lambda item: str(item.uri))
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Export stable Defender Hunt MCP contracts")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("contracts/defender-hunt-mcp.v1.json"),
    )
    args = parser.parse_args()
    snapshot = asyncio.run(build_contract_snapshot())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
