import asyncio
import json
from pathlib import Path

from export_contracts import build_contract_snapshot


def test_committed_contract_snapshot_matches_runtime() -> None:
    committed = json.loads(Path("contracts/defender-hunt-mcp.v1.json").read_text())
    runtime = asyncio.run(build_contract_snapshot())

    assert committed == runtime
    assert len(runtime["tools"]) == 38
    assert len(runtime["resources"]) == 8
