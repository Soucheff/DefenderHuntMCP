import asyncio
from unittest.mock import AsyncMock

import pytest

import server


@pytest.mark.asyncio
async def test_multi_hunt_reports_success_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    run_hunting = AsyncMock(
        return_value={"status": "success", "rowCount": 2, "results": [{"id": 1}, {"id": 2}]}
    )
    monkeypatch.setattr(server, "_run_hunting", run_hunting)

    result = await server._multi_hunt({"processes": "DeviceProcessEvents | limit 2"})

    assert result == {
        "processes": {
            "status": "success",
            "row_count": 2,
            "results": [{"id": 1}, {"id": 2}],
        }
    }
    assert server._count_hunt_findings(result) == 2


@pytest.mark.asyncio
async def test_multi_hunt_preserves_partial_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    run_hunting = AsyncMock(side_effect=RuntimeError("upstream unavailable"))
    monkeypatch.setattr(server, "_run_hunting", run_hunting)

    result = await server._multi_hunt({"network": "DeviceNetworkEvents | limit 1"})

    assert result == {
        "network": {
            "status": "error",
            "row_count": 0,
            "results": [],
            "error": "Query execution failed",
        }
    }
    assert server._count_hunt_findings(result) == 0
    assert server._hunt_response_status(result) == "error"
    assert server._count_hunt_errors(result) == 1


def test_multi_hunt_reports_partial_success_for_mixed_results() -> None:
    result = {
        "successful": {"status": "success", "row_count": 3, "results": [{}, {}, {}]},
        "failed": {
            "status": "error",
            "row_count": 0,
            "results": [],
            "error": "Query execution failed",
        },
    }

    assert server._hunt_response_status(result) == "partial_success"
    assert server._count_hunt_findings(result) == 3
    assert server._count_hunt_errors(result) == 1


@pytest.mark.asyncio
async def test_multi_hunt_runs_queries_concurrently(monkeypatch: pytest.MonkeyPatch) -> None:
    started = 0
    peak = 0

    async def fake_run_hunting(_query: str) -> dict:
        nonlocal started, peak
        started += 1
        peak = max(peak, started)
        try:
            await asyncio.sleep(0.02)
            return {"status": "success", "rowCount": 1, "results": [{"id": 1}]}
        finally:
            started -= 1

    monkeypatch.setattr(server, "_run_hunting", fake_run_hunting)

    result = await server._multi_hunt(
        {"a": "q1", "b": "q2", "c": "q3", "d": "q4"}
    )

    assert set(result) == {"a", "b", "c", "d"}
    assert all(entry["status"] == "success" for entry in result.values())
    assert peak >= 2
