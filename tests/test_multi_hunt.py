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
