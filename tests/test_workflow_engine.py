import asyncio

import pytest

from workflow_engine import run_workflow


@pytest.mark.asyncio
async def test_workflow_runs_steps_with_bounded_concurrency() -> None:
    active = 0
    peak = 0

    def loader(value: int):
        async def run():
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.01)
            active -= 1
            return {"status": "success", "items": list(range(value))}

        return run

    result = await run_workflow(
        {f"step-{index}": loader(5) for index in range(6)},
        max_concurrency=2,
        max_items=2,
    )

    assert result["status"] == "success"
    assert peak == 2
    assert result["results"]["step-0"]["data"]["items"] == [0, 1]


@pytest.mark.asyncio
async def test_workflow_preserves_partial_failures() -> None:
    async def successful():
        return '{"status":"success","count":1}'

    async def failed():
        raise RuntimeError("internal detail")

    result = await run_workflow({"good": successful, "bad": failed})

    assert result["status"] == "partial_success"
    assert result["failed_steps"] == 1
    assert result["results"]["bad"] == {
        "status": "error",
        "error": "Workflow step failed",
    }
    assert "internal detail" not in str(result)
