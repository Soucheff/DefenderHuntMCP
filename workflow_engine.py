import asyncio
import json
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

WorkflowLoader = Callable[[], Awaitable[Any]]


def compact_payload(value: Any, max_items: int) -> Any:
    if isinstance(value, list):
        return [compact_payload(item, max_items) for item in value[:max_items]]
    if isinstance(value, dict):
        return {key: compact_payload(item, max_items) for key, item in value.items()}
    return value


def normalize_tool_result(value: Any, max_items: int) -> Any:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return {"text": value}
    return compact_payload(value, max_items)


async def run_workflow(
    steps: Mapping[str, WorkflowLoader],
    *,
    max_concurrency: int = 4,
    max_items: int = 10,
) -> dict[str, Any]:
    if not 1 <= max_concurrency <= 8:
        raise ValueError("max_concurrency must be between 1 and 8")
    if not 1 <= max_items <= 100:
        raise ValueError("max_items must be between 1 and 100")

    semaphore = asyncio.Semaphore(max_concurrency)

    async def execute(name: str, loader: WorkflowLoader) -> tuple[str, dict[str, Any]]:
        async with semaphore:
            try:
                value = await loader()
                normalized = normalize_tool_result(value, max_items)
                status = "success"
                if isinstance(normalized, dict) and normalized.get("status") in {
                    "error",
                    "partial_success",
                }:
                    status = normalized["status"]
                return name, {"status": status, "data": normalized}
            except Exception:
                return name, {
                    "status": "error",
                    "error": "Workflow step failed",
                }

    entries = await asyncio.gather(*(execute(name, loader) for name, loader in steps.items()))
    results = dict(entries)
    failures = sum(result["status"] == "error" for result in results.values())
    partials = sum(result["status"] == "partial_success" for result in results.values())
    if failures == len(results):
        status = "error"
    elif failures or partials:
        status = "partial_success"
    else:
        status = "success"
    return {
        "status": status,
        "step_count": len(results),
        "failed_steps": failures,
        "results": results,
    }
