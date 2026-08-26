from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, suppress
from typing import Any

WORKER_KEEPALIVE_INTERVAL_SECONDS = 240.0
_WORKER_KEEPALIVE_TASK_NAME = "mcp-worker-keepalive"


def _debug_log(debug: bool, message: str) -> None:
    if debug:
        print(f"[debug] {message}")


def _worker_keepalive_session(session: Any) -> Any:
    bound_session = getattr(session, "session", None)
    return bound_session if bound_session is not None else session


async def _keepalive_worker(session: Any, *, debug: bool, activity: str) -> None:
    keepalive_session = _worker_keepalive_session(session)
    while True:
        await asyncio.sleep(WORKER_KEEPALIVE_INTERVAL_SECONDS)
        try:
            # MCP protocol ping is handled by the supervisor itself. py_eval is
            # forwarded to the bound worker and therefore refreshes its idle TTL.
            await keepalive_session.call_tool(
                name="py_eval",
                arguments={"code": "1"},
            )
            _debug_log(debug, f"refreshed MCP worker TTL during {activity}")
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - keepalive must not replace the foreground result
            _debug_log(
                debug,
                f"MCP worker keepalive stopped during {activity}: "
                f"{type(exc).__name__}: {exc}",
            )
            return


@asynccontextmanager
async def keepalive_worker_during(session: Any, *, debug: bool, activity: str):
    task = asyncio.create_task(
        _keepalive_worker(session, debug=debug, activity=activity),
        name=_WORKER_KEEPALIVE_TASK_NAME,
    )
    try:
        yield
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
