"""Fan-out hub for dashboard alerts.

Ingestion handlers are synchronous and run in the threadpool, so they cannot
await a broadcast. ``publish_threadsafe`` schedules the coroutine on the loop the
app bound at startup, which is the same pattern the older ``src.realtime``
broadcaster used. Clients are capped so a runaway browser cannot exhaust memory.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

log = logging.getLogger(__name__)


class Hub:
    def __init__(self, max_clients: int = 64):
        self.clients: set = set()
        self.max_clients = max_clients
        self._loop: asyncio.AbstractEventLoop | None = None
        self.broadcast_count = 0
        self.rejected_clients = 0

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    @property
    def client_count(self) -> int:
        return len(self.clients)

    async def register(self, ws) -> bool:
        if len(self.clients) >= self.max_clients:
            self.rejected_clients += 1
            return False
        self.clients.add(ws)
        return True

    async def unregister(self, ws) -> None:
        self.clients.discard(ws)

    async def broadcast(self, msg: dict[str, Any]) -> None:
        if not self.clients:
            return
        self.broadcast_count += 1
        dead = []
        for ws in list(self.clients):
            try:
                await ws.send_json(msg)
            except Exception:  # noqa: BLE001 - a dead socket must not stop the fan-out
                dead.append(ws)
        for ws in dead:
            self.clients.discard(ws)

    def publish_threadsafe(self, payload: dict[str, Any]) -> None:
        """Schedule a broadcast from a worker thread; never raises."""

        if not self.clients:
            return
        loop = self._loop
        if loop is None or loop.is_closed() or not loop.is_running():
            return
        try:
            asyncio.run_coroutine_threadsafe(self.broadcast(payload), loop)
        except RuntimeError:  # loop shutting down between the check and the call
            log.debug("hub publish skipped: loop unavailable", exc_info=True)

    def status(self) -> dict[str, Any]:
        return {
            "clients": self.client_count,
            "max_clients": self.max_clients,
            "broadcasts": self.broadcast_count,
            "rejected_clients": self.rejected_clients,
            "available": self._loop is not None and self._loop.is_running() if self._loop else False,
        }
