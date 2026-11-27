"""WebSocket fan-out with per-client back-pressure.

The ingestion worker runs in a plain thread (SQLite and scikit-learn are
synchronous), so publishing goes through ``publish_threadsafe`` which hops
onto the asyncio loop that owns the WebSocket connections.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any

logger = logging.getLogger(__name__)


class ConnectionManager:
    def __init__(self, max_clients: int = 200, queue_size: int = 500) -> None:
        self.max_clients = max_clients
        self.queue_size = queue_size
        self._clients: dict[int, asyncio.Queue] = {}
        self._loop: asyncio.AbstractEventLoop | None = None
        self._lock = threading.Lock()
        self._next_id = 0
        self.dropped_messages = 0
        self.rejected_clients = 0

    # ------------------------------------------------------------------ #
    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    @property
    def client_count(self) -> int:
        with self._lock:
            return len(self._clients)

    def register(self) -> tuple[int, asyncio.Queue] | None:
        with self._lock:
            if len(self._clients) >= self.max_clients:
                self.rejected_clients += 1
                return None
            self._next_id += 1
            client_id = self._next_id
            queue: asyncio.Queue = asyncio.Queue(maxsize=self.queue_size)
            self._clients[client_id] = queue
            return client_id, queue

    def unregister(self, client_id: int) -> None:
        with self._lock:
            self._clients.pop(client_id, None)

    # ------------------------------------------------------------------ #
    async def broadcast(self, message: dict[str, Any]) -> None:
        with self._lock:
            queues = list(self._clients.values())
        for queue in queues:
            try:
                queue.put_nowait(message)
            except asyncio.QueueFull:
                # Drop the oldest item to keep the stream live for this client.
                try:
                    queue.get_nowait()
                    queue.put_nowait(message)
                    self.dropped_messages += 1
                except (asyncio.QueueEmpty, asyncio.QueueFull):
                    self.dropped_messages += 1

    def publish_threadsafe(self, message: dict[str, Any]) -> None:
        loop = self._loop
        if loop is None or loop.is_closed():
            return
        try:
            asyncio.run_coroutine_threadsafe(self.broadcast(message), loop)
        except RuntimeError:  # loop shutting down
            pass

    def status(self) -> dict[str, Any]:
        return {
            "clients": self.client_count,
            "max_clients": self.max_clients,
            "dropped_messages": self.dropped_messages,
            "rejected_clients": self.rejected_clients,
        }
