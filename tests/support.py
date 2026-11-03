# Copyright 2026 Future Joint-Stock Company
# SPDX-License-Identifier: Apache-2.0

"""Shared helpers for the test modules."""

import asyncio
import contextlib
import json
import os
import sys
from types import SimpleNamespace
from typing import Any

import httpx

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from ti_mcp import server  # noqa: E402 - needs the path above
from ti_mcp.settings import Settings  # noqa: E402

BASE_ENV = {"TI_LOGIN": "user@example.com", "TI_API_KEY": "test-key"}


def settings(**env: str) -> Settings:
    """Settings as the server would read them from this environment (and nothing else)."""
    return Settings.from_env({**BASE_ENV, **env})


class App:
    """The server's state under a controlled environment, with the network
    replaced by whichever Recorder is installed. One state per App, as in a
    running server: the client, the throttle and the open scrolls carry over
    from call to call. Each call runs in its own asyncio.run() loop; sharing one
    AsyncClient across loops is safe only because MockTransport opens no
    connections — a real transport here would need one loop for the App."""

    def __init__(self, **env: str):
        self.settings = settings(**env)
        self.recorder: Recorder | None = None
        self.state = server.app_state(self.settings, transport=httpx.MockTransport(self._handle))

    def _handle(self, request: httpx.Request) -> httpx.Response:
        if self.recorder is None:
            raise AssertionError(f"unexpected request: {request.url}")
        return self.recorder(request)

    def call_tool(self, name: str, **arguments: Any):
        params = server.types.CallToolRequestParams(name=name, arguments=arguments)
        context = SimpleNamespace(lifespan_context=self.state)
        return asyncio.run(server.on_call_tool(context, params))

    def get(self, path: str, params: dict[str, Any] | None = None):
        return asyncio.run(self.state.client.get(path, params, throttle_key=path))


class Recorder:
    """A mock network that records requests and plays back canned responses;
    a callable instead of responses decides each answer itself."""

    def __init__(self, *responses: httpx.Response, handler=None):
        self.responses = list(responses)
        self.handler = handler
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.handler is not None:
            return self.handler(request)
        return self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]

    @contextlib.contextmanager
    def install(self, app: App):
        """Route the app's requests here for the duration of the block."""
        app.recorder = self
        try:
            yield self
        finally:
            app.recorder = None


def json_response(status: int, payload: Any, **headers: str) -> httpx.Response:
    return httpx.Response(
        status, content=json.dumps(payload).encode(), headers={"content-type": "application/json", **headers}
    )
