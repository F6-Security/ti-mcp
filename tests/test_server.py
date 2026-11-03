# Copyright 2026 Future Joint-Stock Company
# SPDX-License-Identifier: Apache-2.0

"""Tests for the TI MCP server.

Run from the repository root:

    ./venv/bin/python -m unittest discover -s tests -v

No network: the server is exercised in-process, and the stdio handshake test
spawns the installed console script with placeholder credentials.
"""

import asyncio
import json
import os
import shutil
import subprocess
import threading
import unittest
from types import SimpleNamespace
from unittest import mock

from support import BASE_ENV, App
from ti_mcp import catalog, server, settings

EXPECTED_TOOLS = [
    "ti_list_collections",
    "ti_get_collection",
    "ti_get_updates",
    "ti_global_search",
    "ti_get_sequence_list",
    "ti_get_item",
    "ti_graph_lookup",
    "ti_describe_collections",
    "ti_request",
]


ti = App()


class TestToolList(unittest.TestCase):
    def test_lists_every_tool_once(self):
        context = SimpleNamespace(lifespan_context=ti.state)
        result = asyncio.run(server.on_list_tools(context, None))
        self.assertEqual([tool.name for tool in result.tools], EXPECTED_TOOLS)

    def test_every_tool_is_read_only(self):
        for tool in ti.state.tools:
            with self.subTest(tool=tool.name):
                self.assertTrue(tool.annotations.read_only_hint)
                self.assertFalse(tool.annotations.destructive_hint)

    def test_only_describe_is_local(self):
        local = [tool.name for tool in ti.state.tools if not tool.annotations.open_world_hint]
        self.assertEqual(local, ["ti_describe_collections"])


class TestVersion(unittest.TestCase):
    def test_user_agent_and_server_version_follow_the_package(self):
        from ti_mcp import __version__

        self.assertEqual(settings.USER_AGENT, f"f6-ti-mcp/{__version__}")
        self.assertEqual(server.build_server(ti.settings).version, __version__)


class TestDescribeCollections(unittest.TestCase):
    """The only tool that answers without the network, so it is callable here."""

    def call(self, **arguments):
        result = ti.call_tool("ti_describe_collections", **arguments)
        self.assertFalse(result.is_error, result.content[0].text)
        return json.loads(result.content[0].text)

    def test_listing_covers_the_catalogue(self):
        listing = self.call()
        names = [entry["collection"] for entry in listing["collections"]]
        self.assertEqual(names, catalog.KNOWN_COLLECTIONS)
        self.assertNotIn("fields", listing["collections"][0])

    def test_single_collection_includes_fields(self):
        described = self.call(collection="ioc/common")
        self.assertTrue(described["documented"])
        self.assertIn("fields", described)

    def test_unknown_tool_is_an_error(self):
        result = ti.call_tool("ti_nope")
        self.assertTrue(result.is_error)
        self.assertIn("Unknown tool", result.content[0].text)


class TestStartup(unittest.TestCase):
    def test_a_bad_setting_stops_the_server_with_its_reason(self):
        env = {**BASE_ENV, "TI_TIMEOUT": "soon"}
        with mock.patch.dict(os.environ, env, clear=True), self.assertRaises(SystemExit) as caught:
            server.cli()
        self.assertEqual(str(caught.exception.code), "ti-mcp: TI_TIMEOUT must be a number, got 'soon'")

    def test_the_tool_descriptions_follow_the_settings(self):
        description = App(TI_RESULT_ID_TTL="90").state.tools[1].description
        self.assertIn("valid ~90 s after its last use", description)


TI_MCP = shutil.which("ti-mcp")


# In CI the command must be installed: a missing script fails the test rather than skipping it.
@unittest.skipUnless(TI_MCP or os.environ.get("CI"), "console script is not installed")
class TestStdioHandshake(unittest.TestCase):
    """The installed `ti-mcp` command must answer initialize and tools/list."""

    REQUESTS = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "0"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    ]

    def test_initialize_and_list_tools(self):
        self.assertIsNotNone(TI_MCP, "the ti-mcp console script is not on PATH")
        env = {**os.environ, **BASE_ENV, "TI_BASE_URL": "https://ti.example.com"}
        proc = subprocess.Popen(  # noqa: S603 - absolute path, fixed argv, no shell
            [TI_MCP], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, env=env
        )
        # A server that stays alive but never answers would block the read
        # below for good; the watchdog turns that into a failed assertion.
        watchdog = threading.Timer(30, proc.kill)
        watchdog.start()
        tools = instructions = None
        try:
            for request in self.REQUESTS:
                proc.stdin.write(json.dumps(request) + "\n")
            proc.stdin.flush()
            # Read while stdin stays open: closing it first makes the server
            # exit on EOF before it has answered.
            for line in proc.stdout:
                message = json.loads(line)
                if message.get("id") == 1:
                    instructions = message["result"].get("instructions")
                if message.get("id") == 2:
                    tools = [tool["name"] for tool in message["result"]["tools"]]
                    break
        finally:
            watchdog.cancel()
            proc.stdin.close()
            proc.terminate()
            proc.wait(timeout=10)
            proc.stdout.close()
        self.assertEqual(tools, EXPECTED_TOOLS)
        self.assertEqual(instructions, server.INSTRUCTIONS)


if __name__ == "__main__":
    unittest.main()
