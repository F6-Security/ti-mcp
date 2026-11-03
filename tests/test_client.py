# Copyright 2026 Future Joint-Stock Company
# SPDX-License-Identifier: Apache-2.0

"""What leaves the process and what comes back, through a mock transport."""

import asyncio
import base64
import json
import unittest
from unittest import mock

import httpx

from support import App, Recorder, json_response
from ti_mcp import client, server, settings

# No feed throttling: the retry tests would otherwise sleep a second per attempt.
ti = App(TI_MIN_FEED_INTERVAL="0", TI_RETRIES="1")


def get(recorder: Recorder, path: str, params=None, app: App = ti):
    with recorder.install(app):
        return app.get(path, params)


class TestRequestShape(unittest.TestCase):
    def test_basic_auth_user_agent_and_api_root(self):
        recorder = Recorder(json_response(200, {"ok": True}))
        result = get(recorder, "user/granted_collections", {"a": 1, "b": None, "c": 0})
        self.assertEqual(result, {"ok": True})
        request = recorder.requests[0]
        self.assertEqual(str(request.url), "https://ti.f6.security/api/v2/user/granted_collections?a=1&c=0")
        expected = base64.b64encode(b"user@example.com:test-key").decode()
        self.assertEqual(request.headers["authorization"], f"Basic {expected}")
        self.assertEqual(request.headers["user-agent"], settings.USER_AGENT)
        self.assertEqual(request.headers["accept"], "application/json")

    def test_missing_credentials_fail_before_any_request(self):
        bare = App(TI_LOGIN="", TI_API_KEY="")
        recorder = Recorder(json_response(200, {}))
        with self.assertRaisesRegex(RuntimeError, "TI_LOGIN and TI_API_KEY"):
            get(recorder, "search", {"q": "x"}, app=bare)
        self.assertEqual(recorder.requests, [])


class TestResponses(unittest.TestCase):
    def test_redirect_is_not_followed_and_names_the_allow_list(self):
        recorder = Recorder(httpx.Response(302, headers={"location": "https://ti.f6.security/login"}))
        with self.assertRaisesRegex(RuntimeError, "trusted list"):
            get(recorder, "search", {"q": "x"})
        self.assertEqual(len(recorder.requests), 1)

    def test_json_error_body_is_echoed_bounded(self):
        body = {"error": "x" * 2000}
        recorder = Recorder(json_response(400, body))
        with self.assertRaises(client.APIError) as caught:
            get(recorder, "ioc/common")
        message = str(caught.exception)
        self.assertEqual(caught.exception.status, 400)
        self.assertIn("API error 400", message)
        self.assertIn(client.STATUS_HINTS[400], message)
        self.assertIn('{"error": "xxx', message)
        self.assertLess(len(message), len(client.STATUS_HINTS[400]) + settings.MAX_ERROR_CHARS + 50)

    def test_html_error_body_is_not_echoed(self):
        recorder = Recorder(
            httpx.Response(
                500, content=b"<html>Traceback at upstream-7</html>", headers={"content-type": "text/html"}
            )
        )
        with self.assertRaises(client.APIError) as caught:
            get(recorder, "ioc/common")
        self.assertNotIn("Traceback", str(caught.exception))
        self.assertIn(client.STATUS_HINTS[500], str(caught.exception))

    def test_oversized_response_is_refused(self):
        payload = {"items": ["x" * settings.MAX_RESPONSE_BYTES]}
        recorder = Recorder(json_response(200, payload))
        with self.assertRaisesRegex(RuntimeError, "byte limit"):
            get(recorder, "ioc/common")

    def test_non_json_success_is_an_error(self):
        for content, content_type in ((b"%PDF-1.4", "application/pdf"), (b"<html>x</html>", "text/html")):
            recorder = Recorder(httpx.Response(200, content=content, headers={"content-type": content_type}))
            with (
                self.subTest(content_type=content_type),
                self.assertRaisesRegex(RuntimeError, f"expected JSON.*unparsable body.*{content_type}"),
            ):
                get(recorder, "apt/threat/1")

    def test_json_success_is_accepted_whatever_the_header_says(self):
        for headers in ({"content-type": "text/plain"}, {}):
            recorder = Recorder(httpx.Response(200, content=b'{"a": 1}', headers=headers))
            with self.subTest(headers=headers):
                self.assertEqual(get(recorder, "search", {"q": "x"}), {"a": 1})

    def test_empty_body_is_reported_as_such(self):
        recorder = Recorder(httpx.Response(204))
        self.assertEqual(get(recorder, "ioc/common"), {"status": 204, "body": None})

    def test_retry_honours_retry_after_then_gives_up(self):
        recorder = Recorder(json_response(429, {"message": "slow down"}, **{"retry-after": "0"}))
        with self.assertRaises(client.APIError) as caught:
            get(recorder, "ioc/common")
        self.assertEqual(caught.exception.status, 429)
        self.assertEqual(len(recorder.requests), ti.settings.retries + 1)

    def test_transport_error_names_the_url(self):
        def boom(request):
            raise httpx.ConnectError("")

        with self.assertRaisesRegex(
            RuntimeError, "Network error contacting https://ti.f6.security/api/v2/search: ConnectError"
        ):
            get(Recorder(handler=boom), "search", {"q": "x"})


class TestProxyHints(unittest.TestCase):
    def network_error(self, app):
        def boom(request):
            raise httpx.ConnectError("refused")

        with self.assertRaises(RuntimeError) as caught:
            get(Recorder(handler=boom), "search", {"q": "x"}, app=app)
        return str(caught.exception)

    def test_proxy_credentials_stay_out_of_the_error(self):
        message = self.network_error(App(TI_PROXY="http://puser:psecret@proxy.local:3128"))
        self.assertIn("TI_PROXY (proxy.local:3128)", message)
        self.assertNotIn("psecret", message)
        self.assertNotIn("puser", message)

    def test_ignored_ambient_proxy_is_named_without_its_value(self):
        message = self.network_error(App(HTTPS_PROXY="http://ambient:3128"))
        self.assertIn("HTTP(S)_PROXY is ignored; set TI_PROXY", message)
        self.assertNotIn("ambient", message)

    def test_no_proxy_no_hint(self):
        message = self.network_error(App())
        self.assertNotIn("PROXY", message)


class TestToolsOnTheWire(unittest.TestCase):
    def test_ti_request_sends_only_vetted_paths(self):
        recorder = Recorder(json_response(200, {"items": []}))
        with recorder.install(ti):
            result = ti.call_tool(
                "ti_request", path="/ioc/common/updated/", params={"limit": 5, "x": None}
            )
        self.assertFalse(result.is_error, result.content[0].text)
        self.assertEqual(str(recorder.requests[0].url), "https://ti.f6.security/api/v2/ioc/common/updated?limit=5")

    def test_ti_request_refuses_internal_paths_without_a_request(self):
        recorder = Recorder(json_response(200, {}))
        with recorder.install(ti):
            result = ti.call_tool("ti_request", path="internal/x/1/y")
        self.assertTrue(result.is_error)
        self.assertIn("must start with", result.content[0].text)
        self.assertEqual(recorder.requests, [])

    def test_ti_request_refuses_percent_encoded_segments_without_a_request(self):
        recorder = Recorder(json_response(200, {}))
        with recorder.install(ti):
            result = ti.call_tool("ti_request", path="apt/threat/123/%61ction/x")
        self.assertTrue(result.is_error)
        self.assertIn("percent-encoding", result.content[0].text)
        self.assertEqual(recorder.requests, [])

    def test_ti_get_item_refuses_an_id_with_a_slash(self):
        recorder = Recorder(json_response(200, {}))
        with recorder.install(ti):
            result = ti.call_tool(
                "ti_get_item", collection="compromised/reaper", id="1/action/highlight"
            )
        self.assertTrue(result.is_error)
        self.assertIn("single plain path segment", result.content[0].text)
        self.assertEqual(recorder.requests, [])

    def test_ti_get_updates_sends_seq_update_as_an_integer(self):
        recorder = Recorder(json_response(200, {"items": [], "seqUpdate": 2}))
        with recorder.install(ti):
            result = ti.call_tool(
                "ti_get_updates", collection="osi/public_leak", seq_update=16394859.0, limit=5000
            )
        self.assertFalse(result.is_error, result.content[0].text)
        # 16394859.0 arrives as a whole number; 5000 is clamped to the collection's cap of 100.
        self.assertEqual(dict(recorder.requests[0].url.params), {"seqUpdate": "16394859", "limit": "100"})

    def test_extra_params_reach_the_query(self):
        recorder = Recorder(json_response(200, {"resultId": None, "count": 0, "items": []}))
        with recorder.install(ti):
            result = ti.call_tool(
                "ti_get_collection", collection="compromised/messenger",
                extra_params={"tags[filterSpam][]": True}, apply_hunting_rules=True,
            )
        self.assertFalse(result.is_error, result.content[0].text)
        params = recorder.requests[0].url.params
        self.assertEqual(params.get_list("tags[filterSpam][]"), ["1"])
        self.assertEqual(params["apply_hunting_rules"], "1")

    def test_error_text_is_bounded(self):
        recorder = Recorder(json_response(400, {"error": "x" * 5000}))
        with recorder.install(ti):
            result = ti.call_tool("ti_get_item", collection="ioc/common", id="1")
        self.assertTrue(result.is_error)
        self.assertLessEqual(len(result.content[0].text), settings.MAX_ERROR_TEXT_CHARS + len("Error: "))
        self.assertTrue(json.loads(json.dumps(result.content[0].text)))


class TestConnectionReuse(unittest.TestCase):
    def test_calls_share_one_http_client(self):
        with mock.patch.object(client.httpx, "AsyncClient", wraps=httpx.AsyncClient) as constructed:
            app = App(TI_MIN_FEED_INTERVAL="0")
            recorder = Recorder(json_response(200, {"items": []}))
            with recorder.install(app):
                for _ in range(3):
                    result = app.call_tool("ti_global_search", query="8.8.8.8")
                    self.assertFalse(result.is_error, result.content[0].text)
        self.assertEqual(constructed.call_count, 1)
        self.assertEqual(len(recorder.requests), 3)

    def test_the_server_closes_its_client_when_it_stops(self):
        async def scenario():
            mcp_server = server.build_server(settings.Settings.from_env({}))
            async with mcp_server.lifespan(mcp_server) as state:
                http = state.client._http
                self.assertFalse(http.is_closed)
            return http

        self.assertTrue(asyncio.run(scenario()).is_closed)


if __name__ == "__main__":
    unittest.main()
