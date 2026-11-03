# Copyright 2026 Future Joint-Stock Company
# SPDX-License-Identifier: Apache-2.0

"""The resultId cache and the scroll flow of ti_get_collection.

The backend opens a new scroll for one user and collection once per 60 s and
forgets a resultId 150 s after its last use; the tool has to stay inside both.
"""

import asyncio
import json
import unittest

from support import App, Recorder, json_response
from ti_mcp.client import FeedThrottle
from ti_mcp.params import ResultIdCache

ti = App(TI_MIN_FEED_INTERVAL="0", TI_RETRIES="0")


def page(result_id, *items, count=None):
    return json_response(200, {"resultId": result_id, "count": count or len(items), "items": list(items)})


class TestResultIdCache(unittest.TestCase):
    def test_key_ignores_paging_and_absent_parameters(self):
        key = ResultIdCache.key
        base = key("ioc/common", {"q": "x", "limit": 100, "offset": 0, "resultId": "r", "df": None})
        self.assertEqual(base, key("ioc/common", {"q": "x", "limit": 5, "offset": 200, "resultId": "s"}))
        self.assertNotEqual(base, key("ioc/common", {"q": "y"}))
        self.assertNotEqual(base, key("malware/cnc", {"q": "x"}))

    def test_entries_expire_after_the_ttl(self):
        async def scenario():
            cache = ResultIdCache(ttl=100)
            cache.put("k", "r1")
            self.assertEqual(cache.get("k"), "r1")
            # Age the entry past the TTL instead of waiting for it.
            result_id, last_used = cache._entries["k"]
            cache._entries["k"] = (result_id, last_used - 101)
            self.assertIsNone(cache.get("k"))
            self.assertNotIn("k", cache._entries)

        asyncio.run(scenario())

    def test_drop_is_idempotent(self):
        async def scenario():
            cache = ResultIdCache(ttl=100)
            cache.drop("missing")
            cache.put("k", "r1")
            cache.drop("k")
            self.assertIsNone(cache.get("k"))

        asyncio.run(scenario())


class TestScrollFlow(unittest.TestCase):
    """ti_get_collection with scroll=true: the resultId flow."""

    def setUp(self):
        ti.state.result_ids._entries.clear()

    def read(self, recorder, **arguments):
        with recorder.install(ti):
            result = ti.call_tool("ti_get_collection", collection="malware/cnc", scroll=True, **arguments)
        self.assertFalse(result.is_error, result.content[0].text)
        text = result.content[0].text
        notes = [line for line in text.splitlines() if line.startswith("Note: ")]
        body = json.loads(text.split("\n\n", 1)[1] if notes else text)
        return notes, body

    def test_second_call_continues_the_remembered_scroll(self):
        recorder = Recorder(page("r1", {"id": 1}), page("r2", {"id": 2}))
        notes, body = self.read(recorder, query="x")
        self.assertEqual((notes, body["items"]), ([], [{"id": 1}]))
        notes, body = self.read(recorder, query="x")
        self.assertEqual(body["items"], [{"id": 2}])
        self.assertIn("Continued the scroll already open", notes[0])
        self.assertEqual([r.url.params.get("resultId") for r in recorder.requests], [None, "r1"])

    def test_a_different_filter_opens_its_own_scroll(self):
        recorder = Recorder(page("r1", {"id": 1}), page("s1", {"id": 2}))
        self.read(recorder, query="x")
        notes, _ = self.read(recorder, query="y")
        self.assertEqual(notes, [])
        self.assertEqual([r.url.params.get("resultId") for r in recorder.requests], [None, None])

    def test_restart_drops_the_remembered_scroll(self):
        recorder = Recorder(page("r1", {"id": 1}), page("r9", {"id": 1}))
        self.read(recorder, query="x")
        notes, _ = self.read(recorder, query="x", restart=True)
        self.assertEqual(notes, [])
        self.assertIsNone(recorder.requests[1].url.params.get("resultId"))

    def test_an_explicit_result_id_wins_over_the_cache(self):
        recorder = Recorder(page("r1", {"id": 1}), page("r2", {"id": 2}))
        self.read(recorder, query="x")
        notes, _ = self.read(recorder, query="x", result_id="mine")
        self.assertEqual(notes, [])
        self.assertEqual(recorder.requests[1].url.params["resultId"], "mine")

    def test_expired_cached_id_is_retried_once_without_it(self):
        recorder = Recorder(page("r1", {"id": 1}), json_response(400, ""), page("r5", {"id": 1}))
        self.read(recorder, query="x")
        notes, body = self.read(recorder, query="x")
        self.assertEqual(body["resultId"], "r5")
        self.assertTrue(any("had expired on the server" in note for note in notes), notes)
        self.assertEqual([r.url.params.get("resultId") for r in recorder.requests], [None, "r1", None])

    def test_expired_cached_id_reported_as_404_is_retried_too(self):
        # Some collections answer an expired scroll id with 404, not 400.
        gone = json_response(404, {"code": 404, "message": "unmask scroll id: masked scroll id not found"})
        recorder = Recorder(page("r1", {"id": 1}), gone, page("r5", {"id": 1}))
        self.read(recorder, query="x")
        notes, body = self.read(recorder, query="x")
        self.assertEqual(body["resultId"], "r5")
        self.assertTrue(any("had expired on the server" in note for note in notes), notes)
        self.assertEqual([r.url.params.get("resultId") for r in recorder.requests], [None, "r1", None])

    def test_a_400_on_an_explicit_id_is_not_retried(self):
        recorder = Recorder(json_response(400, {"message": "bad id"}))
        with recorder.install(ti):
            result = ti.call_tool(
                "ti_get_collection", collection="malware/cnc", scroll=True, result_id="stale"
            )
        self.assertTrue(result.is_error)
        self.assertIn("API error 400", result.content[0].text)
        self.assertEqual(len(recorder.requests), 1)

    def test_empty_page_closes_the_scroll(self):
        recorder = Recorder(page("r1", {"id": 1}), page("r1"), page("n1", {"id": 1}))
        self.read(recorder, query="x")
        self.read(recorder, query="x")
        notes, _ = self.read(recorder, query="x")
        self.assertEqual(notes, [])
        self.assertEqual([r.url.params.get("resultId") for r in recorder.requests], [None, "r1", None])

    def test_null_result_id_means_offset_paging(self):
        recorder = Recorder(page(None, {"id": 1}, count=250))
        notes, body = self.read(recorder, query="ip:1.2.3.4")
        self.assertIsNone(body["resultId"])
        self.assertTrue(any("without scroll=true" in note for note in notes), notes)
        # The recommended follow-up: the default mode, paging by offset.
        with recorder.install(ti):
            result = ti.call_tool(
                "ti_get_collection", collection="malware/cnc", query="ip:1.2.3.4", offset=100
            )
        self.assertFalse(result.is_error, result.content[0].text)
        params = recorder.requests[1].url.params
        self.assertEqual((params["offset"], params["use_scroll"], params.get("resultId")), ("100", "0", None))


class TestOffsetFlow(unittest.TestCase):
    """The default mode: offset paging, no scroll opened, cache untouched."""

    def setUp(self):
        ti.state.result_ids._entries.clear()

    def test_default_read_sends_use_scroll_0_and_leaves_the_cache_alone(self):
        recorder = Recorder(page(None, {"id": 1}, count=42))
        with recorder.install(ti):
            result = ti.call_tool("ti_get_collection", collection="malware/cnc", limit=1)
        self.assertFalse(result.is_error, result.content[0].text)
        params = dict(recorder.requests[0].url.params)
        self.assertEqual(params, {"limit": "1", "use_scroll": "0"})
        body = json.loads(result.content[0].text)
        self.assertEqual((body["count"], body["items"]), (42, [{"id": 1}]))
        self.assertNotIn("resultId", body)
        self.assertNotIn("Note:", result.content[0].text)
        self.assertEqual(ti.state.result_ids._entries, {})

    def test_a_backend_that_ignores_use_scroll_is_called_out(self):
        recorder = Recorder(page("r1", {"id": 1}))
        with recorder.install(ti):
            result = ti.call_tool("ti_get_collection", collection="malware/cnc", limit=1)
        self.assertFalse(result.is_error, result.content[0].text)
        text = result.content[0].text
        self.assertIn("ignored use_scroll=0", text)
        self.assertEqual(json.loads(text.split("\n\n", 1)[1])["resultId"], "r1")
        self.assertEqual(ti.state.result_ids._entries, {})

    def test_offset_is_passed_through(self):
        recorder = Recorder(page(None, {"id": 3}, count=42))
        with recorder.install(ti):
            result = ti.call_tool("ti_get_collection", collection="malware/cnc", limit=2, offset=2)
        self.assertFalse(result.is_error, result.content[0].text)
        self.assertEqual(recorder.requests[0].url.params["offset"], "2")

    def test_a_remembered_scroll_does_not_leak_into_offset_mode(self):
        async def remember():
            ti.state.result_ids.put(ResultIdCache.key("malware/cnc", {"limit": 1}), "r1")

        asyncio.run(remember())
        recorder = Recorder(page(None, {"id": 1}))
        with recorder.install(ti):
            ti.call_tool("ti_get_collection", collection="malware/cnc", limit=1)
        self.assertIsNone(recorder.requests[0].url.params.get("resultId"))

    def test_result_id_and_restart_need_scroll(self):
        recorder = Recorder(page(None))
        for arguments in ({"result_id": "r1"}, {"restart": True}):
            with self.subTest(arguments=arguments), recorder.install(ti):
                result = ti.call_tool("ti_get_collection", collection="malware/cnc", **arguments)
            self.assertTrue(result.is_error)
            self.assertIn("scroll=true only", result.content[0].text)
        self.assertEqual(recorder.requests, [])

    def test_flags_are_not_strings(self):
        recorder = Recorder(page(None))
        for arguments in ({"scroll": "false"}, {"restart": "no"}):
            with self.subTest(arguments=arguments), recorder.install(ti):
                result = ti.call_tool("ti_get_collection", collection="malware/cnc", **arguments)
            self.assertTrue(result.is_error)
            self.assertIn("must be an integer", result.content[0].text)
        self.assertEqual(recorder.requests, [])

    def test_use_scroll_cannot_be_set_through_extra_params(self):
        recorder = Recorder(page(None))
        with recorder.install(ti):
            result = ti.call_tool(
                "ti_get_collection", collection="malware/cnc", extra_params={"use_scroll": 1}
            )
        self.assertTrue(result.is_error)
        self.assertIn("must not set use_scroll", result.content[0].text)

    def test_window_overflow_hint(self):
        recorder = Recorder(
            json_response(400, {"code": 400, "message": "sum of offset and limit exceeds the limit (10000)"})
        )
        with recorder.install(ti):
            result = ti.call_tool("ti_get_collection", collection="malware/cnc", limit=100, offset=9950)
        self.assertTrue(result.is_error)
        self.assertIn("scroll=true for deeper reads", result.content[0].text)
        self.assertIn("exceeds the limit (10000)", result.content[0].text)


class TestFeedThrottle(unittest.TestCase):
    def test_same_feed_is_spaced_and_different_feeds_are_not(self):
        async def scenario():
            throttle = FeedThrottle(0.1)
            loop = asyncio.get_running_loop()
            started = loop.time()
            await throttle.acquire("a")
            await throttle.acquire("b")
            self.assertLess(loop.time() - started, 0.1)
            await throttle.acquire("a")
            self.assertGreaterEqual(loop.time() - started, 0.1)

        asyncio.run(scenario())

    def test_zero_interval_never_waits(self):
        async def scenario():
            throttle = FeedThrottle(0)
            loop = asyncio.get_running_loop()
            started = loop.time()
            for _ in range(5):
                await throttle.acquire("a")
            self.assertLess(loop.time() - started, 0.05)

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
