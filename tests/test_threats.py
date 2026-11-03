# Copyright 2026 Future Joint-Stock Company
# SPDX-License-Identifier: Apache-2.0

"""Searching the threat collections: the notes with their search rules, history
left out of list pages, and hints that tell a failed search from an empty one."""

import json
import unittest

from support import App, Recorder, json_response
from ti_mcp import catalog, client, server

ti = App(TI_MIN_FEED_INTERVAL="0", TI_RETRIES="0")

ACTORS = ("apt/threat_actor", "hi/threat_actor")
REPORTS = ("apt/threat", "hi/threat")
HISTORY = [{"field": "description", "old": "x" * 3000, "new": "y"}]


def card(record_id, **fields):
    return {"id": record_id, "name": f"Group {record_id}", "aliases": ["G"], **fields}


def page(*items, **extra):
    return json_response(200, {"count": len(items), "items": list(items), **extra})


def split(result):
    """The Note: lines and the JSON body of a tool answer."""
    text = result.content[0].text
    notes = [line.removeprefix("Note: ") for line in text.splitlines() if line.startswith("Note: ")]
    return notes, json.loads(text.split("\n\n", 1)[1] if notes else text)


def call(recorder, tool, **arguments):
    with recorder.install(ti):
        result = ti.call_tool(tool, **arguments)
    assert not result.is_error, result.content[0].text
    return split(result)


class TestSearchRules(unittest.TestCase):
    def test_each_threat_collection_says_how_to_search_it(self):
        for name in ACTORS:
            with self.subTest(collection=name):
                note = catalog.COLLECTIONS[name].note
                self.assertIn("one record per group", note)
                self.assertIn("aliases:<exact alias>", note)
                self.assertIn("stat.*:value is rejected", note)
        for name in REPORTS:
            with self.subTest(collection=name):
                note = catalog.COLLECTIONS[name].note
                self.assertIn("threatActor names the group", note)
                self.assertIn("400 invalid search field", note)
                self.assertIn("id:<id> and domain:<domain>", note)

    def test_each_one_points_to_its_counterparts(self):
        self.assertIn("apt/threat.", catalog.COLLECTIONS["apt/threat_actor"].note)
        self.assertIn("hi/threat_actor", catalog.COLLECTIONS["apt/threat_actor"].note)
        self.assertIn("hi/threat.", catalog.COLLECTIONS["hi/threat_actor"].note)
        self.assertIn("apt/threat_actor", catalog.COLLECTIONS["hi/threat_actor"].note)
        self.assertIn("hi/threat.", catalog.COLLECTIONS["apt/threat"].note)
        self.assertIn("apt/threat.", catalog.COLLECTIONS["hi/threat"].note)

    def test_the_answer_starts_with_the_rules(self):
        for name in (*ACTORS, *REPORTS):
            with self.subTest(collection=name):
                with Recorder(page()).install(ti):
                    text = ti.call_tool("ti_get_collection", collection=name).content[0].text
                self.assertTrue(text.startswith("Note: " + catalog.COLLECTIONS[name].note), text[:200])

    def test_describe_carries_the_rules_and_the_omitted_fields(self):
        for name in (*ACTORS, *REPORTS):
            with self.subTest(collection=name):
                described = catalog.describe(name, include_fields=False)
                self.assertEqual(described["note"], catalog.COLLECTIONS[name].note)
                expected = ["history"] if name in ACTORS else None
                self.assertEqual(described.get("omitted_in_lists"), expected)

    def test_only_the_actor_cards_lose_fields_in_lists(self):
        heavy = {name for name, meta in catalog.COLLECTIONS.items() if meta.omit_in_lists}
        self.assertEqual(heavy, set(ACTORS))

    def test_query_and_global_search_say_where_field_value_fails(self):
        tools = {t.name: t.model_dump(by_alias=True) for t in ti.state.tools}
        query = tools["ti_get_collection"]["inputSchema"]["properties"]["query"]["description"]
        self.assertIn("apt/threat and hi/threat accept nothing but id: and domain:", query)
        self.assertIn("repeat the value as free text", query)
        self.assertIn("An entry with error was NOT searched", tools["ti_global_search"]["description"])

    def test_the_server_gives_instructions(self):
        built = server.build_server(ti.settings)
        self.assertEqual(built.instructions, server.INSTRUCTIONS)
        self.assertIn("look in both before saying a group is unknown", server.INSTRUCTIONS)
        self.assertIn("A tool error is not an empty result", server.INSTRUCTIONS)


class TestHistoryOutOfLists(unittest.TestCase):
    def setUp(self):
        ti.state.result_ids._entries.clear()

    def test_offset_pages_leave_history_out_and_say_so(self):
        recorder = Recorder(page(card("a1", history=HISTORY), card("a2", history=HISTORY)))
        notes, body = call(recorder, "ti_get_collection", collection="hi/threat_actor", query="aliases:G")
        self.assertEqual(body["items"], [card("a1"), card("a2")])
        left_out = [note for note in notes if note.startswith("Left out history")]
        self.assertEqual(len(left_out), 1, notes)
        self.assertIn("(6 KB on this page)", left_out[0])
        self.assertIn("ti_get_item with collection hi/threat_actor", left_out[0])
        # The search rules come first, the note about the page after them.
        self.assertTrue(notes[0].startswith("Group cards of cybercriminals"))

    def test_scroll_pages_leave_history_out_and_keep_the_scroll(self):
        recorder = Recorder(
            page(card("a1", history=HISTORY), resultId="r1"), page(card("a2", history=HISTORY), resultId="r2")
        )
        notes, body = call(recorder, "ti_get_collection", collection="apt/threat_actor", scroll=True)
        self.assertEqual(body["items"], [card("a1")])
        self.assertEqual(body["resultId"], "r1")
        self.assertTrue(any(note.startswith("Left out history") for note in notes), notes)
        notes, body = call(recorder, "ti_get_collection", collection="apt/threat_actor", scroll=True)
        self.assertEqual(body["items"], [card("a2")])
        self.assertEqual([r.url.params.get("resultId") for r in recorder.requests], [None, "r1"])

    def test_cards_without_history_come_back_as_they_are_without_a_note(self):
        notes, body = call(Recorder(page(card("a1"))), "ti_get_collection", collection="hi/threat_actor")
        self.assertEqual(body["items"], [card("a1")])
        self.assertFalse(any(note.startswith("Left out") for note in notes), notes)

    def test_other_collections_keep_history(self):
        report = {"id": "r1", "threatActor": {"name": "Group"}, "history": HISTORY}
        for name, record in (("hi/threat", report), ("ioc/common", {"id": "i1", "history": HISTORY})):
            with self.subTest(collection=name):
                notes, body = call(Recorder(page(record)), "ti_get_collection", collection=name)
                self.assertEqual(body["items"], [record])
                self.assertFalse(any(note.startswith("Left out") for note in notes), notes)

    def test_get_item_and_updates_return_the_card_whole(self):
        whole = card("a1", history=HISTORY)
        item = Recorder(json_response(200, whole))
        _, body = call(item, "ti_get_item", collection="hi/threat_actor", id="a1")
        self.assertEqual(body, whole)
        _, body = call(Recorder(page(whole, seqUpdate=5)), "ti_get_updates", collection="hi/threat_actor")
        self.assertEqual(body["items"], [whole])


class TestFailedIsNotEmpty(unittest.TestCase):
    def test_400_says_to_repeat_the_value_as_free_text(self):
        self.assertIn("repeat the value as free text", client.STATUS_HINTS[400])

    def test_5xx_says_the_collection_is_unchecked(self):
        for status in (500, 502, 503, 504):
            with self.subTest(status=status):
                hint = client.STATUS_HINTS[status]
                self.assertIn("report this collection as unchecked, not as empty", hint)

    def test_a_502_reaches_the_model_as_unchecked(self):
        with Recorder(json_response(502, {"message": "Bad Gateway"})).install(ti):
            result = ti.call_tool("ti_get_collection", collection="hi/threat", query="GOFFEE")
        self.assertTrue(result.is_error)
        self.assertIn("API error 502", result.content[0].text)
        self.assertIn("unchecked, not as empty", result.content[0].text)

    def test_field_value_in_reports_reaches_the_model_with_the_free_text_hint(self):
        body = {"message": "parameter 'q': invalid search field"}
        with Recorder(json_response(400, body)).install(ti):
            result = ti.call_tool("ti_get_collection", collection="apt/threat", query="name:GOFFEE")
        self.assertTrue(result.is_error)
        self.assertIn("repeat the value as free text", result.content[0].text)
        self.assertIn("invalid search field", result.content[0].text)


if __name__ == "__main__":
    unittest.main()
