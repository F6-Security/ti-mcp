# Copyright 2026 Future Joint-Stock Company
# SPDX-License-Identifier: Apache-2.0

"""Tool arguments are checked before they shape a URL or a query string."""

import json
import unittest

from support import App
from ti_mcp import arguments, catalog, params


class TestAsInt(unittest.TestCase):
    def test_whole_numbers_pass(self):
        self.assertEqual(params.as_int("n", 10, minimum=1), 10)
        self.assertEqual(params.as_int("n", 10.0, minimum=1), 10)
        self.assertIsNone(params.as_int("n", None, minimum=1))

    def test_fractions_strings_and_booleans_are_refused(self):
        for value in (10.5, "10", True, [10]):
            with self.subTest(value=value), self.assertRaises(ValueError):
                params.as_int("n", value, minimum=1)

    def test_bounds(self):
        with self.assertRaisesRegex(ValueError, ">= 1"):
            params.as_int("n", 0, minimum=1)
        with self.assertRaisesRegex(ValueError, "<= 1"):
            params.as_int("n", 2, minimum=0, maximum=1)

    def test_limit_is_clamped_to_the_collection_cap(self):
        self.assertEqual(params.clamp_limit("osi/public_leak", 5000), 100)
        self.assertEqual(params.clamp_limit("osi/public_leak", 7), 7)
        self.assertIsNone(params.clamp_limit("osi/public_leak", None))

    def test_flags_accept_booleans(self):
        self.assertEqual(params.check_flag(True, "f"), 1)
        self.assertEqual(params.check_flag(0, "f"), 0)
        with self.assertRaises(ValueError):
            params.check_flag(2, "f")


class TestCollectionName(unittest.TestCase):
    def test_aliases_and_suffixes(self):
        self.assertEqual(catalog.resolve_collection("ioc/common/updated"), "ioc/common")
        self.assertEqual(catalog.resolve_collection("/hi/open_threat"), "hi/open_threats")

    def test_unknown_but_well_formed_names_pass(self):
        self.assertEqual(catalog.resolve_collection("bp/phishing"), "bp/phishing")

    def test_names_that_are_not_two_segments_are_refused(self):
        for name in ("ioc", "ioc/common/123", "../user", "ioc/common?x=1", "ioc/Common", "a b/c"):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "section/name"):
                catalog.resolve_collection(name)


class TestRecordId(unittest.TestCase):
    def test_plain_ids_pass(self):
        for value in ("123", "0a1b2c", "f6b2c6d2-1c0e-4b7e-9f5e-2f3a1b4c5d6e", " abc "):
            with self.subTest(value=value):
                self.assertEqual(params.check_id(value), value.strip())

    def test_ids_that_would_change_the_path_are_refused(self):
        for value in (
            "1/action/highlight", "..", "a?b", "a#b", "a b", "", None, 5,
            "..%2F..%2Finternal", "%2e%2e", "1%2Faction",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                params.check_id(value)


class TestExtraParams(unittest.TestCase):
    def test_scalars_lists_and_booleans(self):
        extra = params.extra_params(
            {"tags[filterSpam][]": 1, "has_exploit": True, "ids[]": ["a", "b"], "skip": None}
        )
        self.assertEqual(extra, {"tags[filterSpam][]": 1, "has_exploit": 1, "ids[]": ["a", "b"]})

    def test_tool_parameters_cannot_be_overridden(self):
        for key in ("q", "limit", "resultId", "seqUpdate", "use_scroll"):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "must not set"):
                params.extra_params({key: 1})

    def test_nested_values_and_bad_keys_are_refused(self):
        with self.assertRaises(ValueError):
            params.extra_params({"filter": {"a": 1}})
        with self.assertRaises(ValueError):
            params.extra_params({"": 1})
        with self.assertRaises(ValueError):
            params.extra_params([1, 2])

    def test_request_params_may_set_what_the_tools_reserve(self):
        self.assertEqual(params.query_params({"limit": 5}, name="params"), {"limit": 5})


class TestRequestPath(unittest.TestCase):
    def test_documented_paths_pass(self):
        for path in ("ioc/common/updated", "/search", "user/granted_collections", "utils/graph/ip"):
            with self.subTest(path=path):
                self.assertEqual(params.check_path(path), path.strip("/").split("/"))

    def test_sections_outside_the_client_api_are_refused(self):
        for path in ("internal/x/1/y", "web/x", "srv/x", "../etc"):
            with (
                self.subTest(path=path),
                self.assertRaisesRegex(ValueError, "must start with|plain segments"),
            ):
                params.check_path(path)

    def test_actions_and_files_are_refused(self):
        with self.assertRaisesRegex(ValueError, "read-only"):
            params.check_path("compromised/reaper/1/action/highlight")
        with self.assertRaisesRegex(ValueError, "JSON only"):
            params.check_path("apt/threat/1/file/abc")

    def test_query_strings_and_odd_segments_are_refused(self):
        for path in (
            "search?q=1", "ioc//common", "ioc/./common", "ioc/co mmon", "", None,
            "apt/threat/1/%61ction/x", "ioc/%2e%2e/internal/x", "ioc/common\\..\\internal",
        ):
            with self.subTest(path=path), self.assertRaises(ValueError):
                params.check_path(path)


class TestArgumentModels(unittest.TestCase):
    """The models behind every tool: what the client is shown and what a bad call is told."""

    app = App()

    def call_error(self, name, **arguments):
        result = self.app.call_tool(name, **arguments)
        self.assertTrue(result.is_error, result.content[0].text)
        return result.content[0].text

    def test_schemas_stay_plain(self):
        # An optional argument is its type, not anyOf with null; no titles or defaults.
        for tool in self.app.state.tools:
            schema = json.dumps(tool.model_dump(by_alias=True)["inputSchema"])
            for word in ('"anyOf"', '"null"', '"title"', '"default"', '"$defs"'):
                with self.subTest(tool=tool.name, word=word):
                    self.assertNotIn(word, schema)

    def test_checked_arguments_keep_their_json_type(self):
        properties = arguments.input_schema(arguments.GetCollectionArguments)["properties"]
        types = {name: properties[name]["type"] for name in ("collection", "limit", "scroll", "extra_params")}
        self.assertEqual(types, {"collection": "string", "limit": "number", "scroll": "boolean",
                                 "extra_params": "object"})

    def test_every_bad_argument_is_reported_at_once(self):
        text = self.call_error("ti_get_collection", collection="ioc/common", limit=10.5, date_from="soon")
        self.assertIn("limit must be a whole number, got 10.5", text)
        self.assertIn("; date_from must be YYYY-MM-DD", text)

    def test_missing_argument_is_named(self):
        self.assertEqual(self.call_error("ti_get_item", collection="ioc/common"), "Error: id is required")

    def test_types_the_schema_states_are_enforced(self):
        self.assertIn("query: Input should be a valid string",
                      self.call_error("ti_get_collection", collection="ioc/common", query=5))
        self.assertIn("category: Input should be",
                      self.call_error("ti_describe_collections", category="nope"))

    def test_unknown_arguments_are_ignored(self):
        result = self.app.call_tool("ti_describe_collections", collection="ioc/common", verbose=True)
        self.assertFalse(result.is_error, result.content[0].text)


if __name__ == "__main__":
    unittest.main()
