# Copyright 2026 Future Joint-Stock Company
# SPDX-License-Identifier: Apache-2.0

"""The collection catalogue is data typed out by hand from the guides; these
checks catch a slip in it before the model sees it."""

import dataclasses
import typing
import unittest

import support  # noqa: F401 - puts src/ on the path
from ti_mcp import catalog


class TestCatalogue(unittest.TestCase):
    def test_every_entry_is_well_formed(self):
        availability = typing.get_args(catalog.Availability)
        for name, meta in catalog.COLLECTIONS.items():
            with self.subTest(collection=name):
                self.assertTrue(catalog.COLLECTION_NAME.fullmatch(name))
                self.assertIn(meta.category, catalog.CATEGORIES)
                self.assertIn(meta.availability, (*availability, None))
                # type(), not isinstance: True is an int too.
                self.assertIs(type(meta.limit), int)
                self.assertGreaterEqual(meta.limit, 1)
                self.assertTrue(meta.label)
                # The guides leave the fields of a couple of collections out;
                # an entry without them must say why.
                if not meta.fields:
                    self.assertTrue(meta.note, "no fields and no note saying why")
                self.assertIsInstance(meta.fields, tuple)
                self.assertEqual(len(set(meta.fields)), len(meta.fields), "duplicate field")

    def test_categories_match_their_literal(self):
        self.assertEqual(catalog.CATEGORIES, typing.get_args(catalog.Category))

    def test_entries_are_immutable(self):
        meta = catalog.COLLECTIONS["ioc/common"]
        with self.assertRaises(dataclasses.FrozenInstanceError):
            meta.limit = 1

    def test_deprecated_and_aliased_names_are_not_collections(self):
        for name in (*catalog.DEPRECATED, *catalog.ALIASES):
            with self.subTest(name=name):
                self.assertNotIn(name, catalog.COLLECTIONS)
        for target in catalog.ALIASES.values():
            self.assertIn(target, catalog.COLLECTIONS)


if __name__ == "__main__":
    unittest.main()
