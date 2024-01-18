# Copyright (c) 2014, Palo Alto Networks
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import random
import unittest

import panos
import xml.etree.ElementTree as ET


class TestPanOSVersion(unittest.TestCase):
    """
    [Test section: PanOSVersion]

    Verify that PanOSVersion comparisons operate correctly.

    """

    def setUp(self):
        self.c1 = panos.PanOSVersion("7.0.0-c1")
        self.c2 = panos.PanOSVersion("7.0.0-c2")
        self.b1 = panos.PanOSVersion("7.0.0-b1")
        self.b2 = panos.PanOSVersion("7.0.0-b2")
        self.m1 = panos.PanOSVersion("7.0.0")
        self.h1 = panos.PanOSVersion("7.0.0-h1")
        self.h2 = panos.PanOSVersion("7.0.0-h2")
        self.m2 = panos.PanOSVersion("7.0.1")
        self.h3 = panos.PanOSVersion("7.0.1-h1")

    def test_version_parsed(self):
        expected = [7, 0, 0, "-", "c", 1]

        ret_val = self.c1.version

        self.assertEqual(expected, ret_val)

    def test_str_returns_string_version(self):
        expected = "7.0.0-c1"

        ret_val = str(self.c1)

        self.assertEqual(expected, ret_val)

    def test_candidate_version_is_less_than_next_candidate_version(self):
        self.assertTrue(self.c1 < self.c2)

    def test_beta_version_is_less_than_next_beta_version(self):
        self.assertTrue(self.b1 < self.b2)

    def test_release_version_is_less_than_next_release_version(self):
        self.assertTrue(self.m1 < self.m2)

    def test_hotfix_version_is_less_than_next_hotfix_version_with_same_version_number(
        self,
    ):
        self.assertTrue(self.h1 < self.h2)

    def test_candidate_version_is_less_than_same_beta_version(self):
        self.assertTrue(self.c1 < self.b1)

    def test_candidate_version_is_less_than_same_release_version(self):
        self.assertTrue(self.c1 < self.m1)

    def test_candidate_version_is_less_than_same_hotfix_version(self):
        self.assertTrue(self.c1 < self.h1)

    def test_candidate_version_is_less_than_next_hotfix_version(self):
        self.assertTrue(self.c1 < self.h3)

    def test_beta_version_is_greater_than_same_candidate_version(self):
        self.assertTrue(self.b1 > self.c1)

    def test_beta_version_is_less_than_same_release_version(self):
        self.assertTrue(self.b1 < self.m1)

    def test_beta_version_is_less_than_same_hotfix_version(self):
        self.assertTrue(self.b1 < self.h1)

    def test_beta_version_is_less_than_next_hotfix_version(self):
        self.assertTrue(self.b1 < self.h3)

    def test_release_version_is_greater_than_same_candidate_version(self):
        self.assertTrue(self.m1 > self.c1)

    def test_release_version_is_greater_than_same_beta_version(self):
        self.assertTrue(self.m1 > self.b1)

    def test_release_version_is_less_than_same_hotfix_version(self):
        self.assertTrue(self.m1 < self.h1)

    def test_release_version_is_less_than_next_hotfix_version(self):
        self.assertTrue(self.m1 < self.h3)

    def test_hotfix_version_is_greater_than_same_candidate_version(self):
        self.assertTrue(self.h1 > self.c1)

    def test_hotfix_version_is_greater_than_same_beta_version(self):
        self.assertTrue(self.h1 > self.b1)

    def test_hotfix_version_is_greater_than_same_release_version(self):
        self.assertTrue(self.h1 > self.m1)

    def test_hotfix_version_is_less_than_next_release_version(self):
        self.assertTrue(self.h1 < self.m2)

    def test_hotfix_version_is_less_than_next_hotfix_version(self):
        self.assertTrue(self.h1 < self.h3)

    def test_release_version_is_greater_than_previous_candidate_version(self):
        self.assertTrue(self.m2 > self.c1)

    def test_release_version_is_greater_than_previous_beta_version(self):
        self.assertTrue(self.m2 > self.b1)

    def test_release_version_is_greater_than_previous_hotfix_version(self):
        self.assertTrue(self.m2 > self.h1)

    def test_release_version_is_less_than_hotfix_version(self):
        self.assertTrue(self.m2 < self.h3)

    def test_hotfix_version_is_greater_than_previous_candidate_version(self):
        self.assertTrue(self.h3 > self.c1)

    def test_hotfix_version_is_greater_than_previous_beta_version(self):
        self.assertTrue(self.h3 > self.b1)

    def test_hotfix_version_is_greater_than_previous_release_version(self):
        self.assertTrue(self.h3 > self.m1)

    def test_hotfix_version_is_greater_than_previous_hotfix_version(self):
        self.assertTrue(self.h3 > self.h1)

    def test_hotfix_version_is_greater_than_previous_same_release_version(self):
        self.assertTrue(self.h3 > self.m2)


class TestStringToXml(unittest.TestCase):
    def _str(self, elm):
        return ET.tostring(elm, encoding="utf-8")

    def quotes(self):
        for x in ('"', '"', "|", "`", '"""', "'''"):
            yield x

    def test_single_word(self):
        root = ET.Element("hello")

        self.assertEqual(panos.string_to_xml("hello"), self._str(root))

    def test_two_words(self):
        root = ET.Element("hello")
        ET.SubElement(root, "world")

        self.assertEqual(panos.string_to_xml("hello world"), self._str(root))

    def test_three_words(self):
        root = ET.Element("foo")
        e = ET.SubElement(root, "bar")
        ET.SubElement(e, "baz")

        self.assertEqual(panos.string_to_xml("foo bar baz"), self._str(root))

    def test_base_is_single_key_value(self):
        root = ET.Element("hello")
        root.text = "world"

        for x in self.quotes():
            self.assertEqual(
                panos.string_to_xml("hello {0}world{0}".format(x), x),
                self._str(root),
            )

    def test_base_root_with_one_key_value(self):
        root = ET.Element("foo")
        e = ET.SubElement(root, "bar")
        e.text = "baz"

        for x in self.quotes():
            self.assertEqual(
                panos.string_to_xml("foo bar {0}baz{0}".format(x), x),
                self._str(root),
            )

    def test_base_root_with_two_key_values(self):
        root = ET.Element("one")
        ET.SubElement(root, "first").text = "a"
        ET.SubElement(root, "second").text = "b"

        for x in self.quotes():
            self.assertEqual(
                panos.string_to_xml("one first {0}a{0} second {0}b{0}".format(x), x),
                self._str(root),
            )

    def test_removed_graft_point_with_one_key_value(self):
        root = ET.Element("foo")
        e = ET.SubElement(root, "bar")
        ET.SubElement(e, "palo").text = "alto"

        for x in self.quotes():
            self.assertEqual(
                panos.string_to_xml("foo bar palo {0}alto{0}".format(x), x),
                self._str(root),
            )

    def test_removed_graft_point_with_two_key_values(self):
        root = ET.Element("foo")
        e = ET.SubElement(root, "bar")
        ET.SubElement(e, "palo").text = "alto"
        ET.SubElement(e, "panos").text = "python"

        for x in self.quotes():
            self.assertEqual(
                panos.string_to_xml(
                    "foo bar palo {0}alto{0} panos {0}python{0}".format(x), x
                ),
                self._str(root),
            )

    def test_multiple_words_can_be_quoted(self):
        root = ET.Element("this")
        root.text = "is a test"

        for x in self.quotes():
            self.assertEqual(
                panos.string_to_xml("this {0}is a test{0}".format(x), x),
                self._str(root),
            )

    def test_multi_level_key_values(self):
        root = ET.Element("first")
        ET.SubElement(root, "key1").text = "value1"
        e = ET.SubElement(root, "second")
        ET.SubElement(e, "key2").text = "value2"

        for x in self.quotes():
            self.assertEqual(
                panos.string_to_xml(
                    "first key1 {0}value1{0} second key2 {0}value2{0}".format(x), x
                ),
                self._str(root),
            )

    def test_leading_quote_causes_valueerror(self):
        for x in self.quotes():
            with self.assertRaises(ValueError):
                panos.string_to_xml("{0}fails".format(x), x)

    def test_dangling_quote_on_first_param_raises_error(self):
        for x in self.quotes():
            with self.assertRaises(ValueError):
                panos.string_to_xml("fails{0}".format(x), x)

    def test_no_ending_quote_causes_value_error(self):
        for x in self.quotes():
            with self.assertRaises(ValueError):
                panos.string_to_xml("this also {0}fails".format(x), x)


class SomeClass(object):
    def __init__(self, uid):
        self.uid = uid


class TestChunkInstancesForDeleteSimilar(unittest.TestCase):
    def get_list(self, length=10, count=1):
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        return [
            SomeClass("".join(random.choice(chars) for x in range(length)))
            for y in range(count)
        ]

    def test_one_chunk_basic(self):
        items = self.get_list(count=5)
        chunks = panos.chunk_instances_for_delete_similar(items)

        self.assertEqual(1, len(chunks))
        self.assertEqual(items, chunks[0])
        self.assertEqual(len(items), sum(len(x) for x in chunks))

    def test_one_chunk_for_greater_than_25k_name(self):
        items = self.get_list(length=26000)
        chunks = panos.chunk_instances_for_delete_similar(items)

        self.assertEqual(1, len(chunks))
        self.assertEqual(items, chunks[0])
        self.assertEqual(len(items), sum(len(x) for x in chunks))

    def test_one_chunk_for_25k_exactly(self):
        items = self.get_list(count=5, length=4988)
        chunks = panos.chunk_instances_for_delete_similar(items)

        self.assertEqual(1, len(chunks))
        self.assertEqual(items, chunks[0])
        self.assertEqual(len(items), sum(len(x) for x in chunks))

    def test_two_chunks_high_count(self):
        items = self.get_list(length=30, count=900)
        chunks = panos.chunk_instances_for_delete_similar(items)

        self.assertEqual(2, len(chunks))
        self.assertEqual(len(items), sum(len(x) for x in chunks))

    def test_two_chunks_long_names(self):
        items = self.get_list(length=300, count=100)
        chunks = panos.chunk_instances_for_delete_similar(items)

        self.assertEqual(2, len(chunks))
        self.assertEqual(len(items), sum(len(x) for x in chunks))


if __name__ == "__main__":
    unittest.main()
