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

import unittest

import pandevice


class TestPanOSVersion(unittest.TestCase):
    """
    [Test section: PanOSVersion]

    Verify that PanOSVersion comparisons operate correctly.

    """
    def setUp(self):

        self.c1 = pandevice.PanOSVersion('7.0.0-c1')
        self.c2 = pandevice.PanOSVersion('7.0.0-c2')
        self.b1 = pandevice.PanOSVersion('7.0.0-b1')
        self.b2 = pandevice.PanOSVersion('7.0.0-b2')
        self.m1 = pandevice.PanOSVersion('7.0.0')
        self.h1 = pandevice.PanOSVersion('7.0.0-h1')
        self.h2 = pandevice.PanOSVersion('7.0.0-h2')
        self.m2 = pandevice.PanOSVersion('7.0.1')
        self.h3 = pandevice.PanOSVersion('7.0.1-h1')

    def test_version_parsed(self):
        expected = [7, 0, 0, '-', 'c', 1]

        ret_val = self.c1.version

        self.assertEqual(expected, ret_val)

    def test_str_returns_string_version(self):
        expected = '7.0.0-c1'

        ret_val = str(self.c1)

        self.assertEqual(expected, ret_val)

    def test_candidate_version_is_less_than_next_candidate_version(self):
        self.assertTrue(self.c1 < self.c2)

    def test_beta_version_is_less_than_next_beta_version(self):
        self.assertTrue(self.b1 < self.b2)

    def test_release_version_is_less_than_next_release_version(self):
        self.assertTrue(self.m1 < self.m2)

    def test_hotfix_version_is_less_than_next_hotfix_version_with_same_version_number(self):
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

if __name__=='__main__':
    unittest.main()
