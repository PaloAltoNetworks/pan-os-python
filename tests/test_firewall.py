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
import pandevice.firewall


class TestFirewall(unittest.TestCase):
    def test_id_returns_serial(self):
        expected = 'serial#'

        fw = pandevice.firewall.Firewall(
            serial=expected,
        )

        ret_val = fw.id

        self.assertEqual(expected, ret_val)

    def test_id_returns_hostname(self):
        expected = 'hostName'

        fw = pandevice.firewall.Firewall(
            hostname=expected,
        )

        ret_val = fw.id

        self.assertEqual(expected, ret_val)

    def test_id_returns_no_id(self):
        expected = '<no-id>'

        fw = pandevice.firewall.Firewall()

        ret_val = fw.id

        self.assertEqual(expected, ret_val)

if __name__=='__main__':
    unittest.main()
