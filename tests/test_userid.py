# Copyright (c) 2018, Palo Alto Networks
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
try:
    from unittest import mock
except ImportError:
    import mock
import sys
import unittest

import panos.firewall
import panos.panorama


class TestUserId(unittest.TestCase):
    """
    [Test section:  userid]

    Verify some userid methods that can be tested without
    a live device
    """

    def test_login(self):
        # Must set up different expectations for python 3.8 and higher
        # Per documentation: "Changed in version 3.8: The tostring()
        #   function now preserves the attribute order specified..."
        # https://docs.python.org/3/library/xml.etree.elementtree.html#xml.etree.ElementTree.tostring
        if sys.version_info <= (3, 8):
            expected = (
                b"<uid-message><version>1.0</version>"
                b"<type>update</type><payload><login>"
                b'<entry ip="10.1.1.1" name="example.com\\username" timeout="10" />'
                b"</login></payload></uid-message>"
            )
        else:
            expected = (
                b"<uid-message><version>1.0</version>"
                b"<type>update</type><payload><login>"
                b'<entry name="example.com\\username" ip="10.1.1.1" timeout="10" />'
                b"</login></payload></uid-message>"
            )
        vsys = "vsys3"

        fw = panos.firewall.Firewall(
            "fw1", "user", "passwd", "authkey", serial="Serial", vsys=vsys
        )
        fw.xapi
        fw._xapi_private.user_id = mock.Mock()

        fw.userid.login(r"example.com\username", "10.1.1.1", timeout=10)

        fw._xapi_private.user_id.assert_called_once_with(cmd=expected, vsys=vsys)

    def test_batch_tag_user(self):
        fw = panos.firewall.Firewall(
            "fw1", "user", "passwd", "authkey", serial="Serial", vsys="vsys1"
        )
        fw.xapi
        fw.userid.batch_start()
        fw.userid.tag_user(
            "user1",
            [
                "tag1",
            ],
        )
        fw.userid.tag_user(
            "user2",
            [
                "tag1",
            ],
        )

    def test_batch_untag_user(self):
        fw = panos.firewall.Firewall(
            "fw1", "user", "passwd", "authkey", serial="Serial", vsys="vsys2"
        )
        fw.xapi
        fw.userid.batch_start()
        fw.userid.untag_user(
            "user1",
            [
                "tag1",
            ],
        )
        fw.userid.untag_user(
            "user2",
            [
                "tag1",
            ],
        )


if __name__ == "__main__":
    unittest.main()
