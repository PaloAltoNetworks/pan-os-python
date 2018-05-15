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
import unittest

import pandevice.firewall
import pandevice.panorama


class TestUserId(unittest.TestCase):
    """
    [Test section:  userid]

    Verify some userid methods that can be tested without
    a live device
    """

    def test_login(self):
        expected = b'<uid-message><version>1.0</version>' \
                   b'<type>update</type><payload><login>' \
                   b'<entry ip="10.1.1.1" name="example.com\username" timeout="10" />' \
                   b'</login></payload></uid-message>'
        vsys = 'vsys3'

        fw = pandevice.firewall.Firewall(
            'fw1', 'user', 'passwd', 'authkey', serial='Serial', vsys=vsys)
        fw.xapi
        fw._xapi_private.user_id = mock.Mock()

        fw.userid.login(r'example.com\username', '10.1.1.1', timeout=10)

        fw._xapi_private.user_id.assert_called_once_with(cmd=expected, vsys=vsys)


if __name__=='__main__':
    unittest.main()
