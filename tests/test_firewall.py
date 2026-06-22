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

# Python 2 has no unittest.mock; fall back to the standalone mock package.
try:
    from unittest import mock
except ImportError:
    import mock

import panos
import panos.firewall


class TestFirewall(unittest.TestCase):
    def test_id_returns_serial(self):
        expected = "serial#"

        fw = panos.firewall.Firewall(
            serial=expected,
        )

        ret_val = fw.id

        self.assertEqual(expected, ret_val)

    def test_id_returns_hostname(self):
        expected = "hostName"

        fw = panos.firewall.Firewall(
            hostname=expected,
        )

        ret_val = fw.id

        self.assertEqual(expected, ret_val)

    def test_id_returns_no_id(self):
        expected = "<no-id>"

        fw = panos.firewall.Firewall()

        ret_val = fw.id

        self.assertEqual(expected, ret_val)


class TestFirewallHa(unittest.TestCase):
    def _ha_pair(self):
        fw = panos.firewall.Firewall("10.0.0.1", "user", "pass")
        peer = panos.firewall.Firewall("10.0.0.2", "user", "pass")
        fw.set_ha_peers(peer)
        return fw, peer

    def test_refresh_ha_active_clears_stale_ha_failed(self):
        """A live state refresh clears ha_failed on the reachable device."""
        fw, peer = self._ha_pair()
        # A transient error failed this device and promoted the peer to active.
        fw.set_failed()
        self.assertTrue(fw.ha_failed)
        # Live HA now reports this device is active again.
        fw.show_highavailability_state = mock.Mock(return_value=("active", None))
        peer.show_highavailability_state = mock.Mock(return_value=("passive", None))

        fw.refresh_ha_active()

        self.assertFalse(fw.ha_failed)

    def test_refresh_ha_active_keeps_ha_failed_when_state_not_authoritative(self):
        """A non-authoritative state (initial/disabled) leaves ha_failed untouched."""
        fw, peer = self._ha_pair()
        # A transient error failed this device.
        fw.set_failed()
        self.assertTrue(fw.ha_failed)
        # HA is still initializing, so the reported state is not authoritative.
        fw.show_highavailability_state = mock.Mock(return_value=("initial", None))
        peer.show_highavailability_state = mock.Mock(return_value=("active", None))

        fw.refresh_ha_active()

        self.assertTrue(fw.ha_failed)


if __name__ == "__main__":
    unittest.main()
