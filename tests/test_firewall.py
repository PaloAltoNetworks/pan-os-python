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
import xml.etree.ElementTree as ET
from unittest import mock

import panos
import panos.errors as err
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


class TestCommitWithoutJob(unittest.TestCase):
    def _firewall(self, response):
        fw = panos.firewall.Firewall(hostname="fw.example")
        xapi = mock.Mock()
        xapi.commit.return_value = response
        fw._xapi_private = xapi
        return fw

    def test_no_changes_message_returns_none(self):
        fw = self._firewall(
            ET.fromstring(
                "<response status='success'><msg><line>"
                "There are no changes to commit."
                "</line></msg></response>"
            )
        )

        self.assertIsNone(fw._commit(sync=False, exception=False))

    def test_result_message_without_job_returns_none(self):
        fw = self._firewall(
            ET.fromstring(
                "<response status='success'><result><msg><line>"
                "The result of this commit would be the same. No action needed."
                "</line></msg></result></response>"
            )
        )

        self.assertIsNone(fw._commit(sync=True, exception=False))

    def test_empty_commit_response_returns_none(self):
        fw = self._firewall(None)

        self.assertIsNone(fw._commit())

    def test_exception_flag_raises_commit_not_needed(self):
        fw = self._firewall(
            ET.fromstring(
                "<response><msg><line>There are no changes to commit.</line></msg></response>"
            )
        )

        with self.assertRaises(err.PanCommitNotNeeded):
            fw._commit(exception=True)

    def test_log_collector_group_push_without_job(self):
        message = (
            "Generated config and committed to connected collectors in group lab"
        )
        fw = self._firewall(
            ET.fromstring(
                "<response><msg><line>{0}</line></msg></response>".format(message)
            )
        )

        result = fw._commit()

        self.assertEqual(result["success"], True)
        self.assertEqual(result["jobid"], "0")
        self.assertEqual(result["messages"], [message])

    def test_job_id_is_returned(self):
        fw = self._firewall(
            ET.fromstring("<response><result><job>42</job></result></response>")
        )

        self.assertEqual(fw._commit(sync=False), "42")


if __name__ == "__main__":
    unittest.main()
