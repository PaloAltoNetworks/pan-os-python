# Copyright (c) 2020, Palo Alto Networks
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
import xml.etree.ElementTree as ET

import panos
import panos.panorama


class TestPanorama(unittest.TestCase):
    def setUp(self):
        self.obj = panos.panorama.Panorama("localhost", "admin", "admin", "secret")

    def test_get_device_group_hierarchy(self):
        resp = """
<response code="19" status="success">
  <result>
    <dg-hierarchy>
      <dg dg_id="55" name="parent grp 1">
        <dg dg_id="54" name="child grp">
          <dg dg_id="57" name="trick2g">
            <dg dg_id="58" name="trick3g" />
          </dg>
        </dg>
      </dg>
      <dg dg_id="11" name="some group" />
      <dg dg_id="44" name="ansible device group" />
      <dg dg_id="56" name="parent grp 2" />
    </dg-hierarchy>
  </result>
</response>"""
        expected = {
            "parent grp 1": None,
            "some group": None,
            "ansible device group": None,
            "parent grp 2": None,
            "child grp": "parent grp 1",
            "trick2g": "child grp",
            "trick3g": "trick2g",
        }

        spec = {"return_value": ET.fromstring(resp)}
        self.obj.op = mock.Mock(**spec)

        ans = self.obj.get_device_group_hierarchy()

        self.assertEqual(expected, ans)


class TestDeviceGroup(unittest.TestCase):
    def setUp(self):
        self.pano = panos.panorama.Panorama("localhost", "admin", "admin", "secret")
        self.obj = panos.panorama.DeviceGroup("myGroup")
        self.pano.add(self.obj)

    def test_update_hierarchical_parent_with_parent(self):
        resp1 = [
            '<response status="success" code="19">',
            "<result>",
            "<msg><line>Job enqueued with jobid 4999</line></msg>",
            "<job>4999</job>",
            "</result>",
            "</response>",
        ]

        resp2 = [
            '<response status="success">',
            "<result>",
            "<job>",
            "<tenq>2020/09/18 10:08:08</tenq>",
            "<tdeq>10:08:08</tdeq>",
            "<id>4999</id>",
            "<user>admin</user>",
            "<type>Move-DG</type>",
            "<status>FIN</status>",
            "<queued>NO</queued>",
            "<stoppable>no</stoppable>",
            "<result>OK</result>",
            "<tfin>10:08:08</tfin>",
            "<description></description>",
            "<positionInQ>0</positionInQ>",
            "<progress>100</progress>",
            "<details><line>successfully moved dg myGroup</line></details>",
            "<warnings></warnings>",
            "</job>",
            "</result>",
            "</response>",
        ]
        r2_xml = ET.fromstring("".join(resp2))

        expected = {
            "success": True,
            "result": "OK",
            "jobid": "4999",
            "user": "admin",
            "starttime": "2020/09/18 10:08:08",
            "endtime": "10:08:08",
            "messages": ["successfully moved dg myGroup",],
            "warnings": None,
            "devices": {},
            "xml": r2_xml,
        }

        spec1 = {
            "return_value": ET.fromstring("".join(resp1)),
        }
        self.pano.op = mock.Mock(**spec1)

        spec2 = {
            "return_value": r2_xml,
        }
        self.pano.xapi.op = mock.Mock(**spec2)

        ans = self.obj.update_hierarchical_parent("group2")

        self.pano.op.assert_called_once_with(
            ET.tostring(
                ET.fromstring(
                    "".join(
                        [
                            "<request>",
                            "<move-dg>",
                            '<entry name="myGroup">',
                            "<new-parent-dg>group2</new-parent-dg>",
                            "</entry>",
                            "</move-dg>",
                            "</request>",
                        ]
                    )
                ),
                encoding="utf-8",
            ),
            cmd_xml=False,
        )
        self.assertEqual(expected, ans)

    def test_update_hierarchical_parent_without_parent(self):
        resp1 = [
            '<response status="success" code="19">',
            "<result>",
            "<msg><line>Job enqueued with jobid 4999</line></msg>",
            "<job>4999</job>",
            "</result>",
            "</response>",
        ]

        resp2 = [
            '<response status="success">',
            "<result>",
            "<job>",
            "<tenq>2020/09/18 10:08:08</tenq>",
            "<tdeq>10:08:08</tdeq>",
            "<id>4999</id>",
            "<user>admin</user>",
            "<type>Move-DG</type>",
            "<status>FIN</status>",
            "<queued>NO</queued>",
            "<stoppable>no</stoppable>",
            "<result>OK</result>",
            "<tfin>10:08:08</tfin>",
            "<description></description>",
            "<positionInQ>0</positionInQ>",
            "<progress>100</progress>",
            "<details><line>successfully moved dg myGroup</line></details>",
            "<warnings></warnings>",
            "</job>",
            "</result>",
            "</response>",
        ]
        r2_xml = ET.fromstring("".join(resp2))

        expected = {
            "success": True,
            "result": "OK",
            "jobid": "4999",
            "user": "admin",
            "starttime": "2020/09/18 10:08:08",
            "endtime": "10:08:08",
            "messages": ["successfully moved dg myGroup",],
            "warnings": None,
            "devices": {},
            "xml": r2_xml,
        }

        spec1 = {
            "return_value": ET.fromstring("".join(resp1)),
        }
        self.pano.op = mock.Mock(**spec1)

        spec2 = {
            "return_value": r2_xml,
        }
        self.pano.xapi.op = mock.Mock(**spec2)

        ans = self.obj.update_hierarchical_parent()

        self.pano.op.assert_called_once_with(
            ET.tostring(
                ET.fromstring(
                    "".join(
                        [
                            "<request>",
                            "<move-dg>",
                            '<entry name="myGroup">',
                            "</entry>",
                            "</move-dg>",
                            "</request>",
                        ]
                    )
                ),
                encoding="utf-8",
            ),
            cmd_xml=False,
        )
        self.assertEqual(expected, ans)


if __name__ == "__main__":
    unittest.main()
