#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_pandevice
----------------------------------

Tests for `pandevice` module.
"""

from pandevice import device
from pandevice.interface import PanInterface
import pan.xapi

import api_xml

import mock
import unittest

from credentials import TESTFW_HOSTNAME, TESTFW_USERNAME, TESTFW_PASSWORD


class TestPandevice(unittest.TestCase):

    def setUp(self):

        # Get current test (in string with format):
        #   tests.test_pandevice.TestPandevice.test_refresh_interfaces_mock
        test_method = self.id()
        if test_method.endswith("_mock"):
            # This is a test with a mock firewall
            mock.patch.object(device.pan.xapi, 'PanXapi', mock.MagicMock())
            self.d = device.PanDevice(hostname="fake-hostname",
                                      api_username="fake-username",
                                      api_password="fake-password",
                                      )
            self.d._retrieve_api_key = mock.Mock(return_value="fakekey")
            # Trigger attempt to populate API key by accessing xapi
            self.xapi = self.d._xapi
        else:
            # This is a test against a real firewall
            self.d = device.PanDevice(hostname=TESTFW_HOSTNAME,
                                      api_username=TESTFW_USERNAME,
                                      api_password=TESTFW_PASSWORD,
                                      )

    def tearDown(self):
        pass

    def test_refresh_interfaces(self):
        # TODO: Set interfaces before refreshing them
        self.d.refresh_interfaces()
        expected = {'ethernet1/1': PanInterface(name="ethernet1/1",
                                                zone="untrust",
                                                router="default",
                                                subnets=["10.5.5.1/24"],
                                                state="up",
                                                ),
                    'ethernet1/2': PanInterface(name="ethernet1/2",
                                                zone="trust",
                                                router="default",
                                                subnets=["10.6.6.1/24"],
                                                state="down",
                                                ),
                    }
        self.assertDictEqual(self.d.interfaces, expected, "Interfaces dictionary is incorrect\nExpected: %s\n     Got: %s" % (expected, self.d.interfaces))

    def test_refresh_interfaces_mock(self):
        self.xapi.op = mock.Mock()
        self.xapi.xml_python = mock.Mock(
            return_value=api_xml.op_show_interfaces_all
        )
        self.d.refresh_interfaces()
        expected = {'ethernet1/1': PanInterface(name="ethernet1/1",
                                                zone="untrust",
                                                router="default",
                                                subnets=["10.5.5.1/24"],
                                                state="up",
                                                ),
                    'ethernet1/2': PanInterface(name="ethernet1/2",
                                                zone="trust",
                                                router="default",
                                                subnets=["10.6.6.1/24"],
                                                state="down",
                                                ),
                    }
        self.assertDictEqual(self.d.interfaces, expected, "Interfaces dictionary is incorrect\nExpected: %s\n     Got: %s" % (expected, self.d.interfaces))


if __name__ == '__main__':
    unittest.main()
