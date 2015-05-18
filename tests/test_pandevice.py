#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_pandevice
----------------------------------

Tests for `pandevice` module.
"""

from pandevice import device
from pandevice import network

import expect

import mock
import unittest
import logging

from credentials import TESTRAMA_HOSTNAME, TESTRAMA_USERNAME, TESTRAMA_PASSWORD
from credentials import TESTFW_HOSTNAME, TESTFW_USERNAME, TESTFW_PASSWORD


class TestPandevice(unittest.TestCase):

    def setUp(self):

        logging.basicConfig(level=7)

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
            # This is a test against a real firewall and panorama
            self.p = device.PanDevice(hostname=TESTRAMA_HOSTNAME,
                                      api_username=TESTRAMA_USERNAME,
                                      api_password=TESTRAMA_PASSWORD,
                                      )
            self.d = device.PanDevice(hostname=TESTFW_HOSTNAME,
                                      api_username=TESTFW_USERNAME,
                                      api_password=TESTFW_PASSWORD,
                                      )

    def tearDown(self):
        pass

    def test_set_ntp_servers(self):
        self.d.set_ntp_servers(None)
        self.d.set_ntp_servers("8.8.8.8", secondary="4.2.2.3")

    def test_refresh_devices_from_panorama(self):
        self.p.refresh_devices_from_panorama(self.d)
        self.assertEquals(self.d.serial, "007200002065")
        self.assertTrue(self.d.connected_to_panorama)
        self.assertTrue(self.d.dg_in_sync)

    def test_refresh_interfaces(self):
        # TODO: Set interfaces before refreshing them
        self.d.refresh_interfaces()
        expected = {'ethernet1/1': network.Interface(name="ethernet1/1",
                                                     zone="untrust",
                                                     router="default",
                                                     subnets=["10.5.5.1/24"],
                                                     state="up",
                                                     ),
                    'ethernet1/2': network.Interface(name="ethernet1/2",
                                                     zone="trust",
                                                     router="default",
                                                     subnets=["10.6.6.1/24"],
                                                     state="up",
                                                     ),
                    }
        self.assertDictEqual(self.d.interfaces, expected, "Interfaces dictionary is incorrect\nExpected: %s\n     Got: %s" % (expected, self.d.interfaces))

    def test_refresh_interfaces_mock(self):
        self.xapi.op = mock.Mock()
        self.xapi.xml_python = mock.Mock(
            return_value=expect.op_show_interfaces_all
        )
        self.d.refresh_interfaces()
        expected = {'ethernet1/1': network.Interface(name="ethernet1/1",
                                                     zone="untrust",
                                                     router="default",
                                                     subnets=["10.5.5.1/24"],
                                                     state="up",
                                                     ),
                    'ethernet1/2': network.Interface(name="ethernet1/2",
                                                     zone="trust",
                                                     router="default",
                                                     subnets=["10.6.6.1/24"],
                                                     state="down",
                                                     ),
                    }
        self.assertDictEqual(self.d.interfaces, expected, "Interfaces dictionary is incorrect\nExpected: %s\n     Got: %s" % (expected, self.d.interfaces))

    def test_static_routes(self):
        vr = network.VirtualRouter()
        self.d.add(vr)
        route = vr.add(network.StaticRoute("Default", "0.0.0.0/0", None, "10.5.5.2"))
        route.create()
        route.delete()


if __name__ == '__main__':
    unittest.main()
