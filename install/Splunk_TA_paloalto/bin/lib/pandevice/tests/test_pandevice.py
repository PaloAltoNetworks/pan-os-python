#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_pandevice
----------------------------------

Tests for `pandevice` module.
"""

from pandevice import firewall
from pandevice import panorama
from pandevice import network
from pandevice import objects

import expect

import mock
import unittest
import logging

from pprint import pformat

from credentials import TESTRAMA_HOSTNAME, TESTRAMA_USERNAME, TESTRAMA_PASSWORD
from credentials import TESTFW_HOSTNAME, TESTFW_USERNAME, TESTFW_PASSWORD


class TestPandevice(unittest.TestCase):

    def setUp(self):

        logging.basicConfig(level=10)

        # Get current test (in string with format):
        #   tests.test_pandevice.TestPandevice.test_refresh_interfaces_mock
        test_method = self.id()
        if test_method.endswith("_mock"):
            # This is a test with a mock firewall
            mock.patch.object(firewall.pan.xapi, 'PanXapi', mock.MagicMock())
            self.d = firewall.Firewall(hostname="fake-hostname",
                                       api_username="fake-username",
                                       api_password="fake-password",
                                       )
            self.d._retrieve_api_key = mock.Mock(return_value="fakekey")
            # Trigger attempt to populate API key by accessing xapi
            self.xapi = self.d.xapi
        else:
            # This is a test against a real firewall and panorama
            self.p = panorama.Panorama(hostname=TESTRAMA_HOSTNAME,
                                       api_username=TESTRAMA_USERNAME,
                                       api_password=TESTRAMA_PASSWORD,
                                       )
            self.d = firewall.Firewall(hostname=TESTFW_HOSTNAME,
                                       api_username=TESTFW_USERNAME,
                                       api_password=TESTFW_PASSWORD,
                                       )

    def tearDown(self):
        pass

    def test_system_info(self):
        version, model, serial = self.d.system_info()
        self.assertEqual(version, "6.0.0")


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

    def test_static_routes(self):
        vr = network.VirtualRouter()
        self.d.add(vr)
        route = vr.add(network.StaticRoute("Default", "0.0.0.0/0", None, "10.5.5.2"))
        vr.create()
        vr.delete()
        #route.create()
        #route.delete()

    def test_software_updater(self):
        #result = self.d.updater.download("6.1.0", sync=True)
        result = self.d.software.check()

    def test_content_updater(self):
        result = self.d.content.download(sync=True)
        result = self.d.content.install(sync=True)

    def test_upgrade_to_version(self):
        #result = self.d.software.upgrade_to_version("latest", dryrun=True)
        result = self.d.software.upgrade_to_version("7.0.0", dryrun=True)

    def test_syncreboot(self):
        import re
        self.d.xapi.op("request restart system", cmd_xml=True)
        version = self.d.syncreboot(timeout=120)
        result = re.match(r"\d+\.\d+\.\d+", version)
        self.assertIsNotNone(result)

    def test_addressobject(self):
        address_object = objects.AddressObject("mytest", "5.5.4.5/24",
                                               description="new test")
        self.d.add(address_object)
        address_object.create()


if __name__ == '__main__':
    unittest.main()
