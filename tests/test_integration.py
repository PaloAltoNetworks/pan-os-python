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
try:
    from unittest import mock
except ImportError:
    import mock
import unittest
import pan.xapi

import pandevice.base as Base
import pandevice.device
import pandevice.errors as Err
import pandevice.firewall
import pandevice.ha
import pandevice.network
import pandevice.objects
import pandevice.panorama

import xml.etree.ElementTree as ET


class TestTemplates(unittest.TestCase):
    def setUp(self):
        self.pano = pandevice.panorama.Panorama(
            'foo', 'bar', 'baz', 'apikey')
        self.pano._version_info = (8, 0, 0)

    def test_template_element_str_stays_consistent(self):
        expected = ''.join([
            '<entry name="blah"><description>my description</description>',
            '<settings><default-vsys>vsys1</default-vsys></settings>',
            '<config><devices><entry name="localhost.localdomain"><vsys>',
            '<entry name="vsys1"><import><network><interface /></network>',
            '</import></entry></vsys><network><virtual-router>',
            '<entry name="some vr"><admin-dists><static>42</static>',
            '<ebgp>21</ebgp></admin-dists></entry></virtual-router>',
            '</network></entry></devices></config></entry>',
        ])

        xml_tree = ET.fromstring('<result>{0}</result>'.format(expected))
        t = pandevice.panorama.Template()
        self.pano.add(t)
        other = t.refreshall_from_xml(xml_tree)[0]

        self.assertEqual(expected, other.element_str().decode('utf-8'))


class TestNearestPandevice(unittest.TestCase):
    """
    [Test section: nearest_pandevice()]

    Verify that `nearest_pandevice()` returns the correct PanObject.

    All tests have a setup of the following:
        Panorama > DeviceGroup > Firewall > AddressObject

    In this configuration, running .nearest_pandevice() should return the
    panorama device in all cases but running it from the AddressObject.
    """
    def setUp(self):
        self.panorama = pandevice.panorama.Panorama(
            'foo', 'bar', 'baz', 'apikey')
        self.device_group = pandevice.panorama.DeviceGroup(
            'My pandevice Group')
        self.firewall = pandevice.firewall.Firewall(
            'foo', 'bar', 'baz', 'apikey')
        self.address_object = pandevice.objects.AddressObject(
            'webserver', '192.168.1.100', description='Intranet web server',
            tag=['http', 'https'])

        self.firewall.add(self.address_object)
        self.device_group.add(self.firewall)
        self.panorama.add(self.device_group)

        self.assertEqual(self.firewall, self.address_object.parent)
        self.assertEqual([], self.address_object.children)
        self.assertEqual(self.device_group, self.firewall.parent)
        self.assertEqual([self.address_object, ], self.firewall.children)
        self.assertEqual(self.panorama, self.device_group.parent)
        self.assertEqual([self.firewall, ], self.device_group.children)
        self.assertEqual(None, self.panorama.parent)
        self.assertEqual([self.device_group, ], self.panorama.children)

    def test_nearest_pandevice_from_addressobject_in_pano_dg_fw_ao_chain(self):
        """Runs nearest_pandevice() on the AddressObject.

        This should return the Firewall PanDevice.
        """
        ret_val = self.address_object.nearest_pandevice()

        self.assertEqual(self.firewall, ret_val)

    def test_nearest_pandevice_from_firewall_in_pano_dg_fw_ao_chain(self):
        """Runs nearest_pandevice() on the firewall.

        This should return the Panorama PanDevice.
        """
        ret_val = self.firewall.nearest_pandevice()

        self.assertEqual(self.panorama, ret_val)

    def test_nearest_pandevice_from_device_group_in_pano_dg_fw_ao_chain(self):
        """Runs nearest_pandevice() on the device group.

        This should return the Panorama PanDevice.
        """
        ret_val = self.device_group.nearest_pandevice()

        self.assertEqual(self.panorama, ret_val)

    def test_nearest_pandevice_from_panorama_in_pano_dg_fw_ao_chain(self):
        """Runs nearest_pandevice() on the panorama.

        This should return the Panorama PanDevice.
        """
        ret_val = self.panorama.nearest_pandevice()

        self.assertEqual(self.panorama, ret_val)

    def test_nearest_pandevice_from_firewall_with_no_parents_returns_self(self):
        fw = pandevice.firewall.Firewall(
            'foo', 'bar', 'baz', 'apikey')

        ret_val = fw.nearest_pandevice()

        self.assertEqual(fw, ret_val)


class TestElementStr_7_0(unittest.TestCase):
    """
    [Test section:  element_str()]

    Verify the XML created under various circumstances for various
    objects and setups:

        * HighAvailability with HA1 and HA2 children
        * VirtualRouter with StaticRoute child
        * EthernetInterface
        * Firewall
        * AddressObject
    """

    # 1) HighAvailability with HA1 and HA2 children
    def test_element_str_from_highavailability_with_ha1_and_ha2_children(self):
        expected = b''.join([
            b'<high-availability><enabled>yes</enabled><group><entry name="1">',
            b'<description>my ha conf description</description>',
            b'<configuration-synchronization><enabled>yes</enabled>',
            b'</configuration-synchronization><peer-ip>10.5.1.5</peer-ip>',
            b'<mode><active-passive><passive-link-state>passive state',
            b'</passive-link-state></active-passive></mode>',
            b'<state-synchronization><enabled>no</enabled><ha2-keep-alive>',
            b'<enabled>yes</enabled><action>ha2 do stuff</action><threshold>',
            b'2</threshold></ha2-keep-alive></state-synchronization></entry>',
            b'</group><interface><ha1><ip-address>10.5.1.1</ip-address>',
            b'<netmask>255.255.255.0</netmask><port>ethernet1/6</port>',
            b'<gateway>10.5.1.2</gateway><link-speed>1000</link-speed>',
            b'<link-duplex>auto</link-duplex><monitor-hold-time>7',
            b'</monitor-hold-time></ha1><ha1-backup /><ha2>',
            b'<ip-address>10.6.1.1</ip-address><netmask>255.255.255.0',
            b'</netmask><port>ethernet1/7</port><gateway>10.6.1.2</gateway>',
            b'<link-speed>1000</link-speed><link-duplex>auto</link-duplex>',
            b'</ha2><ha2-backup /><ha3 /></interface></high-availability>',
        ])

        h1o = pandevice.ha.HA1(
            name='ha101', ip_address='10.5.1.1', netmask='255.255.255.0',
            port='ethernet1/6', gateway='10.5.1.2', link_speed='1000',
            link_duplex='auto', monitor_hold_time=7)
        h2o = pandevice.ha.HA2(
            name='ha202', ip_address='10.6.1.1', netmask='255.255.255.0',
            port='ethernet1/7', gateway='10.6.1.2', link_speed='1000',
            link_duplex='auto')
        ha_config = pandevice.ha.HighAvailability(
            'my high availability config', True, '1', 'my ha conf description',
            True, '10.5.1.5', 'active-passive', 'passive state', False, True,
            'ha2 do stuff', 2)

        ha_config.add(h1o)
        ha_config.add(h2o)
        ha_config.retrieve_panos_version = mock.Mock(return_value=(7, 0, 0))

        ret_val = ha_config.element_str()

        self.assertEqual(expected, ret_val,
            '\n{0}\n{1}'.format(expected, ret_val))

    # 2) VirtualRouter with StaticRoute child
    def test_element_str_from_virtualrouter_with_sr_parent(self):
        '''StaticRoute > VirtualRouter'''
        expected = b''.join([
            b'<entry name="default"><interface><member>ethernet1/3</member>',
            b'</interface><routing-table><ip><static-route>',
            b'<entry name="my static route"><destination>0.0.0.0/0',
            b'</destination><nexthop><ip-address>192.168.5.1</ip-address>',
            b'</nexthop><interface>ethernet1/4</interface><metric>10</metric>',
            b'</entry></static-route></ip></routing-table></entry>',
        ])

        vro = pandevice.network.VirtualRouter('default', 'ethernet1/3')
        sro = pandevice.network.StaticRoute(
            'my static route', '0.0.0.0/0', 'ip-address',
            '192.168.5.1', 'ethernet1/4')

        vro.add(sro)

        ret_val = vro.element_str()

        self.assertEqual(expected, ret_val)

    # 3) EthernetInterface
    def test_element_str_from_ethernetinterface(self):
        expected = b''.join([
            b'<entry name="ethernet1/1"><layer3><ip><entry name="10.1.1.1" />',
            b'</ip></layer3><link-speed>1000</link-speed><link-duplex>auto',
            b'</link-duplex><link-state>auto</link-state></entry>',
        ])

        o = pandevice.network.EthernetInterface(
            'ethernet1/1', 'layer3', '10.1.1.1', link_speed='1000',
            link_duplex='auto', link_state='auto')

        o_str = o.element_str()
        self.assertEqual(expected, o_str)

    def test_element_str_from_ethernetinterface_in_en_l3s_arp(self):
        '''EthernetInterface > Layer3Subinterface > Arp'''
        expected = b''.join([
            b'<entry name="ethernet1/1"><layer3><ip>',
            b'<entry name="10.3.6.12" /></ip><units>',
            b'<entry name="ethernet1/1.355"><tag>355</tag><ip>',
            b'<entry name="10.20.30.40/24" /></ip><mtu>1500</mtu>',
            b'<adjust-tcp-mss>yes</adjust-tcp-mss><arp>',
            b'<entry name="10.5.10.15"><hw-address>00:30:48:52:cd:dc',
            b'</hw-address></entry></arp></entry></units></layer3></entry>',
        ])

        ao = pandevice.network.Arp('10.5.10.15', '00:30:48:52:cd:dc')
        l3so = pandevice.network.Layer3Subinterface(
            'ethernet1/1.355', 355, '10.20.30.40/24',
            mtu=1500, adjust_tcp_mss=True)
        eio = pandevice.network.EthernetInterface(
            'ethernet1/1', mode='layer3', ip='10.3.6.12')

        l3so.add(ao)
        eio.add(l3so)

        # This is actually a 7.x test
        for o in (ao, l3so, eio):
            o.retrieve_panos_version = mock.Mock(return_value=(7, 0, 0))

        ret_val = eio.element_str()

        self.assertEqual(expected, ret_val)

    def test_element_str_from_ethernetinterface_for_aggregate_group(self):
        expected = b''.join([
            b'<entry name="ethernet1/1"><aggregate-group>ae1',
            b'</aggregate-group></entry>',
        ])
        eio = pandevice.network.EthernetInterface(
            'ethernet1/1', 'aggregate-group', '10.3.6.12',
            aggregate_group='ae1')

        ret_val = eio.element_str()

        self.assertEqual(expected, ret_val)

    # 4) Firewall
    """
    * vsys of the firewall
    * multi_vsys variable is
    * serial is set / not set
    * parent is pano / device group
    """
    def test_element_str_from_firewall_with_pano_parent_and_systemsettings_child(self):
        expected = b''.join([
            b'<entry name="Serial"><vsys>',
            b'<entry name="vsys1" /></vsys></entry>',
        ])

        fw = pandevice.firewall.Firewall(
            'fw1', 'user', 'passwd', 'authkey', serial='Serial', vsys='vsys3')
        pano = pandevice.panorama.Panorama('10.100.5.2')
        conf = pandevice.device.SystemSettings(
            hostname='Hostname-Setting',
            domain='paloaltonetworks.com',
            ip_address='10.20.30.40',
            netmask='255.255.255.0',
            default_gateway='10.20.30.1',
            panorama='10.100.5.2',
            login_banner="This is not the firewall you're looking for..",
            update_server='8.8.8.8',
        )

        fw.add(conf)
        pano.add(fw)

        ret_val = fw.element_str()

        self.assertEqual(expected, ret_val)

    def test_element_str_from_firewall_without_serial_number_raises_error(self):
        fw = pandevice.firewall.Firewall('foo')

        self.assertRaises(
            ValueError,
            fw.element_str)

    def test_element_str_from_firewall_with_dg_pano_parents_and_multi_vsys(self):
        expected = b''.join([
            b'<entry name="serial"><vsys><entry name="vsys3" />',
            b'</vsys></entry>',
        ])

        fw = pandevice.firewall.Firewall(
            'fw1', 'user', 'passwd', 'authkey',
            serial='serial', vsys='vsys3', multi_vsys=True)
        dg = pandevice.panorama.DeviceGroup('my group')
        p = pandevice.panorama.Panorama('pano')

        dg.add(fw)
        p.add(dg)

        ret_val = fw.element_str()

        self.assertEqual(expected, ret_val)

    # 5) AddressObject
    def test_element_str_from_addressobject(self):
        expected = b''.join([
            b'<entry name="webserver"><ip-netmask>192.168.1.100</ip-netmask>',
            b'<description>Intranet web server</description><tag><member>',
            b'https</member><member>http</member></tag></entry>',
        ])
        o = pandevice.objects.AddressObject(
            'webserver', '192.168.1.100', description='Intranet web server',
            tag=['https', 'http'])

        o_str = o.element_str()
        self.assertEqual(expected, o_str)


class TestXpaths_7_0(unittest.TestCase):
    """
    [Test section: xpaths]
    Test that both set and edit xpaths are reported correctly.

    These test cases have various object constructions, and verify that both
    the 'set' and 'edit/delete' xpath can correctly be identified.
    """

    # HA1 / HA2 Tests
    def test_edit_xpath_from_ha1_with_ha_fw_parents(self):
        expected = ''.join([
            "/config/devices/entry[@name='localhost.localdomain']",
            "/deviceconfig/high-availability",
            "/interface/ha1",
        ])

        child = pandevice.ha.HA1()
        parent = pandevice.ha.HighAvailability()
        fw = pandevice.firewall.Firewall()

        parent.add(child)
        fw.add(parent)

        ret_val = child.xpath()

        self.assertEqual(expected, ret_val)

    def test_edit_xpath_from_ha1_with_ha_fw_pano_parents(self):
        expected = ''.join([
            "/config/devices/entry[@name='localhost.localdomain']",
            "/deviceconfig/high-availability",
            "/interface/ha1",
        ])

        child = pandevice.ha.HA1('ha1')
        parent = pandevice.ha.HighAvailability('ha parent')
        fw = pandevice.firewall.Firewall('myfw')
        pano = pandevice.panorama.Panorama('panorama')

        parent.add(child)
        fw.add(parent)
        pano.add(fw)

        ret_val = child.xpath()

        self.assertEqual(expected, ret_val)

    def test_edit_xapth_from_ha2_with_ha_fw_parents(self):
        expected = ''.join([
            "/config/devices/entry[@name='localhost.localdomain']",
            "/deviceconfig/high-availability",
            "/interface/ha2",
        ])

        child = pandevice.ha.HA2('child')
        parent = pandevice.ha.HighAvailability('parent')
        fw = pandevice.firewall.Firewall('myfw')

        parent.add(child)
        fw.add(parent)

        ret_val = child.xpath()

        self.assertEqual(expected, ret_val)

    def test_set_xpath_from_ha2_with_ha_fw_parents(self):
        expected = ''.join([
            "/config/devices/entry[@name='localhost.localdomain']",
            "/deviceconfig/high-availability",
            "/interface",
        ])

        child = pandevice.ha.HA2('child')
        parent = pandevice.ha.HighAvailability('HighAvail')
        fw = pandevice.firewall.Firewall('myfw')

        parent.add(child)
        fw.add(parent)

        ret_val = child.xpath_short()

        self.assertEqual(ret_val, expected)
        self.assertEqual(expected, ret_val)

    # VirtualRouter tests
    def test_edit_xpath_from_virtualrouter_with_sr_fw_parents(self):
        '''Firewall > VirtualRouter > StaticRoute'''
        expected = ''.join([
            "/config/devices/entry[@name='localhost.localdomain']",
            "/routing-table/ip/static-route/entry[@name='sr']",
            "/network/virtual-router/entry[@name='vr']",
        ])

        child = pandevice.network.VirtualRouter('vr')
        parent = pandevice.network.StaticRoute('sr')
        fw = pandevice.firewall.Firewall('fw')
        fw.get_device_version = mock.Mock(return_value=(7, 0, 0))

        parent.add(child)
        fw.add(parent)

        ret_val = child.xpath()

        self.assertEqual(expected, ret_val)

    def test_set_xpath_from_virtualrouter_with_sr_fw_parents(self):
        '''Firewall > VirtualRouter > StaticRoute'''
        expected = ''.join([
            "/config/devices/entry[@name='localhost.localdomain']",
            "/routing-table/ip/static-route/entry[@name='sr']",
            "/network/virtual-router",
        ])

        child = pandevice.network.VirtualRouter('vr')
        parent = pandevice.network.StaticRoute('sr')
        fw = pandevice.firewall.Firewall('fw')
        fw.get_device_version = mock.Mock(return_value=(7, 0, 0))

        parent.add(child)
        fw.add(parent)

        ret_val = child.xpath_short()

        self.assertEqual(expected, ret_val)

    # Arp (EthernetInterface) tests
    def test_edit_xpath_from_arp_with_l3s_ei_fw_parents(self):
        expected = ''.join([
            "/config/devices/entry[@name='localhost.localdomain']",
            "/network/interface/ethernet/entry[@name='Eth Interface Object']",
            "/layer3/units/entry[@name='Layer3 Subint Object']",
            "/arp/entry[@name='arp object']",
        ])

        ao = pandevice.network.Arp('arp object')
        l3so = pandevice.network.Layer3Subinterface('Layer3 Subint Object')
        eio = pandevice.network.EthernetInterface('Eth Interface Object')
        fw = pandevice.firewall.Firewall('fw')
        fw.get_device_version = mock.Mock(return_value=(7, 0, 0))

        l3so.add(ao)
        eio.add(l3so)
        fw.add(eio)

        ret_val = ao.xpath()

        self.assertEqual(expected, ret_val)

    def test_set_xpath_from_arp_with_l3s_ei_fw_parents(self):
        expected = ''.join([
            "/config/devices/entry[@name='localhost.localdomain']",
            "/network/interface/ethernet/entry[@name='Eth Interface Object']",
            "/layer3/units/entry[@name='Layer3 Subint Object']",
            "/arp",
        ])

        ao = pandevice.network.Arp('arp object')
        l3so = pandevice.network.Layer3Subinterface('Layer3 Subint Object')
        eio = pandevice.network.EthernetInterface('Eth Interface Object')
        fw = pandevice.firewall.Firewall('fw')
        fw.get_device_version = mock.Mock(return_value=(7, 0, 0))

        l3so.add(ao)
        eio.add(l3so)
        fw.add(eio)

        ret_val = ao.xpath_short()

        self.assertEqual(expected, ret_val)

    # Firewall tests
    def test_edit_xpath_from_firewall(self):
        # This is not a valid xpath, but its what should happen
        # if there is no parent
        expected = ''.join([
            "/devices/entry[@name='serial']",
        ])

        fw = pandevice.firewall.Firewall(
            'foo', vsys='vsys2', serial='serial')

        ret_val = fw.xpath()

        self.assertEqual(expected, ret_val)

    def test_set_xpath_from_firewall(self):
        # This is not a valid xpath, but its what should happen
        # if there is no parent
        expected = ''.join([
            "/devices",
        ])

        fw = pandevice.firewall.Firewall(
            'foo', vsys='vsys2', serial='serial')

        ret_val = fw.xpath_short()

        self.assertEqual(expected, ret_val)

    def test_edit_xpath_from_firewall_with_pano_parent(self):
        expected = "/config/mgt-config/devices/entry[@name='serial']"

        p = pandevice.panorama.Panorama('pano')
        fw = pandevice.firewall.Firewall(
            'foo', vsys='vsys2', serial='serial')

        p.add(fw)

        ret_val = fw.xpath()

        self.assertEqual(expected, ret_val)

    def test_set_xpath_from_firewall_with_pano_parent(self):
        expected = "/config/mgt-config/devices"

        p = pandevice.panorama.Panorama('pano')
        fw = pandevice.firewall.Firewall(
            'foo', vsys='vsys2', serial='serial')

        p.add(fw)

        ret_val = fw.xpath_short()

        self.assertEqual(expected, ret_val)

    def test_edit_xpath_from_firewall_with_dg_pano_parents(self):
        expected = ''.join([
            "/config/devices/entry[@name='localhost.localdomain']",
            "/device-group/entry[@name='my group']/devices",
            "/entry[@name='serial']",
        ])

        p = pandevice.panorama.Panorama('pano')
        dg = pandevice.panorama.DeviceGroup('my group')
        fw = pandevice.firewall.Firewall(
            'foo', vsys='vsys2', serial='serial')

        dg.add(fw)
        p.add(dg)

        ret_val = fw.xpath()

        self.assertEqual(expected, ret_val)

    def test_set_xpath_from_firewall_with_dg_pano_parents(self):
        expected = ''.join([
            "/config/devices/entry[@name='localhost.localdomain']",
            "/device-group/entry[@name='my group']/devices",
        ])

        p = pandevice.panorama.Panorama('pano')
        dg = pandevice.panorama.DeviceGroup('my group')
        fw = pandevice.firewall.Firewall(
            'foo', vsys='vsys2', serial='serial')

        dg.add(fw)
        p.add(dg)

        ret_val = fw.xpath_short()

        self.assertEqual(expected, ret_val)

    # AddressObject tests
    def test_edit_xpath_from_addressobject_with_fw_parent(self):
        expected = ''.join([
            "/config/devices/entry[@name='localhost.localdomain']",
            "/vsys/entry[@name='vsys2']",
            "/address/entry[@name='ntp server']",
        ])

        ao = pandevice.objects.AddressObject('ntp server')
        fw = pandevice.firewall.Firewall('fw', vsys='vsys2')
        fw.get_device_version = mock.Mock(return_value=(7, 0, 0))

        fw.add(ao)

        ret_val = ao.xpath()

        self.assertEqual(expected, ret_val)

    def test_edit_xpath_from_addressobject_with_dg_panorama_parents(self):
        expected = ''.join([
            "/config/devices/entry[@name='localhost.localdomain']",
            "/device-group/entry[@name='My Group']",
            "/address/entry[@name='webproxy']",
        ])

        ao = pandevice.objects.AddressObject('webproxy')
        dg = pandevice.panorama.DeviceGroup('My Group')
        pano = pandevice.panorama.Panorama('My Panorama')
        pano.get_device_version = mock.Mock(return_value=(7, 0, 0))

        dg.add(ao)
        pano.add(dg)

        ret_val = ao.xpath()

        self.assertEqual(expected, ret_val)

    def test_set_xpath_from_addressobject_with_fw_parent(self):
        expected = ''.join([
            "/config/devices/entry[@name='localhost.localdomain']",
            "/vsys/entry[@name='vsys2']",
            "/address",
        ])

        ao = pandevice.objects.AddressObject('ntp server')
        fw = pandevice.firewall.Firewall('fw', vsys='vsys2')
        fw.get_device_version = mock.Mock(return_value=(7, 0, 0))

        fw.add(ao)

        ret_val = ao.xpath_short()

        self.assertEqual(expected, ret_val)

    def test_set_xpath_from_addressobject_with_dg_panorama_parents(self):
        expected = ''.join([
            "/config/devices/entry[@name='localhost.localdomain']",
            "/device-group/entry[@name='My Group']",
            "/address",
        ])

        ao = pandevice.objects.AddressObject('webproxy')
        dg = pandevice.panorama.DeviceGroup('My Group')
        pano = pandevice.panorama.Panorama('My Panorama')
        pano.get_device_version = mock.Mock(return_value=(7, 0, 0))

        dg.add(ao)
        pano.add(dg)

        ret_val = ao.xpath_short()

        self.assertEqual(expected, ret_val)

    def test_xpath_from_addressobject_with_pano_parent(self):
        expected = "/config/shared/address/entry[@name='shared ao']"

        ao = pandevice.objects.AddressObject('shared ao')
        pano = pandevice.panorama.Panorama('pano')
        pano.get_device_version = mock.Mock(return_value=(7, 0, 0))

        pano.add(ao)

        ret_val = ao.xpath()

        self.assertEqual(expected, ret_val)


class TestVariousSubinterfaceXpaths(unittest.TestCase):
    def test_l2_subinterface_with_firewall_parent(self):
        fw = pandevice.firewall.Firewall('192.168.1.1', 'admin', 'admin', vsys='vsys2')
        iface = pandevice.network.EthernetInterface('ethernet1/3', 'layer2')
        eth = pandevice.network.Layer2Subinterface('ethernet1/3.3', 3)
        iface.add(eth)
        fw.add(iface)

        expected = eth.xpath()

        fw.add(eth)

        self.assertEqual(expected, eth.xpath())

    def test_l2_subinterface_with_vsys_parent(self):
        fw = pandevice.firewall.Firewall('192.168.1.1', 'admin', 'admin')
        vsys = pandevice.device.Vsys('vsys2')
        iface = pandevice.network.EthernetInterface('ethernet1/3', 'layer2')
        eth = pandevice.network.Layer2Subinterface('ethernet1/3.3', 3)
        iface.add(eth)
        vsys.add(iface)
        fw.add(vsys)

        expected = eth.xpath()

        vsys.add(eth)

        self.assertEqual(expected, eth.xpath())

    def test_l3_subinterface_with_firewall_parent(self):
        fw = pandevice.firewall.Firewall('192.168.1.1', 'admin', 'admin', vsys='vsys3')
        iface = pandevice.network.EthernetInterface('ethernet1/4', 'layer3')
        eth = pandevice.network.Layer3Subinterface('ethernet1/4.4', 4)
        iface.add(eth)
        fw.add(iface)

        expected = eth.xpath()

        fw.add(eth)

        self.assertEqual(expected, eth.xpath())

    def test_l3_subinterface_with_vsys_parent(self):
        fw = pandevice.firewall.Firewall('192.168.1.1', 'admin', 'admin')
        vsys = pandevice.device.Vsys('vsys3')
        iface = pandevice.network.EthernetInterface('ethernet1/4', 'layer3')
        eth = pandevice.network.Layer2Subinterface('ethernet1/4.4', 4)
        iface.add(eth)
        vsys.add(iface)
        fw.add(vsys)

        expected = eth.xpath()

        vsys.add(eth)

        self.assertEqual(expected, eth.xpath())


if __name__=='__main__':
    unittest.main()
