import pytest

from pandevice import device
from pandevice import firewall
from pandevice import network
from pandevice import objects
from pandevice import panorama


def _check(obj, vsys, with_pano, chk_import=False):
    if chk_import:
        func = 'xpath_import_base'
    else:
        func = 'xpath'
    fw = firewall.Firewall('127.0.0.1', 'admin', 'admin', serial='01234567890')
    fw.vsys = vsys
    fw.add(obj)

    if with_pano:
        pano = panorama.Panorama('127.0.0.1', 'admin2', 'admin2')
        pano.add(fw)

    expected = getattr(obj, func)()

    fw.remove(obj)
    fw.vsys = None
    vsys = device.Vsys(vsys or 'vsys1')
    fw.add(vsys)
    vsys.add(obj)

    result = getattr(obj, func)()

    assert expected == result


@pytest.mark.parametrize('vsys', [None, 'vsys1', 'vsys3'])
@pytest.mark.parametrize('with_pano', [False, True])
def test_xpath_for_vsys_root(vsys, with_pano):
    obj = network.Zone('myzone')
    _check(obj, vsys, with_pano)


@pytest.mark.parametrize('vsys', [None, 'vsys1', 'vsys3'])
@pytest.mark.parametrize('with_pano', [False, True])
def test_xpath_for_device_root(vsys, with_pano):
    obj = device.SystemSettings(hostname='example')
    _check(obj, vsys, with_pano)


@pytest.mark.parametrize('vsys', [None, 'vsys1', 'vsys3'])
@pytest.mark.parametrize('with_pano', [False, True])
def test_xpath_for_mgtconfig_root(vsys, with_pano):
    obj = device.Administrator('newadmin')
    _check(obj, vsys, with_pano)


@pytest.mark.parametrize('vsys', [None, 'vsys1', 'vsys3'])
@pytest.mark.parametrize('with_pano', [False, True])
@pytest.mark.parametrize('obj', [
    network.EthernetInterface('ethernet1/3', 'layer3'),
    network.Layer3Subinterface('ethernet1/4.42', 42),
    network.Layer2Subinterface('ethernet1/4.420', 420),
    network.VirtualRouter('someroute'),
    network.VirtualWire('tripwire'),
    network.Vlan('myvlan'),
])
def test_xpath_import(vsys, with_pano, obj):
    _check(obj, vsys, with_pano, True)


def test_vsys_xpath_unchanged():
    expected = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys3']"
    c = firewall.Firewall('127.0.0.1', 'admin', 'admin')
    c.vsys = 'vsys3'

    assert expected == c.xpath_vsys()

    c.vsys = None
    vsys = device.Vsys('vsys3')
    c.add(vsys)

    assert expected == vsys.xpath_vsys()

    zone = network.Zone('myzone')
    vsys.add(zone)

    assert expected == zone.xpath_vsys()


def test_device_group_xpath_unchanged():
    expected = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='somegroup']/address/entry[@name='intnet']"
    pano = panorama.Panorama('127.0.0.1')
    dg = panorama.DeviceGroup('somegroup')
    ao = objects.AddressObject('intnet', '192.168.0.0/16')
    pano.add(dg)
    dg.add(ao)

    assert expected == ao.xpath()
