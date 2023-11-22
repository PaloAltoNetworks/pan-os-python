import xml.etree.ElementTree as ET

import pytest

try:
    from unittest import mock
except ImportError:
    import mock

from panos.device import SnmpServerProfile
from panos.device import SnmpV2cServer
from panos.device import SnmpV3Server

from panos.device import EmailServerProfile
from panos.device import EmailServer

from panos.device import LdapServerProfile
from panos.device import LdapServer

from panos.device import SyslogServerProfile
from panos.device import SyslogServer

from panos.device import HttpServerProfile
from panos.device import HttpServer
from panos.device import HttpConfigHeader
from panos.device import HttpConfigParam
from panos.device import HttpSystemHeader
from panos.device import HttpSystemParam
from panos.device import HttpThreatHeader
from panos.device import HttpThreatParam
from panos.device import HttpTrafficHeader
from panos.device import HttpTrafficParam
from panos.device import HttpHipMatchHeader
from panos.device import HttpHipMatchParam
from panos.device import HttpUrlHeader
from panos.device import HttpUrlParam
from panos.device import HttpDataHeader
from panos.device import HttpDataParam
from panos.device import HttpWildfireHeader
from panos.device import HttpWildfireParam
from panos.device import HttpTunnelHeader
from panos.device import HttpTunnelParam
from panos.device import HttpUserIdHeader
from panos.device import HttpUserIdParam
from panos.device import HttpGtpHeader
from panos.device import HttpGtpParam
from panos.device import HttpAuthHeader
from panos.device import HttpAuthParam
from panos.device import HttpSctpHeader
from panos.device import HttpSctpParam
from panos.device import HttpIpTagHeader
from panos.device import HttpIpTagParam

from panos.firewall import Firewall
from panos.device import Vsys

from panos.panorama import Panorama
from panos.panorama import Template


OBJECTS = {
    SnmpServerProfile: [None, SnmpV2cServer, SnmpV3Server],
    EmailServerProfile: [
        None,
        EmailServer,
    ],
    LdapServerProfile: [
        None,
        LdapServer,
    ],
    SyslogServerProfile: [
        None,
        SyslogServer,
    ],
    HttpServerProfile: [
        None,
        HttpServer,
        HttpConfigHeader,
        HttpConfigParam,
        HttpSystemHeader,
        HttpSystemParam,
        HttpThreatHeader,
        HttpThreatParam,
        HttpTrafficHeader,
        HttpTrafficParam,
        HttpHipMatchHeader,
        HttpHipMatchParam,
        HttpUrlHeader,
        HttpUrlParam,
        HttpDataHeader,
        HttpDataParam,
        HttpWildfireHeader,
        HttpWildfireParam,
        HttpTunnelHeader,
        HttpTunnelParam,
        HttpUserIdHeader,
        HttpUserIdParam,
        HttpGtpHeader,
        HttpGtpParam,
        HttpAuthHeader,
        HttpAuthParam,
        HttpSctpHeader,
        HttpSctpParam,
        HttpIpTagHeader,
        HttpIpTagParam,
    ],
}

"""
@pytest.fixture(
    scope="function",
    params=[x for x in DEVICES],
    ids=[x.__class__.__name__ for x in DEVICES],
)
def pdev(request):
    request.param.removeall()
    return request.param
"""


@pytest.fixture(
    scope="function",
    params=[(x, y) for x, v in OBJECTS.items() for y in v],
    ids=[
        "{0}{1}".format(x.__class__.__name__, y.__class__.__name__ if y else "None")
        for x, v in OBJECTS.items()
        for y in v
    ],
)
def combination(request):
    return request.param


def test_firewall_shared_xpath(combination):
    expected = [
        "/config/shared",
    ]
    fw = Firewall("127.0.0.1", "admin", "admin", "secret")
    fw._version_info = (9999, 0, 0)
    fw.vsys = "shared"
    parent_cls, child_cls = combination

    o = parent_cls("one")
    expected.append(o.xpath())
    if child_cls is not None:
        o2 = child_cls("two")
        expected.append(o2.xpath())
        o.add(o2)
        o = o2
        fw.add(o.parent)
    else:
        fw.add(o)

    assert "".join(expected) == o.xpath()


def test_firewall_vsys_xpath(combination):
    expected = [
        "/config/devices/entry[@name='localhost.localdomain']",
        "/vsys/entry[@name='vsys1']",
    ]
    fw = Firewall("127.0.0.1", "admin", "admin", "secret")
    fw._version_info = (9999, 0, 0)
    parent_cls, child_cls = combination

    o = parent_cls("one")
    expected.append(o.xpath())
    if child_cls is not None:
        o2 = child_cls("two")
        expected.append(o2.xpath())
        o.add(o2)
        o = o2
        fw.add(o.parent)
    else:
        fw.add(o)

    assert "".join(expected) == o.xpath()


def test_firewall_vsys_object_xpath(combination):
    expected = [
        "/config/devices/entry[@name='localhost.localdomain']",
        "/vsys/entry[@name='vsys2']",
    ]
    fw = Firewall("127.0.0.1", "admin", "admin", "secret")
    fw._version_info = (9999, 0, 0)
    vsys = Vsys("vsys2")
    fw.add(vsys)
    parent_cls, child_cls = combination

    o = parent_cls("one")
    expected.append(o.xpath())
    if child_cls is not None:
        o2 = child_cls("two")
        expected.append(o2.xpath())
        o.add(o2)
        o = o2
        vsys.add(o.parent)
    else:
        vsys.add(o)

    assert "".join(expected) == o.xpath()


def test_panorama_template_object_xpath(combination):
    expected = [
        "/config/devices/entry[@name='localhost.localdomain']",
    ]
    pano = Panorama("127.0.0.1", "admin", "admin", "secret")
    pano._version_info = (9999, 0, 0)
    tmpl = Template("myTemplate")
    expected.append(tmpl.xpath())
    pano.add(tmpl)
    expected.append("/config/shared")
    vsys = Vsys("shared")
    tmpl.add(vsys)
    parent_cls, child_cls = combination

    o = parent_cls("one")
    expected.append(o.xpath())
    if child_cls is not None:
        o2 = child_cls("two")
        expected.append(o2.xpath())
        o.add(o2)
        o = o2
        vsys.add(o.parent)
    else:
        vsys.add(o)

    assert "".join(expected) == o.xpath()


def test_panorama_local_object_xpath(combination):
    expected = [
        "/config/panorama",
    ]
    pano = Panorama("127.0.0.1", "admin", "admin", "secret")
    pano._version_info = (9999, 0, 0)
    parent_cls, child_cls = combination

    o = parent_cls("one")
    expected.append(o.xpath())
    if child_cls is not None:
        o2 = child_cls("two")
        expected.append(o2.xpath())
        o.add(o2)
        o = o2
        pano.add(o.parent)
    else:
        pano.add(o)

    assert "".join(expected) == o.xpath()
