#!/usr/bin/env python

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

# Author: Brian Torres-Gil <btorres-gil@paloaltonetworks.com>

# import modules
import re
import logging
import xml.etree.ElementTree as ET
import pandevice
from base import PanObject, Root, MEMBER, ENTRY, VsysImportMixin
from base import VarPath as Var

# import other parts of this pandevice package
import errors as err

# set logging to nullhandler to prevent exceptions if logging not enabled
try:
    # working for python 2.7 and higher
    logging.getLogger(__name__).addHandler(logging.NullHandler())
except AttributeError as e:
    # python 2.6 doesn't have a null handler, so create it
    class NullHandler(logging.Handler):
        def emit(self, record):
            pass
    logging.NullHandler = NullHandler
    logging.getLogger(__name__).addHandler(logging.NullHandler())


class Zone(PanObject):

    XPATH = "/zone"
    ROOT = Root.VSYS
    SUFFIX = ENTRY

    def __init__(self,
                 name,
                 mode="layer3",
                 interface=(),
                 ):
        super(Zone, self).__init__(name=name)
        self.mode = mode
        self.interface = interface

    @staticmethod
    def vars():
        return (
            Var("network/(tap|virtual-wire|layer2|layer3|external)", "mode"),
            Var("network/{{mode}}", "interface", vartype="member"),
        )


class StaticMac(PanObject):

    XPATH = "/mac"
    SUFFIX = ENTRY

    def __init__(self,
                 mac,
                 interface,
                 ):
        super(StaticMac, self).__init__(name=mac)
        self.interface = interface

    @staticmethod
    def vars():
        return (
            Var("interface"),
        )

    @property
    def mac(self):
        return self.name

    @mac.setter
    def mac(self, value):
        self.name = value


class Vlan(PanObject):

    XPATH = "/network/vlan"
    SUFFIX = ENTRY
    ROOT = Root.DEVICE
    CHILDTYPES = (
        StaticMac,
    )

    def __init__(self,
                 name,
                 interface=(),
                 virtual_interface=None
                 ):
        super(Vlan, self).__init__(name)
        self.interface = interface
        self.virtual_interface = virtual_interface

    @staticmethod
    def vars():
        return (
            Var("interface", vartype="member"),
            Var("virtual-interface/interface", "virtual_interface"),
        )


class IPv6Address(PanObject):
    """IPv6 Address for use on network interfaces"""

    XPATH = "/ipv6/address"
    SUFFIX = ENTRY
    NAME = "address"

    def __init__(self,
                 address,
                 enable_on_interface=None,
                 prefix=None,
                 anycast=None,
                 advertise_enabled=None,
                 valid_lifetime=None,
                 preferred_lifetime=None,
                 onlink_flag=None,
                 auto_config_flag=None,
                 ):
        super(IPv6Address, self).__init__(name=address)
        self.enable_on_interface = enable_on_interface
        self.prefix = prefix
        self.anycast = anycast
        self.advertise_enabled = advertise_enabled
        self.valid_lifetime = valid_lifetime
        self.preferred_lifetime = preferred_lifetime
        self.onlink_flag = onlink_flag
        self.auto_config_flag = auto_config_flag

    @staticmethod
    def vars():
        return (
            Var("enable-on-interface", vartype="bool"),
            Var("prefix", vartype="exist"),
            Var("anycast", vartype="exist"),
            Var("advertise/enable", "advertise_enabled", vartype="bool"),
            Var("advertise/valid-lifetime", vartype="int"),
            Var("advertise/preferred-lifetime", vartype="int"),
            Var("advertise/onlink-flag", vartype="bool"),
            Var("advertise/auto-config-flag", vartype="bool"),
        )

    @property
    def address(self):
        return self.name

    @address.setter
    def address(self, value):
        self.name = value


class Interface(PanObject):
    """Abstract base class for all interfaces"""

    SUFFIX = ENTRY
    ROOT = Root.DEVICE

    def __init__(self,
                 name,
                 ):
        if type(self) == Interface:
            raise err.PanDeviceError("Do not instantiate class. Please use a subclass.")
        super(Interface, self).__init__(name=name)


class Arp(PanObject):
    """Static ARP Mapping"""

    def __init__(self,
                 ip,
                 hw_address,
                 ):
        super(Arp, self).__init__(name=ip)
        self.hw_address = hw_address

    @staticmethod
    def vars():
        return (
            Var("hw-address"),
        )

    @property
    def ip(self):
        return self.name

    @ip.setter
    def ip(self, value):
        self.name = value


class Layer3Interface(Interface):
    """L3 interfaces parameters

    Can be added as a child of an EthernetInterface or other kind of concrete interface
    """

    XPATH = "/layer3"
    SUFFIX = None
    CHILDTYPES = (
        IPv6Address,
    )

    def __init__(self,
                 ip=(),
                 ipv6_enabled=None,
                 management_profile=None,
                 mtu=None,
                 adjust_tcp_mss=None,
                 netflow_profile=None,
                 ):
        super(Layer3Interface, self).__init__(name=None)
        self.ip = pandevice.string_or_list(ip)
        self.ipv6_enabled = ipv6_enabled
        self.management_profile = management_profile
        self.mtu = mtu
        self.adjust_tcp_mss = adjust_tcp_mss
        self.netflow_profile = netflow_profile

    @staticmethod
    def vars():
        return super(Layer3Interface, Layer3Interface).vars() + (
            Var("ip", vartype="entry"),
            Var("ipv6/enabled", "ipv6_enabled", vartype="bool"),
            Var("interface-management-profile", "management_profile"),
            Var("mtu", vartype="int"),
            Var("adjust-tcp-mss", vartype="bool"),
            Var("netflow-profile"),
        )


class Layer2Interface(Interface):
    """L3 interfaces parameters

    Can be added as a child of an EthernetInterface or other kind of concrete interface
    """

    XPATH = "/layer2"
    SUFFIX = None

    def __init__(self,
                 lldp_enabled=None,
                 lldp_profile=None,
                 netflow_profile=None,
                 ):
        super(Layer2Interface, self).__init__(name=None)
        self.lldp_enable = lldp_enabled
        self.lldp_profile = lldp_profile
        self.netflow_profile = netflow_profile

    @staticmethod
    def vars():
        return super(Layer2Interface, Layer2Interface).vars() + (
            Var("lldp/enable", "lldp_enabled", vartype="bool"),
            Var("lldp/profile", "lldp_profile"),
            Var("netflow-profile"),
        )


class VirtualWireInterface(Interface):
    """Abstract base class for vwire interfaces"""

    XPATH = "/virtual-wire"
    SUFFIX = None


class Layer3Subinterface(VsysImportMixin, Layer3Interface):

    XPATH = "/layer3/units"
    XPATH_IMPORT = "/network/interface"
    SUFFIX = ENTRY
    CHILDTYPES = (
        IPv6Address,
    )

    def __init__(self,
                 name,
                 ip=None,
                 ipv6_enabled=None,
                 tag=None,
                 management_profile=None,
                 mtu=None,
                 adjust_tcp_mss=None,
                 netflow_profile=None,
                 ):
        super(Layer3Subinterface, self).__init__(ip,
                                                 ipv6_enabled,
                                                 management_profile,
                                                 mtu,
                                                 adjust_tcp_mss,
                                                 netflow_profile,
                                                 name=name,
                                                 )
        self.name = name
        self.tag = tag

    @staticmethod
    def vars():
        return super(Layer3Subinterface, Layer3Subinterface).vars() + (
            Var("tag", vartype="int"),
        )


class Layer2Subinterface(VsysImportMixin, Interface):

    XPATH = "/layer2/units"
    XPATH_IMPORT = "/network/interface"
    SUFFIX = ENTRY

    def __init__(self,
                 name,
                 tag,
                 comment=None,
                 netflow_profile=None,
                 ):
        super(Layer2Subinterface, self).__init__(name=name)
        self.name = name
        self.tag = tag
        self.comment = comment
        self.netflow_profile = netflow_profile

    @staticmethod
    def vars():
        return (
            Var("tag", vartype="int"),
            Var("comment"),
            Var("netflow-profile"),
        )


class EthernetInterface(VsysImportMixin, Interface):

    XPATH = "/network/interface/ethernet"
    XPATH_IMPORT = "/network/interface"
    CHILDTYPES = (
        Layer3Interface,
        Layer3Subinterface,
        Layer2Interface,
        Layer2Subinterface,
    )

    def __init__(self,
                 name,
                 link_speed=None,
                 link_duplex=None,
                 link_state=None,
                 aggregate_group=None,
                 ):
        super(EthernetInterface, self).__init__(name)
        self.link_speed = link_speed
        self.link_duplex = link_duplex
        self.link_state = link_state
        self.aggregate_group = aggregate_group

    @staticmethod
    def vars():
        return super(EthernetInterface, EthernetInterface).vars() + (
            Var("link-speed"),
            Var("link-duplex"),
            Var("link-state"),
            Var("aggregate-group"),
        )


class AggregateInterface(VsysImportMixin, Interface):

    XPATH = "/network/interface/aggregate-ethernet"
    XPATH_IMPORT = "/network/interface"
    CHILDTYPES = (
        Layer3Interface,
        Layer3Subinterface,
        Layer2Interface,
        Layer2Subinterface,
    )


class HAInterfaceMixin(object):

    XPATH_IMPORT = None
    CHILDTYPES = ()

    def __init__(self, *args, **kwargs):
        super(HAInterfaceMixin, self).__init__(*args, **kwargs)

    def vars(self):
        return super(HAInterfaceMixin, self).vars() + (
            Var("ha", vartype="none"),
        )


class HAEthernetInterface(HAInterfaceMixin, EthernetInterface):
    pass


class HAAggregateInterface(HAInterfaceMixin, AggregateInterface):
    pass


class VlanInterface(VsysImportMixin, Layer3Interface):
    XPATH = "/network/interface/vlan/units"


class LoopbackInterface(VsysImportMixin, Layer3Interface):
    XPATH = "/network/interface/loopback/units"


class TunnelInterface(VsysImportMixin, Layer3Interface):
    XPATH = "/network/interface/tunnel/units"


class StaticRoute(PanObject):

    XPATH = "/routing-table/ip/static-route"
    SUFFIX = ENTRY

    def __init__(self,
                 name,
                 destination,
                 nexthop=None,
                 nexthop_type="ip-address",
                 interface=None,
                 admin_dist=None,
                 metric=10,
                 ):
        super(StaticRoute, self).__init__(name=name)
        self.destination = destination
        self.nexthop = nexthop
        self.nexthop_type = nexthop_type
        self.interface = interface
        self.admin_dist = admin_dist
        self.metric = metric

    @staticmethod
    def vars():
        return (
            Var("destination"),
            Var("nexthop/(ip-address|discard)", "nexthop_type"),
            Var("nexthop/ip-address", "nexthop"),
            Var("interface"),
            Var("admin-dist"),
            Var("metric", vartype="int", default=10),
        )


class StaticRouteV6(StaticRoute):
    XPATH = "/routing-table/ipv6/static-route"


class VirtualRouter(VsysImportMixin, PanObject):

    ROOT = Root.DEVICE
    XPATH = "/network/virtual-router"
    SUFFIX = ENTRY
    CHILDTYPES = (
        StaticRoute,
        StaticRouteV6,
    )

    def __init__(self,
                 name="default",
                 interface=()):
        super(VirtualRouter, self).__init__(name=name)
        # Save interface as a list, even if a string was given
        self.interface = pandevice.string_or_list(interface)

    @staticmethod
    def vars():
        return (
            Var("interface", vartype="member"),
        )
