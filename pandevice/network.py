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
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


def interface(name, *args, **kwargs):
    """Interface object factory

    The object type is determined by the name of the interface
    """
    if name.startswith("ethernet") and name.find(".") == -1:
        return EthernetInterface(name, *args, **kwargs)
    elif name.startswith("ae") and name.find(".") == -1:
        return AggregateInterface(name, *args, **kwargs)
    elif name.startswith("ethernet") or name.startswith("ae"):
        # Subinterface
        # Get mode from args
        args = list(args)
        if len(args) > 0:
            mode = args[0]
            del args[0]
        else:
            mode = kwargs.pop("mode", None)
        # Get tag from args
        if len(args) > 0:
            tag = args[0]
        else:
            tag = kwargs.get("tag", None)
        if tag is None:
            # Determine tag from name
            tag = name.split(".")[-1]
            kwargs["tag"] = tag
        if mode == "layer3":
            return Layer3Subinterface(name, *args, **kwargs)
        elif mode == "layer2":
            return Layer2Subinterface(name, *args, **kwargs)
        else:
            return AbstractSubinterface(name, *args, **kwargs)
    elif name.startswith("vlan"):
        return VlanInterface(name, *args, **kwargs)
    elif name.startswith("loopback"):
        return LoopbackInterface(name, *args, **kwargs)
    elif name.startswith("tunnel"):
        return TunnelInterface(name, *args, **kwargs)
    else:
        raise err.PanDeviceError("Can't identify interface type from name: %s" % name)

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
        self.interface = pandevice.string_or_list(interface)

    @classmethod
    def vars(cls):
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

    @classmethod
    def vars(cls):
        return (
            Var("interface"),
        )

    @property
    def mac(self):
        return self.name

    @mac.setter
    def mac(self, value):
        self.name = value


class Vlan(VsysImportMixin, PanObject):

    XPATH = "/network/vlan"
    SUFFIX = ENTRY
    ROOT = Root.DEVICE
    CHILDTYPES = (
        StaticMac,
    )
    XPATH_IMPORT = "/network/vlan"

    def __init__(self,
                 name,
                 interface=(),
                 virtual_interface=None
                 ):
        super(Vlan, self).__init__(name)
        self.interface = pandevice.string_or_list(interface)
        self.virtual_interface = virtual_interface

    @classmethod
    def vars(cls):
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

    @classmethod
    def vars(cls):
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
        self.state = None

    def up(self):
        if self.state == "up":
            return True
        else:
            return False

    def set_zone(self, zone_name, mode=None, refresh=False, update=False, running_config=False):
        return self._set_reference(zone_name, Zone, "interface", True, refresh, update, running_config, mode=mode)

    def set_virtual_router(self, virtual_router_name, refresh=False, update=False, running_config=False):
        return self._set_reference(virtual_router_name, VirtualRouter, "interface", True, refresh, update, running_config)

    def get_counters(self):
        """Pull the counters for an interface"""
        from pan.config import PanConfig
        pconf = self.pandevice().op('show counter interface "%s"' % self.name)
        pconf = PanConfig(pconf)
        response = pconf.python()
        logger.debug("response: " + str(response))
        counters = response['response']['result']
        if counters is not None:
            entry = {}
            # Check for entry in ifnet
            if 'entry' in counters.get('ifnet', {}):
                entry = counters['ifnet']['entry'][0]
            elif 'ifnet' in counters.get('ifnet', {}):
                if 'entry' in counters['ifnet'].get('ifnet', {}):
                    entry = counters['ifnet']['ifnet']['entry'][0]

            # Convert strings to integers, if they are integers
            entry.update((k, pandevice.convert_if_int(v)) for k, v in entry.iteritems())
            # If empty dictionary (no results) it usually means the interface is not
            # configured, so return None
            return entry if entry else None

    def refresh_state(self):
        response = self.pandevice().op('show interface "%s"' % self.name)
        state = response.findtext("result/hw/state")
        if state is None:
            state = "unconfigured"
        self.state = state
        return self.state


class Arp(PanObject):
    """Static ARP Mapping"""

    def __init__(self,
                 ip,
                 hw_address,
                 ):
        super(Arp, self).__init__(name=ip)
        self.hw_address = hw_address

    @classmethod
    def vars(cls):
        return (
            Var("hw-address"),
        )

    @property
    def ip(self):
        return self.name

    @ip.setter
    def ip(self, value):
        self.name = value


class Layer3Parameters(object):
    """L3 interfaces parameters mixin"""

    def __init__(self, *args, **kwargs):
        ip = kwargs.pop("ip", None)
        ipv6_enabled = kwargs.pop("ipv6_enabled", None)
        management_profile = kwargs.pop("management_profile", None)
        mtu = kwargs.pop("mtu", None)
        adjust_tcp_mss = kwargs.pop("adjust_tcp_mss", None)
        netflow_profile = kwargs.pop("netflow_profile", None)
        super(Layer3Parameters, self).__init__(*args, **kwargs)
        self.ip = pandevice.string_or_list(ip)
        self.ipv6_enabled = ipv6_enabled
        self.management_profile = management_profile
        self.mtu = mtu
        self.adjust_tcp_mss = adjust_tcp_mss
        self.netflow_profile = netflow_profile

    @classmethod
    def _vars(cls):
        return (
            Var("ip", vartype="entry"),
            Var("ipv6/enabled", "ipv6_enabled", vartype="bool"),
            Var("interface-management-profile", "management_profile"),
            Var("mtu", vartype="int"),
            Var("adjust-tcp-mss", vartype="bool"),
            Var("netflow-profile"),
        )

    @classmethod
    def vars(cls):
        return super(Layer3Parameters, cls).vars() + cls._vars()

    @classmethod
    def vars_with_mode(cls):
        l3vars = Layer3Parameters._vars()
        for var in l3vars:
            var.path = "{{mode}}/" + var.path
            var.condition = "mode:layer3"
        return super(Layer3Parameters, cls).vars_with_mode() + l3vars


class Layer2Parameters(object):
    """L2 interfaces parameters mixing"""

    def __init__(self, *args, **kwargs):
        lldp_enabled = kwargs.pop("lldp_enabled", None)
        lldp_profile = kwargs.pop("lldp_profile", None)
        netflow_profile = kwargs.pop("netflow_profile", None)
        super(Layer2Parameters, self).__init__(*args, **kwargs)
        self.lldp_enabled = lldp_enabled
        self.lldp_profile = lldp_profile
        self.netflow_profile = netflow_profile

    @classmethod
    def _vars(cls):
        return (
            Var("lldp/enable", "lldp_enabled", vartype="bool"),
            Var("lldp/profile", "lldp_profile"),
            Var("netflow-profile"),
        )

    @classmethod
    def vars(cls):
        return super(Layer2Parameters, cls).vars() + cls._vars()

    @classmethod
    def vars_with_mode(cls):
        l2vars = Layer2Parameters._vars()
        for var in l2vars:
            var.path = "{{mode}}/" + var.path
            var.condition = "mode:layer2"
        return super(Layer2Parameters, cls).vars_with_mode() + l2vars

    def set_vlan(self, vlan_name, refresh=False, update=False, running_config=False):
        super(Layer2Parameters, self)._set_reference(vlan_name, Vlan, "interface", True, refresh, update, running_config)


class VirtualWireInterface(Interface):
    """Abstract base class for vwire interfaces"""

    XPATH = "/virtual-wire"
    SUFFIX = None


class Subinterface(Interface):
    """Subinterface"""
    def __init__(self, name, tag):
        if type(self) == Subinterface:
            raise err.PanDeviceError("Do not instantiate class. Please use a subclass.")
        super(Subinterface, self).__init__(name)
        self.tag = tag

    @classmethod
    def vars(cls):
        return super(Subinterface, Subinterface).vars() + (
            Var("tag", vartype="int"),
        )

    def set_name(self):
        """Create a name appropriate for a subinterface if it isn't already"""
        if self.name.find(".") == -1:
            self.name = self.name + "." + str(self.tag)


class AbstractSubinterface(object):
    """When a subinterface is needed, but the layer is unknown

    Kinda like a placeholder or reference for a Layer2Subinterface or Layer3Subinterface.
    This class gets a parent which is the ethernet or aggregate interface, but it should
    not be added to the parent interface with add().
    """
    def __init__(self, name, tag, parent=None):
        self.name = name
        self.tag = tag
        self.parent = parent

    def set_name(self):
        """Create a name appropriate for a subinterface if it isn't already"""
        if self.name.find(".") == -1:
            self.name = self.name + "." + str(self.tag)

    def pandevice(self):
        return self.parent.pandevice()

    def set_zone(self, zone_name, mode=None, refresh=False, update=False, running_config=False):
        raise err.PanDeviceError("Unable to set zone on abstract subinterface because layer must be known to set zone")

    def set_virtual_router(self, virtual_router_name, refresh=False, update=False, running_config=False):
        interface = Layer3Subinterface(self.name, self.tag)
        interface.parent = self.parent
        return interface._set_reference(virtual_router_name, VirtualRouter, "interface", True, refresh=False, update=update, running_config=running_config)

    def get_layered_subinterface(self, mode, create=True):
        if self.parent is not None:
            if mode == "layer3":
                subintclass = Layer3Subinterface
            elif mode == "layer2":
                subintclass = Layer2Subinterface
            else:
                raise err.PanDeviceError("Unknown layer passed to subinterface factory: %s" % mode)
            layered_subinterface = self.parent.find(self.name, subintclass)
            # Verify tag is correct
            if layered_subinterface is not None:
                if layered_subinterface.tag != self.tag:
                    layered_subinterface.tag = self.tag
            else:
                if create:
                    layered_subinterface = self.parent.add(subintclass(self.name, tag=self.tag))
                else:
                    return
            return layered_subinterface

    def delete(self):
        """Override delete method to delete both Layer3 and Layer2 types by name"""
        layer3subinterface = self.parent.find_or_create(self.name, Layer3Subinterface, tag=self.tag)
        layer3subinterface.delete()
        layer2subinterface = self.parent.find_or_create(self.name, Layer2Subinterface, tag=self.tag)
        layer2subinterface.delete()


class Layer3Subinterface(Layer3Parameters, VsysImportMixin, Subinterface):

    XPATH = "/layer3/units"
    XPATH_IMPORT = "/network/interface"
    SUFFIX = ENTRY
    CHILDTYPES = (
        IPv6Address,
    )

    def __init__(self, name, tag, *args, **kwargs):
        super(Layer3Subinterface, self).__init__(name, tag, *args, **kwargs)
        self.mode = "layer3"

    def set_zone(self, zone_name, mode="layer3", refresh=False, update=False, running_config=False):
        return self._set_reference(zone_name, Zone, "interface", True, refresh, update, running_config, mode=mode)


class Layer2Subinterface(Layer2Parameters, VsysImportMixin, Subinterface):

    XPATH = "/layer2/units"
    XPATH_IMPORT = "/network/interface"
    SUFFIX = ENTRY

    def __init__(self, name, tag, *args, **kwargs):
        comment = kwargs.pop("comment", None)
        super(Layer2Subinterface, self).__init__(name, tag, *args, **kwargs)
        self.comment = comment
        self.mode = "layer2"

    @classmethod
    def vars(cls):
        return super(Layer2Subinterface, Layer2Subinterface).vars() + (
            Var("comment"),
        )

    def set_zone(self, zone_name, mode="layer2", refresh=False, update=False, running_config=False):
        return self._set_reference(zone_name, Zone, "interface", True, refresh, update, running_config, mode=mode)


class PhysicalInterface(Interface):
    """Absract base class for Ethernet and Aggregate Ethernet Interfaces"""
    def __init__(self,
                 name,
                 mode,
                 ):
        if type(self) == PhysicalInterface:
            raise err.PanDeviceError("Do not instantiate class. Please use a subclass.")
        super(PhysicalInterface, self).__init__(name=name)
        self.mode = mode

    def element(self):
        mode = None
        if self.children and self.mode is not None:
            mode = self.mode
            self.mode = None
        elif not self.children and self.mode is None:
            self.mode = "tap"
        element = super(PhysicalInterface, self).element()
        if self.children and mode is not None:
            self.mode = mode
        return element

    @classmethod
    def vars(cls):
        return (
            Var("(layer3|layer2|virtual-wire|tap|ha|decrypt-mirror|aggregate-group)", "mode"),
        ) + super(PhysicalInterface, PhysicalInterface).vars()

    @staticmethod
    def vars_with_mode():
        return PhysicalInterface.vars()

    def set_zone(self, zone_name, mode=None, refresh=False, update=False, running_config=False):
        if mode is None:
            mode = self.mode
        super(PhysicalInterface, self).set_zone(zone_name, mode, refresh, update, running_config)



class EthernetInterface(Layer3Parameters, Layer2Parameters, VsysImportMixin, PhysicalInterface):

    XPATH = "/network/interface/ethernet"
    XPATH_IMPORT = "/network/interface"
    CHILDTYPES = (
        Layer3Subinterface,
        Layer2Subinterface,
    )

    def __init__(self,
                 name,
                 mode="layer3",
                 ip=(),
                 link_speed=None,
                 link_duplex=None,
                 link_state=None,
                 aggregate_group=None,
                 *args,
                 **kwargs
                 ):
        super(EthernetInterface, self).__init__(name, mode, ip=ip, *args, **kwargs)
        self.link_speed = link_speed
        self.link_duplex = link_duplex
        self.link_state = link_state
        self.aggregate_group = aggregate_group

    @classmethod
    def vars(cls):
        return super(EthernetInterface, cls).vars_with_mode() + (
            Var("link-speed"),
            Var("link-duplex"),
            Var("link-state"),
            Var("aggregate-group", condition="mode:aggregate-group"),
        )


class AggregateInterface(Layer3Parameters, Layer2Parameters, VsysImportMixin, PhysicalInterface):

    XPATH = "/network/interface/aggregate-ethernet"
    XPATH_IMPORT = "/network/interface"
    CHILDTYPES = (
        Layer3Subinterface,
        Layer2Subinterface,
    )

    def __init__(self,
                 name,
                 mode="layer3",
                 *args,
                 **kwargs
                 ):
        super(AggregateInterface, self).__init__(name, mode, *args, **kwargs)


class VlanInterface(Layer3Parameters, VsysImportMixin, Interface):
    XPATH = "/network/interface/vlan/units"


class LoopbackInterface(Layer3Parameters, VsysImportMixin, Interface):
    XPATH = "/network/interface/loopback/units"


class TunnelInterface(Layer3Parameters, VsysImportMixin, Interface):
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

    @classmethod
    def vars(cls):
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
    XPATH_IMPORT = "/network/virtual-router"

    def __init__(self,
                 name="default",
                 interface=()):
        super(VirtualRouter, self).__init__(name=name)
        # Save interface as a list, even if a string was given
        self.interface = pandevice.string_or_list(interface)

    @classmethod
    def vars(cls):
        return (
            Var("interface", vartype="member"),
        )
