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


"""Network module contains objects that exist in the 'Network' tab in the firewall GUI"""

import logging
import re
import xml.etree.ElementTree as ET

import panos
import panos.errors as err
from panos import device, getlogger, string_or_list
from panos.base import ENTRY, MEMBER, PanObject, Root
from panos.base import VarPath as Var
from panos.base import VersionedPanObject, VersionedParamPath, VsysOperations

logger = getlogger(__name__)


def interface(name, *args, **kwargs):
    """Interface object factory

    Creates an interface object of type determined by the name of the interface.

    Args:
        name (str): Name of the interface to create (eg. ethernet1/1.5)
        mode (str): Mode of the interface.
            Possible values: layer3, layer2, virtual-wire, tap, ha, aggregate-group.
            Default: None

    Keyword Args:
        tag (int): Tag for the interface, aka vlan id

    Returns:
        Interface: An instantiated subclass of :class:`panos.network.Interface`

    """
    name = str(name)
    if name.startswith("ethernet") and "." not in name:
        return EthernetInterface(name, *args, **kwargs)
    elif name.startswith("ae") and "." not in name:
        return AggregateInterface(name, *args, **kwargs)
    elif name.startswith("ethernet") or name.startswith("ae"):
        # Subinterface
        # Get mode from args
        args = string_or_list(args)
        if len(args) > 0:
            mode = args[0]
            del args[0]
        else:
            mode = kwargs.pop("mode", None)
        # Get tag from kwargs
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


class Zone(VersionedPanObject):
    """Security zone

    Args:
        name (str): Name of the zone
        mode (str): The mode of the security zone. Must match the mode of the interface.
            Possible values: tap, virtual-wire, layer2, layer3, external
        interface (list): List of interface names or instantiated subclasses
            of :class:`panos.network.Interface`.
        zone_profile (str): Zone protection profile
        log_setting (str): Log forwarding setting
        enable_user_identification (bool): If user identification is enabled
        include_acl (list/str): User identification ACL include list
        exclude_acl (list/str): User identification ACL exclude list
        enable_packet_buffer_protection (bool): (PAN-OS 8.0+) Enable packet buffer protection
        enable_device_identification (bool): (PAN-OS 10.0+) Enable device identification
        device_include_acl (list): (PAN-OS 10.0+) Device include ACLs list
        device_exclude_acl (list): (PAN-OS 10.0+) Device exclude ACLs list

    """

    ROOT = Root.VSYS
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/zone")
        self._xpaths.add_profile(
            value="{0}/zone".format(self._TEMPLATE_VSYS_XPATH),
            parents=("Template", "TemplateStack"),
        )

        # params
        params = []

        params.append(
            VersionedParamPath(
                "mode",
                default="layer3",
                path="network/{mode}",
                values=["tap", "virtual-wire", "layer2", "layer3", "external"],
            )
        )
        params.append(
            VersionedParamPath("interface", path="network/{mode}", vartype="member")
        )
        params.append(
            VersionedParamPath("zone_profile", path="network/zone-protection-profile")
        )
        params.append(VersionedParamPath("log_setting", path="network/log-setting"))
        params.append(
            VersionedParamPath(
                "enable_user_identification",
                vartype="yesno",
                path="enable-user-identification",
            )
        )
        params.append(
            VersionedParamPath(
                "include_acl", vartype="member", path="user-acl/include-list"
            )
        )
        params.append(
            VersionedParamPath(
                "exclude_acl", vartype="member", path="user-acl/exclude-list"
            )
        )
        params.append(
            VersionedParamPath(
                "enable_packet_buffer_protection",
                exclude=True,
            )
        )
        params[-1].add_profile(
            "8.0.0",
            path="network/enable-packet-buffer-protection",
            vartype="yesno",
        )
        params.append(
            VersionedParamPath(
                "enable_device_identification",
                exclude=True,
            )
        )
        params[-1].add_profile(
            "10.0.0",
            path="enable-device-identification",
            vartype="yesno",
        )
        params.append(
            VersionedParamPath(
                "device_include_acl",
                exclude=True,
            )
        )
        params[-1].add_profile(
            "10.0.0",
            path="device-acl/include-list",
            vartype="member",
        )
        params.append(
            VersionedParamPath(
                "device_exclude_acl",
                exclude=True,
            )
        )
        params[-1].add_profile(
            "10.0.0",
            path="device-acl/exclude-acl",
            vartype="member",
        )

        self._params = tuple(params)


class StaticMac(VersionedPanObject):
    """Static MAC address for a Vlan

    Can be added to a :class:`panos.network.Vlan` object

    Args:
        mac (str): The MAC address
        interface (str): Name of an interface

    """

    SUFFIX = ENTRY
    NAME = "mac"

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/mac")

        # params
        params = []

        params.append(VersionedParamPath("interface", path="interface"))

        self._params = tuple(params)


class Vlan(VsysOperations):
    """Vlan

    Args:
        name (str): The name
        interface (list): List of interface names
        virtual_interface (VlanInterface): The layer3 vlan interface for this vlan

    """

    SUFFIX = ENTRY
    ROOT = Root.DEVICE
    CHILDTYPES = ("network.StaticMac",)

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/network/vlan")
        self._xpaths.add_profile(
            value="{0}/network/vlan".format(self._TEMPLATE_DEVICE_XPATH),
            parents=("Template", "TemplateStack"),
        )

        # xpath_imports
        self._xpath_imports.add_profile(value="/network/vlan")

        # params
        params = []

        params.append(
            VersionedParamPath("interface", vartype="member", path="interface")
        )
        params.append(
            VersionedParamPath("virtual_interface", path="virtual-interface/interface")
        )

        self._params = tuple(params)


class IPv6Address(VersionedPanObject):
    """IPv6 Address

    Can be added to any :class:`panos.network.Interface` subclass
    that supports IPv6.

    Args:
        address (str): The IPv6 address
        enable_on_interface (bool): Enabled IPv6 on the interface this
            object was added to
        prefix (bool): Use interface ID as host portion
        anycast (bool): Enable anycast
        advertise_enabled (bool): Enabled router advertisements
        valid_lifetime (int): Valid lifetime
        preferred_lifetime (int): Preferred lifetime
        onlink_flag (bool):
        auto_config_flag (bool):

    """

    SUFFIX = ENTRY
    NAME = "address"

    def _setup(self):
        # xpaths
        # Non-mode interface xpaths
        self._xpaths.add_profile(value="/ipv6/address")
        # Mode interface xpaths (mode: layer3)
        self._xpaths.add_profile(
            value="/layer3/ipv6/address",
            parents=("EthernetInterface", "AggregateInterface"),
        )

        # params
        params = []

        params.append(
            VersionedParamPath(
                "enable_on_interface", vartype="yesno", path="enable-on-interface"
            )
        )
        params.append(VersionedParamPath("prefix", vartype="exist", path="prefix"))
        params.append(VersionedParamPath("anycast", vartype="exist", path="anycast"))
        params.append(
            VersionedParamPath(
                "advertise_enabled", vartype="yesno", path="advertise/enable"
            )
        )
        params.append(
            VersionedParamPath(
                "valid_lifetime", vartype="int", path="advertise/valid-lifetime"
            )
        )
        params.append(
            VersionedParamPath(
                "preferred_lifetime", vartype="int", path="advertise/preferred-lifetime"
            )
        )
        params.append(
            VersionedParamPath(
                "onlink_flag", vartype="yesno", path="advertise/onlink-flag"
            )
        )
        params.append(
            VersionedParamPath(
                "auto_config_flag", vartype="yesno", path="advertise/auto-config-flag"
            )
        )

        self._params = tuple(params)


class Interface(VsysOperations):
    """Base class for all interfaces

    Do not instantiate this object. Use a subclass.
    Methods in this class are available to all interface subclasses.

    Args:
        name (str): Name of the interface
        state (str): Link state, 'up' or 'down'

    """

    SUFFIX = ENTRY
    ROOT = Root.DEVICE
    DEFAULT_MODE = None
    ALLOW_SET_VLAN = False
    ALWAYS_IMPORT = True

    def up(self):
        """Link state of interface

        Returns:
            bool: True if state is 'up', False if state is 'down',
                'unconfigured' or other

        """
        return self.state == "up"

    def set_zone(
        self,
        zone_name,
        mode=None,
        refresh=False,
        update=False,
        running_config=False,
        return_type="object",
    ):
        """Set the zone for this interface

        Creates a reference to this interface in the specified zone and removes
        references to this interface from all other zones. The zone will be
        created if it doesn't exist.

        Args:
            zone_name (str): The name of the Zone or a
                :class:`panos.network.Zone` instance
            mode (str): The mode of the zone. See
                :class:`panos.network.Zone` for possible values
            refresh (bool): Refresh the relevant current state of the device
                before taking action (Default: False)
            update (bool): Apply the changes to the device (Default: False)
            running_config: If refresh is True, refresh from the running
                configuration (Default: False)
            return_type (str): Specify what this function returns, can be
                either 'object' (the default) or 'bool'.  If this is 'object',
                then the return value is the Zone in question.  If
                this is 'bool', then the return value is a boolean that tells
                you about if the live device needs updates (update=False) or
                was updated (update=True).

        Returns:
            Zone: The zone for this interface after the operation completes

        """
        if mode is None:
            mode = self.DEFAULT_MODE
        elif self.vsys == "shared":
            return False

        return self._set_reference(
            zone_name,
            Zone,
            "interface",
            "list",
            True,
            refresh,
            update,
            running_config,
            return_type,
            False,
            mode=mode,
        )

    def set_virtual_router(
        self,
        virtual_router_name,
        refresh=False,
        update=False,
        running_config=False,
        return_type="object",
    ):
        """Set the virtual router for this interface

        Creates a reference to this interface in the specified virtual router
        and removes references to this interface from all other virtual
        routers. The virtual router will be created if it doesn't exist.

        Args:
            virtual_router_name (str): The name of the VirtualRouter or
                a :class:`panos.network.VirtualRouter` instance
            refresh (bool): Refresh the relevant current state of the device
                before taking action (Default: False)
            update (bool): Apply the changes to the device (Default: False)
            running_config: If refresh is True, refresh from the running
                configuration (Default: False)
            return_type (str): Specify what this function returns, can be
                either 'object' (the default) or 'bool'.  If this is 'object',
                then the return value is the VirtualRouter in question.  If
                this is 'bool', then the return value is a boolean that tells
                you about if the live device needs updates (update=False) or
                was updated (update=True).

        Returns:
            Zone: The zone for this interface after the operation completes

        """
        # Don't add HA, layer 2 or aggregate-group interfaces to virtual router.
        if getattr(self, "mode", "") in ("ha", "aggregate-group", "layer2"):
            return False

        return self._set_reference(
            virtual_router_name,
            VirtualRouter,
            "interface",
            "list",
            True,
            refresh,
            update,
            running_config,
            return_type,
            False,
        )

    def set_vlan(
        self,
        vlan_name,
        refresh=False,
        update=False,
        running_config=False,
        return_type="object",
    ):
        """Set the vlan for this interface

        Creates a reference to this interface in the specified vlan and removes
        references to this interface from all other interfaces.  The vlan will
        be created if it doesn't exist.

        Args:
            vlan_name (str): The name of the vlan or
                a :class:`panos.network.Vlan` instance
            refresh (bool): Refresh the relevant current state of the device
                before taking action (Default: False)
            update (bool): Apply the changes to the device (Default: False)
            running_config: If refresh is True, refresh from the running
                configuration (Default: False)
            return_type (str): Specify what this function returns, can be
                either 'object' (the default) or 'bool'.  If this is 'object',
                then the return value is the Vlan in question.  If
                this is 'bool', then the return value is a boolean that tells
                you about if the live device needs updates (update=False) or
                was updated (update=True).

        Raises:
            AttributeError: if this class is not allowed to use this function.

        Returns:
            Vlan: The VLAN for this interface after the operation completes

        """
        if not self.ALLOW_SET_VLAN:
            msg = 'Class "{0}" cannot invoke this function'
            raise AttributeError(msg.format(self.__class__))

        return self._set_reference(
            vlan_name,
            Vlan,
            "interface",
            "list",
            True,
            refresh,
            update,
            running_config,
            return_type,
            False,
        )

    def get_counters(self):
        """Pull the counters for an interface

        Returns:
            dict: counter name as key, counter as value, None if interface is
                not configured

        """
        from pan.config import PanConfig

        device = self.nearest_pandevice()
        cmd = 'show counter interface "{0}"'.format(self.name)
        pconf = device.op(cmd)
        pconf = PanConfig(pconf)
        response = pconf.python()
        logger.debug("response: " + str(response))
        counters = response["response"]["result"]
        if counters is not None:
            entry = {}
            # Check for entry in ifnet
            if "entry" in counters.get("ifnet", {}):
                entry = counters["ifnet"]["entry"][0]
            elif "ifnet" in counters.get("ifnet", {}):
                if "entry" in counters["ifnet"].get("ifnet", {}):
                    entry = counters["ifnet"]["ifnet"]["entry"][0]

            # Convert strings to integers, if they are integers
            entry.update((k, panos.convert_if_int(v)) for k, v in entry.items())

            # If empty dictionary (no results) it usually means the interface is not
            # configured, so return None
            return entry if entry else None

    def refresh_state(self):
        """Pull the state of the interface from the firewall

        The attribute 'state' is populated with the current state from the
        firewall.

        Returns:
            str: The current state from the firewall

        """
        device = self.nearest_pandevice()
        cmd = 'show interface "{0}"'.format(self.name)
        response = device.op(cmd)
        state = response.findtext("result/hw/state")
        if state is None:
            state = "unconfigured"
        self.state = state

        return self.state

    def full_delete(
        self, refresh=False, delete_referencing_objects=False, include_vsys=False
    ):
        """Delete the interface and all references to the interface

        Often when deleting an interface there is an API error because
        there are still references to the interface from zones, virtual-router,
        vsys, etc. This method deletes all references to the interface before
        deleting the interface itself.

        Args:
            refresh (bool): Refresh the current state of the device before
                taking action
            delete_referencing_objects (bool): Delete the entire object that
                references this interface

        """
        self.set_zone(None, refresh=refresh, update=True)
        if self.ALLOW_SET_VLAN:
            self.set_vlan(None, refresh=refresh, update=True)
        self.set_virtual_router(None, refresh=refresh, update=True)

        # Remove any references to the interface across all known
        # children of this pan_device. This does not use 'refresh'.
        # Only pre-refreshed objects are scanned for references.
        for obj in self.nearest_pandevice().findall(PanObject, recursive=True):
            if isinstance(obj, device.Vsys):
                if not include_vsys:
                    continue
            try:
                if str(self) == obj.interface or self == obj.interface:
                    if delete_referencing_objects:
                        obj.delete()
                    else:
                        obj.interface = None
                        obj.update("interface")
                elif "__iter__" in dir(obj.interface) and str(self) in obj.interface:
                    if delete_referencing_objects:
                        obj.delete()
                    else:
                        obj.interface.remove(str(self))
                        obj.update("interface")
                elif "__iter__" in dir(obj.interface) and self in obj.interface:
                    if delete_referencing_objects:
                        obj.delete()
                    else:
                        obj.interface.remove(self)
                        obj.update("interface")
            except AttributeError:
                pass
        self.delete()


class Arp(VersionedPanObject):
    """Static ARP Mapping

    Can be added to various interfaces.

    Args:
        ip (str): The IP address
        hw_address (str): The MAC address for the static ARP
        interface (str): The interface (when attached to VlanInterface only)

    """

    SUFFIX = ENTRY
    NAME = "ip"

    def _setup(self):
        # xpaths
        # Interface xpaths
        self._xpaths.add_profile(value="/layer3/arp")
        # Subinterface xpaths
        self._xpaths.add_profile(value="/arp", parents=("Layer3Subinterface",))

        # params
        params = []

        params.append(VersionedParamPath("hw_address", path="hw-address"))
        params.append(VersionedParamPath("interface", path="interface"))

        self._params = tuple(params)


class VirtualWire(VsysOperations):
    """Virtual wires (vwire)

    Args:
        name (str): The vwire name
        tag (int): Tag for the interface, aka vlan id
        interface1 (str): The first interface to use
        interface2 (str): The second interface to use
        multicast (bool): Enable multicast firewalling or not
        pass_through (bool): Enable link state pass through or not

    """

    ROOT = Root.DEVICE
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/network/virtual-wire")
        self._xpaths.add_profile(
            value="{0}/network/virtual-wire".format(self._TEMPLATE_DEVICE_XPATH),
            parents=("Template", "TemplateStack"),
        )

        # xpath imports
        self._xpath_imports.add_profile(value="/network/virtual-wire")

        # params
        params = []

        params.append(VersionedParamPath("tag", path="tag-allowed"))
        params.append(VersionedParamPath("interface1", path="interface1"))
        params.append(VersionedParamPath("interface2", path="interface2"))
        params.append(
            VersionedParamPath(
                "multicast",
                path="multicast-firewalling/enable",
                default=False,
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "pass_through",
                path="link-state-pass-through/enable",
                default=True,
                vartype="yesno",
            )
        )

        self._params = tuple(params)


class Subinterface(Interface):
    """Subinterface class

    Do not instantiate this object. Use a subclass.

    """

    _BASE_INTERFACE_NAME = "entry BASE_INTERFACE_NAME"
    _BASE_INTERFACE_TYPE = "var BASE_INTERFACE_TYPE"

    def set_name(self):
        """Create a name appropriate for a subinterface if it isn't already"""
        if "." not in self.name:
            self.name = "{0}.{1}".format(self.name, self.tag)

    @property
    def XPATH(self):
        path = super(Subinterface, self).XPATH

        if self._BASE_INTERFACE_TYPE in path:
            if self.uid.startswith("ae"):
                rep = "aggregate-ethernet"
            else:
                rep = "ethernet"
            path = path.replace(self._BASE_INTERFACE_TYPE, rep)

        if self._BASE_INTERFACE_NAME in path:
            base = self.uid.split(".")[0]
            path = path.replace(
                self._BASE_INTERFACE_NAME, "entry[@name='{0}']".format(base)
            )

        return path


class AbstractSubinterface(object):
    """When a subinterface is needed, but the layer is unknown

    Kindof like a placeholder or reference for a Layer2Subinterface or Layer3Subinterface.
    This class gets a parent which is the ethernet or aggregate interface, but it should
    not be added to the parent interface with add().

    Args:
        name (str): Name of the interface (eg. ethernet1/1.5)
        tag (int): Tag for the interface, aka vlan id
        parent (Interface): The base interface for this subinterface

    """

    def __init__(self, name, tag, parent=None):
        self.name = name
        self.tag = tag
        self.parent = parent

    def set_name(self):
        """Create a name appropriate for a subinterface if it isn't already created

        Example:
            If self.name is 'ethernet1/1' and self.tag is 5, this method will change the
            name to 'ethernet1/1.5'.

        """
        if self.name.find(".") == -1:
            self.name = self.name + "." + str(self.tag)

    def nearest_pandevice(self):
        """The PanDevice parent for this instance

        Returns:
            PanDevice: Parent PanDevice instance (Firewall or Panorama)

        """
        return self.parent._nearest_pandevice()

    def set_zone(
        self, zone_name, mode=None, refresh=False, update=False, running_config=False
    ):
        raise err.PanDeviceError(
            "Unable to set zone on abstract subinterface because layer must be known to set zone"
        )

    def set_virtual_router(
        self, virtual_router_name, refresh=False, update=False, running_config=False
    ):
        """Set the virtual router for this interface

        Creates a reference to this interface in the specified virtual router and removes references
        to this interface from all other virtual routers. The virtual router will be created if it doesn't exist.

        Args:
            virtual_router_name (str): The name of the VirtualRouter or
                a :class:`panos.network.VirtualRouter` instance
            refresh (bool): Refresh the relevant current state of the device before taking action
                (Default: False)
            update (bool): Apply the changes to the device (Default: False)
            running_config: If refresh is True, refresh from the running configuration
                (Default: False)

        Returns:
            Zone: The zone for this interface after the operation completes

        """
        interface = Layer3Subinterface(self.name, self.tag)
        interface.parent = self.parent
        return interface._set_reference(
            virtual_router_name,
            VirtualRouter,
            "interface",
            "list",
            True,
            refresh=False,
            update=update,
            running_config=running_config,
            return_type="object",
            name_only=False,
        )

    def get_layered_subinterface(self, mode, add=True):
        """Instantiate a regular subinterface type from this AbstractSubinterface

        Converts an abstract subinterface to a real subinterface by offering it a mode.

        Args:
            mode (str): Mode of the subinterface ('layer3' or 'layer2')
            add (bool): Add the newly instantiated subinterface to the base interface object

        Returns:
            Subinterface: A :class:`panos.network.Layer3Subinterface` or
            :class:`panos.network.Layer2Subinterface` instance, depending on the mode argument

        """
        if self.parent is not None:
            if mode == "layer3":
                subintclass = Layer3Subinterface
            elif mode == "layer2":
                subintclass = Layer2Subinterface
            else:
                raise err.PanDeviceError(
                    "Unknown layer passed to subinterface factory: %s" % mode
                )
            layered_subinterface = self.parent.find(self.name, subintclass)
            # Verify tag is correct
            if layered_subinterface is not None:
                if layered_subinterface.tag != self.tag:
                    layered_subinterface.tag = self.tag
            else:
                if add:
                    layered_subinterface = self.parent.add(
                        subintclass(self.name, tag=self.tag)
                    )
                else:
                    return
            return layered_subinterface

    def delete(self):
        """Deletes both Layer3 and Layer2 subinterfaces by name

        This is necessary because an AbstractSubinterface's mode is unknown.

        """
        for cls in (Layer3Subinterface, Layer2Subinterface):
            i = self.parent.find_or_create(self.uid, cls, tag=self.tag)
            i.delete()


class Layer3Subinterface(Subinterface):
    """Ethernet or Aggregate Subinterface in Layer 3 mode.

    Args:
        name (str): The name
        tag (int): Tag for the interface, aka vlan id
        ip (tuple): Interface IPv4 addresses
        ipv6_enabled (bool): IPv6 Enabled (requires IPv6Address child object)
        management_profile (ManagementProfile): Interface Management Profile
        mtu(int): MTU for interface
        adjust_tcp_mss (bool): Adjust TCP MSS
        netflow_profile (str): Netflow profile
        comment (str): The interface's comment
        ipv4_mss_adjust(int): TCP MSS adjustment for ipv4
        ipv6_mss_adjust(int): TCP MSS adjustment for ipv6
        enable_dhcp (bool): Enable DHCP on this interface
        create_dhcp_default_route (bool): Create default route pointing to default gateway provided by server
        dhcp_default_route_metric (int): Metric for the DHCP default route
        decrypt_forward (bool): (PAN-OS 8.1+) Decrypt forward.

    """

    DEFAULT_MODE = "layer3"
    CHILDTYPES = (
        "network.IPv6Address",
        "network.Arp",
    )

    def _setup(self):
        # xpaths for parents: EthernetInterface, AggregateInterface)
        self._xpaths.add_profile(value="/layer3/units")
        # xpaths for parents: firewall.Firewall, device.Vsys
        self._xpaths.add_profile(
            parents=("Firewall", "Vsys"),
            value=(
                "/network/interface/{0}/{1}/layer3/units".format(
                    self._BASE_INTERFACE_TYPE, self._BASE_INTERFACE_NAME
                )
            ),
        )
        self._xpaths.add_profile(
            value="{0}/network/interface/{1}/{2}/layer3/units".format(
                self._TEMPLATE_DEVICE_XPATH,
                self._BASE_INTERFACE_TYPE,
                self._BASE_INTERFACE_NAME,
            ),
            parents=("Template", "TemplateStack"),
        )

        # xpath imports
        self._xpath_imports.add_profile(value="/network/interface")

        # params
        params = []

        params.append(VersionedParamPath("tag", path="tag", vartype="int"))
        params.append(VersionedParamPath("ip", path="ip", vartype="entry"))
        params.append(
            VersionedParamPath("ipv6_enabled", path="ipv6/enabled", vartype="yesno")
        )
        params.append(
            VersionedParamPath(
                "management_profile", path="interface-management-profile"
            )
        )
        params.append(VersionedParamPath("mtu", path="mtu", vartype="int"))
        params.append(
            VersionedParamPath("adjust_tcp_mss", path="adjust-tcp-mss", vartype="yesno")
        )
        params[-1].add_profile("7.1.0", vartype="yesno", path="adjust-tcp-mss/enable")
        params.append(VersionedParamPath("netflow_profile", path="netflow-profile"))
        params.append(VersionedParamPath("comment", path="comment"))
        params.append(VersionedParamPath("ipv4_mss_adjust", exclude=True))
        params[-1].add_profile(
            "7.1.0", path="adjust-tcp-mss/ipv4-mss-adjustment", vartype="int"
        )
        params.append(VersionedParamPath("ipv6_mss_adjust", exclude=True))
        params[-1].add_profile(
            "7.1.0", path="adjust-tcp-mss/ipv6-mss-adjustment", vartype="int"
        )
        params.append(
            VersionedParamPath(
                "enable_dhcp", path="dhcp-client/enable", vartype="yesno"
            )
        )
        params.append(
            VersionedParamPath(
                "create_dhcp_default_route",
                path="dhcp-client/create-default-route",
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "dhcp_default_route_metric",
                path="dhcp-client/default-route-metric",
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath("decrypt_forward", vartype="yesno", exclude=True)
        )
        params[-1].add_profile("8.1.0", vartype="yesno", path="decrypt-forward")

        self._params = tuple(params)


class Layer2Subinterface(Subinterface):
    """Ethernet or Aggregate Subinterface in Layer 2 mode.

    Args:
        name (str): The name
        tag (int): Tag for the interface, aka vlan id
        lldp_enabled (bool): Enable LLDP
        lldp_profile (str): Reference to an lldp profile
        netflow_profile_l2 (str): Netflow profile
        comment (str): The interface's comment

    """

    SUFFIX = ENTRY
    DEFAULT_MODE = "layer2"
    ALLOW_SET_VLAN = True

    def _setup(self):
        # xpaths for parents: EthernetInterface, AggregateInterface
        self._xpaths.add_profile(value="/layer2/units")
        # xpaths for parents: firewall.Firewall, device.Vsys
        self._xpaths.add_profile(
            parents=("Firewall", "Vsys"),
            value=(
                "/network/interface/{0}/{1}/layer2/units".format(
                    self._BASE_INTERFACE_TYPE, self._BASE_INTERFACE_NAME
                )
            ),
        )
        self._xpaths.add_profile(
            value="{0}/network/interface/{1}/{2}/layer2/units".format(
                self._TEMPLATE_DEVICE_XPATH,
                self._BASE_INTERFACE_TYPE,
                self._BASE_INTERFACE_NAME,
            ),
            parents=("Template", "TemplateStack"),
        )

        # xpath imports
        self._xpath_imports.add_profile(value="/network/interface")

        # params
        params = []

        params.append(VersionedParamPath("tag", path="tag", vartype="int"))
        params.append(
            VersionedParamPath("lldp_enabled", path="lldp/enable", vartype="yesno")
        )
        params.append(VersionedParamPath("lldp_profile", path="lldp/profile"))
        params.append(VersionedParamPath("netflow_profile_l2", path="netflow-profile"))
        params.append(VersionedParamPath("comment", path="comment"))

        self._params = tuple(params)


class PhysicalInterface(Interface):
    """Absract base class for Ethernet and Aggregate Interfaces

    Do not instantiate this object. Use a subclass.

    """

    def set_zone(
        self,
        zone_name,
        mode=None,
        refresh=False,
        update=False,
        running_config=False,
        return_type="object",
    ):
        """Set the zone for this interface

        Creates a reference to this interface in the specified zone and removes
        references to this interface from all other zones. The zone will be
        created if it doesn't exist.

        Args:
            zone_name (str): The name of the Zone or a
                :class:`panos.network.Zone` instance
            mode (str): The mode of the zone. See
                :class:`panos.network.Zone` for possible values
            refresh (bool): Refresh the relevant current state of the device
                before taking action (Default: False)
            update (bool): Apply the changes to the device (Default: False)
            running_config: If refresh is True, refresh from the running
                configuration (Default: False)
            return_type (str): Specify what this function returns, can be
                either 'object' (the default) or 'bool'.  If this is 'object',
                then the return value is the Zone in question.  If
                this is 'bool', then the return value is a boolean that tells
                you about if the live device needs updates (update=False) or
                was updated (update=True).

        Returns:
            Zone: The zone for this interface after the operation completes

        """
        if mode is None:
            mode = self.mode

        return super(PhysicalInterface, self).set_zone(
            zone_name, mode, refresh, update, running_config, return_type
        )


class EthernetInterface(PhysicalInterface):
    """Ethernet interface (eg. 'ethernet1/1')

    Args:
        name (str): Name of interface (eg. 'ethernet1/1')
        mode (str): Mode of the interface:
                * layer3
                * layer2
                * virtual-wire
                * tap
                * ha
                * decrypt-mirror
                * aggregate-group

            Not all modes apply to all interface types (Default: layer3)

        ip (tuple): Layer3: Interface IPv4 addresses
        ipv6_enabled (bool): Layer3: IPv6 Enabled (requires
            IPv6Address child object)
        management_profile (ManagementProfile): Layer3: Interface Management
            Profile
        mtu(int): Layer3: MTU for interface
        adjust_tcp_mss (bool): Layer3: Adjust TCP MSS
        netflow_profile (str): Netflow profile
        lldp_enabled (bool): Layer2: Enable LLDP
        lldp_profile (str): Layer2: Reference to an lldp profile
        netflow_profile_l2 (str): Netflow profile
        link_speed (str): Link speed: eg. auto, 10, 100, 1000
        link_duplex (str): Link duplex: eg. auto, full, half
        link_state (str): Link state: eg. auto, up, down
        aggregate_group (str): Aggregate interface (eg. ae1)
        comment (str): The interface's comment
        ipv4_mss_adjust(int): (PAN-OS 7.1+) TCP MSS adjustment for ipv4
        ipv6_mss_adjust(int): (PAN-OS 7.1+) TCP MSS adjustment for ipv6
        enable_dhcp (bool): Enable DHCP on this interface
        create_dhcp_default_route (bool): Create default route pointing to default gateway provided by server
        dhcp_default_route_metric (int): Metric for the DHCP default route
        enable_untagged_subinterface (bool): (PAN-OS 7.1+) Enable untagged
            subinterface
        decrypt_forward (bool): (PAN-OS 8.1+) Decrypt forward.
        rx_policing_rate (int): (PAN-OS 8.1+) Receive policing rate
        tx_policing_rate (int): (PAN-OS 8.1+) Transmit policing rate
        dhcp_send_hostname_enable (bool): Enable send firewall or custom hostname
            to DHCP server
        dhcp_send_hostname_value (string): Set interface hostname

    """

    ALLOW_SET_VLAN = True
    CHILDTYPES = (
        "network.Layer3Subinterface",
        "network.Layer2Subinterface",
        "network.IPv6Address",
        "network.Arp",
    )

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/network/interface/ethernet")
        self._xpaths.add_profile(
            value="{0}/network/interface/ethernet".format(self._TEMPLATE_DEVICE_XPATH),
            parents=("Template", "TemplateStack"),
        )

        # xpath imports
        self._xpath_imports.add_profile(value="/network/interface")

        # params
        params = []

        params.append(
            VersionedParamPath(
                "mode",
                path="{mode}",
                default="layer3",
                values=[
                    "layer3",
                    "layer2",
                    "virtual-wire",
                    "tap",
                    "ha",
                    "decrypt-mirror",
                    "aggregate-group",
                ],
            )
        )
        params.append(
            VersionedParamPath(
                "ip", path="{mode}/ip", vartype="entry", condition={"mode": "layer3"}
            )
        )
        params.append(
            VersionedParamPath(
                "ipv6_enabled",
                vartype="yesno",
                path="{mode}/ipv6/enabled",
                condition={"mode": "layer3"},
            )
        )
        params.append(
            VersionedParamPath(
                "management_profile",
                path="{mode}/interface-management-profile",
                condition={"mode": "layer3"},
            )
        )
        params.append(
            VersionedParamPath(
                "mtu", path="{mode}/mtu", vartype="int", condition={"mode": "layer3"}
            )
        )
        params.append(
            VersionedParamPath(
                "adjust_tcp_mss",
                path="{mode}/adjust-tcp-mss",
                vartype="yesno",
                condition={"mode": "layer3"},
            )
        )
        params[-1].add_profile(
            "7.1.0",
            path="{mode}/adjust-tcp-mss/enable",
            vartype="yesno",
            condition={"mode": "layer3"},
        )
        params.append(
            VersionedParamPath(
                "netflow_profile",
                path="{mode}/netflow-profile",
                condition={"mode": "layer3"},
            )
        )
        params.append(
            VersionedParamPath(
                "lldp_enabled",
                path="{mode}/lldp/enable",
                vartype="yesno",
                condition={"mode": ["layer2", "layer3", "virtual-wire"]},
            )
        )
        params.append(
            VersionedParamPath(
                "lldp_profile",
                path="{mode}/lldp/profile",
                condition={"mode": ["layer2", "layer3", "virtual-wire"]},
            )
        )
        params.append(
            VersionedParamPath(
                "netflow_profile_l2",
                path="{mode}/netflow-profile",
                condition={"mode": "layer2"},
            )
        )
        params.append(VersionedParamPath("link_speed", path="link-speed"))
        params.append(VersionedParamPath("link_duplex", path="link-duplex"))
        params.append(VersionedParamPath("link_state", path="link-state"))
        params.append(
            VersionedParamPath(
                "aggregate_group",
                path="aggregate-group",
                condition={"mode": "aggregate-group"},
            )
        )
        params.append(VersionedParamPath("comment", path="comment"))
        params.append(VersionedParamPath("ipv4_mss_adjust", exclude=True))
        params[-1].add_profile(
            "7.1.0",
            path="{mode}/adjust-tcp-mss/ipv4-mss-adjustment",
            vartype="int",
            condition={"mode": "layer3"},
        )
        params.append(VersionedParamPath("ipv6_mss_adjust", exclude=True))
        params[-1].add_profile(
            "7.1.0",
            path="{mode}/adjust-tcp-mss/ipv6-mss-adjustment",
            vartype="int",
            condition={"mode": "layer3"},
        )
        params.append(
            VersionedParamPath(
                "enable_dhcp",
                path="{mode}/dhcp-client/enable",
                vartype="yesno",
                condition={"mode": "layer3"},
            )
        )
        params.append(
            VersionedParamPath(
                "create_dhcp_default_route",
                path="{mode}/dhcp-client/create-default-route",
                vartype="yesno",
                condition={"mode": "layer3"},
            )
        )
        params.append(
            VersionedParamPath(
                "dhcp_default_route_metric",
                path="{mode}/dhcp-client/default-route-metric",
                vartype="int",
                condition={"mode": "layer3"},
            )
        )
        params.append(VersionedParamPath("enable_untagged_subinterface", exclude=True))
        params[-1].add_profile(
            "7.1.0",
            vartype="yesno",
            condition={"mode": "layer3"},
            path="{mode}/untagged-sub-interface",
        )
        params.append(VersionedParamPath("decrypt_forward", exclude=True))
        params[-1].add_profile(
            "8.1.0",
            vartype="yesno",
            condition={"mode": "layer3"},
            path="{mode}/decrypt-forward",
        )
        params.append(VersionedParamPath("rx_policing_rate", exclude=True))
        params[-1].add_profile(
            "8.1.0",
            vartype="int",
            condition={"mode": "layer3"},
            path="{mode}/policing/rx-rate",
        )
        params.append(VersionedParamPath("tx_policing_rate", exclude=True))
        params[-1].add_profile(
            "8.1.0",
            vartype="int",
            condition={"mode": "layer3"},
            path="{mode}/policing/tx-rate",
        )
        params.append(VersionedParamPath("dhcp_send_hostname_enable", exclude=True))
        params[-1].add_profile(
            "9.0.0",
            vartype="yesno",
            condition={"mode": "layer3"},
            path="{mode}/dhcp-client/send-hostname/enable",
        )
        params.append(VersionedParamPath("dhcp_send_hostname_value", exclude=True))
        params[-1].add_profile(
            "9.0.0",
            condition={"mode": "layer3"},
            path="{mode}/dhcp-client/send-hostname/hostname",
        )

        self._params = tuple(params)


class AggregateInterface(PhysicalInterface):
    """Aggregate interface (eg. 'ae1')

    Args:
        name (str): Name of interface (eg. 'ae1')
        mode (str): Mode of the interface:
                * layer3
                * layer2
                * virtual-wire
                * ha

            Not all modes apply to all interface types (Default: layer3)

        ip (tuple): Layer3: Interface IPv4 addresses
        ipv6_enabled (bool): Layer3: IPv6 Enabled (requires
            IPv6Address child object)
        management_profile (ManagementProfile): Layer3: Interface Management Profile
        mtu(int): Layer3: MTU for interface
        adjust_tcp_mss (bool): Layer3: Adjust TCP MSS
        netflow_profile (str): Netflow profile
        lldp_enabled (bool): Enable LLDP
        lldp_profile (str): Reference to an lldp profile
        comment (str): The interface's comment
        ipv4_mss_adjust(int): Layer3: TCP MSS adjustment for ipv4
        ipv6_mss_adjust(int): Layer3: TCP MSS adjustment for ipv6
        enable_dhcp (bool): Enable DHCP on this interface
        create_dhcp_default_route (bool): Layer3: Create default route pointing to default gateway provided by server
        dhcp_default_route_metric (int): Layer3: Metric for the DHCP default route
        lacp_enable (bool): Enables LACP
        lacp_passive_pre_negotiation (bool): Enable LACP passive pre-negotiation, off by default
        lacp_mode (str): Set LACP mode to 'active' or 'passive'
        lacp_rate (str): Set LACP transmission-rate to 'fast' or 'slow'
        lacp_fast_failover (bool): Enable fast failover for LACP

    """

    ALLOW_SET_VLAN = True
    CHILDTYPES = (
        "network.Layer3Subinterface",
        "network.Layer2Subinterface",
        "network.IPv6Address",
        "network.Arp",
    )

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/network/interface/aggregate-ethernet")
        self._xpaths.add_profile(
            value="{0}/network/interface/aggregate-ethernet".format(
                self._TEMPLATE_DEVICE_XPATH
            ),
            parents=("Template", "TemplateStack"),
        )

        # xpath imports
        self._xpath_imports.add_profile(value="/network/interface")

        # params
        params = []

        params.append(
            VersionedParamPath(
                "mode",
                path="{mode}",
                default="layer3",
                values=[
                    "layer3",
                    "layer2",
                    "virtual-wire",
                    "ha",
                ],
            )
        )
        params.append(
            VersionedParamPath(
                "ip", condition={"mode": "layer3"}, path="{mode}/ip", vartype="entry"
            )
        )
        params.append(
            VersionedParamPath(
                "ipv6_enabled",
                condition={"mode": "layer3"},
                path="{mode}/ipv6/enabled",
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "management_profile",
                condition={"mode": ["layer3", "layer2"]},
                path="{mode}/interface-management-profile",
            )
        )
        params.append(
            VersionedParamPath(
                "mtu", condition={"mode": "layer3"}, path="{mode}/mtu", vartype="int"
            )
        )
        params.append(
            VersionedParamPath(
                "adjust_tcp_mss",
                condition={"mode": "layer3"},
                path="{path}/adjust-tcp-mss/enable",
                vartype="yesno",
            )
        )
        params[-1].add_profile(
            "7.1.0",
            condition={"mode": "layer3"},
            vartype="yesno",
            path="{mode}/adjust-tcp-mss/enable",
        )
        params.append(
            VersionedParamPath(
                "netflow_profile",
                condition={"mode": ["layer3", "layer2", "virtual-wire"]},
                path="{mode}/netflow-profile",
            )
        )
        params.append(
            VersionedParamPath(
                "lldp_enabled",
                condition={"mode": ["layer3", "layer2", "virtual-wire"]},
                path="{mode}/lldp/enable",
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "lldp_profile",
                condition={"mode": ["layer3", "layer2", "virtual-wire"]},
                path="{mode}/lldp/profile",
            )
        )
        params.append(VersionedParamPath("comment", path="comment"))
        params.append(VersionedParamPath("ipv4_mss_adjust", exclude=True))
        params[-1].add_profile(
            "7.1.0",
            condition={"mode": "layer3"},
            path="{mode}/adjust-tcp-mss/ipv4-mss-adjustment",
            vartype="int",
        )
        params.append(VersionedParamPath("ipv6_mss_adjust", exclude=True))
        params[-1].add_profile(
            "7.1.0",
            condition={"mode": "layer3"},
            path="{mode}/adjust-tcp-mss/ipv6-mss-adjustment",
            vartype="int",
        )
        params.append(
            VersionedParamPath(
                "enable_dhcp",
                path="{mode}/dhcp-client/enable",
                vartype="yesno",
                condition={"mode": "layer3"},
            )
        )
        params.append(
            VersionedParamPath(
                "create_dhcp_default_route",
                path="{mode}/dhcp-client/create-default-route",
                vartype="yesno",
                condition={"mode": "layer3"},
            )
        )
        params.append(
            VersionedParamPath(
                "dhcp_default_route_metric",
                path="{mode}/dhcp-client/default-route-metric",
                vartype="int",
                condition={"mode": "layer3"},
            )
        )
        params.append(
            VersionedParamPath(
                "lacp_enable",
                condition={"mode": ["layer3", "layer2", "ha"]},
                vartype="yesno",
                path="{mode}/lacp/enable",
            )
        )
        params.append(
            VersionedParamPath(
                "lacp_passive_pre_negotiation",
                condition={"mode": ["layer3", "layer2"], "lacp_enable": True},
                vartype="yesno",
                path="{mode}/lacp/high-availability/passive-pre-negotiation",
            )
        )
        params.append(
            VersionedParamPath(
                "lacp_mode",
                condition={"mode": ["layer3", "layer2", "ha"], "lacp_enable": True},
                values=["active", "passive"],
                path="{mode}/lacp/mode",
            )
        )
        params.append(
            VersionedParamPath(
                "lacp_rate",
                condition={"mode": ["layer3", "layer2", "ha"], "lacp_enable": True},
                values=["fast", "slow"],
                path="{mode}/lacp/transmission-rate",
            )
        )
        params.append(
            VersionedParamPath(
                "lacp_fast_failover",
                condition={"mode": ["layer3", "layer2", "ha"], "lacp_enable": True},
                vartype="yesno",
                path="{mode}/lacp/fast-failover",
            )
        )

        self._params = tuple(params)


class VlanInterface(Interface):
    """Vlan interface

    Args:
        name (str): Interface name
        ip (tuple): Interface IPv4 addresses
        ipv6_enabled (bool): IPv6 Enabled (requires IPv6Address child object)
        management_profile (ManagementProfile): Interface Management Profile
        mtu(int): MTU for interface
        adjust_tcp_mss (bool): Adjust TCP MSS
        netflow_profile (str): Netflow profile
        comment (str): The interface's comment
        ipv4_mss_adjust(int): TCP MSS adjustment for ipv4
        ipv6_mss_adjust(int): TCP MSS adjustment for ipv6
        enable_dhcp (bool): Enable DHCP on this interface
        create_dhcp_default_route (bool): Create default route pointing to default gateway provided by server
        dhcp_default_route_metric (int): Metric for the DHCP default route

    """

    CHILDTYPES = (
        "network.IPv6Address",
        "network.Arp",
    )

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/network/interface/vlan/units")
        self._xpaths.add_profile(
            value="{0}/network/interface/vlan/units".format(
                self._TEMPLATE_DEVICE_XPATH
            ),
            parents=("Template", "TemplateStack"),
        )

        # xpath imports
        self._xpath_imports.add_profile(value="/network/interface")

        # params
        params = []

        params.append(VersionedParamPath("ip", path="ip", vartype="entry"))
        params.append(
            VersionedParamPath("ipv6_enabled", path="ipv6/enabled", vartype="yesno")
        )
        params.append(
            VersionedParamPath(
                "management_profile", path="interface-management-profile"
            )
        )
        params.append(VersionedParamPath("mtu", path="mtu", vartype="int"))
        params.append(
            VersionedParamPath("adjust_tcp_mss", path="adjust-tcp-mss", vartype="yesno")
        )
        params[-1].add_profile("7.1.0", vartype="yesno", path="adjust-tcp-mss/enable")
        params.append(VersionedParamPath("netflow_profile", path="netflow-profile"))
        params.append(VersionedParamPath("comment", path="comment"))
        params.append(VersionedParamPath("ipv4_mss_adjust", exclude=True))
        params[-1].add_profile(
            "7.1.0", path="adjust-tcp-mss/ipv4-mss-adjustment", vartype="int"
        )
        params.append(VersionedParamPath("ipv6_mss_adjust", exclude=True))
        params[-1].add_profile(
            "7.1.0", path="adjust-tcp-mss/ipv6-mss-adjustment", vartype="int"
        )
        params.append(
            VersionedParamPath(
                "enable_dhcp", path="dhcp-client/enable", vartype="yesno"
            )
        )
        params.append(
            VersionedParamPath(
                "create_dhcp_default_route",
                path="dhcp-client/create-default-route",
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "dhcp_default_route_metric",
                path="dhcp-client/default-route-metric",
                vartype="int",
            )
        )

        self._params = tuple(params)

    def set_vlan_interface(
        self,
        vlan_name,
        refresh=False,
        update=False,
        running_config=False,
        return_type="object",
    ):
        """Sets the VLAN's VLAN interface to this VLAN interface

        Creates a reference to this interface in the specified vlan and removes
        references to this interface from all other VLANs.  The vlan will
        be created if it doesn't exist.

        Args:
            vlan_name (str): The name of the vlan or
                a :class:`panos.network.Vlan` instance
            refresh (bool): Refresh the relevant current state of the device
                before taking action (Default: False)
            update (bool): Apply the changes to the device (Default: False)
            running_config: If refresh is True, refresh from the running
                configuration (Default: False)
            return_type (str): Specify what this function returns, can be
                either 'object' (the default) or 'bool'.  If this is 'object',
                then the return value is the Vlan in question.  If
                this is 'bool', then the return value is a boolean that tells
                you about if the live device needs updates (update=False) or
                was updated (update=True).

        Returns:
            Vlan: The VLAN for this interface after the operation completes

        """
        return self._set_reference(
            vlan_name,
            Vlan,
            "virtual_interface",
            "string",
            True,
            refresh,
            update,
            running_config,
            return_type,
            False,
        )


class LoopbackInterface(Interface):
    """Loopback interface

    Args:
        name (str): The name
        ip (tuple): Interface IPv4 addresses
        ipv6_enabled (bool): IPv6 Enabled (requires IPv6Address child object)
        management_profile (ManagementProfile): Interface Management Profile
        mtu(int): MTU for interface
        adjust_tcp_mss (bool): Adjust TCP MSS
        netflow_profile (str): Netflow profile
        comment (str): The interface's comment
        ipv4_mss_adjust(int): TCP MSS adjustment for ipv4
        ipv6_mss_adjust(int): TCP MSS adjustment for ipv6

    """

    CHILDTYPES = ("network.IPv6Address",)

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/network/interface/loopback/units")
        self._xpaths.add_profile(
            value="{0}/network/interface/loopback/units".format(
                self._TEMPLATE_DEVICE_XPATH
            ),
            parents=("Template", "TemplateStack"),
        )

        # xpath imports
        self._xpath_imports.add_profile(value="/network/interface")

        # params
        params = []

        params.append(VersionedParamPath("ip", path="ip", vartype="entry"))
        params.append(
            VersionedParamPath("ipv6_enabled", path="ipv6/enabled", vartype="yesno")
        )
        params.append(
            VersionedParamPath(
                "management_profile", path="interface-management-profile"
            )
        )
        params.append(VersionedParamPath("mtu", path="mtu", vartype="int"))
        params.append(
            VersionedParamPath("adjust_tcp_mss", path="adjust-tcp-mss", vartype="yesno")
        )
        params[-1].add_profile("7.1.0", vartype="yesno", path="adjust-tcp-mss/enable")
        params.append(VersionedParamPath("netflow_profile", path="netflow-profile"))
        params.append(VersionedParamPath("comment", path="comment"))
        params.append(VersionedParamPath("ipv4_mss_adjust", exclude=True))
        params[-1].add_profile(
            "7.1.0", path="adjust-tcp-mss/ipv4-mss-adjustment", vartype="int"
        )
        params.append(VersionedParamPath("ipv6_mss_adjust", exclude=True))
        params[-1].add_profile(
            "7.1.0", path="adjust-tcp-mss/ipv6-mss-adjustment", vartype="int"
        )

        self._params = tuple(params)


class TunnelInterface(Interface):
    """Tunnel interface

    Args:
        name (str): The name
        ip (tuple): Interface IPv4 addresses
        ipv6_enabled (bool): IPv6 Enabled (requires IPv6Address child object)
        management_profile (ManagementProfile): Interface Management Profile
        mtu(int): MTU for interface
        netflow_profile (str): Netflow profile
        comment (str): The interface's comment

    """

    CHILDTYPES = ("network.IPv6Address",)

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/network/interface/tunnel/units")
        self._xpaths.add_profile(
            value="{0}/network/interface/tunnel/units".format(
                self._TEMPLATE_DEVICE_XPATH
            ),
            parents=("Template", "TemplateStack"),
        )

        # xpath imports
        self._xpath_imports.add_profile(value="/network/interface")

        # params
        params = []

        params.append(VersionedParamPath("ip", path="ip", vartype="entry"))
        params.append(
            VersionedParamPath("ipv6_enabled", path="ipv6/enabled", vartype="yesno")
        )
        params.append(
            VersionedParamPath(
                "management_profile", path="interface-management-profile"
            )
        )
        params.append(VersionedParamPath("mtu", path="mtu", vartype="int"))
        params.append(VersionedParamPath("netflow_profile", path="netflow-profile"))
        params.append(VersionedParamPath("comment", path="comment"))

        self._params = tuple(params)


class StaticRoute(VersionedPanObject):
    """Static Route

    Add to a :class:`panos.network.VirtualRouter` instance.

    Args:
        name (str): The name
        destination (str): Destination network
        nexthop_type (str): ip-address, discard, or next-vr
        nexthop (str): Next hop IP address or Next VR Name
        interface (str): Next hop interface
        admin_dist (str): Administrative distance
        metric (int): Metric (Default: 10)
        enable_path_monitor (bool): Enable Path Monitor
        failure_condition (str): Path Monitor failure condition set 'any' or 'all'
        preemptive_hold_time (int): Path Monitor Preemptive Hold Time in minutes

    """

    SUFFIX = ENTRY
    CHILDTYPES = ("network.PathMonitorDestination",)

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/routing-table/ip/static-route")

        # params
        params = []

        params.append(VersionedParamPath("destination", path="destination"))
        params.append(
            VersionedParamPath(
                "nexthop_type",
                default="ip-address",
                values=["discard", "ip-address", "next-vr"],
                path="nexthop/{nexthop_type}",
            )
        )
        params.append(VersionedParamPath("nexthop", path="nexthop/{nexthop_type}"))
        params.append(VersionedParamPath("interface", path="interface"))
        params.append(
            VersionedParamPath("admin_dist", vartype="int", path="admin-dist")
        )
        params.append(
            VersionedParamPath("metric", default=10, vartype="int", path="metric")
        )
        params.append(
            VersionedParamPath(
                "enable_path_monitor", path="path-monitor/enable", vartype="yesno"
            )
        )
        params.append(
            VersionedParamPath(
                "failure_condition",
                values=("all", "any"),
                path="path-monitor/failure-condition",
            )
        )
        params.append(
            VersionedParamPath(
                "preemptive_hold_time", vartype="int", path="path-monitor/hold-time"
            )
        )

        self._params = tuple(params)


class StaticRouteV6(VersionedPanObject):
    """IPV6 Static Route

    Add to a :class:`panos.network.VirtualRouter` instance.

    Args:
        name (str): The name
        destination (str): Destination network
        nexthop_type (str): ip-address or discard
        nexthop (str): Next hop IP address
        interface (str): Next hop interface
        admin_dist (str): Administrative distance
        metric (int): Metric (Default: 10)
        enable_path_monitor (bool): Enable Path Monitor
        failure_condition (str): Path Monitor failure condition set 'any' or 'all'
        preemptive_hold_time (int): Path Monitor Preemptive Hold Time in minutes

    """

    SUFFIX = ENTRY
    CHILDTYPES = ("network.PathMonitorDestination",)

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/routing-table/ipv6/static-route")

        # params
        params = []

        params.append(VersionedParamPath("destination", path="destination"))
        params.append(
            VersionedParamPath(
                "nexthop_type",
                default="ipv6-address",
                values=["discard", "ipv6-address"],
                path="nexthop/{nexthop_type}",
            )
        )
        params.append(VersionedParamPath("nexthop", path="nexthop/{nexthop_type}"))
        params.append(VersionedParamPath("interface", path="interface"))
        params.append(
            VersionedParamPath("admin_dist", vartype="int", path="admin-dist")
        )
        params.append(
            VersionedParamPath("metric", default=10, vartype="int", path="metric")
        )
        params.append(
            VersionedParamPath(
                "enable_path_monitor", path="path-monitor/enable", vartype="yesno"
            )
        )
        params.append(
            VersionedParamPath(
                "failure_condition",
                values=("all", "any"),
                path="path-monitor/failure-condition",
            )
        )
        params.append(
            VersionedParamPath(
                "preemptive_hold_time", vartype="int", path="path-monitor/hold-time"
            )
        )

        self._params = tuple(params)


class PathMonitorDestination(VersionedPanObject):
    """PathMonitorDestination Static Route

    Args:
        name (str): Name of Path Monitor Destination
        enable (bool): Enable Path Monitor Destination
        source (str): Source ip of interface
        destination (str): Destination ip
        interval (int): Ping Interval (sec) (Default: 3)
        count (int): Ping count (Default: 5)

    """

    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/path-monitor/monitor-destinations")

        # params
        params = []

        params.append(VersionedParamPath("enable", vartype="yesno", path="enable"))
        params.append(VersionedParamPath("source", path="source"))
        params.append(VersionedParamPath("destination", path="destination"))
        params.append(
            VersionedParamPath("interval", default=3, vartype="int", path="interval")
        )
        params.append(
            VersionedParamPath("count", default=5, vartype="int", path="count")
        )

        self._params = tuple(params)


class VirtualRouter(VsysOperations):
    """Virtual router

    Args:
        name (str): Name of virtual router (Default: "default")
        interface (list): List of interface names
        ad_static (int): Administrative distance for this protocol
        ad_static_ipv6 (int): Administrative distance for this protocol
        ad_ospf_int (int): Administrative distance for this protocol
        ad_ospf_ext (int): Administrative distance for this protocol
        ad_ospfv3_int (int): Administrative distance for this protocol
        ad_ospfv3_ext (int): Administrative distance for this protocol
        ad_ibgp (int): Administrative distance for this protocol
        ad_ebgp (int): Administrative distance for this protocol
        ad_rip (int): Administrative distance for this protocol

    """

    _DEFAULT_NAME = "default"
    SUFFIX = ENTRY
    CHILDTYPES = (
        "network.StaticRoute",
        "network.StaticRouteV6",
        "network.RedistributionProfile",
        "network.RedistributionProfileIPv6",
        "network.Ospf",
        "network.Bgp",
        "network.Rip",
    )

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/network/virtual-router")
        self._xpaths.add_profile(
            value="{0}/network/virtual-router".format(self._TEMPLATE_DEVICE_XPATH),
            parents=("Template", "TemplateStack"),
        )

        # xpath imports
        self._xpath_imports.add_profile(value="/network/virtual-router")

        # params
        params = []

        params.append(
            VersionedParamPath("interface", path="interface", vartype="member")
        )

        admin_dists = (
            ("ad_static", "static"),
            ("ad_static_ipv6", "static-ipv6"),
            ("ad_ospf_int", "ospf-int"),
            ("ad_ospf_ext", "ospf-ext"),
            ("ad_ospfv3_int", "ospfv3-int"),
            ("ad_ospfv3_ext", "ospfv3-ext"),
            ("ad_ibgp", "ibgp"),
            ("ad_ebgp", "ebgp"),
            ("ad_rip", "rip"),
        )

        for var_name, path in admin_dists:
            params.append(
                VersionedParamPath(var_name, vartype="int", path="admin-dists/" + path)
            )

        self._params = tuple(params)


class RedistributionProfileBase(VersionedPanObject):
    """Redistribution Profile

    Args:
        name (str): Name of profile
        priority (int): Priority id
        action (str): 'no-redist' or 'redist'
        filter_type (tuple): Any of 'static', 'connect', 'rip', 'ospf', or 'bgp'
        filter_interface (tuple): Filter interface
        filter_destination (tuple): Filter destination
        filter_nexthop (tuple): Filter nexthop
        ospf_filter_pathtype (tuple): Any of 'intra-area', 'inter-area', 'ext-1', or 'ext-2
        ospf_filter_area (tuple): OSPF filter on area
        ospf_filter_tag (tuple): OSPF filter on tag
        bgp_filter_community (tuple): BGP filter on community
        bgp_filter_extended_community (tuple): BGP filter on extended community

    """

    SUFFIX = ENTRY

    def _setup(self):
        # self._xpaths.add_profile(value='/protocol/redist-profile')

        params = []

        params.append(VersionedParamPath("priority", vartype="int"))
        params.append(
            VersionedParamPath(
                "action", values=["no-redist", "redist"], path="action/{action}"
            )
        )
        params.append(
            VersionedParamPath("filter_type", path="filter/type", vartype="member")
        )
        params.append(
            VersionedParamPath(
                "filter_interface", path="filter/interface", vartype="member"
            )
        )
        params.append(
            VersionedParamPath(
                "filter_destination", path="filter/destination", vartype="member"
            )
        )
        params.append(
            VersionedParamPath(
                "filter_nexthop", path="filter/nexthop", vartype="member"
            )
        )
        params.append(
            VersionedParamPath(
                "ospf_filter_pathtype",
                path="filter/ospf/path-type",
                vartype="member",
                values=["intra-area", "inter-area", "ext-1", "ext-2"],
            )
        )
        params.append(
            VersionedParamPath(
                "ospf_filter_area", path="filter/ospf/area", vartype="member"
            )
        )
        params.append(
            VersionedParamPath(
                "ospf_filter_tag", path="filter/ospf/tag", vartype="member"
            )
        )
        params.append(
            VersionedParamPath(
                "bgp_filter_community", path="filter/bgp/community", vartype="member"
            )
        )
        params.append(
            VersionedParamPath(
                "bgp_filter_extended_community",
                path="filter/bgp/extended-community",
                vartype="member",
            )
        )

        self._params = tuple(params)


class RedistributionProfile(RedistributionProfileBase):
    """Redistribution Profile

    Args:
        name (str): Name of profile
        priority (int): Priority id
        action (str): 'no-redist' or 'redist'
        filter_type (tuple): Any of 'static', 'connect', 'rip', 'ospf', or 'bgp'
        filter_interface (tuple): Filter interface
        filter_destination (tuple): Filter destination
        filter_nexthop (tuple): Filter nexthop
        ospf_filter_pathtype (tuple): Any of 'intra-area', 'inter-area', 'ext-1', or 'ext-2
        ospf_filter_area (tuple): OSPF filter on area
        ospf_filter_tag (tuple): OSPF filter on tag
        bgp_filter_community (tuple): BGP filter on community
        bgp_filter_extended_community (tuple): BGP filter on extended community

    """

    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(value="/protocol/redist-profile")

        RedistributionProfileBase._setup(self)


class RedistributionProfileIPv6(RedistributionProfileBase):
    """Redistribution Profile

    Args:
        name (str): Name of profile
        priority (int): Priority id
        action (str): 'no-redist' or 'redist'
        filter_type (tuple): Any of 'static', 'connect', 'rip', 'ospf', or 'bgp'
        filter_interface (tuple): Filter interface
        filter_destination (tuple): Filter destination
        filter_nexthop (tuple): Filter nexthop
        ospf_filter_pathtype (tuple): Any of 'intra-area', 'inter-area', 'ext-1', or 'ext-2
        ospf_filter_area (tuple): OSPF filter on area
        ospf_filter_tag (tuple): OSPF filter on tag
        bgp_filter_community (tuple): BGP filter on community
        bgp_filter_extended_community (tuple): BGP filter on extended community

    """

    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(value="/protocol/redist-profile-ipv6")

        RedistributionProfileBase._setup(self)


class Rip(VersionedPanObject):
    """Rip

    Add to a :class:`panos.network.VirtualRouter` instance.

    Args:
        enable (bool): Enable RIP
        reject_default_route (bool): Reject default route
        allow_redist_default_route (bool): Allow Redistribute Default Route
        delete_intervals (int): Delete Intervals
        expire_intervals (int): Expire Intervals
        interval_seconds (int): Interval Seconds (sec)
        update_intervals (int): Update Intervals
        global_bfd_profile (str): Global BFD profile

    """

    NAME = None
    CHILDTYPES = (
        "network.RipInterface",
        "network.RipAuthProfile",
        "network.RipExportRule",
    )

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/protocol/rip")

        # params
        params = []

        params.append(
            VersionedParamPath("enable", path="enable", default=True, vartype="yesno")
        )
        params.append(
            VersionedParamPath(
                "reject_default_route",
                default=True,
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "allow_redist_default_route",
                path="allow-redist-default-route",
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "delete_intervals",
                path="timers/delete-intervals",
                vartype="int",
                default=120,
            )
        )
        params.append(
            VersionedParamPath(
                "expire_intervals",
                path="timers/expire-intervals",
                vartype="int",
                default=180,
            )
        )
        params.append(
            VersionedParamPath(
                "interval_seconds",
                path="timers/interval-seconds",
                vartype="int",
                default=1,
            )
        )
        params.append(
            VersionedParamPath(
                "update_intervals",
                path="timers/update-intervals",
                vartype="int",
                default=30,
            )
        )
        params.append(
            VersionedParamPath("global_bfd_profile", path="global-bfd/profile")
        )

        self._params = tuple(params)


class RipInterface(VersionedPanObject):
    """Rip Interface

    Add to a :class:`panos.network.Rip` instance.

    Args:
        name (str): Interface name
        enable (bool): Enable
        advertise_default_route: Advertise default route
                * advertise
                * disable
        metric (int): Default route metric. Requires {advertise_default_route: "advertise"}
        auth_profile (str): Auth profile name
        mode (str): Mode of RipInterface
                * normal (default)
                * passive
                * send-only
    """

    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(value="/interface")

        params = []

        params.append(
            VersionedParamPath("enable", path="enable", vartype="yesno", default=True)
        )
        params.append(
            VersionedParamPath(
                "advertise_default_route",
                values=["advertise", "disable"],
                default="disable",
                path="default-route/{advertise_default_route}",
            )
        )
        params.append(
            VersionedParamPath(
                "metric",
                path="default-route/{advertise_default_route}/metric",
                vartype="int",
                default=10,
                condition={"advertise_default_route": "advertise"},
            )
        )
        params.append(VersionedParamPath("auth_profile", path="authentication"))
        params.append(
            VersionedParamPath(
                "mode",
                path="mode",
                values=["normal", "passive", "send-only"],
                default="normal",
            )
        )

        self._params = tuple(params)


class RipAuthProfile(VersionedPanObject):
    """Rip Authentication Profile

    Args:
        name (str): Name of Auth Profile
        auth_type (str): 'password' or 'md5'
        password (str): The password if auth_type is set to 'password'.
            If auth_type is set to 'md5', add a :class:`panos.network.RipAuthProfileMd5`

    """

    SUFFIX = ENTRY
    CHILDTYPES = ("network.RipAuthProfileMd5",)

    def _setup(self):
        self._xpaths.add_profile(value="/auth-profile")

        params = []
        params.append(
            VersionedParamPath(
                "auth_type", values=["password", "md5"], path="{auth_type}"
            )
        )
        params.append(
            VersionedParamPath(
                "password",
                condition={"auth_type": "password"},
                path="{auth_type}",
                vartype="encrypted",
            )
        )

        self._params = tuple(params)


class RipAuthProfileMd5(VersionedPanObject):
    """Rip Authentication Profile

    Args:
        keyid (int): Identifier for key
        key (str): The authentication key
        preferred (bool): This key is preferred

    """

    SUFFIX = ENTRY
    NAME = "keyid"

    def _setup(self):
        self._xpaths.add_profile(value="/md5")

        params = []

        params.append(VersionedParamPath("key", vartype="encrypted"))
        params.append(VersionedParamPath("preferred", vartype="yesno"))

        self._params = tuple(params)


class RipExportRule(VersionedPanObject):
    """Rip Export Rules

    Args:
        name (str): IP subnet or :class:`panos.network.RedistributionProfile`
        metric (int): Metric

    """

    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(value="/export-rules")

        params = []

        params.append(VersionedParamPath("metric", vartype="int"))

        self._params = tuple(params)


class Ospf(VersionedPanObject):
    """OSPF Process

    Args:
        enable (bool): Enable OSPF (Default: True)
        router_id (str): Router ID in IP format (eg. 1.1.1.1)
        reject_default_route (bool): Reject default route
        allow_redist_default_route (bool): Allow redistribution in default route
        rfc1583 (bool): rfc1583
        spf_calculation_delay (int): SPF calculation delay
        lsa_interval (int): LSA interval
        graceful_restart_enable (bool): Enable OSPF graceful restart
        gr_grace_period (int): Graceful restart period
        gr_helper_enable (bool): Graceful restart helper enable
        gr_strict_lsa_checking (bool): Graceful restart strict lsa checking
        gr_max_neighbor_restart_time (int): Graceful restart neighbor restart time

    """

    NAME = None
    CHILDTYPES = (
        "network.OspfArea",
        "network.OspfAuthProfile",
        "network.OspfExportRules",
    )

    def _setup(self):
        self._xpaths.add_profile(value="/protocol/ospf")

        params = []

        params.append(
            VersionedParamPath("enable", default=True, path="enable", vartype="yesno")
        )
        params.append(VersionedParamPath("router_id"))
        params.append(VersionedParamPath("reject_default_route", vartype="yesno"))
        params.append(VersionedParamPath("allow_redist_default_route", vartype="yesno"))
        params.append(VersionedParamPath("rfc1583", vartype="yesno"))
        # TODO: Add flood prevention
        params.append(
            VersionedParamPath(
                "spf_calculation_delay",
                path="timers/spf-calculation-delay",
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "lsa_interval", path="timers/lsa-interval", vartype="int"
            )
        )
        params.append(
            VersionedParamPath(
                "graceful_restart_enable",
                path="graceful-restart/enable",
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "gr_grace_period", path="graceful-restart/grace-period", vartype="int"
            )
        )
        params.append(
            VersionedParamPath(
                "gr_helper_enable",
                path="graceful-restart/helper-enable",
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "gr_strict_lsa_checking",
                path="graceful-restart/strict-LSA-checking",
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "gr_max_neighbor_restart_time",
                path="graceful-restart/max-neighbor-restart-time",
                vartype="int",
            )
        )

        self._params = tuple(params)


class OspfArea(VersionedPanObject):
    """OSPF Area

    Args:
        name (str): Area in IP format
        type (str): Type of area, 'normal', 'stub', or 'nssa' (Default: normal)
        accept_summary (bool): Accept summary route - stub and nssa only
        default_route_advertise (str): 'disable' or 'advertise' (Default: disable) - stub and nssa only
        default_route_advertise_metric (int): Default route metric - stub and nssa only
        default_route_advertise_type (str): 'ext-1' or 'ext2' (Default: ext-2 - nssa only

    """

    SUFFIX = ENTRY
    CHILDTYPES = (
        "network.OspfRange",
        "network.OspfAreaInterface",
        "network.OspfNssaExternalRange",
    )

    def _setup(self):
        self._xpaths.add_profile(value="/area")

        params = []

        params.append(
            VersionedParamPath(
                "type",
                default="normal",
                values=["normal", "stub", "nssa"],
                path="type/{type}",
            )
        )
        params.append(
            VersionedParamPath(
                "accept_summary",
                condition={"type": ["stub", "nssa"]},
                path="type/{type}/accept-summary",
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "default_route_advertise",
                default="disable",
                condition={"type": ["stub", "nssa"]},
                values=["disable", "advertise"],
                path="type/{type}/default-route/{default_route_advertise}",
            )
        )
        params.append(
            VersionedParamPath(
                "default_route_advertise_metric",
                condition={
                    "type": ["stub", "nssa"],
                    "default_route_advertise": "advertise",
                },
                path="type/{type}/default-route/advertise/metric",
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "default_route_advertise_type",
                default="ext-2",
                condition={"type": "nssa", "default_route_advertise": "advertise"},
                values=["ext-1", "ext-2"],
                path="type/nssa/default-route/advertise/type",
            )
        )

        self._params = tuple(params)


class OspfRange(VersionedPanObject):
    """OSPF Range

    Args:
        name (str): IP network with prefix
        mode (str): 'advertise' or 'suppress' (Default: advertise)

    """

    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(value="/range")

        params = []

        params.append(
            VersionedParamPath(
                "mode",
                default="advertise",
                values=["advertise", "suppress"],
                path="{mode}",
            )
        )

        self._params = tuple(params)


class OspfNssaExternalRange(VersionedPanObject):
    """OSPF NSSA External Range

    Args:
        name (str): IP network with prefix
        mode (str): 'advertise' or 'suppress' (Default: advertise)

    """

    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(value="/type/nssa/nssa-ext-range")

        params = []

        params.append(
            VersionedParamPath(
                "mode",
                default="advertise",
                values=["advertise", "suppress"],
                path="{mode}",
            )
        )

        self._params = tuple(params)


class OspfAreaInterface(VersionedPanObject):
    """OSPF Area Interface

    Args:
        name (str): Name of the interface (interface must exist)
        enable (bool): OSPF enabled on this interface
        passive (bool): Passive mode
        link_type (str): Link type, 'broadcast', 'p2p', or 'p2mp' (Default: broadcast)
        metric (int): Metric
        priority (int): Priority id
        hello_interval (int): Hello interval
        dead_counts (int): Dead counts
        retransmit_interval (int): Retransmit interval
        transit_delay (int): Transit delay
        gr_delay (int): Graceful restart delay
        authentication (str): Reference to a :class:`panos.network.OspfAuthProfile`

    """

    SUFFIX = ENTRY
    CHILDTYPES = ("network.OspfNeighbor",)

    def _setup(self):
        self._xpaths.add_profile(value="/interface")

        params = []

        params.append(VersionedParamPath("enable", vartype="yesno"))
        params.append(VersionedParamPath("passive", vartype="yesno"))
        params.append(
            VersionedParamPath(
                "link_type",
                default="broadcast",
                values=["broadcast", "p2p", "p2mp"],
                path="link-type/{link_type}",
            )
        )
        params.append(VersionedParamPath("metric", vartype="int"))
        params.append(VersionedParamPath("priority", vartype="int"))
        params.append(VersionedParamPath("hello_interval", vartype="int"))
        params.append(VersionedParamPath("dead_counts", vartype="int"))
        params.append(VersionedParamPath("retransmit_interval", vartype="int"))
        params.append(VersionedParamPath("transit_delay", vartype="int"))
        params.append(VersionedParamPath("gr_delay", vartype="int"))
        params.append(VersionedParamPath("authentication"))

        self._params = tuple(params)


class OspfNeighbor(VersionedPanObject):
    """OSPF Neighbor

    Args:
        name (str): IP of neighbor
        metric (int): Metric

    """

    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(value="/neighbor")

        params = []

        params.append(VersionedParamPath("metric", vartype="int", exclude=True))

        self._params = tuple(params)


class OspfAuthProfile(VersionedPanObject):
    """OSPF Authentication Profile

    Args:
        name (str): Name of Auth Profile
        type (str): 'password' or 'md5'
        password (str): The password if type is set to 'password'.
            If type is set to 'md5', add a :class:`panos.network.OspfAuthProfileMd5`

    """

    SUFFIX = ENTRY
    CHILDTYPES = ("network.OspfAuthProfileMd5",)

    def _setup(self):
        self._xpaths.add_profile(value="/auth-profile")

        params = []

        params.append(
            VersionedParamPath("type", values=["password", "md5"], path="{type}")
        )
        params.append(
            VersionedParamPath(
                "password", condition={"type": "password"}, path="{type}"
            )
        )

        self._params = tuple(params)


class OspfAuthProfileMd5(VersionedPanObject):
    """OSPF Authentication Profile

    Args:
        keyid (int): Identifier for key
        key (str): The authentication key
        preferred (bool): This key is preferred

    """

    SUFFIX = ENTRY
    NAME = "keyid"

    def _setup(self):
        self._xpaths.add_profile(value="/md5")

        params = []

        params.append(VersionedParamPath("key", vartype="encrypted"))
        params.append(VersionedParamPath("preferred", vartype="yesno"))

        self._params = tuple(params)


class OspfExportRules(VersionedPanObject):
    """OSPF Export Rules

    Args:
        name (str): IP subnet or :class:`panos.network.RedistributionProfile`
        new_path_type (str): New path type, 'ext-1' or 'ext-2' (Default: ext-2)
        new_tag (str): New tag (int or IP format)
        metric (int): Metric

    """

    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(value="/export-rules")

        params = []

        params.append(
            VersionedParamPath(
                "new_path_type", default="ext-2", values=["ext-1", "ext-2"]
            )
        )
        params.append(VersionedParamPath("new_tag"))
        params.append(VersionedParamPath("metric", vartype="int"))

        self._params = tuple(params)


class Bgp(VersionedPanObject):
    """BGP Process

    Args:
        enable (bool): Enable BGP (Default: True)
        router_id (str): Router ID in IP format (eg. 1.1.1.1)
        reject_default_route (bool): Reject default route
        allow_redist_default_route (bool): Allow redistribution in default route
        install_route (bool): Populate BGP learned route to global route table
        ecmp_multi_as (bool): Support multiple AS in ECMP
        enforce_first_as (bool): Enforce First AS for EBGP
        local_as (int): local AS number
        global_bfd_profile (str): BFD Profile

    """

    NAME = None
    CHILDTYPES = (
        "network.BgpRoutingOptions",
        "network.BgpAuthProfile",
        "network.BgpDampeningProfile",
        "network.BgpPeerGroup",
        "network.BgpPolicyImportRule",
        "network.BgpPolicyExportRule",
        "network.BgpPolicyConditionalAdvertisement",
        "network.BgpPolicyAggregationAddress",
        "network.BgpRedistributionRule",
    )

    def _setup(self):
        self._xpaths.add_profile(value="/protocol/bgp")

        params = []

        params.append(
            VersionedParamPath("enable", default=True, path="enable", vartype="yesno")
        )
        params.append(VersionedParamPath("router_id"))
        params.append(
            VersionedParamPath("reject_default_route", default=True, vartype="yesno")
        )
        params.append(
            VersionedParamPath(
                "allow_redist_default_route", default=False, vartype="yesno"
            )
        )
        params.append(
            VersionedParamPath("install_route", default=False, vartype="yesno")
        )
        params.append(
            VersionedParamPath("ecmp_multi_as", default=False, vartype="yesno")
        )
        params.append(
            VersionedParamPath("enforce_first_as", default=True, vartype="yesno")
        )
        params.append(VersionedParamPath("local_as", vartype="str"))
        params.append(
            VersionedParamPath("global_bfd_profile", path="global-bfd/profile")
        )

        self._params = tuple(params)


class BgpRoutingOptions(VersionedPanObject):
    """BGP Routing Options

    Args:
        as_format (str): AS format ('2-byte'/'4-byte')
        always_compare_med (bool): always compare MEDs
        deterministic_med_comparison (bool): deterministic MEDs comparison
        default_local_preference (int): default local preference
        graceful_restart_enable (bool): enable graceful restart
        gr_stale_route_time (int): time to remove stale routes after peer restart (in seconds)
        gr_local_restart_time (int): local restart time to advertise to peer (in seconds)
        gr_max_peer_restart_time (int): maximum of peer restart time accepted (in seconds)
        reflector_cluster_id (str): route reflector cluster ID
        confederation_member_as (str): 32-bit value in decimal or dot decimal AS.AS format
        aggregate_med (bool): aggregate route only if they have same MED attributes

    """

    NAME = None
    SUFFIX = None
    CHILDTYPES = ("network.BgpOutboundRouteFilter",)

    def _setup(self):
        self._xpaths.add_profile(value="/routing-options")

        params = []

        params.append(
            VersionedParamPath(
                "as_format", default="2-byte", values=["2-byte", "4-byte"]
            )
        )
        params.append(
            VersionedParamPath(
                "always_compare_med", path="med/always-compare-med", vartype="yesno"
            )
        )
        params.append(
            VersionedParamPath(
                "deterministic_med_comparison",
                path="med/deterministic-med-comparison",
                vartype="yesno",
            )
        )
        params.append(VersionedParamPath("default_local_preference", vartype="int"))
        params.append(
            VersionedParamPath(
                "graceful_restart_enable",
                path="graceful-restart/enable",
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "gr_stale_route_time",
                path="graceful-restart/stale-route-time",
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "gr_local_restart_time",
                path="graceful-restart/local-restart-time",
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "gr_max_peer_restart_time",
                path="graceful-restart/max-peer-restart-time",
                vartype="int",
            )
        )
        params.append(VersionedParamPath("reflector_cluster_id"))
        params.append(VersionedParamPath("confederation_member_as", default=None))
        params.append(
            VersionedParamPath(
                "aggregate_med", path="aggregate/aggregate-med", vartype="yesno"
            )
        )

        self._params = tuple(params)


class BgpOutboundRouteFilter(VersionedPanObject):
    """BGP Outbound Route Filtering

    NOTE: This functionality is not enabled yet in PanOS

    Args:
        enable (bool): enable prefix-based outbound route filtering.
        max_received_entries (int): maximum of ORF prefixes to receive.
        cisco_prefix_mode (bool): ORF vendor-compatible mode

    """

    NAME = None
    SUFFIX = None

    def _setup(self):
        self._xpaths.add_profile(value="/outbound-route-filter")

        params = []

        params.append(VersionedParamPath("enable", path="enable", vartype="yesno"))
        params.append(
            VersionedParamPath(
                "max_received_entries", path="max-received-entries", vartype="int"
            )
        )
        params.append(
            VersionedParamPath(
                "cisco_prefix_mode", path="cisco-prefix-mode", vartype="yesno"
            )
        )

        self._params = tuple(params)


class BgpDampeningProfile(VersionedPanObject):
    """BGP Dampening Profile

    Args:
        name (str): Name of Dampening Profile
        enable (bool): Enable profile (Default: True)
        cutoff (float): Cutoff threshold value
        reuse (float): Reuse threshold value
        max_hold_time (int): Maximum of hold-down time (in seconds)
        decay_half_life_reachable (int): Decay half-life while reachable (in seconds)
        decay_half_life_unreachable (int): Decay half-life while unreachable (in seconds)

    """

    _DEFAULT_NAME = "default"
    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(value="/dampening-profile")

        params = []

        params.append(VersionedParamPath("enable", vartype="yesno"))
        params.append(VersionedParamPath("cutoff", vartype="float"))
        params.append(VersionedParamPath("reuse", vartype="float"))
        params.append(VersionedParamPath("max_hold_time", vartype="int"))
        params.append(VersionedParamPath("decay_half_life_reachable", vartype="int"))
        params.append(VersionedParamPath("decay_half_life_unreachable", vartype="int"))

        self._params = tuple(params)


class BgpAuthProfile(VersionedPanObject):
    """BGP Authentication Profile

    Args:
        name (str): Name of Auth Profile
        secret (str): shared secret for the TCP MD5 authentication.

    """

    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(value="/auth-profile")

        params = []

        params.append(VersionedParamPath("secret", vartype="encrypted"))

        self._params = tuple(params)


class BgpPeerGroup(VersionedPanObject):
    """BGP Peer Group

    Args:
        name (str): Name of BGP Peer Group
        enable (bool): Enable Peer Group (Default: True)
        aggregated_confed_as_path (bool): the peers understand aggregated confederation AS path
        soft_reset_with_stored_info (bool): soft reset with stored info
        type (str): peer group type I('ebgp')/I('ibgp')/I('ebgp-confed')/I('ibgp-confed')
        export_nexthop (str): export locally resolved nexthop I('resolve')/I('use-self')
        import_nexthop (str): override nexthop with peer address I('original')/I('use-peer'), only with 'ebgp'
        remove_private_as (bool): remove private AS when exporting route, only with 'ebgp'

    """

    SUFFIX = ENTRY
    CHILDTYPES = ("network.BgpPeer",)

    def _setup(self):
        self._xpaths.add_profile(value="/peer-group")

        params = []

        params.append(VersionedParamPath("enable", vartype="yesno"))
        params.append(VersionedParamPath("aggregated_confed_as_path", vartype="yesno"))
        params.append(
            VersionedParamPath("soft_reset_with_stored_info", vartype="yesno")
        )
        params.append(
            VersionedParamPath(
                "type",
                path="type/{type}",
                default="ebgp",
                values=("ebgp", "ibgp", "ebgp-confed", "ibgp-confed"),
            )
        )
        params.append(
            VersionedParamPath(
                "export_nexthop",
                path="type/{type}/export-nexthop",
                values=("resolve", "use-self"),
            )
        )
        params.append(
            VersionedParamPath(
                "import_nexthop",
                condition={"type": "ebgp"},
                path="type/{type}/import-nexthop",
                values=("original", "use-peer"),
            )
        )
        params.append(
            VersionedParamPath(
                "remove_private_as",
                condition={"type": "ebgp"},
                path="type/{type}/remove-private-as",
                vartype="yesno",
            )
        )

        self._params = tuple(params)


class BgpPeer(VersionedPanObject):
    """BGP Peer

    Args:
        name (str): Name of BGP Peer
        enable (bool): Enable Peer (Default: True)
        peer_as (str): peer AS number
        enable_mp_bgp (bool): enable MP-BGP extentions
        address_family_identifier (str): peer address family type
            * ipv4
            * ipv6
        subsequent_address_unicast (bool): select SAFI for this peer
        subsequent_address_multicast (bool): select SAFI for this peer
        local_interface (str): interface to accept BGP session
        local_interface_ip (str): specify exact IP address if interface has multiple addresses
        peer_address_ip (str): IP address of peer
        connection_authentication (str): BGP auth profile name
        connection_keep_alive_interval (int): keep-alive interval (in seconds)
        connection_min_route_adv_interval (int): Minimum Route Advertisement Interval (in seconds)
        connection_multihop (int): IP TTL value used for sending BGP packet. set to 0 means eBGP use 2, iBGP use 255
        connection_open_delay_time (int): open delay time (in seconds)
        connection_hold_time (int): hold time (in seconds)
        connection_idle_hold_time (int): idle hold time (in seconds)
        connection_incoming_allow (bool): allow incoming connections
        connection_outgoing_allow (bool): allow outgoing connections
        connection_incoming_remote_port (int): restrict remote port for incoming BGP connections
        connection_outgoing_local_port (int): use specific local port for outgoing BGP connections
        enable_sender_side_loop_detection (bool):
        reflector_client (str):
            * non-client
            * client
            * meshed-client
        peering_type (str):
            * unspecified
            * bilateral
        max_prefixes (int): maximum of prefixes to receive from peer
        bfd_profile (str): BFD configuration
            * Inherit-vr-global-setting
            * None
            * Pre-existing BFD profile name
            * None

    """

    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(value="/peer")

        params = []

        params.append(VersionedParamPath("enable", path="enable", vartype="yesno"))
        params.append(VersionedParamPath("peer_as", path="peer-as"))
        params.append(VersionedParamPath("enable_mp_bgp", vartype="yesno"))
        params.append(
            VersionedParamPath(
                "address_family_identifier",
                condition={"enable_mp_bgp": True},
                values=("ipv4", "ipv6"),
            )
        )
        params.append(
            VersionedParamPath(
                "subsequent_address_unicast",
                condition={"enable_mp_bgp": True},
                path="subsequent-address-family-identifier/unicast",
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "subsequent_address_multicast",
                condition={"enable_mp_bgp": True},
                path="subsequent-address-family-identifier/multicast",
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath("local_interface", path="local-address/interface")
        )
        params.append(VersionedParamPath("local_interface_ip", path="local-address/ip"))
        params.append(VersionedParamPath("peer_address_ip", path="peer-address/ip"))
        params.append(
            VersionedParamPath(
                "connection_authentication", path="connection-options/authentication"
            )
        )
        params.append(
            VersionedParamPath(
                "connection_keep_alive_interval",
                path="connection-options/keep-alive-interval",
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "connection_min_route_adv_interval",
                path="connection-options/min-route-adv-interval",
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "connection_multihop", path="connection-options/multihop", vartype="int"
            )
        )
        params.append(
            VersionedParamPath(
                "connection_open_delay_time",
                path="connection-options/open-delay-time",
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "connection_hold_time",
                path="connection-options/hold-time",
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "connection_idle_hold_time",
                path="connection-options/idle-hold-time",
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "connection_incoming_allow",
                path="connection-options/incoming-bgp-connection/allow",
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "connection_outgoing_allow",
                path="connection-options/outgoing-bgp-connection/allow",
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "connection_incoming_remote_port",
                path="connection-options/incoming-bgp-connection/remote-port",
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "connection_outgoing_local_port",
                path="connection-options/outgoing-bgp-connection/local-port",
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath("enable_sender_side_loop_detection", vartype="yesno")
        )
        params.append(
            VersionedParamPath(
                "reflector_client", values=("non-client", "client", "meshed-client")
            )
        )
        params.append(
            VersionedParamPath("peering_type", values=("unspecified", "bilateral"))
        )

        """
        aggregated_confed_as_path (bool): this peer understands aggregated confederation AS path
        max_orf_entries (int): maximum of ORF entries accepted from peer
        soft_reset_with_stored_info (bool): soft reset with stored info
        """
        # params.append(VersionedParamPath(
        #     'aggregated_confed_as_path', vartype='yesno'))
        params.append(VersionedParamPath("max_prefixes"))
        # params.append(VersionedParamPath(
        #     'max_orf_entries', vartype='int'))
        # params.append(VersionedParamPath(
        #     'soft_reset_with_stored_info', vartype='yesno'))
        params.append(VersionedParamPath("bfd_profile", path="bfd/profile"))

        self._params = tuple(params)


class BgpPolicyFilter(VersionedPanObject):
    """Base class for BGP Policy Match Filters

    Do not instantiate this class, use one of:
        * BgpPolicyImportRule
        * BgpPolicyExportRule

    Args:
        name (str): Name of filter
        enable (bool): Enable rule.
        match_afi (str): Address Family Identifier
            * ip
            * ipv6
        match_safi (str): Subsequent Address Family Identifier
            * ip
            * ipv6
        match_route_table (str): Route table to match rule
            * unicast
            * multicast
            * both
        match_nexthop (list): Next-hop attributes
        match_from_peer (list): Filter by peer that sent this route
        match_med (int): Multi-Exit Discriminator
        match_as_path_regex (str): AS-path regular expression
        match_community_regex (str): Community AS-path regular expression
        match_extended_community_regex (str): Extended Community AS-path regular expression

    """

    # SUFFIX = None

    def _setup(self):
        # disabled because this is a base class
        # self._xpaths.add_profile(value='/policy')

        params = []

        params.append(VersionedParamPath("enable", vartype="yesno"))
        params.append(
            VersionedParamPath(
                "match_afi", path="match/afi", default=None, values=("ip", "ipv6")
            )
        )
        params.append(
            VersionedParamPath(
                "match_safi", path="match/safi", default=None, values=("ip", "ipv6")
            )
        )
        params.append(
            VersionedParamPath(
                "match_route_table",
                path="match/route-table",
                default="unicast",
                values=("unicast", "multicast", "both"),
            )
        )
        params.append(
            VersionedParamPath("match_nexthop", path="match/nexthop", vartype="member")
        )
        params.append(
            VersionedParamPath(
                "match_from_peer", path="match/from-peer", vartype="member"
            )
        )
        params.append(VersionedParamPath("match_med", path="match/med", vartype="int"))
        params.append(
            VersionedParamPath("match_as_path_regex", path="match/as-path/regex")
        )
        params.append(
            VersionedParamPath("match_community_regex", path="match/community/regex")
        )
        params.append(
            VersionedParamPath(
                "match_extended_community_regex", path="match/extended-community/regex"
            )
        )

        self._params = tuple(params)


class BgpPolicyNonExistFilter(BgpPolicyFilter):
    """BGP Policy Non-Exist Filter

    Args:
        name (str): Name of filter
        enable (bool): Enable rule.
        match_afi (str): Address Family Identifier
            * ip
            * ipv6
        match_safi (str): Subsequent Address Family Identifier
            * ip
            * ipv6
        match_route_table (str): Route table to match rule
            * unicast
            * multicast
            * both
        match_nexthop (list): Next-hop attributes
        match_from_peer (list): Filter by peer that sent this route
        match_med (int): Multi-Exit Discriminator
        match_as_path_regex (str): AS-path regular expression
        match_community_regex (str): Community AS-path regular expression
        match_extended_community_regex (str): Extended Community AS-path regular expression

    """

    SUFFIX = ENTRY
    CHILDTYPES = ("network.BgpPolicyAddressPrefix",)

    def _setup(self):
        self._xpaths.add_profile(value="/non-exist-filters")

        BgpPolicyFilter._setup(self)


class BgpPolicyAdvertiseFilter(BgpPolicyFilter):
    """BGP Policy Advertise Filter

    Args:
        name (str): Name of filter
        enable (bool): Enable rule.
        match_afi (str): Address Family Identifier
            * ip
            * ipv6
        match_safi (str): Subsequent Address Family Identifier
            * ip
            * ipv6
        match_route_table (str): Route table to match rule
            * unicast
            * multicast
            * both
        match_nexthop (list): Next-hop attributes
        match_from_peer (list): Filter by peer that sent this route
        match_med (int): Multi-Exit Discriminator
        match_as_path_regex (str): AS-path regular expression
        match_community_regex (str): Community AS-path regular expression
        match_extended_community_regex (str): Extended Community AS-path regular expression

    """

    SUFFIX = ENTRY
    CHILDTYPES = ("network.BgpPolicyAddressPrefix",)

    def _setup(self):
        self._xpaths.add_profile(value="/advertise-filters")

        BgpPolicyFilter._setup(self)


class BgpPolicySuppressFilter(BgpPolicyFilter):
    """BGP Policy Suppress Filter

    Args:
        name (str): Name of filter
        enable (bool): Enable rule.
        match_afi (str): Address Family Identifier
            * ip
            * ipv6
        match_safi (str): Subsequent Address Family Identifier
            * ip
            * ipv6
        match_route_table (str): Route table to match rule
            * unicast
            * multicast
            * both
        match_nexthop (list): Next-hop attributes
        match_from_peer (list): Filter by peer that sent this route
        match_med (int): Multi-Exit Discriminator
        match_as_path_regex (str): AS-path regular expression
        match_community_regex (str): Community AS-path regular expression
        match_extended_community_regex (str): Extended Community AS-path regular expression

    """

    SUFFIX = ENTRY
    CHILDTYPES = ("network.BgpPolicyAddressPrefix",)

    def _setup(self):
        self._xpaths.add_profile(value="/suppress-filters")

        BgpPolicyFilter._setup(self)


class BgpPolicyConditionalAdvertisement(VersionedPanObject):
    """BGP Conditional Advertisement Policy

    Args:
        name (str): Name of Conditional Advertisement Policy
        enable (bool): enable prefix-based outbound route filtering.
        used_by (list): peer-groups that use this rule.

    """

    SUFFIX = ENTRY
    CHILDTYPES = (
        "network.BgpPolicyNonExistFilter",
        "network.BgpPolicyAdvertiseFilter",
    )

    def _setup(self):
        self._xpaths.add_profile(value="/policy/conditional-advertisement/policy")

        params = []

        params.append(VersionedParamPath("enable", vartype="yesno"))
        params.append(VersionedParamPath("used_by", vartype="member"))

        self._params = tuple(params)


class BgpPolicyRule(BgpPolicyFilter):
    """Base class for BGP Policy Import/Export Rules

    Do not instantiate this class, use one of:
        * BgpPolicyImportRule
        * BgpPolicyExportRule

    Args:
        name (str): The name
        enable (bool): Enable rule.
        match_afi (str): Address Family Identifier
            * ip
            * ipv6
        match_safi (str): Subsequent Address Family Identifier
            * ip
            * ipv6
        match_route_table (str): Route table to match rule
            * unicast
            * multicast
            * both
        match_nexthop (list): Next-hop attributes
        match_from_peer (list): Filter by peer that sent this route
        match_med (int): Multi-Exit Discriminator
        match_as_path_regex (str): AS-path regular expression
        match_community_regex (str): AS-path regular expression
        match_extended_community_regex (str): AS-path regular expression
        used_by (list): Peer-groups that use this rule.
        action (str): The action
        action_local_preference (int): New local preference value
        action_med (int): New MED value
        action_nexthop (str): Nexthop address
        action_origin (str): New route origin
            * igp
            * egp
            * incomplete
        action_as_path_limit (int): Add AS path limit attribute if it does not exist
        action_as_path_type (str): AS path update options
            * none (string, not to be confused with the Python type None)
            * remove
            * prepend
            * remove-and-prepend
        action_as_path_prepend_times (int): Prepend local AS for specified number of times
            * only valid when action_as_path_type is 'prepend' or 'remove-and-prepend'
        action_community (str): Community update options
            * none (string, not to be confused with the Python type None)
            * remove-all
            * remove-regex
            * append
            * overwrite
        action_community_argument (str): Argument to the action community value if needed
            * None
            * regex
        action_community_modifier (str): Argument to the action community value when type is 'append' or 'overwrite'
            * local-as
            * no-advertise
            * no-export
            * nopeer
            * 32-bit value
            * AS:VAL
        action_extended_community_type (str): Extended community update options
            * none (string, not to be confused with the Python type None)
            * remove-all
            * remove-regex
            * append
            * overwrite
        action_extended_community_argument (str): Argument to the action extended community value if needed

    """

    # SUFFIX = None

    def _setup(self):
        # disabled because this is a base class
        # self._xpaths.add_profile(value='/policy')
        BgpPolicyFilter._setup(self)

        params = list(self._params)

        params.append(VersionedParamPath("used_by", vartype="member"))
        params.append(
            VersionedParamPath(
                "action",
                path="action/{action}",
                default="allow",
                values=("allow", "deny"),
            )
        )
        params.append(
            VersionedParamPath(
                "action_local_preference",
                condition={"action": "allow"},
                path="action/{action}/update/local-preference",
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "action_med",
                condition={"action": "allow"},
                path="action/{action}/update/med",
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "action_nexthop",
                condition={"action": "allow"},
                path="action/{action}/update/nexthop",
            )
        )
        params.append(
            VersionedParamPath(
                "action_origin",
                default="incomplete",
                condition={"action": "allow"},
                path="action/{action}/update/origin",
                values=("igp", "egp", "incomplete"),
            )
        )
        params.append(
            VersionedParamPath(
                "action_as_path_limit",
                condition={"action": "allow"},
                path="action/{action}/update/as-path-limit",
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "action_as_path_type",
                condition={"action": "allow"},
                default="none",
                path="action/{action}/update/as-path/{action_as_path_type}",
                values=("none", "remove", "prepend", "remove-and-prepend"),
            )
        )
        params.append(
            VersionedParamPath(
                "action_as_path_prepend_times",
                condition={
                    "action": "allow",
                    "action_as_path_type": ["prepend", "remove-and-prepend"],
                },
                path="action/{action}/update/as-path/{action_as_path_type}",
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "action_community_type",
                condition={"action": "allow"},
                default="none",
                path="action/{action}/update/community/{action_community_type}",
                values=("none", "remove-all", "remove-regex", "append", "overwrite"),
            )
        )
        params.append(
            VersionedParamPath(
                "action_community_argument",
                default=None,
                condition={
                    "action": "allow",
                    "action_community_type": ["remove-regex"],
                },
                path="action/{action}/update/community/{action_community_type}",
            )
        )
        params.append(
            VersionedParamPath(
                "action_community_modifier",
                default=None,
                condition={
                    "action": "allow",
                    "action_community_type": ["append", "overwrite"],
                },
                path="action/{action}/update/community/{action_community_type}",
                vartype="member",
            )
        )
        params.append(
            VersionedParamPath(
                "action_extended_community_type",
                condition={"action": "allow"},
                default="none",
                path="action/{action}/update/extended-community/{action_extended_community_type}",
                values=("none", "remove-all", "remove-regex", "append", "overwrite"),
            )
        )
        params.append(
            VersionedParamPath(
                "action_extended_community_argument",
                default=None,
                condition={
                    "action": "allow",
                    "action_extended_community_type": [
                        "remove-regex",
                        "append",
                        "overwrite",
                    ],
                },
                path="action/{action}/update/extended-community/{action_extended_community_type}",
            )
        )

        self._params = tuple(params)


class BgpPolicyImportRule(BgpPolicyRule):
    """BGP Policy Import Rule

    Args:
        name (str): The name
        enable (bool): Enable rule.
        match_afi (str): Address Family Identifier
            * ip
            * ipv6
        match_safi (str): Subsequent Address Family Identifier
            * ip
            * ipv6
        match_route_table (str): Route table to match rule
            * unicast
            * multicast
            * both
        match_nexthop (list): Next-hop attributes
        match_from_peer (list): Filter by peer that sent this route
        match_med (int): Multi-Exit Discriminator
        match_as_path_regex (str): AS-path regular expression
        match_community_regex (str): AS-path regular expression
        match_extended_community_regex (str): AS-path regular expression
        used_by (list): Peer-groups that use this rule.
        action (str): The action
        action_local_preference (int): New local preference value
        action_med (int): New MED value
        action_nexthop (str): Nexthop address
        action_origin (str): New route origin
            * igp
            * egp
            * incomplete
        action_as_path_limit (int): Add AS path limit attribute if it does not exist
        action_as_path_type (str): AS path update options
            * none (string, not to be confused with the Python type None)
            * remove
            * prepend
            * remove-and-prepend
        action_as_path_prepend_times (int): Prepend local AS for specified number of times
            * only valid when action_as_path_type is 'prepend' or 'remove-and-prepend'
        action_community_type (str): Community update options
            * none (string, not to be confused with the Python type None)
            * remove-all
            * remove-regex
            * append
            * overwrite
        action_community_argument (str): Argument to the action community value if needed
            * None
            * regex
        action_community_modifier (str): Argument to the action community value when type is 'append' or 'overwrite'
            * local-as
            * no-advertise
            * no-export
            * nopeer
            * 32-bit value
            * AS:VAL
        action_extended_community_type (str): Extended community update options
            * none (string, not to be confused with the Python type None)
            * remove-all
            * remove-regex
            * append
            * overwrite
        action_extended_community_argument (str): Argument to the action extended community value if needed
        action_dampening (str): Route flap dampening profile
        action_weight (int): New weight value

    """

    SUFFIX = ENTRY
    CHILDTYPES = ("network.BgpPolicyAddressPrefix",)

    def _setup(self):
        self._xpaths.add_profile(value="/policy/import/rules")

        BgpPolicyRule._setup(self)

        params = list(self._params)

        params.append(
            VersionedParamPath(
                "action_dampening",
                path="action/{action}/dampening",
                condition={"action": "allow"},
            )
        )
        params.append(
            VersionedParamPath(
                "action_weight",
                path="action/{action}/update/weight",
                condition={"action": "allow"},
                vartype="int",
            )
        )

        self._params = tuple(params)


class BgpPolicyExportRule(BgpPolicyRule):
    """BGP Policy Export Rule

    Args:
        name (str): The name
        enable (bool): Enable rule.
        match_afi (str): Address Family Identifier
            * ip
            * ipv6
        match_safi (str): Subsequent Address Family Identifier
            * ip
            * ipv6
        match_route_table (str): Route table to match rule
            * unicast
            * multicast
            * both
        match_nexthop (list): Next-hop attributes
        match_from_peer (list): Filter by peer that sent this route
        match_med (int): Multi-Exit Discriminator
        match_as_path_regex (str): AS-path regular expression
        match_community_regex (str): AS-path regular expression
        match_extended_community_regex (str): AS-path regular expression
        used_by (list): Peer-groups that use this rule.
        action (str): The action
        action_local_preference (int): New local preference value
        action_med (int): New MED value
        action_nexthop (str): Nexthop address
        action_origin (str): New route origin
            * igp
            * egp
            * incomplete
        action_as_path_limit (int): Add AS path limit attribute if it does not exist
        action_as_path_type (str): AS path update options
            * none (string, not to be confused with the Python type None)
            * remove
            * prepend
            * remove-and-prepend
        action_as_path_prepend_times (int): Prepend local AS for specified number of times
            * only valid when action_as_path_type is 'prepend' or 'remove-and-prepend'
        action_community_type (str): Community update options
            * none (string, not to be confused with the Python type None)
            * remove-all
            * remove-regex
            * append
            * overwrite
        action_community_argument (str): Argument to the action community value if needed
            * None
            * regex
        action_community_modifier (str): Argument to the action community value when type is 'append' or 'overwrite'
            * local-as
            * no-advertise
            * no-export
            * nopeer
            * 32-bit value
            * AS:VAL
        action_extended_community_type (str): Extended community update options
            * none (string, not to be confused with the Python type None)
            * remove-all
            * remove-regex
            * append
            * overwrite
        action_extended_community_argument (str): Argument to the action extended community value if needed

    """

    SUFFIX = ENTRY
    CHILDTYPES = ("network.BgpPolicyAddressPrefix",)

    def _setup(self):
        self._xpaths.add_profile(value="/policy/export/rules")

        BgpPolicyRule._setup(self)


class BgpPolicyAddressPrefix(VersionedPanObject):
    """BGP Policy Address Prefix with Exact

    Args:
        name (str): address prefix
        exact (str): match exact prefix length

    """

    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(value="/match/address-prefix")

        params = []

        params.append(VersionedParamPath("exact", default=None, vartype="yesno"))

        self._params = tuple(params)


class BgpPolicyAggregationAddress(VersionedPanObject):
    """BGP Policy Aggregation Address

    Args:
        name (str): Sddress prefix
        enable (bool): Enable aggregation for this prefix
        prefix (str): Aggregating address prefix
        summary (bool): Summarize route
        as_set (bool): Generate AS-set attribute
        attr_local_preference (int): New local preference value
        attr_med (int): New MED value
        attr_weight (int): New weight value
        attr_nexthop (str): Nexthop address
        attr_origin (str): New route origin
            * igp
            * egp
            * incomplete
        attr_as_path_limit (int): Add AS path limit attribute if it does not exist
        attr_as_path_type (str): AS path update options
            * none (string, not to be confused with the Python type None)
            * remove
            * prepend
            * remove-and-prepend
        attr_as_path_prepend_times (int): Prepend local AS for specified number of times
            * only valid when attr_as_path_type is 'prepend' or 'remove-and-prepend'
        attr_community_type (str): Community update options
            * none (string, not to be confused with the Python type None)
            * remove-all
            * remove-regex
            * append
            * overwrite
        attr_community_argument (str): Argument to the attr community value if needed
            * None
            * local-as
            * no-advertise
            * no-export
            * nopeer
            * regex
            * 32-bit value
            * AS:VAL
        attr_extended_community_type (str): Extended community update options
            * none (string, not to be confused with the Python type None)
            * remove-all
            * remove-regex
            * append
            * overwrite
        attr_extended_community_argument (str): Argument to the attr extended community value if needed

    """

    SUFFIX = ENTRY
    CHILDTYPES = (
        "network.BgpPolicySuppressFilter",
        "network.BgpPolicyAdvertiseFilter",
    )

    def _setup(self):
        self._xpaths.add_profile(value="/policy/aggregation/address")

        params = []

        params.append(VersionedParamPath("enable", default=True, vartype="yesno"))
        params.append(VersionedParamPath("prefix"))
        params.append(VersionedParamPath("summary", default=False, vartype="yesno"))
        params.append(VersionedParamPath("as_set", default=False, vartype="yesno"))
        params.append(
            VersionedParamPath(
                "attr_local_preference",
                condition={"attr": "allow"},
                path="aggregate-route-attributes/local-preference",
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "attr_med",
                condition={"attr": "allow"},
                path="aggregate-route-attributes/med",
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "attr_weight",
                condition={"attr": "allow"},
                path="aggregate-route-attributes/weight",
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "attr_nexthop",
                condition={"attr": "allow"},
                path="aggregate-route-attributes/nexthop",
            )
        )
        params.append(
            VersionedParamPath(
                "attr_origin",
                default="incomplete",
                condition={"attr": "allow"},
                path="aggregate-route-attributes/origin",
                values=("igp", "egp", "incomplete"),
            )
        )
        params.append(
            VersionedParamPath(
                "attr_as_path_limit",
                condition={"attr": "allow"},
                path="aggregate-route-attributes/as-path-limit",
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "attr_as_path_type",
                condition={"attr": "allow"},
                default="none",
                path="aggregate-route-attributes/as-path/{attr_as_path_type}",
                values=("none", "remove", "prepend", "remove-and-prepend"),
            )
        )
        params.append(
            VersionedParamPath(
                "attr_as_path_prepend_times",
                condition={
                    "attr": "allow",
                    "attr_as_path_type": ["prepend", "remove-and-prepend"],
                },
                path="aggregate-route-attributes/as-path/{attr_as_path_type}",
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "attr_community_type",
                condition={"attr": "allow"},
                default="none",
                path="aggregate-route-attributes/community/{attr_community_type}",
                values=("none", "remove-all", "remove-regex", "append", "overwrite"),
            )
        )
        params.append(
            VersionedParamPath(
                "attr_community_argument",
                default=None,
                condition={
                    "attr": "allow",
                    "attr_community_type": ["remove-regex", "append", "overwrite"],
                },
                path="aggregate-route-attributes/community/{attr_community_type}",
            )
        )
        params.append(
            VersionedParamPath(
                "attr_extended_community_type",
                condition={"attr": "allow"},
                default="none",
                path="aggregate-route-attributes/extended-community/{attr_extended_community_type}",
                values=("none", "remove-all", "remove-regex", "append", "overwrite"),
            )
        )
        params.append(
            VersionedParamPath(
                "attr_extended_community_argument",
                default=None,
                condition={
                    "attr": "allow",
                    "attr_extended_community_type": [
                        "remove-regex",
                        "append",
                        "overwrite",
                    ],
                },
                path="aggregate-route-attributes/extended-community/{attr_extended_community_type}",
            )
        )

        self._params = tuple(params)


class BgpRedistributionRule(VersionedPanObject):
    """BGP Policy Address Prefix with Exact

    Args:
        name (str): Redistribution profile name
        enable (bool): Enable redistribution rule.
        address_family_identifier (str): Select redistribution profile type
            * ipv4
            * ipv6
        route_table (str): Select destination SAFI for redistribution
            * unicast
            * multicast
            * both
        set_origin (str): Add the ORIGIN path attribute
            * igp
            * egp
            * incomplete
        set_med (int): Add the MULTI_EXIT_DISC path attribute
        set_local_preference (int): Add the LOCAL_PREF path attribute
        set_as_path_limit (int): Add the AS_PATHLIMIT path attribute
        set_community (list): Add the COMMUNITY path attribute
        set_extended_community (list): Add the EXTENDED COMMUNITY path attribute
        metric (int): Metric value

    """

    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(value="/redist-rules")

        params = []

        params.append(VersionedParamPath("enable", vartype="yesno"))
        params.append(
            VersionedParamPath(
                "address_family_identifier", default="ipv4", values=("ipv4", "ipv6")
            )
        )
        params.append(
            VersionedParamPath(
                "route_table",
                default="unicast",
                values=("unicast", "multicast", "both"),
            )
        )
        params.append(
            VersionedParamPath(
                "set_origin", default="incomplete", values=("igp", "egp", "incomplete")
            )
        )
        params.append(VersionedParamPath("set_med", vartype="int"))
        params.append(VersionedParamPath("set_local_preference", vartype="int"))
        params.append(VersionedParamPath("set_as_path_limit", vartype="int"))
        params.append(VersionedParamPath("set_community", vartype="member"))
        params.append(VersionedParamPath("set_extended_community", vartype="member"))
        params.append(VersionedParamPath("metric", vartype="int"))

        self._params = tuple(params)


class ManagementProfile(VersionedPanObject):
    """Interface management provile.

    Add to any of the following interfaces:

    * Layer3Subinterface
    * EthernetInterface
    * AggregateInterface
    * VlanInterface
    * LoopbackInterface
    * TunnelInterface

    Args:
        name (str): The name
        ping (bool): Enable ping
        telnet (bool): Enable telnet
        ssh (bool): Enable ssh
        http (bool): Enable http
        http_ocsp (bool): Enable http-ocsp
        https (bool): Enable https
        snmp (bool): Enable snmp
        response_pages (bool): Enable response pages
        userid_service (bool): Enable userid service
        userid_syslog_listener_ssl (bool): Enable userid syslog listener ssl
        userid_syslog_listener_udp (bool): Enable userid syslog listener udp
        permitted_ip (list): The list of permitted IP addresses

    """

    ROOT = Root.DEVICE
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/network/profiles/interface-management-profile")
        self._xpaths.add_profile(
            value="{0}/network/profiles/interface-management-profile".format(
                self._TEMPLATE_DEVICE_XPATH
            ),
            parents=("Template", "TemplateStack"),
        )

        # params
        params = []

        yesnos = (
            "ping",
            "telnet",
            "ssh",
            "http",
            "http-ocsp",
            "https",
            "snmp",
            "response-pages",
            "userid-service",
            "userid-syslog-listener-ssl",
            "userid-syslog-listener-udp",
        )
        for yn in yesnos:
            params.append(VersionedParamPath(yn, path=yn, vartype="yesno"))
        params.append(
            VersionedParamPath("permitted-ip", path="permitted-ip", vartype="entry")
        )

        self._params = tuple(params)


class IkeGateway(VersionedPanObject):
    """IKE Gateway.

    Args:
        name: IKE gateway name
        version: (7.0+) ikev1, ikev2, or ikev2-prefered (default: ikev1)
        enable_ipv6 (bool): (7.0+) enable IPv6
        disabled (bool): (7.0+) disable this object
        peer_ip_type: ip, dynamic, or fqdn (8.1+) (default: ip)
        peer_ip_value: the IP for peer_ip_type of 'ip' or 'fqdn'
        interface: local gateway end-point
        local_ip_address_type: ip or floating-ip
        local_ip_address: IP address if interface has multiple addresses
        auth_type: pre-shared-key or certificate (default: pre-shared-key)
        pre_shared_key: The string used as pre-shared key
        local_id_type: ipaddr, fqdn, ufqdn, keyid, or dn
        local_id_value: The value for local_id_type
        peer_id_type: ipaddr, fqdn, ufqdn, keyid, or dn
        peer_id_value: The value for peer_id_type
        peer_id_check: exact or wildcard (default: exact)
        local_cert: Local certificate name
        cert_enable_hash_and_url (bool): (7.0+) Use hash-and-url for local
            certificate.
        cert_base_url: (7.0+) The host and directory part of URL for
            local certificates (http only).
        cert_use_management_as_source (bool): (7.0+) Use management interface IP
            as source to retrieve http certificates
        cert_permit_payload_mismatch (bool): Permit peer identification and
            certificate payload identification mismatch.
        cert_profile: Local certificate name
        cert_enable_strict_validation (bool): Enable strict validation of
            peer's extended key use
        enable_passive_mode (bool): Enable passive mode (responder only)
        enable_nat_traversal (bool): Enable NAT traversal
        nat_traversal_keep_alive (int): sending interval for NAT keep-alive
            packets (in seconds)
        nat_traversal_enable_udp_checksum (bool): enable UDP checksum
        enable_fragmentation (bool): Enable IKE fragmentation
        ikev1_exchange_mode: auto, main, or aggressive
        ikev1_crypto_profile: IKE SA crypto oprofile name
        enable_dead_peer_detection (bool): enable Dead-Peer-Detection
        dead_peer_detection_interval (int): sending interval for probing
            packets (in seconds)
        dead_peer_detection_retry (int): number of retries before disconnection
        ikev1_send_commit_bit (bool): Send commit bit
        ikev1_initial_contact (bool): send initial contact
        ikev2_crypto_profile: (7.0+) IKE SE crypto profile name
        ikev2_cookie_validation (bool): (7.0+) require cookie
        ikev2_send_peer_id (bool): (7.0+) send peer ID
        enable_liveness_check (bool): (7.0+) enable sending empty information
            liveness check message
        liveness_check_interval (int): (7.0+) delay interval before sending
            probing packets (in seconds)

    """

    ROOT = Root.DEVICE
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/network/ike/gateway")
        self._xpaths.add_profile(
            value="{0}/network/ike/gateway".format(self._TEMPLATE_DEVICE_XPATH),
            parents=("Template", "TemplateStack"),
        )

        # params
        params = []

        params.append(VersionedParamPath("version", default="ikev1", exclude=True))
        params[-1].add_profile(
            "7.0.0",
            values=("ikev1", "ikev2", "ikev2-preferred"),
            path="protocol/version",
        )
        params.append(VersionedParamPath("enable_ipv6", exclude=True))
        params[-1].add_profile("7.0.0", path="ipv6", vartype="yesno")
        params.append(VersionedParamPath("disabled", exclude=True))
        params[-1].add_profile("7.0.0", path="disabled", vartype="yesno")
        params.append(
            VersionedParamPath(
                "peer_ip_type",
                values=("ip", "dynamic"),
                default="ip",
                path="peer-address/{peer_ip_type}",
            )
        )
        params[-1].add_profile(
            "8.1.0",
            values=(
                "ip",
                "dynamic",
                "fqdn",
            ),
            path="peer-address/{peer_ip_type}",
        )
        params.append(
            VersionedParamPath(
                "peer_ip_value",
                condition={"peer_ip_type": "ip"},
                path="peer-address/{peer_ip_type}",
            )
        )
        params[-1].add_profile(
            "8.1.0",
            condition={"peer_ip_type": ["ip", "fqdn"]},
            path="peer-address/{peer_ip_type}",
        )
        params.append(VersionedParamPath("interface", path="local-address/interface"))
        params.append(
            VersionedParamPath(
                "local_ip_address_type",
                values=("ip", "floating-ip"),
                path="local-address/{local_ip_address_type}",
            )
        )
        params.append(
            VersionedParamPath(
                "local_ip_address", path="local-address/{local_ip_address_type}"
            )
        )
        params.append(
            VersionedParamPath(
                "auth_type",
                values=("pre-shared-key", "certificate"),
                default="pre-shared-key",
                path="authentication/{auth_type}",
            )
        )
        params.append(
            VersionedParamPath(
                "pre_shared_key",
                condition={"auth_type": "pre-shared-key"},
                vartype="encrypted",
                path="authentication/{auth_type}/key",
            )
        )
        params.append(
            VersionedParamPath(
                "local_id_type",
                values=("ipaddr", "fqdn", "ufqdn", "keyid", "dn"),
                path="local-id/type",
            )
        )
        params.append(VersionedParamPath("local_id_value", path="local-id/id"))
        params.append(
            VersionedParamPath(
                "peer_id_type",
                values=("ipaddr", "fqdn", "ufqdn", "keyid", "dn"),
                path="peer-id/type",
            )
        )
        params.append(VersionedParamPath("peer_id_value", path="peer-id/id"))
        params.append(
            VersionedParamPath(
                "peer_id_check", values=("exact", "wildcard"), path="peer-id/matching"
            )
        )
        params.append(
            VersionedParamPath(
                "local_cert",
                condition={"auth_type": "certificate"},
                path="authentication/{auth_type}/local-certificate",
            )
        )
        params[-1].add_profile(
            "7.0.0",
            condition={"auth_type": "certificate"},
            path="authentication/{auth_type}/local-certificate/name",
        )
        params.append(VersionedParamPath("cert_enable_hash_and_url", exclude=True))
        params[-1].add_profile(
            "7.0.0",
            vartype="yesno",
            condition={"auth_type": "certificate"},
            path="authentication/{auth_type}/local-certificate/hash-and-url/enable",
        )
        params.append(VersionedParamPath("cert_base_url", exclude=True))
        params[-1].add_profile(
            "7.0.0",
            condition={"auth_type": "certificate"},
            path="authentication/{auth_type}/local-certificate/hash-and-url/base-url",
        )
        params.append(VersionedParamPath("cert_use_management_as_source", exclude=True))
        params[-1].add_profile(
            "7.0.0",
            vartype="yesno",
            condition={"auth_type": "certificate"},
            path="authentication/{auth_type}/use-management-as-source",
        )
        params.append(
            VersionedParamPath(
                "cert_permit_payload_mismatch",
                vartype="yesno",
                condition={"auth_type": "certificate"},
                path="authentication/{auth_type}/allow-id-payload-mismatch",
            )
        )
        params.append(
            VersionedParamPath(
                "cert_profile",
                condition={"auth_type": "certificate"},
                path="authentication/{auth_type}/certificate-profile",
            )
        )
        params.append(
            VersionedParamPath(
                "cert_enable_strict_validation",
                vartype="yesno",
                condition={"auth_type": "certificate"},
                path="authentication/{auth_type}/strict-validation-revocation",
            )
        )
        params.append(
            VersionedParamPath(
                "enable_passive_mode",
                vartype="yesno",
                path="protocol-common/passive-mode",
            )
        )
        params.append(
            VersionedParamPath(
                "enable_nat_traversal",
                vartype="yesno",
                path="protocol-common/nat-traversal/enable",
            )
        )
        params.append(
            VersionedParamPath(
                "nat_traversal_keep_alive",
                vartype="int",
                path="protocol-common/nat-traversal/keep-alive-interval",
            )
        )
        params.append(
            VersionedParamPath(
                "nat_traversal_enable_udp_checksum",
                vartype="yesno",
                path="protocol-common/nat-traversal/udp-checksum-enable",
            )
        )
        params.append(
            VersionedParamPath(
                "enable_fragmentation",
                vartype="yesno",
                path="protocol-common/fragmentation/enable",
            )
        )
        params.append(
            VersionedParamPath(
                "ikev1_exchange_mode",
                values=("auto", "main", "aggressive"),
                path="protocol/ikev1/exchange-mode",
            )
        )
        params.append(
            VersionedParamPath(
                "ikev1_crypto_profile", path="protocol/ikev1/ike-crypto-profile"
            )
        )
        params.append(
            VersionedParamPath(
                "enable_dead_peer_detection",
                vartype="yesno",
                path="protocol/ikev1/dpd/enable",
            )
        )
        params.append(
            VersionedParamPath(
                "dead_peer_detection_interval",
                vartype="int",
                path="protocol/ikev1/dpd/interval",
            )
        )
        params.append(
            VersionedParamPath(
                "dead_peer_detection_retry",
                vartype="int",
                path="protocol/ikev1/dpd/retry",
            )
        )
        params.append(
            VersionedParamPath(
                "ikev1_send_commit_bit",
                exclude=True,
                vartype="yesno",
                path="protocol/ikev1/commit-bit",
            )
        )
        params.append(
            VersionedParamPath(
                "ikev1_initial_contact",
                exclude=True,
                vartype="yesno",
                path="protocol/ikev1/initial-contact",
            )
        )
        params.append(VersionedParamPath("ikev2_crypto_profile", exclude=True))
        params[-1].add_profile("7.0.0", path="protocol/ikev2/ike-crypto-profile")
        params.append(VersionedParamPath("ikev2_cookie_validation", exclude=True))
        params[-1].add_profile(
            "7.0.0", vartype="yesno", path="protocol/ikev2/require-cookie"
        )
        params.append(VersionedParamPath("ikev2_send_peer_id", exclude=True))
        params[-1].add_profile(
            "7.0.0", vartype="yesno", exclude=True, path="protocol/ikev2/send-peer-id"
        )
        params.append(VersionedParamPath("enable_liveness_check", exclude=True))
        params[-1].add_profile(
            "7.0.0", vartype="yesno", path="protocol/ikev2/dpd/enable"
        )
        params.append(VersionedParamPath("liveness_check_interval", exclude=True))
        params[-1].add_profile(
            "7.0.0", vartype="int", path="protocol/ikev2/dpd/interval"
        )

        self._params = tuple(params)


class IpsecTunnel(VersionedPanObject):
    """IPSec Tunnel

    A large number of params have prefixes:
        * ak:   Auto Key
        * mk:   Manual Key
        * gps:  GlobalProtect Satellite

    Only attach IpsecTunnelIpv4ProxyId or IpsecTunnelIpv4ProxyId  objects to
    this one if you are using type='auto-key'.

    Args:
        name: IPSec tunnel name
        tunnel_interface: apply IPSec VPN tunnels to tunnel interface
        ipv6 (bool): (7.0+) use IPv6 for the IPSec tunnel
        type: auto-key (default), manual-key, or global-protect-satellite
        ak_ike_gateway (string/list): IKE gateway name
        ak_ipsec_crypto_profile: IPSec crypto profile name
        mk_local_spi: outbound SPI in hex
        mk_interface: interface to terminate tunnel
        mk_remote_spi: inbound SPI in hex
        mk_remote_address: tunnel peer IP address
        mk_local_address_ip: exact IP address if interface has multiple IP
            addresses
        mk_local_address_floating_ip: floating IP address in HA Active-Active
            configuration
        mk_protocol: esp or ah
        mk_auth_type: md5, sha1, sha256, sha384, or sha512
        mk_auth_key: the key for the given mk_auth_type
        mk_esp_encryption: des, 3des, aes128 / aes-128-cbc, aes192 / aes-192-cbc,
            aes256 / aes-256-cbc, or null.  The various "aes" options changed
            in version 7.0 onward.  If you need to make a script that is
            compatible with 6.1 PANOS, then use "set_mk_esp_encryption()".  Passing
            it either "aes128" or "aes-128-cbc" will have it set the appropriate
            string for the given version.
        mk_esp_encryption_key: The ESP encryption key for mk_esp_encryption type
        gps_portal_address: GlobalProtect portal address
        gps_prefer_ipv6 (bool): (8.0+) perfer to register portal in IPv6
        gps_interface: interface to communicate with portal
        gps_interface_ipv4_ip: exact IPv4 IP address if interface has multiple IP
            addresses
        gps_interface_ipv6_ip: (8.0+) exact IPv6 IP address if interface has
            multiple IP addresses
        gps_interface_ipv4_floating_ip: (7.0+) floating IPv4 IP address in HA
            Active-Active configuration
        gps_interface_ipv6_floating_ip: (8.0+) floating IPv6 IP address in HA
            Active-Active configuration
        gps_publish_connected_routes (bool): enable publishing of connected
            and static routes
        gps_publish_routes (str/list): specify list of routes to publish to
            GlobalProtect gateway
        gps_local_certificate: GlobalProtect satellite certificate file name
        gps_certificate_profile: profile for authenticating GlobalProtect
            gateway certificates
        anti_replay (bool): enable anti-replay check on this tunnel
        copy_tos (bool): copy IP TOS bits from inner packet to IPSec
            packet (not recommended)
        copy_flow_label (bool): (7.0+) copy IPv6 flow label for 6in6 tunnel
            from inner packet to IPSec packet (not recommended)
        enable_tunnel_monitor (bool): enable tunnel monitoring on this tunnel
        tunnel_monitor_dest_ip: destination IP to send ICMP probe
        tunnel_monitor_proxy_id: (7.0+) which proxy-id (or proxy-id-v6) the
            monitoring traffic will use
        tunnel_monitor_profile: monitoring action
        disabled (bool): (7.0+) disable the IPSec tunnel

    """

    ROOT = Root.DEVICE
    SUFFIX = ENTRY
    CHILDTYPES = (
        "network.IpsecTunnelIpv4ProxyId",
        "network.IpsecTunnelIpv6ProxyId",
    )

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/network/tunnel/ipsec")
        self._xpaths.add_profile(
            value="{0}/network/tunnel/ipsec".format(self._TEMPLATE_DEVICE_XPATH),
            parents=("Template", "TemplateStack"),
        )

        # params
        params = []

        params.append(VersionedParamPath("tunnel_interface", path="tunnel-interface"))
        params.append(VersionedParamPath("ipv6", exclude=True))
        params[-1].add_profile("7.0.0", vartype="yesno", path="ipv6")
        params.append(
            VersionedParamPath(
                "type",
                default="auto-key",
                path="{type}",
                values=("auto-key", "manual-key", "global-protect-satellite"),
            )
        )
        params.append(
            VersionedParamPath(
                "ak_ike_gateway",
                condition={"type": "auto-key"},
                vartype="entry",
                path="{type}/ike-gateway",
            )
        )
        params.append(
            VersionedParamPath(
                "ak_ipsec_crypto_profile",
                condition={"type": "auto-key"},
                path="{type}/ipsec-crypto-profile",
            )
        )
        params.append(
            VersionedParamPath(
                "mk_local_spi",
                condition={"type": "manual-key"},
                path="{type}/local-spi",
            )
        )
        params.append(
            VersionedParamPath(
                "mk_interface",
                condition={"type": "manual-key"},
                path="{type}/local-address/interface",
            )
        )
        params.append(
            VersionedParamPath(
                "mk_remote_spi",
                condition={"type": "manual-key"},
                path="{type}/remote-spi",
            )
        )
        params.append(
            VersionedParamPath(
                "mk_remote_address",
                condition={"type": "manual-key"},
                path="{type}/peer-address/ip",
            )
        )
        params.append(
            VersionedParamPath(
                "mk_local_address_ip",
                condition={"type": "manual-key"},
                path="{type}/local-address/ip",
            )
        )
        params.append(VersionedParamPath("mk_local_address_floating_ip", exclude=True))
        params[-1].add_profile(
            "7.0.0",
            condition={"type": "manual-key"},
            path="{type}/local-address/floating-ip",
        )
        params.append(
            VersionedParamPath(
                "mk_protocol",
                condition={"type": "manual-key"},
                values=("esp", "ah"),
                path="{type}/{mk_protocol}",
            )
        )
        params.append(
            VersionedParamPath(
                "mk_auth_type",
                condition={"type": "manual-key"},
                values=("md5", "sha1", "sha256", "sha384", "sha512"),
                path="{type}/{mk_protocol}/authentication/{mk_auth_type}",
            )
        )
        params.append(
            VersionedParamPath(
                "mk_auth_key",
                vartype="encrypted",
                condition={"type": "manual-key"},
                path="{type}/{mk_protocol}/authentication/{mk_auth_type}/key",
            )
        )
        params.append(
            VersionedParamPath(
                "mk_esp_encryption",
                values=(
                    "des",
                    "3des",
                    "aes128",
                    "aes192",
                    "aes256",
                    "null",
                ),
                path="{type}/{mk_protocol}/encryption/algorithm",
            )
        )
        params[-1].add_profile(
            "7.0.0",
            condition={"type": "manual-key", "mk_protocol": "esp"},
            values=(
                "des",
                "3des",
                "aes-128-cbc",
                "aes-192-cbc",
                "aes-256-cbc",
                "null",
            ),
            path="{type}/{mk_protocol}/encryption/algorithm",
        )
        params.append(
            VersionedParamPath(
                "mk_esp_encryption_key",
                vartype="encrypted",
                condition={"type": "manual-key", "mk_protocol": "esp"},
                path="{type}/{mk_protocol}/encryption/key",
            )
        )
        params.append(
            VersionedParamPath(
                "gps_portal_address",
                condition={"type": "global-protect-satellite"},
                path="{type}/portal-address",
            )
        )
        params.append(VersionedParamPath("gps_prefer_ipv6", exclude=True))
        params[-1].add_profile(
            "8.0.0",
            vartype="yesno",
            condition={"type": "global-protect-satellite"},
            path="{type}/ipv6-preferred",
        )
        params.append(
            VersionedParamPath(
                "gps_interface",
                condition={"type": "global-protect-satellite"},
                path="{type}/local-address/interface",
            )
        )
        params.append(
            VersionedParamPath(
                "gps_interface_ipv4_ip",
                condition={"type": "global-protect-satellite"},
                path="{type}/local-address/ip",
            )
        )
        params[-1].add_profile(
            "8.0.0",
            condition={"type": "global-protect-satellite"},
            path="{type}/local-address/ip/ipv4",
        )
        params.append(VersionedParamPath("gps_interface_ipv6_ip", exclude=True))
        params[-1].add_profile(
            "8.0.0",
            condition={"type": "global-protect-satellite"},
            path="{type}/local-address/ip/ipv6",
        )
        params.append(
            VersionedParamPath("gps_interface_ipv4_floating_ip", exclude=True)
        )
        params[-1].add_profile(
            "7.0.0",
            condition={"type": "global-protect-satellite"},
            path="{type}/local-address/floating-ip",
        )
        params[-1].add_profile(
            "8.0.0",
            condition={"type": "global-protect-satellite"},
            path="{type}/local-address/floating-ip/ipv4",
        )
        params.append(
            VersionedParamPath("gps_interface_ipv6_floating_ip", exclude=True)
        )
        params[-1].add_profile(
            "8.0.0",
            condition={"type": "global-protect-satellite"},
            path="{type}/local-address/floating-ip/ipv6",
        )
        params.append(
            VersionedParamPath(
                "gps_publish_connected_routes",
                vartype="yesno",
                condition={"type": "global-protect-satellite"},
                path="{type}/publish-connected-routes/enable",
            )
        )
        params.append(
            VersionedParamPath(
                "gps_publish_routes",
                vartype="member",
                condition={"type": "global-protect-satellite"},
                path="{type}/publish-routes",
            )
        )
        params.append(
            VersionedParamPath(
                "gps_local_certificate",
                condition={"type": "global-protect-satellite"},
                path="{type}/external-ca/local-certificate",
            )
        )
        params.append(
            VersionedParamPath(
                "gps_certificate_profile",
                condition={"type": "global-protect-satellite"},
                path="{type}/external-ca/certificate-profile",
            )
        )
        params.append(
            VersionedParamPath(
                "anti_replay", default=True, vartype="yesno", path="anti-replay"
            )
        )
        params.append(VersionedParamPath("copy_tos", vartype="yesno", path="copy-tos"))
        params.append(VersionedParamPath("copy_flow_label", exclude=True))
        params[-1].add_profile("7.0.0", vartype="yesno", path="copy-flow-label")
        params.append(
            VersionedParamPath(
                "enable_tunnel_monitor", vartype="yesno", path="tunnel-monitor/enable"
            )
        )
        params.append(
            VersionedParamPath(
                "tunnel_monitor_dest_ip", path="tunnel-monitor/destination-ip"
            )
        )
        params.append(VersionedParamPath("tunnel_monitor_proxy_id", exclude=True))
        params[-1].add_profile("7.0.0", path="tunnel-monitor/proxy-id")
        params.append(
            VersionedParamPath(
                "tunnel_monitor_profile", path="tunnel-monitor/tunnel-monitor-profile"
            )
        )
        params.append(VersionedParamPath("disabled", exclude=True))
        params[-1].add_profile("7.0.0", vartype="yesno", path="disabled")

        self._params = tuple(params)

    def set_mk_esp_encryption(self, value):
        """Version agnostic set for mk_esp_encryption.

        This object should be connected to a panos.Firewall before
        invocation.

        Valid values include the following:
            * des
            * 3des
            * aes128
            * aes-128-cbc
            * aes192
            * aes-192-cbc
            * aes256
            * aes-256-cbc
            * null

        Raises:
            PanDeviceNotSet: if there is no Firewall in the object tree
            ValueError: if value is not one of the above

        """
        # Some values are constant across versioning, so set them outright.
        if value in ("des", "3des", "null"):
            self.mk_esp_encryption = value
            return

        # Get the version specific values for mk_esp_encryption.
        self.nearest_pandevice()
        vals = self.about("mk_esp_encryption")["About"]["Values"]

        # Normalize the value.
        for masks in (
            ("aes128", "aes-128-cbc"),
            ("aes192", "aes-192-cbc"),
            ("aes256", "aes-256-cbc"),
        ):
            if value in masks:
                break
        else:
            raise ValueError("Unknown encryption type: {0}".format(value))

        # Set the version specific encryption type.
        for x in vals:
            if x in masks:
                self.mk_esp_encryption = x
                break


class IpsecTunnelIpv4ProxyId(VersionedPanObject):
    """IKEv1 proxy-id for auto-key IPSec tunnels.

    Args:
        name: The proxy ID
        local: IP subnet or IP address represents local network
        remote: IP subnet or IP address represents remote network
        any_protocol (bool): Any protocol
        number_protocol (int): Numbered Protocol: protocol number (1-254)
        tcp_local_port (int): Protocol TCP: local port
        tcp_remote_port (int): Protocol TCP: remote port
        udp_local_port (int): Protocol UDP: local port
        udp_remote_port (int): Protocol UDP: remote port

    """

    ROOT = Root.DEVICE
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/auto-key/proxy-id")
        self._xpaths.add_profile(
            value="{0}/auto-key/proxy-id".format(self._TEMPLATE_DEVICE_XPATH),
            parents=("Template", "TemplateStack"),
        )

        # params
        params = []

        params.append(VersionedParamPath("local", path="local"))
        params.append(VersionedParamPath("remote", path="remote"))
        params.append(
            VersionedParamPath("any_protocol", vartype="exist", path="protocol/any")
        )
        params.append(
            VersionedParamPath("number_protocol", vartype="int", path="protocol/number")
        )
        params.append(
            VersionedParamPath(
                "tcp_local_port", vartype="int", path="protocol/tcp/local-port"
            )
        )
        params.append(
            VersionedParamPath(
                "tcp_remote_port", vartype="int", path="protocol/tcp/remote-port"
            )
        )
        params.append(
            VersionedParamPath(
                "udp_local_port", vartype="int", path="protocol/udp/local-port"
            )
        )
        params.append(
            VersionedParamPath(
                "udp_remote_port", vartype="int", path="protocol/udp/remote-port"
            )
        )

        self._params = tuple(params)


class IpsecTunnelIpv6ProxyId(VersionedPanObject):
    """IKEv1 IPv6 proxy-id for auto-key IPSec tunnels.

    NOTE:  Only supported in 7.0 and forward.

    Args:
        name: The proxy ID
        local: IP subnet or IP address represents local network
        remote: IP subnet or IP address represents remote network
        any_protocol (bool): Any protocol
        number_protocol (int): Numbered Protocol: protocol number (1-254)
        tcp_local_port (int): Protocol TCP: local port
        tcp_remote_port (int): Protocol TCP: remote port
        udp_local_port (int): Protocol UDP: local port
        udp_remote_port (int): Protocol UDP: remote port

    """

    ROOT = Root.DEVICE
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/auto-key/proxy-id-v6")
        self._xpaths.add_profile(
            value="{0}/auto-key/proxy-id-v6".format(self._TEMPLATE_DEVICE_XPATH),
            parents=("Template", "TemplateStack"),
        )

        # params
        params = []

        params.append(VersionedParamPath("local", path="local"))
        params.append(VersionedParamPath("remote", path="remote"))
        params.append(
            VersionedParamPath("any_protocol", vartype="exist", path="protocol/any")
        )
        params.append(
            VersionedParamPath("number_protocol", vartype="int", path="protocol/number")
        )
        params.append(
            VersionedParamPath(
                "tcp_local_port", vartype="int", path="protocol/tcp/local-port"
            )
        )
        params.append(
            VersionedParamPath(
                "tcp_remote_port", vartype="int", path="protocol/tcp/remote-port"
            )
        )
        params.append(
            VersionedParamPath(
                "udp_local_port", vartype="int", path="protocol/udp/local-port"
            )
        )
        params.append(
            VersionedParamPath(
                "udp_remote_port", vartype="int", path="protocol/udp/remote-port"
            )
        )

        self._params = tuple(params)


class IpsecCryptoProfile(VersionedPanObject):
    """IPSec SA proposals.

    Args:
        name: IPSec crypto profile name
        esp_encryption (string/list): des, 3des, null, aes128 / aes-128-cbc,
            aes192 / aes-192-cbc, aes256 / aes-256-cbc, aes-128-gcm (7.0+), or
            aes-256-gcm (7.0+).  If you need to write a script that works older
            than 7.0 firewalls, then please use set_esp_encryption().
        esp_authentication (string/list): none, md5, sha1, sha256, sha384, or
            sha512
        ah_authentication (string/list): md5, sha1, sha256, sha384, or sha512
        dh_group: no-pfs, group1, group2, group5, group14, group19, or group20
        lifetime_seconds (int): IPSec SA lifetime in seconds
        lifetime_minutes (int): IPSec SA lifetime in minutes
        lifetime_hours (int): IPSec SA lifetime in hours
        lifetime_days (int): IPSec SA lifetime in days
        lifesize_kb (int): IPSec SA lifesize in kilobytes (KB)
        lifesize_mb (int): IPSec SA lifesize in megabytes (MB)
        lifesize_gb (int): IPSec SA lifesize in gigabytes (GB)
        lifesize_tb (int): IPSec SA lifesize in terabytes (TB)

    """

    ROOT = Root.DEVICE
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(
            value="/network/ike/crypto-profiles/ipsec-crypto-profiles"
        )
        self._xpaths.add_profile(
            value="{0}/network/ike/crypto-profiles/ipsec-crypto-profiles".format(
                self._TEMPLATE_DEVICE_XPATH
            ),
            parents=("Template", "TemplateStack"),
        )

        # params
        params = []

        params.append(
            VersionedParamPath(
                "esp_encryption",
                vartype="member",
                path="esp/encryption",
                values=("des", "3des", "aes128", "aes192", "aes256", "null"),
            )
        )
        params[-1].add_profile(
            "7.0.0",
            vartype="member",
            path="esp/encryption",
            values=(
                "des",
                "3des",
                "aes-128-cbc",
                "aes-192-cbc",
                "aes-256-cbc",
                "aes-128-gcm",
                "aes-256-gcm",
                "null",
            ),
        )
        params.append(
            VersionedParamPath(
                "esp_authentication",
                vartype="member",
                path="esp/authentication",
                values=("none", "md5", "sha1", "sha256", "sha384", "sha512"),
            )
        )
        params.append(
            VersionedParamPath(
                "ah_authentication",
                vartype="member",
                path="ah/authentication",
                values=("md5", "sha1", "sha256", "sha384", "sha512"),
            )
        )
        params.append(
            VersionedParamPath(
                "dh_group",
                path="dh-group",
                values=(
                    "no-pfs",
                    "group1",
                    "group2",
                    "group5",
                    "group14",
                    "group19",
                    "group20",
                ),
            )
        )
        params.append(
            VersionedParamPath(
                "lifetime_seconds", vartype="int", path="lifetime/seconds"
            )
        )
        params.append(
            VersionedParamPath(
                "lifetime_minutes", vartype="int", path="lifetime/minutes"
            )
        )
        params.append(
            VersionedParamPath("lifetime_hours", vartype="int", path="lifetime/hours")
        )
        params.append(
            VersionedParamPath("lifetime_days", vartype="int", path="lifetime/days")
        )
        params.append(
            VersionedParamPath("lifesize_kb", vartype="int", path="lifesize/kb")
        )
        params.append(
            VersionedParamPath("lifesize_mb", vartype="int", path="lifesize/mb")
        )
        params.append(
            VersionedParamPath("lifesize_gb", vartype="int", path="lifesize/gb")
        )
        params.append(
            VersionedParamPath("lifesize_tb", vartype="int", path="lifesize/tb")
        )

        self._params = tuple(params)

    def set_esp_encryption(self, value):
        """Version agnostic set for esp_encryption.

        This object should be connected to a panos.Firewall before
        invocation.

        Valid values include the following:
            * des
            * 3des
            * aes128
            * aes-128-cbc
            * aes192
            * aes-192-cbc
            * aes256
            * aes-256-cbc
            * aes-128-gcm (7.0+)
            * aes-256-gcm (7.0+)
            * null

        Args:
            value (string/list): values to put in esp_encryption

        Raises:
            PanDeviceNotSet: if there is no Firewall in the object tree
            ValueError: if value is not one of the above, or you attempt
                to configure aes-128-gcm or aes-256-gcm with this object
                connected to a PANOS 6.1 firewall.

        """
        normalized = []

        # Make sure there is a pandevice set such that we can get versioning.
        self.nearest_pandevice()

        for token in string_or_list(value):
            # Some values are constant across versioning.
            if token in ("des", "3des", "null"):
                normalized.append(token)
                continue

            # Get the version specific values for mk_esp_encryption.
            vals = self.about("esp_encryption")["About"]["Values"]

            # Normalize the value.
            for masks in (
                ("aes128", "aes-128-cbc"),
                ("aes192", "aes-192-cbc"),
                ("aes256", "aes-256-cbc"),
                ("aes-128-gcm",),
                ("aes-256-gcm",),
            ):
                if token in masks:
                    break
            else:
                raise ValueError("Unknown encryption type: {0}".format(token))

            # Set the version specific encryption type.
            for x in vals:
                if x in masks:
                    normalized.append(x)
                    break
            else:
                raise ValueError(
                    "ESP encryption {0} not supported in this version".format(token)
                )

        self.esp_encryption = normalized


class IkeCryptoProfile(VersionedPanObject):
    """IKE SA proposal.

    Args:
        name: IKE crypto profile name
        dh_group (string/list): phase-1 DH group:  group1, group2, group5,
            group14, group19 (7.0+), or group20 (7.0+).
        authentication (string/list): hashing algorithm: md5, sha1, sha256,
            sha384, or sha512.
        encryption (string/list): encryption algorithm: des (7.1+), 3des,
            aes128 / aes-128-cbc, aes192 / aes-192-cbc, or
            aes256 / aes-256-cbc.  If you need to be able to work with older
            than 7.0 firewalls, then use set_encryption().
        lifetime_seconds (int): IKE SA lifetime in seconds
        lifetime_minutes (int): IKE SA lifetime in minutes
        lifetime_hours (int): IKE SA lifetime in hours
        lifetime_days (int): IKE SA lifetime in days
        authentication_multiple (int): (7.0+) IKEv2 SA reauthentication
            interval equals authentication_multiple * lifetime; 0 means
            reauthentication is disabled.

    """

    ROOT = Root.DEVICE
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(
            value="/network/ike/crypto-profiles/ike-crypto-profiles"
        )
        self._xpaths.add_profile(
            value="{0}/network/ike/crypto-profiles/ike-crypto-profiles".format(
                self._TEMPLATE_DEVICE_XPATH
            ),
            parents=("Template", "TemplateStack"),
        )

        # params
        params = []

        params.append(
            VersionedParamPath(
                "dh_group",
                vartype="member",
                path="dh-group",
                values=("group1", "group2", "group5", "group14"),
            )
        )
        params[-1].add_profile(
            "7.0.0",
            vartype="member",
            path="dh-group",
            values=("group1", "group2", "group5", "group14", "group19", "group20"),
        )
        params.append(
            VersionedParamPath(
                "authentication",
                vartype="member",
                path="hash",
                values=("md5", "sha1", "sha256", "sha384", "sha512"),
            )
        )
        params.append(
            VersionedParamPath(
                "encryption",
                vartype="member",
                path="encryption",
                values=("3des", "aes128", "aes192", "aes256"),
            )
        )
        params[-1].add_profile(
            "7.0.0",
            vartype="member",
            path="encryption",
            values=("3des", "aes-128-cbc", "aes-192-cbc", "aes-256-cbc"),
        )
        params[-1].add_profile(
            "7.1.0",
            vartype="member",
            path="encryption",
            values=("des", "3des", "aes-128-cbc", "aes-192-cbc", "aes-256-cbc"),
        )
        params.append(
            VersionedParamPath(
                "lifetime_seconds", vartype="int", path="lifetime/seconds"
            )
        )
        params.append(
            VersionedParamPath(
                "lifetime_minutes", vartype="int", path="lifetime/minutes"
            )
        )
        params.append(
            VersionedParamPath("lifetime_hours", vartype="int", path="lifetime/hours")
        )
        params.append(
            VersionedParamPath("lifetime_days", vartype="int", path="lifetime/days")
        )
        params.append(VersionedParamPath("authentication_multiple", exclude=True))
        params[-1].add_profile("7.0.0", vartype="int", path="authentication-multiple")

        self._params = tuple(params)

    def set_encryption(self, value):
        """Version agnostic set for encryption.

        This object should be connected to a panos.Firewall before
        invocation.

        Valid values include the following:
            * des (7.1+)
            * 3des
            * aes128
            * aes-128-cbc
            * aes192
            * aes-192-cbc
            * aes256
            * aes-256-cbc

        Raises:
            PanDeviceNotSet: if there is no Firewall in the object tree
            ValueError: if value is not one of the above, or you attempt
                to configure 3des with this object connected to a PANOS
                7.0 or earlier firewall.

        """
        normalized = []

        # Make sure there is a pandevice set such that we can get versioning.
        self.nearest_pandevice()

        for token in string_or_list(value):
            # Some values are constant across versioning.
            if token in ("3des"):
                normalized.append(token)
                continue

            # Get the version specific values for mk_esp_encryption.
            vals = self.about("encryption")["About"]["Values"]

            # Normalize the value.
            for masks in (
                ("3des",),
                ("aes128", "aes-128-cbc"),
                ("aes192", "aes-192-cbc"),
                ("aes256", "aes-256-cbc"),
            ):
                if token in masks:
                    break
            else:
                raise ValueError("Unknown encryption type: {0}".format(token))

            # Set the version specific encryption type.
            for x in vals:
                if x in masks:
                    normalized.append(x)
                    break
            else:
                raise ValueError(
                    "Encryption {0} not supported in this version".format(token)
                )

        self.encryption = normalized


class GreTunnel(VersionedPanObject):
    """GRE Tunnel configuration.

    Note:  This is valid for PAN-OS 9.0+

    Args:
        name: GRE tunnel name.
        interface: Interface to terminate tunnel.
        local_address_type: Type of local address.  Can be "ip" (default) or
            "floating-ip".
        local_address_value: IP address value.
        peer_address: Peer IP address.
        tunnel_interface: To apply GRE tunnels to tunnel interface.
        ttl (int): TTL.
        copy_tos (bool): Copy IP TOS bits from inner packet to GRE packet.
        enable_keep_alive (bool): Enable tunnel monitoring.
        keep_alive_interval (int): Interval.
        keep_alive_retry (int): Retry.
        keep_alive_hold_timer (int): Hold timer.
        disabled (bool): Disable the GRE tunnel.

    """

    SUFFIX = ENTRY
    ROOT = Root.DEVICE

    def _setup(self):
        self._xpaths.add_profile(value="/network/tunnel/gre")
        self._xpaths.add_profile(
            value="{0}/network/tunnel/gre".format(self._TEMPLATE_DEVICE_XPATH),
            parents=("Template", "TemplateStack"),
        )

        # Hidden when default: all keep alive, ttl
        params = []
        params.append(VersionedParamPath("interface", path="local-address/interface"))
        params.append(
            VersionedParamPath(
                "local_address_type",
                default="ip",
                values=["ip", "floating-ip"],
                path="local-address/{local_address_type}",
            )
        )
        params.append(
            VersionedParamPath(
                "local_address_value", path="local-address/{local_address_type}"
            )
        )
        params.append(VersionedParamPath("peer_address", path="peer-address/ip"))
        params.append(VersionedParamPath("tunnel_interface", path="tunnel-interface"))
        params.append(VersionedParamPath("ttl", default=64, vartype="int", path="ttl"))
        params.append(VersionedParamPath("copy_tos", vartype="yesno", path="copy-tos"))
        params.append(
            VersionedParamPath(
                "enable_keep_alive", vartype="yesno", path="keep-alive/enable"
            )
        )
        params.append(
            VersionedParamPath(
                "keep_alive_interval",
                default=10,
                vartype="int",
                path="keep-alive/interval",
            )
        )
        params.append(
            VersionedParamPath(
                "keep_alive_retry", default=3, vartype="int", path="keep-alive/retry"
            )
        )
        params.append(
            VersionedParamPath(
                "keep_alive_hold_timer",
                default=5,
                vartype="int",
                path="keep-alive/hold-timer",
            )
        )
        params.append(VersionedParamPath("disabled", vartype="yesno", path="disabled"))

        self._params = tuple(params)


class Dhcp(VersionedPanObject):
    """DHCP config.

    Args:
        name (str): Interface name.

    """

    SUFFIX = ENTRY
    ROOT = Root.DEVICE

    CHILDTYPES = ("network.DhcpRelay",)

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/network/dhcp/interface")

        # params
        self._params = ()


class DhcpRelay(VersionedPanObject):
    """DHCP relay config.

    Args:
        name (str): The (interface) name
        enabled (bool): Enabled.
        servers (list): Relay server IP addresses.
        ipv6_enabled (bool): Enable DHCPv6 relay.

    """

    SUFFIX = None
    CHILDTYPES = ("network.DhcpRelayIpv6Address",)

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/relay")

        # params
        params = []

        params.append(
            VersionedParamPath("enabled", vartype="yesno", path="ip/enabled"),
        )
        params.append(
            VersionedParamPath("servers", vartype="member", path="ip/server"),
        )
        params.append(
            VersionedParamPath("ipv6_enabled", vartype="yesno", path="ipv6/enabled"),
        )

        self._params = tuple(params)


class DhcpRelayIpv6Address(VersionedPanObject):
    """DHCP relay IPv6 address.

    Args:
        name (str): DHCP server IPv6 address.
        interface (str): Outgoing interface when using an IPv6 multicast address for
            the DHCPv6 server.

    """

    SUFFIX = ENTRY
    ROOT = Root.DEVICE

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/ipv6/server")

        params = []

        params.append(
            VersionedParamPath("interface", path="interface"),
        )

        self._params = tuple(params)


class LogicalRouter(VsysOperations):
    """Logical router

    Args:
        name (str): Name of logical router
        vrf (str): Name of VRF
    """

    SUFFIX = ENTRY
    CHILDTYPES = ("network.Vrf",)

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/network/logical-router")
        self._xpaths.add_profile(
            value="{0}/network/logical-router".format(self._TEMPLATE_DEVICE_XPATH),
            parents=("Template", "TemplateStack"),
        )

        # xpath imports
        self._xpath_imports.add_profile(value="/network/logical-router")

        # params
        params = []

        params.append(VersionedParamPath("vrf", path="vrf", vartype="entry"))

        self._params = tuple(params)


class Vrf(VsysOperations):
    """VRF

    Args:
        name (str): Name of VRF
        interface (list): List of interface names
        ad_static (int): Administrative distance for this protocol
        ad_static_ipv6 (int): Administrative distance for this protocol
        ad_ospf_inter (int): Administrative distance for this protocol
        ad_ospf_intra (int): Administrative distance for this protocol
        ad_ospf_ext (int): Administrative distance for this protocol
        ad_ospfv3_inter (int): Administrative distance for this protocol
        ad_ospfv3_intra (int): Administrative distance for this protocol
        ad_ospfv3_ext (int): Administrative distance for this protocol
        ad_bgp_internal (int): Administrative distance for this protocol
        ad_bgp_external (int): Administrative distance for this protocol
        ad_bgp_local (int): Administrative distance for this protocol
        ad_rip (int): Administrative distance for this protocol
        bgp_enable (bool): Enable BGP
        bgp_router_id (str): Router id of this BGP instance
        bgp_local_as (str): Local AS number
        bgp_install_route (bool): Populate BGP learned route to global route table
        bgp_enforce_first_as (bool): Enforce First AS
        bgp_fast_external_failover (bool): Immediately reset session if a link to a directly connected external peer goes down
        bgp_ecmp_multi_as (bool): Support multiple AS in ECMP
        bgp_default_local_preference (int): Global Default Local Preference
        bgp_graceful_shutdown (bool): Gracefully Shutdown BGP following RFC-8326
        bgp_always_advertise_network_route (bool): Always advertise network routes even if not present in RIB
        bgp_med_always_compare_med (bool): Always compare MEDs
        bgp_med_deterministic_med_comparison (bool): Deterministic MEDs comparison
        bgp_graceful_restart_enable (bool): Graceful-restart options enabled
        bgp_graceful_restart_stale_route_time (int): Time to remove stale routes after peer restart
        bgp_graceful_max_peer_restart_time (int): Maximum of peer restart time accepted
        bgp_graceful_local_restart_time (int): Local restart time to advertise to peer
        bgp_global_bfd (str): BGP Global BFD Profile
        bgp_redistribution_profile_ipv4_unicast (str): IPv4 Redistribution Profile
        bgp_redistribution_profile_ipv6_unicast (str): IPv6 Redistribution Profile
        ospf_enable (bool): Enable OSPF (Default: True)
        ospf_router_id (str): Router ID in IP format (eg. 1.1.1.1)
        ospf_global_bfd (str): OSPF Global BFD Profile
        ospf_spf_timer (str): SPF timer setting
        ospf_global_if_timer (str): Global protocol timer setting
        ospf_redistribution_profile (str): Redistribution profile setting
        ospf_rfc1583 (bool): RFC 1583 compatibility
        ospf_graceful_restart_enable (bool): Enable OSPF graceful restart
        ospf_graceful_restart_grace_period (int): Graceful restart period
        ospf_graceful_restart_helper_enable (bool): Graceful restart helper enable
        ospf_graceful_restart_strict_lsa_checking (bool): Graceful restart strict lsa checking
        ospf_graceful_restart_max_neighbor_restart_time (int): Graceful restart neighbor restart time
        ospfv3_enable (bool): Enable OSPFv3 (Default: True)
        ospfv3_router_id (str): Router ID in IP format (eg. 1.1.1.1)
        ospfv3_global_bfd (str): OSPFv3 Global BFD Profile
        ospfv3_spf_timer (str): SPF timer setting
        ospfv3_global_if_timer (str): Global protocol timer setting
        ospfv3_redistribution_profile (str): Redistribution profile setting
        ospfv3_disable_transit_traffic (bool): Disable R-Bit and v6-Bit
        ospfv3_graceful_restart_enable (bool): Enable OSPFv3 graceful restart
        ospfv3_graceful_restart_grace_period (int): Graceful restart period
        ospfv3_graceful_restart_helper_enable (bool): Graceful restart helper enable
        ospfv3_graceful_restart_strict_lsa_checking (bool): Graceful restart strict lsa checking
        ospfv3_graceful_restart_max_neighbor_restart_time (int): Graceful restart neighbor restart time
        rib_filter_ipv4_static (str): IPv4 static route map
        rib_filter_ipv4_bgp  (str): IPv4 BGP route map
        rib_filter_ipv4_ospf (str): IPv4 OSPF route map
        rib_filter_ipv6_static (str): IPv6 static route map
        rib_filter_ipv6_bgp (str): IPv6 BGP route map
        rib_filter_ipv6_ospfv3 (str): IPv6 OSPFv3 route map
        ecmp_enable (bool): Enable Equal Cost Multipath
        ecmp_symmetric_return (bool): Allows return packets to egress out of the ingress interface of the flow
        ecmp_strict_source_path (bool): Force VPN traffic to exit interface that the source-ip belongs to
        ecmp_max_path (int): Maxmum number of ECMP paths supported, change this configuration will result in a virtual router restart
        ecmp_algorithm (str): Load balancing algorithm
        ecmp_algorithm_src_only (bool): Only use source address for hash
        ecmp_algorithm_use_port (bool): Use source/destination port for hash
        ecmp_algorithm_hash_seed (int): User-specified hash seed
    """

    SUFFIX = ENTRY
    CHILDTYPES = (
        "network.VrfStaticRoute",
        "network.VrfStaticRouteV6",
        "network.VrfBgpPeerGroup",
        "network.VrfOspfArea",
        "network.VrfOspfv3Area",
        "network.VrfEcmpInterfaceWeight",
        "network.RoutingProfileBfd",
        "network.RoutingProfileBgpAuth",
        "network.RoutingProfileBgpTimer",
        "network.RoutingProfileBgpAddressFamily",
        "network.RoutingProfileBgpDampening",
        "network.RoutingProfileBgpRedistribution",
        "network.RoutingProfileBgpFiltering",
        "network.RoutingProfileOspfAuth",
        "network.RoutingProfileOspfIfTimer",
        "network.RoutingProfileOspfSpfTimer",
        "network.RoutingProfileOspfRedistribution",
        "network.RoutingProfileOspfv3Auth",
        "network.RoutingProfileOspfv3IfTimer",
        "network.RoutingProfileOspfv3SpfTimer",
        "network.RoutingProfileOspfv3Redistribution",
        "network.RoutingProfileFilterAccessList",
        "network.RoutingProfileFilterPrefixList",
        "network.RoutingProfileFilterAsPathAccessList",
        "network.RoutingProfileFilterCommunityList",
        "network.RoutingProfileFilterRouteMaps",
        "network.RoutingProfileFilterRouteMapsRedistribution",
    )

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/vrf")

        # params
        params = []

        params.append(
            VersionedParamPath("interface", path="interface", vartype="member")
        )

        admin_dists = (
            ("ad_static", "static"),
            ("ad_static_ipv6", "static-ipv6"),
            ("ad_ospf_inter", "ospf-inter"),
            ("ad_ospf_intra", "ospf-intra"),
            ("ad_ospf_ext", "ospf-ext"),
            ("ad_ospfv3_inter", "ospfv3-inter"),
            ("ad_ospfv3_intra", "ospfv3-intra"),
            ("ad_ospfv3_ext", "ospfv3-ext"),
            ("ad_bgp_internal", "bgp-internal"),
            ("ad_bgp_external", "bgp-external"),
            ("ad_bgp_local", "bgp-local"),
            ("ad_rip", "rip"),
        )

        for var_name, path in admin_dists:
            params.append(
                VersionedParamPath(var_name, vartype="int", path="admin-dists/" + path)
            )

        params.append(
            VersionedParamPath(
                "bgp_enable", path="bgp/enable", default=False, vartype="yesno"
            )
        )
        params.append(VersionedParamPath("bgp_router_id", path="bgp/router-id"))
        params.append(VersionedParamPath("bgp_local_as", path="bgp/local-as"))
        params.append(
            VersionedParamPath(
                "bgp_install_route",
                path="bgp/install-route",
                default=False,
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "bgp_enforce_first_as",
                path="bgp/enforce-first-as",
                default=True,
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "bgp_fast_external_failover",
                path="bgp/fast-external-failover",
                default=True,
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "bgp_ecmp_multi_as",
                path="bgp/ecmp-multi-as",
                default=False,
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "bgp_default_local_preference",
                path="bgp/default-local-preference",
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "bgp_graceful_shutdown",
                path="bgp/graceful-shutdown",
                default=False,
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "bgp_always_advertise_network_route",
                path="bgp/always-advertise-network-route",
                default=True,
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "bgp_med_always_compare_med",
                path="bgp/med/always-compare-med",
                default=False,
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "bgp_med_deterministic_med_comparison",
                path="bgp/med/deterministic-med-comparison",
                default=True,
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "bgp_graceful_restart_enable",
                path="bgp/graceful-restart/enable",
                default=True,
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "bgp_graceful_restart_stale_route_time",
                path="bgp/graceful-restart/stale-route-time",
                default=120,
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "bgp_graceful_max_peer_restart_time",
                path="bgp/graceful-restart/max-peer-restart-time",
                default=120,
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "bgp_graceful_local_restart_time",
                path="bgp/graceful-restart/local-restart-time",
                default=120,
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "bgp_global_bfd", path="bgp/global-bfd/profile", default="None"
            )
        )
        params.append(
            VersionedParamPath(
                "bgp_redistribution_profile_ipv4_unicast",
                path="bgp/redistribution-profile/ipv4/unicast",
            )
        )
        params.append(
            VersionedParamPath(
                "bgp_redistribution_profile_ipv6_unicast",
                path="bgp/redistribution-profile/ipv6/unicast",
            )
        )

        params.append(
            VersionedParamPath(
                "ospf_enable", default=False, path="ospf/enable", vartype="yesno"
            )
        )
        params.append(
            VersionedParamPath("ospf_router_id", path="ospf/router-id", default=None)
        )
        params.append(
            VersionedParamPath("ospf_global_bfd", path="ospf/global-bfd/profile")
        )
        params.append(VersionedParamPath("ospf_spf_timer", path="ospf/spf-timer"))
        params.append(
            VersionedParamPath("ospf_global_if_timer", path="ospf/global-if-timer")
        )
        params.append(
            VersionedParamPath(
                "ospf_redistribution_profile", path="ospf/redistribution-profile"
            )
        )
        params.append(
            VersionedParamPath(
                "ospf_rfc1583",
                path="ospf/rfc1583",
                default=False,
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "ospf_graceful_restart_enable",
                path="ospf/graceful-restart/enable",
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "ospf_graceful_restart_grace_period",
                path="ospf/graceful-restart/grace-period",
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "ospf_graceful_restart_helper_enable",
                path="ospf/graceful-restart/helper-enable",
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "ospf_graceful_restart_strict_lsa_checking",
                path="ospf/graceful-restart/strict-LSA-checking",
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "ospf_graceful_restart_max_neighbor_restart_time",
                path="ospf/graceful-restart/max-neighbor-restart-time",
                vartype="int",
            )
        )

        params.append(
            VersionedParamPath(
                "ospfv3_enable", default=False, path="ospfv3/enable", vartype="yesno"
            )
        )
        params.append(
            VersionedParamPath(
                "ospfv3_router_id", path="ospfv3/router-id", default=None
            )
        )
        params.append(
            VersionedParamPath("ospfv3_global_bfd", path="ospfv3/global-bfd/profile")
        )
        params.append(VersionedParamPath("ospfv3_spf_timer", path="ospfv3/spf-timer"))
        params.append(
            VersionedParamPath("ospfv3_global_if_timer", path="ospfv3/global-if-timer")
        )
        params.append(
            VersionedParamPath(
                "ospfv3_redistribution_profile",
                path="ospfv3/redistribution-profile",
            )
        )
        params.append(
            VersionedParamPath(
                "ospfv3_disable_transit_traffic",
                path="ospfv3/disable-transit-traffic",
                default=False,
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "ospfv3_graceful_restart_enable",
                path="ospfv3/graceful-restart/enable",
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "ospfv3_graceful_restart_grace_period",
                path="ospfv3/graceful-restart/grace-period",
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "ospfv3_graceful_restart_helper_enable",
                path="ospfv3/graceful-restart/helper-enable",
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "ospfv3_graceful_restart_strict_lsa_checking",
                path="ospfv3/graceful-restart/strict-LSA-checking",
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "ospfv3_graceful_restart_max_neighbor_restart_time",
                path="ospfv3/graceful-restart/max-neighbor-restart-time",
                vartype="int",
            )
        )

        params.append(
            VersionedParamPath(
                "rib_filter_ipv4_static",
                path="rib-filter/ipv4/static",
            )
        )
        params.append(
            VersionedParamPath(
                "rib_filter_ipv4_bgp",
                path="rib-filter/ipv4/bgp",
            )
        )
        params.append(
            VersionedParamPath(
                "rib_filter_ipv4_ospf",
                path="rib-filter/ipv4/ospf",
            )
        )
        params.append(
            VersionedParamPath(
                "rib_filter_ipv6_static",
                path="rib-filter/ipv6/static",
            )
        )
        params.append(
            VersionedParamPath(
                "rib_filter_ipv6_bgp",
                path="rib-filter/ipv6/bgp",
            )
        )
        params.append(
            VersionedParamPath(
                "rib_filter_ipv6_ospfv3",
                path="rib-filter/ipv6/ospfv3",
            )
        )

        params.append(
            VersionedParamPath(
                "ecmp_enable",
                default=False,
                path="ecmp/enable",
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "ecmp_symmetric_return",
                default=False,
                path="ecmp/symmetric-return",
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "ecmp_strict_source_path",
                default=False,
                path="ecmp/strict-source-path",
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "ecmp_max_path", path="ecmp/max-path", default=2, vartype="int"
            )
        )
        params.append(
            VersionedParamPath(
                "ecmp_algorithm",
                values=[
                    "ip-modulo",
                    "ip-hash",
                    "weighted-round-robin",
                    "balanced-round-robin",
                ],
                path="ecmp/algorithm/{ecmp_algorithm}",
            )
        )
        params.append(
            VersionedParamPath(
                "ecmp_algorithm_src_only",
                default=False,
                path="ecmp/algorithm/{ecmp_algorithm}/src-only",
                vartype="yesno",
                condition={"ecmp_algorithm": "ip-hash"},
            )
        )
        params.append(
            VersionedParamPath(
                "ecmp_algorithm_use_port",
                default=False,
                path="ecmp/algorithm/{ecmp_algorithm}/use-port",
                vartype="yesno",
                condition={"ecmp_algorithm": "ip-hash"},
            )
        )
        params.append(
            VersionedParamPath(
                "ecmp_algorithm_hash_seed",
                path="ecmp/algorithm/{ecmp_algorithm}/hash-seed",
                default=0,
                vartype="int",
                condition={"ecmp_algorithm": "ip-hash"},
            )
        )

        self._params = tuple(params)


class RoutingProfileBfd(VersionedPanObject):
    """BFD profile

    Args:
        name (str): The name
        mode (str): BFD operation mode
        min_tx_interval (int): Desired Minimum Tx Interval (ms)
        min_rx_interval (int): Required Minimum Rx Interval (ms)
        detection_multiplier (int): Detection Time Multiplier
        hold_time (int) Hold Time (ms)
        min_received_ttl (int): Minimum accepted TTL on received BFD packet
    """

    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/network/routing-profile/bfd")

        # params
        params = []

        params.append(
            VersionedParamPath(
                "mode",
                default="active",
                values=["active", "passive"],
                path="mode",
            )
        )
        params.append(
            VersionedParamPath(
                "min_tx_interval", default=1000, vartype="int", path="min-tx-interval"
            )
        )
        params.append(
            VersionedParamPath(
                "min_rx_interval", default=1000, vartype="int", path="min-rx-interval"
            )
        )
        params.append(
            VersionedParamPath(
                "detection_multiplier",
                default=3,
                vartype="int",
                path="detection-multiplier",
            )
        )
        params.append(
            VersionedParamPath("hold_time", default=0, vartype="int", path="hold-time")
        )
        params.append(
            VersionedParamPath(
                "min_received_ttl", vartype="int", path="multihop/min-received-ttl"
            )
        )

        self._params = tuple(params)


class VrfStaticRoute(VersionedPanObject):
    """VRF Static Route

    Add to a :class:`panos.network.Vrf` instance.

    Args:
        name (str): The name
        destination (str): Destination network
        nexthop_type (str): ip-address, discard, or next-vr
        nexthop (str): Next hop IP address or Next VR Name
        interface (str): Next hop interface
        admin_dist (str): Administrative distance
        metric (int): Metric (Default: 10)
        enable_path_monitor (bool): Enable Path Monitor
        failure_condition (str): Path Monitor failure condition set 'any' or 'all'
        preemptive_hold_time (int): Path Monitor Preemptive Hold Time in minutes
        bfd_profile (str): Name of the BRF profile
    """

    SUFFIX = ENTRY
    CHILDTYPES = ("network.PathMonitorDestination",)

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/routing-table/ip/static-route")

        # params
        params = []

        params.append(VersionedParamPath("destination", path="destination"))
        params.append(
            VersionedParamPath(
                "nexthop_type",
                default="ip-address",
                values=["discard", "ip-address", "next-lr", "fqdn"],
                path="nexthop/{nexthop_type}",
            )
        )
        params.append(VersionedParamPath("nexthop", path="nexthop/{nexthop_type}"))
        params.append(VersionedParamPath("interface", path="interface"))
        params.append(
            VersionedParamPath("admin_dist", vartype="int", path="admin-dist")
        )
        params.append(
            VersionedParamPath("metric", default=10, vartype="int", path="metric")
        )
        params.append(
            VersionedParamPath(
                "enable_path_monitor", path="path-monitor/enable", vartype="yesno"
            )
        )
        params.append(
            VersionedParamPath(
                "failure_condition",
                values=("all", "any"),
                path="path-monitor/failure-condition",
            )
        )
        params.append(
            VersionedParamPath(
                "preemptive_hold_time", vartype="int", path="path-monitor/hold-time"
            )
        )
        params.append(VersionedParamPath("bfd_profile", path="bfd/profile"))

        self._params = tuple(params)


class VrfStaticRouteV6(VersionedPanObject):
    """VRF Static Route IPv6

    Add to a :class:`panos.network.Vrf` instance.

    Args:
        name (str): The name
        destination (str): Destination network
        nexthop_type (str): ip-address, discard, or next-vr
        nexthop (str): Next hop IP address or Next VR Name
        interface (str): Next hop interface
        admin_dist (str): Administrative distance
        metric (int): Metric (Default: 10)
        enable_path_monitor (bool): Enable Path Monitor
        failure_condition (str): Path Monitor failure condition set 'any' or 'all'
        preemptive_hold_time (int): Path Monitor Preemptive Hold Time in minutes
        bfd_profile (str): Name of the BRF profile
    """

    SUFFIX = ENTRY
    CHILDTYPES = ("network.PathMonitorDestination",)

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/routing-table/ipv6/static-route")

        # params
        params = []

        params.append(VersionedParamPath("destination", path="destination"))
        params.append(
            VersionedParamPath(
                "nexthop_type",
                default="ip-address",
                values=["discard", "ipv6-address", "next-lr", "fqdn"],
                path="nexthop/{nexthop_type}",
            )
        )
        params.append(VersionedParamPath("nexthop", path="nexthop/{nexthop_type}"))
        params.append(VersionedParamPath("interface", path="interface"))
        params.append(
            VersionedParamPath("admin_dist", vartype="int", path="admin-dist")
        )
        params.append(
            VersionedParamPath("metric", default=10, vartype="int", path="metric")
        )
        params.append(
            VersionedParamPath(
                "enable_path_monitor", path="path-monitor/enable", vartype="yesno"
            )
        )
        params.append(
            VersionedParamPath(
                "failure_condition",
                values=("all", "any"),
                path="path-monitor/failure-condition",
            )
        )
        params.append(
            VersionedParamPath(
                "preemptive_hold_time", vartype="int", path="path-monitor/hold-time"
            )
        )
        params.append(VersionedParamPath("bfd_profile", path="bfd/profile"))

        self._params = tuple(params)


class VrfEcmpInterfaceWeight(VersionedPanObject):
    """VRF ECMP interface and weight

    Args:
        name (str): Interface name
        weight (int): Interface ECMP weight
    """

    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/ecmp/algorithm/weighted-round-robin/interface")

        # params
        params = []

        params.append(
            VersionedParamPath("weight", default=100, vartype="int", path="weight")
        )

        self._params = tuple(params)


class VrfOspfArea(VersionedPanObject):
    """VRF OSPF area

    Args:
        name (str): The name
        authentication (str): Authentication profile name
        type (str): Area type
        import_list (str): Import list
        export_list (str): Export list
        inbound_filter_list (str): Inbound filter list
        outbound_filter_list (str): Outbound filter list
        no_summary (bool): No summary
        metric (int): Metric value
        metric_type (str): Metric type
    """

    SUFFIX = ENTRY
    CHILDTYPES = (
        "network.VrfOspfAreaRange",
        "network.VrfOspfAreaInterface",
        "network.VrfOspfAreaVirtualLink",
    )

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/ospf/area")

        # params
        params = []

        params.append(VersionedParamPath("authentication", path="authentication"))
        params.append(
            VersionedParamPath(
                "type",
                path="type/{type}",
                values=["normal", "stub", "nssa"],
                default="normal",
            )
        )
        params.append(
            VersionedParamPath(
                "import_list",
                path="type/{type}/abr/import-list",
                condition={"type": ["normal", "stub", "nssa"]},
            )
        )
        params.append(
            VersionedParamPath(
                "export_list",
                path="type/{type}/abr/export-list",
                condition={"type": ["normal", "stub", "nssa"]},
            )
        )
        params.append(
            VersionedParamPath(
                "inbound_filter_list",
                path="type/{type}/abr/inbound-filter-list",
                condition={"type": ["normal", "stub", "nssa"]},
            )
        )
        params.append(
            VersionedParamPath(
                "outbound_filter_list",
                path="type/{type}/abr/outbound-filter-list",
                condition={"type": ["normal", "stub", "nssa"]},
            )
        )
        params.append(
            VersionedParamPath(
                "no_summary",
                path="type/{type}/no-summary",
                condition={"type": ["stub", "nssa"]},
                vartype="yesno",
                default=False,
            )
        )
        params.append(
            VersionedParamPath(
                "metric",
                path="type/{type}/default-information-originate/metric",
                condition={"type": "nssa"},
            )
        )
        params.append(
            VersionedParamPath(
                "metric_type",
                path="type/{type}/default-information-originate/metric-type",
                values=["type-1", "type-2"],
                condition={"type": "nssa"},
            )
        )

        self._params = tuple(params)


class VrfOspfAreaRange(VersionedPanObject):
    """VRF OSPF area range

    Args:
        name (str): IP Address/Netmask
        substitute (str): Substitute network/prefix
        advertise (bool): Do summarization and advertise
    """

    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/range")

        # params
        params = []

        params.append(
            VersionedParamPath("substitute", path="substitute", vartype="attrib")
        )
        params.append(
            VersionedParamPath(
                "advertise",
                path="advertise",
                vartype="yesno",
                default=True,
            )
        )

        self._params = tuple(params)


class VrfOspfAreaInterface(VersionedPanObject):
    """VRF OSPF area interface

    Args:
        name (str): Interface name
        enable (bool): Enable OSPF on this interface
        mtu_ignore (bool): Ignore mtu when try to establish adjacency
        passive (bool): "Suppress the sending of hello packets in this interface
        priority (int): Priority for OSPF designated router selection
        link_type (str): Link Type
        metric (int): Cost of OSPF interface
        authentication (str): Authentication options
        bfd_profile (str): BFD profile
        timing (str): Protocol timer setting
    """

    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/interface")

        # params
        params = []

        params.append(
            VersionedParamPath("enable", path="enable", vartype="yesno", default=True)
        )
        params.append(
            VersionedParamPath(
                "mtu_ignore",
                path="mtu-ignore",
                vartype="yesno",
                default=False,
            )
        )
        params.append(
            VersionedParamPath(
                "passive",
                path="passive",
                vartype="yesno",
                default=False,
            )
        )
        params.append(
            VersionedParamPath("priority", path="priority", vartype="int", default=1)
        )
        params.append(
            VersionedParamPath(
                "link_type",
                path="link-type/{link_type}",
                values=["broadcast", "p2p", "p2mp"],
                default="broadcast",
            )
        )
        params.append(
            VersionedParamPath("metric", path="metric", vartype="int", default=10)
        )
        params.append(VersionedParamPath("authentication", path="authentication"))
        params.append(VersionedParamPath("bfd_profile", path="bfd/profile"))
        params.append(VersionedParamPath("timing", path="timing"))

        ### TODO: implement neighbor for link type p2mp: ospf -> area -> interface -> link-type -> p2mp

        self._params = tuple(params)


class VrfOspfAreaVirtualLink(VersionedPanObject):
    """VRF OSPF area virtual link

    Args:
        name (str): Virtual link name
        enable (bool): Enable this virtual link
        neighbor_id (str): Neighbor router id for virtual link
        transit_area_id (str): ID of transit area, cannot be backbone, stub or NSSA
        timing (str): Timer profile
        authentication (str): Authentication options
    """

    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/virtual-link")

        # params
        params = []

        params.append(
            VersionedParamPath("enable", path="enable", vartype="yesno", default=True)
        )
        params.append(VersionedParamPath("neighbor_id", path="neighbor-id"))
        params.append(VersionedParamPath("transit_area_id", path="transit-area-id"))
        params.append(VersionedParamPath("timing", path="timing"))
        params.append(VersionedParamPath("authentication", path="authentication"))

        self._params = tuple(params)


class VrfOspfv3Area(VersionedPanObject):
    """VRF OSPFv3 area

    Args:
        name (str): The name
        authentication (str): Authentication profile name
        type (str): Area type
        import_list (str): Import list
        export_list (str): Export list
        inbound_filter_list (str): Inbound filter list
        outbound_filter_list (str): Outbound filter list
        no_summary (bool): No summary
        metric (int): Metric value
        metric_type (str): Metric type
    """

    SUFFIX = ENTRY
    CHILDTYPES = (
        "network.VrfOspfv3AreaRange",
        "network.VrfOspfv3AreaInterface",
        "network.VrfOspfv3AreaVirtualLink",
    )

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/ospfv3/area")

        # params
        params = []

        params.append(VersionedParamPath("authentication", path="authentication"))
        params.append(
            VersionedParamPath(
                "type",
                path="type/{type}",
                values=["normal", "stub", "nssa"],
                default="normal",
            )
        )
        params.append(
            VersionedParamPath(
                "import_list",
                path="type/{type}/abr/import-list",
                condition={"type": ["normal", "stub", "nssa"]},
            )
        )
        params.append(
            VersionedParamPath(
                "export_list",
                path="type/{type}/abr/export-list",
                condition={"type": ["normal", "stub", "nssa"]},
            )
        )
        params.append(
            VersionedParamPath(
                "inbound_filter_list",
                path="type/{type}/abr/inbound-filter-list",
                condition={"type": ["normal", "stub", "nssa"]},
            )
        )
        params.append(
            VersionedParamPath(
                "outbound_filter_list",
                path="type/{type}/abr/outbound-filter-list",
                condition={"type": ["normal", "stub", "nssa"]},
            )
        )
        params.append(
            VersionedParamPath(
                "no_summary",
                path="type/{type}/no-summary",
                condition={"type": ["stub", "nssa"]},
                vartype="yesno",
                default=False,
            )
        )
        params.append(
            VersionedParamPath(
                "metric",
                path="type/{type}/default-information-originate/metric",
                condition={"type": "nssa"},
            )
        )
        params.append(
            VersionedParamPath(
                "metric_type",
                path="type/{type}/default-information-originate/metric-type",
                values=["type-1", "type-2"],
                condition={"type": "nssa"},
            )
        )

        self._params = tuple(params)


class VrfOspfv3AreaRange(VersionedPanObject):
    """VRF OSPFv3 area range

    Args:
        name (str): IP Address/Netmask
        substitute (str): Substitute network/prefix
        advertise (bool): Do summarization and advertise
    """

    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/range")

        # params
        params = []

        params.append(
            VersionedParamPath("substitute", path="substitute", vartype="attrib")
        )
        params.append(
            VersionedParamPath(
                "advertise",
                path="advertise",
                vartype="yesno",
                default=True,
            )
        )

        self._params = tuple(params)


class VrfOspfv3AreaInterface(VersionedPanObject):
    """VRF OSPF area interface

    Args:
        name (str): Interface name
        enable (bool): Enable OSPF on this interface
        mtu_ignore (bool): Ignore mtu when try to establish adjacency
        passive (bool): "Suppress the sending of hello packets in this interface
        priority (int): Priority for OSPF designated router selection
        link_type (str): Link Type
        metric (int): Cost of OSPF interface
        instance_id (str): OSPFv3 instance ID
        authentication (str): Authentication options
        bfd_profile (str): BFD profile
        timing (str): Protocol timer setting
    """

    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/interface")

        # params
        params = []

        params.append(
            VersionedParamPath("enable", path="enable", vartype="yesno", default=True)
        )
        params.append(
            VersionedParamPath(
                "mtu_ignore",
                path="mtu-ignore",
                vartype="yesno",
                default=False,
            )
        )
        params.append(
            VersionedParamPath(
                "passive",
                path="passive",
                vartype="yesno",
                default=False,
            )
        )
        params.append(
            VersionedParamPath("priority", path="priority", vartype="int", default=1)
        )
        params.append(
            VersionedParamPath(
                "link_type",
                path="link-type/{link_type}",
                values=["broadcast", "p2p", "p2mp"],
                default="broadcast",
            )
        )
        params.append(
            VersionedParamPath("metric", path="metric", vartype="int", default=10)
        )
        params.append(VersionedParamPath("instance_id", path="instance-id"))
        params.append(VersionedParamPath("authentication", path="authentication"))
        params.append(VersionedParamPath("bfd_profile", path="bfd/profile"))
        params.append(VersionedParamPath("timing", path="timing"))

        ### TODO: implement neighbor for link type p2mp: ospfv3 -> area -> interface -> link-type -> p2mp

        self._params = tuple(params)


class VrfOspfv3AreaVirtualLink(VersionedPanObject):
    """VRF OSPF area virtual link

    Args:
        name (str): Virtual link name
        enable (bool): Enable this virtual link
        neighbor_id (str): Neighbor router id for virtual link
        transit_area_id (str): ID of transit area, cannot be backbone, stub or NSSA
        timing (str): Timer profile
        authentication (str): Authentication options
    """

    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/virtual-link")

        # params
        params = []

        params.append(
            VersionedParamPath("enable", path="enable", vartype="yesno", default=True)
        )
        params.append(VersionedParamPath("neighbor_id", path="neighbor-id"))
        params.append(VersionedParamPath("transit_area_id", path="transit-area-id"))
        params.append(VersionedParamPath("timing", path="timing"))
        params.append(VersionedParamPath("authentication", path="authentication"))

        self._params = tuple(params)


class VrfBgpPeerGroup(VersionedPanObject):
    """VRF BGP peer group

    Args:
        name (str): Name of the BGP peer group
        enable (bool): Enabled BGP peer group
        type (str): Type of BGP peer group
        address_family_ipv4 (str): IPv4 Address Family
        address_family_ipv6 (str): IPv6 Address Family
        filtering_profile_ipv4 (str): IPv4 Filtering Profile
        filtering_profile_ipv6 (str): IPv6 Filtering Profile
        connection_options_timers (str): Timer Profile Name
        connection_options_multihop (int): Multi-hop value
        connection_options_authentication (str): Authentication Profile Name
        connection_options_dampening (str): Dampening Profile Name
    """

    SUFFIX = ENTRY
    CHILDTYPES = ("network.VrfBgpPeer",)

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/bgp/peer-group")

        # params
        params = []

        params.append(
            VersionedParamPath("enable", path="enable", default=True, vartype="yesno")
        )
        params.append(
            VersionedParamPath(
                "type",
                path="type/{type}",
                values=["ebgp", "ibgp"],
                default="ebgp",
            )
        )
        params.append(
            VersionedParamPath("address_family_ipv4", path="address-family/ipv4")
        )
        params.append(
            VersionedParamPath("address_family_ipv6", path="address-family/ipv6")
        )
        params.append(
            VersionedParamPath("filtering_profile_ipv4", path="filtering-profile/ipv4")
        )
        params.append(
            VersionedParamPath("filtering_profile_ipv6", path="filtering-profile/ipv6")
        )

        params.append(
            VersionedParamPath(
                "connection_options_timers",
                path="connection-options/timers/",
            )
        )
        params.append(
            VersionedParamPath(
                "connection_options_multihop",
                path="connection-options/multihop",
                default=0,
            )
        )
        params.append(
            VersionedParamPath(
                "connection_options_authentication",
                path="connection-options/authentication",
            )
        )
        params.append(
            VersionedParamPath(
                "connection_options_dampening",
                path="connection-options/dampening",
            )
        )

        self._params = tuple(params)


class VrfBgpPeer(VersionedPanObject):
    """VRF BGP peer

    Args:
        name (str): Name of the BGP peer
        enable (bool): Enable BGP peer
        passive (bool): If enabled, open messages are not sent to this peer
        peer_as (int): Peer AS number
        enable_sender_side_loop_detection (bool): Enable Sender Side Loop Detection
        local_address_interface (str): Interface to accept BGP session
        local_address_ip (str): Specify exact IP address if interface has multiple addresses
        peer_address_type (str): Peer address configuration
        peer_address_value (str): IP or FQDN
        bfd_profile (str): BFD profile
    """

    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/peer")

        # params
        params = []

        params.append(
            VersionedParamPath("enable", path="enable", default=True, vartype="yesno")
        )
        params.append(
            VersionedParamPath(
                "passive",
                path="passive",
                default=False,
                vartype="yesno",
            )
        )
        params.append(VersionedParamPath("peer_as", path="peer-as", vartype="int"))
        params.append(
            VersionedParamPath(
                "enable_sender_side_loop_detection",
                path="enable-sender-side-loop-detection",
                default=True,
                vartype="yesno",
            )
        )

        ### TODO: implement BGP peer group -> peer -> inherit

        params.append(
            VersionedParamPath(
                "local_address_interface", path="local-address/interface"
            )
        )
        params.append(VersionedParamPath("local_address_ip", path="local-address/ip"))
        params.append(
            VersionedParamPath(
                "peer_address_type",
                path="peer-address/{peer_address_type}",
                values=["ip", "fqdn"],
            )
        )
        params.append(
            VersionedParamPath(
                "peer_address_value",
                path="peer-address/{peer_address_type}/",
            )
        )

        ### TODO: implement BGP peer group -> peer -> connection-options

        params.append(
            VersionedParamPath(
                "bfd_profile",
                path="bfd/profile",
                default="Inherit-lr-global-setting",
            )
        )

        self._params = tuple(params)


### TODO: implement VRF -> BGP -> aggregate-routes


### TODO: implement VRF -> BGP -> advertise-network


class RoutingProfileBgpAuth(VersionedPanObject):
    """BGP authentication profile

    Args:
        name (str): The name of the profile
        secret (str): Shared secret for the TCP MD5 authentication
    """

    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(value="/network/routing-profile/bgp/auth-profile")

        params = []

        params.append(VersionedParamPath("secret", vartype="encrypted"))

        self._params = tuple(params)


class RoutingProfileBgpTimer(VersionedPanObject):
    """BGP timer profile

    Args:
        name (str): The name of the profile
        keep_alive_interval (int): Keep-alive interval
        hold_time (int): Hold time
        reconnect_retry_interval (int): Wait in the connect state before retrying connection to the peer
        open_delay_time (int): Delay time after peer TCP connection up and sending 1st BGP Open Message
        min_route_adv_interval (int): Minimum Route Advertisement Interval
    """

    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(value="/network/routing-profile/bgp/timer-profile")

        params = []

        params.append(
            VersionedParamPath(
                "keep_alive_interval",
                path="keep-alive-interval",
                vartype="int",
                default=30,
            )
        )
        params.append(
            VersionedParamPath(
                "hold_time",
                path="hold-time",
                vartype="int",
                default=90,
            )
        )
        params.append(
            VersionedParamPath(
                "reconnect_retry_interval",
                path="reconnect-retry-interval",
                vartype="int",
                default=15,
            )
        )
        params.append(
            VersionedParamPath(
                "open_delay_time",
                path="open-delay-time",
                vartype="int",
                default=0,
            )
        )
        params.append(
            VersionedParamPath(
                "min_route_adv_interval",
                path="min-route-adv-interval",
                vartype="int",
                default=30,
            )
        )

        self._params = tuple(params)


class RoutingProfileBgpAddressFamily(VersionedPanObject):
    """BGP address family profile

    Args:
        name (str): The name of the profile
        afi (str): Address Family Identifier
        unicast_enable (bool): Enable IPv4/IPv6 Unicast Profile
        unicast_soft_reconfig_with_stored_info (bool): Soft reconfiguration of peer with stored routes
        unicast_add_path_tx_all_paths (bool): Advertise all paths to peer
        unicast_add_path_tx_bestpath_per_as (bool): Advertise the bestpath per each neighboring AS
        unicast_as_override (bool): Override ASNs in outbound updates if AS-Path equals Remote-A
        unicast_default_originate (bool): Originate Default Route
        unicast_route_reflector_client (bool): Route Reflector Client
        unicast_allowas_in (str): Accept my AS in AS_PATH if route originated in my AS
        unicast_allowas_in_occurrence (int): Number of occurrences of AS number
        unicast_maximum_prefix_num_prefixes (int): Max allowed prefixes from this peer
        unicast_maximum_prefix_threshold (int): Threshold value (%) at which to generate a warning msg
        unicast_maximum_prefix_action (str): Action if max-prefixes reached
        unicast_maximum_prefix_action_restart_interval (int): Restart connection when limit exceeded
        unicast_next_hop (str): Disable next-hop calculation
        unicast_remove_private_as (str): Remove private ASNs in outbound updates
        unicast_send_community (str): Send community attributes
        unicast_orf (str): Advertise ORF (Outbound Route Filtering) Capability
        unicast_default_originate_map (str): Default Originate Route-Map
        multicast_enable (bool): Enable IPv4 Multicast Profile
        multicast_soft_reconfig_with_stored_info (bool): Soft reconfiguration of peer with stored routes
        multicast_add_path_tx_all_paths (bool): Advertise all paths to peer
        multicast_add_path_tx_bestpath_per_as (bool): Advertise the bestpath per each neighboring AS
        multicast_as_override (bool): Override ASNs in outbound updates if AS-Path equals Remote-A
        multicast_default_originate (bool): Originate Default Route
        multicast_route_reflector_client (bool): Route Reflector Client
        multicast_allowas_in (str): Accept my AS in AS_PATH if route originated in my AS
        multicast_allowas_in_occurrence (int): Number of occurrences of AS number
        multicast_maximum_prefix_num_prefixes (int): Max allowed prefixes from this peer
        multicast_maximum_prefix_threshold (int): Threshold value (%) at which to generate a warning msg
        multicast_maximum_prefix_action (str): Action if max-prefixes reached
        multicast_maximum_prefix_action_restart_interval (int): Restart connection when limit exceeded
        multicast_next_hop (str): Disable next-hop calculation
        multicast_remove_private_as (str): Remove private ASNs in outbound updates
        multicast_send_community (str): Send community attributes
        multicast_orf (str): Advertise ORF (Outbound Route Filtering) Capability
        multicast_default_originate_map (str): Default Originate Route-Map
    """

    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(
            value="/network/routing-profile/bgp/address-family-profile"
        )

        params = []

        params.append(VersionedParamPath("afi", path="{afi}", default="ipv4"))

        # IPv4/IPv6 unicast
        params.append(
            VersionedParamPath(
                "unicast_enable",
                path="{afi}/unicast/enable",
                default=False,
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "unicast_soft_reconfig_with_stored_info",
                path="{afi}/unicast/soft-reconfig-with-stored-info",
                default=True,
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "unicast_add_path_tx_all_paths",
                path="{afi}/unicast/add-path/tx-all-paths",
                default=False,
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "unicast_add_path_tx_bestpath_per_as",
                path="{afi}/unicast/add-path/tx-bestpath-per-AS",
                default=False,
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "unicast_as_override",
                path="{afi}/unicast/as-override",
                default=False,
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "unicast_default_originate",
                path="{afi}/unicast/default-originate",
                default=False,
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "unicast_route_reflector_client",
                path="{afi}/unicast/route-reflector-client",
                default=False,
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "unicast_allowas_in",
                path="{afi}/unicast/allowas-in/{unicast_allowas_in}",
                values=["origin", "occurrence", "none"],
            )
        )
        params.append(
            VersionedParamPath(
                "unicast_allowas_in_occurrence",
                condition={"unicast_allowas_in": "occurrence"},
                path="{afi}/unicast/allowas-in/occurrence",
                default=1,
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "unicast_maximum_prefix_num_prefixes",
                path="{afi}/unicast/maximum-prefix/num_prefixes",
                default=1000,
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "unicast_maximum_prefix_threshold",
                path="{afi}/unicast/maximum-prefix/threshold",
                default=100,
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "unicast_maximum_prefix_action",
                path="{afi}/unicast/maximum-prefix/action/{unicast_maximum_prefix_action}",
                default="warning-only",
                values=[
                    "restart",
                    "warning-only",
                ],
            )
        )
        params.append(
            VersionedParamPath(
                "unicast_maximum_prefix_action_restart_interval",
                path="{afi}/unicast/maximum-prefix/action/restart/interval",
                condition={"unicast_maximum_prefix_action": "restart"},
                default=1,
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "unicast_next_hop",
                path="{afi}/unicast/next-hop/{unicast_next_hop}",
                values=["self", "self-force"],
            )
        )
        params.append(
            VersionedParamPath(
                "unicast_remove_private_as",
                path="{afi}/unicast/remove-private-AS/{unicast_remove_private_as}",
                values=["all", "replace-AS"],
            )
        )
        params.append(
            VersionedParamPath(
                "unicast_send_community",
                path="{afi}/unicast/send-community/{unicast_send_community}",
                values=["all", "both", "extended", "large", "standard"],
            )
        )
        params.append(
            VersionedParamPath(
                "unicast_orf",
                path="{afi}/unicast/orf/orf-prefix-list",
                values=["none", "both", "receive", "send"],
            )
        )
        params.append(
            VersionedParamPath(
                "unicast_default_originate_map",
                path="{afi}/unicast/default-originate-map",
            )
        )

        # IPv4 multicast
        params.append(
            VersionedParamPath(
                "multicast_enable",
                path="{afi}/multicast/enable",
                condition={"afi": "ipv4"},
                default=False,
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "multicast_soft_reconfig_with_stored_info",
                path="{afi}/multicast/soft-reconfig-with-stored-info",
                condition={"afi": "ipv4"},
                default=True,
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "multicast_add_path_tx_all_paths",
                path="{afi}/multicast/add-path/tx-all-paths",
                condition={"afi": "ipv4"},
                default=False,
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "multicast_add_path_tx_bestpath_per_as",
                path="{afi}/multicast/add-path/tx-bestpath-per-AS",
                condition={"afi": "ipv4"},
                default=False,
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "multicast_as_override",
                path="{afi}/multicast/as-override",
                condition={"afi": "ipv4"},
                default=False,
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "multicast_default_originate",
                path="{afi}/multicast/default-originate",
                condition={"afi": "ipv4"},
                default=False,
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "multicast_route_reflector_client",
                path="{afi}/multicast/route-reflector-client",
                condition={"afi": "ipv4"},
                default=False,
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "multicast_allowas_in",
                path="{afi}/multicast/allowas-in/{multicast_allowas_in}",
                condition={"afi": "ipv4"},
                values=["origin", "occurrence", "none"],
            )
        )
        params.append(
            VersionedParamPath(
                "multicast_allowas_in_occurrence",
                path="{afi}/multicast/allowas-in/occurrence",
                condition={"afi": "ipv4", "multicast_allowas_in": "occurrence"},
                default=1,
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "multicast_maximum_prefix_num_prefixes",
                path="{afi}/multicast/maximum-prefix/num_prefixes",
                condition={"afi": "ipv4"},
                default=1000,
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "multicast_maximum_prefix_threshold",
                path="{afi}/multicast/maximum-prefix/threshold",
                condition={"afi": "ipv4"},
                default=100,
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "multicast_maximum_prefix_action",
                path="{afi}/multicast/maximum-prefix/action/{multicast_maximum_prefix_action}",
                condition={"afi": "ipv4"},
                default="warning-only",
                values=[
                    "restart",
                    "warning-only",
                ],
            )
        )
        params.append(
            VersionedParamPath(
                "multicast_maximum_prefix_action_restart_interval",
                path="{afi}/multicast/maximum-prefix/action/restart/interval",
                condition={"afi": "ipv4", "multicast_maximum_prefix_action": "restart"},
                default=1,
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "multicast_next_hop",
                path="{afi}/multicast/next-hop/{multicast_next_hop}",
                condition={"afi": "ipv4"},
                values=["self", "self-force"],
            )
        )
        params.append(
            VersionedParamPath(
                "multicast_remove_private_as",
                path="{afi}/multicast/remove-private-AS/{multicast_remove_private_as}",
                condition={"afi": "ipv4"},
                values=["all", "replace-AS"],
            )
        )
        params.append(
            VersionedParamPath(
                "multicast_send_community",
                path="{afi}/multicast/send-community/{multicast_send_community}",
                condition={"afi": "ipv4"},
                values=["all", "both", "extended", "large", "standard"],
            )
        )
        params.append(
            VersionedParamPath(
                "multicast_orf",
                path="{afi}/multicast/orf/orf-prefix-list",
                condition={"afi": "ipv4"},
                values=["none", "both", "receive", "send"],
            )
        )
        params.append(
            VersionedParamPath(
                "multicast_default_originate_map",
                path="{afi}/multicast/default-originate-map",
                condition={"afi": "ipv4"},
            )
        )

        self._params = tuple(params)


class RoutingProfileBgpDampening(VersionedPanObject):
    """BGP dampening profile

    Args:
        name (str): The name of the profile
        description (str): Description of the BGP Dampening Profile
        half_life (int): Half-life for the penalty
        reuse_limit (int): Value to start reusing a route
        suppress_limit (int): Value to start supressing the route
        max_suppress_limit (int): Maximum duration (in minutes) a route can be suppressed
    """

    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(value="/network/routing-profile/bgp/dampening-profile")

        params = []

        params.append(VersionedParamPath("description", path="description"))
        params.append(
            VersionedParamPath(
                "half_life",
                path="half-life",
                default=15,
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "reuse_limit",
                path="reuse-limit",
                default=750,
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "suppress_limit",
                path="suppress-limit",
                default=2000,
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "max_suppress_limit",
                path="max-suppress-limit",
                default=60,
                vartype="int",
            )
        )

        self._params = tuple(params)


class RoutingProfileBgpRedistribution(VersionedPanObject):
    """BGP redistribution profile

    Args:
        name (str): The name of the profile
        afi (str): Address Family Identifier
        static_enable (bool): Enable Static Routes
        static_metric (int): Static Metric (Field ignored if route-map configured)
        connected_enable (bool): Enable Connected Routes
        connected_metric (int): Connected Metric (Field ignored if route-map configured)
        ospf_enable (bool): Enable OSPF Routes (only for IPv4)
        ospf_metric (int): OSPF Metric (Field ignored if route-map configured)
        ospfv3_enable (bool): Enable OSPFv3 Routes (only for IPv6)
        ospfv3_metric (int): OSPFv3 Metric (Field ignored if route-map configured)
        rip_enable (bool): Enable RIP Routes
        rip_metric (int): RIP Metric (Field ignored if route-map configured)
    """

    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(
            value="/network/routing-profile/bgp/redistribution-profile"
        )

        params = []

        params.append(VersionedParamPath("afi", path="{afi}", default="ipv4"))
        params.append(
            VersionedParamPath(
                "static_enable",
                path="{afi}/unicast/static/enable",
                condition={"afi": ["ipv4", "ipv6"]},
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "static_metric",
                path="{afi}/unicast/static/metric",
                condition={"afi": ["ipv4", "ipv6"]},
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "connected_enable",
                path="{afi}/unicast/connected/enable",
                condition={"afi": ["ipv4", "ipv6"]},
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "connected_metric",
                path="{afi}/unicast/connected/metric",
                condition={"afi": ["ipv4", "ipv6"]},
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "ospf_enable",
                path="{afi}/unicast/ospf/enable",
                condition={"afi": "ipv4"},
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "ospf_metric",
                path="{afi}/unicast/ospf/metric",
                condition={"afi": "ipv4"},
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "ospfv3_enable",
                path="{afi}/unicast/ospfv3/enable",
                condition={"afi": "ipv6"},
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "ospfv3_metric",
                path="{afi}/unicast/ospfv3/metric",
                condition={"afi": "ipv6"},
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "rip_enable",
                path="{afi}/unicast/rip/enable",
                condition={"afi": "ipv4"},
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "rip_metric",
                path="{afi}/unicast/rip/metric",
                condition={"afi": "ipv4"},
                vartype="int",
            )
        )

        self._params = tuple(params)


class RoutingProfileBgpFiltering(VersionedPanObject):
    """BGP filtering profile

    Args:
        name (str): The name of the profile
        description (str): Description of the profile
        afi (str): Address Family Identifier
    """

    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(value="/network/routing-profile/bgp/filtering-profile")

        params = []

        params.append(VersionedParamPath("description", path="description"))
        params.append(VersionedParamPath("afi", path="{afi}", default="ipv4"))

        self._params = tuple(params)


class RoutingProfileOspfAuth(VersionedPanObject):
    """OSPF authentication profile

    Args:
        name (str): The name of the profile
        password (str): Simple password authentication
    """

    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(value="/network/routing-profile/ospf/auth-profile")

        params = []

        params.append(VersionedParamPath("password", vartype="encrypted"))

        self._params = tuple(params)


class RoutingProfileOspfIfTimer(VersionedPanObject):
    """OSPF interface timer profile

    Args:
        name (str): The name of the profile
        hello_interval (int): Interval (in seconds) to send Hello packets
        dead_counts (int): Number of lost hello packets to declare router down
        retransmit_interval (int): Interval (in seconds) to retransmit LSAs
        transit_delay (int): Estimated delay (in seconds) to transmit LSAs
        gr_delay (int): Period (in seconds) used to send grace LSAs before first hello is sent when graceful restart starts
    """

    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(value="/network/routing-profile/ospf/if-timer-profile")

        params = []

        params.append(
            VersionedParamPath(
                "hello_interval",
                path="hello-interval",
                vartype="int",
                default=10,
            )
        )
        params.append(
            VersionedParamPath(
                "dead_counts",
                path="dead-counts",
                vartype="int",
                default=4,
            )
        )
        params.append(
            VersionedParamPath(
                "retransmit_interval",
                path="retransmit-interval",
                vartype="int",
                default=5,
            )
        )
        params.append(
            VersionedParamPath(
                "transit_delay",
                path="transit-delay",
                vartype="int",
                default=1,
            )
        )
        params.append(
            VersionedParamPath(
                "gr_delay",
                path="gr-delay",
                vartype="int",
                default=10,
            )
        )

        self._params = tuple(params)


class RoutingProfileOspfSpfTimer(VersionedPanObject):
    """OSPF global timer profile

    Args:
        name (str): The name of the profile
        lsa_interval (int): The minimum time in seconds between distinct originations of any particular LSA
        spf_calculation_delay (int): Delay in seconds before running the SPF algorithm
        initial_hold_time (int): Initial hold time (second) between consecutive SPF calculations
        max_hold_time (int): Maximum hold time (second)
    """

    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(
            value="/network/routing-profile/ospf/spf-timer-profile"
        )

        params = []

        params.append(
            VersionedParamPath(
                "lsa_interval",
                path="lsa-interval",
                vartype="int",
                default=5,
            )
        )
        params.append(
            VersionedParamPath(
                "spf_calculation_delay",
                path="spf-calculation-delay",
                vartype="int",
                default=5,
            )
        )
        params.append(
            VersionedParamPath(
                "initial_hold_time",
                path="initial-hold-time",
                vartype="int",
                default=5,
            )
        )
        params.append(
            VersionedParamPath(
                "max_hold_time",
                path="max-hold-time",
                vartype="int",
                default=5,
            )
        )

        self._params = tuple(params)


class RoutingProfileOspfRedistribution(VersionedPanObject):
    """OSPF redistribution profile

    Args:
        name (str): The name of the profile
        static (str): IPv4 static section
        static_enable (bool): IPv4 static enabled
        static_metric (int): IPv4 static metric value (1-65535)
        static_metric_type (str): IPv4 static metric type (type-1, type-2)
        connected (str): Connected section
        connected_enable (bool): Connected enabled
        connected_metric (int): Connected metric value (1-65535)
        connected_metric_type (str): Connected metric type (type-1, type-2)
        rip (str): RIPv2 section
        rip_enable (bool): RIPv2 enabled
        rip_metric (int): RIPv2 metric value (1-65535)
        rip_metric_type (str): RIPv2 metric type (type-1, type-2)
        bgp (str): BGP AFI IPv4 section
        bgp_enable (bool): BGP AFI IPv4 enabled
        bgp_metric (int): BGP AFI IPv4 metric value (1-65535)
        bgp_metric_type (str): BGP AFI IPv4 metric type (type-1, type-2)
        default_route (str): IPv4 Default Route section
        default_route_always (bool): IPv4 Default Route always
        default_route_enable (bool): IPv4 Default Route enabled
        default_route_metric (int): IPv4 Default Route metric value (1-65535)
        default_route_metric_type (str): IPv4 Default Route metric type (type-1, type-2)
    """

    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(
            value="/network/routing-profile/ospf/redistribution-profile"
        )

        params = []

        params.append(
            VersionedParamPath(
                "static",
                path="{static}",
                values=("static"),
                default=None,
            )
        )
        params.append(
            VersionedParamPath(
                "static_enable",
                path="{static}/enable",
                condition={"static": "static"},
                default=True,
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "static_metric",
                path="{static}/metric",
                condition={"static": "static"},
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "static_metric_type",
                path="{static}/metric-type",
                condition={"static": "static"},
                default="type-2",
                values=("type-1", "type-2"),
            )
        )
        params.append(
            VersionedParamPath(
                "connected",
                path="{connected}",
                values=("connected"),
                default=None,
            )
        )
        params.append(
            VersionedParamPath(
                "connected_enable",
                path="connected/enable",
                condition={"connected": "connected"},
                default=True,
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "connected_metric",
                path="connected/metric",
                condition={"connected": "connected"},
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "connected_metric_type",
                path="connected/metric-type",
                condition={"connected": "connected"},
                default="type-2",
                values=("type-1", "type-2"),
            )
        )
        params.append(
            VersionedParamPath(
                "rip",
                path="{rip}",
                values=("rip"),
                default=None,
            )
        )
        params.append(
            VersionedParamPath(
                "rip_enable",
                path="rip/enable",
                condition={"rip": "rip"},
                default=True,
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "rip_metric",
                path="rip/metric",
                condition={"rip": "rip"},
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "rip_metric_type",
                path="rip/metric-type",
                condition={"rip": "rip"},
                default="type-2",
                values=("type-1", "type-2"),
            )
        )
        params.append(
            VersionedParamPath(
                "bgp",
                path="{bgp}",
                values=("bgp"),
                default=None,
            )
        )
        params.append(
            VersionedParamPath(
                "bgp_enable",
                path="bgp/enable",
                condition={"bgp": "bgp"},
                default=True,
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "bgp_metric",
                path="bgp/metric",
                condition={"bgp": "bgp"},
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "bgp_metric_type",
                path="bgp/metric-type",
                condition={"bgp": "bgp"},
                default="type-2",
                values=("type-1", "type-2"),
            )
        )
        params.append(
            VersionedParamPath(
                "default_route",
                path="{default_route}",
                values=("default-route"),
                default=None,
            )
        )
        params.append(
            VersionedParamPath(
                "default_route_always",
                path="default-route/always",
                condition={"default_route": "default-route"},
                default=True,
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "default_route_enable",
                path="default-route/enable",
                condition={"default_route": "default-route"},
                default=True,
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "default_route_metric",
                path="default-route/metric",
                condition={"default_route": "default-route"},
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "default_route_metric_type",
                path="default-route/metric-type",
                condition={"default_route": "default-route"},
                default="type-2",
                values=("type-1", "type-2"),
            )
        )

        self._params = tuple(params)


class RoutingProfileOspfv3Auth(VersionedPanObject):
    """OSPFv3 authentication profile

    Args:
        name (str): The name of the profile
        spi (str): SPI for both inbound and outbound SA, hex format xxxxxxxx.
        protocol (str): Protocol ESP or AH
        esp_auth_type (str): ESP options - Authentication type
        esp_auth_key (str): ESP options - Authentication key
        esp_encrypt_algorithm (str): ESP options - Encryption algorithm
        esp_encrypt_key (str): ESP options - Encryption key
        ah_type (str): AH options - type
        ah_key (str): AH options - key
    """

    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(value="/network/routing-profile/ospfv3/auth-profile")

        params = []

        params.append(VersionedParamPath("spi", path="spi"))
        params.append(
            VersionedParamPath(
                "protocol",
                path="{protocol}",
                values=("esp", "ah"),
                default="esp",
            )
        )
        params.append(
            VersionedParamPath(
                "esp_auth_type",
                path="{protocol}/authentication/{esp_auth_type}",
                values=["md5", "sha1", "sha256", "sha384", "sha512"],
                condition={"protocol": "esp"},
            )
        )
        params.append(
            VersionedParamPath(
                "esp_auth_key",
                path="{protocol}/authentication/{esp_auth_type}/key",
                condition={
                    "protocol": "esp",
                    "esp_auth_type": ["md5", "sha1", "sha256", "sha384", "sha512"],
                },
            )
        )
        params.append(
            VersionedParamPath(
                "esp_encrypt_algorithm",
                path="{protocol}/encryption/algorithm",
                values=["3des", "aes-128-cbc", "aes-192-cbc", "aes-256-cbc", "null"],
                condition={"protocol": "esp"},
            )
        )
        params.append(
            VersionedParamPath(
                "esp_encrypt_key",
                path="{protocol}/encryption/key",
                condition={
                    "protocol": "esp",
                    "esp_encrypt_algorithm": [
                        "3des",
                        "aes-128-cbc",
                        "aes-192-cbc",
                        "aes-256-cbc",
                        "null",
                    ],
                },
            )
        )
        params.append(
            VersionedParamPath(
                "ah_type",
                path="{protocol}/{ah_type}",
                values=["md5", "sha1", "sha256", "sha384", "sha512"],
                condition={"protocol": "ah"},
            )
        )
        params.append(
            VersionedParamPath(
                "ah_key",
                path="{protocol}/{ah_type}/key",
                condition={
                    "protocol": "ah",
                    "ah_type": ["md5", "sha1", "sha256", "sha384", "sha512"],
                },
            )
        )

        self._params = tuple(params)


class RoutingProfileOspfv3IfTimer(VersionedPanObject):
    """OSPFv3 interface timer profile

    Args:
        name (str): The name of the profile
        hello_interval (int): Interval (in seconds) to send Hello packets
        dead_counts (int): Number of lost hello packets to declare router down
        retransmit_interval (int): Interval (in seconds) to retransmit LSAs
        transit_delay (int): Estimated delay (in seconds) to transmit LSAs
        gr_delay (int): Period (in seconds) used to send grace LSAs before first hello is sent when graceful restart starts
    """

    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(
            value="/network/routing-profile/ospfv3/if-timer-profile"
        )

        params = []

        params.append(
            VersionedParamPath(
                "hello_interval",
                path="hello-interval",
                vartype="int",
                default=10,
            )
        )
        params.append(
            VersionedParamPath(
                "dead_counts",
                path="dead-counts",
                vartype="int",
                default=4,
            )
        )
        params.append(
            VersionedParamPath(
                "retransmit_interval",
                path="retransmit-interval",
                vartype="int",
                default=5,
            )
        )
        params.append(
            VersionedParamPath(
                "transit_delay",
                path="transit-delay",
                vartype="int",
                default=1,
            )
        )
        params.append(
            VersionedParamPath(
                "gr_delay",
                path="gr-delay",
                vartype="int",
                default=10,
            )
        )

        self._params = tuple(params)


class RoutingProfileOspfv3SpfTimer(VersionedPanObject):
    """OSPFv3 global timer profile

    Args:
        name (str): The name of the profile
        lsa_interval (int): The minimum time in seconds between distinct originations of any particular LSA
        spf_calculation_delay (int): Delay in seconds before running the SPF algorithm
        initial_hold_time (int): Initial hold time (second) between consecutive SPF calculations
        max_hold_time (int): Maximum hold time (second)
    """

    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(
            value="/network/routing-profile/ospfv3/spf-timer-profile"
        )

        params = []

        params.append(
            VersionedParamPath(
                "lsa_interval",
                path="lsa-interval",
                vartype="int",
                default=5,
            )
        )
        params.append(
            VersionedParamPath(
                "spf_calculation_delay",
                path="spf-calculation-delay",
                vartype="int",
                default=5,
            )
        )
        params.append(
            VersionedParamPath(
                "initial_hold_time",
                path="initial-hold-time",
                vartype="int",
                default=5,
            )
        )
        params.append(
            VersionedParamPath(
                "max_hold_time",
                path="max-hold-time",
                vartype="int",
                default=5,
            )
        )

        self._params = tuple(params)


class RoutingProfileOspfv3Redistribution(VersionedPanObject):
    """OSPFv3 redistribution profile

    Args:
        name (str): The name of the profile
        static (str): IPv4 static section
        static_enable (bool): IPv4 static enabled
        static_metric (int): IPv4 static metric value (1-65535)
        static_metric_type (str): IPv4 static metric type (type-1, type-2)
        connected (str): Connected section
        connected_enable (bool): Connected enabled
        connected_metric (int): Connected metric value (1-65535)
        connected_metric_type (str): Connected metric type (type-1, type-2)
        bgp (str): BGP AFI IPv4 section
        bgp_enable (bool): BGP AFI IPv4 enabled
        bgp_metric (int): BGP AFI IPv4 metric value (1-4294967295)
        bgp_metric_type (str): BGP AFI IPv4 metric type (type-1, type-2)
        default_route (str): IPv6 Default Route section
        default_route_always (bool): IPv6 Default Route always
        default_route_enable (bool): IPv6 Default Route enabled
        default_route_metric (int): IPv6 Default Route metric value (1-4294967295)
        default_route_metric_type (str): IPv6 Default Route metric type (type-1, type-2)
    """

    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(
            value="/network/routing-profile/ospfv3/redistribution-profile"
        )

        params = []

        params.append(
            VersionedParamPath(
                "static",
                path="{static}",
                values=("static"),
                default=None,
            )
        )
        params.append(
            VersionedParamPath(
                "static_enable",
                path="{static}/enable",
                condition={"static": "static"},
                default=True,
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "static_metric",
                path="{static}/metric",
                condition={"static": "static"},
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "static_metric_type",
                path="{static}/metric-type",
                condition={"static": "static"},
                default="type-2",
                values=("type-1", "type-2"),
            )
        )
        params.append(
            VersionedParamPath(
                "connected",
                path="{connected}",
                values=("connected"),
                default=None,
            )
        )
        params.append(
            VersionedParamPath(
                "connected_enable",
                path="connected/enable",
                condition={"connected": "connected"},
                default=True,
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "connected_metric",
                path="connected/metric",
                condition={"connected": "connected"},
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "connected_metric_type",
                path="connected/metric-type",
                condition={"connected": "connected"},
                default="type-2",
                values=("type-1", "type-2"),
            )
        )
        params.append(
            VersionedParamPath(
                "bgp",
                path="{bgp}",
                values=("bgp"),
                default=None,
            )
        )
        params.append(
            VersionedParamPath(
                "bgp_enable",
                path="bgp/enable",
                condition={"bgp": "bgp"},
                default=True,
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "bgp_metric",
                path="bgp/metric",
                condition={"bgp": "bgp"},
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "bgp_metric_type",
                path="bgp/metric-type",
                condition={"bgp": "bgp"},
                default="type-2",
                values=("type-1", "type-2"),
            )
        )
        params.append(
            VersionedParamPath(
                "default_route",
                path="{default_route}",
                values=("default-route"),
                default=None,
            )
        )
        params.append(
            VersionedParamPath(
                "default_route_always",
                path="default-route/always",
                condition={"default_route": "default-route"},
                default=True,
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "default_route_enable",
                path="default-route/enable",
                condition={"default_route": "default-route"},
                default=True,
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "default_route_metric",
                path="default-route/metric",
                condition={"default_route": "default-route"},
                vartype="int",
            )
        )
        params.append(
            VersionedParamPath(
                "default_route_metric_type",
                path="default-route/metric-type",
                condition={"default_route": "default-route"},
                default="type-2",
                values=("type-1", "type-2"),
            )
        )

        self._params = tuple(params)


class RoutingProfileFilterAccessList(VersionedPanObject):
    """Filter Access List

    Args:
        name (str): The name of the access list
        description (str): Description of the access list
        type (str): IPv4 or IPv6
    """

    SUFFIX = ENTRY

    CHILDTYPES = (
        "network.RoutingProfileFilterAccessListEntryIpv4",
        "network.RoutingProfileFilterAccessListEntryIpv6",
    )

    def _setup(self):
        self._xpaths.add_profile(value="/network/routing-profile/filters/access-list")

        params = []

        params.append(VersionedParamPath("description", path="description"))
        params.append(
            VersionedParamPath(
                "type",
                path="type/{type}",
                default="ipv4",
                values=("ipv4", "ipv6"),
            )
        )

        self._params = tuple(params)


class RoutingProfileFilterAccessListEntryIpv4(VersionedPanObject):
    """Filter Access List - IPv4 entry

    Args:
        name (str): The name of the entry
        action (str): Deny or permit action
        source_address_type (str): IPv4 Access-List Source Address (none, any, address)
        source_address (str): IPv4 Source Address
        source_wildcard (str): IPv4 Source Wildcard
        destination_address_type (str): IPv4 Access-List Destination Address (none, any, address)
        destination_address (str): IPv4 Destination Address
        destination_wildcard (str): IPv4 Destination Wildcard
    """

    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(value="/type/ipv4/ipv4-entry")

        params = []

        params.append(
            VersionedParamPath(
                "action",
                path="action",
                default="deny",
                values=("deny", "permit"),
            )
        )
        params.append(
            VersionedParamPath(
                "source_address_type",
                path="source-address/address",
                condition={"source_address_type": "any"},
            )
        )
        params.append(
            VersionedParamPath(
                "source_address",
                path="source-address/entry/address",
                condition={"source_address_type": "address"},
            )
        )
        params.append(
            VersionedParamPath(
                "source_wildcard",
                path="source-address/entry/wildcard",
                condition={"source_address_type": "address"},
            )
        )
        params.append(
            VersionedParamPath(
                "destination_address_type",
                path="destination-address/address",
                condition={"destination_address_type": "any"},
            )
        )
        params.append(
            VersionedParamPath(
                "destination_address",
                path="destination-address/entry/address",
                condition={"destination_address_type": "address"},
            )
        )
        params.append(
            VersionedParamPath(
                "destination_wildcard",
                path="destination-address/entry/wildcard",
                condition={"destination_address_type": "address"},
            )
        )

        self._params = tuple(params)


class RoutingProfileFilterAccessListEntryIpv6(VersionedPanObject):
    """Filter Access List - IPv6 entry

    Args:
        name (str): The name of the entry
        action (str): Deny or permit action
        source_address_type (str): IPv6 Access-List Source Address (none, any, address)
        source_address (str): IPv6 Source Address
        source_exact_match (bool): Exact Match of this address
    """

    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(value="/type/ipv6/ipv6-entry")

        params = []

        params.append(
            VersionedParamPath(
                "action",
                path="action",
                default="deny",
                values=("deny", "permit"),
            )
        )
        params.append(
            VersionedParamPath(
                "source_address_type",
                path="source-address/address",
                condition={"source_address_type": "any"},
            )
        )
        params.append(
            VersionedParamPath(
                "source_address",
                path="source-address/entry/address",
                condition={"source_address_type": "address"},
            )
        )
        params.append(
            VersionedParamPath(
                "source_exact_match",
                path="source-address/entry/exact-match",
                condition={"source_address_type": "address"},
                default=False,
                vartype="yesno",
            )
        )

        self._params = tuple(params)


class RoutingProfileFilterPrefixList(VersionedPanObject):
    """Filter Prefix List

    Args:
        name (str): The name of the prefix list
        description (str): Description of the prefix list
        type (str): IPv4 or IPv6
    """

    SUFFIX = ENTRY

    CHILDTYPES = (
        "network.RoutingProfileFilterPrefixListEntryIpv4",
        "network.RoutingProfileFilterPrefixListEntryIpv6",
    )

    def _setup(self):
        self._xpaths.add_profile(value="/network/routing-profile/filters/prefix-list")

        params = []

        params.append(VersionedParamPath("description", path="description"))
        params.append(
            VersionedParamPath(
                "type",
                path="type/{type}",
                default="ipv4",
                values=("ipv4", "ipv6"),
            )
        )

        self._params = tuple(params)


class RoutingProfileFilterPrefixListEntryIpv4(VersionedPanObject):
    """Filter Prefix List - IPv4 entry

    Args:
        name (str): The name of the entry
        action (str): Deny or permit action
        prefix (str): IPv4 prefix list network (none, any, network)
        network (str): IPv4 prefix
        greater_than_or_equal (int): Maximum Prefix length to be matched
        less_than_or_equal (int): Minimum Prefix length to be matched
    """

    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(value="/type/ipv4/ipv4-entry")

        params = []

        params.append(
            VersionedParamPath(
                "action",
                path="action",
                default="deny",
                values=("deny", "permit"),
            )
        )
        params.append(
            VersionedParamPath(
                "prefix",
                path="prefix/network",
                condition={"prefix": "any"},
            )
        )
        params.append(
            VersionedParamPath(
                "network",
                path="prefix/entry/network",
                condition={"prefix": "network"},
            )
        )
        params.append(
            VersionedParamPath(
                "greater_than_or_equal",
                path="prefix/entry/greater-than-or-equal",
                condition={"prefix": "network"},
            )
        )
        params.append(
            VersionedParamPath(
                "less_than_or_equal",
                path="prefix/entry/less-than-or-equal",
                condition={"prefix": "network"},
            )
        )

        self._params = tuple(params)


class RoutingProfileFilterPrefixListEntryIpv6(VersionedPanObject):
    """Filter Prefix List - IPv6 entry

    Args:
        name (str): The name of the entry
        action (str): Deny or permit action
        prefix (str): IPv4 prefix list network (none, any, network)
        network (str): IPv4 prefix
        greater_than_or_equal (int): Maximum Prefix length to be matched
        less_than_or_equal (int): Minimum Prefix length to be matched
    """

    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(value="/type/ipv6/ipv6-entry")

        params = []

        params.append(
            VersionedParamPath(
                "action",
                path="action",
                default="deny",
                values=("deny", "permit"),
            )
        )
        params.append(
            VersionedParamPath(
                "prefix",
                path="prefix/network",
                condition={"prefix": "any"},
            )
        )
        params.append(
            VersionedParamPath(
                "network",
                path="prefix/entry/network",
                condition={"prefix": "network"},
            )
        )
        params.append(
            VersionedParamPath(
                "greater_than_or_equal",
                path="prefix/entry/greater-than-or-equal",
                condition={"prefix": "network"},
            )
        )
        params.append(
            VersionedParamPath(
                "less_than_or_equal",
                path="prefix/entry/less-than-or-equal",
                condition={"prefix": "network"},
            )
        )

        self._params = tuple(params)


class RoutingProfileFilterAsPathAccessList(VersionedPanObject):
    """Filter AS-Path Access List

    Args:
        name (str): The name of the profile
        description (str): Description of the AS path access list
    """

    SUFFIX = ENTRY

    CHILDTYPES = ("network.RoutingProfileFilterAsPathAccessListEntry",)

    def _setup(self):
        self._xpaths.add_profile(
            value="/network/routing-profile/filters/as-path-access-list"
        )

        params = []

        params.append(VersionedParamPath("description", path="description"))

        self._params = tuple(params)


class RoutingProfileFilterAsPathAccessListEntry(VersionedPanObject):
    """Filter AS-Path Access List - entry

    Args:
        name (str): The name of the AS-Path access list
        action (str): Deny or permit action
        aspath_regex (str): Regular-expression (1234567890_^|[,{}()]$*+.?-\) to match the BGP AS path
    """

    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(value="/aspath-entry")

        params = []

        params.append(
            VersionedParamPath(
                "action",
                path="action",
                default="deny",
                values=("deny", "permit"),
            )
        )
        params.append(
            VersionedParamPath(
                "aspath_regex",
                path="aspath-regex",
            )
        )

        self._params = tuple(params)


class RoutingProfileFilterCommunityList(VersionedPanObject):
    """Filter Community List

    Args:
        name (str): The name of the community list
        description (str): Description of the community list
        type (str): Community list entries type
    """

    SUFFIX = ENTRY

    CHILDTYPES = (
        "network.RoutingProfileFilterCommunityListEntryRegular",
        "network.RoutingProfileFilterCommunityListEntryLarge",
        "network.RoutingProfileFilterCommunityListEntryExtended",
    )

    def _setup(self):
        self._xpaths.add_profile(
            value="/network/routing-profile/filters/community-list"
        )

        params = []

        params.append(VersionedParamPath("description", path="description"))
        params.append(
            VersionedParamPath(
                "type",
                path="type/{type}",
                default="regular",
                values=("regular", "large", "extended"),
            )
        )

        self._params = tuple(params)


class RoutingProfileFilterCommunityListEntryRegular(VersionedPanObject):
    """Filter Community List - regular entry

    Args:
        name (str): The name of the entry
        action (str): Permit or Deny (default) this Regular Community-List Entry
        community(list): Specify Community either using number in AA:NN format (where AA and NN are between (0-65535)) or pre-defined value
    """

    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(value="/type/regular/regular-entry")

        params = []

        params.append(
            VersionedParamPath(
                "action",
                path="action",
                default="deny",
                values=("deny", "permit"),
            )
        )
        params.append(
            VersionedParamPath(
                "community",
                path="community",
                vartype="member",
                values=(
                    "blackhole",
                    "no-peer",
                    "graceful-shutdown",
                    "accept-own",
                    "local-as",
                    "route-filter-v4",
                    "route-filter-v6",
                    "no-advertise",
                    "no-export",
                    "internet",
                ),
            )
        )

        self._params = tuple(params)


class RoutingProfileFilterCommunityListEntryLarge(VersionedPanObject):
    """Filter Community List - large entry

    Args:
        name (str): The name of the entry
        action (str): Permit or Deny (default) this Large Community-List Entry
        lc_regex(list): Specify Large Community regular expression format {regex1:regex2:regex3}
    """

    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(value="/type/large/large-entry")

        params = []

        params.append(
            VersionedParamPath(
                "action",
                path="action",
                default="deny",
                values=("deny", "permit"),
            )
        )
        params.append(
            VersionedParamPath(
                "lc_regex",
                path="lc-regex",
                vartype="member",
            )
        )

        self._params = tuple(params)


class RoutingProfileFilterCommunityListEntryExtended(VersionedPanObject):
    """Filter Community List - extended entry

    Args:
        name (str): The name of the entry
        action (str): Permit or Deny (default) this Extended Community-List Entry
        ec_regex(list): Specify Extended Community regular expression format {regex1:regex2}
    """

    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(value="/type/extended/extended-entry")

        params = []

        params.append(
            VersionedParamPath(
                "action",
                path="action",
                default="deny",
                values=("deny", "permit"),
            )
        )
        params.append(
            VersionedParamPath(
                "ec_regex",
                path="ec-regex",
                vartype="member",
            )
        )

        self._params = tuple(params)


class RoutingProfileFilterRouteMaps(VersionedPanObject):
    """Filter BGP Route-Maps

    Args:
        name (str): The name of BGP route map
        description (str): BGP route map description
    """

    SUFFIX = ENTRY

    CHILDTYPES = ("network.RoutingProfileFilterRouteMapsEntry",)

    def _setup(self):
        self._xpaths.add_profile(
            value="/network/routing-profile/filters/route-maps/bgp/bgp-entry"
        )

        params = []

        params.append(VersionedParamPath("description", path="description"))

        self._params = tuple(params)


class RoutingProfileFilterRouteMapsEntry(VersionedPanObject):
    """Filter BGP Route-Maps - entry

    Args:
        name (str): The name of the entry
        action (str): Permit or Deny (default) route map
        description (str): Description of route map
        match_as_path_access_list (str): AS Path Access List Name
        match_regular_community (str): Regular Community Name
        match_large_community (str): Large Community Name
        match_extended_community (str): Extended Community Name
        match_interface (str): Match Interface of the route
        match_origin (str): Match origin
        match_metric (str): Match Metric (BGP MED) of route
        match_tag (str): Match Tag of route
        match_local_preference (str): "Match Local Preference of route
        match_peer (str): Match Peer Address
        match_ipv4_address_access_list (str): Match IPv4 Route - Route Access-List
        match_ipv4_address_prefix_list (str): Match IPv4 Route - Route Prefix-List
        match_ipv4_next_hop_access_list (str): Match IPv4 Next-Hop of Route - Access-List
        match_ipv4_next_hop_prefix_list (str): Match IPv4 Next-Hop of Route - Prefix-List
        match_ipv4_route_source_access_list (str): Match IPv4 Advertising Source Address of route - Access-List
        match_ipv4_route_source_prefix_list (str): Match IPv4 Advertising Source Address of route - Prefix-List
        match_ipv6_address_access_list (str): Match IPv6 Route - Route Access-List
        match_ipv6_address_prefix_list (str): Match IPv6 Route - Route Prefix-List
        match_ipv6_next_hop_access_list (str): Match IPv6 Next-Hop of Route - Access-List
        match_ipv6_next_hop_prefix_list (str): Match IPv6 Next-Hop of Route - Prefix-List
        set_aggregator_as (str): Set Aggregator AS Number
        set_aggregator_router_id (str): Set Aggregator Router ID
        set_tag (str): Set Tag of route
        set_local_preference (str): Set Local Preference of route
        set_weight (str): Set BGP weight of the route
        set_origin (str): Set BGP origin
        set_atomic_aggregate (bool): Enable BGP atomic aggregate
        set_metric_action (str): Set Metric action
        set_metric_value (str): Set Metric value (BGP MED) of route
        set_originator_id (str): Set BGP Originator Id
        set_ipv4_source_address (str): Source IPv4 Address
        set_ipv4_next_hop (str): IPv4 Next-Hop Address
        set_ipv6_source_address (str): Source IPv6 Address
        set_ipv6_next_hop (str): IPv6 Next-Hop Address
        set_ipv6_next_hop_prefer_global (bool): IPv6 Nexthop Prefer Global Address
        set_overwrite_regular_community (bool): If enabled, set community will overwite existing communities, instead of appending
        set_overwrite_large_community (bool): If enabled, set community will overwite existing large communities, instead of appending
        set_remove_regular_community (str): Remove Regular Community Name
        set_remove_large_community (str): Remove Large Community Name
        set_aspath_exclude (list): Remove BGP AS-Path Attribute
        set_aspath_prepend (list): Prepend BGP AS-Path Attribute
        set_regular_community (list): Regular Community either using number in AA:NN format (where AA and NN are between (0-65535)) or pre-defined value
        set_large_community (list): Large Community in AA:BB:CC format (where AA, BB and CC are between (0-4294967295))
    """

    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(value="/route-map")

        params = []

        params.append(
            VersionedParamPath(
                "action",
                path="action",
                default="deny",
                values=("deny", "permit"),
            )
        )
        params.append(VersionedParamPath("description", path="description"))
        params.append(
            VersionedParamPath(
                "match_as_path_access_list", path="match/as-path-access-list"
            )
        )
        params.append(
            VersionedParamPath(
                "match_regular_community", path="match/regular-community"
            )
        )
        params.append(
            VersionedParamPath("match_large_community", path="match/large-community")
        )
        params.append(
            VersionedParamPath(
                "match_extended_community", path="match/extended-community"
            )
        )
        params.append(VersionedParamPath("match_interface", path="match/interface"))
        params.append(VersionedParamPath("match_origin", path="match/origin"))
        params.append(VersionedParamPath("match_metric", path="match/metric"))
        params.append(VersionedParamPath("match_tag", path="match/tag"))
        params.append(
            VersionedParamPath("match_local_preference", path="match/local-preference")
        )
        params.append(VersionedParamPath("match_peer", path="match/peer"))
        params.append(
            VersionedParamPath(
                "match_ipv4_address_access_list",
                path="match/ipv4/address/access-list",
            )
        )
        params.append(
            VersionedParamPath(
                "match_ipv4_address_prefix_list",
                path="match/ipv4/address/prefix-list",
            )
        )
        params.append(
            VersionedParamPath(
                "match_ipv4_next_hop_access_list",
                path="match/ipv4/next-hop/access-list",
            )
        )
        params.append(
            VersionedParamPath(
                "match_ipv4_next_hop_prefix_list",
                path="match/ipv4/next-hop/prefix-list",
            )
        )
        params.append(
            VersionedParamPath(
                "match_ipv4_route_source_access_list",
                path="match/ipv4/route-source/access-list",
            )
        )
        params.append(
            VersionedParamPath(
                "match_ipv4_route_source_prefix_list",
                path="match/ipv4/route-source/prefix-list",
            )
        )
        params.append(
            VersionedParamPath(
                "match_ipv6_address_access_list",
                path="match/ipv6/address/access-list",
            )
        )
        params.append(
            VersionedParamPath(
                "match_ipv6_address_prefix_list",
                path="match/ipv6/address/prefix-list",
            )
        )
        params.append(
            VersionedParamPath(
                "match_ipv6_next_hop_access_list",
                path="match/ipv6/next-hop/access-list",
            )
        )
        params.append(
            VersionedParamPath(
                "match_ipv6_next_hop_prefix_list",
                path="match/ipv6/next-hop/prefix-list",
            )
        )
        params.append(VersionedParamPath("set_aggregator_as", path="set/aggregator/as"))
        params.append(
            VersionedParamPath(
                "set_aggregator_router_id", path="set/aggregator/router-id"
            )
        )
        params.append(VersionedParamPath("set_tag", path="set/tag"))
        params.append(
            VersionedParamPath("set_local_preference", path="set/local-preference")
        )
        params.append(VersionedParamPath("set_weight", path="set/weight"))
        params.append(VersionedParamPath("set_origin", path="set/origin"))
        params.append(
            VersionedParamPath(
                "set_atomic_aggregate",
                path="set/atomic-aggregate",
                vartype="yesno",
            )
        )
        params.append(VersionedParamPath("set_metric_action", path="set/metric/action"))
        params.append(VersionedParamPath("set_metric_value", path="set/metric/value"))
        params.append(VersionedParamPath("set_originator_id", path="set/originator-id"))
        params.append(
            VersionedParamPath(
                "set_ipv4_source_address", path="set/ipv4/source-address"
            )
        )
        params.append(VersionedParamPath("set_ipv4_next_hop", path="set/ipv4/next-hop"))
        params.append(
            VersionedParamPath(
                "set_ipv6_source_address", path="set/ipv6/source-address"
            )
        )
        params.append(VersionedParamPath("set_ipv6_next_hop", path="set/ipv6/next-hop"))
        params.append(
            VersionedParamPath(
                "set_ipv6_next_hop_prefer_global",
                path="set/ipv6-nexthop-prefer-global",
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "set_overwrite_regular_community",
                path="set/overwrite-regular-community",
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "set_overwrite_large_community",
                path="set/overwrite-large-community",
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "set_remove_regular_community", path="set/remove-regular-community"
            )
        )
        params.append(
            VersionedParamPath(
                "set_remove_large_community", path="set/remove-large-community"
            )
        )
        params.append(
            VersionedParamPath(
                "set_aspath_exclude", path="set/aspath-exclude", vartype="member"
            )
        )
        params.append(
            VersionedParamPath(
                "set_aspath_prepend", path="set/aspath-prepend", vartype="member"
            )
        )
        params.append(
            VersionedParamPath(
                "set_regular_community",
                path="set/regular-community",
                vartype="member",
                values=(
                    "blackhole",
                    "no-peer",
                    "graceful-shutdown",
                    "accept-own",
                    "local-as",
                    "route-filter-v4",
                    "route-filter-v6",
                    "no-advertise",
                    "no-export",
                    "internet",
                ),
            )
        )
        params.append(
            VersionedParamPath(
                "set_large_community", path="set/large-community", vartype="member"
            )
        )

        self._params = tuple(params)


class RoutingProfileFilterRouteMapsRedistribution(VersionedPanObject):
    """Filter BGP Route-Maps Redistribution

    Args:
        name (str): The name of BGP route map redistribution
        description (str): BGP route map description redistribution
    """

    SUFFIX = ENTRY

    CHILDTYPES = ("network.RoutingProfileFilterRouteMapsEntry",)

    def _setup(self):
        self._xpaths.add_profile(
            value="/network/routing-profile/filters/route-maps/redistribution/redist-entry"
        )

        params = []

        params.append(VersionedParamPath("description", path="description"))

        ### TODO: implement routing-profile -> filters -> route-maps -> redistribution -> redist -> from-protocol, to-protocol e.g.
        #   <entry name="custom-filter-route-map-redistribution">
        #     <bgp>
        #       <ospf>
        #         <route-map>
        #           <entry name="1">
        #             <set>
        #               <metric-type>type-2</metric-type>
        #             </set>
        #             <action>deny</action>
        #           </entry>
        #         </route-map>
        #       </ospf>
        #     </bgp>
        #   </entry>

        self._params = tuple(params)
