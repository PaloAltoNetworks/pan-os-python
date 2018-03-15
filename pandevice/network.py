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

# import modules
import re
import logging
import xml.etree.ElementTree as ET
import pandevice
from pandevice.base import PanObject, Root, MEMBER, ENTRY
from pandevice.base import VarPath as Var
from pandevice import getlogger, string_or_list
from pandevice import device
from pandevice.base import VersionedPanObject
from pandevice.base import VersionedParamPath
from pandevice.base import VsysOperations

# import other parts of this pandevice package
import pandevice.errors as err

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
        Interface: An instantiated subclass of :class:`pandevice.network.Interface`

    """
    name = str(name)
    if name.startswith("ethernet") and '.' not in name:
        return EthernetInterface(name, *args, **kwargs)
    elif name.startswith("ae") and '.' not in name:
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
            of :class:`pandevice.network.Interface`.
        zone_profile (str): Zone protection profile
        log_setting (str): Log forwarding setting
        enable_user_identification (bool): If user identification is enabled
        include_acl (list/str): User identification ACL include list
        exclude_acl (list/str): User identification ACL exclude list

    """
    ROOT = Root.VSYS
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value='/zone')
        self._xpaths.add_profile(
            value='{0}/zone'.format(self._TEMPLATE_VSYS_XPATH),
            parents=('Template', ))

        # params
        params = []

        params.append(VersionedParamPath(
            'mode', default='layer3', path='network/{mode}',
            values=['tap', 'virtual-wire', 'layer2', 'layer3', 'external']))
        params.append(VersionedParamPath(
            'interface', path='network/{mode}', vartype='member'))
        params.append(VersionedParamPath(
            'zone_profile', path='network/zone-protection-profile'))
        params.append(VersionedParamPath(
            'log_setting', path='network/log-setting'))
        params.append(VersionedParamPath(
            'enable_user_identification', vartype='yesno',
            path='enable-user-identification'))
        params.append(VersionedParamPath(
            'include_acl', vartype='member',
            path='user-acl/include-list'))
        params.append(VersionedParamPath(
            'exclude_acl', vartype='member',
            path='user-acl/exclude-list'))

        self._params = tuple(params)


class StaticMac(VersionedPanObject):
    """Static MAC address for a Vlan

    Can be added to a :class:`pandevice.network.Vlan` object

    Args:
        interface (str): Name of an interface

    """
    SUFFIX = ENTRY
    NAME = 'mac'

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value='/mac')

        # params
        params = []

        params.append(VersionedParamPath(
            'interface', path='interface'))

        self._params = tuple(params)


class Vlan(VsysOperations):
    """Vlan

    Args:
        interface (list): List of interface names
        virtual-interface (VlanInterface): The layer3 vlan interface for this vlan

    """
    SUFFIX = ENTRY
    ROOT = Root.DEVICE
    CHILDTYPES = (
        'network.StaticMac',
    )

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value='/network/vlan')
        self._xpaths.add_profile(
            value='{0}/network/vlan'.format(self._TEMPLATE_DEVICE_XPATH),
            parents=('Template', ))

        # xpath_imports
        self._xpath_imports.add_profile(value='/network/vlan')

        # params
        params = []

        params.append(VersionedParamPath(
            'interface', vartype='member', path='interface'))
        params.append(VersionedParamPath(
            'virtual_interface', path='/virtual-interface/interface'))

        self._params = tuple(params)


class IPv6Address(VersionedPanObject):
    """IPv6 Address

    Can be added to any :class:`pandevice.network.Interface` subclass
    that supports IPv6.

    Args:
        enabled-on-interface (bool): Enabled IPv6 on the interface this
            object was added to
        prefix (bool): Use interface ID as host portion
        anycast (bool): Enable anycast
        advertise_enabled (bool): Enabled router advertisements
        valid_lifetime (int): Valid lifetime
        onlink_flag (bool):
        auto_config_flag (bool):

    """
    SUFFIX = ENTRY
    NAME = "address"

    def _setup(self):
        # xpaths
        # Non-mode interface xpaths
        self._xpaths.add_profile(value='/ipv6/address')
        # Mode interface xpaths (mode: layer3)
        self._xpaths.add_profile(
            value='/layer3/ipv6/address',
            parents=('EthernetInterface', 'AggregateInterface'))

        # params
        params = []

        params.append(VersionedParamPath(
            'enable_on_interface', vartype='yesno',
            path='enable-on-interface'))
        params.append(VersionedParamPath(
            'prefix', vartype='exist', path='prefix'))
        params.append(VersionedParamPath(
            'anycast', vartype='exist', path='anycast'))
        params.append(VersionedParamPath(
            'advertise_enabled', vartype='yesno',
            path='advertise/enable'))
        params.append(VersionedParamPath(
            'valid_lifetime', vartype='int',
            path='advertise/valid-lifetime'))
        params.append(VersionedParamPath(
            'preferred_lifetime', vartype='int',
            path='advertise/preferred-lifetime'))
        params.append(VersionedParamPath(
            'onlink_flag', vartype='yesno',
            path='advertise/onlink-flag'))
        params.append(VersionedParamPath(
            'auto_config_flag', vartype='yesno',
            path='advertise/auto-config-flag'))

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
        return self.state == 'up'

    def set_zone(self, zone_name, mode=None, refresh=False,
                 update=False, running_config=False):
        """Set the zone for this interface

        Creates a reference to this interface in the specified zone and removes
        references to this interface from all other zones. The zone will be
        created if it doesn't exist.

        Args:
            zone_name (str): The name of the Zone or a
                :class:`pandevice.network.Zone` instance
            mode (str): The mode of the zone. See
                :class:`pandevice.network.Zone` for possible values
            refresh (bool): Refresh the relevant current state of the device
                before taking action (Default: False)
            update (bool): Apply the changes to the device (Default: False)
            running_config: If refresh is True, refresh from the running
                configuration (Default: False)

        Returns:
            Zone: The zone for this interface after the operation completes

        """
        if mode is None:
            mode = self.DEFAULT_MODE

        return self._set_reference(
            zone_name, Zone, "interface", True, refresh,
            update, running_config, mode=mode)

    def set_virtual_router(self, virtual_router_name, refresh=False, update=False, running_config=False):
        """Set the virtual router for this interface

        Creates a reference to this interface in the specified virtual router
        and removes references to this interface from all other virtual
        routers. The virtual router will be created if it doesn't exist.

        Args:
            virtual_router_name (str): The name of the VirtualRouter or
                a :class:`pandevice.network.VirtualRouter` instance
            refresh (bool): Refresh the relevant current state of the device
                before taking action (Default: False)
            update (bool): Apply the changes to the device (Default: False)
            running_config: If refresh is True, refresh from the running
                configuration (Default: False)

        Returns:
            Zone: The zone for this interface after the operation completes

        """
        return self._set_reference(virtual_router_name, VirtualRouter,
                                   "interface", True, refresh, update,
                                   running_config)

    def set_vlan(self, vlan_name, refresh=False,
                 update=False, running_config=False):
        """Set the vlan for this interface

        Creates a reference to this interface in the specified vlan and removes
        references to this interface from all other interfaces.  The vlan will
        be created if it doesn't exist.

        Args:
            vlan_name (str): The name of the vlan or
                a :class:`pandevice.network.Vlan` instance
            refresh (bool): Refresh the relevant current state of the device
                before taking action (Default: False)
            update (bool): Apply the changes to the device (Default: False)
            running_config: If refresh is True, refresh from the running
                configuration (Default: False)

        Raises:
            AttributeError: if this class is not allowed to use this function.

        Returns:
            Zone: The zone for this interface after the operation completes

        """
        if not self.ALLOW_SET_VLAN:
            msg = 'Class "{0}" cannot invoke this function'
            raise AttributeError(msg.format(self.__class__))

        return self._set_reference(vlan_name, Vlan, "interface", True,
                                   refresh, update, running_config)

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
            entry.update((k, pandevice.convert_if_int(v))
                         for k, v in entry.items())

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

    def full_delete(self, refresh=False, delete_referencing_objects=False,
                    include_vsys=False):
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
    NAME = 'ip'

    def _setup(self):
        # xpaths
        # Interface xpaths
        self._xpaths.add_profile(value='/layer3/arp')
        # Subinterface xpaths
        self._xpaths.add_profile(
            value='/arp',
            parents=('Layer3Subinterface', ))

        # params
        params = []

        params.append(VersionedParamPath(
            'hw_address', path='hw-address'))
        params.append(VersionedParamPath(
            'interface', path='interface'))

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
        self._xpaths.add_profile(value='/network/virtual-wire')
        self._xpaths.add_profile(
            value='{0}/network/virtual-wire'.format(self._TEMPLATE_DEVICE_XPATH),
            parents=('Template', ))

        # xpath imports
        self._xpath_imports.add_profile(value='/network/virtual-wire')

        # params
        params = []

        params.append(VersionedParamPath(
            'tag', path='tag-allowed', vartype='int'))
        params.append(VersionedParamPath(
            'interface1', path='interface1'))
        params.append(VersionedParamPath(
            'interface2', path='interface2'))
        params.append(VersionedParamPath(
            'multicast', path='multicast-firewalling/enable',
            default=False, vartype='yesno'))
        params.append(VersionedParamPath(
            'pass_through', path='link-state-pass-through/enable',
            default=True, vartype='yesno'))

        self._params = tuple(params)


class Subinterface(Interface):
    """Subinterface class

    Do not instantiate this object. Use a subclass.

    """
    _BASE_INTERFACE_NAME = 'entry BASE_INTERFACE_NAME'
    _BASE_INTERFACE_TYPE = 'var BASE_INTERFACE_TYPE'

    def set_name(self):
        """Create a name appropriate for a subinterface if it isn't already"""
        if '.' not in self.name:
            self.name = '{0}.{1}'.format(self.name, self.tag)

    @property
    def XPATH(self):
        path = super(Subinterface, self).XPATH

        if self._BASE_INTERFACE_TYPE in path:
            if self.uid.startswith('ae'):
                rep = 'aggregate-ethernet'
            else:
                rep = 'ethernet'
            path = path.replace(self._BASE_INTERFACE_TYPE, rep)

        if self._BASE_INTERFACE_NAME in path:
            base = self.uid.split('.')[0]
            path = path.replace(self._BASE_INTERFACE_NAME,
                                "entry[@name='{0}']".format(base))

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

    def set_zone(self, zone_name, mode=None, refresh=False, update=False, running_config=False):
        raise err.PanDeviceError("Unable to set zone on abstract subinterface because layer must be known to set zone")

    def set_virtual_router(self, virtual_router_name, refresh=False, update=False, running_config=False):
        """Set the virtual router for this interface

        Creates a reference to this interface in the specified virtual router and removes references
        to this interface from all other virtual routers. The virtual router will be created if it doesn't exist.

        Args:
            virtual_router_name (str): The name of the VirtualRouter or
                a :class:`pandevice.network.VirtualRouter` instance
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
        return interface._set_reference(virtual_router_name, VirtualRouter, "interface", True, refresh=False, update=update, running_config=running_config)

    def get_layered_subinterface(self, mode, add=True):
        """Instantiate a regular subinterface type from this AbstractSubinterface

        Converts an abstract subinterface to a real subinterface by offering it a mode.

        Args:
            mode (str): Mode of the subinterface ('layer3' or 'layer2')
            add (bool): Add the newly instantiated subinterface to the base interface object

        Returns:
            Subinterface: A :class:`pandevice.network.Layer3Subinterface` or
            :class:`pandevice.network.Layer2Subinterface` instance, depending on the mode argument

        """
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
                if add:
                    layered_subinterface = self.parent.add(subintclass(self.name, tag=self.tag))
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
        tag (int): Tag for the interface, aka vlan id
        ip (tuple): Interface IPv4 addresses
        ipv6_enabled (bool): IPv6 Enabled (requires IPv6Address child object)
        management_profile (ManagementProfile): Interface Management Profile
        mtu(int): MTU for interface
        adjust_tcp_mss (bool): Adjust TCP MSS
        netflow_profile (NetflowProfile): Netflow profile
        comment (str): The interface's comment
        ipv4_mss_adjust(int): TCP MSS adjustment for ipv4
        ipv6_mss_adjust(int): TCP MSS adjustment for ipv6
        enable_dhcp (bool): Enable DHCP on this interface
        create_dhcp_default_route (bool): Create default route pointing to default gateway provided by server
        dhcp_default_route_metric (int): Metric for the DHCP default route

    """
    DEFAULT_MODE = 'layer3'
    CHILDTYPES = (
        "network.IPv6Address",
        "network.Arp",
    )

    def _setup(self):
        # xpaths for parents: EthernetInterface, AggregateInterface)
        self._xpaths.add_profile(value='/layer3/units')
        # xpaths for parents: firewall.Firewall, device.Vsys
        self._xpaths.add_profile(
            parents=('Firewall', 'Vsys'),
            value=('/network/interface/{0}/{1}/layer3/units'.format(
                self._BASE_INTERFACE_TYPE, self._BASE_INTERFACE_NAME)))
        self._xpaths.add_profile(
            value='{0}/network/interface/{1}/{2}/layer3/units'.format(
                self._TEMPLATE_DEVICE_XPATH,
                self._BASE_INTERFACE_TYPE,
                self._BASE_INTERFACE_NAME),
            parents=('Template', ))

        # xpath imports
        self._xpath_imports.add_profile(value='/network/interface')

        # params
        params = []

        params.append(VersionedParamPath(
            'tag', path='tag', vartype='int'))
        params.append(VersionedParamPath(
            'ip', path='ip', vartype='entry'))
        params.append(VersionedParamPath(
            'ipv6_enabled', path='ipv6/enabled', vartype='yesno'))
        params.append(VersionedParamPath(
            'management_profile', path='interface-management-profile'))
        params.append(VersionedParamPath(
            'mtu', path='mtu', vartype='int'))
        params.append(VersionedParamPath(
            'adjust_tcp_mss', path='adjust-tcp-mss', vartype='yesno'))
        params[-1].add_profile(
            '7.1.0',
            vartype='yesno', path='adjust-tcp-mss/enable')
        params.append(VersionedParamPath(
            'netflow_profile', path='netflow-profile'))
        params.append(VersionedParamPath(
            'comment', path='comment'))
        params.append(VersionedParamPath(
            'ipv4_mss_adjust', exclude=True))
        params[-1].add_profile(
            '7.1.0',
            path='adjust-tcp-mss/ipv4-mss-adjustment', vartype='int')
        params.append(VersionedParamPath(
            'ipv6_mss_adjust', exclude=True))
        params[-1].add_profile(
            '7.1.0',
            path='adjust-tcp-mss/ipv6-mss-adjustment', vartype='int')
        params.append(VersionedParamPath(
            'enable_dhcp', path='dhcp-client/enable', vartype='yesno'))
        params.append(VersionedParamPath(
            'create_dhcp_default_route',
            path='dhcp-client/create-default-route', vartype='yesno'))
        params.append(VersionedParamPath(
            'dhcp_default_route_metric',
            path='dhcp-client/default-route-metric', vartype='int'))

        self._params = tuple(params)


class Layer2Subinterface(Subinterface):
    """Ethernet or Aggregate Subinterface in Layer 2 mode.

    Args:
        tag (int): Tag for the interface, aka vlan id
        lldp_enabled (bool): Enable LLDP
        lldp_profile (str): Reference to an lldp profile
        netflow_profile_l2 (NetflowProfile): Reference to a netflow profile
        comment (str): The interface's comment

    """
    SUFFIX = ENTRY
    DEFAULT_MODE = 'layer2'
    ALLOW_SET_VLAN = True

    def _setup(self):
        # xpaths for parents: EthernetInterface, AggregateInterface
        self._xpaths.add_profile(value='/layer2/units')
        # xpaths for parents: firewall.Firewall, device.Vsys
        self._xpaths.add_profile(
            parents=('Firewall', 'Vsys'),
            value=('/network/interface/{0}/{1}/layer2/units'.format(
                self._BASE_INTERFACE_TYPE, self._BASE_INTERFACE_NAME)))
        self._xpaths.add_profile(
            value='{0}/network/interface/{1}/{2}/layer2/units'.format(
                self._TEMPLATE_DEVICE_XPATH,
                self._BASE_INTERFACE_TYPE,
                self._BASE_INTERFACE_NAME),
            parents=('Template', ))

        # xpath imports
        self._xpath_imports.add_profile(value='/network/interface')

        # params
        params = []

        params.append(VersionedParamPath(
            'tag', path='tag', vartype='int'))
        params.append(VersionedParamPath(
            'lldp_enabled', path='lldp/enable', vartype='yesno'))
        params.append(VersionedParamPath(
            'lldp_profile', path='lldp/profile'))
        params.append(VersionedParamPath(
            'netflow_profile_l2', path='netflow-profile'))
        params.append(VersionedParamPath(
            'comment', path='comment'))

        self._params = tuple(params)


class PhysicalInterface(Interface):
    """Absract base class for Ethernet and Aggregate Interfaces

    Do not instantiate this object. Use a subclass.

    """
    def set_zone(self, zone_name, mode=None, refresh=False,
                 update=False, running_config=False):
        """Set the zone for this interface

        Creates a reference to this interface in the specified zone and removes
        references to this interface from all other zones. The zone will be
        created if it doesn't exist.

        Args:
            zone_name (str): The name of the Zone or a
                :class:`pandevice.network.Zone` instance
            mode (str): The mode of the zone. See
                :class:`pandevice.network.Zone` for possible values
            refresh (bool): Refresh the relevant current state of the device
                before taking action (Default: False)
            update (bool): Apply the changes to the device (Default: False)
            running_config: If refresh is True, refresh from the running
                configuration (Default: False)

        Returns:
            Zone: The zone for this interface after the operation completes

        """
        if mode is None:
            mode = self.mode

        return super(PhysicalInterface, self).set_zone(
            zone_name, mode, refresh, update, running_config)


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
        netflow_profile (NetflowProfile): Netflow profile
        lldp_enabled (bool): Layer2: Enable LLDP
        lldp_profile (str): Layer2: Reference to an lldp profile
        netflow_profile_l2 (NetflowProfile): Netflow profile
        link_speed (str): Link speed: eg. auto, 10, 100, 1000
        link_duplex (str): Link duplex: eg. auto, full, half
        link_state (str): Link state: eg. auto, up, down
        aggregate_group (str): Aggregate interface (eg. ae1)
        comment (str): The interface's comment
        ipv4_mss_adjust(int): TCP MSS adjustment for ipv4
        ipv6_mss_adjust(int): TCP MSS adjustment for ipv6
        enable_dhcp (bool): Enable DHCP on this interface
        create_dhcp_default_route (bool): Create default route pointing to default gateway provided by server
        dhcp_default_route_metric (int): Metric for the DHCP default route

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
        self._xpaths.add_profile(value='/network/interface/ethernet')
        self._xpaths.add_profile(
            value='{0}/network/interface/ethernet'.format(self._TEMPLATE_DEVICE_XPATH),
            parents=('Template', ))

        # xpath imports
        self._xpath_imports.add_profile(value='/network/interface')

        # params
        params = []

        params.append(VersionedParamPath(
            'mode', path='{mode}', default='layer3',
            values=[
                'layer3', 'layer2', 'virtual-wire', 'tap',
                'ha', 'decrypt-mirror', 'aggregate-group',
            ]))
        params.append(VersionedParamPath(
            'ip', path='{mode}/ip', vartype='entry',
            condition={'mode': 'layer3'}))
        params.append(VersionedParamPath(
            'ipv6_enabled', path='{mode}/ipv6/enabled', vartype='yesno',
            condition={'mode': 'layer3'}))
        params.append(VersionedParamPath(
            'management_profile', path='{mode}/interface-management-profile',
            condition={'mode': 'layer3'}))
        params.append(VersionedParamPath(
            'mtu', path='{mode}/mtu', vartype='int',
            condition={'mode': 'layer3'}))
        params.append(VersionedParamPath(
            'adjust_tcp_mss', path='{mode}/adjust-tcp-mss', vartype='yesno',
            condition={'mode': 'layer3'}))
        params[-1].add_profile(
            '7.1.0',
            path='{mode}/adjust-tcp-mss/enable',
            vartype='yesno', condition={'mode': 'layer3'})
        params.append(VersionedParamPath(
            'netflow_profile', path='{mode}/netflow-profile',
            condition={'mode': 'layer3'}))
        params.append(VersionedParamPath(
            'lldp_enabled', path='{mode}/lldp/enable', vartype='yesno',
            condition={'mode': 'layer2'}))
        params.append(VersionedParamPath(
            'lldp_profile', path='{mode}/lldp/profile',
            condition={'mode': 'layer2'}))
        params.append(VersionedParamPath(
            'netflow_profile_l2', path='{mode}/netflow-profile',
            condition={'mode': 'layer2'}))
        params.append(VersionedParamPath(
            'link_speed', path='link-speed'))
        params.append(VersionedParamPath(
            'link_duplex', path='link-duplex'))
        params.append(VersionedParamPath(
            'link_state', path='link-state'))
        params.append(VersionedParamPath(
            'aggregate_group', path='aggregate-group',
            condition={'mode': 'aggregate-group'}))
        params.append(VersionedParamPath(
            'comment', path='comment'))
        params.append(VersionedParamPath(
            'ipv4_mss_adjust', exclude=True))
        params[-1].add_profile(
            '7.1.0',
            path='{mode}/adjust-tcp-mss/ipv4-mss-adjustment',
            vartype='int', condition={'mode': 'layer3'})
        params.append(VersionedParamPath(
            'ipv6_mss_adjust', exclude=True))
        params[-1].add_profile(
            '7.1.0',
            path='{mode}/adjust-tcp-mss/ipv6-mss-adjustment',
            vartype='int', condition={'mode': 'layer3'})
        params.append(VersionedParamPath(
            'enable_dhcp', path='{mode}/dhcp-client/enable',
            vartype='yesno', condition={'mode': 'layer3'}))
        params.append(VersionedParamPath(
            'create_dhcp_default_route',
            path='{mode}/dhcp-client/create-default-route',
            vartype='yesno', condition={'mode': 'layer3'}))
        params.append(VersionedParamPath(
            'dhcp_default_route_metric',
            path='{mode}/dhcp-client/default-route-metric',
            vartype='int', condition={'mode': 'layer3'}))

        self._params = tuple(params)


class AggregateInterface(PhysicalInterface):
    """Aggregate interface (eg. 'ae1')

    Args:
        name (str): Name of interface (eg. 'ae1')
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
        netflow_profile (NetflowProfile): Netflow profile
        lldp_enabled (bool): Layer2: Enable LLDP
        lldp_profile (str): Layer2: Reference to an lldp profile
        netflow_profile_l2 (NetflowProfile): Netflow profile
        comment (str): The interface's comment
        ipv4_mss_adjust(int): TCP MSS adjustment for ipv4
        ipv6_mss_adjust(int): TCP MSS adjustment for ipv6
        enable_dhcp (bool): Enable DHCP on this interface
        create_dhcp_default_route (bool): Create default route pointing to default gateway provided by server
        dhcp_default_route_metric (int): Metric for the DHCP default route

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
        self._xpaths.add_profile(value='/network/interface/aggregate-ethernet')
        self._xpaths.add_profile(
            value='{0}/network/interface/aggregate-ethernet'.format(self._TEMPLATE_DEVICE_XPATH),
            parents=('Template', ))

        # xpath imports
        self._xpath_imports.add_profile(value='/network/interface')

        # params
        params = []

        params.append(VersionedParamPath(
            'mode', path='{mode}', default='layer3',
            values=[
                'layer3', 'layer2', 'virtual-wire', 'tap',
                'ha', 'decrypt-mirror', 'aggregate-group',
            ]))
        params.append(VersionedParamPath(
            'ip', path='ip', vartype='entry'))
        params.append(VersionedParamPath(
            'ipv6_enabled', path='ipv6/enabled', vartype='yesno'))
        params.append(VersionedParamPath(
            'management_profile', path='interface-management-profile'))
        params.append(VersionedParamPath(
            'mtu', path='mtu', vartype='int'))
        params.append(VersionedParamPath(
            'adjust_tcp_mss', path='adjust-tcp-mss', vartype='yesno'))
        params[-1].add_profile(
            '7.1.0',
            vartype='yesno', path='adjust-tcp-mss/enable')
        params.append(VersionedParamPath(
            'netflow_profile', path='netflow-profile'))
        params.append(VersionedParamPath(
            'lldp_enabled', path='lldp/enable', vartype='yesno'))
        params.append(VersionedParamPath(
            'lldp_profile', path='lldp/profile'))
        params.append(VersionedParamPath(
            'netflow_profile_l2', path='netflow-profile'))
        params.append(VersionedParamPath(
            'comment', path='comment'))
        params.append(VersionedParamPath(
            'ipv4_mss_adjust', exclude=True))
        params[-1].add_profile(
            '7.1.0',
            path='adjust-tcp-mss/ipv4-mss-adjustment', vartype='int')
        params.append(VersionedParamPath(
            'ipv6_mss_adjust', exclude=True))
        params[-1].add_profile(
            '7.1.0',
            path='adjust-tcp-mss/ipv6-mss-adjustment', vartype='int')
        params.append(VersionedParamPath(
            'enable_dhcp', path='{mode}/dhcp-client/enable',
            vartype='yesno', condition={'mode': 'layer3'}))
        params.append(VersionedParamPath(
            'create_dhcp_default_route',
            path='{mode}/dhcp-client/create-default-route',
            vartype='yesno', condition={'mode': 'layer3'}))
        params.append(VersionedParamPath(
            'dhcp_default_route_metric',
            path='{mode}/dhcp-client/default-route-metric',
            vartype='int', condition={'mode': 'layer3'}))

        self._params = tuple(params)


class VlanInterface(Interface):
    """Vlan interface

    Args:
        ip (tuple): Interface IPv4 addresses
        ipv6_enabled (bool): IPv6 Enabled (requires IPv6Address child object)
        management_profile (ManagementProfile): Interface Management Profile
        mtu(int): MTU for interface
        adjust_tcp_mss (bool): Adjust TCP MSS
        netflow_profile (NetflowProfile): Netflow profile
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
        self._xpaths.add_profile(value='/network/interface/vlan/units')
        self._xpaths.add_profile(
            value='{0}/network/interface/vlan/units'.format(self._TEMPLATE_DEVICE_XPATH),
            parents=('Template', ))

        # xpath imports
        self._xpath_imports.add_profile(value='/network/interface')

        # params
        params = []

        params.append(VersionedParamPath(
            'ip', path='ip', vartype='entry'))
        params.append(VersionedParamPath(
            'ipv6_enabled', path='ipv6/enabled', vartype='yesno'))
        params.append(VersionedParamPath(
            'management_profile', path='interface-management-profile'))
        params.append(VersionedParamPath(
            'mtu', path='mtu', vartype='int'))
        params.append(VersionedParamPath(
            'adjust_tcp_mss', path='adjust-tcp-mss', vartype='yesno'))
        params[-1].add_profile(
            '7.1.0',
            vartype='yesno', path='adjust-tcp-mss/enable')
        params.append(VersionedParamPath(
            'netflow_profile', path='netflow-profile'))
        params.append(VersionedParamPath(
            'comment', path='comment'))
        params.append(VersionedParamPath(
            'ipv4_mss_adjust', exclude=True))
        params[-1].add_profile(
            '7.1.0',
            path='adjust-tcp-mss/ipv4-mss-adjustment', vartype='int')
        params.append(VersionedParamPath(
            'ipv6_mss_adjust', exclude=True))
        params[-1].add_profile(
            '7.1.0',
            path='adjust-tcp-mss/ipv6-mss-adjustment', vartype='int')
        params.append(VersionedParamPath(
            'enable_dhcp', path='dhcp-client/enable', vartype='yesno'))
        params.append(VersionedParamPath(
            'create_dhcp_default_route',
            path='dhcp-client/create-default-route', vartype='yesno'))
        params.append(VersionedParamPath(
            'dhcp_default_route_metric',
            path='dhcp-client/default-route-metric', vartype='int'))

        self._params = tuple(params)


class LoopbackInterface(Interface):
    """Loopback interface

    Args:
        ip (tuple): Interface IPv4 addresses
        ipv6_enabled (bool): IPv6 Enabled (requires IPv6Address child object)
        management_profile (ManagementProfile): Interface Management Profile
        mtu(int): MTU for interface
        adjust_tcp_mss (bool): Adjust TCP MSS
        netflow_profile (NetflowProfile): Netflow profile
        comment (str): The interface's comment
        ipv4_mss_adjust(int): TCP MSS adjustment for ipv4
        ipv6_mss_adjust(int): TCP MSS adjustment for ipv6

    """
    CHILDTYPES = (
        "network.IPv6Address",
    )

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value='/network/interface/loopback/units')
        self._xpaths.add_profile(
            value='{0}/network/interface/loopback/units'.format(self._TEMPLATE_DEVICE_XPATH),
            parents=('Template', ))

        # xpath imports
        self._xpath_imports.add_profile(value='/network/interface')

        # params
        params = []

        params.append(VersionedParamPath(
            'ip', path='ip', vartype='entry'))
        params.append(VersionedParamPath(
            'ipv6_enabled', path='ipv6/enabled', vartype='yesno'))
        params.append(VersionedParamPath(
            'management_profile', path='interface-management-profile'))
        params.append(VersionedParamPath(
            'mtu', path='mtu', vartype='int'))
        params.append(VersionedParamPath(
            'adjust_tcp_mss', path='adjust-tcp-mss', vartype='yesno'))
        params[-1].add_profile(
            '7.1.0',
            vartype='yesno', path='adjust-tcp-mss/enable')
        params.append(VersionedParamPath(
            'netflow_profile', path='netflow-profile'))
        params.append(VersionedParamPath(
            'comment', path='comment'))
        params.append(VersionedParamPath(
            'ipv4_mss_adjust', exclude=True))
        params[-1].add_profile(
            '7.1.0',
            path='adjust-tcp-mss/ipv4-mss-adjustment', vartype='int')
        params.append(VersionedParamPath(
            'ipv6_mss_adjust', exclude=True))
        params[-1].add_profile(
            '7.1.0',
            path='adjust-tcp-mss/ipv6-mss-adjustment', vartype='int')

        self._params = tuple(params)


class TunnelInterface(Interface):
    """Tunnel interface

    Args:
        ip (tuple): Interface IPv4 addresses
        ipv6_enabled (bool): IPv6 Enabled (requires IPv6Address child object)
        management_profile (ManagementProfile): Interface Management Profile
        mtu(int): MTU for interface
        netflow_profile (NetflowProfile): Netflow profile
        comment (str): The interface's comment

    """
    CHILDTYPES = (
        "network.IPv6Address",
    )

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value='/network/interface/tunnel/units')
        self._xpaths.add_profile(
            value='{0}/network/interface/tunnel/units'.format(self._TEMPLATE_DEVICE_XPATH),
            parents=('Template', ))

        # xpath imports
        self._xpath_imports.add_profile(value='/network/interface')

        # params
        params = []

        params.append(VersionedParamPath(
            'ip', path='ip', vartype='entry'))
        params.append(VersionedParamPath(
            'ipv6_enabled', path='ipv6/enabled', vartype='yesno'))
        params.append(VersionedParamPath(
            'management_profile', path='interface-management-profile'))
        params.append(VersionedParamPath(
            'mtu', path='mtu', vartype='int'))
        params.append(VersionedParamPath(
            'netflow_profile', path='netflow-profile'))
        params.append(VersionedParamPath(
            'comment', path='comment'))

        self._params = tuple(params)


class StaticRoute(VersionedPanObject):
    """Static Route

    Add to a :class:`pandevice.network.VirtualRouter` instance.

    Args:
        name (str): The name
        destination (str): Destination network
        nexthop_type (str): ip-address or discard
        nexthop (str): Next hop IP address
        interface (str): Next hop interface
        admin_dist (str): Administrative distance
        metric (int): Metric (Default: 10)

    """
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value='/routing-table/ip/static-route')

        # params
        params = []

        params.append(VersionedParamPath(
            'destination', path='destination'))
        params.append(VersionedParamPath(
            'nexthop_type', default='ip-address',
            values=['discard', 'ip-address'],
            path='nexthop/{nexthop_type}'))
        params.append(VersionedParamPath(
            'nexthop', path='nexthop/{nexthop_type}'))
        params.append(VersionedParamPath(
            'interface', path='interface'))
        params.append(VersionedParamPath(
            'admin_dist', vartype='int', path='admin-dist'))
        params.append(VersionedParamPath(
            'metric', default=10, vartype='int', path='metric'))

        self._params = tuple(params)


class StaticRouteV6(VersionedPanObject):
    """IPV6 Static Route

    Add to a :class:`pandevice.network.VirtualRouter` instance.

    Args:
        name (str): The name
        destination (str): Destination network
        nexthop_type (str): ip-address or discard
        nexthop (str): Next hop IP address
        interface (str): Next hop interface
        admin_dist (str): Administrative distance
        metric (int): Metric (Default: 10)

    """
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value='/routing-table/ipv6/static-route')

        # params
        params = []

        params.append(VersionedParamPath(
            'destination', path='destination'))
        params.append(VersionedParamPath(
            'nexthop_type', default='ipv6-address',
            values=['discard', 'ipv6-address'],
            path='nexthop/{nexthop_type}'))
        params.append(VersionedParamPath(
            'nexthop', path='nexthop/{nexthop_type}'))
        params.append(VersionedParamPath(
            'interface', path='interface'))
        params.append(VersionedParamPath(
            'admin_dist', vartype='int', path='admin-dist'))
        params.append(VersionedParamPath(
            'metric', default=10, vartype='int', path='metric'))

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
    _DEFAULT_NAME = 'default'
    SUFFIX = ENTRY
    CHILDTYPES = (
        "network.StaticRoute",
        "network.StaticRouteV6",
        "network.RedistributionProfile",
        "network.Ospf",
    )

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value='/network/virtual-router')
        self._xpaths.add_profile(
            value='{0}/network/virtual-router'.format(self._TEMPLATE_DEVICE_XPATH),
            parents=('Template', ))

        # xpath imports
        self._xpath_imports.add_profile(value='/network/virtual-router')

        # params
        params = []

        params.append(VersionedParamPath(
            'interface', path='interface', vartype='member'))

        admin_dists = (
            ('ad_static', 'static'), ('ad_static_ipv6', 'static-ipv6'),
            ('ad_ospf_int', 'ospf-int'), ('ad_ospf_ext', 'ospf-ext'),
            ('ad_ospfv3_int', 'ospfv3-int'), ('ad_ospfv3_ext', 'ospfv3-ext'),
            ('ad_ibgp', 'ibgp'), ('ad_ebgp', 'ebgp'), ('ad_rip', 'rip')
        )

        for var_name, path in admin_dists:
            params.append(VersionedParamPath(
                var_name, vartype='int', path='admin-dists/' + path))

        self._params = tuple(params)


class RedistributionProfile(VersionedPanObject):
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
        self._xpaths.add_profile(value='/protocol/redist-profile')

        params = []

        params.append(VersionedParamPath(
            'priority', vartype='int'))
        params.append(VersionedParamPath(
            'action', values=['no-redist', 'redist'], path='action/{action}'))
        params.append(VersionedParamPath(
            'filter_type', path='filter/type', vartype='member'))
        params.append(VersionedParamPath(
            'filter_interface', path='filter/interface', vartype='member'))
        params.append(VersionedParamPath(
            'filter_destination', path='filter/destination', vartype='member'))
        params.append(VersionedParamPath(
            'filter_nexthop', path='filter/nexthop', vartype='member'))
        params.append(VersionedParamPath(
            'ospf_filter_pathtype', path='filter/ospf/path-type',
            vartype='member'))
        params.append(VersionedParamPath(
            'ospf_filter_area', path='filter/ospf/area', vartype='member'))
        params.append(VersionedParamPath(
            'ospf_filter_tag', path='filter/ospf/tag', vartype='member'))
        params.append(VersionedParamPath(
            'bgp_filter_community', path='filter/bgp/community',
            vartype='member'))
        params.append(VersionedParamPath(
            'bgp_filter_extended_community',
            path='filter/bgp/extended-community', vartype='member'))

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
        self._xpaths.add_profile(value='/protocol/ospf')

        params = []

        params.append(VersionedParamPath(
            'enable', default=True, path='enable', vartype='yesno'))
        params.append(VersionedParamPath(
            'router_id'))
        params.append(VersionedParamPath(
            'reject_default_route', vartype='yesno'))
        params.append(VersionedParamPath(
            'allow_redist_default_route', vartype='yesno'))
        params.append(VersionedParamPath(
            'rfc1583', vartype='yesno'))
        # TODO: Add flood prevention
        params.append(VersionedParamPath(
            'spf_calculation_delay', path='timers/spf-calculation-delay',
            vartype='int'))
        params.append(VersionedParamPath(
            'lsa_interval', path='timers/lsa-interval', vartype='int'))
        params.append(VersionedParamPath(
            'graceful_restart_enable', path='graceful-restart/enable',
            vartype='yesno'))
        params.append(VersionedParamPath(
            'gr_grace_period', path='graceful-restart/grace-period',
            vartype='int'))
        params.append(VersionedParamPath(
            'gr_helper_enable', path='graceful-restart/helper-enable',
            vartype='yesno'))
        params.append(VersionedParamPath(
            'gr_strict_lsa_checking',
            path='graceful-restart/strict-LSA-checking', vartype='yesno'))
        params.append(VersionedParamPath(
            'gr_max_neighbor_restart_time',
            path='graceful-restart/max-neighbor-restart-time', vartype='int'))

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
        self._xpaths.add_profile(value='/area')

        params = []

        params.append(VersionedParamPath(
            'type', default='normal', values=['normal', 'stub', 'nssa'],
            path='type/{type}'))
        params.append(VersionedParamPath(
            'accept_summary',
            condition={'type': ['stub', 'nssa']},
            path='type/{type}/accept-summary',
            vartype='yesno'))
        params.append(VersionedParamPath(
            'default_route_advertise',
            default='disable',
            condition={'type': ['stub', 'nssa']},
            values=['disable', 'advertise'],
            path='type/{type}/default-route/{default_route_advertise}'))
        params.append(VersionedParamPath(
            'default_route_advertise_metric',
            condition={
                'type': ['stub', 'nssa'],
                'default_route_advertise': 'advertise'},
            path='type/{type}/default-route/advertise/metric',
            vartype='int'))
        params.append(VersionedParamPath(
            'default_route_advertise_type',
            default='ext-2',
            condition={'type': 'nssa', 'default_route_advertise': 'advertise'},
            values=['ext-1', 'ext-2'],
            path='type/nssa/default-route/advertise/type'))

        self._params = tuple(params)


class OspfRange(VersionedPanObject):
    """OSPF Range

    Args:
        name (str): IP network with prefix
        mode (str): 'advertise' or 'suppress' (Default: advertise)

    """
    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(value='/range')

        params = []

        params.append(VersionedParamPath(
            'mode', default='advertise', values=['advertise', 'suppress'],
            path='{mode}'))

        self._params = tuple(params)


class OspfNssaExternalRange(VersionedPanObject):
    """OSPF NSSA External Range

    Args:
        name (str): IP network with prefix
        mode (str): 'advertise' or 'suppress' (Default: advertise)

    """
    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(value='/type/nssa/nssa-ext-range')

        params = []

        params.append(VersionedParamPath(
            'mode', default='advertise', values=['advertise', 'suppress'],
            path='{mode}'))

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
        authentication (str): Reference to a :class:`pandevice.network.OspfAuthProfile`

    """
    SUFFIX = ENTRY
    CHILDTYPES = (
        "network.OspfNeighbor",
    )

    def _setup(self):
        self._xpaths.add_profile(value='/interface')

        params = []

        params.append(VersionedParamPath(
            'enable', vartype='yesno'))
        params.append(VersionedParamPath(
            'passive', vartype='yesno'))
        params.append(VersionedParamPath(
            'link_type', default='broadcast',
            values=['broadcast', 'p2p', 'p2mp'], path='link-type/{link_type}'))
        params.append(VersionedParamPath(
            'metric', vartype='int'))
        params.append(VersionedParamPath(
            'priority', vartype='int'))
        params.append(VersionedParamPath(
            'hello_interval', vartype='int'))
        params.append(VersionedParamPath(
            'dead_counts', vartype='int'))
        params.append(VersionedParamPath(
            'retransmit_interval', vartype='int'))
        params.append(VersionedParamPath(
            'transit_delay', vartype='int'))
        params.append(VersionedParamPath(
            'gr_delay', vartype='int'))
        params.append(VersionedParamPath(
            'authentication'))

        self._params = tuple(params)


class OspfNeighbor(VersionedPanObject):
    """OSPF Neighbor

    Args:
        name (str): IP of neighbor
        metric (int): Metric

    """
    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(value='/neighbor')

        params = []

        params.append(VersionedParamPath(
            'metric', vartype='int', exclude=True))

        self._params = tuple(params)


class OspfAuthProfile(VersionedPanObject):
    """OSPF Authentication Profile

    Args:
        name (str): Name of Auth Profile
        type (str): 'password' or 'md5'
        password (str): The password if type is set to 'password'.
            If type is set to 'md5', add a :class:`pandevice.network.OspfAuthProfileMd5`

    """
    SUFFIX = ENTRY
    CHILDTYPES = (
        "network.OspfAuthProfileMd5",
    )

    def _setup(self):
        self._xpaths.add_profile(value='/auth-profile')

        params = []

        params.append(VersionedParamPath(
            'type', values=['password', 'md5'], path='{type}'))
        params.append(VersionedParamPath(
            'password', condition={'type': 'password'}, path='{type}'))

        self._params = tuple(params)


class OspfAuthProfileMd5(VersionedPanObject):
    """OSPF Authentication Profile

    Args:
        keyid (int): Identifier for key
        key (str): The authentication key
        preferred (bool): This key is preferred

    """
    SUFFIX = ENTRY
    NAME = 'keyid'

    def _setup(self):
        self._xpaths.add_profile(value='/md5')

        params = []

        params.append(VersionedParamPath(
            'key', vartype='encrypted'))
        params.append(VersionedParamPath(
            'preferred', vartype='yesno'))

        self._params = tuple(params)


class OspfExportRules(VersionedPanObject):
    """OSPF Export Rules

    Args:
        name (str): IP subnet or :class:`pandevice.network.RedistributionProfile`
        new_path_type (str): New path type, 'ext-1' or 'ext-2' (Default: ext-2)
        new_tag (str): New tag (int or IP format)
        metric (int): Metric

    """
    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(value='/export-rules')

        params = []

        params.append(VersionedParamPath(
            'new_path_type', default='ext-2', values=['ext-1', 'ext-2']))
        params.append(VersionedParamPath(
            'new_tag'))
        params.append(VersionedParamPath(
            'metric', vartype='int'))

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
        self._xpaths.add_profile(
            value='/network/profiles/interface-management-profile')
        self._xpaths.add_profile(
            value='{0}/network/profiles/interface-management-profile'.format(self._TEMPLATE_DEVICE_XPATH),
            parents=('Template', ))

        # params
        params = []

        yesnos = ('ping', 'telnet', 'ssh', 'http', 'http-ocsp', 'https',
                  'snmp', 'response-pages', 'userid-service',
                  'userid-syslog-listener-ssl', 'userid-syslog-listener-udp')
        for yn in yesnos:
            params.append(VersionedParamPath(
                yn, path=yn, vartype='yesno'))
        params.append(VersionedParamPath(
            'permitted-ip', path='permitted-ip', vartype='entry'))

        self._params = tuple(params)


class IkeGateway(VersionedPanObject):
    """IKE Gateway.

    Args:
        name: IKE gateway name
        version: (7.0+) ikev1, ikev2, or ikev2-prefered (default: ikev1)
        enable_ipv6 (bool): (7.0+) enable IPv6
        disabled (bool): (7.0+) disable this object
        peer_ip_type: ip or dynamic (default: ip)
        peer_ip_value: the IP for peer_ip_type of 'ip'
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
        cert_enable_strict_validation (bool): Enable strict valication of
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
        ikev2_cookie_valication (bool): (7.0+) require cookie
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
        self._xpaths.add_profile(value='/network/ike/gateway')
        self._xpaths.add_profile(
            value='{0}/network/ike/gateway'.format(self._TEMPLATE_DEVICE_XPATH),
            parents=('Template', ))

        # params
        params = []

        params.append(VersionedParamPath(
            'version', default='ikev1', exclude=True))
        params[-1].add_profile(
            '7.0.0',
            values=('ikev1', 'ikev2', 'ikev2-preferred'),
            path='protocol/version')
        params.append(VersionedParamPath(
            'enable_ipv6', exclude=True))
        params[-1].add_profile(
            '7.0.0',
            path='ipv6', vartype='yesno')
        params.append(VersionedParamPath(
            'disabled', exclude=True))
        params[-1].add_profile(
            '7.0.0',
            path='disabled', vartype='yesno')
        params.append(VersionedParamPath(
            'peer_ip_type', values=('ip', 'dynamic'), default='ip',
            path='peer-address/{peer_ip_type}'))
        params.append(VersionedParamPath(
            'peer_ip_value', condition={'peer_ip_type': 'ip'},
            path='peer-address/{peer_ip_type}'))
        params.append(VersionedParamPath(
            'interface', path='local-address/interface'))
        params.append(VersionedParamPath(
            'local_ip_address_type', values=('ip', 'floating-ip'),
            path='local-address/{local_ip_address_type}'))
        params.append(VersionedParamPath(
            'local_ip_address',
            path='local-address/{local_ip_address_type}'))
        params.append(VersionedParamPath(
            'auth_type', values=('pre-shared-key', 'certificate'),
            default='pre-shared-key', path='authentication/{auth_type}'))
        params.append(VersionedParamPath(
            'pre_shared_key', condition={'auth_type': 'pre-shared-key'},
            vartype='encrypted', path='authentication/{auth_type}/key'))
        params.append(VersionedParamPath(
            'local_id_type', values=('ipaddr', 'fqdn', 'ufqdn', 'keyid', 'dn'),
            path='local-id/type'))
        params.append(VersionedParamPath(
            'local_id_value', path='local-id/id'))
        params.append(VersionedParamPath(
            'peer_id_type', values=('ipaddr', 'fqdn', 'ufqdn', 'keyid', 'dn'),
            path='peer-id/type'))
        params.append(VersionedParamPath(
            'peer_id_value', path='peer-id/id'))
        params.append(VersionedParamPath(
            'peer_id_check', default='exact',
            values=('exact', 'wildcard'), path='peer-id/matching'))
        params.append(VersionedParamPath(
            'local_cert', condition={'auth_type': 'certificate'},
            path='authentication/{auth_type}/local-certificate'))
        params[-1].add_profile(
            '7.0.0',
            condition={'auth_type': 'certificate'},
            path='authentication/{auth_type}/local-certificate/name')
        params.append(VersionedParamPath(
            'cert_enable_hash_and_url', exclude=True))
        params[-1].add_profile(
            '7.0.0',
            vartype='yesno', condition={'auth_type': 'certificate'},
            path='authentication/{auth_type}/local-certificate/hash-and-url/enable')
        params.append(VersionedParamPath(
            'cert_base_url', exclude=True))
        params[-1].add_profile(
            '7.0.0',
            condition={'auth_type': 'certificate'},
            path='authentication/{auth_type}/local-certificate/hash-and-url/base-url')
        params.append(VersionedParamPath(
            'cert_use_management_as_source', exclude=True))
        params[-1].add_profile(
            '7.0.0',
            vartype='yesno', condition={'auth_type': 'certificate'},
            path='authentication/{auth_type}/use-management-as-source')
        params.append(VersionedParamPath(
            'cert_permit_payload_mismatch',
            vartype='yesno', condition={'auth_type': 'certificate'},
            path='authentication/{auth_type}/allow-id-payload-mismatch'))
        params.append(VersionedParamPath(
            'cert_profile', condition={'auth_type': 'certificate'},
            path='authentication/{auth_type}/certificate-profile'))
        params.append(VersionedParamPath(
            'cert_enable_strict_validation',
            vartype='yesno', condition={'auth_type': 'certificate'},
            path='authentication/{auth_type}/strict-validation-revocation'))
        params.append(VersionedParamPath(
            'enable_passive_mode', vartype='yesno',
            path='protocol-common/passive-mode'))
        params.append(VersionedParamPath(
            'enable_nat_traversal', vartype='yesno',
            path='protocol-common/nat-traversal/enable'))
        params.append(VersionedParamPath(
            'nat_traversal_keep_alive', vartype='int',
            path='protocol-common/nat-traversal/keep-alive-interval'))
        params.append(VersionedParamPath(
            'nat_traversal_enable_udp_checksum', vartype='yesno',
            path='protocol-common/nat-traversal/udp-checksum-enable'))
        params.append(VersionedParamPath(
            'enable_fragmentation', vartype='yesno',
            path='protocol-common/fragmentation/enable'))
        params.append(VersionedParamPath(
            'ikev1_exchange_mode', values=('auto', 'main', 'aggressive'),
            path='protocol/ikev1/exchange-mode'))
        params.append(VersionedParamPath(
            'ikev1_crypto_profile', path='protocol/ikev1/ike-crypto-profile'))
        params.append(VersionedParamPath(
            'enable_dead_peer_detection', vartype='yesno',
            path='protocol/ikev1/dpd/enable'))
        params.append(VersionedParamPath(
            'dead_peer_detection_interval', vartype='int',
            path='protocol/ikev1/dpd/interval'))
        params.append(VersionedParamPath(
            'dead_peer_detection_retry', vartype='int',
            path='protocol/ikev1/dpd/retry'))
        params.append(VersionedParamPath(
            'ikev1_send_commit_bit', exclude=True, vartype='yesno',
            path='protocol/ikev1/commit-bit'))
        params.append(VersionedParamPath(
            'ikev1_initial_contact', exclude=True, vartype='yesno',
            path='protocol/ikev1/initial-contact'))
        params.append(VersionedParamPath(
            'ikev2_crypto_profile', exclude=True))
        params[-1].add_profile(
            '7.0.0',
            path='protocol/ikev2/ike-crypto-profile')
        params.append(VersionedParamPath(
            'ikev2_cookie_validation', exclude=True))
        params[-1].add_profile(
            '7.0.0',
            vartype='yesno',
            path='protocol/ikev2/require-cookie')
        params.append(VersionedParamPath(
            'ikev2_send_peer_id', exclude=True))
        params[-1].add_profile(
            '7.0.0',
            vartype='yesno', exclude=True,
            path='protocol/ikev2/send-peer-id')
        params.append(VersionedParamPath(
            'enable_liveness_check', exclude=True))
        params[-1].add_profile(
            '7.0.0',
            vartype='yesno', path='protocol/ikev2/dpd/enable')
        params.append(VersionedParamPath(
            'liveness_check_interval', exclude=True))
        params[-1].add_profile(
            '7.0.0',
            vartype='int', path='protocol/ikev2/dpd/interval')

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
        anti_replay (bool): enable anti-replay check on this tunnel
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
        'network.IpsecTunnelIpv4ProxyId',
        'network.IpsecTunnelIpv6ProxyId',
    )

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value='/network/tunnel/ipsec')
        self._xpaths.add_profile(
            value='{0}/network/tunnel/ipsec'.format(self._TEMPLATE_DEVICE_XPATH),
            parents=('Template', ))

        # params
        params = []

        params.append(VersionedParamPath(
            'tunnel_interface', path='tunnel-interface'))
        params.append(VersionedParamPath(
            'anti_replay', path='anti-replay', vartype='yesno'))
        params.append(VersionedParamPath(
            'ipv6', exclude=True))
        params[-1].add_profile(
            '7.0.0',
            vartype='yesno', path='ipv6')
        params.append(VersionedParamPath(
            'type', default='auto-key', path='{type}',
            values=('auto-key', 'manual-key', 'global-protect-satellite')))
        params.append(VersionedParamPath(
            'ak_ike_gateway',
            condition={'type': 'auto-key'}, vartype='entry',
            path='{type}/ike-gateway'))
        params.append(VersionedParamPath(
            'ak_ipsec_crypto_profile', condition={'type': 'auto-key'},
            path='{type}/ipsec-crypto-profile'))
        params.append(VersionedParamPath(
            'mk_local_spi', condition={'type': 'manual-key'},
            path='{type}/local-spi'))
        params.append(VersionedParamPath(
            'mk_interface', condition={'type': 'manual-key'},
            path='{type}/local-address/interface'))
        params.append(VersionedParamPath(
            'mk_remote_spi', condition={'type': 'manual-key'},
            path='{type}/remote-spi'))
        params.append(VersionedParamPath(
            'mk_remote_address', condition={'type': 'manual-key'},
            path='{type}/peer-address/ip'))
        params.append(VersionedParamPath(
            'mk_local_address_ip', condition={'type': 'manual-key'},
            path='{type}/local-address/ip'))
        params.append(VersionedParamPath(
            'mk_local_address_floating_ip', exclude=True))
        params[-1].add_profile(
            '7.0.0',
            condition={'type': 'manual-key'},
            path='{type}/local-address/floating-ip')
        params.append(VersionedParamPath(
            'mk_protocol', condition={'type': 'manual-key'},
            values=('esp', 'ah'), path='{type}/{mk_protocol}'))
        params.append(VersionedParamPath(
            'mk_auth_type', condition={'type': 'manual-key'},
            values=('md5', 'sha1', 'sha256', 'sha384', 'sha512'),
            path='{type}/{mk_protocol}/authentication/{mk_auth_type}'))
        params.append(VersionedParamPath(
            'mk_auth_key',
            vartype='encrypted', condition={'type': 'manual-key'},
            path='{type}/{mk_protocol}/authentication/{mk_auth_type}/key'))
        params.append(VersionedParamPath(
            'mk_esp_encryption',
            values=(
                'des',
                '3des',
                'aes128',
                'aes192',
                'aes256',
                'null',
            ),
            path='{type}/{mk_protocol}/encryption/algorithm'))
        params[-1].add_profile(
            '7.0.0',
            condition={'type': 'manual-key', 'mk_protocol': 'esp'},
            values=(
                'des',
                '3des',
                'aes-128-cbc',
                'aes-192-cbc',
                'aes-256-cbc',
                'null',
            ),
            path='{type}/{mk_protocol}/encryption/algorithm')
        params.append(VersionedParamPath(
            'mk_esp_encryption_key', vartype='encrypted',
            condition={'type': 'manual-key', 'mk_protocol': 'esp'},
            path='{type}/{mk_protocol}/encryption/key'))
        params.append(VersionedParamPath(
            'gps_portal_address',
            condition={'type': 'global-protect-satellite'},
            path='{type}/portal-address'))
        params.append(VersionedParamPath(
            'gps_prefer_ipv6', exclude=True))
        params[-1].add_profile(
            '8.0.0',
            vartype='yesno', condition={'type': 'global-protect-satellite'},
            path='{type}/ipv6-preferred')
        params.append(VersionedParamPath(
            'gps_interface',
            condition={'type': 'global-protect-satellite'},
            path='{type}/local-address/interface'))
        params.append(VersionedParamPath(
            'gps_interface_ipv4_ip',
            condition={'type': 'global-protect-satellite'},
            path='{type}/local-address/ip'))
        params[-1].add_profile(
            '8.0.0',
            condition={'type': 'global-protect-satellite'},
            path='{type}/local-address/ip/ipv4')
        params.append(VersionedParamPath(
            'gps_interface_ipv6_ip', exclude=True))
        params[-1].add_profile(
            '8.0.0',
            condition={'type': 'global-protect-satellite'},
            path='{type}/local-address/ip/ipv6')
        params.append(VersionedParamPath(
            'gps_interface_ipv4_floating_ip', exclude=True))
        params[-1].add_profile(
            '7.0.0',
            condition={'type': 'global-protect-satellite'},
            path='{type}/local-address/floating-ip')
        params[-1].add_profile(
            '8.0.0',
            condition={'type': 'global-protect-satellite'},
            path='{type}/local-address/floating-ip/ipv4')
        params.append(VersionedParamPath(
            'gps_interface_ipv6_floating_ip', exclude=True))
        params[-1].add_profile(
            '8.0.0',
            condition={'type': 'global-protect-satellite'},
            path='{type}/local-address/floating-ip/ipv6')
        params.append(VersionedParamPath(
            'gps_publish_connected_routes', vartype='yesno',
            condition={'type': 'global-protect-satellite'},
            path='{type}/publish-connected-routes/enable'))
        params.append(VersionedParamPath(
            'gps_publish_routes', vartype='member',
            condition={'type': 'global-protect-satellite'},
            path='{type}/publish-routes'))
        params.append(VersionedParamPath(
            'gps_local_certificate',
            condition={'type': 'global-protect-satellite'},
            path='{type}/external-ca/local-certificate'))
        params.append(VersionedParamPath(
            'gps_certificate_profile',
            condition={'type': 'global-protect-satellite'},
            path='{type}/external-ca/certificate-profile'))
        params.append(VersionedParamPath(
            'anti_replay', default=True, vartype='yesno', path='anti-replay'))
        params.append(VersionedParamPath(
            'copy_tos', vartype='yesno', path='copy-tos'))
        params.append(VersionedParamPath(
            'copy_flow_label', exclude=True))
        params[-1].add_profile(
            '7.0.0',
            vartype='yesno', path='copy-flow-label')
        params.append(VersionedParamPath(
            'enable_tunnel_monitor',
            vartype='yesno', path='tunnel-monitor/enable'))
        params.append(VersionedParamPath(
            'tunnel_monitor_dest_ip', path='tunnel-monitor/destination-ip'))
        params.append(VersionedParamPath(
            'tunnel_monitor_proxy_id', exclude=True))
        params[-1].add_profile(
            '7.0.0',
            path='tunnel-monitor/proxy-id')
        params.append(VersionedParamPath(
            'tunnel_monitor_profile',
            path='tunnel-monitor/tunnel-monitor-profile'))
        params.append(VersionedParamPath(
            'disabled', exclude=True))
        params[-1].add_profile(
            '7.0.0',
            vartype='yesno', path='disabled')

        self._params = tuple(params)

    def set_mk_esp_encryption(self, value):
        """Version agnostic set for mk_esp_encryption.

        This object should be connected to a pandevice.Firewall before
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
        if value in ('des', '3des', 'null'):
            self.mk_esp_encryption = value
            return

        # Get the version specific values for mk_esp_encryption.
        self.nearest_pandevice()
        vals = self.about('mk_esp_encryption')['About']['Values']

        # Normalize the value.
        for masks in (
            ('aes128', 'aes-128-cbc'),
            ('aes192', 'aes-192-cbc'),
            ('aes256', 'aes-256-cbc'),
        ):
            if value in masks:
                break
        else:
            raise ValueError('Unknown encryption type: {0}'.format(value))

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
        number_proto (int): Numbered Protocol: protocol number (1-254)
        tcp_local_port (int): Protocol TCP: local port
        tcp_remote_port (int): Protocol TCP: remote port
        udp_local_port (int): Protocol UDP: local port
        udp_remote_port (int): Protocol UDP: remote port

    """
    ROOT = Root.DEVICE
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value='/auto-key/proxy-id')
        self._xpaths.add_profile(
            value='{0}/auto-key/proxy-id'.format(self._TEMPLATE_DEVICE_XPATH),
            parents=('Template', ))

        # params
        params = []

        params.append(VersionedParamPath(
            'local', path='local'))
        params.append(VersionedParamPath(
            'remote', path='remote'))
        params.append(VersionedParamPath(
            'any_protocol', vartype='exist', path='protocol/any'))
        params.append(VersionedParamPath(
            'number_protocol', vartype='int', path='protocol/number'))
        params.append(VersionedParamPath(
            'tcp_local_port', vartype='int', path='protocol/tcp/local-port'))
        params.append(VersionedParamPath(
            'tcp_remote_port', vartype='int', path='protocol/tcp/remote-port'))
        params.append(VersionedParamPath(
            'udp_local_port', vartype='int', path='protocol/udp/local-port'))
        params.append(VersionedParamPath(
            'udp_remote_port', vartype='int', path='protocol/udp/remote-port'))

        self._params = tuple(params)


class IpsecTunnelIpv6ProxyId(VersionedPanObject):
    """IKEv1 IPv6 proxy-id for auto-key IPSec tunnels.

    NOTE:  Only supported in 7.0 and forward.

    Args:
        name: The proxy ID
        local: IP subnet or IP address represents local network
        remote: IP subnet or IP address represents remote network
        any_proto (bool): Any protocol
        number_proto (int): Numbered Protocol: protocol number (1-254)
        tcp_local_port (int): Protocol TCP: local port
        tcp_remote_port (int): Protocol TCP: remote port
        udp_local_port (int): Protocol UDP: local port
        udp_remote_port (int): Protocol UDP: remote port

    """
    ROOT = Root.DEVICE
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value='/auto-key/proxy-id-v6')
        self._xpaths.add_profile(
            value='{0}/auto-key/proxy-id-v6'.format(self._TEMPLATE_DEVICE_XPATH),
            parents=('Template', ))

        # params
        params = []

        params.append(VersionedParamPath(
            'local', path='local'))
        params.append(VersionedParamPath(
            'remote', path='remote'))
        params.append(VersionedParamPath(
            'any_protocol', vartype='exist', path='protocol/any'))
        params.append(VersionedParamPath(
            'number_protocol', vartype='int', path='protocol/number'))
        params.append(VersionedParamPath(
            'tcp_local_port', vartype='int', path='protocol/tcp/local-port'))
        params.append(VersionedParamPath(
            'tcp_remote_port', vartype='int', path='protocol/tcp/remote-port'))
        params.append(VersionedParamPath(
            'udp_local_port', vartype='int', path='protocol/udp/local-port'))
        params.append(VersionedParamPath(
            'udp_remote_port', vartype='int', path='protocol/udp/remote-port'))

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
            value='/network/ike/crypto-profiles/ipsec-crypto-profiles')
        self._xpaths.add_profile(
            value='{0}/network/ike/crypto-profiles/ipsec-crypto-profiles'.format(self._TEMPLATE_DEVICE_XPATH),
            parents=('Template', ))

        # params
        params = []

        params.append(VersionedParamPath(
            'esp_encryption', vartype='member', path='esp/encryption',
            values=(
                'des',
                '3des',
                'aes128',
                'aes192',
                'aes256',
                'null')))
        params[-1].add_profile(
            '7.0.0',
            vartype='member', path='esp/encryption',
            values=(
                'des',
                '3des',
                'aes-128-cbc',
                'aes-192-cbc',
                'aes-256-cbc',
                'aes-128-gcm',
                'aes-256-gcm',
                'null'))
        params.append(VersionedParamPath(
            'esp_authentication', vartype='member', path='esp/authentication',
            values=('none', 'md5', 'sha1', 'sha256', 'sha384', 'sha512')))
        params.append(VersionedParamPath(
            'ah_authentication', vartype='member', path='ah/authentication',
            values=('md5', 'sha1', 'sha256', 'sha384', 'sha512')))
        params.append(VersionedParamPath(
            'dh_group', path='dh-group',
            values=(
                'no-pfs',
                'group1',
                'group2',
                'group5',
                'group14',
                'group19',
                'group20')))
        params.append(VersionedParamPath(
            'lifetime_seconds', vartype='int', path='lifetime/seconds'))
        params.append(VersionedParamPath(
            'lifetime_minutes', vartype='int', path='lifetime/minutes'))
        params.append(VersionedParamPath(
            'lifetime_hours', vartype='int', path='lifetime/hours'))
        params.append(VersionedParamPath(
            'lifetime_days', vartype='int', path='lifetime/days'))
        params.append(VersionedParamPath(
            'lifesize_kb', vartype='int', path='lifesize/kb'))
        params.append(VersionedParamPath(
            'lifesize_mb', vartype='int', path='lifesize/mb'))
        params.append(VersionedParamPath(
            'lifesize_gb', vartype='int', path='lifesize/gb'))
        params.append(VersionedParamPath(
            'lifesize_tb', vartype='int', path='lifesize/tb'))

        self._params = tuple(params)

    def set_esp_encryption(self, value):
        """Version agnostic set for esp_encryption.

        This object should be connected to a pandevice.Firewall before
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
            if token in ('des', '3des', 'null'):
                normalized.append(token)
                continue

            # Get the version specific values for mk_esp_encryption.
            vals = self.about('esp_encryption')['About']['Values']

            # Normalize the value.
            for masks in (
                ('aes128', 'aes-128-cbc'),
                ('aes192', 'aes-192-cbc'),
                ('aes256', 'aes-256-cbc'),
                ('aes-128-gcm', ),
                ('aes-256-gcm', ),
            ):
                if token in masks:
                    break
            else:
                raise ValueError('Unknown encryption type: {0}'.format(token))

            # Set the version specific encryption type.
            for x in vals:
                if x in masks:
                    normalized.append(x)
                    break
            else:
                raise ValueError(
                    'ESP encryption {0} not supported in this version'.format(
                        token))

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
            value='/network/ike/crypto-profiles/ike-crypto-profiles')
        self._xpaths.add_profile(
            value='{0}/network/ike/crypto-profiles/ike-crypto-profiles'.format(self._TEMPLATE_DEVICE_XPATH),
            parents=('Template', ))

        # params
        params = []

        params.append(VersionedParamPath(
            'dh_group', vartype='member', path='dh-group',
            values=('group1', 'group2', 'group5', 'group14')))
        params[-1].add_profile(
            '7.0.0',
            vartype='member', path='dh-group',
            values=('group1', 'group2', 'group5', 'group14', 'group19', 'group20'))
        params.append(VersionedParamPath(
            'authentication', vartype='member', path='hash',
            values=('md5', 'sha1', 'sha256', 'sha384', 'sha512')))
        params.append(VersionedParamPath(
            'encryption', vartype='member', path='encryption',
            values=('3des', 'aes128', 'aes192', 'aes256')))
        params[-1].add_profile(
            '7.0.0',
            vartype='member', path='encryption',
            values=('3des', 'aes-128-cbc', 'aes-192-cbc', 'aes-256-cbc'))
        params[-1].add_profile(
            '7.1.0',
            vartype='member', path='encryption',
            values=('des', '3des', 'aes-128-cbc', 'aes-192-cbc', 'aes-256-cbc'))
        params.append(VersionedParamPath(
            'lifetime_seconds', vartype='int', path='lifetime/seconds'))
        params.append(VersionedParamPath(
            'lifetime_minutes', vartype='int', path='lifetime/minutes'))
        params.append(VersionedParamPath(
            'lifetime_hours', vartype='int', path='lifetime/hours'))
        params.append(VersionedParamPath(
            'lifetime_days', vartype='int', path='lifetime/days'))
        params.append(VersionedParamPath(
            'authentication_multiple', exclude=True))
        params[-1].add_profile(
            '7.0.0',
            vartype='int', path='authentication-multiple')

        self._params = tuple(params)

    def set_encryption(self, value):
        """Version agnostic set for encryption.

        This object should be connected to a pandevice.Firewall before
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
            if token in ('3des'):
                normalized.append(token)
                continue

            # Get the version specific values for mk_esp_encryption.
            vals = self.about('encryption')['About']['Values']

            # Normalize the value.
            for masks in (
                ('3des', ),
                ('aes128', 'aes-128-cbc'),
                ('aes192', 'aes-192-cbc'),
                ('aes256', 'aes-256-cbc'),
            ):
                if token in masks:
                    break
            else:
                raise ValueError('Unknown encryption type: {0}'.format(token))

            # Set the version specific encryption type.
            for x in vals:
                if x in masks:
                    normalized.append(x)
                    break
            else:
                raise ValueError(
                    'Encryption {0} not supported in this version'.format(
                        token))

        self.encryption = normalized
