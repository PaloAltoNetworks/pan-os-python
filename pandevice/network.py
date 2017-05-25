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
from base import PanObject, Root, MEMBER, ENTRY, VsysImportMixin
from base import VarPath as Var
from pandevice import getlogger
from pandevice import device
from pandevice.base import VersionedPanObject
from pandevice.base import VersionedParamPath
from pandevice.base import VsysOperations

# import other parts of this pandevice package
import errors as err

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
        args = list(args)
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
        mode (str): The mode of the security zone. Must match the mode of the interface.
            Possible values: tap, virtual-wire, layer2, layer3, external
        interface (list): List of interface names or instantiated subclasses
            of :class:`pandevice.network.Interface`.

    """
    ROOT = Root.VSYS
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value='/zone')

        # params
        params = []

        params.append(VersionedParamPath(
            'mode', default='layer3', path='network/{mode}',
            values=['tap', 'virtual-wire', 'layer2', 'layer3', 'external']))
        params.append(VersionedParamPath(
            'interface', path='network/{mode}', vartype='member'))

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
    that supports IPv6

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
    XPATH = "/ipv6/address"
    SUFFIX = ENTRY
    NAME = "address"

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value='/ipv6/address')

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
                         for k, v in entry.iteritems())

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


class SubinterfaceArp(VersionedPanObject):
    """Static ARP Mapping

    Can be added to subinterfaces in 'layer3' mode

    Args:
        ip (str): The IP address
        hw_address (str): The MAC address for the static ARP

    """
    SUFFIX = ENTRY
    NAME = 'ip'

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value='/arp')

        # params
        params = []

        params.append(VersionedParamPath(
            'hw_address', path='hw-address'))

        self._params = tuple(params)


class EthernetInterfaceArp(SubinterfaceArp):
    """Static ARP Mapping

    Can be added to interfaces in 'layer3' mode

    Args:
        ip (str): The IP address
        hw_address (str): The MAC address for the static ARP

    """
    def _setup(self):
        super(EthernetInterfaceArp, self)._setup()

        # xpaths
        self._xpaths.add_profile(value='/layer3/arp')


class VirtualWire(VersionedPanObject):
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
    def set_name(self):
        """Create a name appropriate for a subinterface if it isn't already"""
        if '.' not in self.name:
            self.name = '{0}.{1}'.format(self.name, self.tag)


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

    """
    DEFAULT_MODE = 'layer3'
    CHILDTYPES = (
        "network.IPv6Address",
        "network.SubinterfaceArp",
        "network.ManagementProfile",
    )

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value='/layer3/units')

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
        params[-1].add_profile(
            '7.1.0',
            vartype='yesno',
            path='ipv6/neighbor-discovery/router-advertisement/enable')
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
            'ipv4_mss_adjust', path=None))
        params[-1].add_profile(
            '7.1.0',
            path='adjust-tcp-mss/ipv4-mss-adjustment', vartype='int')
        params.append(VersionedParamPath(
            'ipv6_mss_adjust', path=None))
        params[-1].add_profile(
            '7.1.0',
            path='adjust-tcp-mss/ipv6-mss-adjustment', vartype='int')

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
        # xpaths
        self._xpaths.add_profile(value='/layer2/units')

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

    """
    ALLOW_SET_VLAN = True
    CHILDTYPES = (
        "network.Layer3Subinterface",
        "network.Layer2Subinterface",
        "network.IPv6Address",
        "network.EthernetInterfaceArp",
        "network.ManagementProfile",
    )

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value='/network/interface/ethernet')

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
        params[-1].add_profile(
            '7.1.0',
            vartype='yesno', condition={'mode': 'layer3'},
            path='{mode}/ipv6/neighbor-discovery/router-advertisement/enable')
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
            'ipv4_mss_adjust', path=None))
        params[-1].add_profile(
            '7.1.0',
            path='{mode}/adjust-tcp-mss/ipv4-mss-adjustment',
            vartype='int', condition={'mode': 'layer3'})
        params.append(VersionedParamPath(
            'ipv6_mss_adjust', path=None))
        params[-1].add_profile(
            '7.1.0',
            path='{mode}/adjust-tcp-mss/ipv6-mss-adjustment',
            vartype='int', condition={'mode': 'layer3'})

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

    """
    ALLOW_SET_VLAN = True
    CHILDTYPES = (
        "network.Layer3Subinterface",
        "network.Layer2Subinterface",
        "network.IPv6Address",
        "network.EthernetInterfaceArp",
        "network.ManagementProfile",
    )

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value='/network/interface/aggregate-ethernet')

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
        params[-1].add_profile(
            '7.1.0',
            vartype='yesno',
            path='ipv6/neighbor-discovery/router-advertisement/enable')
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
            'ipv4_mss_adjust', path=None))
        params[-1].add_profile(
            '7.1.0',
            path='adjust-tcp-mss/ipv4-mss-adjustment', vartype='int')
        params.append(VersionedParamPath(
            'ipv6_mss_adjust', path=None))
        params[-1].add_profile(
            '7.1.0',
            path='adjust-tcp-mss/ipv6-mss-adjustment', vartype='int')

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

    """
    CHILDTYPES = (
        "network.IPv6Address",
        "network.EthernetInterfaceArp",
        "network.ManagementProfile",
    )

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value='/network/interface/vlan/units')

        # params
        params = []

        params.append(VersionedParamPath(
            'ip', path='ip', vartype='entry'))
        params.append(VersionedParamPath(
            'ipv6_enabled', path='ipv6/enabled', vartype='yesno'))
        params[-1].add_profile(
            '7.1.0',
            vartype='yesno',
            path='ipv6/neighbor-discovery/router-advertisement/enable')
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
            'ipv4_mss_adjust', path=None))
        params[-1].add_profile(
            '7.1.0',
            path='adjust-tcp-mss/ipv4-mss-adjustment', vartype='int')
        params.append(VersionedParamPath(
            'ipv6_mss_adjust', path=None))
        params[-1].add_profile(
            '7.1.0',
            path='adjust-tcp-mss/ipv6-mss-adjustment', vartype='int')

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
        "network.EthernetInterfaceArp",
        "network.ManagementProfile",
    )

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value='/network/interface/loopback/units')

        # params
        params = []

        params.append(VersionedParamPath(
            'ip', path='ip', vartype='entry'))
        params.append(VersionedParamPath(
            'ipv6_enabled', path='ipv6/enabled', vartype='yesno'))
        params[-1].add_profile(
            '7.1.0',
            vartype='yesno',
            path='ipv6/neighbor-discovery/router-advertisement/enable')
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
            'ipv4_mss_adjust', path=None))
        params[-1].add_profile(
            '7.1.0',
            path='adjust-tcp-mss/ipv4-mss-adjustment', vartype='int')
        params.append(VersionedParamPath(
            'ipv6_mss_adjust', path=None))
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
        adjust_tcp_mss (bool): Adjust TCP MSS
        netflow_profile (NetflowProfile): Netflow profile
        comment (str): The interface's comment
        ipv4_mss_adjust(int): TCP MSS adjustment for ipv4
        ipv6_mss_adjust(int): TCP MSS adjustment for ipv6

    """
    CHILDTYPES = (
        "network.IPv6Address",
        "network.EthernetInterfaceArp",
        "network.ManagementProfile",
    )

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value='/network/interface/tunnel/units')

        # params
        params = []

        params.append(VersionedParamPath(
            'ip', path='ip', vartype='entry'))
        params.append(VersionedParamPath(
            'ipv6_enabled', path='ipv6/enabled', vartype='yesno'))
        params[-1].add_profile(
            '7.1.0',
            vartype='yesno',
            path='ipv6/neighbor-discovery/router-advertisement/enable')
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
            'ipv4_mss_adjust', path=None))
        params[-1].add_profile(
            '7.1.0',
            path='adjust-tcp-mss/ipv4-mss-adjustment', vartype='int')
        params.append(VersionedParamPath(
            'ipv6_mss_adjust', path=None))
        params[-1].add_profile(
            '7.1.0',
            path='adjust-tcp-mss/ipv6-mss-adjustment', vartype='int')

        self._params = tuple(params)


class StaticRoute(VersionedPanObject):
    SUFFIX = ENTRY

    def _setup_xpaths(self):
        self._xpaths.add_profile(value='/routing-table/ip/static-route')

    def _setup(self):
        self._setup_xpaths()

        params = []

        params.append(VersionedParamPath(
            'destination', path='destination'))
        params.append(VersionedParamPath(
            'nexthop_type', default='ip-address',
            values=['discard', 'ip-address'],
            path='nexthop/{nexthop_type}'))
        params.append(VersionedParamPath(
            'nexthop', path='nexthop/ip-address'))
        params.append(VersionedParamPath(
            'interface', path='interface'))
        params.append(VersionedParamPath(
            'admin_dist', path='admin-dist'))
        params.append(VersionedParamPath(
            'metric', default=10, vartype='int', path='metric'))

        self._params = tuple(params)


class StaticRouteV6(StaticRoute):
    """IPV6 Static Route

    Add to a :class:`pandevice.network.VirtualRouter` instance.

    Args:
        destination (str): Destination network
        nexthop_type (str): ip-address or discard
        nexthop (str): Next hop IP address
        interface (str): Next hop interface
        admin-dist (str): Administrative distance
        metric (int): Metric (Default: 10)

    """
    def _setup_xpaths(self):
        self._xpaths.add_profile(value='/routing-table/ipv6/static-route')


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
        self._xpaths.add_profile(value='/network/virtual-router')

        # xpath imports
        self._xpath_imports.add_profile(value='/network/virtual-router')

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
            'ospf_filter_pathtype', path='filter/ospf/path-type', vartype='member'))
        params.append(VersionedParamPath(
            'ospf_filter_area', path='filter/ospf/area', vartype='member'))
        params.append(VersionedParamPath(
            'ospf_filter_tag', path='filter/ospf/tag', vartype='member'))
        params.append(VersionedParamPath(
            'bgp_filter_community', path='filter/bgp/community', vartype='member'))
        params.append(VersionedParamPath(
            'bgp_filter_extended_community', path='filter/bgp/extended-community', vartype='member'))

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
            'spf_calculation_delay', path='timers/spf-calculation-delay', vartype='int'))
        params.append(VersionedParamPath(
            'lsa_interval', path='timers/lsa-interval', vartype='int'))
        params.append(VersionedParamPath(
            'graceful_restart_enable', path='graceful-restart/enable', vartype='yesno'))
        params.append(VersionedParamPath(
            'gr_grace_period', path='graceful-restart/grace-period', vartype='int'))
        params.append(VersionedParamPath(
            'gr_helper_enable', path='graceful-restart/helper-enable', vartype='yesno'))
        params.append(VersionedParamPath(
            'gr_strict_lsa_checking', path='graceful-restart/strict-LSA-checking', vartype='yesno'))
        params.append(VersionedParamPath(
            'gr_max_neighbor_restart_time', path='graceful-restart/max-neighbor-restart-time', vartype='int'))

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
            'type', default='normal', values=['normal', 'stub', 'nssa'], path='type/{type}'))
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
            condition={'type': ['stub', 'nssa'], 'default_route_advertise': 'advertise'},
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
            'mode', default='advertise', values=['advertise', 'suppress'], path='{mode}'))

        self._params = tuple(params)


class OspfNssaExternalRange(VersionedPanObject):
    """OSPF NSSA External Range

    Args:
        name (str): IP network with prefix
        mode (str): 'advertise' or 'suppress' (Default: advertise)

    """
    SUFFIX = ENTRY

    def _setup(self):
        self._xpaths.add_profile(value='/nssa-ext-range')

        params = []

        params.append(VersionedParamPath(
            'mode', default='advertise', values=['advertise', 'suppress'], path='{mode}'))

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
            'link_type', default='broadcast', values=['broadcast', 'p2p', 'p2mp'], path='link-type/{link_type}'))
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
            'metric', vartype='int'))

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
