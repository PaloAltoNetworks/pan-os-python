#!/usr/bin/env python

# Copyright (c) 2015, Palo Alto Networks
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


"""High availability objects to configure HA for a firewall or Panorama"""

import inspect
import logging
import xml.etree.ElementTree as ET

import pan.xapi

import pandevice.errors as err
from pandevice import firewall, getlogger, isstring, network
from pandevice.base import ENTRY, MEMBER, PanDevice, PanObject, Root
from pandevice.base import VarPath as Var
from pandevice.base import VersionedPanObject, VersionedParamPath

logger = getlogger(__name__)


class HighAvailabilityInterface(PanObject):
    """Base class for high availability interface classes

    Do not instantiate this class.  Use its subclasses.

    """

    HA_SYNC = False

    # TODO: Support encryption
    def __init__(self, *args, **kwargs):
        # Store the 'port' variable
        # This is necessary because 'port' is a property
        # so that self.old_port can work correctly
        # XXX: better to remove the need for old_port in a future version
        try:
            args = list(args)
            port = args.pop(2)
        except IndexError:
            port = kwargs.pop("port", None)
        if type(self) == HighAvailabilityInterface:
            raise AssertionError(
                "Do not instantiate a HighAvailabilityInterface. Please use a subclass."
            )
        super(HighAvailabilityInterface, self).__init__(*args, **kwargs)
        self._port = port

        # This is used by setup_interface method to remove old interfaces
        self.old_port = None

    @property
    def port(self):
        return self._port

    @port.setter
    def port(self, value):
        if hasattr(self, "_port"):
            if value != self._port:
                self.old_port = self._port
        self._port = value

    @classmethod
    def variables(cls):
        return (
            Var("ip-address"),
            Var("netmask"),
            Var("port"),
            Var("gateway"),
            Var("link-speed"),
            Var("link-duplex"),
        )

    def setup_interface(self):
        """Setup the data interface as an HA interface

        Use this method to automatically convert the data interface
        to 'ha' mode. This must be done *before* this HA interface
        is created on the firewall.

        """
        pandevice = self.nearest_pandevice()
        if pandevice is None:
            return None
        if isstring(self.port):
            intname = self.port
        else:
            intname = str(self.port)
        intconfig_needed = False
        inttype = None
        if intname.startswith("ethernet"):
            intprefix = "ethernet"
            inttype = network.EthernetInterface
            intconfig_needed = True
        elif intname.startswith("ae"):
            intprefix = "ae"
            inttype = network.AggregateInterface
            intconfig_needed = True
        elif intname.startswith("management"):
            self.link_speed = None
            self.link_duplex = None
        if intconfig_needed:
            apply_needed = False
            interface = pandevice.find(
                intname, (network.EthernetInterface, network.AggregateInterface)
            )
            if interface is None:
                interface = pandevice.add(inttype(name=intname, mode="ha"))
                apply_needed = True
            elif interface.mode != "ha":
                interface.mode = "ha"
                apply_needed = True
            if inttype == network.EthernetInterface:
                if self.link_speed is not None:
                    # Transfer the link_speed to the eth interface
                    if interface.link_speed != self.link_speed:
                        interface.link_speed = self.link_speed
                        apply_needed = True
                if self.link_duplex is not None:
                    # Transfer the link_duplex to the eth interface
                    if interface.link_duplex != self.link_duplex:
                        interface.link_duplex = self.link_duplex
                        apply_needed = True
            self.link_speed = None
            self.link_duplex = None
            if apply_needed:
                interface.apply()
            return interface

    def delete_old_interface(self):
        """Delete the data interface previously used by this HA interface

        Use this if the 'port' of an HA interface was changed and the old
        interface needs to be cleaned up.

        """
        if self.old_port is not None:
            self.delete_interface(self.old_port)
            self.old_port = None

    def delete_interface(self, interface=None, pan_device=None):
        """Delete the data interface used by this HA interface

        Args:
            interface (HighAvailabilityInterface): The HA interface (HA1, HA2, etc)
            pan_device (PanDevice): The PanDevice object to apply the change

        """
        if pan_device is None:
            pan_device = self.nearest_pandevice()
        if pan_device is None:
            return None
        port = interface if interface is not None else self.port
        if isstring(port):
            intname = port
        else:
            intname = str(port)
        if intname.startswith("ethernet"):
            interface = pan_device.find(intname, network.EthernetInterface)
            if interface is None:
                # Already deleted
                return
            elif interface.mode == "ha":
                interface.delete()
        elif intname.startswith("ae"):
            interface = pan_device.find(intname, network.AggregateInterface)
            if interface is None:
                # Already deleted
                return
            elif interface.mode == "ha":
                interface.mode = "tap"
                interface.apply()


class HA1(HighAvailabilityInterface):
    """HA1 interface

    Args:
        ip-address (str): IP of the interface
        netmask (str): Netmask of the interface
        port (str): Interface to use for this HA interface (eg. ethernet1/5)
        gateway (str): Default gateway of the interface
        link_speed (str): Link speed
        link_duplex (str): Link duplex

    """

    # TODO: Encryption
    XPATH = "/interface/ha1"

    @classmethod
    def variables(cls):
        return super(HA1, HA1).variables() + (Var("monitor-hold-time", vartype="int"),)


class HA1Backup(HighAvailabilityInterface):
    """HA1 Backup interface

    Args:
        ip-address (str): IP of the interface
        netmask (str): Netmask of the interface
        port (str): Interface to use for this HA interface (eg. ethernet1/5)
        gateway (str): Default gateway of the interface
        link_speed (str): Link speed
        link_duplex (str): Link duplex

    """

    XPATH = "/interface/ha1-backup"


class HA2(HighAvailabilityInterface):
    """HA2 interface

    Args:
        ip-address (str): IP of the interface
        netmask (str): Netmask of the interface
        port (str): Interface to use for this HA interface (eg. ethernet1/5)
        gateway (str): Default gateway of the interface
        link_speed (str): Link speed
        link_duplex (str): Link duplex

    """

    XPATH = "/interface/ha2"


class HA2Backup(HighAvailabilityInterface):
    """HA2 Backup interface

    Args:
        ip-address (str): IP of the interface
        netmask (str): Netmask of the interface
        port (str): Interface to use for this HA interface (eg. ethernet1/5)
        gateway (str): Default gateway of the interface
        link_speed (str): Link speed
        link_duplex (str): Link duplex

    """

    XPATH = "/interface/ha2-backup"


class HA3(HighAvailabilityInterface):
    """HA3 interface

    Args:
        port (str): Interface to use for this HA interface (eg. ethernet1/5)
        link_speed (str): Link speed
        link_duplex (str): Link duplex

    """

    XPATH = "/interface/ha3"

    @classmethod
    def variables(cls):
        return (
            Var("port"),
            Var("link_speed"),
            Var("link_duplex"),
        )


class HighAvailability(VersionedPanObject):
    """High availability configuration base object

    All high availability configuration is in this object or is a child of this object

    Args:
        name: (unused, and may be omitted)
        enabled (bool): Enable HA (Default: True)
        group_id (int): The group identifier
        description (str): Description for HA pairing
        config_sync (bool): Enabled configuration synchronization (Default: True)
        peer_ip (str): HA Peer's HA1 IP address
        mode (str): Mode of HA: 'active-passive' or 'active-active' (Default: 'active-passive')
        passive_link_state (str): Passive link state
        state_sync (bool): Enabled state synchronization (Default: False)
        ha2_keepalive (bool): Enable HA2 keepalives
        ha2_keepalive_action (str): HA2 keepalive action
        ha2_keepalive_threshold (int): HA2 keepalive threshold
        peer_ip_backup (str): HA Peer's HA1 backup IP address
        device_id (int): HA3 device id (0 or 1)
        session_owner_selection (str): active-active session owner mode
        session_setup (str): active-active session setup mode
        tentative_hold_time (int): active-active tentative hold timer
        sync_qos (bool): active-active network sync qos
        sync_virtual_router (bool): active-active network sync virtual router
        ip_hash_key (str): active-active hash key used by ip-hash algorithm

    """

    ROOT = Root.DEVICE
    SUFFIX = None
    HA_SYNC = False
    CHILDTYPES = (
        "ha.HA1",
        "ha.HA1Backup",
        "ha.HA2",
        "ha.HA2Backup",
        "ha.HA3",
    )

    ACTIVE_PASSIVE = "active-passive"
    ACTIVE_ACTIVE = "active-active"

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/deviceconfig/high-availability")
        self._xpaths.add_profile(
            value="{0}/deviceconfig/high-availability".format(
                self._TEMPLATE_DEVICE_XPATH
            ),
            parents=("Template", "TemplateStack"),
        )

        # params
        params = []

        params.append(
            VersionedParamPath("enabled", default=True, vartype="yesno", path="enabled")
        )
        params.append(
            VersionedParamPath("group_id", default=1, vartype="entry", path="group")
        )
        params[-1].add_profile("8.1.0", vartype="int", path="group/group-id")
        params.append(
            VersionedParamPath("description", path="group/entry group_id/description")
        )
        params[-1].add_profile("8.1.0", path="group/description")
        params.append(
            VersionedParamPath(
                "config_sync",
                vartype="yesno",
                path="group/entry group_id/configuration-synchronization/enabled",
            )
        )
        params[-1].add_profile(
            "8.1.0", vartype="yesno", path="group/configuration-synchronization/enabled"
        )
        params.append(
            VersionedParamPath("peer_ip", path="group/entry group_id/peer-ip")
        )
        params[-1].add_profile("8.1.0", path="group/peer-ip")
        params.append(
            VersionedParamPath(
                "mode",
                default="active-passive",
                values=("active-passive", "active-active"),
                path="group/entry group_id/mode/{mode}",
            )
        )
        params[-1].add_profile(
            "8.1.0",
            values=("active-passive", "active-active"),
            path="group/mode/{mode}",
        )
        params.append(
            VersionedParamPath(
                "passive_link_state",
                condition={"mode": "active-passive"},
                path="group/entry group_id/mode/{mode}/passive-link-state",
            )
        )
        params[-1].add_profile(
            "8.1.0",
            condition={"mode": "active-passive"},
            path="group/mode/{mode}/passive-link-state",
        )
        params.append(
            VersionedParamPath(
                "state_sync",
                vartype="yesno",
                default=False,
                path="group/entry group_id/state-synchronization/enabled",
            )
        )
        params[-1].add_profile(
            "8.1.0", vartype="yesno", path="group/state-synchronization/enabled"
        )
        params.append(
            VersionedParamPath(
                "ha2_keepalive",
                vartype="yesno",
                path="group/entry group_id/state-synchronization/ha2-keep-alive/enabled",
            )
        )
        params[-1].add_profile(
            "8.1.0",
            vartype="yesno",
            path="group/state-synchronization/ha2-keep-alive/enabled",
        )
        params.append(
            VersionedParamPath(
                "ha2_keepalive_action",
                values=("log-only", "split-datapath"),
                path="group/entry group_id/state-synchronization/ha2-keep-alive/action",
            )
        )
        params[-1].add_profile(
            "8.1.0",
            values=("log-only", "split-datapath"),
            path="group/state-synchronization/ha2-keep-alive/action",
        )
        params.append(
            VersionedParamPath(
                "ha2_keepalive_threshold",
                vartype="int",
                path="group/entry group_id/state-synchronization/ha2-keep-alive/threshold",
            )
        )
        params[-1].add_profile(
            "8.1.0",
            vartype="int",
            path="group/state-synchronization/ha2-keep-alive/threshold",
        )
        params.append(
            VersionedParamPath(
                "peer_ip_backup", path="group/entry group_id/peer-ip-backup"
            )
        )
        params[-1].add_profile("8.1.0", path="group/peer-ip-backup")
        params.append(
            VersionedParamPath(
                "device_id",
                condition={"mode": "active-active"},
                values=(0, 1),
                vartype="int",
                path="group/entry group_id/mode/{mode}/device-id",
            )
        )
        params[-1].add_profile(
            "8.1.0",
            condition={"mode": "active-active"},
            values=(0, 1),
            vartype="int",
            path="group/mode/{mode}/device-id",
        )
        params.append(
            VersionedParamPath(
                "session_owner_selection",
                condition={
                    "mode": "active-active",
                    "session_owner_selection": "primary-device",
                },
                values=("primary-device", "first-packet"),
                path="group/entry group_id/mode/{mode}/session-owner-selection/{session_owner_selection}",
            )
        )
        params[-1].add_profile(
            "8.1.0",
            condition={
                "mode": "active-active",
                "session_owner_selection": "primary-device",
            },
            values=("primary-device", "first-packet"),
            path="group/mode/{mode}/session-owner-selection/{session_owner_selection}",
        )
        params.append(
            VersionedParamPath(
                "session_setup",
                condition={
                    "mode": "active-active",
                    "session_owner_selection": "first-packet",
                },
                values=("first-packet", "ip-modulo", "ip-hash", "primary-device"),
                path="group/entry group_id/mode/{mode}/session-owner-selection/first-packet/session-setup/{session_setup}",
            )
        )
        params[-1].add_profile(
            "8.1.0",
            condition={
                "mode": "active-active",
                "session_owner_selection": "first-packet",
            },
            values=("first-packet", "ip-modulo", "ip-hash", "primary-device"),
            path="group/mode/{mode}/session-owner-selection/first-packet/session-setup/{session_setup}",
        )
        params.append(
            VersionedParamPath(
                "tentative_hold_time",
                condition={"mode": "active-active"},
                vartype="int",
                path="group/entry group_id/mode/{mode}/tentative-hold-time",
            )
        )
        params[-1].add_profile(
            "8.1.0",
            condition={"mode": "active-active"},
            vartype="int",
            path="group/mode/{mode}/tentative-hold-time",
        )
        params.append(
            VersionedParamPath(
                "sync_qos",
                condition={"mode": "active-active"},
                vartype="yesno",
                path="group/entry group_id/mode/{mode}/network-configuration/sync/qos",
            )
        )
        params[-1].add_profile(
            "8.1.0",
            condition={"mode": "active-active"},
            vartype="yesno",
            path="group/mode/{mode}/network-configuration/sync/qos",
        )
        params.append(
            VersionedParamPath(
                "sync_virtual_router",
                condition={"mode": "active-active"},
                vartype="yesno",
                path="group/entry group_id/mode/{mode}/network-configuration/sync/virtual-router",
            )
        )
        params[-1].add_profile(
            "8.1.0",
            condition={"mode": "active-active"},
            vartype="yesno",
            path="group/mode/{mode}/network-configuration/sync/virtual-router",
        )
        params.append(
            VersionedParamPath(
                "ip_hash_key",
                condition={
                    "mode": "active-active",
                    "session_owner_selection": "first-packet",
                    "session_setup": "ip-hash",
                },
                values=("source", "source-and-destination"),
                path="group/entry group_id/mode/{mode}/session-owner-selection/first-packet/session-setup/{session_setup}/hash-key",
            )
        )
        params[-1].add_profile(
            "8.1.0",
            condition={
                "mode": "active-active",
                "session_owner_selection": "first-packet",
                "session_setup": "ip-hash",
            },
            values=("source", "source-and-destination"),
            path="group/mode/{mode}/session-owner-selection/first-packet/session-setup/{session_setup}/hash-key",
        )
        self._params = tuple(params)

        # stubs
        self._stubs.add_profile(
            "0.0.0",
            "interface/ha1",
            "interface/ha1-backup",
            "interface/ha2",
            "interface/ha2-backup",
            "interface/ha3",
        )
