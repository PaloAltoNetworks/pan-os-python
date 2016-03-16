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

# Author: Brian Torres-Gil <btorres-gil@paloaltonetworks.com>

# import modules
import logging
import inspect
import xml.etree.ElementTree as ET

import pan.xapi
from base import PanObject, PanDevice, Root, MEMBER, ENTRY
from base import VarPath as Var
import errors as err
import network
import firewall

# set logging to nullhandler to prevent exceptions if logging not enabled
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class HighAvailabilityInterface(PanObject):
    """Base class for high availability interface classes

    Do not instantiate this class.  Use its subclasses

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
            raise AssertionError("Do not instantiate a HighAvailabilityInterface. Please use a subclass.")
        super(HighAvailabilityInterface, self).__init__(*args, **kwargs)
        self._port = port

        # This is used by setup_interface method to remove old interfaces
        self.old_port = None

    @property
    def port(self):
        return self._port

    @port.setter
    def port(self, value):
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
        """Setup the interface itself as an HA interface"""
        pandevice = self.pandevice()
        if pandevice is None:
            return None
        if isinstance(self.port, basestring):
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
            interface = pandevice.find(intname, (network.EthernetInterface, network.AggregateInterface))
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
        if self.old_port is not None:
            self.delete_interface(self.old_port)
            self.old_port = None

    def delete_interface(self, interface=None, pan_device=None):
        """Delete the HA interface from the list of interfaces

        Args:
            interface (HighAvailabilityInterface): The HA interface (HA1, HA2, etc)
            pan_device (PanDevice): The PanDevice object to apply the change
        """
        if pan_device is None:
            pan_device = self.pandevice()
        if pan_device is None:
            return None
        port = interface if interface is not None else self.port
        if isinstance(port, basestring):
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
    """HA1 interface class

    TODO: Encryption

    """

    XPATH = "/interface/ha1"

    @classmethod
    def variables(cls):
        return super(HA1, HA1).variables() + (
            Var("monitor-hold-time", vartype="int"),
        )


class HA1Backup(HighAvailabilityInterface):
    XPATH = "/interface/ha1-backup"


class HA2(HighAvailabilityInterface):
    XPATH = "/interface/ha2"


class HA2Backup(HighAvailabilityInterface):
    XPATH = "/interface/ha2-backup"


class HA3(HighAvailabilityInterface):
    XPATH = "/interface/ha3"

    @classmethod
    def variables(cls):
        return (
            Var("port"),
        )


class HighAvailability(PanObject):

    ROOT = Root.DEVICE
    XPATH = "/deviceconfig/high-availability"
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

    @classmethod
    def variables(cls):
        return (
            # Enabled flag
            Var("enabled", vartype="bool", default=True),
            # Group
            Var("group", "group_id", vartype="entry", default=(1,)),
            Var("{{group_id}}/description"),
            Var("{{group_id}}/configuration-synchronization/enabled", "config_sync", vartype="bool"),
            Var("{{group_id}}/peer-ip"),
            # HA Mode (A/P, A/A)
            Var("{{group_id}}/mode/(active-passive|active-active)", "mode", default="active-passive"),
            Var("{{group_id}}/mode/{{mode}}/passive-link-state"),
            # State Synchronization
            Var("{{group_id}}/state-synchronization/enabled", "state_sync", vartype="bool", default=True),
            # HA2 Keep-alive
            Var("{{group_id}}/state-synchronization/ha2-keep-alive/enabled", "ha2_keepalive", vartype="bool"),
            Var("{{group_id}}/state-synchronization/ha2-keep-alive/action", "ha2_keepalive_action"),
            Var("{{group_id}}/state-synchronization/ha2-keep-alive/threshold", "ha2_keepalive_threshold", vartype="int"),
            Var("interface", vartype="none"),
            Var("interface/ha1", vartype="none"),
            Var("interface/ha1-backup", vartype="none"),
            Var("interface/ha2", vartype="none"),
            Var("interface/ha2-backup", vartype="none"),
            Var("interface/ha3", vartype="none"),
        )


