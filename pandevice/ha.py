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


class HAPair(firewall.Firewall):
    """A high availability pair of firewalls

    This class can be treated like a single firewall, but will act as a high availability pair
    of firewalls. Most API calls will go to a single firewall, and if connection to that firewall
    fails, the API call will go to the other firewall.

    Attributes:
        fw1 (firewall.Firewall): The main firewall. All API calls will be made to this firewall unless it is down
        fw2 (firewall.Firewall): The other firewall. Used when fw1 is down.
    """
    CONNECTION_EXCEPTIONS = (err.PanConnectionTimeout, err.PanURLError, err.PanSessionTimedOut)

    def __init__(self, fw1, fw2):
        super(HAPair, self).__init__()
        self.fw1 = fw1
        self.fw2 = fw2
        self.firewalls = [fw1, fw2]
        self.fw1.parent = self
        self.fw2.parent = self
        self.hostname = "HAPair:" + self.fw1.hostname + ":" + self.fw2.hostname
        self.is_virtual = fw1.is_virtual
        self.serial = fw1.serial
        self.vsys = fw1.vsys
        self.vsys_name = fw1.vsys_name
        self.multi_vsys = fw1.multi_vsys
        self._fw1_active = True
        self.fw1.serial_ha_pair = self.fw2.serial
        self.fw2.serial_ha_pair = self.fw1.serial

    class HAXapiWrapper(object):
        """Nested class to apply configuration correctly in an HA pair"""
        # TODO: comment the hell out of it!

        def __init__(self, ha_pair):
            self.ha_pair = ha_pair

            for name, method in inspect.getmembers(
                pan.xapi.PanXapi,
                inspect.ismethod):
                # Ignore hidden methods
                if name[0] == "_":
                    continue

                # Wrapper method.  This is used to create
                # methods in this class that match the methods in the
                # pan-python xapi class, and call the methods inside
                # a try/except block.
                wrapper_method = self.make_ha_method(name)

                # Create method matching each public method of the base class
                setattr(self, name, wrapper_method)

        def make_ha_method(self, method_name):
            def method(*args, **kwargs):
                try:
                    # Try making the API call to Firewall 1
                    return getattr(self.ha_pair.active_firewall.xapi, method_name)(*args, **kwargs)
                except HAPair.CONNECTION_EXCEPTIONS:
                    # There was a connection failure to Firewall 1
                    # Try making the API call to Firewall 2
                    self.ha_pair.toggle_active_firewall()
                    return getattr(self.ha_pair.active_firewall.xapi, method_name)(*args, **kwargs)
            return method

        @property
        def element_root(self):
            return self.ha_pair.active_firewall.xapi.element_root

        @property
        def element_result(self):
            return self.ha_pair.active_firewall.xapi.element_result

    @property
    def api_key(self):
        return "No API Key for HA Pair"

    @property
    def active_firewall(self):
        if self._fw1_active:
            return self.fw1
        else:
            return self.fw2

    @property
    def passive_firewall(self):
        if self._fw1_active:
            return self.fw2
        else:
            return self.fw1

    def generate_xapi(self):
        return HAPair.HAXapiWrapper(self)

    def xpath_bypass(self):
        return self._parent_xpath()

    def devices(self):
        return [self.fw1, self.fw2]

    def toggle_active_firewall(self):
        self._fw1_active = not self._fw1_active

    def activate_firewall1(self):
        self._fw1_active = True

    def activate_firewall2(self):
        self._fw1_active = False

    def refresh_system_info(self):
        self.fw1.refresh_system_info()
        self.fw2.refresh_system_info()
        self.serial = self.active_firewall.serial
        self.multi_vsys = self.active_firewall.multi_vsys
        self.serial_ha_peer = self.passive_firewall.serial

    def refresh_active_firewall(self):
        logger.debug("Refreshing active firewall in HA Pair")
        ha_state = self.active_firewall.op("show high-availability state")
        enabled = ha_state.find("./result/enabled")
        if enabled is None:
            return
        if enabled.text == "yes":
            state = ha_state.find("./result/group/local-info/state")
            if state is None:
                return
            if state.text != "active":
                logger.debug("Current firewall state is %s, switching to use other firewall" % state.text)
                self.toggle_active_firewall()
            else:
                logger.debug("Current firewall is active, no change made")

    def synchronize_config(self):
        state = self.config_sync_state()
        if state == "synchronization in progress":
            # Wait until synchronization done
            return self.watch_op("show high-availability state", "group/running-sync", "synchronized")
        elif state != "synchronized":
            logger.debug("Synchronizing configuration with HA peer")
            response = self.active_firewall.op("request high-availability sync-to-remote running-config")
            line = response.find("./msg/line")
            if line is None:
                raise err.PanDeviceError("Unable to synchronize configuration, no response from firewall")
            if line.text.startswith("successfully sync'd running configuration to HA peer"):
                return True
            else:
                raise err.PanDeviceError("Unable to synchronize configuration: %s" % line.text)
        else:
            logger.debug("Config synchronization is not required, already synchronized")
            return True

    def config_sync_state(self):
        logger.debug("Checking if configuration is synced")
        ha_state = self.active_firewall.op("show high-availability state")
        enabled = ha_state.find("./result/enabled")
        if enabled is None or enabled.text == "no":
            logger.debug("HA is not enabled on firewall")
            return
        if enabled.text == "yes":
            sync_enabled = ha_state.find("./result/group/running-sync-enabled")
            if sync_enabled is None or sync_enabled.text != "yes":
                logger.debug("HA config sync is not enabled on firewall")
                return
            else:
                state = ha_state.find("./result/group/running-sync")
                if state is None:
                    logger.debug("HA or config sync is not enabled on firewall")
                    return
                logger.debug("Current config sync state is: %s" % state.text)
                return state.text

    def config_synced(self):
        state = self.config_sync_state()
        if state is None:
            return False
        elif state != "synchronized":
            return False
        else:
            return True

class HighAvailabilityInterface(PanObject):
    """Base class for high availability interface classes

    Do not instantiate this class.  Use its subclasses

    """

    HA_SYNC = False

    # TODO: Support encryption
    def __init__(self,
                 ip_address=None,
                 netmask=None,
                 port=None,
                 gateway=None,
                 link_speed=None,
                 link_duplex=None,
                 ):
        if type(self) == HighAvailabilityInterface:
            raise AssertionError("Do not instantiate a HighAvailabilityInterface. Please use a subclass.")
        super(HighAvailabilityInterface, self).__init__()
        self._port = port
        self.ip_address = ip_address
        self.netmask = netmask
        self.gateway = gateway
        self.link_speed = link_speed
        self.link_duplex = link_duplex

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
            Var("port"),
            Var("ip-address"),
            Var("netmask"),
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

    def __init__(self,
                 ip_address=None,
                 netmask=None,
                 port=None,
                 gateway=None,
                 link_speed=None,
                 link_duplex=None,
                 monitor_hold_time=None,
                 ):
        super(HA1, self).__init__(ip_address, netmask, port, gateway, link_speed, link_duplex)
        self.monitor_hold_time=monitor_hold_time

    @classmethod
    def variables(cls):
        return super(HA1, HA1).variables() + (
            Var("monitor-hold-time", vartype="int"),
        )


class HA1Backup(HighAvailabilityInterface):
    XPATH = "/interface/ha1-backup"

    def __init__(self,
                 ip_address=None,
                 netmask=None,
                 port=None,
                 gateway=None,
                 link_speed=None,
                 link_duplex=None,
                 ):
        super(HA1Backup, self).__init__(ip_address, netmask, port, gateway, link_speed, link_duplex)


class HA2(HighAvailabilityInterface):
    XPATH = "/interface/ha2"

    def __init__(self,
                 ip_address=None,
                 netmask=None,
                 port=None,
                 gateway=None,
                 link_speed=None,
                 link_duplex=None,
                 ):
        super(HA2, self).__init__(ip_address, netmask, port, gateway, link_speed, link_duplex)


class HA2Backup(HighAvailabilityInterface):
    XPATH = "/interface/ha2-backup"

    def __init__(self,
                 ip_address=None,
                 netmask=None,
                 port=None,
                 gateway=None,
                 link_speed=None,
                 link_duplex=None,
                 ):
        super(HA2Backup, self).__init__(ip_address, netmask, port, gateway, link_speed, link_duplex)


class HA3(HighAvailabilityInterface):
    XPATH = "/interface/ha3"

    def __init__(self,
                 port=None,
                 ):
        super(HA3, self).__init__(ip_address=None,
                                  netmask=None,
                                  port=port,
                                  gateway=None,
                                  link_speed=None,
                                  link_duplex=None,
                                  )

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
        HA1,
        HA1Backup,
        HA2,
        HA2Backup,
        HA3,
    )

    ACTIVE_PASSIVE = "active-passive"
    ACTIVE_ACTIVE = "active-active"

    def __init__(self,
                 peer_ip=None,
                 enabled=True,
                 mode=ACTIVE_PASSIVE,
                 config_sync=True,
                 state_sync=False,
                 ha2_keepalive=False,
                 group_id=(1,),
                 description=None,
                 ):
        super(HighAvailability, self).__init__()
        self.peer_ip = peer_ip
        self.enabled = enabled
        self.mode = mode
        self.config_sync = config_sync
        self.state_sync = state_sync
        self.ha2_keepalive = ha2_keepalive
        self.group_id = list(group_id)
        self.description = description

        # Other settings that can be modified after instantiation
        self.passive_link_state = None
        self.ha2_keepalive_action = None
        self.ha2_keepalive_threshold = None

    @classmethod
    def variables(cls):
        return (
            # Enabled flag
            Var("enabled", vartype="bool"),
            # Group
            Var("group", "group_id", vartype="entry"),
            Var("{{group_id}}/description"),
            Var("{{group_id}}/configuration-synchronization/enabled", "config_sync", vartype="bool"),
            Var("{{group_id}}/peer-ip"),
            # HA Mode (A/P, A/A)
            Var("{{group_id}}/mode/(active-passive|active-active)", "mode"),
            Var("{{group_id}}/mode/{{mode}}/passive-link-state", init=False),
            # State Synchronization
            Var("{{group_id}}/state-synchronization/enabled", "state_sync", vartype="bool"),
            # HA2 Keep-alive
            Var("{{group_id}}/state-synchronization/ha2-keep-alive/enabled", "ha2_keepalive", vartype="bool"),
            Var("{{group_id}}/state-synchronization/ha2-keep-alive/action", "ha2_keepalive_action", init=False),
            Var("{{group_id}}/state-synchronization/ha2-keep-alive/threshold", "ha2_keepalive_threshold", vartype="int", init=False),
            Var("interface", vartype="none"),
            Var("interface/ha1", vartype="none"),
            Var("interface/ha1-backup", vartype="none"),
            Var("interface/ha2", vartype="none"),
            Var("interface/ha2-backup", vartype="none"),
            Var("interface/ha3", vartype="none"),
        )


