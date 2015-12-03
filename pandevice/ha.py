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
import xml.etree.ElementTree as ET
from base import PanObject, Root, MEMBER, ENTRY


class HighAvailability(PanObject):

    ROOT = Root.DEVICE
    XPATH = "/deviceconfig/high-availability"

    ACTIVE_PASSIVE = 0
    ACTIVE_ACTIVE = 1

    def __init__(self,
                 peer_ip,
                 enabled=True,
                 mode=ACTIVE_PASSIVE,
                 config_sync=True,
                 state_sync=True,
                 ha2_keepalive=False,
                 group_id=1,
                 description=None,
                 ):
        super(HighAvailability, self).__init__()
        self.peer_ip = peer_ip
        self.enabled = enabled
        self.mode = mode
        self.config_sync = config_sync
        self.state_sync = state_sync
        self.ha2_keepalive = ha2_keepalive
        self.group_id = group_id
        self.description = description

        # Other settings that can be modified after instantiation
        self.passive_link_state = "auto"
        self.ha2_keepalive_action = "log-only"
        self.ha2_keepalive_threshold = 10000

    def element(self):
        root = self.root_element()

        # Enabled flag
        ET.SubElement(root, 'enabled').text = "yes" if self.enabled else "no"

        # Group
        group = ET.SubElement(root, 'group')
        group = ET.SubElement(group, 'entry', {'name': str(self.group_id)})
        if self.description is not None:
            ET.SubElement(group, 'description').text = self.description
        config_sync = ET.SubElement(group, 'configuration-syncronization')
        ET.SubElement(config_sync, 'enabled').text = 'yes' if self.config_sync else 'no'
        ET.SubElement(group, 'peer-ip').text = self.peer_ip

        # HA Mode (A/P, A/A)
        mode = ET.SubElement(group, 'mode')
        if self.mode == HighAvailability.ACTIVE_PASSIVE:
            mode = ET.SubElement(mode, 'active-passive')
            ET.SubElement(mode, 'passive-link-state').text = self.passive_link_state
        elif self.mode == HighAvailability.ACTIVE_ACTIVE:
            mode = ET.SubElement(mode, 'active-active')

        # State Synchronization
        state_sync = ET.SubElement(group, 'state-synchronization')
        ET.SubElement(state_sync, 'enabled').text = "yes" if self.state_sync else "no"

        # HA2 Keep-alive
        ha2_keepalive = ET.SubElement(state_sync, 'ha2-keep-alive')
        ET.SubElement(ha2_keepalive, 'action').text = self.ha2_keepalive_action
        ET.SubElement(ha2_keepalive, 'threshold').text = str(self.ha2_keepalive_threshold)
        ET.SubElement(ha2_keepalive, 'enabled').text = "yes" if self.ha2_keepalive else "no"

        root.extend(self.subelements())
        return root


class HighAvailabilityInterface(PanObject):
    """Base class for high availability interface classes

    Do not instantiate this class.  Use its subclasses

    """

    def __init__(self,
                 ipaddress,
                 netmask,
                 port=None,
                 gateway=None,
                 link_speed="auto",
                 link_duplex="auto",
                 ):
        if type(self) == HighAvailabilityInterface:
            raise AssertionError("Do not instantiate a HighAvailabilityInterface. Please use a subclass.")
        super(HighAvailabilityInterface, self).__init__()
        self.port = port
        self.ipaddress = ipaddress
        self.netmask = netmask
        self.gateway = gateway
        self.link_speed = link_speed
        self.link_duplex = link_duplex

    def element(self):
        root = self.root_element()
        ET.SubElement(root, 'ip-address').text = self.ipaddress
        ET.SubElement(root, 'netmask').text = self.netmask
        if self.gateway is not None:
            ET.SubElement(root, 'gateway').text = self.gateway
        ET.SubElement(root, 'link_speed').text = self.link_speed
        ET.SubElement(root, 'link_duplex').text = self.link_duplex
        return root


class HA1(HighAvailabilityInterface):
    """HA1 interface class

    TODO: Encryption

    """

    XPATH = "/interface/ha1"

    def __init__(self,
                 ipaddress,
                 netmask,
                 port=None,
                 gateway=None,
                 link_speed="auto",
                 link_duplex="auto",
                 monitor_hold_time=3000,
                 ):
        super(HA1, self).__init__(ipaddress, netmask, port, gateway, link_speed, link_duplex)
        self.monitor_hold_time=monitor_hold_time

    def element(self):
        root = super(HA1, self).element()
        if self.monitor_hold_time != 3000:
            ET.SubElement(root, 'monitor-hold-time').text = str(self.monitor_hold_time)
        return root


class HA1Backup(HighAvailabilityInterface):
    XPATH = "/interface/ha1-backup"


class HA2(HighAvailabilityInterface):
    XPATH = "/interface/ha2"


class HA2Backup(HighAvailabilityInterface):
    XPATH = "/interface/ha2-backup"
