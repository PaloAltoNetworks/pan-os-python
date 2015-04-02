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


"""
Generate XPaths using dot notation.

Example:

    >>> import pandevice.paths as paths
    >>> xpath =  paths.PanXpath()
    >>> xpath.vsys.network.interface.ethernet.entry['ethernet1/1']
    "/config/device/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/network/interface/ethernet/entry[@name='ethernet1/1']"


"""

from xml.etree.ElementTree import ElementTree as ET

from . import enum

"""
XPaths for reference

XPATH_INTERFACES = "/config/devices/entry[@name='localhost.localdomain']/network/interface"
XPATH_ETHERNET = "/config/devices/entry[@name='localhost.localdomain']/network/interface/ethernet"
XPATH_VLAN = "/config/devices/entry[@name='localhost.localdomain']/network/vlan"
XPATH_VWIRE = "/config/devices/entry[@name='localhost.localdomain']/network/virtual-wire"
XPATH_ZONE = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/zone"
XPATH_VROUTER = "/config/devices/entry[@name='localhost.localdomain']/network/virtual-router"
XPATH_DEFAULT_VROUTER = "/config/devices/entry[@name='localhost.localdomain']/network/virtual-router/entry[@name='default']"
XPATH_DEFAULT_VROUTER_INTERFACES = "/config/devices/entry[@name='localhost.localdomain']/network/virtual-router/entry[@name='default']/interface"
XPATH_VSYS_IMPORT_NETWORK = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/import/network"
XPATH_DEVICE_GROUPS = "/config/devices/entry[@name='localhost.localdomain']/device-group"
XPATH_DEVICECONFIG_SYSTEM = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system"
"""

Base = enum(
    "ROOT",
    "VSYS",
    "DEVICEGROUP",
    "TEMPLATE",
)

class PanXpath(object):

    def __init__(self,
                 vsys="vsys1",
                 devicegroup=None,
                 template=None):
        self.root = PanXpathNode("/config/device/"
                                 "entry[@name='localhost.localdomain']")
        # Create scope shortcuts
        self.vsys = self.vsys.entry[vsys]
        self.devicegroup = self.devicegroup.entry[devicegroup]
        self.template = self.template.entry[template]

    def path(self, node, base=Base.ROOT):
        xpath = self._base_xpath[base] + "/" + node
        return xpath

    def __getattr__(self, item):
        return PanXpathNode(path=str(self.root), element=item)


class PanXpathNode(object):

    def __init__(self, path="", element=None, name=None):
        self.path = path
        self.element = element
        self.name = name

    def __str__(self):
        string = str(self.path)
        if self.element is not None:
            string += "/" + self.element
            if self.name is not None:
                string += "[@name='%(name)s']" % {'name': self.name}
        return string

    def __getattr__(self, item):
        return PanXpathNode(path=str(self), element=item)

    def __getitem__(self, item):
        self.name = item
        return self

    def node(self, element, name=None):
        return PanXpathNode(path=str(self), element=element, name=name)


class PanElementNode(object):

    def __init__(self, root_node, last_node, element, name=None, text=None):
        self.root_node = root_node
        self.last_node = last_node
        self.element = element
        self.name = name
        self.text = text

    def __str__(self):
        return ET.tostring(root_node)

    def __getattr__(self, item):
        pass

    def __getitem__(self, item):
        pass


