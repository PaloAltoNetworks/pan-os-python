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
import base

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


class Interface(object):
    """An interface on a Palo Alto Networks device

    This interface can be physical or logical (like a vlan)
    """

    def __init__(self,
                 name=None,
                 type="ethernet",
                 mode="layer3",
                 tag=None,
                 zone=None,
                 subnets=None,
                 router="default",
                 pan_device=None,
                 apply_changes=False,
                 parent=None,
                 state=None,
                 ):
        """Initialize Interface"""
        self.name = name
        self.type = type
        self.mode = mode
        self._tag = None
        self.tag = tag
        self._zone = zone
        self.router = router
        self.parent = parent
        self.subinterfaces = {}
        self.apply_changes = apply_changes
        self.pan_device = pan_device
        self._subnets = None
        self.subnets = subnets
        self.state = state
        if tag is not None and not re.search(r"\.\d+$", self.name):
            self.name += "." + str(self.tag)
        if tag is None and re.search(r"\.\d+$", self.name):
            self.tag = self.name.split(".")[1]

    # Builtins

    def __str__(self):
        return self.name

    def __repr__(self):
        return "<%s name:%s state:%s type:%s mode:%s zone:%s>" % ('Interface',
                                                                  self.name,
                                                                  self.state,
                                                                  self.type,
                                                                  self.mode,
                                                                  self.zone,
                                                                  )

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    # Properties

    @property
    def subnets(self):
        return self._subnets

    @property
    def tag(self):
        return self._tag

    @property
    def zone(self):
        return self._zone

    @subnets.setter
    def subnets(self, value):
        if value is None:
            self._subnets = []
        elif issubclass(value.__class__, list):
            self._subnets = value
        else:
            self._subnets = [value]
        if self.apply_changes:
            self.apply()

    @tag.setter
    def tag(self, value):
        if value is not None:
            self._tag = str(value)
        else:
            self._tag = None

    @zone.setter
    def zone(self, value):
        if self._zone == value:
            return
        old_zone = self._zone
        self._zone = value
        if self.apply_changes:
            if old_zone is not None:
                xpath = pandevice.XPATH_ZONE + "/entry[" \
                                     "@name='%s']/network/layer3/" \
                                     "member[text()='%s']" \
                                     % (old_zone, self.name)
                self.pan_device.xapi.delete(xpath)
            if self._zone is not None:
                xpath = pandevice.XPATH_ZONE + "/entry[@name='%s']/network/layer3" \
                                     % (self._zone,)
                element = "<member>%s</member>" % (self.name,)
                self.pan_device.xapi.set(xpath, element)

    def is_up(self):
        if self.state == "up":
            return True
        else:
            return False

    def apply(self):
        if not self.pan_device:
            return
        self.pan_device.set_config_changed()
        # apply the interface
        xpath, element = self._xpath()
        self.pan_device.xapi.edit(xpath, ET.tostring(element))
        # put it in a zone
        if self.zone:
            xpath = pandevice.XPATH_ZONE + "/entry[@name='%s']/network/layer3" \
                                 % (self.zone,)
            element = "<member>%s</member>" % (self.name,)
            self.pan_device.xapi.set(xpath, element)
        # set the virtual router
        if self.router:
            xpath = pandevice.XPATH_DEFAULT_VROUTER_INTERFACES
            element = "<member>%s</member>" % (self.name,)
            self.pan_device.xapi.set(xpath, element)

    def delete(self):
        if not self.pan_device:
            return
        self.pan_device.set_config_changed()
        # remove the interface from the virtual router
        if self.router:
            xpath = pandevice.XPATH_DEFAULT_VROUTER_INTERFACES + "/member[text()='%s']" \
                                                       % (self.name,)
            self.pan_device.xapi.delete(xpath)
        # remove the interface from the zone
        if self.zone:
            xpath = pandevice.XPATH_ZONE + "/entry[@name='%s']/network/layer3/member[" \
                                 "text()='%s']" \
                                 % (self.zone, self.name)
            self.pan_device.xapi.delete(xpath)
        # remove the interface from the configuration
        xpath, element = self._xpath()
        self.pan_device.xapi.delete(xpath)

    def _xpath(self):
        xpath = pandevice.XPATH_INTERFACES + "/%s" % (self.type,)

        if self.type == "ethernet":
            if self.parent:
                xpath += "/entry[@name='%s']/%s/units/entry[@name='%s']" \
                         % (self.parent.name,
                            self.parent.mode,
                            self.name)
                root = ET.Element("entry", {"name": self.name})
                settings = root
            else:
                match = re.search(r"(ethernet\d/\d{1,3})\.\d{1,4}", self.name)
                if match:
                    xpath += "/entry[@name='%s']/%s/units/entry[@name='%s']"\
                             % (match.group(1), self.mode, self.name)
                    root = ET.Element("entry", {"name": self.name})
                    settings = root
                else:
                    xpath += "/entry[@name='%s']" % (self.name,)
                    root = ET.Element("entry", {"name": self.name})
                    settings = ET.SubElement(root, self.mode)
        elif self.type == "vlan":
            xpath += "/units/entry[@name='%s']" % (self.name,)
            root = ET.Element("entry", {"name": self.name})
            settings = root
        else:
            raise err.PanDeviceError("Unknown interface type: %s" % self.type)

        # For Layer 3 interfaces, apply any subnet configuration
        if self.mode == "layer3" and self.subnets:
            node = ET.SubElement(settings, "ip")
            for subnet in self.subnets:
                ET.SubElement(node, "entry", {"name": subnet})

        # If there is a tag, apply it in the XML
        if self.tag:
            node = ET.SubElement(settings, "tag")
            node.text = self.tag

        return xpath, root


class VirtualRouter(base.VsysImportMixin, base.PanObject):

    ROOT = base.Root.DEVICE
    XPATH = "/network/virtual-router"
    SUFFIX = base.PanObject.ENTRY

    def __init__(self,
                 name="default",
                 interfaces=()):
        super(VirtualRouter, self).__init__(name=name)
        self.interfaces = list(interfaces)


class StaticRoute(base.PanObject):

    XPATH = "/routing-table/ip/static-route"
    SUFFIX = base.PanObject.ENTRY

    def __init__(self,
                 name,
                 destination=None,
                 interface=None,
                 nexthop=None):
        super(StaticRoute, self).__init__(name=name)
        self.destination = destination
        self.interface = interface
        self.nexthop = nexthop

    def element(self):
        element = ("<entry name=\"" + self.name + "\">"
                   "<nexthop>"
                   "<ip-address>" + self.nexthop + "</ip-address>"
                   "</nexthop>"
                   )
        if self.interface is not None:
            element += "<interface>%s</interface>" % self.interface
        element += "<metric>10</metric>" \
                   "<destination>%s</destination></entry>" % self.destination
        return element
