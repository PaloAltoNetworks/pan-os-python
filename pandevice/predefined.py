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

# Author: John Anderson <lampwins@gmail.com>

"""Retrieving and parsing predefined objects from the firewall"""

import xml.etree.ElementTree as ET
from copy import deepcopy

from pandevice import getlogger
import pandevice.errors as err
from pandevice import string_or_list
from pandevice import string_or_list_or_none
from pan.xapi import PanXapiError
from pandevice.updater import PanOSVersion
from base import VersionedPanObject
import objects

logger = getlogger(__name__)


class Predefined(VersionedPanObject):
    """Predefined Objects Subsystem of Firewall

    A member of a base.PanDevice object that has special methods for
    interacting with the predefned objects of the firewall

    This class is typically not instantiated by anything but the
    base.PanDevice class itself. There is an instance of this Predefined class
    inside every instantiated base.PanDevice class.

    Args:
        device (base.PanDevice): The firewall or Panorama this Predefined subsystem leverages

    """

    # /config/predefined contains A LOT of stuff including threats, so let's get only what we need
    PREDEFINED_ROOT = "/config/predefined"
    XPATH = PREDEFINED_ROOT
    SUFFIX = None

    CHILDTYPES = (
        "objects.ServiceObject",
        "objects.ApplicationObject",
        "objects.ApplicationContainer",
    )

    def __init__(self, device=None, *args, **kwargs):
        # Create a class logger
        self._logger = getlogger(__name__ + "." + self.__class__.__name__)

        super(Predefined, self).__init__(*args, **kwargs)

        self.parent = device

        self.service_objects = {}
        self.application_objects = {}
        self.application_container_objects = {}

    def xpath(self):
        """overridden to force the predefined xpath special case"""
        return self.XPATH
    
    def _refresh_xml(self, running_config, exceptions):
        """override to ignore suffix check at the end"""
        # Get the root of the xml to parse
        device = self.nearest_pandevice()
        msg = '{0}: refreshing xml on {1} object {2}'.format(
            device.id, type(self), self.uid)
        logger.debug(msg)
        if running_config:
            api_action = device.xapi.show
        else:
            api_action = device.xapi.get
        xpath = self.xpath()
        err_msg = "Object doesn't exist: {0}".format(xpath)

        # Query the live device
        try:
            root = api_action(xpath, retry_on_peer=self.HA_SYNC)
        except (pan.xapi.PanXapiError, err.PanNoSuchNode) as e:
            if exceptions:
                raise err.PanObjectMissing(err_msg, pan_device=device)
            else:
                return

        # in this case, "result" is the root element we want 
        elm = root.find("result")

        if elm is None and exceptions:
            raise err.PanObjectMissing(err_msg, pan_device=device)

        return elm

    def retrieve(self):
        """Retrieve the predefined obejcts from the parent PanDevice

        This is more-or-less a wrapper method to envoke calls to pull in
        predefined ServiceObjects, ApplicationObjects, and ApplicationContainer objects.
        
        """

        # clear out everything to start
        self.service_objects = {}
        self.application_objects = {}
        self.application_container_objects = {}
        self.children = []

        # now we refresh each object type. this puts the objects
        # as children of self, so we loop through for dict insertion
        # and finally clear the cildren list for the next onbject type
        objects.ServiceObject.refreshall(self)
        for obj in self.children:
            self.service_objects[obj.name] = obj
        self.children = []

        objects.ApplicationObject.refreshall(self)
        for obj in self.children:
            self.application_objects[obj.name] = obj
        self.children = []

        objects.ApplicationContainer.refreshall(self)
        for obj in self.children:
            self.application_container_objects[obj.name] = obj
        self.children = []
    
    def find(self, name, class_type=None, recursive=False):
        """override to use the internal dicts"""

        if class_type is objects.ServiceObject:
            return self.service_objects.get(name)
        elif class_type is objects.ApplicationObject:
            return self.application_objects.get(name)
        elif class_type is objects.ApplicationContainer:
            return self.application_container_objects.get(name)
        else:
            return None

    def findall(self, class_type, recursive=False):
        """override to use the internal dicts"""

        if class_type is objects.ServiceObject:
            return list(self.service_objects.values())
        elif class_type is objects.ApplicationObject:
            return list(self.application_objects.values())
        elif class_type is objects.ApplicationContainer:
            return list(self.application_container_objects.values())
        else:
            return []
    
    # these methods are certainly not needed.
    def find_or_create(self, name, class_type, *args, **kwargs):
        raise NotImplementedError()
    
    def findall_or_create(self, class_type, *args, **kwargs):
        raise NotImplementedError()

    def find_index(self, name=None, class_type=None):
        raise NotImplementedError()
