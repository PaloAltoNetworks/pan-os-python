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

"""Retrieving and parsing predefined objects from the firewall"""

import xml.etree.ElementTree as ET
from copy import deepcopy

from pandevice import getlogger
import pandevice.errors as err
from pandevice import string_or_list
from pandevice import string_or_list_or_none
from pan.xapi import PanXapiError
from pandevice.updater import PanOSVersion
from pandevice.base import PanObject

logger = getlogger(__name__)


class Predefined(PanObject):
    """Predefined Objects Subsystem of Firewall

    A member of a firewall.Firewall object that has special methods for
    interacting with the predefned objects of the firewall

    This class is typically not instantiated by anything but the
    base.PanDevice class itself. There is an instance of this UserId class
    inside every instantiated base.PanDevice class.

    Args:
        device (base.PanDevice): The firewall or Panorama this user-id subsystem leverages

    """

    PREDEFINED_ROOT = "/predefined"

    def __init__(self, device, *args, **kwargs):
        # Create a class logger
        self._logger = getlogger(__name__ + "." + self.__class__.__name__)
        self.device = device

        super(Predefined, self).__init(*args, **kwargs)

        self.objects = []

    def retrieve(self):
        self.device.
