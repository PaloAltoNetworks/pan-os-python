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


class AddressObject(base.PanObject):

    ROOT = base.Root.VSYS
    XPATH = "/address"
    SUFFIX = base.PanObject.ENTRY

    def __init__(self,
                 name,
                 value,
                 type="ip-netmask", # other options: ip-range, fqdn
                 description=None,
                 ):
        super(AddressObject, self).__init__(name=name)
        self.value = value
        self.type = type
        self.description = description

    def element(self):
        element = ET.Element("entry", {'name': self.name})
        type = ET.SubElement(element, self.type)
        type.text = self.value
        if self.description is not None:
            description = ET.SubElement(element, 'description')
            description.text = self.description
        return ET.tostring(element)
