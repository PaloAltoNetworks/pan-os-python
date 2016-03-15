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
from base import PanObject, Root, MEMBER, ENTRY
from base import VarPath as Var

# import other parts of this pandevice package
import errors as err

# set logging to nullhandler to prevent exceptions if logging not enabled
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class AddressObject(PanObject):

    ROOT = Root.VSYS
    XPATH = "/address"
    SUFFIX = ENTRY

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

    @classmethod
    def variables(cls):
        return (
            Var("(ip-netmask|ip-range|fqdn)", "type"),
            Var("{{type}}", "value"),
            Var("description"),
        )
