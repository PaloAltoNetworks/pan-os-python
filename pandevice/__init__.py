# -*- coding: utf-8 -*-

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


__author__ = 'Brian Torres-Gil'
__email__ = 'btorres-gil@paloaltonetworks.com'
__version__ = '0.2.0'


import logging

# python 2.6 doesn't have a null handler, so create it
if not hasattr(logging, 'NullHandler'):
    class NullHandler(logging.Handler):
        def emit(self, record):
            pass
    logging.NullHandler = NullHandler


# XPaths
XPATH_SHARED = "/config/shared"
XPATH_DEVICE = "/config/devices/entry[@name='localhost.localdomain']"
XPATH_NETWORK = XPATH_DEVICE + "/network"

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


# Enumerator type
def enum(*sequential, **named):
    enums = dict(zip(sequential, range(len(sequential))), **named)
    reverse = dict((value, key) for key, value in enums.iteritems())
    enums['reverse_mapping'] = reverse
    return type('Enum', (), enums)

