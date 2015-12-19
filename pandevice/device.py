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

import logging
import pandevice
from base import PanObject, Root, MEMBER, ENTRY
from base import VarPath as Var

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


class NTPServer(PanObject):
    """A primary or secondary NTP server

    Add to a SystemSettings object

    Attributes:
        priority (str): 'primary' or 'secondary'
        address (str): IP address or hostname of DNS server
    """
    # TODO: Add authentication
    # TODO: Add PAN-OS pre-7.0 support

    XPATH = "/ntp-servers"

    def __init__(self,
                 priority=None, # 'primary' or 'secondary'
                 address=None
                 ):
        super(NTPServer, self).__init__()
        self._priority = None
        self.address = None

    @staticmethod
    def vars():
        return (
            Var("primary-ntp-server|secondary-ntp-server", "priority"),
            Var("{{priority}}-ntp-server/ntp-server-address", "address"),
        )

    @property
    def priority(self):
        return self._priority

    @priority.setter
    def priority(self, value):
        if value == "primary-ntp-server":
            self._priority = "primary"
        elif value == "secondary-ntp-server":
            self._priority = "secondary"
        else:
            self._priority = value


class SystemSettings(PanObject):

    ROOT = Root.DEVICE
    XPATH = "/deviceconfig/system"
    CHILDTYPES = (
        NTPServer,
    )

    def __init__(self):
        super(SystemSettings, self).__init__()
        self.hostname = None
        self.domain = None
        self.ip_address = None
        self.netmask = None
        self.default_gateway = None
        self.ipv6_address = None
        self.ipv6_default_gateway = None
        self.dns_primary = None
        self.dns_secondary = None
        self.timezone = None
        self.panorama = None
        self.panorama2 = None
        self.login_banner = None
        self.update_server = None

    @staticmethod
    def vars():
        return (
            Var("hostname", init=False),
            Var("domain", init=False),
            Var("ip-address", init=False),
            Var("netmask", init=False),
            Var("default-gateway", init=False),
            Var("ipv6-address", init=False),
            Var("ipv6-default-gateway", init=False),
            Var("dns-setting/servers/primary", "dns_primary", init=False),
            Var("dns-setting/servers/secondary", "dns_secondary", init=False),
            Var("timezone", init=False),
            Var("panorama-server", "panorama", init=False),
            Var("panorama-server-2", "panorama2", init=False),
            Var("login-banner", init=False),
            Var("update-server", init=False),
        )
