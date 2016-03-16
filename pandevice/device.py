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
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class VsysResources(PanObject):

    XPATH = "/import/resource"
    ROOT = Root.VSYS

    @classmethod
    def variables(cls):
        return (
            Var("max-security-rules", vartype="int"),
            Var("max-nat-rules", vartype="int"),
            Var("max-ssl-decryption-rules", vartype="int"),
            Var("max-qos-rules", vartype="int"),
            Var("max-application-override-rules", vartype="int"),
            Var("max-pbf-rules", vartype="int"),
            Var("max-cp-rules", vartype="int"),
            Var("max-dos-rules", vartype="int"),
            Var("max-site-to-site-vpn-tunnels", vartype="int"),
            Var("max-concurrent-ssl-vpn-tunnels", vartype="int"),
            Var("max-sessions", vartype="int"),
        )


class Vsys(PanObject):
    """Virtual System (VSYS)"""

    XPATH = "/vsys"
    ROOT = Root.DEVICE
    SUFFIX = ENTRY

    @classmethod
    def variables(cls):
        return (
            Var("display-name"),
            Var("import/network/interface", vartype="member")
        )

    def xpath_vsys(self):
        if self.name == "shared" or self.name is None:
            return "/config/shared"
        else:
            return "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='%s']" % self.name

    @property
    def vsys(self):
        return self.name

    @vsys.setter
    def vsys(self, value):
        self.name = value


class NTPServer(PanObject):
    """A primary or secondary NTP server"""
    # TODO: Add authentication
    # TODO: Add PAN-OS pre-7.0 support

    XPATH = "/ntp-servers/primary-ntp-server"

    def __init__(self, *args, **kwargs):
        if type(self) == NTPServer:
            raise err.PanDeviceError("Do not instantiate class. Please use a subclass.")
        super(NTPServer, self).__init__(*args, **kwargs)

    @classmethod
    def variables(cls):
        return (
            Var("ntp-server-address", "address"),
        )


class NTPServerPrimary(NTPServer):
    """A primary NTP server

    Add to a SystemSettings object

    Attributes:
        address (str): IP address or hostname of DNS server
    """
    XPATH = "/ntp-servers/primary-ntp-server"


class NTPServerSecondary(NTPServer):
    """A secondary NTP server

    Add to a SystemSettings object

    Attributes:
        address (str): IP address or hostname of DNS server
    """
    XPATH = "/ntp-servers/secondary-ntp-server"


class SystemSettings(PanObject):

    ROOT = Root.DEVICE
    XPATH = "/deviceconfig/system"
    NAME = "hostname"
    HA_SYNC = False
    CHILDTYPES = (
        "device.NTPServerPrimary",
        "device.NTPServerSecondary",
    )

    @classmethod
    def variables(cls):
        return (
            Var("hostname"),
            Var("domain"),
            Var("ip-address"),
            Var("netmask"),
            Var("default-gateway"),
            Var("ipv6-address"),
            Var("ipv6-default-gateway"),
            Var("dns-setting/servers/primary", "dns_primary"),
            Var("dns-setting/servers/secondary", "dns_secondary"),
            Var("timezone"),
            Var("panorama-server", "panorama"),
            Var("panorama-server-2", "panorama2"),
            Var("login-banner"),
            Var("update-server"),
        )
