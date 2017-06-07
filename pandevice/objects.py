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


"""Objects module contains objects that exist in the 'Objects' tab in the firewall GUI"""

# import modules
import re
import logging
import xml.etree.ElementTree as ET
import pandevice
from pandevice import getlogger
from pandevice.base import PanObject, Root, MEMBER, ENTRY
from pandevice.base import VarPath as Var
from pandevice.base import VersionedPanObject
from pandevice.base import VersionedParamPath

# import other parts of this pandevice package
import pandevice.errors as err

logger = getlogger(__name__)


class AddressObject(VersionedPanObject):
    """Address Object

    Args:
        name (str): Name of the object
        value (str): IP address or other value of the object
        type (str): Type of address:
                * ip-netmask (default)
                * ip-range
                * fqdn
        description (str): Description of this object
        tag (list): Administrative tags

    """
    ROOT = Root.VSYS
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value='/address')

        # params
        params = []

        params.append(VersionedParamPath(
            'value', path='{type}'))
        params.append(VersionedParamPath(
            'type', default='ip-netmask',
            values=['ip-netmask', 'ip-range', 'fqdn'], path='{type}'))
        params.append(VersionedParamPath(
            'description', path='description'))
        params.append(VersionedParamPath(
            'tag', path='tag', vartype='member'))

        self._params = tuple(params)


class AddressGroup(VersionedPanObject):
    """Address Group

    Args:
        static_value (list): Values for a static address group
        dynamic_value (str): Registered-ip tags for a dynamic address group
        description (str): Description of this object
        tag (list): Administrative tags (not to be confused with registered-ip tags)

    """
    ROOT = Root.VSYS
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value='/address-group')

        # params
        params = []

        params.append(VersionedParamPath(
            'static_value', path='static', vartype='member'))
        params.append(VersionedParamPath(
            'dynamic_value', path='dynamic/filter'))
        params.append(VersionedParamPath(
            'description', path='description'))
        params.append(VersionedParamPath(
            'tag', path='tag', vartype='member'))

        self._params = tuple(params)


class Tag(PanObject):
    """Administrative tag

    Args:
        name (str): Name of the tag
        color (str): Color ID or name (eg. 'color1', 'color4', 'purple')
        comments (str): Comments

    """
    ROOT = Root.VSYS
    XPATH = "/tag"
    SUFFIX = ENTRY

    COLOR = {
        "red":         1,
        "green":       2,
        "blue":        3,
        "yello":       4,
        "copper":      5,
        "orange":      6,
        "purple":      7,
        "gray":        8,
        "light green": 9,
        "cyan":        10,
        "light gray":  11,
        "blue gray":   12,
        "lime":        13,
        "black":       14,
        "gold":        15,
        "brown":       16,
    }

    def __init__(self, *args, **kwargs):
        super(Tag, self).__init__(*args, **kwargs)
        if not hasattr(self, "_color"):
            self._color = None

    @classmethod
    def variables(cls):
        return (
            Var("color"),
            Var("comments"),
        )

    @property
    def color(self):
        if self._color in self.COLOR:
            return "color"+str(self.COLOR[self._color])
        return self._color

    @color.setter
    def color(self, value):
        self._color = value


class ServiceObject(VersionedPanObject):
    """Service Object

    Args:
        name (str): Name of the object
        protocol (str): Protocol of the service, either tcp or udp
        source_port (str): Source port of the protocol, if any
        destination_port (str): Destination port of the service
        description (str): Description of this object
        tag (list): Administrative tags

    """
    ROOT = Root.VSYS
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value='/service')

        # params
        params = []

        params.append(VersionedParamPath(
            'protocol', path='protocol/{protocol}',
            values=['tcp', 'udp'], default='tcp'))
        params.append(VersionedParamPath(
            'source_port', path='protocol/{protocol}/source-port'))
        params.append(VersionedParamPath(
            'destination_port', path='protocol/{protocol}/port'))
        params.append(VersionedParamPath(
            'description', path='description'))
        params.append(VersionedParamPath(
            'tag', path='tag', vartype='member'))

        self._params = tuple(params)


class ServiceGroup(VersionedPanObject):
    """ServiceGroup Object

    Args:
        name (str): Name of the object
        value (list): List of service values
        tag (list): Administrative tags

    """
    ROOT = Root.VSYS
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value='/service-group')

        # params
        params = []

        params.append(VersionedParamPath(
            'value', path='members', vartype='member'))
        params.append(VersionedParamPath(
            'tag', path='tag', vartype='member'))

        self._params = tuple(params)


class ApplicationObject(VersionedPanObject):
    """Application Object

    Args:
        name (str): Name of the object
        category (str): Application category
        subcategory (str): Application subcategory
        technology (str): Application technology
        risk (int): Risk (1-5) of the application
        default_type (str): Default identification type of the application
        default_value (list): Values for the default type
        parent_app (str): Parent Application for which this app falls under
        timeout (int): Default timeout
        tcp_timeout (int): TCP timeout
        udp_timeout (int): UDP timeout
        tcp_half_closed_timeout (int): TCP half closed timeout
        tcp_time_wait_timeout (int): TCP wait time timeout
        evasive_behavior (bool): Applicaiton is actively evasive
        consume_big_bandwidth (bool): Application uses large bandwidth
        used_by_malware (bool): Application is used by malware
        able_to_transfer_file (bool): Application can do file transfers
        has_known_vulnerability (bool): Application has known vulnerabilities
        tunnel_other_application (bool):
        tunnel_applications (list): List of tunneled applications
        prone_to_misuse (bool):
        pervasive_use (bool):
        file_type_ident (bool):
        virus_ident (bool):
        data_ident (bool):
        description (str): Description of this object
        tag (list): Administrative tags

    Please refer to https://applipedia.paloaltonetworks.com/ for more info on these params

    """
    ROOT = Root.VSYS
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value='/application')

        # params
        params = []

        params.append(VersionedParamPath(
            'category', path='category'))
        params.append(VersionedParamPath(
            'subcategory', path='subcategory'))
        params.append(VersionedParamPath(
            'technology', path='technology'))
        params.append(VersionedParamPath(
            'risk', path='risk', vartype='int'))
        params.append(VersionedParamPath(
            'default_type', path='default/{default_type}',
            values=['port', 'ident-by-ip-protocol', 'ident-by-icmp-type', 'ident-by-icmp6-type']))
        params.append(VersionedParamPath(
            'default_port', path='default/{default_type}', vartype='member',
            condition={'default_type': 'port'}))
        params.append(VersionedParamPath(
            'default_ip_protocol', path='default/{default_type}',
            condition={'default_type': 'ident-by-ip-protocol'}))
        params.append(VersionedParamPath(
            'default_icmp_type', path='default/{default_type}/type', vartype='int',
            condition={'default_type': ['ident-by-icmp-type', 'ident-by-icmp6-type']}))
        params.append(VersionedParamPath(
            'default_icmp_code', path='default/{default_type}/code', vartype='int',
            condition={'default_type': ['ident-by-icmp-type', 'ident-by-icmp6-type']}))
        params.append(VersionedParamPath(
            'parent_app', path='parent-app'))
        params.append(VersionedParamPath(
            'timeout', path='timeout', vartype='int'))
        params.append(VersionedParamPath(
            'tcp_timeout', path='tcp-timeout', vartype='int'))
        params.append(VersionedParamPath(
            'udp_timeout', path='udp-timeout', vartype='int'))
        params.append(VersionedParamPath(
            'tcp_half_closed_timeout', path='tcp-half-closed-timeout', vartype='int'))
        params.append(VersionedParamPath(
            'tcp_time_wait_timeout', path='tcp-time-wait-timeout', vartype='int'))
        params.append(VersionedParamPath(
            'evasive_behavior', path='evasive-behavior', vartype='yesno'))
        params.append(VersionedParamPath(
            'consume_big_bandwidth', path='consume-big-bandwidth', vartype='yesno'))
        params.append(VersionedParamPath(
            'used_by_malware', path='used-by-malware', vartype='yesno'))
        params.append(VersionedParamPath(
            'able_to_transfer_file', path='able-to-transfer-file', vartype='yesno'))
        params.append(VersionedParamPath(
            'has_known_vulnerability', path='has-known-vulnerability', vartype='yesno'))
        params.append(VersionedParamPath(
            'tunnel_other_application', path='tunnel-other-application', vartype='yesno'))
        params.append(VersionedParamPath(
            'tunnel_applications', path='tunnel-applications', vartype='member'))
        params.append(VersionedParamPath(
            'prone_to_misuse', path='prone-to-misuse', vartype='yesno'))
        params.append(VersionedParamPath(
            'pervasive_use', path='pervasive-use', vartype='yesno'))
        params.append(VersionedParamPath(
            'file_type_ident', path='file-type-ident', vartype='yesno'))
        params.append(VersionedParamPath(
            'virus_ident', path='virus-ident', vartype='yesno'))
        params.append(VersionedParamPath(
            'data_ident', path='data-ident', vartype='yesno'))
        params.append(VersionedParamPath(
            'description', path='description'))
        params.append(VersionedParamPath(
            'tag', path='tag', vartype='member'))

        self._params = tuple(params)


class ApplicationGroup(VersionedPanObject):
    """ApplicationGroup Object

    Args:
        name (str): Name of the object
        value (list): List of application values
        tag (list): Administrative tags

    """
    ROOT = Root.VSYS
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value='/application-group')

        # params
        params = []

        params.append(VersionedParamPath(
            'value', path='members', vartype='member'))
        params.append(VersionedParamPath(
            'tag', path='tag', vartype='member'))

        self._params = tuple(params)


class ApplicationFilter(VersionedPanObject):
    """ApplicationFilter Object

    Args:
        name (str): Name of the object
        category (list): Application category
        subcategory (list): Application subcategory
        technology (list): Application technology
        risk (list): Application risk
        evasive (bool):
        excessive_bandwidth_use (bool):
        prone_to_misuse (bool):
        is_saas (bool):
        transfers_files (bool):
        tunnels_other_apps (bool):
        used_by_malware (bool):
        has_known_vulnerabilities (bool):
        pervasive (bool):
        tag (list): Administrative tags

    """
    ROOT = Root.VSYS
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value='/application-filter')

        # params
        params = []

        params.append(VersionedParamPath(
            'category', path='category', vartype='member'))
        params.append(VersionedParamPath(
            'subcategory', path='subcategory', vartype='member'))
        params.append(VersionedParamPath(
            'technology', path='technology', vartype='member'))
        params.append(VersionedParamPath(
            'risk', path='risk', vartype='member'))
        params.append(VersionedParamPath(
            'evasive', path='evasive', vartype='yesno'))
        params.append(VersionedParamPath(
            'excessive_bandwidth_use', path='excessive-bandwidth-use', vartype='yesno'))
        params.append(VersionedParamPath(
            'prone_to_misuse', path='prone-to-misuse', vartype='yesno'))
        params.append(VersionedParamPath(
            'is_saas', path='is-saas', vartype='yesno'))
        params.append(VersionedParamPath(
            'transfers_files', path='transfers-files', vartype='yesno'))
        params.append(VersionedParamPath(
            'tunnels_other_apps', path='tunnels-other-apps', vartype='yesno'))
        params.append(VersionedParamPath(
            'used_by_malware', path='used-by-malware', vartype='yesno'))
        params.append(VersionedParamPath(
            'has_known_vulnerabilities', path='has-known-vulnerabilities', vartype='yesno'))
        params.append(VersionedParamPath(
            'pervasive', path='pervasive', vartype='yesno'))
        params.append(VersionedParamPath(
            'tag', path='tag', vartype='member'))

        self._params = tuple(params)


class ApplicationContainer(VersionedPanObject):
    """ApplicationContainer object

    This is a special class that is used in the predefined module.
    It acts much like an ApplicationGroup object but exists only
    in the predefined context. It is more or less a way that
    Palo Alto groups predefined applications together.

    Args:
        applications (list): List of memeber applications

    """
    ROOT = Root.VSYS
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value='/application-container')

        # params
        params = []

        params.append(VersionedParamPath(
            'applications', path='functions', vartype='member'))

        self._params = tuple(params)
