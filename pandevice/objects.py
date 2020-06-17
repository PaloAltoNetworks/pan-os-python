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

import logging
import re
import xml.etree.ElementTree as ET

import pandevice
import pandevice.errors as err
from pandevice import getlogger
from pandevice.base import ENTRY, MEMBER, PanObject, Root
from pandevice.base import VarPath as Var
from pandevice.base import VersionedPanObject, VersionedParamPath

logger = getlogger(__name__)


class AddressObject(VersionedPanObject):
    """Address Object

    Args:
        name (str): Name of the object
        value (str): IP address or other value of the object
        type (str): Type of address:
                * ip-netmask (default)
                * ip-range
                * ip-wildcard (added in PAN-OS 9.0)
                * fqdn
        description (str): Description of this object
        tag (list): Administrative tags

    """

    ROOT = Root.VSYS
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/address")

        # params
        params = []

        params.append(VersionedParamPath("value", path="{type}"))
        params.append(
            VersionedParamPath(
                "type",
                default="ip-netmask",
                values=["ip-netmask", "ip-range", "ip-wildcard", "fqdn"],
                path="{type}",
            )
        )
        params.append(VersionedParamPath("description", path="description"))
        params.append(VersionedParamPath("tag", path="tag", vartype="member"))

        self._params = tuple(params)


class AddressGroup(VersionedPanObject):
    """Address Group

    Args:
        name (str): Name of the address group
        static_value (list): Values for a static address group
        dynamic_value (str): Registered-ip tags for a dynamic address group
        description (str): Description of this object
        tag (list): Administrative tags (not to be confused with registered-ip tags)

    """

    ROOT = Root.VSYS
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/address-group")

        # params
        params = []

        params.append(
            VersionedParamPath("static_value", path="static", vartype="member")
        )
        params.append(VersionedParamPath("dynamic_value", path="dynamic/filter"))
        params.append(VersionedParamPath("description", path="description"))
        params.append(VersionedParamPath("tag", path="tag", vartype="member"))

        self._params = tuple(params)


class Tag(VersionedPanObject):
    """Administrative tag

    Args:
        name (str): Name of the tag
        color (str): Color ID (eg. 'color1', 'color4', etc). You can
            use :func:`~pandevice.objects.Tag.color_code` to generate the ID.
        comments (str): Comments

    """

    ROOT = Root.VSYS
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/tag")

        # params
        params = []

        params.append(VersionedParamPath("color", path="color"))
        params.append(VersionedParamPath("comments", path="comments"))

        self._params = tuple(params)

    @staticmethod
    def color_code(color_name):
        """Returns the color code for a color

        Args:
            color_name (str): One of the following colors:

                    * red
                    * green
                    * blue
                    * yellow
                    * copper
                    * orange
                    * purple
                    * gray
                    * light green
                    * cyan
                    * light gray
                    * blue gray
                    * lime
                    * black
                    * gold
                    * brown

        """
        colors = {
            "red": 1,
            "green": 2,
            "blue": 3,
            "yellow": 4,
            "copper": 5,
            "orange": 6,
            "purple": 7,
            "gray": 8,
            "light green": 9,
            "cyan": 10,
            "light gray": 11,
            "blue gray": 12,
            "lime": 13,
            "black": 14,
            "gold": 15,
            "brown": 16,
        }
        if color_name not in colors:
            raise ValueError("Color '{0}' is not valid".format(color_name))
        return "color" + str(colors[color_name])


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
        self._xpaths.add_profile(value="/service")

        # params
        params = []

        params.append(
            VersionedParamPath(
                "protocol",
                path="protocol/{protocol}",
                values=["tcp", "udp"],
                default="tcp",
            )
        )
        params.append(
            VersionedParamPath("source_port", path="protocol/{protocol}/source-port")
        )
        params.append(
            VersionedParamPath("destination_port", path="protocol/{protocol}/port")
        )
        params.append(VersionedParamPath("description", path="description"))
        params.append(VersionedParamPath("tag", path="tag", vartype="member"))

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
        self._xpaths.add_profile(value="/service-group")

        # params
        params = []

        params.append(VersionedParamPath("value", path="members", vartype="member"))
        params.append(VersionedParamPath("tag", path="tag", vartype="member"))

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
        self._xpaths.add_profile(value="/application")

        # params
        params = []

        params.append(VersionedParamPath("category", path="category"))
        params.append(VersionedParamPath("subcategory", path="subcategory"))
        params.append(VersionedParamPath("technology", path="technology"))
        params.append(VersionedParamPath("risk", path="risk", vartype="int"))
        params.append(
            VersionedParamPath(
                "default_type",
                path="default/{default_type}",
                values=[
                    "port",
                    "ident-by-ip-protocol",
                    "ident-by-icmp-type",
                    "ident-by-icmp6-type",
                ],
            )
        )
        params.append(
            VersionedParamPath(
                "default_port",
                path="default/{default_type}",
                vartype="member",
                condition={"default_type": "port"},
            )
        )
        params.append(
            VersionedParamPath(
                "default_ip_protocol",
                path="default/{default_type}",
                condition={"default_type": "ident-by-ip-protocol"},
            )
        )
        params.append(
            VersionedParamPath(
                "default_icmp_type",
                path="default/{default_type}/type",
                vartype="int",
                condition={
                    "default_type": ["ident-by-icmp-type", "ident-by-icmp6-type"]
                },
            )
        )
        params.append(
            VersionedParamPath(
                "default_icmp_code",
                path="default/{default_type}/code",
                vartype="int",
                condition={
                    "default_type": ["ident-by-icmp-type", "ident-by-icmp6-type"]
                },
            )
        )
        params.append(VersionedParamPath("parent_app", path="parent-app"))
        params.append(VersionedParamPath("timeout", path="timeout", vartype="int"))
        params.append(
            VersionedParamPath("tcp_timeout", path="tcp-timeout", vartype="int")
        )
        params.append(
            VersionedParamPath("udp_timeout", path="udp-timeout", vartype="int")
        )
        params.append(
            VersionedParamPath(
                "tcp_half_closed_timeout", path="tcp-half-closed-timeout", vartype="int"
            )
        )
        params.append(
            VersionedParamPath(
                "tcp_time_wait_timeout", path="tcp-time-wait-timeout", vartype="int"
            )
        )
        params.append(
            VersionedParamPath(
                "evasive_behavior", path="evasive-behavior", vartype="yesno"
            )
        )
        params.append(
            VersionedParamPath(
                "consume_big_bandwidth", path="consume-big-bandwidth", vartype="yesno"
            )
        )
        params.append(
            VersionedParamPath(
                "used_by_malware", path="used-by-malware", vartype="yesno"
            )
        )
        params.append(
            VersionedParamPath(
                "able_to_transfer_file", path="able-to-transfer-file", vartype="yesno"
            )
        )
        params.append(
            VersionedParamPath(
                "has_known_vulnerability",
                path="has-known-vulnerability",
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "tunnel_other_application",
                path="tunnel-other-application",
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "tunnel_applications", path="tunnel-applications", vartype="member"
            )
        )
        params.append(
            VersionedParamPath(
                "prone_to_misuse", path="prone-to-misuse", vartype="yesno"
            )
        )
        params.append(
            VersionedParamPath("pervasive_use", path="pervasive-use", vartype="yesno")
        )
        params.append(
            VersionedParamPath(
                "file_type_ident", path="file-type-ident", vartype="yesno"
            )
        )
        params.append(
            VersionedParamPath("virus_ident", path="virus-ident", vartype="yesno")
        )
        params.append(
            VersionedParamPath("data_ident", path="data-ident", vartype="yesno")
        )
        params.append(VersionedParamPath("description", path="description"))
        params.append(VersionedParamPath("tag", path="tag", vartype="member"))

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
        self._xpaths.add_profile(value="/application-group")

        # params
        params = []

        params.append(VersionedParamPath("value", path="members", vartype="member"))
        params.append(VersionedParamPath("tag", path="tag", vartype="member"))

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
        self._xpaths.add_profile(value="/application-filter")

        # params
        params = []

        params.append(VersionedParamPath("category", path="category", vartype="member"))
        params.append(
            VersionedParamPath("subcategory", path="subcategory", vartype="member")
        )
        params.append(
            VersionedParamPath("technology", path="technology", vartype="member")
        )
        params.append(VersionedParamPath("risk", path="risk", vartype="member"))
        params.append(VersionedParamPath("evasive", path="evasive", vartype="yesno"))
        params.append(
            VersionedParamPath(
                "excessive_bandwidth_use",
                path="excessive-bandwidth-use",
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath(
                "prone_to_misuse", path="prone-to-misuse", vartype="yesno"
            )
        )
        params.append(VersionedParamPath("is_saas", path="is-saas", vartype="yesno"))
        params.append(
            VersionedParamPath(
                "transfers_files", path="transfers-files", vartype="yesno"
            )
        )
        params.append(
            VersionedParamPath(
                "tunnels_other_apps", path="tunnels-other-apps", vartype="yesno"
            )
        )
        params.append(
            VersionedParamPath(
                "used_by_malware", path="used-by-malware", vartype="yesno"
            )
        )
        params.append(
            VersionedParamPath(
                "has_known_vulnerabilities",
                path="has-known-vulnerabilities",
                vartype="yesno",
            )
        )
        params.append(
            VersionedParamPath("pervasive", path="pervasive", vartype="yesno")
        )
        params.append(VersionedParamPath("tag", path="tag", vartype="member"))

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
        self._xpaths.add_profile(value="/application-container")

        # params
        params = []

        params.append(
            VersionedParamPath("applications", path="functions", vartype="member")
        )

        self._params = tuple(params)


class SecurityProfileGroup(VersionedPanObject):
    """Security Profile Group object

    Args:
        name (str): The group name
        virus (str): Antivirus profile
        spyware (str): Anti-spyware profile
        vulnerability (str): Vulnerability protection profile
        url_filtering (str): URL filtering profile
        file_blocking (str): File blocking profile
        data_filtering (str): Data filtering profile
        wildfire_analysis (str): WildFire analysis profile

    """

    ROOT = Root.VSYS
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/profile-group")

        # params
        params = []

        params.append(VersionedParamPath("virus", path="virus", vartype="member"))
        params.append(VersionedParamPath("spyware", path="spyware", vartype="member"))
        params.append(
            VersionedParamPath("vulnerability", path="vulnerability", vartype="member")
        )
        params.append(
            VersionedParamPath("url_filtering", path="url-filtering", vartype="member")
        )
        params.append(
            VersionedParamPath("file_blocking", path="file-blocking", vartype="member")
        )
        params.append(
            VersionedParamPath(
                "data_filtering", path="data-filtering", vartype="member"
            )
        )
        params.append(
            VersionedParamPath(
                "wildfire_analysis", path="wildfire-analysis", vartype="member"
            )
        )

        self._params = tuple(params)


class CustomUrlCategory(VersionedPanObject):
    """Custom url category group

    Args:
        name (str): The name
        url_value (list): Values to include in custom URL category object
        description (str): Description of this object

    """

    ROOT = Root.VSYS
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/profiles/custom-url-category")

        # params
        params = []

        params.append(VersionedParamPath("url_value", path="list", vartype="member"))
        params.append(VersionedParamPath("description", path="description"))

        self._params = tuple(params)


class LogForwardingProfile(VersionedPanObject):
    """A log forwarding profile.

    Note:  This is valid for PAN-OS 8.0+

    Args:
        name (str): The name
        description (str): The description
        enhanced_logging (bool): (PAN-OS 8.1+) Enabling enhanced application
            logging

    """

    ROOT = Root.VSYS
    SUFFIX = ENTRY
    CHILDTYPES = ("objects.LogForwardingProfileMatchList",)

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/log-settings/profiles")

        # params
        params = []

        params.append(VersionedParamPath("description", path="description"))
        params.append(VersionedParamPath("enhanced_logging", exclude=True))
        params[-1].add_profile(
            "8.1.0", vartype="yesno", path="enhanced-application-logging"
        )

        self._params = tuple(params)


class LogForwardingProfileMatchList(VersionedPanObject):
    """A log forwarding profile match list entry.

    Note: This is valid for PAN-OS 8.0+

    Args:
        name (str): The name
        description (str): Description
        log_type (str): Log type. Valid values are traffic, threat, wildfire,
            url, data, gtp, tunnel, auth, or sctp (PAN-OS 8.1+).
        filter (str): The filter.
        send_to_panorama (bool): Send to panorama or not
        snmp_profiles (str/list): List of SnmpServerProfiles.
        email_profiles (str/list): List of EmailServerProfiles.
        syslog_profiles (str/list): List of SyslogServerProfiles.
        http_profiles (str/list): List of HttpServerProfiles.

    """

    ROOT = Root.VSYS
    SUFFIX = ENTRY
    CHILDTYPES = ("objects.LogForwardingProfileMatchListAction",)

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/match-list")

        # params
        params = []

        params.append(VersionedParamPath("description", path="action-desc"))
        params.append(
            VersionedParamPath(
                "log_type",
                path="log-type",
                values=[
                    "traffic",
                    "threat",
                    "wildfire",
                    "url",
                    "data",
                    "gtp",
                    "tunnel",
                    "auth",
                ],
            )
        )
        params[-1].add_profile(
            "8.1.0",
            path="log-type",
            values=[
                "traffic",
                "threat",
                "wildfire",
                "url",
                "data",
                "gtp",
                "tunnel",
                "auth",
                "sctp",
            ],
        )
        params.append(VersionedParamPath("filter", path="filter"))
        params.append(
            VersionedParamPath(
                "send_to_panorama", vartype="yesno", path="send-to-panorama"
            )
        )
        params.append(
            VersionedParamPath("snmp_profiles", vartype="member", path="send-snmptrap")
        )
        params.append(
            VersionedParamPath("email_profiles", vartype="member", path="send-email")
        )
        params.append(
            VersionedParamPath("syslog_profiles", vartype="member", path="send-syslog")
        )
        params.append(
            VersionedParamPath("http_profiles", vartype="member", path="send-http")
        )

        self._params = tuple(params)


class LogForwardingProfileMatchListAction(VersionedPanObject):
    """Action for a log forwarding profile match list entry.

    Note: This is valid for PAN-OS 8.0+

    Args:
        name (str): The name
        action_type (str): Action type.  Valid values are tagging (default)
            or (PAN-OS 8.1+) integration.
        action (str): The action.  Valid values are add-tag, remove-tag, or
            (PAN-OS 8.1+) Azure-Security-Center-Integration.
        target (str): The target.  Valid values are source-address or
            destination-address.
        registration (str): Registration.  Valid values are localhost,
            panorama, or remote.
        http_profile (str): The HTTP profile for registration of "remote".
        tags (str/list): List of administrative tags.
        timeout (int): (PAN-OS 9.0+) Timeout in minutes

    """

    ROOT = Root.VSYS
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/actions")

        # params
        params = []

        params.append(
            VersionedParamPath(
                "action_type",
                default="tagging",
                values=["tagging",],
                path="type/{action_type}",
            )
        )
        params[-1].add_profile(
            "8.1.0", values=["tagging", "integration"], path="type/{action_type}"
        )
        params.append(
            VersionedParamPath(
                "action",
                path="type/{action_type}/action",
                values=["add-tag", "remove-tag"],
            )
        )
        params[-1].add_profile(
            "8.1.0",
            path="type/{action_type}/action",
            values=["Azure-Security-Center-Integration", "add-tag", "remove-tag"],
        )
        params.append(
            VersionedParamPath(
                "target",
                path="type/{action_type}/target",
                condition={"action_type": "tagging"},
                values=["source-address", "destination-address"],
            )
        )
        params.append(
            VersionedParamPath(
                "registration",
                values=["localhost", "panorama", "remote"],
                condition={"action_type": "tagging"},
                path="type/{action_type}/registration/{registration}",
            )
        )
        params.append(
            VersionedParamPath(
                "http_profile",
                condition={"action_type": "tagging", "registration": "remote"},
                path="type/{action_type}/registration/{registration}/http-profile",
            )
        )
        params.append(
            VersionedParamPath(
                "tags",
                condition={"action_type": "tagging"},
                vartype="member",
                path="type/{action_type}/tags",
            )
        )
        params.append(VersionedParamPath("timeout", exclude=True))
        params[-1].add_profile(
            "9.0.0",
            vartype="int",
            path="type/{action_type}/timeout",
            condition={"action_type": "tagging"},
        )

        self._params = tuple(params)


class DynamicUserGroup(VersionedPanObject):
    """Dynamic user group.

    Note:  PAN-OS 9.1+

    Args:
        name: Name of the dynamic user group
        description (str): Description of this object
        filter: Tag-based filter.
        tag (list): Administrative tags

    """

    ROOT = Root.VSYS
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/dynamic-user-group")

        # params
        params = []

        params.append(VersionedParamPath("description", path="description"))
        params.append(VersionedParamPath("filter", path="filter"))
        params.append(VersionedParamPath("tag", path="tag", vartype="member"))

        self._params = tuple(params)


class ScheduleObject(VersionedPanObject):
    """Schedule Object

    "Date and Time Range" Example:  2019/11/01@00:15-2019/11/28@00:30
    "Time Range" Example:  17:00-19:00

    Args:
        name (str): Name of the object
        disable_override (bool): "True" to set disable-override
        type (str): Type of Schedule: "recurring" or "non-recurring"
        non_recurring_date_time (list/str): "Date and Time Range" string for a non-recurring schedule
        recurrence (str): "daily" or "weekly" recurrence
        daily_time (list/str): "Time Range" for a daily recurring schedule
        weekly_sunday_time (list/str): "Time Range" for a weekly recurring schedule (Sunday)
        weekly_monday_time (list/str): "Time Range" for a weekly recurring schedule (Monday)
        weekly_tuesday_time (list/str): "Time Range" for a weekly recurring schedule (Tuesday)
        weekly_wednesday_time (list/str): "Time Range" for a weekly recurring schedule (Wednesday)
        weekly_thursday_time (list/str): "Time Range" for a weekly recurring schedule (Thursday)
        weekly_friday_time (list/str): "Time Range" for a weekly recurring schedule (Friday)
        weekly_saturday_time (list/str): "Time Range" for a weekly recurring schedule (Saturday)

    """

    ROOT = Root.VSYS
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/schedule")

        # params
        params = []

        params.append(
            VersionedParamPath(
                "disable_override", vartype="yesno", path="disable-override"
            )
        )
        params.append(
            VersionedParamPath(
                "type",
                path="schedule-type/{type}",
                values=["recurring", "non-recurring"],
            )
        )
        params.append(
            VersionedParamPath(
                "non_recurring_date_time",
                path="schedule-type/{type}",
                vartype="member",
                condition={"type": "non-recurring"},
            )
        )
        params.append(
            VersionedParamPath(
                "recurrence",
                path="schedule-type/{type}/{recurrence}",
                values=["weekly", "daily"],
                condition={"type": "recurring"},
            )
        )
        params.append(
            VersionedParamPath(
                "daily_time",
                path="schedule-type/{type}/{recurrence}",
                vartype="member",
                condition={"type": "recurring", "recurrence": "daily"},
            )
        )
        params.append(
            VersionedParamPath(
                "weekly_sunday_time",
                path="schedule-type/{type}/{recurrence}/sunday",
                vartype="member",
                condition={"type": "recurring", "recurrence": "weekly"},
            )
        )
        params.append(
            VersionedParamPath(
                "weekly_monday_time",
                path="schedule-type/{type}/{recurrence}/monday",
                vartype="member",
                condition={"type": "recurring", "recurrence": "weekly"},
            )
        )
        params.append(
            VersionedParamPath(
                "weekly_tuesday_time",
                path="schedule-type/{type}/{recurrence}/tuesday",
                vartype="member",
                condition={"type": "recurring", "recurrence": "weekly"},
            )
        )
        params.append(
            VersionedParamPath(
                "weekly_wednesday_time",
                path="schedule-type/{type}/{recurrence}/wednesday",
                vartype="member",
                condition={"type": "recurring", "recurrence": "weekly"},
            )
        )
        params.append(
            VersionedParamPath(
                "weekly_thursday_time",
                path="schedule-type/{type}/{recurrence}/thursday",
                vartype="member",
                condition={"type": "recurring", "recurrence": "weekly"},
            )
        )
        params.append(
            VersionedParamPath(
                "weekly_friday_time",
                path="schedule-type/{type}/{recurrence}/friday",
                vartype="member",
                condition={"type": "recurring", "recurrence": "weekly"},
            )
        )
        params.append(
            VersionedParamPath(
                "weekly_saturday_time",
                path="schedule-type/{type}/{recurrence}/saturday",
                vartype="member",
                condition={"type": "recurring", "recurrence": "weekly"},
            )
        )

        self._params = tuple(params)


class Region(VersionedPanObject):
    """Region.

    Args:
        name (str): Name of the region
        address (list): List of IP networks
        latitude (float): Latitude of the region
        longitude (float): Longitude of the region

    """

    ROOT = Root.VSYS
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/region")

        # params
        params = []

        params.append(VersionedParamPath("address", path="address", vartype="member"))
        params.append(
            VersionedParamPath(
                "latitude", path="geo-location/latitude", vartype="float"
            )
        )
        params.append(
            VersionedParamPath(
                "longitude", path="geo-location/longitude", vartype="float"
            )
        )

        self._params = tuple(params)
