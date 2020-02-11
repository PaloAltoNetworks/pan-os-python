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


"""Policies module contains policies and rules that exist in the 'Policies' tab in the firewall GUI"""

import pandevice.errors as err
from pandevice import getlogger
from pandevice.base import ENTRY, MEMBER, PanObject, Root
from pandevice.base import VarPath as Var
from pandevice.base import VersionedPanObject, VersionedParamPath

logger = getlogger(__name__)


class Rulebase(VersionedPanObject):
    """Rulebase for a Firewall

    Firewall only.  For Panorama, use :class:`pandevice.policies.PreRulebase` or
    :class:`pandevice.policies.PostRulebase`.

    """

    ROOT = Root.VSYS
    CHILDTYPES = (
        "policies.NatRule",
        "policies.PolicyBasedForwarding",
        "policies.SecurityRule",
    )

    def _setup(self):
        self._xpaths.add_profile(value="/rulebase")


class PreRulebase(Rulebase):
    """Pre-rulebase for a Panorama

    Panorama only.  For Firewall, use :class:`pandevice.policies.Rulebase`.

    """

    def _setup(self):
        self._xpaths.add_profile(value="/pre-rulebase")


class PostRulebase(Rulebase):
    """Post-rulebase for a Panorama

    Panorama only.  For Firewall, use :class:`pandevice.policies.Rulebase`.

    """

    def _setup(self):
        self._xpaths.add_profile(value="/post-rulebase")


class SecurityRule(VersionedPanObject):
    """Security Rule

    Args:
        name (str): Name of the rule
        fromzone (list): From zones
        tozone (list): To zones
        source (list): Source addresses
        source_user (list): Source users and groups
        hip_profiles (list): GlobalProtect host integrity profiles
        destination (list): Destination addresses
        application (list): Applications
        service (list): Destination services (ports) (Default:
            application-default)
        category (list): Destination URL Categories
        action (str): Action to take (deny, allow, drop, reset-client,
            reset-server, reset-both)
            Note: Not all options are available on all PAN-OS versions.
        log_setting (str): Log forwarding profile
        log_start (bool): Log at session start
        log_end (bool): Log at session end
        description (str): Description of this rule
        type (str): 'universal', 'intrazone', or 'intrazone' (Default:
            universal)
        tag (list): Administrative tags
        negate_source (bool): Match on the reverse of the 'source' attribute
        negate_destination (bool): Match on the reverse of the 'destination'
            attribute
        disabled (bool): Disable this rule
        schedule (str): Schedule Profile
        icmp_unreachable (bool): Send ICMP Unreachable
        disable_server_response_inspection (bool): Disable server response
            inspection
        group (str): Security Profile Group
        virus (str): Antivirus Security Profile
        spyware (str): Anti-Spyware Security Profile
        vulnerability (str): Vulnerability Protection Security Profile
        url_filtering (str): URL Filtering Security Profile
        file_blocking (str): File Blocking Security Profile
        wildfire_analysis (str): Wildfire Analysis Security Profile
        data_filtering (str): Data Filtering Security Profile
        negate_target (bool): Target all but the listed target firewalls
            (applies to panorama/device groups only)
        target (list): Apply this policy to the listed firewalls only
            (applies to panorama/device groups only)
        uuid (str): (PAN-OS 9.0+) The UUID for this rule.

    """

    # TODO: Add QoS variables
    SUFFIX = ENTRY
    ROOT = Root.VSYS

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/security/rules")

        # params
        params = []

        any_defaults = (
            ("fromzone", "from"),
            ("tozone", "to"),
            ("source", "source"),
            ("source_user", "source-user"),
            ("hip_profiles", "hip-profiles"),
            ("destination", "destination"),
            ("application", "application"),
        )
        for var_name, path in any_defaults:
            params.append(
                VersionedParamPath(
                    var_name, default=["any",], vartype="member", path=path
                )
            )

        params.append(
            VersionedParamPath(
                "service",
                default="application-default",
                vartype="member",
                path="service",
            )
        )
        params.append(
            VersionedParamPath(
                "category", default=["any",], vartype="member", path="category"
            )
        )
        params.append(VersionedParamPath("action", path="action"))
        params.append(VersionedParamPath("log_setting", path="log-setting"))
        params.append(
            VersionedParamPath("log_start", path="log-start", vartype="yesno")
        )
        params.append(VersionedParamPath("log_end", path="log-end", vartype="yesno"))
        params.append(VersionedParamPath("description", path="description"))
        params.append(VersionedParamPath("type", default="universal", path="rule-type"))
        params.append(VersionedParamPath("tag", path="tag", vartype="member"))
        params.append(
            VersionedParamPath("negate_source", path="negate-source", vartype="yesno")
        )
        params.append(
            VersionedParamPath(
                "negate_destination", path="negate-destination", vartype="yesno"
            )
        )
        params.append(VersionedParamPath("disabled", path="disabled", vartype="yesno"))
        params.append(VersionedParamPath("schedule", path="schedule"))
        params.append(
            VersionedParamPath(
                "icmp_unreachable", path="icmp-unreachable", vartype="yesno"
            )
        )
        params.append(
            VersionedParamPath(
                "disable_server_response_inspection",
                vartype="yesno",
                path="option/disable-server-response-inspection",
            )
        )
        params.append(
            VersionedParamPath("group", path="profile-setting/group", vartype="member")
        )
        params.append(
            VersionedParamPath("negate_target", path="target/negate", vartype="yesno")
        )
        params.append(
            VersionedParamPath("target", path="target/devices", vartype="entry")
        )

        member_profiles = (
            "virus",
            "spyware",
            "vulnerability",
            "url-filtering",
            "file-blocking",
            "wildfire-analysis",
            "data-filtering",
        )
        for p in member_profiles:
            params.append(
                VersionedParamPath(
                    p, vartype="member", path="profile-setting/profiles/{0}".format(p)
                )
            )

        params.append(VersionedParamPath("uuid", exclude=True))
        params[-1].add_profile("9.0.0", vartype="attrib", path="uuid")

        self._params = tuple(params)


class NatRule(VersionedPanObject):
    """NAT Rule

    Both the naming convention and the order of the parameters tries to closly
    match what is presented in the GUI.

    There are groupings of parameters that give hints to the sections that
    they contribute towards:

        * source_translation_<etc>
        * source_translation_fallback_<etc>
        * source_translation_static_<etc>
        * destination_translation_<etc>

    Args:
        name (str): Name of the rule
        description (str): The description
        nat_type (str): Type of NAT
        fromzone (list): From zones
        tozone (list): To zones
        to_interface (str): Egress interface from route lookup
        service (str): The service
        source (list): Source addresses
        destination (list): Destination addresses
        source_translation_type (str): Type of source address translation
        source_translation_address_type (str): Address type for Dynamic IP
            And Port or Dynamic IP source translation types
        source_translation_interface (str): Interface of the source address
            translation for Dynamic IP and Port source translation types
        source_translation_ip_address (str): IP address of the source address
            translation for Dynamic IP and Port source translation types
        source_translation_translated_addresses (list): Translated addresses
            of the source address translation for Dynamic IP And Port or
            Dynamic IP source translation types
        source_translation_fallback_type (str): Type of fallback for Dynamic IP
            source translation types
        source_translation_fallback_translated_addresses (list): Addresses for
            translated address types of fallback source translation
        source_translation_fallback_interface (str): The interface for the
            fallback source translation
        source_translation_fallback_ip_type (str): The type of the IP address
            for the fallback source translation IP address
        source_translation_fallback_ip_address (str): The IP address of the
            fallback source translation
        source_translation_static_translated_address (str): The IP address
            for the static source translation
        source_translation_static_bi_directional (bool): Allow reverse
            translation from translated address to original address
        destination_translated_address (str): Translated destination IP
            address
        destination_translated_port (int): Translated destination port number
        ha_binding (str): Device binding configuration in HA Active-Active mode
        disabled (bool): Disable this rule
        negate_target (bool): Target all but the listed target firewalls
            (applies to panorama/device groups only)
        target (list): Apply this policy to the listed firewalls only
            (applies to panorama/device groups only)
        tag (list): Administrative tags
        uuid (str): (PAN-OS 9.0+) The UUID for this rule.

    """

    SUFFIX = ENTRY
    ROOT = Root.VSYS

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/nat/rules")

        # params
        params = []

        params.append(VersionedParamPath("description", path="description"))
        params.append(
            VersionedParamPath(
                "nat_type",
                path="nat-type",
                default="ipv4",
                values=("ipv4", "nat64", "nptv6"),
            )
        )
        params.append(
            VersionedParamPath(
                "fromzone", default=["any",], vartype="member", path="from"
            )
        )
        params.append(VersionedParamPath("tozone", vartype="member", path="to"))
        params.append(VersionedParamPath("to_interface", path="to-interface"))
        params.append(VersionedParamPath("service", default="any", path="service"))
        params.append(
            VersionedParamPath(
                "source", default=["any",], vartype="member", path="source"
            )
        )
        params.append(
            VersionedParamPath(
                "destination", default=["any",], vartype="member", path="destination"
            )
        )
        params.append(
            VersionedParamPath(
                "source_translation_type",
                path="source-translation/{source_translation_type}",
                values=("dynamic-ip-and-port", "dynamic-ip", "static-ip"),
            )
        )
        params.append(
            VersionedParamPath(
                "source_translation_address_type",
                path="/".join(
                    (
                        "source-translation",
                        "{source_translation_type}",
                        "{source_translation_address_type}",
                    )
                ),
                values=("interface-address", "translated-address"),
                default="translated-address",
                condition={
                    "source_translation_type": ["dynamic-ip-and-port", "dynamic-ip"]
                },
            )
        )
        params.append(
            VersionedParamPath(
                "source_translation_interface",
                path="/".join(
                    (
                        "source-translation",
                        "{source_translation_type}",
                        "{source_translation_address_type}",
                        "interface",
                    )
                ),
                condition={
                    "source_translation_type": "dynamic-ip-and-port",
                    "source_translation_address_type": "interface-address",
                },
            )
        )
        params.append(
            VersionedParamPath(
                "source_translation_ip_address",
                path="/".join(
                    (
                        "source-translation",
                        "{source_translation_type}",
                        "{source_translation_address_type}",
                        "ip",
                    )
                ),
                condition={
                    "source_translation_type": "dynamic-ip-and-port",
                    "source_translation_address_type": "interface-address",
                },
            )
        )
        params.append(
            VersionedParamPath(
                "source_translation_translated_addresses",
                vartype="member",
                path="/".join(
                    (
                        "source-translation",
                        "{source_translation_type}",
                        "{source_translation_address_type}",
                    )
                ),
                condition={
                    "source_translation_type": ["dynamic-ip-and-port", "dynamic-ip"],
                    "source_translation_address_type": "translated-address",
                },
            )
        )
        params.append(
            VersionedParamPath(
                "source_translation_fallback_type",
                path="/".join(
                    (
                        "source-translation",
                        "{source_translation_type}",
                        "fallback",
                        "{source_translation_fallback_type}",
                    )
                ),
                values=("translated-address", "interface-address"),
                condition={"source_translation_type": "dynamic-ip"},
            )
        )
        params.append(
            VersionedParamPath(
                "source_translation_fallback_translated_addresses",
                path="/".join(
                    (
                        "source-translation",
                        "{source_translation_type}",
                        "fallback",
                        "{source_translation_fallback_type}",
                    )
                ),
                vartype="member",
                condition={
                    "source_translation_type": "dynamic-ip",
                    "source_translation_fallback_type": "translated-address",
                },
            )
        )
        params.append(
            VersionedParamPath(
                "source_translation_fallback_interface",
                path="/".join(
                    (
                        "source-translation",
                        "{source_translation_type}",
                        "fallback",
                        "{source_translation_fallback_type}",
                        "interface",
                    )
                ),
                condition={
                    "source_translation_type": "dynamic-ip",
                    "source_translation_fallback_type": "interface-address",
                },
            )
        )
        params.append(
            VersionedParamPath(
                "source_translation_fallback_ip_type",
                path="/".join(
                    (
                        "source-translation",
                        "{source_translation_type}",
                        "fallback",
                        "{source_translation_fallback_type}",
                        "{source_translation_fallback_ip_type}",
                    )
                ),
                values=("ip", "floating-ip"),
                default="ip",
                condition={
                    "source_translation_type": "dynamic-ip",
                    "source_translation_fallback_type": "interface-address",
                },
            )
        )
        params.append(
            VersionedParamPath(
                "source_translation_fallback_ip_address",
                path="/".join(
                    (
                        "source-translation",
                        "{source_translation_type}",
                        "fallback",
                        "{source_translation_fallback_type}",
                        "{source_translation_fallback_ip_type}",
                    )
                ),
                condition={
                    "source_translation_type": "dynamic-ip",
                    "source_translation_fallback_type": "interface-address",
                },
            )
        )
        params.append(
            VersionedParamPath(
                "source_translation_static_translated_address",
                path="/".join(
                    (
                        "source-translation",
                        "{source_translation_type}",
                        "translated-address",
                    )
                ),
                condition={"source_translation_type": "static-ip"},
            )
        )
        params.append(
            VersionedParamPath(
                "source_translation_static_bi_directional",
                vartype="yesno",
                path="/".join(
                    (
                        "source-translation",
                        "{source_translation_type}",
                        "bi-directional",
                    )
                ),
                condition={"source_translation_type": "static-ip"},
            )
        )
        params.append(
            VersionedParamPath(
                "destination_translated_address",
                path="destination-translation/translated-address",
            )
        )
        params.append(
            VersionedParamPath(
                "destination_translated_port",
                vartype="int",
                path="destination-translation/translated-port",
            )
        )
        params.append(
            VersionedParamPath(
                "ha_binding",
                path="active-active-device-binding",
                values=("primary", "both", "0", "1"),
            )
        )
        params.append(VersionedParamPath("disabled", vartype="yesno", path="disabled"))
        params.append(
            VersionedParamPath("negate_target", path="target/negate", vartype="yesno")
        )
        params.append(
            VersionedParamPath("target", path="target/devices", vartype="entry")
        )
        params.append(VersionedParamPath("tag", path="tag", vartype="member"))
        params.append(
            VersionedParamPath("destination_dynamic_translated_address", exclude=True)
        )
        params[-1].add_profile(
            "8.1.0", path="dynamic-destination-translation/translated-address"
        )
        params.append(
            VersionedParamPath("destination_dynamic_translated_port", exclude=True)
        )
        params[-1].add_profile(
            "8.1.0",
            path="dynamic-destination-translation/translated-port",
            vartype="int",
        )
        params.append(
            VersionedParamPath(
                "destination_dynamic_translated_distribution", exclude=True
            )
        )
        params[-1].add_profile(
            "8.1.0",
            path="dynamic-destination-translation/distribution",
            values=("round-robin",),
        )
        params.append(VersionedParamPath("uuid", exclude=True))
        params[-1].add_profile("9.0.0", vartype="attrib", path="uuid")

        self._params = tuple(params)


class PolicyBasedForwarding(VersionedPanObject):
    """PBF rule.

    Args:
        name (str): The name
        description (str): The descripton
        tags (str/list): List of tags
        from_type (str): Source from type.  Valid values are 'zone' (default)
            or 'interface'.
        from_values (str/list): The source values for the given type.
        source_addresses (str/list): List of source IP addresses.
        source_users (str/list): List of source users.
        negate_source (bool): Set to negate the source.
        destination_addresses (str/list): List of destination addresses.
        negate_destination (bool): Set to negate the destination.
        applications (str/list): List of applications.
        services (str/list): List of services.
        schedule (str): The schedule.
        disabled (bool): Set to disable this rule.
        action (str): The action to take.  Valid values are 'forward'
            (default), 'forward-to-vsys', 'discard', or 'no-pbf'.
        forward_vsys (str): The vsys to forward to if action is set to
            forward to a vsys.
        forward_egress_interface (str): The egress interface.
        forward_next_hop_type (str): The next hop type.  Valid values
            are 'ip-address', 'fqdn', or None (default).
        forward_next_hop_value (str): The next hop value if the forward
            next hop type is not None.
        forward_monitor_profile (str): The monitor profile to use.
        forward_monitor_ip_address (str): The monitor IP address.
        forward_monitor_disable_if_unreachable (bool): Set to disable
            this rule if nexthop / monitor IP is unreachable.
        enable_enforce_symmetric_return (bool): Set to enforce
            symmetric return.
        symmetric_return_addresses (str/list): List of symmetric return
            addresses.
        target (list): Apply this policy to the listed firewalls only
            (applies to panorama/device groups only)
        negate_target (bool): Target all but the listed target firewalls
            (applies to panorama/device groups only)
        uuid (str): (PAN-OS 9.0+) The UUID for this rule.

    """

    SUFFIX = ENTRY
    ROOT = Root.VSYS

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/pbf/rules")

        # params
        params = []

        params.append(VersionedParamPath("description", path="description"))
        params.append(VersionedParamPath("tags", vartype="member", path="tag"))
        params.append(
            VersionedParamPath(
                "from_type",
                default="zone",
                values=["zone", "interface"],
                path="from/{from_type}",
            )
        )
        params.append(
            VersionedParamPath("from_value", vartype="member", path="from/{from_type}")
        )
        params.append(
            VersionedParamPath("source_addresses", vartype="member", path="source")
        )
        params.append(
            VersionedParamPath("source_users", vartype="member", path="source-user")
        )
        params.append(
            VersionedParamPath("negate_source", vartype="yesno", path="negate-source")
        )
        params.append(
            VersionedParamPath(
                "destination_addresses", vartype="member", path="destination"
            )
        )
        params.append(
            VersionedParamPath(
                "negate_destination", vartype="yesno", path="negate-destination"
            )
        )
        params.append(
            VersionedParamPath("applications", vartype="member", path="application")
        )
        params.append(VersionedParamPath("services", vartype="member", path="service"))
        params.append(VersionedParamPath("schedule", path="schedule"))
        params.append(VersionedParamPath("disabled", vartype="yesno", path="disabled"))
        params.append(
            VersionedParamPath(
                "action",
                default="forward",
                values=["forward", "forward-to-vsys", "discard", "no-pbf"],
                path="action/{action}",
            )
        )
        params.append(
            VersionedParamPath(
                "forward_vsys",
                condition={"action": "forward-to-vsys"},
                path="action/{action}/forward-to-vsys",
            )
        )
        params.append(
            VersionedParamPath(
                "forward_egress_interface",
                condition={"action": "forward"},
                path="action/{action}/egress-interface",
            )
        )
        params.append(
            VersionedParamPath(
                "forward_next_hop_type",
                condition={"action": "forward"},
                values=["ip-address", "fqdn", None],
                path="action/{action}/nexthop/{forward_next_hop_type}",
            )
        )
        params.append(
            VersionedParamPath(
                "forward_next_hop_value",
                condition={
                    "action": "forward",
                    "forward_next_hop_type": ["ip-address", "fqdn"],
                },
                path="action/{action}/nexthop/{forward_next_hop_type}",
            )
        )
        params.append(
            VersionedParamPath(
                "forward_monitor_profile",
                condition={"action": "forward"},
                path="action/{action}/monitor/profile",
            )
        )
        params.append(
            VersionedParamPath(
                "forward_monitor_ip_address",
                condition={"action": "forward"},
                path="action/{action}/monitor/ip-address",
            )
        )
        params.append(
            VersionedParamPath(
                "forward_monitor_disable_if_unreachable",
                vartype="yesno",
                condition={"action": "forward"},
                path="action/{action}/monitor/disable-if-unreachable",
            )
        )
        params.append(
            VersionedParamPath(
                "enable_enforce_symmetric_return",
                vartype="yesno",
                path="enforce-symmetric-return/enabled",
            )
        )
        params.append(
            VersionedParamPath(
                "symmetric_return_addresses",
                vartype="entry",
                path="enforce-symmetric-return/nexthop-address-list",
            )
        )
        params.append(
            VersionedParamPath(
                "active_active_device_binding", path="active-active-device-binding"
            )
        )
        params.append(
            VersionedParamPath("target", vartype="entry", path="target/devices")
        )
        params.append(
            VersionedParamPath("negate_target", vartype="yesno", path="target/negate")
        )
        params.append(VersionedParamPath("uuid", exclude=True))
        params[-1].add_profile("9.0.0", vartype="attrib", path="uuid")

        self._params = tuple(params)
