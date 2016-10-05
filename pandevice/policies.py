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

"""Policies module contains policies and rules that exist in the 'Policies' tab in the firewall GUI"""

# import modules
import logging
from base import PanObject, Root, MEMBER, ENTRY
from base import VarPath as Var

# import other parts of this pandevice package
import errors as err

# set logging to nullhandler to prevent exceptions if logging not enabled
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class Rulebase(PanObject):
    """Rulebase for a Firewall

    Firewall only.  For Panorama, use :class:`pandevice.policies.PreRulebase` or
    :class:`pandevice.policies.PostRulebase`.

    """
    ROOT = Root.VSYS
    XPATH = "/rulebase"
    CHILDTYPES = (
        "policies.SecurityRule",
    )


class PreRulebase(Rulebase):
    """Pre-rulebase for a Panorama

    Panorama only.  For Firewall, use :class:`pandevice.policies.Rulebase`.

    """
    XPATH = "/pre-rulebase"


class PostRulebase(Rulebase):
    """Pre-rulebase for a Panorama

    Panorama only.  For Firewall, use :class:`pandevice.policies.Rulebase`.

    """
    XPATH = "/post-rulebase"


class SecurityRule(PanObject):
    """Security Rule

    Firewall only.  Use SecurityPreRule or SecurityPostRule with Panorama.

    Args:
        name (str): Name of the rule
        fromzone (list): From zones
        tozone (list): To zones
        source (list): Source addresses
        destination (list): Destination addresses
        application (list): Applications
        service (list): Destination services (ports) (Default: application-default)
        category (list): Destination URL Categories
        action (str): Action to take (deny, allow, drop, reset-client, reset-server, reset-both)
            Note: Not all options are available on all PAN-OS versions.
        log_setting (str): Log forwarding profile
        log_start (bool): Log at session start
        log_end (bool): Log at session end
        description (str): Description of this rule
        type (str): 'universal', 'intrazone', or 'intrazone' (Default: universal)
        tag (list): Administrative tags
        negate_source (bool): Match on the reverse of the 'source' attribute
        negate_destination (bool): Match on the reverse of the 'destination' attribute
        disabled (bool): Disable this rule
        schedule (str): Schedule Profile
        icmp_unreachable (bool): Send ICMP Unreachable
        disable_server_response_inspection (bool): Disable server response inspection
        group (str): Security Profile Group
        virus (str): Antivirus Security Profile
        spyware (str): Anti-Spyware Security Profile
        vulnerability (str): Vulnerability Protection Security Profile
        url_filtering (str): URL Filtering Security Profile
        file_blocking (str): File Blocking Security Profile
        wildfire_analysis (str): Wildfire Analysis Security Profile
        data_filtering (str): Data Filtering Security Profile

    """
    # TODO: Add QoS variables
    XPATH = "/security/rules"
    SUFFIX = ENTRY

    @classmethod
    def variables(cls):
        return (
            Var("from", "fromzone", vartype="member", default=("any",)),
            Var("to", "tozone", vartype="member", default=("any",)),
            Var("source", vartype="member", default=("any",)),
            Var("source-user", vartype="member", default=("any",)),
            Var("hip-profiles", vartype="member", default=("any",)),
            Var("destination", vartype="member", default=("any",)),
            Var("application", vartype="member", default=("any",)),
            Var("service", vartype="member", default=("application-default",)),
            Var("category", vartype="member", default=("any",)),
            Var("action"),
            Var("log-setting"),
            Var("log-start", vartype="bool"),
            Var("log-end", vartype="bool"),
            Var("description"),
            Var("rule-type", "type", default="universal"),
            Var("tag", vartype="member"),
            Var("negate-source", vartype="bool"),
            Var("negate-destination", vartype="bool"),
            Var("disabled", vartype="bool"),
            Var("schedule"),
            Var("icmp-unreachable"),
            Var("option/disable-server-response-inspection", vartype="bool"),
            Var("profile-setting/group", vartype="member"),
            Var("profile-setting/profiles/virus", vartype="member"),
            Var("profile-setting/profiles/spyware", vartype="member"),
            Var("profile-setting/profiles/vulnerability", vartype="member"),
            Var("profile-setting/profiles/url-filtering", vartype="member"),
            Var("profile-setting/profiles/file-blocking", vartype="member"),
            Var("profile-setting/profiles/wildfire-analysis", vartype="member"),
            Var("profile-setting/profiles/data-filtering", vartype="member"),

        )
