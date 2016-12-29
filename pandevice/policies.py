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
from pandevice import getlogger
from base import PanObject, Root, MEMBER, ENTRY
from base import VarPath as Var
from pandevice.base import VersionedPanObject
from pandevice.base import VersionedParamPath

# import other parts of this pandevice package
import errors as err

logger = getlogger(__name__)


class Rulebase(VersionedPanObject):
    """Rulebase for a Firewall

    Firewall only.  For Panorama, use :class:`pandevice.policies.PreRulebase` or
    :class:`pandevice.policies.PostRulebase`.
    """
    ROOT = Root.VSYS
    CHILDTYPES = (
        "policies.SecurityRule",
    )

    def _setup(self):
        self._xpaths.add_profile(value='/rulebase')


class PreRulebase(Rulebase):
    """Pre-rulebase for a Panorama

    Panorama only.  For Firewall, use :class:`pandevice.policies.Rulebase`.
    """
    def _setup(self):
        self._xpaths.add_profile(value='/pre-rulebase')


class PostRulebase(Rulebase):
    """Post-rulebase for a Panorama

    Panorama only.  For Firewall, use :class:`pandevice.policies.Rulebase`.
    """
    def _setup(self):
        self._xpaths.add_profile(value='/post-rulebase')


class SecurityRule(VersionedPanObject):
    """Security Rule

    Firewall only.  Use SecurityPreRule or SecurityPostRule with Panorama.

    Args:
        name (str): Name of the rule
        fromzone (list): From zones
        tozone (list): To zones
        source (list): Source addresses
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
    """
    # TODO: Add QoS variables
    SUFFIX = ENTRY

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value='/security/rules')

        # params
        params = []

        any_defaults = (
            ('fromzone', 'from'), ('tozone', 'to'), ('source', 'source'),
            ('source_user', 'source-user'), ('hip_profiles', 'hip-profiles'),
            ('destination', 'destination'), ('application', 'application'),
        )
        for var_name, path in any_defaults:
            params.append(VersionedParamPath(
                var_name, default='any', vartype='member', path=path))

        params.append(VersionedParamPath(
            'service', default='application-default',
            vartype='member', path='service'))
        params.append(VersionedParamPath(
            'category', default='any', vartype='member', path='category'))
        params.append(VersionedParamPath(
            'action', path='action'))
        params.append(VersionedParamPath(
            'log_setting', path='log-setting'))
        params.append(VersionedParamPath(
            'log_start', path='log-start', vartype='yesno'))
        params.append(VersionedParamPath(
            'log_end', path='log-end', vartype='yesno'))
        params.append(VersionedParamPath(
            'description', path='description'))
        params.append(VersionedParamPath(
            'type', default='universal', path='rule-type'))
        params.append(VersionedParamPath(
            'tag', path='tag', vartype='member'))
        params.append(VersionedParamPath(
            'negate_source', path='negate-source', vartype='yesno'))
        params.append(VersionedParamPath(
            'negate_destination', path='negate-destination', vartype='yesno'))
        params.append(VersionedParamPath(
            'disabled', path='disabled', vartype='yesno'))
        params.append(VersionedParamPath(
            'schedule', path='schedule'))
        params.append(VersionedParamPath(
            'icmp_unreachable', path='icmp-unreachable'))
        params.append(VersionedParamPath(
            'disable_server_response_inspection', vartype='yesno',
            path='option/disable-server-response-inspection'))
        params.append(VersionedParamPath(
            'group', path='profile-setting/group', vartype='member'))

        member_profiles = (
            'virus', 'spyware', 'vulnerability', 'url-filtering',
            'file-blocking', 'wildfire-analysis', 'data-filtering',
        )
        for p in member_profiles:
            params.append(VersionedParamPath(
                p, vartype='member',
                path='profile-setting/profiles/{0}'.format(p)))

        self._params = tuple(params)
