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

# import modules
from pandevice import getlogger
from pandevice.base import PanObject, Root, MEMBER, ENTRY
from pandevice.base import VarPath as Var
from pandevice.base import VersionedPanObject
from pandevice.base import VersionedParamPath

# import other parts of this pandevice package
import pandevice.errors as err

logger = getlogger(__name__)


class GlobalProtectGateway(VersionedPanObject):
    """GlobalProtectGateway for a Firewall

    """
    ROOT = Root.VSYS
    SUFFIX = ENTRY
    
    def _setup(self):
        self._xpath.add_profile(value='/global-protect-gateway')


class RemoteUserTunnelConfigs(VersionedPanObject):
    ROOT = Root.VSYS
    SUFFIX = ENTRY

    def _setup(self):
        self._xpath.add_profile(value='/remote-user-tunnel-configs')
        # params
        params = []
        
        params.append(VersionedParamPath(
            'split-tunneling', vartype='member', path='split-tunneling'))

        self._params = tuple(params)