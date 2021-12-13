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


"""Prisma Access module contains objects that exist in the 'Plugins/Cloud Services' tab in the Panorama GUI"""

import logging
import re
import xml.etree.ElementTree as ET

import panos
import panos.errors as err
from panos import device, getlogger, string_or_list
from panos.base import ENTRY, MEMBER, PanObject, Root
from panos.base import VarPath as Var
from panos.base import VersionedPanObject, VersionedParamPath, VsysOperations


class CloudServicesPlugin(VersionedPanObject):
    """Prisma Access configuration base object

    Args:
        name: (unused, and may be omitted)

    """

    ROOT = Root.DEVICE
    SUFFIX = None
    CHILDTYPES = (
        "prisma_access.RemoteNetworks",
    )

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(value="/plugins/cloud_services")

        # params
        params = []

        params.append(
            VersionedParamPath("all_traffic_to_dc", default=False,
                               vartype="yesno", path="traffic-steering/All-Traffic-To-DC", version="9.1.0")
        )

        self._params = tuple(params)


class RemoteNetworks(VersionedPanObject):
    """Prisma Access Remote-Networks configuration base object

    Args:
        name: (unused, and may be omitted)

    """
    NAME = "remote_networks"
    ROOT = Root.DEVICE
    SUFFIX = None
    CHILDTYPES = (
        "prisma_access.RemoteNetworkEntry",
    )

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(
            value="/remote-networks")

        # params
        params = []

        params.append(
            VersionedParamPath("overlapped_subnets", default=False,
                               vartype="yesno", path="overlapped-subnets", version="9.1.0")
        )

        self._params = tuple(params)


class RemoteNetworkEntry(VersionedPanObject):
    """Prisma Access Remote-Networks Onboarding configuration base object

    Args:
        name: (unused, and may be omitted)

    """
    ROOT = Root.DEVICE
    SUFFIX = ENTRY
    CHILDTYPES = (

    )

    def _setup(self):
        # xpaths
        self._xpaths.add_profile(
            value="/onboarding")

        # params
        params = []

        params.append(
            VersionedParamPath("overlapped_subnets", default=False,
                               vartype="yesno", path="overlapped-subnets", version="9.1.0")
        )

        self._params = tuple(params)
