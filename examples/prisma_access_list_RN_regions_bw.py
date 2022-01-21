#!/usr/bin/env python

# Copyright (c) 2022, Palo Alto Networks
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
# ACTION OF CONTRACT, NEGLIGENCE OR OTpHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# Author: Bastien Migette <bmigette@paloaltonetworks.com>

"""
prisma_access_list_RN_regions_bw.py
==========

This script is an example on how to retrieve list of prisma access 
remote networks locations and bandwidth allocation and print it.

"""
__author__ = "bmigette"


import logging
import os
import sys

# This is needed to import module from parent folder
curpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(curpath, os.pardir)]


from panos.base import PanDevice
from panos.panorama import Panorama
from panos.plugins import (
    AggBandwidth,
    CloudServicesPlugin,
    Region,
    RemoteNetwork,
    RemoteNetworks,
)

curpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(curpath, os.pardir)]


HOSTNAME = os.environ["PAN_HOSTNAME"]
USERNAME = os.environ["PAN_USERNAME"]
PASSWORD = os.environ["PAN_PASSWORD"]


def main():
    # Setting logging to debug the PanOS SDK
    logging_format = "%(levelname)s:%(name)s:%(message)s"
    # logging.basicConfig(format=logging_format, level=logging.DEBUG - 2) #Use this to be even more verbose
    logging.basicConfig(format=logging_format, level=logging.DEBUG)
    # First, let's create the panorama  object that we want to modify.
    pan = Panorama(HOSTNAME, USERNAME, PASSWORD)
    csp = pan.add(CloudServicesPlugin())

    csp.refresh()

    rn = csp.findall(RemoteNetworks)
    rnes = rn[0].findall(RemoteNetwork)
    agg_bw = rn[0].findall(AggBandwidth)

    regions = agg_bw[0].findall(Region)
    ### Print XML Dump of Prisma Config ###
    print(csp.element_str())
    print(csp.about())

    ### Print Remote networks name ###
    print(" -- Remote Networks --")
    for rne in rnes:
        print(
            f"{rne.name} - spn: {rne.spn_name}, region: {rne.region}, tunnel {rne.ipsec_tunnel}, subnets: {rne.subnets}"
        )
        print(
            f"{rne.name} - secondary_wan: {rne.secondary_wan_enabled}, secondary ipsec tunnel: {rne.secondary_ipsec_tunnel}"
        )

    ### Print Regions BW ###
    print(f"Agg BW Enabled: {agg_bw[0].enabled}")
    print(" -- Regions --")
    print(regions)
    for region in regions:
        print(
            f"Region:  {region}, allocated_bw: {region.allocated_bw}, spns: {region.spn_name_list}"
        )


if __name__ == "__main__":
    main()
