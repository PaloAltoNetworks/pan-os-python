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
prisma_access_show_remote_net_per_tenant.py
==========

This script is an example on how to retrieve list of prisma access 
tenants and their remote networks

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
from panos.plugins import CloudServicesPlugin, RemoteNetwork, RemoteNetworks, Tenants

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

    # This is to load candidate config instead of running config
    csp.refresh(running_config=False)

    if not csp.multi_tenant_enable:
        logging.error("Multi Tenant not enabled")
        sys.exit(-1)
    tenants = csp.findall(Tenants)

    ### Print Tenants ###
    for tenant in tenants:
        logging.info("====== Tenant: %s ======", tenant.name)
        remote_networks = tenant.findall(RemoteNetworks)[0].findall(RemoteNetwork)
        for remote_network in remote_networks:
            logging.info(
                "name: %s, region: %s, IPSEC Node: %s, spn name: %s",
                remote_network.name,
                remote_network.region,
                remote_network.ipsec_tunnel,
                remote_network.spn_name,
            )


if __name__ == "__main__":
    main()
