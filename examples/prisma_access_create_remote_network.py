#!/usr/bin/env python

# Copyright (c) 2021, Palo Alto Networks
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

# Author: Bastien Migette <bmigette@paloaltonetworks.com>

"""
prisma_access_create_remote_network.py
==========

This script is an example on how to create a prisma access Remote Network,
along with needed IPSEC Tunnel and IKEv2 Gateway.
To use the script, you need to replace the variables below with desired values.

"""
__author__ = "bmigette"


import logging
import os
import sys


# This is needed to import module from parent folder
curpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(curpath, os.pardir)]

from panos.panorama import Template
from panos.network import IkeGateway, IpsecTunnel
from panos.plugins import (
    CloudServicesPlugin,
    RemoteNetwork,
    RemoteNetworks,
    Bgp,
    AggBandwidth,
)
from panos.panorama import Panorama


HOSTNAME = os.environ["PAN_HOSTNAME"]
USERNAME = os.environ["PAN_USERNAME"]
PASSWORD = os.environ["PAN_PASSWORD"]

IPSEC_PEER = "1.2.3.4"
BGP_PEER = "1.2.3.4"
BGP_PEER_AS = 65123
IPSEC_TUNNEL_NAME = "panos-sdk-tunnel"
IKE_GW = "panos-sdk-ikev2-gw"
IKE_PSK = "Secret123"
IKE_CRYPTO = "Generic-IKE-Crypto-Default"
IPSEC_CRYPTO = "Generic-IPSEC-Crypto-Default"
TEMPLATE = "Remote_Network_Template"

REMOTE_NETWORK_NAME = "panos-sdk-rn"
# This is the Region that you put in the RN. A compute region can have multiple Regions
REMOTE_NETWORK_REGION = "eu-central-1"
# This is the Compute Region, used to get SPN list. You can use Panorama CLI to get available options
REMOTE_NETWORK_COMPUTEREGION = "europe-central"


def get_region_spn(remote_networks, region):
    """This function will return first SPN from a given region name.
    You should implement some logic here to get the correct SPN.
    The script will break if the region has no SPN / BW allocated

    Args:
        remote_networks (RemoteNetworks): RemoteNetworks Object
        region (str): The region to get SPN from

    Returns:
        str: spn name
    """
    agg_bw = remote_networks.findall(AggBandwidth)
    region_obj = agg_bw[0].find(region)
    print(f"SPN for region {region}: {region_obj.spn_name_list[0]}")
    return region_obj.spn_name_list[0]


def main():
    # Setting logging to debug the PanOS SDK
    logging_format = "%(levelname)s:%(name)s:%(message)s"
    # logging.basicConfig(format=logging_format, level=logging.DEBUG - 2) #Use this to be even more verbose
    logging.basicConfig(format=logging_format, level=logging.DEBUG)
    # 1 - let's create the panorama  object that we want to modify.
    pan = Panorama(HOSTNAME, USERNAME, PASSWORD)

    # 2 - Refreshing Prisma Access config
    csp = pan.add(CloudServicesPlugin())
    csp.refresh()

    rn_template = pan.add(Template(name=TEMPLATE))
    rn_template.refresh()
    # 3 - Getting the remote_networks object
    remote_networks = csp.findall(RemoteNetworks)[0]

    # 4 - Creating IKEv2 GW and IPSEC Tunnels
    # 4.1 - IKEv2 GW
    gw = IkeGateway()
    gw.name = IKE_GW
    gw.version = "ikev2"
    gw.peer_ip_type = "ip"
    gw.peer_ip_value = IPSEC_PEER
    gw.peer_id_type = "ipaddr"
    gw.peer_id_value = IPSEC_PEER
    gw.auth_type = "pre-shared-key"
    gw.pre_shared_key = IKE_PSK
    gw.ikev2_crypto_profile = IKE_CRYPTO
    gw.enable_liveness_check = True
    rn_template.add(gw).create()

    # 4.2 - IPSEC Tunnel
    ipsec_tun = IpsecTunnel()
    ipsec_tun.name = IPSEC_TUNNEL_NAME
    ipsec_tun.ak_ike_gateway = IKE_GW
    ipsec_tun.ak_ipsec_crypto_profile = IPSEC_CRYPTO
    ipsec_tun.mk_remote_address = IPSEC_PEER
    rn_template.add(ipsec_tun).create()

    # 5 - Creating Remote Network
    rn = RemoteNetwork()
    rn.name = REMOTE_NETWORK_NAME
    rn.subnets = ["10.11.12.0/24"]
    rn.region = REMOTE_NETWORK_REGION
    rn.spn_name = get_region_spn(remote_networks, REMOTE_NETWORK_COMPUTEREGION)
    rn.ipsec_tunnel = IPSEC_TUNNEL_NAME
    bgp = Bgp()
    bgp.enable = True
    bgp.peer_as = BGP_PEER_AS
    bgp.peer_ip_address = BGP_PEER

    rn.add(bgp)
    remote_networks.add(rn).create()
    # 6 - Commit + Push
    # pan.commit_all(devicegroup="Remote_Network_Device_Group") #commit + push
    pan.commit()  # commit only


if __name__ == "__main__":
    main()
