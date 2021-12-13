

import argparse
import logging
import os
import sys

curpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(curpath, os.pardir)]

from panos.base import PanDevice
from panos.panorama import Panorama
from panos.prisma_access import CloudServicesPlugin, RemoteNetworkEntry, RemoteNetworks

HOSTNAME = os.environ["PAN_HOSTNAME"]
USERNAME = os.environ["PAN_USERNAME"]
PASSWORD = os.environ["PAN_PASSWORD"]


def main():
    logging_format = "%(levelname)s:%(name)s:%(message)s"

    logging.basicConfig(format=logging_format, level=logging.DEBUG)
    # First, let's create the panorama  object that we want to modify.
    pan = Panorama(HOSTNAME, USERNAME, PASSWORD)
    csp = pan.add(CloudServicesPlugin())

    csp.refresh()

    rn = RemoteNetworks.refreshall(csp)
    rnes = RemoteNetworkEntry.refreshall(rn[0])
    print(csp.element_str())
    print(csp.about())
    print(csp.all_traffic_to_dc)
    print(rn)
    print("Overlapped: " + str(rn[0].overlapped_subnets))
    print(rnes)
    for rne in rnes:
        print(rne.name)


if __name__ == "__main__":
    main()
