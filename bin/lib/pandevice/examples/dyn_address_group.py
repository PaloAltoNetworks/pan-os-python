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

"""
dyn_address_group.py
====================

Tag/untag ip addresses for Dynamic Address Groups on a firewall

**Usage**::

    dyn_address_group.py [-h] [-v] [-q] [-u] [-c] hostname username password ip tags

**Examples**:

Tag the IP 3.3.3.3 with the tag 'linux' and 'apache'::

    $ python dyn_address_group.py 10.0.0.1 admin password 3.3.3.3 linux,apache

Remove the tag apache from the IP 3.3.3.3::

    $ python dyn_address_group.py -u 10.0.0.1 admin password 3.3.3.3 linux

Clear all tags from all IP's::

    $ python dyn_address_group.py -c 10.0.0.1 admin password notused notused

"""

__author__ = 'btorres-gil'

import sys
import os
import argparse
import logging

curpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(curpath, os.pardir)]

from pandevice.base import PanDevice
from pandevice.panorama import Panorama


def main():

    # Get command line arguments
    parser = argparse.ArgumentParser(description="Tag an IP address on a Palo Alto Networks Next generation Firewall")
    parser.add_argument('-v', '--verbose', action='count', help="Verbose (-vv for extra verbose)")
    parser.add_argument('-q', '--quiet', action='store_true', help="No output")
    parser.add_argument('-u', '--unregister', action='store_true', help="Remove the tags (default is register)")
    parser.add_argument('-c', '--clear', action='store_true', help="Clear all tags. ip and tags arguments are ignored")
    # Palo Alto Networks related arguments
    fw_group = parser.add_argument_group('Palo Alto Networks Device')
    fw_group.add_argument('hostname', help="Hostname of Firewall")
    fw_group.add_argument('username', help="Username for Firewall")
    fw_group.add_argument('password', help="Password for Firewall")
    fw_group.add_argument('ip', help="The IP address that should be tagged")
    fw_group.add_argument('tags', help="Comma delimited tags.  eg. linux,apache,server")
    args = parser.parse_args()

    ### Set up logger
    # Logging Levels
    # WARNING is 30
    # INFO is 20
    # DEBUG is 10
    if args.verbose is None:
        args.verbose = 0
    if not args.quiet:
        logging_level = 20 - (args.verbose * 10)
        if logging_level <= logging.DEBUG:
            logging_format = '%(levelname)s:%(name)s:%(message)s'
        else:
            logging_format = '%(message)s'
        logging.basicConfig(format=logging_format, level=logging_level)

    # Connect to the device and determine its type (Firewall or Panorama).
    device = PanDevice.create_from_device(args.hostname,
                                          args.username,
                                          args.password,
                                          )

    # Panorama does not have a userid API, so exit.
    # You can use the userid API on a firewall with the Panorama 'target'
    # parameter by creating a Panorama object first, then create a
    # Firewall object with the 'panorama' and 'serial' variables populated.
    if issubclass(type(device), Panorama):
        logging.error("Connected to a Panorama, but user-id API is not possible on Panorama.  Exiting.")
        sys.exit(1)

    if args.clear:
        device.userid.clear_all_registered_ip()
        sys.exit(0)

    if args.unregister:
        device.userid.unregister(args.ip, args.tags.split(','))
    else:
        device.userid.register(args.ip, args.tags.split(','))


# Call the main() function to begin the program if not
# loaded as a module.
if __name__ == '__main__':
    main()