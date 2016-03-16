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
userid.py
=========

Update User-ID by adding or removing a user-to-ip mapping on the firewall

**Usage**::

    userid.py [-h] [-v] [-q] hostname username password action user ip

**Examples**:

Send a User-ID login event to a firewall at 10.0.0.1::

    $ python userid.py 10.0.0.1 admin password login exampledomain/user1 4.4.4.4

Send a User-ID logout event to a firewall at 172.16.4.4::

    $ python userid.py 172.16.4.4 admin password logout user2 5.1.2.2

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
    parser = argparse.ArgumentParser(description="Update User-ID by adding or removing a user-to-ip mapping")
    parser.add_argument('-v', '--verbose', action='count', help="Verbose (-vv for extra verbose)")
    parser.add_argument('-q', '--quiet', action='store_true', help="No output")
    # Palo Alto Networks related arguments
    fw_group = parser.add_argument_group('Palo Alto Networks Device')
    fw_group.add_argument('hostname', help="Hostname of Firewall")
    fw_group.add_argument('username', help="Username for Firewall")
    fw_group.add_argument('password', help="Password for Firewall")
    fw_group.add_argument('action', help="The action of the user. Must be 'login' or 'logout'.")
    fw_group.add_argument('user', help="The username of the user")
    fw_group.add_argument('ip', help="The IP address of the user")
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

    logging.debug("Detecting type of device")

    # Panorama does not have a userid API, so exit.
    # You can use the userid API on a firewall with the Panorama 'target'
    # parameter by creating a Panorama object first, then create a
    # Firewall object with the 'panorama' and 'serial' variables populated.
    if issubclass(type(device), Panorama):
        logging.error("Connected to a Panorama, but user-id API is not possible on Panorama.  Exiting.")
        sys.exit(1)

    if args.action == "login":
        logging.debug("Login user %s at IP %s" % (args.user, args.ip))
        device.userid.login(args.user, args.ip)
    elif args.action == "logout":
        logging.debug("Logout user %s at IP %s" % (args.user, args.ip))
        device.userid.logout(args.user, args.ip)
    else:
        raise StandardError("Unknown action: %s.  Must be 'login' or 'logout'." % args.action)

    logging.debug("Done")


# Call the main() function to begin the program if not
# loaded as a module.
if __name__ == '__main__':
    main()
