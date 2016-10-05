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
upgrade.py
==========

This script upgrades a Palo Alto Networks firewall or Panorama to the
specified version. It takes care of all intermediate upgrades and reboots.

**Usage**::

    upgrade.py [-h] [-v] [-q] [-n] hostname username password version

**Examples**:

Upgrade a firewall at 10.0.0.1 to PAN-OS 7.0.0::

    $ python upgrade.py 10.0.0.1 admin password 7.0.0

Upgrade a Panorama at 172.16.4.4 to the latest Panorama version::

    $ python upgrade.py 172.16.4.4 admin password latest

"""

__author__ = 'btorres-gil'

import sys
import os
import argparse
import logging

curpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(curpath, os.pardir)]

from pandevice.base import PanDevice


def main():

    # Get command line arguments
    parser = argparse.ArgumentParser(description="Upgrade a Palo Alto Networks Firewall or Panorama to the specified version")
    parser.add_argument('-v', '--verbose', action='count', help="Verbose (-vv for extra verbose)")
    parser.add_argument('-q', '--quiet', action='store_true', help="No output")
    parser.add_argument('-n', '--dryrun', action='store_true', help="Print what would happen, but don't perform upgrades")
    # Palo Alto Networks related arguments
    fw_group = parser.add_argument_group('Palo Alto Networks Device')
    fw_group.add_argument('hostname', help="Hostname of Firewall or Panorama")
    fw_group.add_argument('username', help="Username for Firewall or Panorama")
    fw_group.add_argument('password', help="Password for Firewall or Panorama")
    fw_group.add_argument('version', help="The target PAN-OS/Panorama version (eg. 7.0.0 or latest)")
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
    # This is important to know what version to upgrade to next.
    device = PanDevice.create_from_device(args.hostname,
                                          args.username,
                                          args.password,
                                          )

    # Perform the upgrades in sequence with reboots between each upgrade
    device.software.upgrade_to_version(args.version, args.dryrun)


# Call the main() function to begin the program if not
# loaded as a module.
if __name__ == '__main__':
    main()
