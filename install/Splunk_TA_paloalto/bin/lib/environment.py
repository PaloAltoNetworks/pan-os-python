#!/usr/bin/env python

# Copyright (c) 2015, Palo Alto Networks
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

"""Functions to help set up the command environment (logging, etc)"""

import os
import sys


SPLUNK_HOME = os.environ.get('SPLUNK_HOME')
SPLUNK_SERVER_NAME = os.environ.get('SPLUNK_SERVER_NAME')


def run_by_splunk():
    """Check if this script was run by Splunk, or on the CLI

    Returns: True if the script was run by Splunk, otherwise False
    """
    if SPLUNK_SERVER_NAME is None:
        return False
    else:
        return True


def init_logging(level=20):  # level 20 is logging.INFO
    if run_by_splunk():
        import splunk.mining.dcutils as dcu
        logger = dcu.getLogger()
    else:
        import logging
        logger = logging.getLogger()
        logger.setLevel(level)
        ch = logging.StreamHandler(sys.stdout)
        logger.addHandler(ch)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        ch.setFormatter(formatter)
    return logger


def init_splunk_environment(splunk_home):
    """Configure paths and env vars to support Splunk imports, even if script was run from CLI

    Only run this if you have already determined the SPLUNK_HOME and passed it as a parameter to this method.
    This method is not necessary if the script was run by Splunk.

    """
    if run_by_splunk():
        return
    # Set python path to include Splunk python libraries
    sys.path[:0] = [os.path.join(splunk_home, 'lib', 'python2.7', 'site-packages')]
    # Set SPLUNK_DB env variable which is used by some Splunk python libraries
    if os.environ.get('SPLUNK_DB') is None:
        os.environ['SPLUNK_DB'] = os.path.join(splunk_home, 'var', 'lib', 'splunk')
    # Set LD_LIBRARY_PATH to include Splunk libs (might not work on Windows)
    #os.environ['LD_LIBRARY_PATH'] = os.path.join(splunk_home, 'lib') + ':' + os.getenv('LD_LIBRARY_PATH', '')
    ld_path = os.path.join(splunk_home, 'lib')
    # This doesn't work because ctypes is not in the Splunk python libraries
    #ctypes.cdll.LoadLibrary(os.path.join(splunk_home, 'lib', 'libxslt.so.1'))

    # We need to set the LD_LIBRARY_PATH to $SPLUNK_HOME/lib,
    # but the LD_LIBRARY_PATH is only read at program start,
    # so set the LD_LIBRARY_PATH and restart this program.
    if not os.environ.get('LD_LIBRARY_PATH'):
        os.environ['LD_LIBRARY_PATH'] = ld_path
    elif not ld_path in os.environ.get('LD_LIBRARY_PATH'):
        os.environ['LD_LIBRARY_PATH'] += ":" + ld_path
    else:
        return  # everything is fine, so don't re-run the program

    # Re-run this program with the new environment variables for Splunk
    # using Splunk's python executable
    python_path = os.path.join(SPLUNK_HOME, 'bin', 'python')
    sys.argv[:0] = [python_path]
    os.execve(python_path, sys.argv, os.environ)