#!/usr/bin/env python

# Copyright (c) 2016, Palo Alto Networks
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

"""Generate API reference page for each module"""

import os
import sys
import pkgutil
import errno


tree_exists = [
    "device",
    "firewall",
    "ha",
    "network",
    "panorama",
    "policies",
]

tree_not_exists = [
    "base",
    "errors",
    "objects",
    "updater",
    "userid",
]


template_main = """Module: {0}
========{1}

Inheritance diagram
-------------------

.. inheritance-diagram:: pandevice.{0}
   :parts: 1{2}

Class Reference
---------------

.. automodule:: pandevice.{0}
"""


template_tree = """

Configuration tree diagram
--------------------------

.. graphviz:: _diagrams/pandevice.{0}.dot """


def mkdir_p(path):
    """Make a full directory path"""
    try:
        os.makedirs(path)
    except OSError as exc:  # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise


def create_module_references(directory=None):
    # Set paths to package and modules
    curdir = os.path.dirname(os.path.abspath(__file__))
    rootpath = [os.path.join(curdir, os.pardir)]
    libpath = [os.path.join(curdir, os.pardir, "pandevice")]
    sys.path[:0] = rootpath
    sys.path[:0] = libpath
    # print "Looking for pandevice in path: %s" % libpath

    # Import all modules in package
    modules = []
    for importer, modname, ispkg in pkgutil.iter_modules(
        path=libpath, prefix="pandevice."
    ):
        modules.append(__import__(modname, fromlist="dummy"))

    output = {}

    # Create output for each module
    for module in modules:
        module_name = module.__name__.split(".")[-1]
        header_pad = "=" * len(module_name)
        if module_name in tree_exists:
            config_tree = template_tree.format(module_name)
        else:
            config_tree = ""
        module_string = template_main.format(module_name, header_pad, config_tree)
        output[module_name] = module_string

    # Write output to file or stdout
    path = ""
    if directory is not None:
        mkdir_p(directory)
        path = directory + "/"
    for module, lines in output.iteritems():
        if module == "interface":
            continue
        if not lines:
            continue
        with open("{0}module-{1}.rst".format(path, module), "w") as file:
            file.write(lines)


if __name__ == "__main__":
    create_module_references()
