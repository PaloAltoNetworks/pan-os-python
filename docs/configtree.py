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

"""Generate configtree.dot class diagram from module and class source code"""

import os
import sys
import pkgutil
import inspect


# Set paths to package and modules
curdir = os.path.dirname(os.path.abspath(__file__))
rootpath = [os.path.join(curdir, os.pardir)]
libpath = [os.path.join(curdir, os.pardir, 'pandevice')]
sys.path[:0] = rootpath
sys.path[:0] = libpath
#print "Looking for pandevice in path: %s" % libpath

# Import all modules in package
modules = []
for importer, modname, ispkg in pkgutil.iter_modules(path=libpath,
                                                     prefix="pandevice."):
    modules.append(__import__(modname, fromlist="dummy"))

# Begin printing the diagram
print """digraph configtree {
    graph [rankdir=LR, fontsize=10, margin=0.001];
    node [shape=box, fontsize=10, height=0.001, margin=0.1, ordering=out];"""

# Gather a list of all classes in all modules
classes_seen = []
for module in modules:
    for class_name, cls in inspect.getmembers(module, inspect.isclass):
        if hasattr(cls, "CHILDTYPES") and getattr(cls, "CHILDTYPES"):
            children = list(getattr(cls, "CHILDTYPES"))
            children.sort()
            for child in children:
                module = child.split(".")[0]
                child_name = child.split(".")[-1]
                if child not in classes_seen:
                    classes_seen.append(child)
                    print "    %s [URL=\"../module-%s.html#pandevice.%s\" target=\"_top\"];" % (child_name, module, child)
                print "    %s -> %s;" % (class_name, child_name)

# End printing the diagram
print "    Panorama [style=filled, URL=\"../module-panorama.html#pandevice.panorama.Panorama\" target=\"_top\"];"
print "    Firewall [style=filled];"
print "}"
