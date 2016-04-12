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

"""Generate class diagram from module and class source code"""

import os
import sys
import pkgutil
import inspect
import errno


header = """digraph configtree {
    graph [rankdir=LR, fontsize=10, margin=0.001];
    node [shape=box, fontsize=10, height=0.001, margin=0.1, ordering=out];"""


footer = "}\n"


nodestyle = {
    #'Firewall':  '',
    #'Panorama':  '',
    'device':    'fillcolor=lightpink',
    'firewall':  'fillcolor=lightblue',
    'ha':        'fillcolor=lavender',
    'network':   'fillcolor=lightcyan',
    'objects':   'fillcolor=lemonchiffon',
    'policies':  'fillcolor=lightsalmon',
    'panorama':  'fillcolor=lightgreen',
}


def mkdir_p(path):
    """Make a full directory path"""
    try:
        os.makedirs(path)
    except OSError as exc:  # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise


def node_style(cls):
    cls = str(cls)
    style = ""
    if "." in cls:
        module = cls.split(".")[0]
        cls_name = cls.split(".")[-1]
        try:
            style = "style=filled " + nodestyle[cls_name] + " "
        except KeyError:
            try:
                style = "style=filled " + nodestyle[module] + " "
            except:
                pass
        result = "    {0} [{1}URL=\"../module-{2}.html#pandevice.{3}\" target=\"_top\"];\n".format(
            cls_name, style, module, cls
        )
    else:
        if style:
            result = "    {0} [{1}]\n".format(style)
        else:
            result = ""
    return result


def legend(modules):
    result = []
    result.append("graph configtree {\n")
    result.append("    graph [fontsize=10, margin=0.001];\n")
    result.append("    node [shape=box, fontsize=10, height=0.001, margin=0.1, ordering=out];\n")
    for module in modules:
        module_name = module.__name__.split(".")[-1]
        try:
            result.append("    {0} [style=filled {1}]\n".format(module_name, nodestyle[module_name]))
        except KeyError:
            pass
    result.append("    PanDevice [style=filled]\n")
    result.append("}\n")
    return result


def create_object_diagram(directory=None):
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


    output = {}

    output["legend"] = legend(modules)

    # Gather a list of all classes in all modules
    for module in modules:
        module_name = module.__name__
        output[module_name] = []
        classes_seen = []
        for class_name, cls in inspect.getmembers(module, inspect.isclass):
            if hasattr(cls, "CHILDTYPES") and getattr(cls, "CHILDTYPES"):
                full_class_name = "{0}.{1}".format(module_name.split(".")[-1], class_name)
                if full_class_name not in classes_seen:
                    classes_seen.append(full_class_name)
                    output[module_name].append(node_style(full_class_name))
                children = list(getattr(cls, "CHILDTYPES"))
                children.sort()
                for child in children:
                    child_module = child.split(".")[0]
                    child_name = child.split(".")[-1]
                    #if child_name == "IPv6Address":
                        #continue
                    if child not in classes_seen:
                        classes_seen.append(child)
                        output[module_name].append(node_style(child))
                    output[module_name].append("    {0} -> {1};\n".format(class_name, child_name))

    # Write output to file or stdout
    path = ""
    if directory is not None:
        mkdir_p(directory)
        path = directory + "/"
    for module, lines in output.iteritems():
        if not lines:
            continue
        moduleout = "".join(lines)
        if module == "legend":
            fulloutput = moduleout
        else:
            fulloutput = header + moduleout + footer
        with open("{0}{1}.dot".format(path, module), 'w') as file:
            file.write(fulloutput)


if __name__ == "__main__":
    create_object_diagram()
