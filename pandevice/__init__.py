# -*- coding: utf-8 -*-

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


"""pandevice library is a framework for interacting with Palo Alto Networks devices

Documentation available at http://pandevice.readthedocs.io

"""

__author__ = 'Brian Torres-Gil'
__email__ = 'btorres-gil@paloaltonetworks.com'
__version__ = '0.3.5'


import logging
from distutils.version import LooseVersion  # Used by PanOSVersion class

try:
    import pan
except ImportError as e:
    message = e.message + ", please install the pan-python library (pip install pan-python)"
    raise ImportError(message)

# python 2.6 doesn't have a null handler, so create it
if not hasattr(logging, 'NullHandler'):
    class NullHandler(logging.Handler):
        def emit(self, record):
            pass
    logging.NullHandler = NullHandler


def getlogger(name=__name__):
    import types
    logger_instance = logging.getLogger(name)
    # Add nullhandler to prevent exceptions in python 2.6
    logger_instance.addHandler(logging.NullHandler())
    # Add convenience methods for logging
    logger_instance.debug1 = types.MethodType(
        lambda inst, msg, *args, **kwargs: inst.log(DEBUG1, msg, *args, **kwargs), logger_instance)
    logger_instance.debug2 = types.MethodType(
        lambda inst, msg, *args, **kwargs: inst.log(DEBUG2, msg, *args, **kwargs), logger_instance)
    logger_instance.debug3 = types.MethodType(
        lambda inst, msg, *args, **kwargs: inst.log(DEBUG3, msg, *args, **kwargs), logger_instance)
    logger_instance.debug4 = types.MethodType(
        lambda inst, msg, *args, **kwargs: inst.log(DEBUG4, msg, *args, **kwargs), logger_instance)
    return logger_instance


logger = getlogger(__name__)


# Enumerator type
def enum(*sequential, **named):
    enums = dict(zip(sequential, range(len(sequential))), **named)
    reverse = dict((value, key) for key, value in enums.iteritems())
    enums['reverse_mapping'] = reverse
    return type('Enum', (), enums)

# Create more debug logging levels
DEBUG1 = logging.DEBUG -1
DEBUG2 = DEBUG1 - 1
DEBUG3 = DEBUG2 - 1
DEBUG4 = DEBUG3 - 1

logging.addLevelName(DEBUG1, 'DEBUG1')
logging.addLevelName(DEBUG2, 'DEBUG2')
logging.addLevelName(DEBUG3, 'DEBUG3')
logging.addLevelName(DEBUG4, 'DEBUG4')

# Adjust pan-python logging levels so they don't interfere with pandevice logging
pan.DEBUG1 = logging.DEBUG - 2  # equavalent to DEBUG2
pan.DEBUG2 = pan.DEBUG1 - 1
pan.DEBUG3 = pan.DEBUG2 - 1


class PanOSVersion(LooseVersion):
    """LooseVersion with convenience properties to access version components"""
    @property
    def major(self):
        return self.version[0]

    @property
    def minor(self):
        return self.version[1]

    @property
    def patch(self):
        try:
            patch = self.version[2]
        except IndexError:
            patch = 0
        return patch

    @property
    def mainrelease(self):
        return self.version[0:3]

    @property
    def subrelease(self):
        try:
            subrelease = str(self.version[4]) + str(self.version[5])
        except IndexError:
            subrelease = None
        return subrelease

    @property
    def subrelease_type(self):
        try:
            subrelease_type = self.version[4]
        except IndexError:
            subrelease_type = None
        return subrelease_type

    @property
    def subrelease_num(self):
        try:
            subrelease_num = self.version[5]
        except IndexError:
            subrelease_num = None
        return subrelease_num

    def __repr__ (self):
        return "PanOSVersion ('%s')" % str(self)

    def __cmp__ (self, other):
        if isinstance(other, basestring):
            other = PanOSVersion(other)

        # Compare subreleases if number part of version is the same
        if cmp(self.mainrelease, other.mainrelease) == 0:
            if self.subrelease_type == 'c' and other.subrelease_type != 'c':
                return -1
            elif self.subrelease_type == 'b' and other.subrelease is None:
                return -1
            elif self.subrelease_type != 'c' and other.subrelease_type == 'c':
                return 1
            elif self.subrelease is None and other.subrelease_type == 'b':
                return 1

        return cmp(self.version, other.version)


# Convenience methods used internally by module
# Do not use these methods outside the module


def string_or_list(value):
    """Return a list containing value

    This method allows flexibility in class __init__ arguments,
    allowing you to pass a string, object, list, or tuple.
    In all cases, a list will be returned.

    Args:
        value: a string, object, list, or tuple

    Returns:
        list

    Examples:
        "string" -> [string]
        ("t1", "t2") -> ["t1", "t2"]
        ["l1", "l2"] -> ["l1", "l2"]
        None -> None

    """
    if value is None:
        return None
    else:
        return list(value) if "__iter__" in dir(value) else [value]


def string_or_list_or_none(value):
    """Return a list containing value

    This method allows flexibility in class __init__ arguments,
    allowing you to pass a string, object, list, tuple, or None.
    In all cases, a list will be returned.

    Args:
        value: a string, object, list, tuple, or None

    Returns:
        list

    Examples:
        "string" -> [string]
        ("t1", "t2") -> ["t1", "t2"]
        ["l1", "l2"] -> ["l1", "l2"]
        None -> []

    """
    if value is None:
        return []
    else:
        return string_or_list(value)


def convert_if_int(string):
    """Convert a string to an int, only if it is an int

    Args:
        string (str): The string to convert if it's an integer

    Returns:
        int or str of the original value, dependin if it could be converted to an int

    """
    try:
        integer = int(string)
        return integer
    except ValueError:
        return string


def xml_combine(root, elements):
    """Combine two xml elements and their subelements

    This method will modify the 'root' argument and does
    not return anything.

    Args:
        root (Element): The Element that will contain the merger
        elements (Element or list): If an Element, merge all subelements of this element into root.
            If a list, merge all Elements in the list into root.

    """
    # If one of the args is None, return the other as-is
    if root is None:
        return elements
    elif elements is None:
        return root
    for element in elements:
        found_element = root.find(element.tag)
        if found_element is None:
            root.append(element)
            continue
        xml_combine(found_element, element)


def yesno(value):
    """Convert 'yes' or 'no' to True or False

    Args:
        value (str): The string containing 'yes' or 'no'

    Returns:
        bool: True if value is 'yes', False if value is 'no'

    """
    if value is None:
        return
    convert = {
        "yes": True,
        "no": False,
        True: "yes",
        False: "no",
    }
    return convert[value]
