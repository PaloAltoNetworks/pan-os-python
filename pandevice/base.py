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


"""Base object classes for inheritence by other classes"""

import base64
import collections
import copy
import datetime
import hashlib
import inspect
import itertools
import re
import sys
import time
import xml.dom.minidom as minidom
import xml.etree.ElementTree as ET

import pan.commit
import pan.xapi
from pan.config import PanConfig

import pandevice
import pandevice.errors as err
from pandevice import isstring, string_or_list, updater, userid, yesno

logger = pandevice.getlogger(__name__)

Root = pandevice.enum("DEVICE", "VSYS", "MGTCONFIG")
SELF = "/%s"
ENTRY = "/entry[@name='%s']"
MEMBER = "/member[text()='%s']"


# PanObject type
class PanObject(object):
    """Base class for all package objects

    This class defines an object that can be placed in a tree to generate configuration.

    Args:
        name (str): The name of this object

    Attributes:
        uid (str): The unique identifier for this object if it has one.  If it
            doesn't have one, then this returns the class name.
        vsys (str): The vsys id for this object (eg. 'vsys2') or 'shared' if no vsys

    """

    XPATH = ""
    SUFFIX = None
    ROOT = Root.DEVICE
    NAME = "name"
    CHILDTYPES = ()
    CHILDMETHODS = ()
    HA_SYNC = True
    TEMPLATE_NATIVE = False

    def __init__(self, *args, **kwargs):
        # Set the 'name' variable
        idx_start = 0
        if self.NAME is not None:
            try:
                name = args[0]
                idx_start = 1
            except IndexError:
                name = kwargs.pop(self.NAME, None)
            setattr(self, self.NAME, name)
        # Initialize other common variables
        self.parent = None
        self.children = []
        # Gather all the variables from the 'variables' class method
        # from the args/kwargs into instance variables.
        variables = kwargs.pop("variables", None)
        if variables is None:
            variables = type(self).variables()
        # Sort the variables by order
        variables = sorted(variables, key=lambda x: x.order)
        for idx, var in enumerate(variables, idx_start):
            varname = var.variable
            try:
                # Try to get the variables from 'args' first
                varvalue = args[idx]
            except IndexError:
                # If it's not in args, get it from 'kwargs', or store a None in the variable
                try:
                    varvalue = kwargs.pop(varname)
                except KeyError:
                    # If None was stored in the variable, check if
                    # there's a default value, and store that instead
                    if var.default is not None:
                        setattr(self, varname, var.default)
                    else:
                        setattr(self, varname, None)
                    continue
            # For member variables, store a list containing the value instead of the individual value
            if var.vartype in ("member", "entry"):
                varvalue = pandevice.string_or_list(varvalue)
            # Store the value in the instance variable
            setattr(self, varname, varvalue)

    def __str__(self):
        return self.uid

    def __repr__(self):
        return "<{0}{1} {2:#x}>".format(
            type(self).__name__, " {0}".format(self.uid) if self.uid else "", id(self)
        )

    @classmethod
    def variables(cls):
        """Defines the variables that exist in this object. Override in each subclass."""
        return ()

    @property
    def vsys(self):
        """Return the vsys for this object

        Traverses the tree to determine the vsys from a :class:`pandevice.firewall.Firewall`
        or :class:`pandevice.device.Vsys` instance somewhere before this node in the tree.

        Returns:
            str: The vsys id (eg. vsys2)

        """
        if self.parent is not None:
            vsys = self.parent.vsys
            if vsys is None and self.ROOT == Root.VSYS:
                return getattr(self.parent, "DEFAULT_VSYS", None)
            else:
                return vsys

    @vsys.setter
    def vsys(self, value):
        raise err.PanDeviceError("Cannot set vsys on non-vsys object")

    @property
    def uid(self):
        """Returns the unique identifier of this object as a string."""
        if hasattr(self, "id"):
            return self.id
        elif self.NAME is not None:
            return str(getattr(self, self.NAME))
        else:
            return ""

    def add(self, child):
        """Add a child node to this node

        Args:
            child (PanObject): Node to add as a child

        Returns:
            PanObject: Child node

        """
        child.parent = self
        self.children.append(child)
        return child

    def insert(self, index, child):
        """Insert a child node at a specific index

        This is useful for ordering or reordering security policy rules

        Args:
            index (int): The index where the child obj should be inserted
            child (PanObject): Node to add as a child

        Returns:
            PanObject: Child node

        """
        child.parent = self
        self.children.insert(index, child)
        return child

    def extend(self, children):
        """Add a list of child nodes to this node

        Args:
            children (list): List of PanObject instances

        """
        for child in children:
            child.parent = self
        self.children.extend(children)

    def pop(self, index):
        """Remove and return the object at an index

        Args:
            index (int): Index of the object to remove and return

        Returns:
            PanObject: The object removed from the children of this node

        """
        child = self.children.pop(index)
        child.parent = None
        return child

    def remove(self, child):
        """Remove the child from this node

        Args:
            child (PanObject): Child to remove

        """
        self.children.remove(child)
        child.parent = None

    def remove_by_name(self, name, cls=None):
        """Remove a child node by name

        If the class is not specified, then it defaults to type(self).

        Args:
            name (str): Name of the child node

        Keyword Args:
            cls (class): Restrict removal to instances of this class

        Returns:
            PanObject: The removed node, otherwise None

        """
        # Get the index of the first matching child
        index = self.find_index(name, cls)
        if index is not None:
            return self.pop(index)

    def removeall(self, cls=None):
        """Remove all children of a type

        Not recursive.

        Args:
            cls (class): The class of objects to remove

        Returns:
            list: List of PanObjects that were removed

        """
        if not self.children:
            return
        if cls is not None:
            children = [child for child in self.children if isinstance(child, cls)]
            for child in children:
                self.children.remove(child)
            return children
        else:
            children = self.children
            for child in children:
                child.parent = None
            self.children = []
            return children

    def xpath(self, root=None):
        """Return the full xpath for this object

        Xpath in the form: parent's xpath + this object's xpath + entry or member if applicable.

        Args:
            root: The root to use for this object (default: this object's root)

        Returns:
            str: The full xpath to this object

        """
        path = []
        p = self
        if root is None:
            root = self.ROOT
        vsys = self.vsys
        label = getattr(self, "VSYS_LABEL", "vsys")
        while True:
            if isinstance(p, PanDevice) and p != self:
                # Stop on the first pandevice encountered, unless the
                # pandevice.PanDevice object is the object whose xpath
                # was asked for.
                path.insert(0, p.xpath_root(root, vsys, label))
                break
            elif not hasattr(p, "VSYS_LABEL") or p == self:
                # Add on the xpath of this object, unless it is a
                # device.Vsys, unless the device.Vsys is the object whose
                # xpath was asked for.
                addon = p.XPATH
                if p.SUFFIX is not None:
                    addon += p.SUFFIX % (p.uid,)
                path.insert(0, addon)
                if p.__class__.__name__ == "Firewall" and p.parent is not None:
                    if p.parent.__class__.__name__ == "DeviceGroup":
                        root = Root.VSYS
            p = p.parent
            if p is None:
                break
            if hasattr(p, "VSYS_LABEL"):
                # Either panorama.DeviceGroup or device.Vsys.
                label = p.VSYS_LABEL
                vsys = p.vsys
            elif p.__class__.__name__ in ("Template", "TemplateStack"):
                if not self.TEMPLATE_NATIVE:
                    # Hit a template, make sure that the appropriate /config/...
                    # xpath has been saved.
                    if not path[0].startswith("/config/"):
                        path.insert(0, self.xpath_root(root, vsys, label))
                    vsys = p.vsys
                    root = p.ROOT

        return "".join(path)

    def xpath_nosuffix(self):
        """Return the xpath without the suffix

        This is used by refreshall().

        Returns:
            str: The xpath without entry or member on the end

        """
        if self.SUFFIX is None:
            return self.xpath()
        else:
            return self.xpath_short()

    def xpath_short(self, root=None):
        """Return an xpath for this object without the final segment

        Xpath in the form: parent's xpath + this object's xpath.  Used for set API calls.

        Args:
            root: The root to use for this object (default: this object's root)

        Returns:
            str: The xpath without the final segment

        """
        xpath = self.xpath(root)
        xpath = re.sub(r"/(?=[^/']*'[^']*'[^/']*$|[^/]*$).*$", "", xpath)
        return xpath

    def xpath_root(self, root_type, vsys, label="vsys"):
        if self.parent:
            return self.parent.xpath_root(root_type, vsys, label)

    def xpath_vsys(self):
        if self.parent is not None:
            return self.parent.xpath_vsys()

    def xpath_panorama(self):
        if self.parent is not None:
            return self.parent.xpath_panorama()

    def _root_xpath_vsys(self, vsys, label="vsys"):
        if vsys == "shared":
            xpath = "/config/shared"
        else:
            xpath = "/config/devices/entry[@name='localhost.localdomain']"
            xpath += "/{0}/entry[@name='{1}']".format(label, vsys or "vsys1")

        return xpath

    def element(self, with_children=True, comparable=False):
        """Construct an ElementTree for this PanObject and all its children

        Args:
            with_children (bool): Include children in element.
            comparable (bool): Element will be used in a comparison with another.

        Returns:
            xml.etree.ElementTree: An ElementTree instance representing the
                xml form of this object and its children

        """
        root = self._root_element()
        variables = self.variables()
        for var in variables:
            missing_replacement = False
            if var.vartype == "none":
                value = "nonetype"
            else:
                value = getattr(self, var.variable)
            if value is None:
                continue
            if var.condition is not None:
                condition = var.condition.split(":")
                if str(getattr(self, condition[0])) != condition[1]:
                    continue
            path = var.path.split("/")
            nextelement = root

            for section in path:

                if section.find("|") != -1:
                    # This is an element variable, so create an element containing
                    # the variables's value
                    section = re.sub(r"\([\w\d|-]*\)", str(value), section)

                # Search for variable replacements in path
                matches = re.findall(r"{{(.*?)}}", section)
                entryvar = None
                # Do variable replacement, ie. {{ }}
                for match in matches:
                    regex = r"{{" + re.escape(match) + r"}}"
                    # Ignore variables that are None
                    if getattr(self, match) is None:
                        missing_replacement = True
                        break
                    # Find the discovered replacement in the list of vars
                    for nextvar in variables:
                        if nextvar.variable == match:
                            matchedvar = nextvar
                            break
                    if matchedvar.vartype == "entry":
                        # If it's an 'entry' variable
                        # XXX: this is using a quick patch.  Should handle array-based entry vars better.
                        entry_value = pandevice.string_or_list(
                            getattr(self, matchedvar.variable)
                        )
                        section = re.sub(
                            regex,
                            matchedvar.path
                            + "/"
                            + "entry[@name='%s']" % entry_value[0],
                            section,
                        )
                        entryvar = matchedvar
                    else:
                        # Not an 'entry' variable
                        section = re.sub(
                            regex, getattr(self, matchedvar.variable), section
                        )
                if missing_replacement:
                    break

                found = nextelement.find(section)
                if found is not None:
                    # Existing element
                    nextelement = found
                else:
                    # Create elements
                    if entryvar is not None:
                        # for vartype="entry" with replacement from above
                        nextelement = ET.SubElement(nextelement, entryvar.path)
                        nextelement = ET.SubElement(
                            nextelement,
                            "entry",
                            {"name": getattr(self, entryvar.variable)},
                        )
                    else:
                        # for entry vartypes that are empty
                        if var.vartype == "entry" and not value:
                            continue
                        # non-entry vartypes
                        nextelement = ET.SubElement(nextelement, section)
            if missing_replacement:
                continue
            var._set_inner_xml_tag_text(nextelement, value, comparable)

        if with_children:
            self.xml_merge(root, self._subelements())

        return root

    def element_str(self, pretty_print=False):
        """The XML representation of this PanObject and all its children.

        Args:
            pretty_print (bool): Return the resulting string pretty_printed with indentation.

        Returns:
            str: XML form of this object and its children

        """
        if pretty_print:
            raw = ET.tostring(self.element(), encoding="utf-8")
            parsed = minidom.parseString(raw)
            return parsed.toprettyxml(indent="\t", encoding="utf-8")
        return ET.tostring(self.element(), encoding="utf-8")

    def _root_element(self):
        if self.SUFFIX == ENTRY:
            return ET.Element("entry", {"name": self.uid})
        elif self.SUFFIX == MEMBER:
            root = ET.Element("member")
            root.text = self.uid
            return root
        elif self.SUFFIX is None:
            # Get right of last / in xpath
            tag = self.XPATH.rsplit("/", 1)[-1]
            return ET.Element(tag)

        raise ValueError(
            "No suffix or XPATH defined for {0}".format(self.__class__.__name__)
        )

    def _subelements(self, comparable=False):
        """Generator function to turn children into XML objects.

        Yields:
            xml.etree.ElementTree: The next child as an ``ElementTree`` object.

        """
        for child in self.children:
            root = self._root_element()
            # Paths have a leading slash to get rid of
            xpath_sections = child.XPATH.split("/")[1:]
            if child.SUFFIX is None:
                # If not suffix, remove the last xpath section
                # because it will be part of the element
                xpath_sections = xpath_sections[:-1]
            e = root
            for path in xpath_sections:
                if path == "entry[@name='localhost.localdomain']":
                    e = ET.SubElement(e, "entry", {"name": "localhost.localdomain"})
                else:
                    e = ET.SubElement(e, path)
            e.append(child.element(comparable=comparable))
            yield root

    def _check_child_methods(self, method):
        if method in self.CHILDMETHODS:
            getattr(self, "child_" + method)()
        for child in self.children:
            child._check_child_methods(method)

    def equal(self, panobject, force=False, compare_children=True):
        """Compare this object to another object

        Equality of the objects is determined by the XML they generate, not by the
        values of their variables.

        Args:
            panobject (PanObject): The object to compare with this object
            force (bool): Do not raise a PanObjectError if the objects are different classes
            compare_children (bool): Not supported in this object, use True

        Raises:
            PanObjectError: Raised if the objects are different types that
                would not normally be comparable

        Returns:
            bool: True if the XML of the objects is equal, False if not

        """
        if not panobject:
            return False
        if not force and type(self) != type(panobject):
            raise err.PanObjectError(
                "Object {0} is not comparable to {1}".format(
                    type(self), type(panobject)
                )
            )
        return self.element_str() == panobject.element_str()

    def apply(self):
        """Apply this object to the device, replacing any existing object of the same name

        **Modifies the live device**

        """
        device = self.nearest_pandevice()
        logger.debug(
            device.id + ': apply called on %s object "%s"' % (type(self), self.uid)
        )
        device.set_config_changed()
        if self.HA_SYNC:
            device.active().xapi.edit(
                self.xpath(), self.element_str(), retry_on_peer=self.HA_SYNC
            )
        else:
            device.xapi.edit(
                self.xpath(), self.element_str(), retry_on_peer=self.HA_SYNC
            )
        for child in self.children:
            child._check_child_methods("apply")

    def create(self):
        """Create this object on the device

        **Modifies the live device**

        This method is nondestructive. If the object exists, the variables are added to the device
        without changing existing variables on the device. If a variables already exists on the
        device and this object has a different value, the value on the firewall is changed to
        the value in this object.

        """
        device = self.nearest_pandevice()
        logger.debug(
            device.id + ': create called on %s object "%s"' % (type(self), self.uid)
        )
        device.set_config_changed()
        element = self.element_str()
        if self.HA_SYNC:
            device.active().xapi.set(
                self.xpath_short(), element, retry_on_peer=self.HA_SYNC
            )
        else:
            device.xapi.set(self.xpath_short(), element, retry_on_peer=self.HA_SYNC)
        for child in self.children:
            child._check_child_methods("create")

    def delete(self):
        """Delete this object from the firewall

        **Modifies the live device**

        """
        device = self.nearest_pandevice()
        logger.debug(
            device.id + ': delete called on %s object "%s"' % (type(self), self.uid)
        )
        device.set_config_changed()
        for child in self.children:
            child._check_child_methods("delete")
        if self.HA_SYNC:
            device.active().xapi.delete(self.xpath(), retry_on_peer=self.HA_SYNC)
        else:
            device.xapi.delete(self.xpath(), retry_on_peer=self.HA_SYNC)
        if self.parent is not None:
            self.parent.remove(self)

    def update(self, variable):
        """Change the value of a variable

        **Modifies the live device**

        Do not attempt this on an element variable (|) or variable with replacement {{}}
        If the variable's value is None, then a delete API call is attempted.

        Args:
            variable (str): The name of an instance variable to update on the device

        """
        device = self.nearest_pandevice()
        logger.debug(
            device.id
            + ': update called on %s object "%s" and variable "%s"'
            % (type(self), self.uid, variable)
        )
        device.set_config_changed()
        path, value, var_path = self._get_param_specific_info(variable)
        xpath = "{0}/{1}".format(self.xpath(), path)

        if value is None:
            # Value is None, so delete it from the live device.
            device.xapi.delete(xpath, retry_on_peer=self.HA_SYNC)
        else:
            # Variable has a new value.
            element_tag = path.split("/")[-1]
            element = ET.Element(element_tag)
            var_path._set_inner_xml_tag_text(element, value)
            device.xapi.edit(
                xpath,
                ET.tostring(element, encoding="utf-8"),
                retry_on_peer=self.HA_SYNC,
            )

    def rename(self, new_name):
        """Change the name of this object.

        **Modifies the live device**

        NOTE:  This does not change any references that may exist in your
        pandevice object hierarchy, but it does update the name of the
        object itself.

        Args:
            new_name (str): The new UID for this object.

        """
        dev = self.nearest_pandevice()
        logger.debug(
            '{0}: rename called on {1} object "{2}"'.format(
                dev.id, type(self), self.uid
            )
        )
        dev.set_config_changed()
        dev.xapi.rename(self.xpath(), new_name)
        setattr(self, self.NAME, new_name)

    def move(self, location, ref=None, update=True):
        """Moves the current object.

        **Modifies the live device**

        This is useful for stuff like moving one security policy above another.

        If this object's parent is a rulebase object, then this object is also
        moved to the appropriate position in the local pandevice object tree.

        Args:
            location (str): Any of the following: before, after, top, or bottom
            ref (PanObject/str): If location is "before" or "after", move this object before/after the ref object.  If this is a string, then the string should just be the name of the object.
            update (bool): If this is set to False, then only move this object in the pandevice object tree, do not actually perform the MOVE operation on the live device.  Note that in order for this object to be moved in the pandevice object tree, the parent object must be a rulebase object.

        Raises:
            ValueError

        """
        d = self.nearest_pandevice()
        dst = None
        new_index = None
        rbs = ("Rulebase", "PreRulebase", "PostRulebase")
        ref_locs = ("before", "after")
        standalone_locs = ("top", "bottom")
        parent = self.parent

        # Sanity checks + determine move location.
        if parent is None:
            raise ValueError("No parent for object {0}".format(self.uid))
        elif location in standalone_locs:
            if ref is not None:
                raise ValueError("ref should be None for {0} move".format(location))
            if parent.__class__.__name__ in rbs:
                new_index = 0 if location == "top" else len(parent.children) - 1
        elif location in ref_locs:
            if ref is None:
                raise ValueError("ref must be specified for {0} move".format(location))
            dst = str(ref)
            if self.uid == dst:
                raise ValueError("Cannot move rule in relation to self")
            if parent.__class__.__name__ in rbs:
                offset = 0
                for i, x in enumerate(parent.children):
                    if self == x:
                        offset = 1
                    elif type(x) == type(self) and x.uid == dst:
                        new_index = (
                            i - offset if location == "before" else i - offset + 1
                        )
                        break
        else:
            raise ValueError(
                "Location must be one of:  {0} or {1}".format(ref_locs, standalone_locs)
            )

        logger.debug('{0}: move called on {1} "{2}"'.format(d.id, type(self), self.uid))

        # Move the rule in the pandevice object tree, if applicable.
        if new_index is not None:
            parent.remove(self)
            parent.insert(new_index, self)

        # Done if we're not updating.
        if not update:
            return

        # Perform the move on the nearest pandevice.
        d.set_config_changed()
        d.xapi.move(self.xpath(), location, dst)

    def _get_param_specific_info(self, variable):
        """Gets a tuple of info for the given parameter.

        This is to aid in things like updates or refreshes of a specific
        parameter attached to this PanObject / VersionedPanObject.

        Returns:
            A three element tuple of the variable's xpath (str), the value of
            the variable, and the full ``VarPath`` or ``ParamPath`` object that
            is responsible for handling this variable.

        Raises:
            PanDeviceError: If the variable specified does not exist.

        """
        variables = type(self).variables()
        value = getattr(self, variable)
        # Get the requested variable from the class' variables tuple
        var = next((x for x in variables if x.variable == variable), None)
        if var is None:
            raise err.PanDeviceError(
                "Variable %s does not exist in variable tuple" % variable
            )
        varpath = var.path
        # Do replacements on variable path
        if varpath.find("|") != -1:
            # This is an element variable, so create an element containing
            # the variables's value
            varpath = re.sub(r"\([\w\d|-]*\)", str(value), varpath)
        # Search for variable replacements in path
        matches = re.findall(r"{{(.*?)}}", varpath)
        entryvar = None
        # Do variable replacement, ie. {{ }}
        for match in matches:
            regex = r"{{" + re.escape(match) + r"}}"
            # Ignore variables that are None
            if getattr(self, match) is None:
                raise ValueError(
                    "While updating variable %s, missing replacement variable %s in path"
                    % (variable, match)
                )
            # Find the discovered replacement in the list of vars
            for nextvar in variables:
                if nextvar.variable == match:
                    matchedvar = nextvar
                    break
            if matchedvar.vartype == "entry":
                # If it's an 'entry' variable
                # XXX: this is using a quick patch.  Should handle array-based entry vars better.
                entry_value = pandevice.string_or_list(
                    getattr(self, matchedvar.variable)
                )
                varpath = re.sub(
                    regex,
                    matchedvar.path + "/" + "entry[@name='%s']" % entry_value[0],
                    varpath,
                )
            else:
                # Not an 'entry' variable
                varpath = re.sub(regex, getattr(self, matchedvar.variable), varpath)

        return (varpath, value, var)

    def refresh(
        self, running_config=False, refresh_children=True, exceptions=True, xml=None
    ):
        """Refresh all variables and child objects from the device.

        Args:
            running_config (bool): Set to True to refresh from the running
                configuration (Default: False)
            xml (xml.etree.ElementTree): XML from a configuration to use
                instead of refreshing from a live device
            refresh_children (bool): Set to False to prevent refresh of child
                objects (Default: True)
            exceptions (bool): Set to False to prevent exceptions on failure
                (Default: True)

        """
        # Either retrieve the xml or use what is passed in
        if xml is None:
            xml = self._refresh_xml(running_config, exceptions, refresh_children)
        else:
            logger.debug(
                'refresh called using xml on {0} object "{1}"'.format(
                    type(self), self.uid
                )
            )

        if xml is None:
            return

        # Refresh this object
        if hasattr(self, "parse_xml"):
            # Versioned object
            self.parse_xml(xml)
        else:
            # Classic object
            variables = type(self)._parse_xml(xml)
            for var, value in variables.items():
                setattr(self, var, value)

        # Refresh children objects if requested
        if refresh_children:
            self._refresh_children(xml=xml)

    def refresh_variable(self, variable, running_config=False, exceptions=False):
        """Refresh a single variable of an object.

        **Don't use for variables with replacements or selections in path.**

        Args:
            variable (str): Variable name to refresh.
            running_config (bool): Set to True to refresh from the running
                configuration (Default: False)
            exceptions (bool): Set to False to prevent exceptions on failure
                (Default: True)

        Returns:
            New value of the refreshed variable.

        Raises:
            PanObjectMissing: When the object this variable is connected to
                does not exist.

        """
        device = self.nearest_pandevice()
        msg = '{0}: refresh_variable({1}) called on {2} object "{3}"'
        logger.debug(msg.format(device.id, variable, self.__class__.__name__, self.uid))

        info = self._get_param_specific_info(variable)
        path = info[0]
        var_path = info[2]
        xpath = "{0}/{1}".format(self.xpath(), path)
        err_msg = "Object doesn't exist: {0}".format(xpath)
        setattr(self, variable, [] if var_path.vartype in ("member", "entry") else None)

        # Query to get the variable's XML from the device
        if running_config:
            api_action = device.xapi.show
        else:
            api_action = device.xapi.get
        try:
            root = api_action(xpath, retry_on_peer=self.HA_SYNC)
        except (pan.xapi.PanXapiError, err.PanNoSuchNode) as e:
            if exceptions:
                raise err.PanObjectMissing(err_msg, pan_device=device)
            return

        # Determine the first element to look for in the XML
        lasttag = path.rsplit("/", 1)[-1]
        obj = root.find("result/" + lasttag)
        if obj is None:
            if exceptions:
                raise err.PanObjectMissing(err_msg, pan_device=device)
            return

        if hasattr(var_path, "parse_value_from_xml_last_tag"):
            # Versioned class
            settings = {}
            var_path.parse_value_from_xml_last_tag(obj, settings)
            setattr(self, variable, settings.get(variable))
        else:
            # Classic class
            # Rebuild the elements that are lost by refreshing the
            # variable directly
            sections = path.split("/")[:-1]
            root = ET.Element("root")
            next_element = root
            for section in sections:
                next_element = ET.SubElement(next_element, section)
            next_element.append(obj)
            # Refresh the requested variable
            variables = type(self)._parse_xml(root)
            for var, value in variables.items():
                if var == variable:
                    setattr(self, var, value)

        return getattr(self, variable)

    def _refresh_children(self, running_config=False, xml=None):
        # Retrieve the xml if we weren't given it
        if xml is None:
            xml = self._refresh_xml(running_config, True)

        if xml is None:
            return

        # Remove all the current child instances first
        self.removeall()

        # Check for children in the remaining XML
        for child_type_string in self.CHILDTYPES:
            module_name, class_name = child_type_string.split(".")
            if module_name == "device":
                import pandevice.device
            elif module_name == "firewall":
                import pandevice.firewall
            elif module_name == "ha":
                import pandevice.ha
            elif module_name == "network":
                import pandevice.network
            elif module_name == "objects":
                import pandevice.objects
            elif module_name == "panorama":
                import pandevice.panorama
            elif module_name == "policies":
                import pandevice.policies
            child = getattr(getattr(pandevice, module_name), class_name)()

            # Versioned objects need a PanDevice to get the version from, so
            # set the child's parent before accessing XPATH.
            child.parent = self

            childroot = xml.find(child.XPATH[1:])
            if childroot is not None:
                l = child.refreshall_from_xml(childroot)
                self.extend(l)

        return self.children

    def _refresh_xml(self, running_config, exceptions, refresh_children=True):
        """Get the XML for a single PanObject."""
        # Get the root of the xml to parse
        optimized = False
        dev = self.nearest_pandevice()
        msg = "{0}: refreshing xml on {1} object {2}".format(
            dev.id, type(self), self.uid
        )
        logger.debug(msg)

        api_action = dev.xapi.show if running_config else dev.xapi.get

        if running_config or refresh_children:
            xpath = self.xpath()
        else:
            optimized = True
            info = self._build_element_info()
            paths, settings = info[0], info[2]
            query_paths = list(
                set(p.path.split("/")[0].format(**settings) for p in paths)
            )
            xpath = "|".join("{0}/{1}".format(self.xpath(), x) for x in query_paths)

        err_msg = "Object doesn't exist: {0}".format(xpath)
        # Query the live device
        try:
            root = api_action(xpath, retry_on_peer=self.HA_SYNC)
        except (pan.xapi.PanXapiError, err.PanNoSuchNode) as e:
            if exceptions:
                raise err.PanObjectMissing(err_msg, pan_device=dev)
            else:
                return

        # Determine the first element to look for in the XML
        if not optimized:
            # Normal XML recovery for parsing
            if self.SUFFIX is None:
                lasttag = self.XPATH.rsplit("/", 1)[-1]
            else:
                lasttag = re.match(r"^/(\w*?)\[", self.SUFFIX).group(1)
            elm = root.find("result/" + lasttag)
        else:
            # Construct the XML for parsing.
            elm = self._root_element()
            results = root.find("./result")
            if results is not None:
                for se in results:
                    elm.append(se)

        if elm is None and exceptions:
            raise err.PanObjectMissing(err_msg, pan_device=dev)

        return elm

    def nearest_pandevice(self):
        """The nearest :class:`pandevice.base.PanDevice` object to.

        This method is used to determine the device to apply this object.

        Returns:
            PanDevice: The PanDevice object closest to this object in
                the configuration tree.

        Raises:
            PanDeviceNotSet: There is no PanDevice object in the tree.

        """
        return self._nearest_pandevice()

    def _nearest_pandevice(self):
        if self.parent is not None:
            return self.parent._nearest_pandevice()
        raise err.PanDeviceNotSet("No PanDevice set for object tree")

    def panorama(self):
        """The nearest :class:`pandevice.panorama.Panorama` object.

        This method is used to determine the device to apply this object to.

        Returns:
            Panorama: The Panorama object closest to this object in the
                configuration tree

        Raises:
            PanDeviceNotSet: There is no Panorama object in the tree.

        """
        if self.parent is not None:
            return self.parent.panorama()
        raise err.PanDeviceNotSet("No Panorama set for object tree")

    def devicegroup(self):
        """The nearest :class:`pandevice.panorama.DeviceGroup` object.

        This method is used to determine the device to apply this object to.

        Returns:
            DeviceGroup: The DeviceGroup object closest to this object in the
            configuration tree, or None if there is no DeviceGroup in the path
            to this node.

        """
        if self.parent is not None:
            return self.parent.devicegroup()

    def find(self, name, class_type=None, recursive=False):
        """Find an object in the configuration tree by name

        Args:
            name (str): Name of the object to find
            class_type: Class to look for
            recursive (bool): Find recursively (Default: False)

        Returns:
            PanObject: The object in the tree that fits the criteria, or None if no object is found

        """
        if class_type is None:
            # Find the matching object or return None
            result = next((child for child in self.children if child.uid == name), None)
        else:
            # Find the matching object or return None
            result = next(
                (
                    child
                    for child in self.children
                    if child.uid == name and isinstance(child, class_type)
                ),
                None,
            )
        # Search recursively in children
        if result is None and recursive:
            for child in self.children:
                result = child.find(name, class_type, recursive)
                if result is not None:
                    break
        return result

    def findall(self, class_type, recursive=False):
        """Find all objects of a class in configuration tree

        Args:
            class_type: Class to look for
            recursive (bool): Find recursively (Default: False)

        Returns:
            list: List of 'class_type' objects

        """
        result = [child for child in self.children if isinstance(child, class_type)]
        # Search recursively in children
        if recursive:
            for child in self.children:
                result.extend(child.findall(class_type, recursive))
        return result

    def find_or_create(self, name, class_type, *args, **kwargs):
        """Find an object in the configuration tree by name, and create it if it doesn't exist

        If the object does not exist, it is created and added to the current object.

        Args:
            name (str): Name of the object to find
            class_type: Class to look for or create
            *args: Arguments to pass to the __init__ method of class_type
            *kwargs: Keyworkd arguments to pass to the __init__ method of class_type

        Returns:
            PanObject: The object in the tree that fits the criteria, or None if no object is found

        """
        result = self.find(name, class_type)
        if result is not None:
            return result
        else:
            if name is not None:
                return self.add(class_type(name, *args, **kwargs))
            else:
                return self.add(class_type(*args, **kwargs))

    def findall_or_create(self, class_type, *args, **kwargs):
        """Find all object in the configuration tree by class, and create a new object if none exist

        If no objects of this type exist, one is created and added to the current object.

        Args:
            class_type: Class to look for or create
            *args: Arguments to pass to the __init__ method of class_type
            *kwargs: Keyworkd arguments to pass to the __init__ method of class_type

        Returns:
            list: List of 'class_type' objects

        """
        result = self.findall(class_type)
        if result:
            return result
        else:
            return [self.add(class_type(*args, **kwargs))]

    def find_index(self, name=None, class_type=None):
        """Finds the first index of the given name and class type.

        If name is None, just find the first instance of class_type.

        If class_type is unspecified, it defaults to the current class type.

        Args:
            name (str): Name of the child node
            class_type (class): Restrict the find to children of this type

        Returns:
            int:  the index of the first matching child

        """
        if class_type is None:
            class_type = type(self)

        for num, child in enumerate(self.children):
            if (name is None or child.uid == name) and type(child) == class_type:
                return num

    @classmethod
    def refreshall(
        cls, parent, running_config=False, add=True, exceptions=False, name_only=False
    ):
        """Factory method to instantiate class from live device.

        This method is a factory for the class. It takes an firewall or
        Panorama and gets the xml config from the live device. It generates
        instances of this class for each item this class represents in the xml
        config. For example, if the class is AddressObject and there are 5
        address objects on the firewall, then this method will generate 5
        instances of the class AddressObject.

        Args:
            parent (PanObject): A PanDevice, or a PanObject subclass with a
                PanDevice as its parental root.
            running_config (bool): False for candidate config, True for running
                config.
            add (bool): Update the objects of this type in pandevice with
                the refreshed values.
            exceptions (bool): If False, exceptions are ignored if the xpath
                can't be found.
            name_only (bool): If True, refresh only the name of the object, but
                not its variables.  This results in a smaller response to the
                API call when only the object name is needed.

        Returns:
            list: created instances of class

        """
        if not running_config and exceptions:
            # This is because get api calls don't produce exceptions when the
            # node doesn't exist
            raise ValueError("exceptions requires running_config to be True")
        if name_only and running_config:
            raise ValueError("can't get name_only from running_config")
        if name_only and cls.SUFFIX != ENTRY:
            raise ValueError(
                "name_only is invalid, can only be used on entry type objects"
            )

        # Versioned objects need a PanDevice to get the version from, so
        # set the child's parent before accessing XPATH.
        class_instance = cls()
        class_instance.parent = parent

        device = class_instance.nearest_pandevice()
        logger.debug(device.id + ": refreshall called on %s type" % cls)

        # Set api_action and xpath
        api_action = device.xapi.show if running_config else device.xapi.get
        xpath = class_instance.xpath_nosuffix()
        if name_only:
            xpath = xpath + "/entry/@name"

        try:
            root = api_action(xpath, retry_on_peer=cls.HA_SYNC)
        except (err.PanNoSuchNode, pan.xapi.PanXapiError) as e:
            if exceptions:
                raise e
            if not str(e).startswith("No such node"):
                raise e
            else:
                return []
        if name_only:
            obj = root.find("result")
        else:
            lasttag = class_instance.XPATH.rsplit("/", 1)[-1]
            obj = root.find("result/" + lasttag)
        if obj is None:
            return []

        # Refresh each object
        instances = class_instance.refreshall_from_xml(obj)

        if add:
            # Remove current children of this type from parent
            parent.removeall(cls=cls)
            # Add the new children that were just refreshed from the device
            parent.extend(instances)

        return instances

    def refreshall_from_xml(self, xml, refresh_children=True, variables=None):
        """Factory method to instantiate class from firewall config.

        This method is a factory for the class. It takes an xml config
        from a firewall and generates instances of this class for each item
        this class represents in the xml config. For example, if the class is
        AddressObject and there are 5 address objects on the firewall, then
        this method will generate 5 instances of the class AddressObject.

        Args:
            xml (xml.etree.ElementTree): A section of XML configuration from a
                firewall or Panorama.  It should not contain the response or
                result tags.
            refresh_children (bool): Refresh children objects or not.
            variables (iterable): A list or tuple of the variables to parse
                from the XML.  Note that this is only used when invoked
                against classes not derived from ``VersionedPanObject``.

        Returns:
            list: created instances of class

        """
        instances = []

        if xml is None:
            return []

        # Get the objects from the xml at this level
        if self.SUFFIX is None:
            objects = [xml]
        else:
            lasttag = re.match(r"^/(\w*?)\[", self.SUFFIX).group(1)
            objects = xml.findall(lasttag)

        # Refresh each object
        for obj in objects:
            # Create the object instance
            if hasattr(self, "parse_xml"):
                # Versioned object handling
                instance = type(self)()
                instance.parent = self.parent
                instance.parse_xml(obj)
            else:
                # Classic object handling
                objvars = self._parse_xml(obj, variables=variables)
                if self.SUFFIX is not None:
                    name = obj.get("name")
                    if name is not None:
                        objvars[self.NAME] = name
                instance = type(self)(variables=variables, **objvars)

            # Add this instance to the list
            instances.append(instance)

            # Refresh the children of these instances
            if refresh_children:
                instance._refresh_children(xml=obj)

        return instances

    @classmethod
    def _parse_xml(cls, xml, variables=None):
        """Classic class method to parse XML to variables.

        Args:
            xml (xml.etree.ElementTree): the xml to retrieve variables from.
            variables (list): a list of ``VarPath`` instances to parse
                from the given XML.  If this is not specified, then all of the
                variables that this ``PanObject`` contains are parsed.

        Returns:
            A dict of ``VarPath`` objects.

        """
        vardict = {}
        # Parse each variable
        if variables:
            allvars = variables
        else:
            allvars = cls.variables()
        for var in allvars:
            missing_replacement = False
            # Determine if variable is part of __init__ args
            if var.vartype == "none":
                continue
            # Search for variable replacements in path
            path = var.path
            matches = re.findall(r"{{(.*?)}}", path)
            for match in matches:
                regex = r"{{" + re.escape(match) + r"}}"
                # Find the discovered replacement in the list of vars
                matchedvar = next(
                    (x for x in cls.variables() if x.variable == match), None
                )
                replacement = vardict[match]
                if replacement is None:
                    missing_replacement = True
                    break
                if matchedvar.vartype == "entry":
                    # If it's an 'entry' variable
                    if len(replacement) == 1:
                        replacement = replacement[0]
                    path = re.sub(
                        regex,
                        matchedvar.path + "/" + "entry[@name='%s']" % replacement,
                        path,
                    )
                else:
                    # Not an 'entry' variable
                    path = re.sub(regex, replacement, path)
            if missing_replacement:
                continue
            # Determine the type of variable
            if var.vartype == "member":
                members = xml.findall(path + "/member")
                vardict[var.variable] = [m.text for m in members]
            elif var.vartype == "entry":
                entries = xml.findall(path + "/entry")
                entries = [e.get("name") for e in entries]
                if len(entries) == 1:
                    entries = entries[0]
                vardict[var.variable] = entries
            elif var.vartype == "exist":
                match = xml.find(path)
                vardict[var.variable] = True if match is not None else False
            else:
                if path.find("|") != -1:
                    # This is an element variable
                    # Get the different options in a list
                    options = re.search(r"\(([\w\d|-]*)\)", path).group(1).split("|")
                    # Create a list of all the possible paths
                    option_paths = {
                        opt: re.sub(r"\([\w\d|-]*\)", opt, path) for opt in options
                    }
                    found = False
                    for opt, opt_path in option_paths.items():
                        match = xml.find(opt_path)
                        if match is not None:
                            vardict[var.variable] = cls._convert_var(opt, var.vartype)
                            found = True
                            break
                    if not found:
                        vardict[var.variable] = None
                else:
                    # This is a text variable
                    # Save the variable if it exists in the xml
                    vardict[var.variable] = cls._convert_var(
                        xml.findtext(path), var.vartype
                    )
        return vardict

    @classmethod
    def _convert_var(cls, value, vartype):
        if value is None:
            return None
        elif vartype is None:
            return value
        elif vartype == "int":
            return int(value)
        elif vartype == "bool":
            return yesno(value)

    def _set_reference(
        self,
        reference_name,
        reference_type,
        reference_var,
        var_type,
        exclusive,
        refresh,
        update,
        running_config,
        return_type,
        name_only,
        **kwargs
    ):
        """Used by helper methods to set references between objects

        For example, set_zone() would set the zone for an interface by creating a reference from
        the zone to the interface. If the desired reference already exists then nothing happens.

        This function has two modes:  refresh=True and refresh=False.  You
        should only ever use refresh=False if:

            1) all reference objects are in the current pandevice object tree
            2) all reference objects are children attached to nearest_pandevice()
            3) this is for firewall only, not a template / template stack
            4) you're using firewall.vsys, not the device.Vsys object

        If any of the above do not apply, you should be using refresh=True.

        """
        parent = None
        update_needed = False

        if return_type not in ("bool", "object"):
            raise ValueError("Unknown return_type specified: {0}".format(return_type))

        if refresh:
            """
            pandevice is too flexible:  users can use simple vsys mode or a
            device.Vsys object, which means vsys importables can be attached
            to a Vsys object or a Firewall.  But a Vsys object can also be
            attached to a Firewall or a Template or a TemplateStack.  So
            create a separate pandevice object tree to operate on, leaving
            the user's tree alone, but making it so we know where things are.

            Basically, we need a pandevice object tree where all objects are
            are sibling objects, just like refresh=False assumes.  Doing
            this allows the rest of this function to operate as before.
            """
            from pandevice.firewall import Firewall
            from pandevice.panorama import Panorama, Template, TemplateStack
            from pandevice.device import Vsys

            new_tree = None
            if reference_type.ROOT == Root.VSYS:
                # If the reference type belongs in a vsys (Zone), then
                # initialize the new tree with a Vsys object.  Otherwise do not
                # have a vsys specified as we don't care where an object is
                # or is not imported into.
                parent = Vsys(self.vsys or "vsys1")
                new_tree = parent

            p = self
            while p is not None:
                new_obj = None
                if isinstance(p, Firewall):
                    new_obj = Firewall(
                        hostname=p.hostname,
                        port=p.port,
                        api_username=p._api_username,
                        api_password=p._api_password,
                        api_key=p._api_key,
                        serial=p.serial,
                    )
                elif isinstance(p, Template):
                    new_obj = Template(p.name)
                elif isinstance(p, TemplateStack):
                    new_obj = TemplateStack(p.name)
                elif isinstance(p, Panorama):
                    new_obj = Panorama(
                        hostname=p.hostname,
                        port=p.port,
                        api_username=p._api_username,
                        api_password=p._api_password,
                        api_key=p._api_key,
                    )

                if new_obj is not None:
                    if parent is None:
                        parent = new_obj
                        new_tree = new_obj
                    else:
                        new_obj.add(new_tree)
                        new_tree = new_obj

                p = p.parent

            if parent is None or isinstance(parent, Panorama):
                raise err.PanDeviceError("Improper pandevice object tree")

            allobjects = reference_type.refreshall(
                parent, name_only=name_only, running_config=running_config
            )
            if name_only:
                for obj in allobjects:
                    obj.refresh_variable(reference_var)
        else:
            parent = self.nearest_pandevice()
            allobjects = parent.findall(reference_type)

        # Find any current references to self and remove them, unless it is the desired reference
        if exclusive:
            for obj in allobjects:
                references = getattr(obj, reference_var)
                if not references:
                    continue
                elif reference_name is not None and obj.uid == reference_name:
                    continue
                elif isinstance(references, list) and self in references:
                    update_needed = True
                    references.remove(self)
                    if update:
                        obj.update(reference_var)
                elif isinstance(references, list) and str(self) in references:
                    update_needed = True
                    references.remove(str(self))
                    if update:
                        obj.update(reference_var)
                elif references == self or references == str(self):
                    update_needed = True
                    setattr(obj, reference_var, None)
                    if update:
                        obj.update(reference_var)

        # Add new reference to self in requested object
        if reference_name is not None:
            obj = parent.find_or_create(reference_name, reference_type, **kwargs)
            var = getattr(obj, reference_var)
            if var_type == "list":
                if var is None:
                    update_needed = True
                    setattr(obj, reference_var, [self,])
                    if update:
                        obj.update(reference_var)
                elif not isinstance(var, list):
                    if var != self and var != str(self):
                        update_needed = True
                        setattr(obj, reference_var, [var, self])
                        if update:
                            obj.update(reference_var)
                elif self not in var and str(self) not in var:
                    update_needed = True
                    var.append(self)
                    if update:
                        obj.update(reference_var)
            elif var != self and var != str(self):
                update_needed = True
                setattr(obj, reference_var, self)
                if update:
                    obj.update(reference_var)
            if return_type == "object":
                return obj

        if return_type == "bool":
            return update_needed

    def xml_merge(self, root, elements):
        """Merges other elements into the root element.

        This differs from xml_combine in a few important ways:

        1) The base tag of root is valid
        2) The root element must be a valid ElementTree object
        3) Individual Nones in the elements iterable are ignored

        Args:
            root (xml.etree.ElementTree): The root element.
            elements (iterable): Other xml.etree.ElementTree instances (or
                None) that should be merged into ``root`` as well.

        Returns:
            xml.etree.ElementTree: The final merged root element.

        """
        for e in elements:
            if e is not None:
                self._merge_elements(root, e)

        return root

    def _merge_elements(self, root, elm):
        class dicthash(dict):
            def __hash__(self):
                return hash(tuple(sorted(self.items())))

        # Copy text only if it isn't set already
        if root.tag == elm.tag and root.text is None:
            root.text = elm.text

        mapping = dict(((e.tag, dicthash(e.attrib)), e) for e in root)
        for e in elm:
            hashed_attribs = dicthash(e.attrib)
            if len(e) == 0:
                try:
                    # Copy text only if it isn't set already
                    if mapping[e.tag, hashed_attribs].text is None:
                        # Tag doesn't have text, but another element does
                        mapping[e.tag, hashed_attribs].text = e.text
                    if (
                        mapping[e.tag, hashed_attribs].tag == e.tag
                        and mapping[e.tag, hashed_attribs].text
                        and e.text
                        and mapping[e.tag, hashed_attribs].text != e.text
                    ):
                        # Member vartypes, so append this element
                        raise KeyError
                except KeyError:
                    # Add new element to the mapping
                    mapping[e.tag, hashed_attribs] = e
                    root.append(e)
            else:
                try:
                    # Merge subelements together
                    self._merge_elements(mapping[e.tag, hashed_attribs], e)
                except KeyError:
                    # Add new element to the mapping
                    mapping[e.tag, hashed_attribs] = e
                    root.append(e)

    def about(self, parameter=None):
        """Return information about this object or the given parameter.

        If no parameter is specified, then invoking this function is similar to
        doing `vars(obj)`:  it will return a dict of key/value pairs, with the
        difference being that the keys are all specifically parameters attached
        to this `VersionedPanObject`, and the values being what the current
        settings are for those keys.

        If a parameter is specified and this object is connected to a
        parent PanDevice, then version specific information on the parameter
        is returned.

        If a parameter is specified but this object is not connected to a
        PanDevice instance, then all versioning information for the given
        parameter is returned.

        Args:
            parameter (str): The parameter to get info for.

        Returns:
            dict: An informational dict about either the object as a whole
            or the specified parameter.

        Raises:
            AttributeError: If a parameter is specified that does not exist
                on this object.

        """
        if parameter is None:
            return self._about_object()
        else:
            return self._about_parameter(parameter)

    def _about_object(self):
        ans = {}

        # Get the variables for this object
        for v in type(self).variables():
            ans[v.variable] = getattr(self, v.variable)

        # Add the object's uid if applicable
        if self.NAME is not None:
            ans[self.NAME] = self.uid

        return ans

    def _about_parameter(self, parameter):
        parameter = str(parameter)
        ans = {
            "Parameter": parameter,
            "Current Value": getattr(self, parameter, None),
        }

        for v in type(self).variables():
            if parameter == v.variable:
                ans["About"] = v.about()
                break
        else:
            if parameter == self.NAME:
                ans["About"] = "This is the object's unique identifier"
            else:
                raise AttributeError(parameter)

        return ans

    def _requires_import_consideration(self):
        if self.vsys == "shared" or not hasattr(self, "XPATH_IMPORT"):
            return False
        return True

    def _gather_bulk_info(self, func=None):
        """Returns info for the bulk functions to operate on.

        This function gets a single instance which will act as xpath scope,
        but goes back to the nearest pandevice to collect all instances of
        cType with the same xpath, as we need to be aware that instances could
        share path but be in different vsys.

        Args:
            func (str): The function calling this function

        Returns:
            3 element tuple:
                * nearest PanDevice
                * list of instances of cType that share single instance's scope
                * dict: vsys key with value of dict:
                    * import path key with value of list of PanObject instances

        """
        dev = self.nearest_pandevice()
        logger.debug(
            '{0}: {1} called on {2} object "{3}"'.format(dev.id, func, self, self.uid)
        )
        dev.set_config_changed()

        # Determine base xpath to match against.
        xpath = self.xpath_short()

        # Now, find all PanObjects with a similar xpath.
        tree = [
            dev,
        ]
        instances = []
        for node in itertools.chain(tree):
            tree.extend(node.children)
            if node.xpath_short() == xpath:
                instances.append(node)

        # Now find all the objects that need to be imported.
        vsys_dict = {}
        all_objects = instances[:]
        for node in itertools.chain(all_objects):
            all_objects.extend(node.children)
            if node._requires_import_consideration():
                vsys = node.vsys
                if vsys is None and node.ALWAYS_IMPORT:
                    if getattr(node, "mode", None) in ("ha", "aggregate-group"):
                        continue
                    vsys = "vsys1"
                vsys_dict.setdefault(vsys, {})
                vsys_dict[vsys].setdefault(node.xpath_import_base(), [])
                vsys_dict[vsys][node.xpath_import_base()].append(node)

        return dev, instances, vsys_dict

    def create_similar(self):
        """Bulk create all objects similar to this one.

        **Modifies the live device**

        This is similar to create(), except instead of calling create only
        on this object, it calls create for all objects that share the same
        xpath as this object, recursively searching the entire object tree
        from the nearest firewall or panorama instance.

        As an example, if you called create_similar on an object representing
        ethernet1/5.42, all of the subinterfaces for ethernet1/5 would be
        included in the resulting XML document, regardless of which vsys
        those subinterfaces existed in.

        """
        dev, instances, vsys_dict = self._gather_bulk_info("create_similar")
        if not instances:
            return

        # The new root tag is the last tag in the xpath, while the new xpath
        # is what remains.
        xpath_tokens = self.xpath_short().split("/")
        new_root = xpath_tokens.pop()
        xpath = "/".join(xpath_tokens)

        # Append all similar children.
        shared_root = ET.Element(new_root)
        for x in instances:
            shared_root.append(x.element())

        # Perform the create.
        dev.xapi.set(
            xpath,
            ET.tostring(shared_root, encoding="utf-8"),
            retry_on_peer=self.HA_SYNC,
        )

        # Do all necessary imports, per vsys, per import xpath.
        self._perform_vsys_dict_import_set(dev, vsys_dict)

    def apply_similar(self):
        """Bulk apply all objects similar to this one.

        **Modifies the live device**

        This is similar to apply(), except instead of calling apply only
        on this object, it calls apply for all objects that share the same
        xpath as this object, recursively searching the entire object tree
        from the nearest firewall or panorama instance.

        As an example, if you called apply_similar on an object representing
        ethernet1/5.42, all of the subinterfaces for ethernet1/5 would be
        included in the resulting XML document, regardless of which vsys
        those subinterfaces existed in.

        Since apply does a replace of the config at the given xpath, please
        be careful when using this function that all objects, whether they
        be updated or not, exist in your pandevice object tree.

        """
        dev, instances, vsys_dict = self._gather_bulk_info("apply_similar")
        if not instances:
            return

        # The new root tag is the last tag in the xpath, while the new xpath
        # is what remains.
        xpath = self.xpath_short()
        new_root = xpath.split("/")[-1]

        # Append all children of type cType.
        shared_root = ET.Element(new_root)
        for x in instances:
            shared_root.append(x.element())

        # Perform the create.
        dev.xapi.edit(
            xpath,
            ET.tostring(shared_root, encoding="utf-8"),
            retry_on_peer=self.HA_SYNC,
        )

        # Do all necessary imports, per vsys, per import xpath.
        self._perform_vsys_dict_import_set(dev, vsys_dict)

    def delete_similar(self):
        """Bulk delete all objects similar to this one.

        **Modifies the live device**

        This is similar to delete(), except instead of calling delete only
        on this object, it calls delete for all objects that share the same
        xpath as this object, recursively searching the entire object tree
        from the nearest firewall or panorama instance.

        As an example, if you called delete_similar on an object representing
        ethernet1/5.42, all of the subinterfaces in your pandevice object
        tree for ethernet1/5 would be removed.

        """
        dev, instances, vsys_dict = self._gather_bulk_info("delete_similar")
        if not instances:
            return

        # This operation is only supported for entry/member objects.
        if self.SUFFIX not in (ENTRY, MEMBER):
            raise ValueError("delete_similar requires member or entry")

        # Do all necessary unimports, per vsys, per xpath.
        self._perform_vsys_dict_import_delete(dev, vsys_dict)

        # Now perform the bulk delete.
        xpath = self.xpath_nosuffix()
        if self.SUFFIX == ENTRY:
            entries = " or ".join("@name='{0}'".format(x.uid) for x in instances)
            xpath += "/entry[{0}]".format(entries)
        elif self.SUFFIX == MEMBER:
            members = " or ".join("text()='{0}'".format(x.uid) for x in instances)
            xpath += "/member[{0}]".format(members)
        dev.xapi.delete(xpath, retry_on_peer=self.HA_SYNC)

        # Remove each object from self, just like delete().
        for x in instances:
            x.parent.remove(x)

    def _perform_vsys_dict_import_set(self, dev, vsys_dict):
        """Iterates of a vsys_dict, doing imports for all instances."""
        for vsys, vsys_spec in vsys_dict.items():
            if vsys is None:
                continue
            for xpath_import_base, objs in vsys_spec.items():
                xpath_tokens = xpath_import_base.split("/")
                new_root = xpath_tokens.pop()

                # Form the xpath from what remains of the xpath.
                xpath = "/".join(xpath_tokens)

                # Append objects as members to the new root.
                shared_root = ET.Element(new_root)
                for x in objs:
                    ET.SubElement(shared_root, "member").text = x.uid

                # Perform the import.
                dev.xapi.set(
                    xpath,
                    ET.tostring(shared_root, encoding="utf-8"),
                    retry_on_peer=self.HA_SYNC,
                )

    def _perform_vsys_dict_import_delete(self, dev, vsys_dict):
        """Iterates over a vsys_dict, deleting the import for all instances."""
        for vsys_spec in vsys_dict.values():
            for objs in vsys_spec.values():
                members = " or ".join("text()='{0}'".format(x.uid) for x in objs)
                xpath = "{0}/member[{1}]".format(objs[0].xpath_import_base(), members)
                # API complains if you try to do this in one delete statement,
                # so do one delete per vsys per path, just like when we set the
                # imports.
                dev.xapi.delete(xpath, retry_on_peer=self.HA_SYNC)

    def dot(self):
        result = (
            "digraph configtree {graph [rankdir=LR, fontsize=10, margin=0.001];"
            "node [shape=box, fontsize=10, height=0.001, margin=0.1, ordering=out];"
        )
        result += self._dot(root_node=True)
        result += "}"
        return result

    def _dot(self, root_node=False):
        node = type(self).__name__
        module = type(self).__module__.split(".")[-1]
        result = (
            '"{node_name}" [style=filled fillcolor={color} '
            'URL="{url}'
            '/module-{module}.html#pandevice.{module}.{node}" '
            'target="_blank"];'
        )
        result = result.format(
            node_name=node + " : " + self.uid,
            node=node,
            module=module,
            url=pandevice.DOCUMENTATION_URL,
            color=pandevice.node_color(module),
        )
        # Make recursive call to children
        for child in self.children:
            result += child._dot()
        # Build relationship with parent
        if not root_node and self.parent is not None:
            if self.parent is not None:
                result += '"{0}" -> "{1}";'.format(
                    type(self.parent).__name__ + " : " + self.parent.uid,
                    type(self).__name__ + " : " + self.uid,
                )
        return result

    def tree(self):
        """Display a graph of the configuration tree

        The tree includes this object and its children, recursively.

        This method is only for use in Jupyder Notebooks

        """
        import graphviz

        return graphviz.Source(self.dot())

    def fulltree(self):
        """Display a graph of the entire configuration tree

        This method is only for use in Jupyder Notebooks

        """
        if self.parent is not None:
            return self.parent.fulltree()
        return self.tree()

    def retrieve_panos_version(self):
        """Gets the panos_version of the closest PanDevice.

        If this object is not attached to a PanDevice, then a very large
        number is returned to ensure that the newest version of the
        object and xpath is presented to the user.

        Returns:
            tuple: The version as (x, y, z)
        """
        try:
            device = self.nearest_pandevice()
            panos_version = device.get_device_version()
        except (err.PanDeviceNotSet, err.PanApiKeyNotSet):
            panos_version = self._UNKNOWN_PANOS_VERSION

        return panos_version


class VersioningSupport(object):
    """A class that supports getting version specific values of something.

    Versions of the value are added in ascending order using ``add_profile()``,
    then can be retrieved by using ``_get_versioned_value()``.  You can specify
    how the retrieved value is cast by overriding ``_cast_version_value()``.

    """

    def __init__(self):
        self.__profiles = []

    def add_profile(self, version=None, value=None):
        """Add support for version ``version`` that returns ``value``.

        **Version support must be added in ascending order.**

        Args:
            version (str): The version to add support for.  If this is
                unspecified, then the version defaults to '0.0.0'.
            value: The value to be retrieved for this version.

        Raises:
            ValueError: If the given version is lower than the most recent
                version.

        """
        # TODO(gfreeman): use pandevice versioning
        if version is None:
            version_tuple = (0, 0, 0)
        else:
            version_tuple = tuple(int(x) for x in version.split("-")[0].split("."))
            if len(version_tuple) != 3:
                msg = "{0} profile version {1} not formatted as X.Y.Z"
                raise ValueError(msg.format(self.param, version))

        # Make sure that this new profile is not a version lower
        if self.__profiles:
            if self.__profiles[0][0] > version_tuple:
                msg = "Cannot add version {0} support after version {1}"
                raise ValueError(msg.format(version_tuple, self.__profiles[0][0]))

        # Add the profile
        self.__profiles.insert(0, (version_tuple, value))

        # Return self for chained invocations
        return self

    def _get_versioned_value(self, panos_version):
        """Returns version specific value.

        Args:
            panos_version (tuple): The version as (x, y, z) tuple

        Returns:
            The casted value stored for this version.

        """
        value = None

        for version_number, value in self.__profiles:
            if panos_version >= version_number:
                break

        return self._cast_version_value(value)

    def __iter__(self):
        for version_number, value in self.__profiles:
            yield version_number, self._cast_version_value(value)

    def _cast_version_value(self, value):
        """Defines any special handling for the value before returning it."""
        return value


class VersionedStubs(VersioningSupport):
    def add_profile(self, version=None, *paths):
        """Adds the following stubs for the specified version.

        Args:
            version (str): The version to add support for.
            *paths (str): Variable length arg list of paths for this version.

        """
        return super(VersionedStubs, self).add_profile(version, paths)

    def _cast_version_value(self, value):
        """Turn the list of strings into a list of stubs."""
        if value is None:
            return []

        ans = []
        for path in value:
            ans.append(ParamPath(None, path, "stub"))

        return ans


class ParentAwareXpath(object):
    """Class to handle xpaths of objects.

    Some objects have a different xpath based on where in the tree they are
    located.  This class allows you configure various xpaths that can vary
    both on version and what the parent class is.

    If no explicit parent is specified, then the global parent of `None' is
    assumed.

    """

    def __init__(self):
        self.settings = {}
        self.parent_params = []

    def add_profile(
        self,
        version=None,
        value=None,
        parents=None,
        parent_param=None,
        parent_param_values=None,
    ):
        """Adds support for the given versions, specific to the parents.

        If no parents are specified, then a parent of ``None`` is assumed,
        which is the global parent type.

        **Version support per parent must be in ascending order.**

        Args:
            version (str): The version number (default: '0.0.0').
            value (str): The xpath setting.
            parents (list/tuple): The parent classes this version/value is valid for.
            parent_param (str): Parent param to key off of.
            parent_param_values (list): Values of the parent param to key off of.

        """
        if parents is None:
            parents = (None,)

        if parent_param not in self.parent_params:
            # None is always a fallback, so make sure None as a
            # parent param is last.
            index = -1 if parent_param is not None else len(self.parent_params)
            self.parent_params.insert(index, parent_param)

        if parent_param_values is None:
            parent_param_values = [
                None,
            ]

        for p in parents:
            for ppv in parent_param_values:
                combo = (p, parent_param, ppv)
                self.settings.setdefault(combo, VersioningSupport())
                self.settings[combo].add_profile(version, value)

    def _get_versioned_value(self, panos_version, parent):
        """Gets the xpath for this version/parent combination.

        Args:
            panos_version (tuple): The version as (x, y, z) tuple.
            parent: The self.parent for this VersionedPanObject.

        Returns:
            string.  The xpath.

        Raises:
            ValueError if no applicable xpath is found.

        """
        parents = [
            None,
        ]
        parent_settings = {}
        if parent is not None:
            parents = [parent.__class__.__name__, None]
            parent_settings = parent._about_object()

        for p in parents:
            for parent_param in self.parent_params:
                combo = (p, parent_param, parent_settings.get(parent_param, None))
                try:
                    return self.settings[combo]._get_versioned_value(panos_version)
                except KeyError:
                    pass

        raise ValueError("No applicable combination found for xpath")


class VersionedPanObject(PanObject):
    """Base class for all versioned package objects.

    This class is an extention of :class:`pandevice.base.PanObject` that
    supports versioning.

    Args:
        name (str): The name of this object.
        *args: Variable length list of values to initialize this object.
        **kwargs: Keyword args to initialize this object.

    Attributes:
        uid (str): The unique identifier for this object if it has one.  If it
            doesn't have one, then this returns the class name.
        vsys (str): The vsys id for this object (e.g. 'vsys2') or 'shared' if
            no vsys.
        XPATH (str): The xpath for this object, based on where in the tree it
            currently resides, as well as the versioning.

    """

    _UNKNOWN_PANOS_VERSION = (sys.maxsize, 0, 0)
    _DEFAULT_NAME = None
    _TEMPLATE_DEVICE_XPATH = "/config/devices/entry[@name='localhost.localdomain']"
    _TEMPLATE_VSYS_XPATH = _TEMPLATE_DEVICE_XPATH + "/vsys/entry[@name='{vsys}']"
    _TEMPLATE_MGTCONFIG_XPATH = "/config/mgt-config"

    def __init__(self, *args, **kwargs):
        if self.NAME is not None:
            try:
                name = args[0]
                args = args[1:]
            except IndexError:
                name = kwargs.pop(self.NAME, None)
            setattr(self, self.NAME, name or self._DEFAULT_NAME)
        self.parent = None
        self.children = []
        self._xpaths = ParentAwareXpath()
        self._stubs = VersionedStubs()

        self._setup()

        try:
            params = super(VersionedPanObject, self).__getattribute__("_params")
        except AttributeError:
            params = ()

        # Sanity check: there shouldn't be more args than params
        if len(args) > len(params):
            msg = 'Args "{0}" exceeds params "{1}"'
            raise ValueError(msg.format(args, params))

        # Set all params to their default values initially
        for param in params:
            param.value = param.default

        # Handle positional params
        for value, param in zip(args, params):
            param.value = value

        # Handle kwargs params
        for name, value in kwargs.items():
            for param in params:
                if param.name == name:
                    param.value = value
                    break
            else:
                raise ValueError('No param "{0}" exists'.format(name))

    def _setup(self):
        """Setup the object here.

        The setup includes configuring the following:

        * _xpaths
        * _xpath_imports (VsysOperations objects only)
        * _params
        * _stubs

        If you want this to have versioned parameters, be sure to
        set a `_params` variable here.  It should be a tuple of
        :class:`pandevice.base.VersionedParamPath` objects.

        """
        pass

    def _about_object(self):
        try:
            ans = dict((p.name, p.value) for p in self._params)
        except AttributeError:
            ans = {}
        finally:
            # If the object has a self.NAME, include that in the result
            if self.NAME is not None:
                ans[self.NAME] = self.uid

        return ans

    def _about_parameter(self, parameter):
        parameter = str(parameter)
        ans = {
            "Parameter": parameter,
            "Current Value": getattr(self, parameter, None),
        }

        # Make sure the param exists or raise AttributeError
        try:
            for param in self._params:
                if param.name == parameter:
                    break
            else:
                raise AttributeError
        except AttributeError:
            # Check if the parameter is the object's uid
            if parameter == self.NAME:
                ans["About"] = "This is the object's unique identifier"
                return ans
            else:
                raise AttributeError(parameter)

        version_info = []
        panos_version = self.retrieve_panos_version()

        if panos_version == self._UNKNOWN_PANOS_VERSION:
            # No parent, return all versioning info for this parameter
            version_info = []
            for version_number, var_path in param:
                version_info.append(var_path.about(version_number))
            ans["About"] = version_info
        else:
            # Display parameter's version specific info
            var_path = param._get_versioned_value(panos_version)
            if var_path:
                ans["About"] = var_path.about()
            else:
                ans["About"] = "No VarPath for this version"

        return ans

    def __dir__(self):
        """This is for tab-complete options."""
        ans = set([])

        # Get standard stuff:  methods and variables/properties
        try:
            ans.update(super(VersionedPanObject, self).__dir__())
        except AttributeError:
            # Get variables
            ans.update(self.__dict__.keys())
            # Get functions
            ans.update(dir(type(self)))

        # Get the _params stuff if it's present
        try:
            ans.update(x.name for x in self._params)
        except Exception:
            pass

        return list(ans)

    def _build_element_info(self):
        panos_version = self.retrieve_panos_version()
        settings = {}
        params = ()
        try:
            params = self._params
        except AttributeError:
            pass

        paths = []
        for param in params:
            settings[param.name] = param.value
            var_path = param._get_versioned_value(panos_version)
            if var_path:
                paths.append(var_path)

        stubs = []
        try:
            stubs = self._stubs._get_versioned_value(panos_version)
        except AttributeError:
            pass

        return (paths, stubs, settings)

    def element(self, with_children=True, comparable=False):
        """Return an xml.etree.ElementTree for this object and its children.

        Args:
            with_children (bool): Include the children objects.
            comparable (bool): Element will be used in a comparison with another.

        Returns:
            xml.etree.ElementTree for this object.

        """
        ans = self._root_element()
        paths, stubs, settings = self._build_element_info()

        iterchain = (
            (p.element(self._root_element(), settings, comparable) for p in paths),
            (s.element(self._root_element(), settings, comparable) for s in stubs),
        )
        if with_children:
            iterchain += (self._subelements(comparable),)

        self.xml_merge(ans, itertools.chain(*iterchain))

        # Now that the whole element is built, mixin an attrib vartypes.
        for p in paths:
            if p.vartype != "attrib":
                continue
            attrib_path = p.path.split("/")
            attrib_name = attrib_path.pop()
            attrib_value = settings[p.param]
            if attrib_value is None or p.exclude:
                continue
            e = ans
            find_path = [
                ".",
            ]
            for ap in attrib_path:
                if not ap:
                    continue
                if ap.startswith("entry "):
                    junk, var_to_use = ap.split()
                    sol_value = pandevice.string_or_list(settings[var_to_use])[0]
                    find_path.append("entry[@name='{0}']".format(sol_val))
                elif ap == "entry[@name='localhost.localdomain']":
                    find_path.append(ap)
                else:
                    find_path.append(ap.format(**settings))
            if len(find_path) > 1:
                e = e.find("/".join(find_path))
            if e is not None:
                e.attrib[attrib_name] = attrib_value

        return ans

    def equal(self, panobject, force=False, compare_children=True):
        """Compare this object to another object

        Equality of the objects is determined by the XML they generate, not by the
        values of their variables.

        Args:
            panobject (VersionedPanObject): The object to compare with this object
            force (bool): Do not raise a PanObjectError if the objects are different classes
            compare_children (bool): Include children of the PanObject in the comparison

        Raises:
            PanObjectError: Raised if the objects are different types that
                would not normally be comparable

        Returns:
            bool: True if the XML of the objects is equal, False if not

        """
        if not panobject:
            return False
        if type(self) != type(panobject) and not force:
            msg = "Object {0} is not compareable to {1}"
            raise err.PanObjectError(msg.format(self, panobject))

        xml_self = ET.tostring(self.element(compare_children, True), encoding="utf-8")
        xml_other = ET.tostring(
            panobject.element(compare_children, True), encoding="utf-8"
        )

        return xml_self == xml_other

    def _get_param_specific_info(self, param):
        """Gets a tuple of info for the given parameter.

        This is to aid in things like updates or refreshes of a specific
        parameter attached to this PanObject / VersionedPanObject.

        Returns:
            A three element tuple of the variable's xpath (str), the value of
            the variable, and the full ``VarPath`` or ``ParamPath`` object that
            is responsible for handling this variable.

        Raises:
            ValueError: If the param does not exist in this object.
            PanDeviceError: If the param does not exist in the XML.

        """
        paths, stubs, settings = self._build_element_info()
        value = settings[param]

        # Find the VarPath to use
        for var_path in paths:
            if var_path.param == param:
                break
        else:
            msg = "Variable {0} is not present in this version"
            raise ValueError(msg.format(param))

        # Build up the xpath
        xpath = []
        for token in var_path.path.split("/"):
            if not token:
                continue
            p = None
            if token.startswith("entry "):
                junk, var_to_use = token.split()
                p = "entry[name='{0}']".format(
                    *(x for x in self._value_as_list(settings[var_to_use]))
                )
            else:
                p = None
                try:
                    p = token.format(**{})
                except KeyError as ke:
                    param_ref = ke.args[0]
                    if settings[param_ref] is None:
                        msg = " ".join(
                            [
                                "While updating variable {0},",
                                "missing replacement variable {1} in path",
                            ]
                        )
                        raise ValueError(msg.format(param, param_ref))
                    p = token.format(**settings)
            xpath.append(p)

        return ("/".join(xpath), value, var_path)

    def parse_xml(self, xml):
        """Parse the given XML into this object's parameters.

        Args:
            xml (xml.etree.ElementTree): The XML to parse values from.

        """
        settings = {}
        panos_version = self.retrieve_panos_version()
        params = ()
        try:
            params = self._params
        except AttributeError:
            return

        # Build up the paths and the possibilities for each param.
        paths = []
        possibilities = {}
        for param in params:
            var_path = param._get_versioned_value(panos_version)
            if var_path:
                paths.append(var_path)
                if var_path.param and var_path.values:
                    possibilities[param.name] = var_path.values

        # Get the stubs and append those to the paths to parse as well.  We
        # do this because a stub could sometimes help us find the value of
        # another param that might not otherwise be present.
        stubs = []
        try:
            stubs = self._stubs._get_versioned_value(panos_version)
        except AttributeError:
            pass
        for stub in stubs:
            if stub:
                paths.append(stub)

        # Retrieve the uid (if applicable)
        if self.SUFFIX == ENTRY:
            setattr(self, self.NAME, xml.attrib["name"])

        # Parse out all VarPaths
        for var_path in paths:
            var_path.parse_xml(xml, settings, possibilities)

        # Save results from the settings dict
        for param in params:
            param.value = settings.get(param.name)

    def __getattr__(self, name):
        params = super(VersionedPanObject, self).__getattribute__("_params")

        for param in params:
            if name == param.name:
                return param.value

        raise AttributeError(str(name))

    def __setattr__(self, name, value):
        params = ()

        try:
            params = super(VersionedPanObject, self).__getattribute__("_params")
        except AttributeError:
            pass

        for param in params:
            if name == param.name:
                param.value = value
                break
        else:
            super(VersionedPanObject, self).__setattr__(name, value)

    @property
    def XPATH(self):
        """Returns the version specific xpath of this object."""
        panos_version = self.retrieve_panos_version()
        val = self._xpaths._get_versioned_value(panos_version, self.parent)
        return val.format(vsys=self.vsys or "vsys1")


class VersionedParamPath(VersioningSupport):
    """A wrapper class for ParamPath objects.

    Specifying any kwargs will be interpreted as args for the first profile to
    add for this parameter.  If there are no kwargs specified, then any version
    that may or may not have been passed in is ignored.

    The ``values`` stored in each profile added are the kwargs used to
    initialize the ``ParamPath`` object.  The ``name`` should not be specified,
    as that will be passed in positionally for you.

    Args:
        name (str): The parameter name.  Any hyphens in the name are replaced
            with underscores, as hyphens are not a valid variable character.
        default: The default value this parameter should take when the user
            is creating a ``VersionedPanObject``, but doesn't specify a value.
        version (str): A version string like '1.2.3' or None.  If the version
            is None, then the version is set to '0.0.0'.
        **kwargs: Various ``ParamPath`` parameters for the given version.

    """

    def __init__(self, name, default=None, version=None, **kwargs):
        super(VersionedParamPath, self).__init__()
        self.name = name.replace("-", "_")
        self.default = default
        self.value = None

        if kwargs:
            self.add_profile(version, **kwargs)

    def add_profile(self, version=None, **kwargs):
        """Add support for version ``version``.

        Args:
            version (str): The version to add support for.  If this is
                unspecified, then the version defaults to '0.0.0'.
            **kwargs: The various ``ParamPath`` arguments to use for the
                given version.  Note that if your kwargs do not contain
                a ``path``, then this means that the variable will only be
                present in the resulting XML if another ``VersionedParamPath``
                references this parameter in it's ``path``.

        """
        return super(VersionedParamPath, self).add_profile(version, kwargs)

    def _cast_version_value(self, value):
        if value is None:
            value = {}
        return ParamPath(self.name, **value)

    def __repr__(self):
        return "<{0} {1}={2} default={3} {4:#x}>".format(
            self.__class__.__name__, self.name, self.value, self.default, id(self)
        )


class ValueEntry(VersionedPanObject):
    """Base class for objects that only have a value element.

    """

    ROOT = Root.VSYS
    SUFFIX = ENTRY
    LOCATION = None

    def _setup(self):
        if self.LOCATION is None:
            raise Exception("{0}.LOCATION is unset".format(self.__class__))

        # xpath
        self._xpaths.add_profile(value=self.LOCATION)

        # params
        self._params = (VersionedParamPath("value", path="value"),)


class VarPath(object):
    """Configuration variable within the object

    Args:
        path (str): The relative xpath to the variable
        variable (str): The name of the instance variable in the class
        vartype (str): The type of variable (None, 'member', 'entry', 'bool', 'int', 'exist', 'none')
        default: The default value if no value is specified during __init__ of the object
        xmldefault (bool): The default value if no value exists in the xml from a device
        condition (str): In the format othervariable:value where this variable is only
            considered if othervariable equals value
        order (int): The order of this variable relative to other variables in this constructor of the
            class that contains this variables. Defaults to 100, set variable order to less than or
            greater than 100 to alter the order of the variables.

    """

    def __init__(
        self,
        path,
        variable=None,
        vartype=None,
        default=None,
        xmldefault=None,
        condition=None,
        order=100,
    ):
        self.path = path
        self.vartype = vartype
        self.default = default
        self.xmldefault = xmldefault
        self.condition = condition
        self.order = order

        if variable is None:
            self.variable = self.path.rsplit("/", 1)[-1].replace("-", "_")
        else:
            self.variable = variable

    def __repr__(self):
        return "<%s %s at 0x%x>" % (type(self).__name__, repr(self.variable), id(self))

    def about(self):
        """Returns information about this VarPath as a dict."""
        return {
            "Type": self.vartype or "string",
            "Condition": self.condition,
            "Default": self.default,
            "XML Path": self.path,
        }

    def _set_inner_xml_tag_text(self, elm, value, comparable=False):
        """Sets the final elm's .text as appropriate given the vartype.

        Args:
            elm (xml.etree.ElementTree.Element): The element whose .text to set.
            value (various): The value to put in the .text, conforming to the vartype of this parameter.
            comparable (bool): Make updates for element string comparisons.  For entry and member vartypes, sort the entries (True) or leave them as-is (False).

        """
        # Create an element containing the value in the instance variable
        if self.vartype == "member":
            values = pandevice.string_or_list(value)
            if comparable:
                values = sorted(values)
            for member in values:
                ET.SubElement(elm, "member").text = str(member)
        elif self.vartype == "entry":
            values = pandevice.string_or_list(value)
            if comparable:
                values = sorted(values)
            for entry in values:
                ET.SubElement(elm, "entry", {"name": str(entry)})
        elif self.vartype == "exist":
            if value:
                ET.SubElement(elm, self.variable)
        elif self.vartype == "bool":
            elm.text = yesno(value)
        elif self.path.find("|") != -1:
            # This is an element variable,
            # it has already been created
            # so do nothing
            pass
        elif self.vartype == "none":
            # There is no variable, so don't try to populate it
            pass
        else:
            elm.text = str(value)


class ParamPath(object):
    """Configuration parameter within the object.

    Args:
        param (str): The name of the instance parameter in the class
        path: The relative xpath to the variable.
        vartype: The type of variable (None, 'member', 'entry', 'yesno',
            'int', 'exist').
        condition (dict): Other settings that must be true for this param
            to appear in the XML.  The keys of the condition should be other
            parameter names, with the value being what the necessary value of
            that parameter should be.
        values (list): Valid values this param can be set to.  This is not
            enforced in any way from the user's perspective when setting
            parameters, but these values are referenced when parsing any XML
            returned from a live device.
        exclude (bool): Exclude this param from the resultant XML.

    """

    def __init__(
        self, param, path=None, vartype=None, condition=None, values=None, exclude=False
    ):
        self.param = param
        self.path = path
        self.vartype = vartype
        self.condition = condition or {}
        self.values = values or []
        self.exclude = exclude

        if self.path is None:
            self.path = self.param.replace("_", "-")

    def about(self, version_header=None):
        """Returns information about this ParamPath as a dict."""
        info = {
            "Type": self.vartype or "string",
            "Values": self.values,
            "Condition": self.condition,
            "XML Path": self.path,
        }

        if version_header is not None:
            info["Versioning"] = version_header

        return info

    def __repr__(self):
        return "<{0} '{1}' at {2:#x}>".format(
            self.__class__.__name__, self.param, id(self)
        )

    def _value_as_list(self, value):
        if isstring(value):
            yield value
        elif hasattr(value, "__iter__"):
            for v in value:
                yield str(v)
        else:
            yield str(value)

    def element(self, elm, settings, comparable=False):
        """Create the xml.etree.ElementTree for this parameter.

        Args:
            elm (xml.etree.ElementTree): the root node for which to append
                onto this param's XML.
            settings (dict): All parameter settings for the
                ``VersionedPanObject``.
            comparable (bool): Make necessary adjustments to the XML for comparison's sake.

        Returns:
            xml.etree.ElementTree: The ``elm`` passed in, modified to contain
            this parameter in the XML.  If this param should not be contained
            in the full ``VersionedPanObject``'s XML, then None is returned.

        """
        value = settings.get(self.param)

        # Check if this should return None instead of an element
        if self.exclude:
            return None
        elif self.vartype == "attrib":
            return None
        elif value is None and self.vartype != "stub":
            return None
        for condition_key, condition_value in self.condition.items():
            try:
                if settings[condition_key] not in condition_value:
                    return None
            except TypeError:
                if settings[condition_key] != condition_value:
                    return None
            except KeyError:
                # This condition references a param that does not exist and it is
                # thus not needed
                return None

        e = elm
        # Build the element
        tokens = self.path.split("/")
        if self.vartype == "exist":
            del tokens[-1]
        for token in tokens:
            if not token:
                continue
            if token.startswith("entry "):
                junk, var_to_use = token.split()
                sol_val = pandevice.string_or_list(settings[var_to_use])[0]
                child = ET.Element("entry", {"name": str(sol_val)})
            elif token == "entry[@name='localhost.localdomain']":
                child = ET.Element("entry", {"name": "localhost.localdomain"})
            else:
                child = ET.Element(token.format(**settings))
                if child.tag == "None":
                    return None
            e.append(child)
            e = child

        self._set_inner_xml_tag_text(e, value, comparable)

        return elm

    @staticmethod
    def _sha1_hash(string):
        # Check if this string is cleartext or encrypted
        if string.startswith("-"):
            # Get sha1 part of encrypted string
            return string[5:33]
        else:
            # Sha1 hash the cleartext value
            # Python3:  encode for sha1, decode for XML serialization.
            sha1 = hashlib.sha1(string.encode("utf-8"))
            return base64.b64encode(sha1.digest()).decode("utf-8")

    def parse_xml(self, xml, settings, possibilities):
        """Parse the XML to find this parameter's value.

        Both this parameter, and any other parameters that may be discovered
        during the parsing of this parameter, will be saved in the ``settings``
        dict passed in to this function.

        Args:
            xml (xml.etree.ElementTree): The XML to parse.
            settings (dict): Current known values for this object's parameters.
            possibilities (dict): A dict where the key is a parameter's name,
                and the value is a list of strings that that param could be
                in the XML.

        """
        if not self.path:
            # No path, so this is just a parameter ParamPath
            return

        # Check that conditional is met
        for condition_key, condition_value in self.condition.items():
            try:
                if settings[condition_key] not in condition_value:
                    return
            except TypeError:
                if settings[condition_key] != condition_value:
                    return
            except KeyError:
                # This condition references a param that does not exist and it is
                # thus not needed
                return None

        e = xml
        tokens = self.path.split("/")
        if self.vartype == "exist":
            del tokens[-1]
        for p in tokens:
            # Skip this path part if there is no path part
            if not p:
                continue

            path_str = None
            if p.startswith("entry "):
                # Entry path part
                entry_var = p.split()[1]
                if entry_var not in settings:
                    # Entry's name is not yet known, try to find it
                    ans = e.find("./entry")
                    if ans is None:
                        return
                    settings[entry_var] = ans.attrib["name"]
                sol_val = pandevice.string_or_list(settings[entry_var])[0]
                path_str = "entry[@name='{0}']".format(sol_val)
            else:
                # Standard path part
                try:
                    # If we don't have all the settings necessary to format
                    # this string, a KeyError will be raised
                    path_str = p.format(**settings)
                except KeyError as ke:
                    # Missing a parameter's setting, check all of that param's
                    # possibilities against the XML to see which one it is
                    missing_variable = ke.args[0]
                    if missing_variable not in possibilities:
                        return
                    possibility_settings = settings.copy()
                    for pos in possibilities[missing_variable]:
                        possibility_settings[missing_variable] = pos
                        path_str = p.format(**possibility_settings)
                        ans = e.find("./{0}".format(path_str))
                        if ans is not None:
                            settings[missing_variable] = pos
                            break
                    else:
                        return

            ans = e.find("./{0}".format(path_str))
            if ans is None:
                return
            e = ans

        # Pull the value, properly formatted, from this last element
        self.parse_value_from_xml_last_tag(e, settings)

    def _set_inner_xml_tag_text(self, elm, value, comparable=False):
        """Sets the final elm's .text as appropriate given the vartype.

        Args:
            elm (xml.etree.ElementTree.Element): The element whose .text to set.
            value (various): The value to put in the .text, conforming to the vartype of this parameter.
            comparable (bool): Make updates for element string comparisons.  For encrypted fields, if the text should be set to a password hash (True) or left as a basestring (False).  For entry and member vartypes, sort the entries (True) or leave them as-is (False).

        """
        # Format the element text appropriately
        if self.vartype == "member":
            values = self._value_as_list(value)
            if comparable:
                values = sorted(values)
            for v in values:
                ET.SubElement(elm, "member").text = v
        elif self.vartype == "entry":
            values = self._value_as_list(value)
            if comparable:
                values = sorted(values)
            for v in values:
                ET.SubElement(elm, "entry", {"name": v})
        elif self.vartype == "exist":
            if value:
                exist_tag = self.path.split("/")[-1]
                ET.SubElement(elm, exist_tag)
        elif self.vartype == "yesno":
            elm.text = "yes" if value else "no"
        elif (
            self.vartype == "stub"
            or "{{{0}}}".format(self.param) == self.path.split("/")[-1]
        ):
            pass
        elif self.vartype == "int":
            elm.text = str(int(value))
        elif self.vartype == "encrypted" and comparable:
            elm.text = self._sha1_hash(str(value))
        else:
            elm.text = str(value)

    def parse_value_from_xml_last_tag(self, elm, settings):
        """Actually do the parsing for this parameter.

        The value parsed is saved into the ``settings`` dict.

        Args:
            elm (xml.etree.ElementTree): The final (deepest) tag in the XML
                document passed in to ``parse_xml()`` that contains the actual
                value to parse out for this parameter.
            settings (dict): The dict where the parsed value will be saved.

        Raises:
            ValueError: If a param is in an incorrect format.

        """
        # Do vartype processing
        if self.vartype == "member":
            settings[self.param] = [x.text for x in elm.findall("member")]
        elif self.vartype == "entry":
            settings[self.param] = [x.attrib["name"] for x in elm.findall("entry")]
        elif self.vartype == "exist":
            exist_tag = self.path.split("/")[-1]
            ans = elm.find("./{0}".format(exist_tag))
            settings[self.param] = True if ans is not None else False
        elif self.vartype == "yesno":
            if elm.text == "yes":
                settings[self.param] = True
            elif elm.text == "no":
                settings[self.param] = False
            else:
                raise ValueError('{0} "{1}" is not yes/no'.format(self.param, elm.text))
        elif (
            self.vartype == "stub"
            or "{{{0}}}".format(self.param) == self.path.split("/")[-1]
        ):
            pass
        elif self.vartype == "int":
            settings[self.param] = int(elm.text)
        else:
            settings[self.param] = elm.text


class VsysOperations(VersionedPanObject):
    """Modify PanObject methods to set vsys import configuration."""

    CHILDMETHODS = ("create", "apply", "delete")
    ALWAYS_IMPORT = False

    def __init__(self, *args, **kwargs):
        self._xpath_imports = ParentAwareXpath()
        super(VsysOperations, self).__init__(*args, **kwargs)

    @property
    def XPATH_IMPORT(self):
        """Returns the version specific xpath import for this object."""
        panos_version = self.retrieve_panos_version()
        return self._xpath_imports._get_versioned_value(panos_version, self.parent)

    def create(self):
        super(VsysOperations, self).create()
        self.child_create()

    def apply(self):
        super(VsysOperations, self).apply()
        self.child_apply()

    def delete(self):
        self.child_delete()
        super(VsysOperations, self).delete()

    def child_create(self):
        return self._create_apply_child()

    def child_apply(self):
        return self._create_apply_child()

    def _create_apply_child(self):
        # Remove vsys import if this object has an interface in ha or ag mode
        if str(getattr(self, "mode", None)) in ("ha", "aggregate-group"):
            self.set_vsys(None, refresh=True, update=True)
        elif self.ALWAYS_IMPORT and self.vsys is None:
            self.create_import("vsys1")
        else:
            self.create_import()

    def child_delete(self):
        if self.ALWAYS_IMPORT and self.vsys is None:
            self.delete_import("vsys1")
        else:
            self.delete_import()

    def create_import(self, vsys=None):
        """Create a vsys import for the object

        Args:
            vsys (str): Override the vsys

        """
        if vsys is None:
            vsys = self.vsys

        # There are no vsys imports in template stacks.
        p = self
        while p is not None:
            if p.__class__.__name__ == "TemplateStack":
                return
            p = p.parent

        if vsys != "shared" and vsys is not None and self.XPATH_IMPORT is not None:
            xpath = self.xpath_import_base(vsys)
            element = "<member>{0}</member>".format(self.uid)
            device = self.nearest_pandevice()
            device.active().xapi.set(xpath, element, retry_on_peer=True)

    def xpath_import_base(self, vsys=None):
        template = ""
        p = self
        while p is not None:
            if p.__class__.__name__ in ("Template", "TemplateStack"):
                template = p.xpath()
                break
            p = p.parent

        vsys_xpath = self._root_xpath_vsys(vsys or self.vsys or "vsys1")
        return "{0}{1}/import{2}".format(template, vsys_xpath, self.XPATH_IMPORT)

    def delete_import(self, vsys=None):
        """Delete a vsys import for the object

        Args:
            vsys (str): Override the vsys

        """
        if vsys is None:
            vsys = self.vsys

        # There are no vsys imports in template stacks.
        p = self
        while p is not None:
            if p.__class__.__name__ == "TemplateStack":
                return
            p = p.parent

        if vsys != "shared" and vsys is not None and self.XPATH_IMPORT is not None:
            xpath = "{0}/member[text()='{1}']".format(
                self.xpath_import_base(vsys), self.uid
            )
            device = self.nearest_pandevice()
            device.active().xapi.delete(xpath, retry_on_peer=True)

    def set_vsys(
        self,
        vsys_id,
        refresh=False,
        update=False,
        running_config=False,
        return_type="object",
    ):
        """Set the vsys for this interface.

        Creates a reference to this interface in the specified vsys and
        removes references to this interface from all other vsys. The vsys
        will be created if it doesn't exist.

        Args:
            vsys_id (str): The vsys id to set for this object (eg. vsys2)
            refresh (bool): Refresh the relevant current state of the device
                before taking action (Default: False)
            update (bool): Apply the changes to the device (Default: False)
            running_config (bool): If refresh is True, refresh from the running
                configuration (Default: False)
            return_type (str): Specify what this function returns, can be
                either 'object' (the default) or 'bool'.  If this is 'object',
                then the return value is the device.Vsys in question.  If
                this is 'bool', then the return value is a boolean that tells
                you about if the live device needs updates (update=False) or
                was updated (update=True).

        Returns:
            Vsys: The vsys for this interface after the operation completes

        """
        if refresh and running_config:
            msg = "Can't refresh vsys from running config in set_vsys"
            raise ValueError(msg)

        # Don't import HA or aggregate-group interfaces.
        if getattr(self, "mode", "") in ("ha", "aggregate-group"):
            return False

        # There are no vsys imports in template stacks.
        p = self
        while p is not None:
            if p.__class__.__name__ == "TemplateStack":
                if return_type == "bool":
                    return False
                return
            p = p.parent

        import_to_vsys_param = {
            "vlan": "vlans",
            "virtual-wire": "virtual_wires",
            "virtual-router": "virtual_routers",
            "interface": "interface",
        }
        for key, param_name in import_to_vsys_param.items():
            if self.XPATH_IMPORT.endswith("/{0}".format(key)):
                break
        else:
            raise ValueError("Unknown import type: {0}".format(self.XPATH_IMPORT))

        from pandevice.device import Vsys

        return self._set_reference(
            vsys_id,
            Vsys,
            param_name,
            "list",
            True,
            refresh,
            update,
            running_config,
            return_type,
            True,
        )

    @classmethod
    def refreshall(
        cls,
        parent,
        running_config=False,
        add=True,
        exceptions=False,
        name_only=False,
        matching_vsys=True,
    ):
        instances = super(VsysOperations, cls).refreshall(
            parent,
            running_config,
            add=False,
            exceptions=exceptions,
            name_only=name_only,
        )

        if not matching_vsys:
            return instances

        # Versioned objects need a PanDevice to get the version from, so
        # set the child's parent before accessing XPATH.
        class_instance = cls()
        class_instance.parent = parent

        # Filter out instances that are not in this vsys's imports
        device = parent.nearest_pandevice()
        api_action = device.xapi.show if running_config else device.xapi.get
        if (
            parent.vsys != "shared"
            and parent.vsys is not None
            and class_instance.XPATH_IMPORT is not None
        ):
            imports = []
            xpath = class_instance.xpath_import_base()
            try:
                imports_xml = api_action(xpath, retry_on_peer=True)
            except (err.PanNoSuchNode, pan.xapi.PanXapiError) as e:
                if not str(e).startswith("No such node"):
                    raise e
            else:
                imports = imports_xml.findall(".//member")
                if imports is not None:
                    imports = [member.text for member in imports]

            if imports is not None:
                instances = [
                    instance for instance in instances if instance.name in imports
                ]

        if add:
            # Remove current children of this type from parent
            parent.removeall(cls=cls)
            # Add the new children that were just refreshed from the device
            parent.extend(instances)

        return instances


class PanDevice(PanObject):
    """A Palo Alto Networks device

    The device can be of any type (currently supported devices are firewall,
    or panorama). The class handles common device functions that apply
    to all device types.

    Usually this class is not instantiated directly. It is the base class for a
    firewall.Firewall object or a panorama.Panorama object.

    Args:
        hostname: Hostname or IP of device for API connections
        api_username: Username of administrator to access API
        api_password: Password of administrator to access API
        api_key: The API Key for connecting to the device's API
        port: Port of device for API connections
        is_virtual (bool): Physical or Virtual firewall
        timeout: The timeout for asynchronous jobs
        interval: The interval to check asynchronous jobs

    Attributes:
        ha_peer (PanDevice): The HA peer device of this PanDevice

    """

    NAME = "hostname"

    def __init__(
        self,
        hostname,
        api_username=None,
        api_password=None,
        api_key=None,
        port=443,
        is_virtual=None,
        timeout=1200,
        interval=0.5,
        *args,
        **kwargs
    ):
        """Initialize PanDevice"""
        super(PanDevice, self).__init__(*args, **kwargs)
        # create a class logger
        self._logger = pandevice.getlogger(__name__ + "." + self.__class__.__name__)

        self.hostname = hostname
        self.port = port
        self._api_username = api_username
        self._api_password = api_password
        self._api_key = api_key
        self.is_virtual = is_virtual
        self.timeout = timeout
        self.interval = interval
        self.serial = None
        self._xapi_private = None
        self.config_locked = False
        self.commit_locked = False
        self.lock_before_change = False
        self.shared_lock_before_change = False
        self.config_changed = []

        # Create a PAN-OS updater subsystem
        self.software = updater.SoftwareUpdater(self)
        # Create a content updater subsystem
        self.content = updater.ContentUpdater(self)

        # State variables
        self.version = None
        self._version_info = None
        self.content_version = None
        self.platform = None

        # HA Pair Firewall or Panorama
        self._ha_peer = None
        self._ha_active = True
        self.ha_failed = None

        # Create a User-ID subsystem
        self.userid = userid.UserId(self)
        """User-ID subsystem

        See Also: :class:`pandevice.userid`

        """

        # create a predefined object subsystem
        # avoid a premature import
        from pandevice import predefined

        self.predefined = predefined.Predefined(self)
        """Predefined object subsystem

        See Also: :class:`pandevice.predefined`

        """

    def get_device_version(self):
        """Gets the current version on the PanDevice."""
        # If it's already known, return the version info
        if self._version_info is not None:
            return self._version_info

        # If the version is unknown but we have an API key, get the version
        # from the device.
        if self._api_key is not None:
            self.refresh_system_info()
            return self._version_info

        # The version is unknown and there is not yet an API key, so there
        # is no permission to touch the live device yet.
        raise err.PanApiKeyNotSet("Please retrieve an API KEY first.")

    @classmethod
    def create_from_device(
        cls, hostname, api_username=None, api_password=None, api_key=None, port=443,
    ):
        """Factory method to create a :class:`pandevice.firewall.Firewall`
        or :class:`pandevice.panorama.Panorama` object from a live device

        Connects to the device and detects its type and current state
        in order to create a PanDevice subclass.

        Args:
            hostname: Hostname or IP of device for API connections
            api_username: Username of administrator to access API
            api_password: Password of administrator to access API
            api_key: The API Key for connecting to the device's API
            port: Port of device for API connections

        Returns:
            PanDevice: New subclass instance (Firewall or Panorama instance)

        """
        # Create generic PanDevice to connect and get information
        from pandevice import firewall, panorama

        device = PanDevice(hostname, api_username, api_password, api_key, port,)
        system_info = device.refresh_system_info()
        version = system_info[0]
        model = system_info[1]
        if model == "Panorama" or model.startswith("M-"):
            instance = panorama.Panorama(
                hostname, api_username, api_password, device.api_key, port,
            )
        else:
            serial = system_info[2]
            instance = firewall.Firewall(
                hostname, api_username, api_password, device.api_key, serial, port,
            )
        instance._set_version_and_version_info(version)
        return instance

    class XapiWrapper(pan.xapi.PanXapi):
        # This is a confusing class used for catching exceptions and faults.
        # TODO: comment this class

        CONNECTION_EXCEPTIONS = (
            err.PanConnectionTimeout,
            err.PanURLError,
            err.PanOutdatedSslError,
            err.PanSessionTimedOut,
        )

        def __init__(self, *args, **kwargs):
            self.pan_device = kwargs.pop("pan_device", None)
            pan.xapi.PanXapi.__init__(self, *args, **kwargs)
            pred = lambda x: inspect.ismethod(x) or inspect.isfunction(
                x
            )  # inspect.ismethod needed for Python2, inspect.isfunction needed for Python3
            for name, method in inspect.getmembers(pan.xapi.PanXapi, pred):
                # Ignore hidden methods
                if name[0] == "_":
                    continue
                # Ignore non-api methods
                if name in ("xml_result", "xml_root", "cmd_xml"):
                    continue

                # Wrapper method.  This is used to create
                # methods in this class that match the methods in the
                # super class, and call the super class methods inside
                # a try/except block, which allows us to check and
                # analyze the exceptions and convert them to more
                # useful exceptions than generic PanXapiErrors.
                wrapper_method = PanDevice.XapiWrapper.make_method(name, method)

                # Create method matching each public method of the base class
                setattr(PanDevice.XapiWrapper, name, wrapper_method)

        @classmethod
        def make_method(cls, super_method_name, super_method):
            def method(self, *args, **kwargs):
                retry_on_peer = kwargs.pop(
                    "retry_on_peer",
                    True
                    if super_method_name not in ("keygen", "op", "ad_hoc", "export")
                    else False,
                )
                apply_on_peer = kwargs.pop("apply_on_peer", False)
                ha_peer = self.pan_device.ha_peer
                # Check if apply to both devices
                # Note: An exception will not be raised if one device could not be accessed
                # An exception will be raised on other errors on either device, or if both
                # devices could not be accessed.
                if apply_on_peer:
                    # Apply to peer first
                    connection_failures = 0
                    if ha_peer is not None and not ha_peer.ha_failed:
                        try:
                            kwargs["retry_on_peer"] = False
                            result = getattr(ha_peer.xapi, super_method_name)(
                                *args, **kwargs
                            )
                        except pan.xapi.PanXapiError as e:
                            the_exception = self.classify_exception(e)
                            if type(the_exception) in self.CONNECTION_EXCEPTIONS:
                                # passive firewall connection failed
                                connection_failures += 1
                            else:
                                raise the_exception
                    if not self.pan_device.ha_failed:
                        try:
                            super_method(self, *args, **kwargs)
                            result = copy.deepcopy(self.element_root)
                        except pan.xapi.PanXapiError as e:
                            the_exception = self.classify_exception(e)
                            if type(the_exception) in self.CONNECTION_EXCEPTIONS:
                                # passive firewall connection failed
                                connection_failures += 1
                            else:
                                raise the_exception

                elif (
                    self.pan_device.ha_failed
                    and ha_peer is not None
                    and not ha_peer.ha_failed
                    and retry_on_peer
                ):
                    # This device is failed, use the other
                    logger.debug("Current device is failed, starting with other device")
                    kwargs["retry_on_peer"] = True
                    result = getattr(ha_peer.xapi, super_method_name)(*args, **kwargs)
                elif (
                    not self.pan_device.is_active()
                    and ha_peer is not None
                    and retry_on_peer
                ):
                    # I'm not active, call the peer
                    kwargs["retry_on_peer"] = True
                    result = getattr(ha_peer.xapi, super_method_name)(*args, **kwargs)
                    # Copy result from peer xapi to this xapi
                    result_vars = (
                        "status",
                        "status_detail",
                        "status_code",
                        "element_root",
                        "element_result",
                        "export_result",
                        "xml_document",
                        "text_document",
                    )
                    for var in result_vars:
                        setattr(self, var, getattr(ha_peer.xapi, var))
                else:
                    try:
                        # This device has not failed, or both have failed
                        # and this device is active
                        # First get the superclass method
                        super_method(self, *args, **kwargs)
                        result = copy.deepcopy(self.element_root)
                    except pan.xapi.PanXapiError as e:
                        the_exception = self.classify_exception(e)
                        if type(the_exception) in self.CONNECTION_EXCEPTIONS:
                            # The attempt on the active failed with a connection error
                            new_active = self.pan_device.set_failed()
                            if retry_on_peer and new_active is not None:
                                logger.debug(
                                    "Connection to device '%s' failed, using HA peer '%s'"
                                    % (self.pan_device.id, new_active.hostname)
                                )
                                # The active failed, apply on passive (which is now active)
                                kwargs["retry_on_peer"] = False
                                getattr(new_active.xapi, super_method_name)(
                                    *args, **kwargs
                                )
                                result = copy.deepcopy(new_active.xapi.element_root)
                            else:
                                raise the_exception
                        else:
                            raise the_exception
                return result

            return method

        def classify_exception(self, e):
            if str(e) == "Invalid credentials.":
                return err.PanInvalidCredentials(str(e), pan_device=self.pan_device,)
            elif str(e).startswith("URLError:"):
                if str(e).endswith("timed out"):
                    return err.PanConnectionTimeout(str(e), pan_device=self.pan_device,)
                else:
                    # This could be that we have an old version of OpenSSL
                    # that doesn't support TLSv1.1, so check for that and give
                    # a more explicit error if so.
                    if (
                        str(e)
                        == "URLError: reason: [Errno 54] Connection reset by peer"
                    ):
                        min_openssl_version = ["1", "0", "1"]
                        help_url = "http://pandevice.readthedocs.io/en/latest/usage.html#connecting-to-pan-os-8-0"
                        try:
                            # Examples:
                            #   OpenSSL 1.0.2j  26 Sep 2016
                            #   OpenSSL 0.9.8zh 14 Jan 2016
                            import ssl

                            vs = ssl.OPENSSL_VERSION.split()[1].split(".")
                        except (ImportError, IndexError):
                            pass
                        else:
                            if vs < min_openssl_version:
                                msg = " ".join(
                                    (
                                        "You are attempting to connect to PANOS",
                                        "8.0 or higher with an outdated OpenSSL",
                                        "library({0}). Please update to OpenSSL",
                                        "{1} or higher. Refer to the following",
                                        "URL for more information: {2}",
                                    )
                                )
                                return err.PanOutdatedSslError(
                                    msg.format(
                                        ssl.OPENSSL_VERSION,
                                        ".".join(min_openssl_version),
                                        help_url,
                                    ),
                                    pan_device=self.pan_device,
                                )

                    return err.PanURLError(str(e), pan_device=self.pan_device)

            elif str(e).startswith("timeout waiting for job"):
                return err.PanJobTimeout(str(e), pan_device=self.pan_device)

            elif str(e).startswith(
                "Another commit/validate is in" " progress. Please try again later"
            ):
                return err.PanCommitInProgress(str(e), pan_device=self.pan_device)

            elif str(e).startswith("A commit is in progress."):
                return err.PanCommitInProgress(str(e), pan_device=self.pan_device)

            elif str(e).startswith(
                "You cannot commit while an install is in progress. Please try again later."
            ):
                return err.PanInstallInProgress(str(e), pan_device=self.pan_device)

            elif str(e).startswith("Session timed out"):
                return err.PanSessionTimedOut(str(e), pan_device=self.pan_device)

            elif str(e).startswith("No such node"):
                return err.PanNoSuchNode(str(e), pan_device=self.pan_device)
            elif str(e).startswith(
                "Failed to synchronize running configuration with HA peer"
            ):
                return err.PanHAConfigSyncFailed(str(e), pan_device=self.pan_device)
            elif str(e).startswith("Configuration is locked by"):
                return err.PanLockError(str(e), pan_device=self.pan_device)
            elif str(e).startswith(
                "Another sync is in progress. Please try again later"
            ):
                return err.PanHASyncInProgress(str(e), pan_device=self.pan_device)
            else:
                return err.PanDeviceXapiError(str(e), pan_device=self.pan_device)

    # Properties

    @property
    def id(self):
        return str(getattr(self, self.NAME, "<no-id>"))

    @property
    def api_key(self):
        if self._api_key is None:
            self._api_key = self._retrieve_api_key()
        return self._api_key

    @property
    def xapi(self):
        if self._xapi_private is None:
            self._xapi_private = self.generate_xapi()
        return self._xapi_private

    def op(
        self,
        cmd=None,
        vsys=None,
        xml=False,
        cmd_xml=True,
        extra_qs=None,
        retry_on_peer=False,
    ):
        """Perform operational command on this device

        Args:
            cmd (str): The operational command to execute
            vsys (str): Vsys id.
            xml (bool): Return value should be a string (Default: False)
            cmd_xml (bool): True: cmd is not XML, False: cmd is XML (Default: True)
            extra_qs: Extra parameters for API call
            retry_on_peer (bool): Try on active Firewall first, then try on passive Firewall

        Returns:
            xml.etree.ElementTree: The result of the operational command. May also return a string of XML if xml=True

        """
        element = self.xapi.op(
            cmd, vsys, cmd_xml, extra_qs, retry_on_peer=retry_on_peer
        )
        if xml:
            return ET.tostring(element, encoding="utf-8")
        else:
            return element

    def update_connection_method(self):
        """Regenerate the xapi object used to connect to the device

        This is only necessary if the API key, password, hostname, or other
        connectivity information in this object has changed. In this case,
        the xapi object used to communicate with the firewall must be regenerated
        to use the new connectivity information.

        The new xapi is stored in the PanDevice object and returned.

        Returns:
            XapiWrapper: The xapi object which is also stored in self.xapi.

        """
        self._xapi_private = self.generate_xapi()
        return self._xapi_private

    def generate_xapi(self):
        kwargs = {
            "api_key": self.api_key,
            "hostname": self.hostname,
            "port": self.port,
            "timeout": self.timeout,
            "pan_device": self,
        }
        xapi_constructor = PanDevice.XapiWrapper
        return xapi_constructor(**kwargs)

    def set_config_changed(self, scope=None):
        """Set flag that configuration of this device has changed

        This is useful for checking if a commit is necessary by knowing
        if the configuration was actually changed. This method is already
        used by every pandevice package method that makes a configuration
        change. But this method could also by run directly to force
        a 'dirty' configuration state in a PanDevice object.

        Args:
            scope: vsys in which configuration was changed, or 'shared'

        """
        # TODO: enhance to support device-group and template scope
        if scope is None:
            scope = getattr(self, "vsys", None)
        if scope is None:
            scope = "shared"
        if self.lock_before_change:
            if not self.config_locked:
                self.add_config_lock(scope=scope, exceptions=True)
        elif self.shared_lock_before_change:
            if not self.config_locked:
                self.add_config_lock(scope="shared", exceptions=True)
        if scope not in self.config_changed:
            self.config_changed.append(scope)

    def _build_xpath(self, root, vsys):
        return self.xpath_root(root, vsys or self.vsys)

    def xpath_root(self, root_type, vsys, label="vsys"):
        if root_type == Root.DEVICE:
            xpath = self.xpath_device()
        elif root_type == Root.VSYS:
            xpath = self._root_xpath_vsys(vsys, label)
        elif root_type == Root.MGTCONFIG:
            xpath = self.xpath_mgtconfig()
        elif root_type == Root.PANORAMA:
            xpath = self.xpath_panorama()
        else:
            xpath = self.XPATH
        return xpath

    def xpath_mgtconfig(self):
        return "/config/mgt-config"

    def xpath_device(self):
        return "/config/devices/entry[@name='localhost.localdomain']"

    def xpath_vsys(self):
        raise NotImplementedError

    def xpath_panorama(self):
        raise NotImplementedError

    def _retrieve_api_key(self):
        """Return an API key for a username and password

        Given a username and password, return the API key of that user for
        this PAN Device. The username and password are not stored, and the
        API key is returned.  It is up to the caller to store it in an
        instance variable if desired.

        Returns:
            A string containing the API key

        """
        self._logger.debug(
            "Getting API Key from %s for user %s" % (self.hostname, self._api_username)
        )
        xapi = PanDevice.XapiWrapper(
            pan_device=self,
            api_username=self._api_username,
            api_password=self._api_password,
            hostname=self.hostname,
            port=self.port,
            timeout=self.timeout,
        )
        xapi.keygen(retry_on_peer=False)
        return xapi.api_key

    def devices(self):
        return self

    def show_system_info(self):
        root = self.xapi.op(cmd="show system info", cmd_xml=True)
        pconf = PanConfig(root)
        system_info = pconf.python()
        return system_info["response"]["result"]

    def refresh_system_info(self):
        """Refresh system information variables.

        Variables refreshed:

        - version
        - platform
        - serial
        - multi_vsys (if this is a :class:`pandevice.firewall.Firewall`)

        Returns:
            namedtuple: version, platform, serial
        """
        #       This section is commented because version api cannot be targeted
        #       on Panorama.  When this feature is added, ok to uncomment this.
        # try:
        #    # For PANOS >= 7.1, this is faster than the op command.
        #    ans = self.xapi.ad_hoc('type=version', modify_qs=True)
        # except err.PanDeviceXapiError as e:
        #    # If this is an error other than "version" isn't supported,
        #    # reraise the exception.
        #    if str(e) != 'Illegal value for parameter "type" [version].':
        #        raise
        #
        #    # Otherwise, this is PANOS < 7.1, so do the (slower) op command.
        #    system_info = self.show_system_info()
        # else:
        #    # The `show_system_info()` returns way more information than
        #    # `refresh_system_info()` cares about, so to share the same parsing
        #    # code, we'll create our own dict to pass `_save_system_info()`
        #    # that contains the keys we care about.  Doing the above
        #    # `xapi.ad_hoc()` returns the things we care about, both for
        #    # panorama and the firewall's cases, so we don't need to do any
        #    # extra processing or tweaking than just formatting the response.
        #    system_info = {'system': {}}
        #    for e in ans.find('./result'):
        #        system_info['system'][e.tag] = e.text

        system_info = self.show_system_info()

        # Save the system info to this object
        self._save_system_info(system_info)

        # Return the important fields as a namedtuple
        SystemInfo = collections.namedtuple(
            "SystemInfo", ["version", "platform", "serial"]
        )

        return SystemInfo(self.version, self.platform, self.serial)

    def _save_system_info(self, system_info):
        """Save information about the PanDevice to the object itself.

        This function has a few purposes:
            * Save the PANOS version so that we can make versioning decisions
            * Save the platform
            * Save the serial number

        Subclasses may super() this function to get the shared functionality,
        then save anything specific to them.

        Args:
            system_info (dict): A dict of system info passed from the
                "refresh_system_info()" function.
        """
        self._set_version_and_version_info(system_info["system"]["sw-version"])
        self.platform = system_info["system"]["model"]
        self.serial = system_info["system"]["serial"]

    def _set_version_and_version_info(self, version):
        """Sets the version and the specially formatted versioning version."""
        self.version = version
        # Example PAN-OS versions:  9.0.3-h1, 9.0.3.xfr
        tokens = self.version.split(".")[:3]
        tokens[2] = tokens[2].split("-")[0]
        self._version_info = tuple(int(x) for x in tokens)

    def refresh_version(self):
        """Refresh version of PAN-OS

        Version is stored in self.version and returned

        returns:
            str: version of PAN-OS

        """
        system_info = self.refresh_system_info()
        self.version = system_info[0]
        return self.version

    def set_hostname(self, hostname):
        """Set the device hostname

        Convenience method to set the firewall or Panorama hostname

        Args:
            hostname (str): hostname to set (should never be None)

        """
        if hostname is None:
            raise ValueError("hostname should not be None")
        import pandevice.device

        self._logger.debug("Set hostname: %s" % str(hostname))
        system = self.findall_or_create(pandevice.device.SystemSettings)[0]
        if system.hostname != hostname:
            system.hostname = hostname
            # This handles addition and deletion
            system.update("hostname")

    def set_dns_servers(self, primary, secondary=None):
        """Set the device DNS Servers

        Convenience method to set the firewall or Panorama dns servers

        Args:
            primary (str): IP address of primary DNS server
            secondary (str): IP address of secondary DNS server

        """
        import pandevice.device

        self._logger.debug(
            "Set dns-servers: primary:%s secondary:%s" % (primary, secondary)
        )
        system = self.findall_or_create(pandevice.device.SystemSettings)[0]
        if system.dns_primary != primary:
            system.dns_primary = primary
            # This handles addition and deletion
            system.update("dns_primary")
        if system.dns_secondary != secondary:
            system.dns_secondary = secondary
            system.update("dns_secondary")

    def set_ntp_servers(self, primary, secondary=None):
        """Set the device NTP Servers

        Convenience method to set the firewall or Panorama NTP servers

        Args:
            primary (str): IP address of primary DNS server
            secondary (str): IP address of secondary DNS server

        """
        import pandevice.device

        self._logger.debug(
            "Set ntp-servers: primary:%s secondary:%s" % (primary, secondary)
        )
        system = self.findall_or_create(pandevice.device.SystemSettings)[0]
        if primary is None:
            ntp1 = system.findall(pandevice.device.NTPServerPrimary)
            if ntp1:
                ntp1[0].delete()
        else:
            ntp1 = system.findall_or_create(pandevice.device.NTPServerPrimary)[0]
            if ntp1.address != primary:
                ntp1.address = primary
                ntp1.create()
        if secondary is None:
            ntp2 = system.findall(pandevice.device.NTPServerSecondary)
            if ntp2:
                ntp2[0].delete()
        else:
            ntp2 = system.findall_or_create(pandevice.device.NTPServerSecondary)[0]
            if ntp2.address != secondary:
                ntp2.address = secondary
                ntp2.create()

    def pending_changes(self, retry_on_peer=True):
        """Check if there are pending changes on the live device

        Args:
            retry_on_peer (bool): Try on active Firewall first, if connection error try on passive Firewall

        Returns:
            bool: True if pending changes, False if not

        """
        self.xapi.op(
            cmd="check pending-changes", cmd_xml=True, retry_on_peer=retry_on_peer
        )
        pconf = PanConfig(self.xapi.element_result)
        response = pconf.python()
        return response["result"]

    def add_commit_lock(
        self, comment=None, scope="shared", exceptions=True, retry_on_peer=True
    ):
        self._logger.debug(
            "%s: Add commit lock requested for scope %s" % (self.id, scope)
        )
        cmd = ET.Element("request")
        subel = ET.SubElement(cmd, "commit-lock")
        subel = ET.SubElement(subel, "add")
        if comment is not None:
            subel = ET.SubElement(subel, "comment")
            subel.text = comment
        try:
            self.xapi.op(
                ET.tostring(cmd, encoding="utf-8"),
                vsys=scope,
                retry_on_peer=retry_on_peer,
            )
        except (pan.xapi.PanXapiError, err.PanDeviceXapiError) as e:
            if not re.match(r"Commit lock is already held", str(e)):
                raise
            else:
                if exceptions:
                    raise err.PanLockError(str(e), pan_device=self)
                else:
                    self._logger.debug(str(e))
                    return False
        self.commit_locked = True
        return True

    def remove_commit_lock(
        self, admin=None, scope="shared", exceptions=True, retry_on_peer=True
    ):
        self._logger.debug(
            "%s: Remove commit lock requested for scope %s" % (self.id, scope)
        )
        cmd = ET.Element("request")
        subel = ET.SubElement(cmd, "commit-lock")
        subel = ET.SubElement(subel, "remove")
        if admin is not None:
            subel = ET.SubElement(subel, "admin")
            subel.text = admin
        try:
            self.xapi.op(
                ET.tostring(cmd, encoding="utf-8"),
                vsys=scope,
                retry_on_peer=retry_on_peer,
            )
        except (pan.xapi.PanXapiError, err.PanDeviceXapiError) as e:
            if not re.match(r"Commit lock is not currently held", str(e)):
                raise
            else:
                if exceptions:
                    raise err.PanLockError(str(e), pan_device=self)
                else:
                    self._logger.debug(str(e))
                    return False
        self.commit_locked = False
        return True

    def add_config_lock(
        self, comment=None, scope="shared", exceptions=True, retry_on_peer=True
    ):
        self._logger.debug(
            "%s: Add config lock requested for scope %s" % (self.id, scope)
        )
        cmd = ET.Element("request")
        subel = ET.SubElement(cmd, "config-lock")
        subel = ET.SubElement(subel, "add")
        if comment is not None:
            subel = ET.SubElement(subel, "comment")
            subel.text = comment
        try:
            self.xapi.op(
                ET.tostring(cmd, encoding="utf-8"),
                vsys=scope,
                retry_on_peer=retry_on_peer,
            )
        except (pan.xapi.PanXapiError, err.PanDeviceXapiError) as e:
            if not re.match(
                r"Config for scope (shared|vsys\d) is currently locked", str(e)
            ) and not re.match(r"You already own a config lock for scope", str(e)):
                raise
            else:
                if exceptions:
                    raise err.PanLockError(str(e), pan_device=self)
                else:
                    self._logger.debug(str(e))
                    return False
        self.config_locked = True
        return True

    def remove_config_lock(self, scope="shared", exceptions=True, retry_on_peer=True):
        self._logger.debug(
            "%s: Remove config lock requested for scope %s" % (self.id, scope)
        )
        cmd = ET.Element("request")
        subel = ET.SubElement(cmd, "config-lock")
        subel = ET.SubElement(subel, "remove")
        try:
            self.xapi.op(
                ET.tostring(cmd, encoding="utf-8"),
                vsys=scope,
                retry_on_peer=retry_on_peer,
            )
        except (pan.xapi.PanXapiError, err.PanDeviceXapiError) as e:
            if not re.match(
                r"Config is not currently locked for scope (shared|vsys\d)", str(e)
            ):
                raise
            else:
                if exceptions:
                    raise err.PanLockError(str(e), pan_device=self)
                else:
                    self._logger.debug(str(e))
                    return False
        self.config_locked = False
        return True

    def remove_all_locks(self, scope="shared", retry_on_peer=True):
        self.remove_config_lock(
            scope=scope, exceptions=False, retry_on_peer=retry_on_peer
        )
        self.remove_commit_lock(
            scope=scope, exceptions=False, retry_on_peer=retry_on_peer
        )

    def check_commit_locks(self, retry_on_peer=True):
        self.xapi.op("show commit-locks", cmd_xml=True, retry_on_peer=retry_on_peer)
        response = self.xapi.element_result.find(".//entry")
        return True if response is not None else False

    def check_config_locks(self, retry_on_peer=True):
        self.xapi.op("show config-locks", cmd_xml=True, retry_on_peer=retry_on_peer)
        response = self.xapi.element_result.find(".//entry")
        return True if response is not None else False

    def revert_to_running_configuration(self, retry_on_peer=True):
        self._logger.debug("%s: Revert to running configuration" % self.id)
        self.xapi.op(
            "<load><config><from>" "running-config.xml" "</from></config></load>",
            retry_on_peer=retry_on_peer,
        )

    def restart(self):
        self._logger.debug("Requesting restart on device: %s" % (self.id,))
        try:
            self.xapi.op("request restart system", cmd_xml=True)
        except pan.xapi.PanXapiError as e:
            if not str(e).startswith("Command succeeded with no output"):
                raise e

    # High Availability Methods

    @property
    def ha_peer(self):
        return self._ha_peer

    def set_ha_peers(self, device):
        """Establish an HA peer relationship between two PanDevice objects

        Args:
            device: The HA peer device

        """
        self._ha_peer = device
        self.ha_peer._ha_peer = self
        # If both are active or both are passive,
        # set self to active and ha_peer to passive
        if self._ha_active == self.ha_peer._ha_active:
            self._ha_active = True
            self.ha_peer._ha_active = False

    def ha_pair(self):
        """List containing this firewall and its HA peer

        Returns:
            list: self and self.ha_peer in a list. If there is not ha_peer, then
                a single item list containing only self is returned.

        """
        return [fw for fw in [self, self.ha_peer] if fw is not None]

    def active(self):
        """Return the active device in the HA Pair"""
        if self._ha_active:
            return self
        else:
            return self.ha_peer

    def passive(self):
        """Return the passive device in the HA Pair"""
        if self._ha_active:
            return self.ha_peer
        else:
            return self

    def is_active(self):
        """Return True if this device is active"""
        return self._ha_active

    def activate(self):
        """Make this PanDevice active and the other passive"""
        self._ha_active = True
        if self.ha_peer is not None:
            self.ha_peer._ha_active = False

    def toggle_ha_active(self):
        """Switch the active device in this HA Pair"""
        if self.ha_peer is not None:
            self._ha_active = not self._ha_active
            self.ha_peer._ha_active = not self.ha_peer._ha_active

    def update_ha_active(self):
        # TODO: Implement this
        raise NotImplementedError

    def set_failed(self):
        """Set this PanDevice as a failed HA Peer

        API calls will no longer be attempted to this device until one of
        the following conditions:

        1. self.ha_failed is set to False
        2. self.ha_failed is set to True on the peer device

        Returns:
            PanDevice: The HA Peer device

        """
        if self.ha_peer is None:
            return None
        self.ha_failed = True
        if self.ha_peer is not None:
            self.ha_peer.activate()
            return self.ha_peer

    def map_ha(self, method_name, *args, **kwargs):
        """Apply to both devices in HA Pair

        Invoke a method of this class on both this instance and its HA peer

        Args:
            method_name: The name of the method in this class (or subclass) to invoke
            *args: Arguments to pass to the method
            **kwargs: Keyword arguments to pass to the method

        Returns:
            A tuple of the return values of invoking the method on each device. The
            first item in the tuple is always from invoking the method on self, and
            the second item is from invoking the method on the ha_peer. The second
            item is None if there is no HA Peer.

        """
        result1 = getattr(self, method_name)(*args, **kwargs)
        result2 = None
        if self.ha_peer is not None:
            result2 = getattr(self.ha_peer, method_name)(*args, **kwargs)
        return result1, result2

    def show_highavailability_state(self):
        ha_state = self.op("show high-availability state")
        enabled = ha_state.findtext("result/enabled")
        if enabled is None or enabled == "no":
            return "disabled", None
        else:
            return ha_state.findtext("result/group/local-info/state"), ha_state

    def refresh_ha_active(self):
        """Refresh which device is active using the live device

        Returns:
            str: Current HA state of this device

        """
        logger.debug("Refreshing active firewall in HA Pair")
        if self.ha_peer is None:
            return
        self_state = self.show_highavailability_state()[0]
        peer_state = self.ha_peer.show_highavailability_state()[0]
        states = (self_state, peer_state)
        if "disabled" in states:
            return
        elif "initial" in states:
            logger.debug("HA is initializing on one or both devices, try again soon")
            return "initial"
        else:
            for fw, state in ((self, self_state), (self.ha_peer, peer_state)):
                fw._ha_active = state == "active"
            return self_state

    def synchronize_config(self):
        """Force configuration synchronization from this device to its HA peer"""
        # TODO: Fix return value, too many types
        state = self.config_sync_state()
        if state is None:
            return
        elif state == "synchronization in progress":
            # Wait until synchronization done
            return self.watch_op(
                "show high-availability state", "group/running-sync", "synchronized"
            )
        elif state != "synchronized":
            logger.debug("Synchronizing configuration with HA peer")
            response = self.active().op(
                "request high-availability sync-to-remote running-config", "shared"
            )
            line = response.find("./msg/line")
            if line is None:
                raise err.PanDeviceError(
                    "Unable to syncronize configuration, no response from firewall"
                )
            elif line.text.startswith(
                "successfully sync'd running configuration to HA peer"
            ):
                # PAN-OS 7.0
                return True
            elif line.text.startswith(
                "HA synchronization job has been queued on peer. "
                "Please check job status on peer."
            ):
                # PAN-OS 7.1
                # Wait until synchronization done
                return self.watch_op(
                    "show high-availability state", "group/running-sync", "synchronized"
                )
            else:
                raise err.PanDeviceError(
                    "Unable to syncronize configuration: %s" % line.text
                )
        else:
            logger.debug("Config synchronization is not required, already synchronized")
            return True

    def config_sync_state(self):
        """Get the current configuration synchronization state from the live device

        Returns:
            str: Current configuration sync state, or None if HA is not enabled

        """
        # TODO: What if HA is on, but HA config sync is off?
        logger.debug("Checking configuration sync state")
        ha_state = self.active().op("show high-availability state")
        enabled = ha_state.find("./result/enabled")
        if enabled is None or enabled.text == "no":
            logger.debug("HA is not enabled on firewall")
            return
        if enabled.text == "yes":
            sync_enabled = ha_state.find("./result/group/running-sync-enabled")
            if sync_enabled is None or sync_enabled.text != "yes":
                logger.debug("HA config sync is not enabled on firewall")
                return
            else:
                state = ha_state.find("./result/group/running-sync")
                if state is None:
                    logger.debug("HA or config sync is not enabled on firewall")
                    return
                logger.debug("Current config sync state is: %s" % state.text)
                return state.text

    def config_synced(self):
        """Check if configuration is synchronized between HA peers

        Returns:
            bool: True if synchronized, False if not

        """
        state = self.config_sync_state()
        if state is None:
            return False
        elif state != "synchronized":
            return False
        else:
            return True

    # Commit methods

    def commit(
        self, sync=False, exception=False, cmd=None, admins=None, sync_all=False
    ):
        """Trigger a commit

        Args:
            sync (bool): Block until the commit is finished (Default: False)
            exception (bool): Create an exception on commit errors (Default: False)
            cmd (str): Commit options in XML format
            admins (str/list): name or list of admins whose changes need to be committed 
            sync_all (bool): If this is a Panorama commit, wait for firewalls jobs to finish (Default: False)

        Returns:
            dict: Commit results

        """
        self._logger.debug("Commit initiated on device: %s" % (self.id,))
        return self._commit(
            sync=sync, exception=exception, cmd=cmd, admins=admins, sync_all=sync_all
        )

    def _commit(
        self,
        cmd=None,
        exclude=None,
        commit_all=False,
        sync=False,
        sync_all=False,
        exception=False,
        admins=None,
    ):
        """Internal use commit helper method.

        :param exclude:
            Can be:
                device-and-network
                policy-and-objects

        :param admins:
            string or list containing specific admin user(s) whose changes need to be committed

        :param sync:
            Synchronous commit, ie. wait for job to finish
        :return:
            Result of commit as dict if synchronous.  JobID if asynchronous.
            In either case, if no commit is needed, return None.
            Most important fields in dict:
                success:  True or False
                result:  OK or FAIL
                messages: list of warnings or errors

        """
        action = None

        # Adding in handling for the commit normalizations.
        if (
            cmd is not None
            and hasattr(cmd, "element")
            and hasattr(cmd, "commit_action")
        ):
            action = cmd.commit_action
            cmd = cmd.element()

        # TODO: Support per-vsys commit
        if isinstance(cmd, pan.commit.PanCommit):
            cmd = cmd.cmd()
        elif isinstance(cmd, ET.Element):
            cmd = ET.tostring(cmd, encoding="utf-8")
        elif isstring(cmd):
            pass
        else:
            cmd = ET.Element("commit")
            if exclude is not None or admins is not None:
                partial = ET.SubElement(cmd, "partial")
                if admins is not None:
                    partial_admin = ET.SubElement(partial, "admin")
                    admins = pandevice.string_or_list(admins)
                    for admin in admins:
                        admin_xml = ET.SubElement(partial_admin, "member")
                        admin_xml.text = admin
                if exclude is not None:
                    excluded = ET.SubElement(partial, exclude)
            cmd = ET.tostring(cmd, encoding="utf-8")

        logger.debug(
            self.id
            + ": commit requested: commit_all:%s sync:%s sync_all:%s cmd:%s"
            % (str(commit_all), str(sync), str(sync_all), cmd,)
        )
        if commit_all:
            action = "all"

        self._logger.debug("Initiating commit")
        commit_response = self.xapi.commit(
            cmd=cmd,
            action=action,
            sync=False,
            interval=self.interval,
            timeout=self.timeout,
            retry_on_peer=True,
        )

        # Set locks off
        self.config_changed = []
        self.config_locked = False
        self.commit_locked = False
        # Determine if a commit was needed and get the job id
        try:
            jobid = commit_response.find("./result/job").text
        except AttributeError:
            if exception:
                raise err.PanCommitNotNeeded("Commit not needed", pan_device=self)
            else:
                return
        if not sync:
            # Don't synchronize, just return
            self._logger.debug("Commit initiated (async), job id: %s" % (jobid,))
            return jobid
        else:
            result = self.syncjob(commit_response, sync_all=sync_all)

            if exception and not result["success"]:
                self._logger.debug(
                    "Commit failed - device: %s, job: %s, messages: %s, warnings: %s"
                    % (self.id, result["jobid"], result["messages"], result["warnings"])
                )
                raise err.PanCommitFailed(pan_device=self, result=result)
            else:
                if result["success"]:
                    self._logger.debug(
                        "Commit succeeded - device: %s, job: %s, messages: %s, warnings: %s"
                        % (
                            self.id,
                            result["jobid"],
                            result["messages"],
                            result["warnings"],
                        )
                    )
                else:
                    self._logger.debug(
                        "Commit failed - device: %s, job: %s, messages: %s, warnings: %s"
                        % (
                            self.id,
                            result["jobid"],
                            result["messages"],
                            result["warnings"],
                        )
                    )
                return result

    def syncjob(self, job_id, sync_all=False, interval=0.5):
        """Block until job completes and return result

        Args:
            job_id (int): job ID, or response XML from job creation
            sync_all (bool): Wait for all devices to complete if commit all operation
            interval (float): Interval in seconds to check if job is complete

        Returns:
            dict: Job result

        """
        try:
            import http.client as httplib
        except ImportError:
            import httplib
        if interval is not None:
            try:
                interval = float(interval)
                if interval < 0:
                    raise ValueError
            except ValueError:
                raise err.PanDeviceError("Invalid interval: %s" % interval)

        try:
            job = job_id.find("./result/job")
            if job is None:
                return False
            job = job.text
        except AttributeError:
            job = job_id

        cmd = 'show jobs id "%s"' % job
        start_time = time.time()

        self._logger.debug("Waiting for job to finish...")

        attempts = 0
        while True:
            try:
                attempts += 1
                job_xml = self.xapi.op(cmd=cmd, cmd_xml=True, retry_on_peer=True)
            except (pan.xapi.PanXapiError, err.PanDeviceError) as e:
                # Connection errors (URLError) are ok, this can happen in PAN-OS 7.0.1 and 7.0.2
                # if the hostname is changed
                # Invalid cred errors are ok because FW auth system takes longer to start up in these cases
                # Other errors should be raised
                if not str(e).startswith("URLError:") and not str(e).startswith(
                    "Invalid credentials."
                ):
                    # Error not related to connection issue.  Raise it.
                    raise e
                else:
                    # self._logger.debug2("Sleep %.2f seconds" % interval)
                    time.sleep(interval)
                    continue
            except httplib.BadStatusLine as e:
                # Connection issue.  The firewall is currently restarting the API service or rebooting
                # self._logger.debug2("Sleep %.2f seconds" % interval)
                time.sleep(interval)
                continue

            status = job_xml.find("./result/job/status")
            if status is None:
                raise pan.xapi.PanXapiError(
                    "No status element in " + "'%s' response" % cmd
                )
            if status.text == "FIN" and sync_all:
                # Check the status of each device commit
                device_commits_finished = True
                device_results = job_xml.findall("./result/job/devices/entry/result")
                for device_result in device_results:
                    if device_result.text == "PEND":
                        device_commits_finished = False
                        break  # One device isn't finished, so stop checking others
                if device_results and device_commits_finished:
                    return self._parse_job_results(job_xml, get_devices=True)
                elif not device_results:
                    return self._parse_job_results(job_xml, get_devices=False)
            elif status.text == "FIN":
                # Job completed, parse the results
                return self._parse_job_results(job_xml, get_devices=False)

            logger.debug("Job %s status %s" % (job, status.text))

            if (
                self.timeout is not None
                and self.timeout != 0
                and time.time() > start_time + self.timeout
            ):
                raise pan.xapi.PanXapiError(
                    "Timeout waiting for " + "job %s completion" % job
                )

            # self._logger.debug2("Sleep %.2f seconds" % interval)
            time.sleep(interval)

    def syncreboot(self, interval=5.0, timeout=600):
        """Block until reboot completes and return version of device"""
        try:
            import http.client as httplib
        except ImportError:
            import httplib

        # Validate interval and convert it to float
        if interval is not None:
            try:
                interval = float(interval)
                if interval < 0:
                    raise ValueError
            except ValueError:
                raise err.PanDeviceError("Invalid interval: %s" % interval)

        self._logger.debug("Syncing reboot...")

        # Record start time to gauge timeout
        start_time = time.time()
        attempts = 0
        is_rebooting = False

        time.sleep(interval)
        while True:
            try:
                # Try to get the device version (ie. test to see if firewall is up)
                attempts += 1
                version = self.refresh_version()
            except (pan.xapi.PanXapiError, err.PanDeviceXapiError) as e:
                # Connection errors (URLError) are ok
                # Invalid cred errors are ok because FW auth system takes longer to start up
                # Other errors should be raised
                if not str(e).startswith("URLError:") and not str(e).startswith(
                    "Invalid credentials."
                ):
                    # Error not related to connection issue.  Raise it.
                    raise e
                else:
                    # Connection issue.  The firewall is currently rebooting.
                    is_rebooting = True
                    self._logger.debug("Connection attempted: %s" % str(e))
                    self._logger.debug(
                        "Device is not available yet. Connection attempts: %s"
                        % str(attempts)
                    )
            except httplib.BadStatusLine as e:
                # Connection issue.  The firewall is currently rebooting.
                is_rebooting = True
                self._logger.debug("Connection attempted: %s" % str(e))
                self._logger.debug(
                    "Device is not available yet. Connection attempts: %s"
                    % str(attempts)
                )
            else:
                # No exception... connection succeeded and device is up!
                # This could mean reboot hasn't started yet, so check that we had
                # a connection error prior to this success.
                if is_rebooting:
                    self._logger.debug("Device is up! Running version %s" % version)
                    return version
                else:
                    self._logger.debug(
                        "Device is up, but it probably hasn't started rebooting yet."
                    )

            # Check to see if we hit timeout
            if (
                self.timeout is not None
                and self.timeout != 0
                and time.time() > start_time + self.timeout
            ):
                raise err.PanDeviceError("Timeout waiting for device to reboot")

            # Sleep and try again
            self._logger.debug("Sleep %.2f seconds" % interval)
            time.sleep(interval)

    def _parse_job_results(self, show_job_xml, get_devices=True):
        # Parse the final results
        pconf = PanConfig(show_job_xml)
        job_response = pconf.python()
        try:
            job = job_response["response"]["result"]["job"]
        except KeyError:
            raise err.PanDeviceError("Can't get job results, error parsing results xml")
        devices_results = {}
        devices_success = True
        # Determine if this was a commit all job
        devices = show_job_xml.findall("./result/job/devices/entry")
        if devices and get_devices:
            devices = job["devices"]["entry"]
            for device in devices:
                dev_success = True if device["result"] == "OK" else False
                if not dev_success:
                    devices_success = False
                devices_results[device["serial-no"]] = {
                    "success": dev_success,
                    "serial": device["serial-no"],
                    "name": device["devicename"],
                    "result": device["result"],
                    "starttime": device["tstart"],
                    "endtime": device["tfin"],
                }
                # Errors and warnings might not have a full structure.  If it is just a string, then
                # a TypeError will be produced, so in that case, just grab the string.
                try:
                    devices_results[device["serial-no"]]["warnings"] = device[
                        "details"
                    ]["msg"]["warnings"]["line"]
                except (TypeError, KeyError) as e:
                    try:
                        devices_results[device["serial-no"]]["warnings"] = device[
                            "details"
                        ]["msg"]["warnings"]
                    except (TypeError, KeyError) as e:
                        devices_results[device["serial-no"]]["warnings"] = ""
                except (TypeError, KeyError) as e:
                    devices_results[device["serial-no"]]["warnings"] = ""
                try:
                    devices_results[device["serial-no"]]["messages"] = device[
                        "details"
                    ]["msg"]["errors"]["line"]
                except (TypeError, KeyError) as e:
                    devices_results[device["serial-no"]]["messages"] = device["details"]

        success = True if job["result"] == "OK" and devices_success else False

        if get_devices:
            messages = []
        else:
            try:
                messages = job["details"]["line"]
            except KeyError:
                messages = []
        if isstring(messages):
            messages = string_or_list(messages)
        # Create the results dict
        result = {
            "success": success,
            "result": job["result"],
            "jobid": job["id"],
            "user": job["user"],
            "warnings": job["warnings"],
            "starttime": job["tenq"],
            "endtime": job["tfin"],
            "messages": messages,
            "devices": devices_results,
            "xml": show_job_xml,
        }
        return result

    def watch_op(self, cmd, path, value, vsys=None, cmd_xml=True, interval=1.0):
        """Watch an operational command for an expected value

        Blocks script execution until the value exists or timeout expires

        Args:
            cmd (str): Operational command to run
            path (str): XPath to the value to watch
            value (str): The value expected before method completes
            vsys (str): Vsys id for the operational command
            cmd_xml (bool): True: cmd is not XML, False: cmd is XML (Default: True)
            interval (float): Interval in seconds to check if the value exists

        """
        if interval is not None:
            try:
                interval = float(interval)
                if interval < 0:
                    raise ValueError
            except ValueError:
                raise err.PanDeviceError("Invalid interval: %s" % interval)

        if vsys is None:
            vsys = self.vsys

        self._logger.debug("Waiting for value %s..." % value)

        start_time = time.time()
        attempts = 0
        while True:
            attempts += 1
            xml = self.xapi.op(cmd=cmd, cmd_xml=cmd_xml)
            status = xml.find("./result/%s" % path)
            if status is None:
                raise err.PanNoSuchNode("No element at path")
            current_value = status.text
            logger.debug("Current value %s" % current_value)

            if current_value == value:
                return True

            if (
                self.timeout is not None
                and self.timeout != 0
                and time.time() > start_time + self.timeout
            ):
                raise err.PanJobTimeout("Timeout waiting for value: %s" % value)

            logger.debug("Sleep %.2f seconds" % interval)
            time.sleep(interval)

    def nearest_pandevice(self):
        """The nearest :class:`pandevice.base.PanDevice` object.

        This method is used to determine the device to apply this object to.

        Returns:
            PanDevice: The PanDevice object closest to this object in
                the configuration tree.

        Raises:
            PanDeviceNotSet: There is no PanDevice object in the tree.

        """
        if self.parent is not None:
            return self.parent._nearest_pandevice()
        else:
            return self._nearest_pandevice()

    def _nearest_pandevice(self):
        return self

    def _format_result_as_license_list(self, result):
        """Formats the ElementTree as a list of License namedtuples."""
        ans = []
        License = collections.namedtuple(
            "License",
            [
                "feature",
                "description",
                "serial",
                "issued",
                "expires",
                "expired",
                "authcode",
            ],
        )

        def _parse_license_date(value):
            """Turns a string into a datetime.date object.

            If the value is "Never", this function returns None.

            If the value can't be parsed, then the string itself is returned.
            """
            if value is None or value.text is None or value.text == "Never":
                return None

            date_format = "%B %d, %Y"
            months = {
                "January": 1,
                "February": 2,
                "March": 3,
                "April": 4,
                "May": 5,
                "June": 6,
                "July": 7,
                "August": 8,
                "September": 9,
                "October": 10,
                "November": 11,
                "December": 12,
            }

            tokens = value.text.split()
            try:
                return datetime.date(
                    int(tokens[2]), months[tokens[0]], int(tokens[1][:-1])
                )
            except (ValueError, KeyError, IndexError):
                return value.text

        for x in result.findall("./result/licenses/entry"):
            ans.append(
                License(
                    x.find("./feature").text,
                    x.find("./description").text,
                    x.find("./serial").text,
                    _parse_license_date(x.find("./issued")),
                    _parse_license_date(x.find("./expires")),
                    x.find("./expired").text == "yes",
                    x.find("./authcode").text,
                )
            )

        return ans

    def request_license_info(self):
        """Returns the licenses currently installed on this device.

        **Touches the live device**

        Note: For namedtuple objects, you can access the variables via
        its index like a normal tuple or via name like a class.

        Returns:
            list: A list of namedtuples of the licenses with the following attributes:

                - feature (str): the feature name
                - description (str): description
                - serial (str): the license's serial number
                - issued (datetime.date/None): issue date
                - expires (datetime.date/None): expiration date, or None if the license does not expire
                - expired (bool): True if the license is currently expired
                - authcode (str/None): license's authcode

        """
        result = self.op("request license info")
        return self._format_result_as_license_list(result)

    def fetch_licenses_from_license_server(self):
        """Fetches licenses from the license server.

        **Modifies the live device**

        Note: For namedtuple objects, you can access the variables via
        its index like a normal tuple or via name like a class.

        Returns:
            list: A list of namedtuples of the licenses with the following attributes:

                - feature (str): the feature name
                - description (str): description
                - serial (str): the license's serial number
                - issued (datetime.date/None): issue date
                - expires (datetime.date/None): expiration date, or None if the license does not expire
                - expired (bool): True if the license is currently expired
                - authcode (str/None): license's authcode

        """
        result = self.op("request license fetch")
        return self._format_result_as_license_list(result)

    def activate_feature_using_authorization_code(self, code):
        """Updates a license using the given auth code.

        **Modifies the live device**

        Args:
            code (str): The authorization code.

        Raises:
            PanActivateFeatureAuthCodeError
        """
        try:
            result = self.op('request license fetch auth-code "{0}"'.format(code))
        except pan.xapi.PanXapiError as e:
            """
            pan-python can handle both XML responses & plaintext responses from
            a PAN-OS, and it makes this determination based on headers that are
            sent back from any given action.  Raw XML text returned is stored
            in pan.xapi.PanXapi.xml_document, and the raw plain text is stored
            in pan.xapi.PanXapi.text_document.

            When it comes to licensing, it's been observed that PAN-OS can
            send back a response with Content-Type: application/xml, but the
            content isn't actually XML, it's plain text.  When this happens,
            pan-python wraps the xml.etree.ElementTree error and returns
            a PanXapiError instead that mentions the parsing problem.

            So, check the not-actually-XML response sent back to see if the
            licensing operation was actually successful.
            """
            err_msg = "{0}".format(e)
            if err_msg.startswith("ElementTree.fromstring ParseError:"):
                acceptable_errors = (
                    "VM Device License installed. Restarting pan services.",
                )
                for msg in acceptable_errors:
                    if msg in self.xapi.xml_document:
                        return
                raise pan.xapi.PanXapiError(
                    "{0} | xml_document={1}".format(err_msg, self.xapi.xml_document)
                )
            else:
                raise

        if result.attrib.get("status") != "success":
            raise err.PanActivateFeatureAuthCodeError(
                result.get("./msg/line").text, pan_device=self
            )

    def request_password_hash(self, value):
        """Request a password hash from the live device.

        This function does not modify the live device, but it does
        interact with the live device to generate the password hash.

        Args:
            value (str): The password

        Returns:
            str: A hashed version of the password provided.

        Raises:
            ValueError: If the password hash is not found.

        """
        result = self.op('request password-hash password "{0}"'.format(value))
        elm = result.find("./result/phash")
        if elm is None:
            raise ValueError("No password hash in response")

        return elm.text

    def test_security_policy_match(
        self,
        source,
        destination,
        protocol,
        application=None,
        category=None,
        port=None,
        user=None,
        from_zone=None,
        to_zone=None,
        show_all=False,
    ):
        """Test security policy match using the given criteria.

        This function will always return a list for its results.  If `show_all`
        is set to False, then the list will only have one entry in it.  The
        keys in each dict are as follows:
            * name (str): rule's name
            * index (int): the index of the security rule
            * action (str): the security rule's action

        Args:
            source (str): Source IP address.
            destination (str): Destination IP address.
            protocol (int): IP protocol value (1-255).
            application (str): Application name.
            category (str): Category name.
            port (int): Destination port.
            user (str): Source user.
            from_zone (str): Source zone name.
            to_zone (str): Destination zone name.
            show_all (bool): Show all potential match rules until first allow.

        Returns:
            List of dicts
        """
        extras = (
            ("application", application),
            ("category", category),
            ("destination-port", port),
            ("source-user", user),
            ("from", from_zone),
            ("to", to_zone),
            ("show-all", show_all),
        )

        # Build up the XML document.
        root = ET.Element("test")
        elm = ET.SubElement(root, "security-policy-match")

        # Add in required params.
        ET.SubElement(elm, "source").text = source
        ET.SubElement(elm, "destination").text = destination
        ET.SubElement(elm, "protocol").text = str(int(protocol))

        # Add in the optional params.
        for desc, val in extras:
            if val is None:
                continue

            if desc == "destination-port":
                ET.SubElement(elm, desc).text = str(int(val))
            elif desc == "show-all":
                ET.SubElement(elm, desc).text = "yes" if val else "no"
            else:
                ET.SubElement(elm, desc).text = val

        # Run the test operation.
        res = self.op(ET.tostring(root, encoding="utf-8"), cmd_xml=False)

        # Build up the answer.
        #
        # Side note here:  the XML document returned here does not follow the
        # rules of the API, so we can't use the SecurityRule module to parse
        # the results.  For this reason, we won't parse everything, just
        # name, index, and action.
        ans = []
        for elm in res.findall("./result/rules/entry"):
            if "name" in elm.attrib:
                val = {
                    "name": elm.attrib["name"],
                }

                e = elm.find("./index")
                val["index"] = 0 if e is None else int(e.text)

                e = elm.find("./action")
                val["action"] = "" if e is None else e.text

                ans.append(val)
            else:
                tokens = elm.text.split(";")
                if len(tokens) == 2 and tokens[1].startswith(" index: "):
                    ans.append(
                        {"name": tokens[0], "index": int(tokens[1].split(":")[1])}
                    )
                else:
                    raise err.PanDeviceError(
                        "Not sure how to parse response: {0}".format(elm.text)
                    )

        # Done.
        return ans

    def clock(self):
        """Gets the current time on PAN-OS.

        Returns:
            datetime.datetime
        """
        ans = self.op("<show><clock/></show>", cmd_xml=False)

        res = ans.find("./result")
        if res is None:
            return None

        fmt = "%a %b %d %H:%M:%S %Z %Y"
        text = res.text.strip()
        return datetime.strptime(text, fmt)
