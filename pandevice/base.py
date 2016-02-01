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


"""Base object classes for inheritence by other classes"""

import re
import xml.etree.ElementTree as ET
import logging
import inspect
import time
import copy

import pandevice
from pandevice import yesno

import pan.xapi
import pan.commit
from pan.config import PanConfig
import errors as err
import updater

# set logging to nullhandler to prevent exceptions if logging not enabled
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

Root = pandevice.enum("DEVICE", "VSYS", "MGTCONFIG")
SELF = "/%s"
ENTRY = "/entry[@name='%s']"
MEMBER = "/member[text()='%s']"


# PanObject type
class PanObject(object):
    XPATH = ""
    SUFFIX = None
    ROOT = Root.DEVICE
    NAME = "name"
    CHILDTYPES = ()
    CHILDMETHODS = ()
    HA_SYNC = True

    def __init__(self, name=None):
        self.name = name
        self.parent = None
        self.children = []

    def __str__(self):
        return str(self.name)

    @classmethod
    def vars(cls):
        return ()

    @property
    def vsys(self):
        if self.parent is not None:
            return self.parent.vsys

    @vsys.setter
    def vsys(self, value):
        raise err.PanDeviceError("Cannot set vsys on non-vsys object")

    def add(self, child):
        child.parent = self
        self.children.append(child)
        return child

    def extend(self, children):
        for child in children:
            child.parent = self
        self.children.extend(children)

    def pop(self, index):
        child = self.children.pop(index)
        child.parent = None
        return child

    def remove(self, child):
        self.children.remove(child)
        child.parent = None

    def remove_by_name(self, name, cls=None):
        index = PanObject.find_index(self.children, name, cls)
        if index is None:
            return None
        return self.pop(index)  # Just remove the first child that matches the name

    def removeall(self, cls=None):
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

    def xpath(self):
        """Return the full xpath for this object

        Xpath in the form: parent's xpath + this object's xpath + entry or member if applicable.
        """
        xpath = self._parent_xpath() + self.XPATH
        suffix = "" if self.SUFFIX is None else self.SUFFIX % getattr(self, self.NAME)
        return xpath + suffix

    def xpath_nosuffix(self):
        """Return the xpath without the suffix"""
        xpath = self._parent_xpath() + self.XPATH
        return xpath

    def xpath_short(self):
        """Return an xpath for this object without the final segment

        Xpath in the form: parent's xpath + this object's xpath.  Used for set API calls.
        """
        xpath = self._parent_xpath() + self.XPATH
        if self.SUFFIX is None:
            # Remove last segment of xpath
            xpath = re.sub(r"/(?=[^/']*'[^']*'[^/']*$|[^/]*$).*$", "", xpath)
        return xpath

    def _parent_xpath(self):
        if self.parent is None:
            # self with no parent
            parent_xpath = ""
        elif isinstance(self.parent, PanDevice):
            # Parent is Firewall or Panorama
            parent_xpath = self.parent.xpath_root(self.ROOT)
        else:
            parent_xpath = self.parent.xpath()
        return parent_xpath

    def xpath_vsys(self):
        if self.parent is not None:
            return self.parent.xpath_vsys()

    def xpath_panorama(self):
        if self.parent is not None:
            return self.parent.xpath_panorama()

    def element(self):
        root = self.root_element()
        variables = self.vars()
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
                matches = re.findall(r'{{(.*?)}}', section)
                entryvar = None
                # Do variable replacement, ie. {{ }}
                for match in matches:
                    regex = r'{{' + re.escape(match) + r'}}'
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
                        entry_value = pandevice.string_or_list(getattr(self, matchedvar.variable))
                        section = re.sub(regex,
                                         matchedvar.path + "/" + "entry[@name='%s']" % entry_value[0],
                                         section)
                        entryvar = matchedvar
                    else:
                        # Not an 'entry' variable
                        section = re.sub(regex, getattr(self, matchedvar.variable), section)
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
                        nextelement = ET.SubElement(nextelement, "entry", {"name": getattr(self, entryvar.variable)})
                    else:
                        # for entry vartypes that are empty
                        if var.vartype == "entry" and not value:
                            continue
                        # non-entry vartypes
                        nextelement = ET.SubElement(nextelement, section)
            if missing_replacement:
                continue
            # Create an element containing the value in the instance variable
            if var.vartype == "member":
                for member in value:
                    ET.SubElement(nextelement, 'member').text = str(member)
            elif var.vartype == "entry":
                try:
                    # Value is an array
                    for entry in pandevice.string_or_list(value):
                        ET.SubElement(nextelement, 'entry', {'name': str(entry)})
                except TypeError:
                    # Value is not an array
                    ET.SubElement(nextelement, 'entry', {'name': str(value)})
            elif var.vartype == "exist":
                if value:
                    ET.SubElement(nextelement, var.variable)
            elif var.vartype == "bool":
                nextelement.text = yesno(value)
            elif var.path.find("|") != -1:
                # This is an element variable,
                # it has already been created
                # so do nothing
                pass
            elif var.vartype == "none":
                # There is no variable, so don't try to populate it
                pass
            else:
                nextelement.text = str(value)
        pandevice.xml_combine(root, self.subelements())
        return root

    def element_str(self):
        return ET.tostring(self.element())

    def root_element(self):
        if self.SUFFIX == ENTRY:
            return ET.Element("entry", {'name': self.name})
        elif self.SUFFIX == MEMBER:
            root = ET.Element("member")
            root.text = self.name
            return root
        elif self.SUFFIX is None:
            tag = self.XPATH.rsplit('/', 1)[-1] # Get right of last / in xpath
            return ET.Element(tag)

    def subelements(self):

        def _next_xpath_level(child, element, xpath_sections):
            """Recursive nested method to handle long xpaths"""
            if not xpath_sections:
                element.append(child.element())
                return
            next_section = xpath_sections[0]
            next_element = element.find(next_section)
            if next_element is None:
                next_element = ET.SubElement(element, xpath_sections[0])
            _next_xpath_level(child,
                              next_element,
                              xpath_sections[1:])
            return

        elements = ET.Element('root')
        for child in self.children:
            # Get the extra layers in the next node's xpath
            xpath_sections = type(child).XPATH.split('/')[1:]
            # If no suffix, remove the last xpath section
            # because it will be part of the element
            if type(child).SUFFIX is None:
                xpath_sections = xpath_sections[:-1]
            _next_xpath_level(child, elements, xpath_sections)
        # Return a list of subelements
        return [element for element in elements]

    def _check_child_methods(self, method):
        if method in self.CHILDMETHODS:
            getattr(self, "child_"+method)()
        for child in self.children:
            child.check_child_methods(method)

    def apply(self):
        pandevice = self.pandevice()
        logger.debug(pandevice.hostname + ": apply called on %s object \"%s\"" % (type(self), self.name))
        pandevice.set_config_changed()
        if self.HA_SYNC:
            pandevice.active().xapi.edit(self.xpath(), self.element_str(), retry_on_peer=self.HA_SYNC)
        else:
            pandevice.xapi.edit(self.xpath(), self.element_str(), retry_on_peer=self.HA_SYNC)
        for child in self.children:
            child._check_child_methods("apply")

    def create(self):
        pandevice = self.pandevice()
        logger.debug(pandevice.hostname + ": create called on %s object \"%s\"" % (type(self), self.name))
        pandevice.set_config_changed()
        element = self.element_str()
        if self.HA_SYNC:
            pandevice.active().xapi.set(self.xpath_short(), element, retry_on_peer=self.HA_SYNC)
        else:
            pandevice.xapi.set(self.xpath_short(), element, retry_on_peer=self.HA_SYNC)
        for child in self.children:
            child._check_child_methods("create")

    def delete(self):
        pandevice = self.pandevice()
        logger.debug(pandevice.hostname + ": delete called on %s object \"%s\"" % (type(self), self.name))
        pandevice.set_config_changed()
        for child in self.children:
            child._check_child_methods("delete")
        if self.HA_SYNC:
            pandevice.active().xapi.delete(self.xpath(), retry_on_peer=self.HA_SYNC)
        else:
            pandevice.xapi.delete(self.xpath(), retry_on_peer=self.HA_SYNC)
        if self.parent is not None:
            self.parent.remove_by_name(getattr(self, self.NAME), type(self))

    def update(self, variable):
        """Change the value of a variable

        Do not attempt this on an element variable (|) or variable with replacement {{}}
        If the variable's value is None, then a delete API call is attempted.

        Args:
            variable (str): the name of an instance variable to update on the device
        """
        import ha
        pandevice = self.pandevice()
        logger.debug(pandevice.hostname + ": update called on %s object \"%s\" and variable \"%s\"" %
                     (type(self), self.name, variable))
        pandevice.set_config_changed()
        variables = type(self).vars()
        value = getattr(self, variable)
        # Get the requested variable from the class' variables tuple
        var = next((x for x in variables if x.variable == variable), None)
        if var is None:
            raise err.PanDeviceError("Variable %s does not exist in variable tuple" % variable)
        varpath = var.path
        # Do replacements on variable path
        if varpath.find("|") != -1:
            # This is an element variable, so create an element containing
            # the variables's value
            varpath = re.sub(r"\([\w\d|-]*\)", str(value), varpath)
        # Search for variable replacements in path
        matches = re.findall(r'{{(.*?)}}', varpath)
        entryvar = None
        # Do variable replacement, ie. {{ }}
        for match in matches:
            regex = r'{{' + re.escape(match) + r'}}'
            # Ignore variables that are None
            if getattr(self, match) is None:
                raise ValueError("While updating variable %s, missing replacement variable %s in path" %(variable, match))
            # Find the discovered replacement in the list of vars
            for nextvar in variables:
                if nextvar.variable == match:
                    matchedvar = nextvar
                    break
            if matchedvar.vartype == "entry":
                # If it's an 'entry' variable
                # XXX: this is using a quick patch.  Should handle array-based entry vars better.
                entry_value = pandevice.string_or_list(getattr(self, matchedvar.variable))
                varpath = re.sub(regex,
                                 matchedvar.path + "/" + "entry[@name='%s']" % entry_value[0],
                                 varpath)
            else:
                # Not an 'entry' variable
                varpath = re.sub(regex, getattr(self, matchedvar.variable), varpath)
        if value is None:
            pandevice.xapi.delete(self.xpath() + "/" + varpath, retry_on_peer=self.HA_SYNC)
        else:
            element_tag = varpath.split("/")[-1]
            element = ET.Element(element_tag)
            if var.vartype == "member":
                for member in value:
                    ET.SubElement(element, 'member').text = str(member)
                xpath = self.xpath() + "/" + varpath
            else:
                # Regular text variables
                element.text = value
                xpath = self.xpath() + "/" + varpath
            pandevice.xapi.edit(xpath, ET.tostring(element), retry_on_peer=self.HA_SYNC)

    def refresh(self, running_config=False, xml=None, refresh_children=True, exceptions=True):
        # Get the root of the xml to parse
        if xml is None:
            pandevice = self.pandevice()
            logger.debug(pandevice.hostname + ": refresh called on %s object \"%s\"" % (type(self), self.name))
            if running_config:
                api_action = pandevice.xapi.show
            else:
                api_action = pandevice.xapi.get
            try:
                root = api_action(self.xpath(), retry_on_peer=self.HA_SYNC)
            except (pan.xapi.PanXapiError, err.PanNoSuchNode) as e:
                if exceptions:
                    raise err.PanObjectMissing("Object doesn't exist: %s" % self.xpath(), pan_device=self.pandevice())
                else:
                    return
            # Determine the first element to look for in the XML
            if self.SUFFIX is None:
                lasttag = self.XPATH.rsplit("/", 1)[-1]
            else:
                lasttag = re.match(r'^/(\w*?)\[', self.SUFFIX).group(1)
            obj = root.find("result/" + lasttag)
            if obj is None:
                if exceptions:
                    raise err.PanObjectMissing("Object doesn't exist: %s" % self.xpath(), pan_device=self.pandevice())
                else:
                    return
        else:
            # Use the xml that was passed in
            logger.debug("refresh called using xml on %s object \"%s\"" % (type(self), self.name))
            obj = xml
        # Refresh each variable
        variables, noninit_variables = type(self)._parse_xml(obj)
        for var, value in variables.iteritems():
            setattr(self, var, value)
        for var, value in noninit_variables.iteritems():
            setattr(self, var, value)
        # Refresh sub-objects
        if refresh_children:
            self.refresh_children(xml=obj)

    def refresh_variable(self, variable, running_config=False, xml=None, exceptions=False):
        """Refresh a single variable in an object

        Doesn't work for variables with replacements or selections in path
        """
        # Get the root of the xml to parse
        variables = type(self).vars()
        # Get the requested variable from the class' variables tuple
        var = next((x for x in variables if x.variable == variable), None)
        if var is None:
            raise err.PanDeviceError("Variable %s does not exist in variable tuple" % variable)
        if xml is None:
            pandevice = self.pandevice()
            logger.debug(pandevice.hostname + ": refresh_variable called on %s object \"%s\" with variable %s" % (type(self), self.name, variable))
            if running_config:
                api_action = pandevice.xapi.show
            else:
                api_action = pandevice.xapi.get
            try:
                root = api_action(self.xpath() + "/" + var.path, retry_on_peer=self.HA_SYNC)
            except (pan.xapi.PanXapiError, err.PanNoSuchNode) as e:
                if exceptions:
                    raise err.PanObjectMissing("Object doesn't exist: %s" % self.xpath(), pan_device=self.pandevice())
                else:
                    setattr(self, variable, None)
                    return
            # Determine the first element to look for in the XML
            lasttag = var.path.rsplit("/", 1)[-1]
            obj = root.find("result/" + lasttag)
            if obj is None:
                if exceptions:
                    raise err.PanObjectMissing("Object doesn't exist: %s" % self.xpath(), pan_device=self.pandevice())
                else:
                    if var.vartype in ("member", "entry"):
                        setattr(self, variable, [])
                    else:
                        setattr(self, variable, None)
                    return
        else:
            # Use the xml that was passed in
            logger.debug("refresh_variable called using xml on %s object \"%s\" with variable %s" % (type(self), self.name, variable))
            obj = xml
        # Rebuild the elements that are lost by refreshing the variable directly
        sections = var.path.split("/")[:-1]
        root = ET.Element("root")
        next_element = root
        for section in sections:
            next_element = ET.SubElement(next_element, section)
        next_element.append(obj)
        # Refresh each variable
        variables, noninit_variables = type(self)._parse_xml(root)
        for var, value in variables.iteritems():
            setattr(self, var, value)
        for var, value in noninit_variables.iteritems():
            setattr(self, var, value)
        return getattr(self, variable, None)

    def refresh_children(self, running_config=False, xml=None):
        # Get the root of the xml to parse
        if xml is None:
            pandevice = self.pandevice()
            if running_config:
                api_action = pandevice.xapi.show
            else:
                api_action = pandevice.xapi.get
            root = api_action(self.xpath(), retry_on_peer=self.HA_SYNC)
            # Determine the first element to look for in the XML
            if self.SUFFIX is None:
                lasttag = self.XPATH.rsplit("/", 1)[-1]
            else:
                lasttag = re.match(r'^/(\w*?)\[', self.SUFFIX).group(1)
            obj = root.find("result/" + lasttag)
            if obj is None:
                raise err.PanDeviceError("Object no longer exists!")
        else:
            # Use the xml that was passed in
            obj = xml
        # Remove all the current child instances first
        self.removeall()
        # Check for children in the remaining XML
        for childtype in self.CHILDTYPES:
            childroot = obj.find(childtype.XPATH[1:])
            if childroot is not None:
                l = childtype.refresh_all_from_xml(childroot)
                self.extend(l)
        return self.children

    def refresh_xml(self, running_config=False, refresh_children=True, exceptions=True):
        # Get the root of the xml to parse
        pandevice = self.pandevice()
        logger.debug(pandevice.hostname + ": refresh_xml called on %s object \"%s\"" % (type(self), self.name))
        if running_config:
            api_action = pandevice.xapi.show
        else:
            api_action = pandevice.xapi.get
        try:
            root = api_action(self.xpath(), retry_on_peer=self.HA_SYNC)
        except (pan.xapi.PanXapiError, err.PanNoSuchNode) as e:
            if exceptions:
                raise err.PanObjectMissing("Object doesn't exist: %s" % self.xpath(), pan_device=self.pandevice())
            else:
                return
        # Determine the first element to look for in the XML
        if self.SUFFIX is None:
            lasttag = self.XPATH.rsplit("/", 1)[-1]
        else:
            lasttag = re.match(r'^/(\w*?)\[', self.SUFFIX).group(1)
        obj = root.find("result/" + lasttag)
        if obj is None:
            if exceptions:
                raise err.PanObjectMissing("Object doesn't exist: %s" % self.xpath(), pan_device=self.pandevice())
            else:
                return
        self.refresh(xml=obj, refresh_children=refresh_children, exceptions=exceptions)
        return obj

    def pandevice(self):
        if self.parent is not None:
            if isinstance(self.parent, PanDevice):
                return self.parent
            else:
                return self.parent.pandevice()
        else:
            raise err.PanDeviceNotSet("No PanDevice set for object tree")

    def panorama(self):
        if self.parent is None:
            raise err.PanDeviceNotSet("No Panorama set for object tree")
        else:
            return self.parent.panorama()

    def devicegroup(self):
        if self.parent is None:
            return
        else:
            return self.parent.devicegroup()

    def find(self, name, class_type=None, recursive=False):
        if class_type is None:
            # Find the matching object or return None
            result = next((child for child in self.children if getattr(child, child.NAME) == name), None)
        else:
            # Find the matching object or return None
            result = next((child for child in self.children if
                           getattr(child, child.NAME) == name and isinstance(child, class_type)), None)
        # Search recursively in children
        if result is None and recursive:
            for child in self.children:
                result = child.find(name, class_type, recursive)
                if result is not None:
                    break
        return result

    def findall(self, class_type, recursive=False):
        result = [child for child in self.children if isinstance(child, class_type)]
        # Search recursively in children
        if recursive:
            for child in self.children:
                result.extend(child.findall(class_type, recursive))
        return result

    def find_or_create(self, name, class_type=None, *args, **kwargs):
        result = self.find(name, class_type)
        if result is not None:
            return result
        else:
            if name is not None:
                return self.add(class_type(name, *args, **kwargs))
            else:
                return self.add(class_type(*args, **kwargs))

    def findall_or_create(self, class_type, *args, **kwargs):
        result = self.findall(class_type)
        if result:
            return result
        else:
            return [self.add(class_type(*args, **kwargs))]

    @classmethod
    def find_index(cls, list_of_panobjects, name, class_type=None):
        if class_type is None:
            class_type = cls
        indexes = [i for i, child in enumerate(list_of_panobjects) if
                   getattr(child, child.NAME) == name and type(child) == class_type]
        for index in indexes:
            return index  # Just return the first index that matches the name
        return None

    @classmethod
    def apply_all_to_device(cls, parent):
        pandevice = parent.pandevice()
        logger.debug(pandevice.hostname + ": refresh_all_to_device called on %s type" % cls)
        objects = parent.findall(cls)
        if not objects:
            return
        # Create the xpath
        xpath = objects[0].xpath_nosuffix()
        # Create the root element
        lasttag = cls.XPATH.rsplit("/", 1)[-1]
        element = ET.Element(lasttag)
        # Build the full element from the objects
        for obj in objects:
            pandevice.xml_combine(element, [obj.element()])
        # Apply the element to the xpath
        pandevice.set_config_changed()
        pandevice.xapi.edit(xpath, ET.tostring(element), retry_on_peer=cls.HA_SYNC)
        for obj in objects:
            obj._check_child_methods("apply")

    @classmethod
    def refresh_all_from_device(cls, parent, running_config=False, add=True, exceptions=False, name_only=False):
        """Factory method to instantiate class from firewall config

        This method is a factory for the class. It takes an firewall or Panorama
        and gets the xml config from the device. It generates instances of this
        class for each item this class represents in the xml config. For example,
        if the class is AddressObject and there are 5 address objects on the
        firewall, then this method will generate 5 instances of the class AddressObject.

        Args:
            parent (PanObject): A PanDevice, or a PanObject subclass with a PanDevice as its parental root
            running_config (bool): False for candidate config, True for running config
            add (bool): Update the objects of this type in pandevice with
                the refreshed values
            exceptions (bool): If False, exceptions are ignored if the xpath can't be found
            name_only (bool): If True, refresh only the name of the object, but not its variables
                This results in a smaller response to the API call when only the object name is needed.

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
            raise ValueError("name_only is invalid, can only be used on entry type objects")
        if isinstance(parent, PanDevice):
            pandevice = parent
            parent_xpath = parent.xpath_root(cls.ROOT)
        else:
            pandevice = parent.pandevice()
            parent_xpath = parent.xpath()
        logger.debug(pandevice.hostname + ": refresh_all_from_device called on %s type" % cls)
        if running_config:
            api_action = pandevice.xapi.show
        else:
            api_action = pandevice.xapi.get
        xpath = parent_xpath + cls.XPATH
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
            lasttag = cls.XPATH.rsplit("/", 1)[-1]
            obj = root.find("result/" + lasttag)
        if obj is None:
            return []
        # Refresh each object
        instances = cls.refresh_all_from_xml(obj)
        if add:
            # Remove current children of this type from parent
            parent.removeall(cls=cls)
            # Add the new children that were just refreshed from the device
            parent.extend(instances)
        return instances

    @classmethod
    def refresh_all_from_xml(cls, xml, refresh_children=True, variables=None):
        """Factory method to instantiate class from firewall config

        This method is a factory for the class. It takes an xml config
        from a firewall and generates instances of this class for each item
        this class represents in the xml config. For example, if the class is
        AddressObject and there are 5 address objects on the firewall, then
        this method will generate 5 instances of the class AddressObject.

        Args:
            xml (Element): A section of XML configuration from a firewall or Panorama
                Should not contain response or result tags

        Returns:
            list: created instances of class
        """
        instances = []
        if cls.SUFFIX is None:
            objects = [xml]
        else:
            lasttag = re.match(r'^/(\w*?)\[', cls.SUFFIX).group(1)
            objects = xml.findall(lasttag)
        # Refresh each object
        for obj in objects:
            init_variables, noinit_variables = cls._parse_xml(obj, variables=variables)
            if cls.SUFFIX is not None:
                name = obj.get('name')
                if name is not None:
                    init_variables[cls.NAME] = name
            # Create the object instance
            instance = cls(**init_variables)
            # Set values of no init variables
            for var, value in noinit_variables.iteritems():
                vars(instance)[var] = value
            instances.append(instance)
            # Refresh the children of these instances
            if refresh_children:
                for childtype in cls.CHILDTYPES:
                    childroot = obj.find(childtype.XPATH[1:])
                    if childroot is not None:
                        l = childtype.refresh_all_from_xml(childroot)
                        instance.extend(l)
        return instances

    @classmethod
    def _parse_xml(cls, xml, variables=None):
        init_variables = {}
        noinit_variables = {}
        # Parse each variable
        if variables:
            vars = variables
        else:
            vars = cls.vars()
        for var in vars:
            missing_replacement = False
            # Determine if variable is part of __init__ args
            if var.vartype == "none":
                continue
            if var.init:
                vardict = init_variables
            else:
                vardict = noinit_variables
            # Search for variable replacements in path
            path = var.path
            matches = re.findall(r'{{(.*?)}}', path)
            for match in matches:
                regex = r'{{' + re.escape(match) + r'}}'
                # Find the discovered replacement in the list of vars
                matchedvar = next((x for x in cls.vars() if x.variable == match), None)
                try:
                    replacement = init_variables[match]
                except KeyError:
                    replacement = noinit_variables[match]
                if replacement is None:
                    missing_replacement = True
                    break
                if matchedvar.vartype == "entry":
                    # If it's an 'entry' variable
                    if len(replacement) == 1:
                        replacement = replacement[0]
                    path = re.sub(regex,
                                  matchedvar.path + "/" + "entry[@name='%s']" % replacement,
                                  path)
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
                    option_paths = {opt: re.sub(r"\([\w\d|-]*\)", opt, path) for opt in options}
                    found = False
                    for opt, opt_path in option_paths.iteritems():
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
                    vardict[var.variable] = cls._convert_var(xml.findtext(path), var.vartype)
                if var.default is not None and vardict[var.variable] is None:
                    vardict[var.variable] = var.default
        return init_variables, noinit_variables

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

    def _set_reference(self, reference_name, reference_type, reference_var, exclusive, refresh, update, running_config, *args, **kwargs):
        pandevice = self.pandevice()
        if refresh:
            allobjects = reference_type.refresh_all_from_device(pandevice, running_config=running_config)
        else:
            allobjects = pandevice.findall(reference_type)
        # Find any current references to self and remove them
        if exclusive:
            for obj in allobjects:
                references = getattr(obj, reference_var)
                if self in references:
                    if reference_name is not None and getattr(obj, reference_type.NAME) == reference_name:
                        continue
                    references.remove(self)
                    if update: obj.update(reference_var)
                elif str(self) in references:
                    if reference_name is not None and getattr(obj, reference_type.NAME) == reference_name:
                        continue
                    references.remove(str(self))
                    if update: obj.update(reference_var)
        # Add new reference to self in requested object
        if reference_name is not None:
            obj = pandevice.find_or_create(reference_name, reference_type, *args, **kwargs)
            var = getattr(obj, reference_var)
            if self not in var and str(self) not in var:
                var.append(self)
                if update: obj.update(reference_var)
            return obj


class VarPath(object):
    """Configuration variable within the object

    Attributes:
        path (string): The relative xpath to the variable
        variable (string): The name of the instance variable in the class
        vartype (string): The type of variable (None or 'member')
    """
    def __init__(self, path, variable=None, vartype=None, default=None, init=True, condition=None):
        self.path = path
        self._variable = variable
        self.vartype = vartype
        self.default = default
        self.init = init
        self.condition = condition

    @property
    def variable(self):
        if self._variable is None:
            return self.path.rsplit("/", 1)[-1].replace('-','_')
        else:
            return self._variable

    @variable.setter
    def variable(self, value):
        self._variable = value


class VsysImportMixin(object):
    """Modify PanObject methods to set vsys import configuration

    This only applies to some object types, hence it is a Mixin,
    and not part of PanObject
    """
    XPATH_IMPORT = None
    CHILDMETHODS = ("apply", "create", "delete")

    def __init__(self, *args, **kwargs):
        super(VsysImportMixin, self).__init__(*args, **kwargs)

    def apply(self, *args, **kwargs):
        super(VsysImportMixin, self).apply(*args, **kwargs)
        self.child_apply()

    def create(self, *args, **kwargs):
        super(VsysImportMixin, self).create(*args, **kwargs)
        self.child_create()

    def delete(self, *args, **kwargs):
        self.child_delete()
        super(VsysImportMixin, self).delete(*args, **kwargs)

    def child_apply(self):
        # Don't do anything if interface in ha or ag mode
        if str(self.mode) in ("ha", "aggregate-group"):
            self.set_vsys(None, refresh=True, update=True)
        else:
            self.create_import()

    def child_create(self):
        # Don't do anything if interface in ha or ag mode
        if str(self.mode) in ("ha", "aggregate-group"):
            self.set_vsys(None, refresh=True, update=True)
        else:
            self.create_import()

    def child_delete(self):
        self.delete_import()

    def create_import(self, vsys=None):
        if vsys is None:
            vsys = self.vsys
        if vsys != "shared" and self.XPATH_IMPORT is not None:
            pandevice = self.pandevice().active()
            xpath_import = self.xpath_vsys() + "/import" + self.XPATH_IMPORT
            pandevice.xapi.set(xpath_import, "<member>%s</member>" % self.name, retry_on_peer=True)

    def delete_import(self, vsys=None):
        if vsys is None:
            vsys = self.vsys
        if vsys != "shared" and self.XPATH_IMPORT is not None:
            pandevice = self.pandevice().active()
            xpath_import = self.xpath_vsys() + "/import" + self.XPATH_IMPORT
            pandevice.xapi.delete(xpath_import + "/member[text()='%s']" % self.name, retry_on_peer=True)

    def set_vsys(self, vsys_id, refresh=False, update=False, running_config=False):
        import device
        if refresh and running_config:
            raise ValueError("Can't refresh vsys from running config in set_vsys method")
        if refresh:
            pandevice = self.pandevice().active()
            all_vsys = device.Vsys.refresh_all_from_device(pandevice, name_only=True)
            for a_vsys in all_vsys:
                a_vsys.refresh_variable(self.XPATH_IMPORT.split("/")[-1])
        return self._set_reference(vsys_id, device.Vsys, self.XPATH_IMPORT.split("/")[-1], True, refresh=False, update=update, running_config=running_config)

    @classmethod
    def refresh_all_from_device(cls, parent, running_config=False, add=True, exceptions=False, name_only=False):
        instances = super(VsysImportMixin, cls).refresh_all_from_device(parent, running_config, add=False, exceptions=exceptions, name_only=name_only)
        # Filter out instances that are not in this vlan's imports
        pandevice = parent.pandevice()
        if running_config:
            api_action = pandevice.xapi.show
        else:
            api_action = pandevice.xapi.get
        if parent.vsys != "shared" and cls.XPATH_IMPORT is not None:
            xpath_import = parent.xpath_vsys() + "/import" + cls.XPATH_IMPORT
            try:
                imports_xml = api_action(xpath_import, retry_on_peer=True)
            except (err.PanNoSuchNode, pan.xapi.PanXapiError) as e:
                if not str(e).startswith("No such node"):
                    raise e
                else:
                    imports = []
            else:
                imports = imports_xml.findall(".//member")
                if imports is not None:
                    imports = [member.text for member in imports]
            if imports is not None:
                instances = [instance for instance in instances if instance.name in imports]
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

    Attributes:
        hostname: Hostname or IP of device for API connections
        port: Port of device for API connections
        vsys: This device class represents a specific VSYS
        devicegroup: This device class represents a specific Device-Group
            in Panorama
        xpath: The XPath for the root of this device, taking into account any
            VSYS, Device-Group, or Panorama state
        timeout: The timeout for API connections
        api_key: The API Key for connecting to the device's API
    """

    def __init__(self,
                 hostname,
                 api_username=None,
                 api_password=None,
                 api_key=None,
                 port=443,
                 is_virtual=None,
                 timeout=1200,
                 interval=.5,
                 ):
        """Initialize PanDevice"""
        super(PanDevice, self).__init__()
        # create a class logger
        self._logger = logging.getLogger(__name__ + "." + self.__class__.__name__)

        self.hostname = hostname
        self.port = port
        self._api_username = api_username
        self._api_password = api_password
        self._api_key = api_key
        self.is_virtual = is_virtual
        self.timeout = timeout
        self.interval = interval
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
        self.content_version = None
        self.platform = None

        # HA Pair Firewall or Panorama
        self._ha_peer = None
        self._ha_active = True
        self.ha_failed = None

    @classmethod
    def create_from_device(cls,
                           hostname,
                           api_username=None,
                           api_password=None,
                           api_key=None,
                           port=443,
                           ):
        """Create a Firewall or Panorama object from a live device

        This method connects to the device and detects its type and current
        state in order to create a PanDevice subclass.

        :returns PanDevice subclass instance (Firewall or Panorama instance)
        """
        # Create generic PanDevice to connect and get information
        import firewall
        import panorama
        device = PanDevice(hostname,
                           api_username,
                           api_password,
                           api_key,
                           port,
                           )
        system_info = device.refresh_system_info()
        version = system_info[0]
        model = system_info[1]
        if model == "Panorama":
            instance = panorama.Panorama(hostname,
                                         api_username,
                                         api_password,
                                         device.api_key,
                                         port,
                                         )
        else:
            serial = system_info[2]
            instance = firewall.Firewall(hostname,
                                         api_username,
                                         api_password,
                                         device.api_key,
                                         serial,
                                         port,
                                         )
        instance.version = version
        return instance

    class XapiWrapper(pan.xapi.PanXapi):
        """This is a confusing class used for catching exceptions and faults."""
        # TODO: comment the hell out of it!

        CONNECTION_EXCEPTIONS = (err.PanConnectionTimeout, err.PanURLError, err.PanSessionTimedOut)

        def __init__(self, *args, **kwargs):
            self.pan_device = kwargs.pop('pan_device', None)
            pan.xapi.PanXapi.__init__(self, *args, **kwargs)

            for name, method in inspect.getmembers(
                    pan.xapi.PanXapi,
                    inspect.ismethod):
                # Ignore hidden methods
                if name[0] == "_":
                    continue
                # Ignore non-api methods
                if name in ('xml_result', 'xml_root', 'cmd_xml'):
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
                retry_on_peer = kwargs.pop("retry_on_peer", True if super_method_name not in ('keygen', 'op', 'ad_hoc', 'export') else False)
                if self.pan_device.ha_failed and self.pan_device.ha_peer is not None \
                    and not self.pan_device.ha_peer.ha_failed and retry_on_peer:
                    # This device is failed, use the other
                    # TODO: Should this be retry_on_peer, or should there be some way to remove failure status?
                    # TODO: Don't do this if retry on peer is false!
                    logger.debug("Current device is failed, starting with other device")
                    result = getattr(self.pan_device.ha_peer.xapi, super_method_name)(retry_on_peer=True, *args, **kwargs)
                elif not self.pan_device.is_active() and self.pan_device.ha_peer is not None and retry_on_peer:
                    # I'm not active, call the peer
                    logger.debug("super_method_name: " + str(super_method_name))
                    logger.debug("ha_peer: " + str(self.pan_device.ha_peer))
                    result = getattr(self.pan_device.ha_peer.xapi, super_method_name)(retry_on_peer=True, *args, **kwargs)
                else:
                    try:
                        # This device has not failed, or both have failed
                        # and this device is active
                        # Frist get the superclass method
                        super_method(self, *args, **kwargs)
                        result = copy.deepcopy(self.element_root)
                    except pan.xapi.PanXapiError as e:
                        the_exception = self.classify_exception(e)
                        if type(the_exception) in self.CONNECTION_EXCEPTIONS:
                            # The attempt on the active failed with a connection error
                            new_active = self.pan_device.set_failed()
                            if retry_on_peer and new_active is not None:
                                logger.debug("Connection to device '%s' failed, using HA peer '%s'" %
                                             (self.pan_device.hostname, new_active.hostname))
                                # The active failed, apply on passive (which is now active)
                                kwargs["retry_on_peer"] = False
                                getattr(new_active.xapi, super_method_name)(*args, **kwargs)
                                result = copy.deepcopy(new_active.xapi.element_root)
                            else:
                                raise the_exception
                        else:
                            raise the_exception
                return result

            return method

        def classify_exception(self, e):
            if str(e) == "Invalid credentials.":
                return err.PanInvalidCredentials(
                    str(e),
                    pan_device=self.pan_device,
                )
            elif str(e).startswith("URLError:"):
                if str(e).endswith("timed out"):
                    return err.PanConnectionTimeout(
                        str(e),
                        pan_device=self.pan_device,
                    )
                else:
                    return err.PanURLError(str(e),
                                          pan_device=self.pan_device)

            elif str(e).startswith("timeout waiting for job"):
                return err.PanJobTimeout(str(e),
                                        pan_device=self.pan_device)

            elif str(e).startswith("Another commit/validate is in"
                                   " progress. Please try again later"):
                return err.PanCommitInProgress(str(e),
                                              pan_device=self.pan_device)

            elif str(e).startswith("A commit is in progress."):
                return err.PanCommitInProgress(str(e),
                                              pan_device=self.pan_device)

            elif str(e).startswith("You cannot commit while an install is in progress. Please try again later."):
                return err.PanInstallInProgress(str(e),
                                               pan_device=self.pan_device)

            elif str(e).startswith("Session timed out"):
                return err.PanSessionTimedOut(str(e),
                                             pan_device=self.pan_device)

            elif str(e).startswith("No such node"):
                return err.PanNoSuchNode(str(e),
                                        pan_device=self.pan_device)
            elif str(e).startswith("Failed to synchronize running configuration with HA peer"):
                return err.PanHAConfigSyncFailed(str(e),
                                                pan_device=self.pan_device)
            elif str(e).startswith("Configuration is locked by"):
                return err.PanLockError(str(e),
                                       pan_device=self.pan_device)
            elif str(e).startswith("Another sync is in progress. Please try again later"):
                return err.PanHASyncInProgress(str(e),
                                              pan_device=self.pan_device)
            else:
                return err.PanDeviceXapiError(str(e),
                                             pan_device=self.pan_device)

    # Properties

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

    def update_connection_method(self):
        self._xapi_private = self.generate_xapi()
        return self._xapi_private

    def pandevice(self):
        if self.parent is None:
            return self
        else:
            return self.parent.pandevice()

    def generate_xapi(self):
        kwargs = {'api_key': self.api_key,
                  'hostname': self.hostname,
                  'port': self.port,
                  'timeout': self.timeout,
                  'pan_device': self,
                  }
        xapi_constructor = PanDevice.XapiWrapper
        return xapi_constructor(**kwargs)

    def set_config_changed(self, scope=None):
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

    def _parent_xpath(self):
        parent_xpath = self.xpath_root(self.ROOT)
        return parent_xpath

    def xpath_root(self, root_type):
        if root_type == Root.DEVICE:
            xpath = self.xpath_device()
        elif root_type == Root.VSYS:
            xpath = self.xpath_vsys()
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
        self._logger.debug("Getting API Key from %s for user %s" %
                           (self.hostname, self._api_username))
        xapi = PanDevice.XapiWrapper(
            pan_device=self,
            api_username=self._api_username,
            api_password=self._api_password,
            hostname=self.hostname,
            port=self.port,
            timeout=self.timeout
        )
        xapi.keygen(retry_on_peer=False)
        return xapi.api_key

    def devices(self):
        return self

    def show_system_info(self):
        root = self.xapi.op(cmd="show system info", cmd_xml=True)
        pconf = PanConfig(root)
        system_info = pconf.python()
        return system_info['response']['result']

    def refresh_system_info(self):
        """Refresh system information variables

        Returns:
            system information like version, platform, etc.
        """
        system_info = self.show_system_info()

        self.version = system_info['system']['sw-version']
        self.platform = system_info['system']['model']

        return self.version, self.platform

    def refresh_version(self):
        """Get version of PAN-OS

        returns:
            version of PAN-OS
        """
        system_info = self.refresh_system_info()
        self.version = system_info[0]
        return self.version

    def set_hostname(self, hostname):
        """Set the device hostname

        Convenience method to set the firewall or Panorama hostname

        Args:
            hostname (str): hostname to set (should never be None)

        Raises:
            ValueError: if hostname is None
        """
        if hostname is None:
            raise ValueError("hostname should not be None")
        from pandevice import device
        self._logger.debug("Set hostname: %s" % str(hostname))
        system = self.findall_or_create(device.SystemSettings)[0]
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
        from pandevice import device
        self._logger.debug("Set dns-servers: primary:%s secondary:%s" % (primary, secondary))
        system = self.findall_or_create(device.SystemSettings)[0]
        if system.dns_primary != primary:
            system.dns_primary = primary
            # This handles addition and deletion
            system.update("dns_primary")
        if system.dns_secondary != secondary:
            system.dns_secondary = secondary
            system.update("dns_secondary")

    def set_ntp_servers(self, primary, secondary=None):
        from pandevice import device
        self._logger.debug("Set ntp-servers: primary:%s secondary:%s" % (primary, secondary))
        system = self.findall_or_create(device.SystemSettings)[0]
        if primary is None:
            ntp1 = system.findall(device.NTPServerPrimary)
            if ntp1:
                ntp1[0].delete()
        else:
            ntp1 = system.findall_or_create(device.NTPServerPrimary)[0]
            if ntp1.address != primary:
                ntp1.address = primary
                ntp1.create()
        if secondary is None:
            ntp2 = system.findall(device.NTPServerSecondary)
            if ntp2:
                ntp2[0].delete()
        else:
            ntp2 = system.findall_or_create(device.NTPServerSecondary)[0]
            if ntp2.address != secondary:
                ntp2.address = secondary
                ntp2.create()

    def pending_changes(self):
        self.xapi.op(cmd="check pending-changes", cmd_xml=True)
        pconf = PanConfig(self.xapi.element_result)
        response = pconf.python()
        return response['result']

    def add_commit_lock(self, comment=None, scope="shared", exceptions=True):
        self._logger.debug("Add commit lock requested for scope %s" % scope)
        cmd = ET.Element("request")
        subel = ET.SubElement(cmd, "commit-lock")
        subel = ET.SubElement(subel, "add")
        if comment is not None:
            subel = ET.SubElement(subel, "comment")
            subel.text = comment
        try:
            self.xapi.op(ET.tostring(cmd), vsys=scope)
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

    def remove_commit_lock(self, admin=None, scope="shared", exceptions=True):
        self._logger.debug("Remove commit lock requested for scope %s" % scope)
        cmd = ET.Element("request")
        subel = ET.SubElement(cmd, "commit-lock")
        subel = ET.SubElement(subel, "remove")
        if admin is not None:
            subel = ET.SubElement(subel, "admin")
            subel.text = admin
        try:
            self.xapi.op(ET.tostring(cmd), vsys=scope)
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

    def add_config_lock(self, comment=None, scope="shared", exceptions=True):
        self._logger.debug("Add config lock requested for scope %s" % scope)
        cmd = ET.Element("request")
        subel = ET.SubElement(cmd, "config-lock")
        subel = ET.SubElement(subel, "add")
        if comment is not None:
            subel = ET.SubElement(subel, "comment")
            subel.text = comment
        try:
            self.xapi.op(ET.tostring(cmd), vsys=scope)
        except (pan.xapi.PanXapiError, err.PanDeviceXapiError) as e:
            if not re.match(r"Config for scope (shared|vsys\d) is currently locked", str(e)) and \
                    not re.match(r"You already own a config lock for scope", str(e)):
                raise
            else:
                if exceptions:
                    raise err.PanLockError(str(e), pan_device=self)
                else:
                    self._logger.debug(str(e))
                    return False
        self.config_locked = True
        return True

    def remove_config_lock(self, scope="shared", exceptions=True):
        self._logger.debug("Remove config lock requested for scope %s" % scope)
        cmd = ET.Element("request")
        subel = ET.SubElement(cmd, "config-lock")
        subel = ET.SubElement(subel, "remove")
        try:
            self.xapi.op(ET.tostring(cmd), vsys=scope)
        except (pan.xapi.PanXapiError, err.PanDeviceXapiError) as e:
            if not re.match(r"Config is not currently locked for scope (shared|vsys\d)", str(e)):
                raise
            else:
                if exceptions:
                    raise err.PanLockError(str(e), pan_device=self)
                else:
                    self._logger.debug(str(e))
                    return False
        self.config_locked = False
        return True

    def remove_all_locks(self, scope="shared"):
        self.remove_config_lock(scope=scope, exceptions=False)
        self.remove_commit_lock(scope=scope, exceptions=False)

    def check_commit_locks(self):
        self.xapi.op("show commit-locks", cmd_xml=True)
        response = self.xapi.element_result.find(".//entry")
        return True if response is not None else False

    def check_config_locks(self):
        self.xapi.op("show config-locks", cmd_xml=True)
        response = self.xapi.element_result.find(".//entry")
        return True if response is not None else False

    def revert_to_running_configuration(self):
        self._logger.debug("Revert to running configuration on device: %s" % (self.hostname,))
        self.xapi.op("<load><config><from>"
                     "running-config.xml"
                     "</from></config></load>")

    def restart(self):
        self._logger.debug("Requesting restart on device: %s" % (self.hostname,))
        try:
            self.xapi.op("request restart system", cmd_xml=True)
        except pan.xapi.PanXapiError as e:
            if not str(e).startswith("Command succeeded with no output"):
                raise e

    # High Availability Methods

    @property
    def ha_peer(self):
        return self._ha_peer

    def set_ha_peers(self, pandevice):
        self._ha_peer = pandevice
        self.ha_peer._ha_peer = self
        # If both are active or both are passive,
        # set self to active and ha_peer to passive
        if self._ha_active == self.ha_peer._ha_active:
            self._ha_active = True
            self.ha_peer._ha_active = False

    def active(self):
        if self._ha_active:
            return self
        else:
            return self.ha_peer

    def passive(self):
        if self._ha_active:
            return self.ha_peer
        else:
            return self

    def is_active(self):
        return self._ha_active

    def activate(self):
        self._ha_active = True
        if self.ha_peer is not None:
            self.ha_peer._ha_active = False

    def toggle_ha_active(self):
        if self.ha_peer is not None:
            self._ha_active = not self._ha_active
            self.ha_peer._ha_active = not self.ha_peer._ha_active

    def update_ha_active(self):
        # TODO: Implement this
        raise NotImplementedError

    def set_failed(self):
        if self.ha_peer is None:
            return None
        self.ha_failed = True
        if self.ha_peer is not None:
            self.ha_peer.activate()
            return self.ha_peer

    def refresh_ha_active(self):
        logger.debug("Refreshing active firewall in HA Pair")
        ha_state = self.active().op("show high-availability state")
        enabled = ha_state.find("./result/enabled")
        if enabled is None:
            return
        if enabled.text == "yes":
            state = ha_state.find("./result/group/local-info/state")
            if state is None:
                return
            if state.text != "active":
                logger.debug("Current firewall state is %s, switching to use other firewall" % state.text)
                self.toggle_ha_active()
            else:
                logger.debug("Current firewall is active, no change made")

    def synchronize_config(self):
        state = self.config_sync_state()
        if state == "synchronization in progress":
            # Wait until synchronization done
            return self.watch_op("show high-availability state", "group/running-sync", "synchronized")
        elif state != "synchronized":
            logger.debug("Synchronizing configuration with HA peer")
            response = self.active().op("request high-availability sync-to-remote running-config", "shared")
            line = response.find("./msg/line")
            if line is None:
                raise err.PanDeviceError("Unable to syncronize configuration, no response from firewall")
            if line.text.startswith("successfully sync'd running configuration to HA peer"):
                return True
            else:
                raise err.PanDeviceError("Unable to syncronize configuration: %s" % line.text)
        else:
            logger.debug("Config synchronization is not required, already synchronized")
            return True

    def config_sync_state(self):
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
        state = self.config_sync_state()
        if state is None:
            return False
        elif state != "synchronized":
            return False
        else:
            return True

    # Commit methods

    def commit(self, sync=False, exception=False, cmd=None):
        self._logger.debug("Commit initiated on device: %s" % (self.hostname,))
        return self._commit(sync=sync, exception=exception, cmd=cmd)

    def _commit(self, cmd=None, exclude=None, commit_all=False,
                sync=False, sync_all=False, exception=False):
        """Internal use commit helper method.
        # TODO: Support per-vsys commit

        :param exclude:
            Can be:
                device-and-network
                policy-and-objects
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
        if isinstance(cmd, pan.commit.PanCommit):
            cmd = cmd.cmd()
        elif isinstance(cmd, ET.Element):
            cmd = ET.tostring(cmd)
        elif isinstance(cmd, basestring):
            pass
        else:
            cmd = ET.Element("commit")
            if exclude is not None:
                excluded = ET.SubElement(cmd, "partial")
                excluded = ET.SubElement(excluded, exclude)
            cmd = ET.tostring(cmd)
        logger.debug(self.hostname + ": commit requested: commit_all:%s sync:%s sync_all:%s cmd:%s" % (str(commit_all),
                                                                                                       str(sync),
                                                                                                       str(sync_all),
                                                                                                       cmd,
                                                                                                       ))
        if commit_all:
            action = "all"
        else:
            action = None
        self._logger.debug("Initiating commit")
        commit_response = self.xapi.commit(cmd=cmd,
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
            jobid = commit_response.find('./result/job').text
        except AttributeError:
            if exception:
                raise err.PanCommitNotNeeded("Commit not needed",
                                             pan_device=self)
            else:
                return
        if not sync:
            # Don't synchronize, just return
            self._logger.debug("Commit initiated (async), job id: %s" % (jobid,))
            return jobid
        else:
            result = self.syncjob(commit_response, sync_all=sync_all)

            if exception and not result['success']:
                self._logger.debug("Commit failed - device: %s, job: %s, messages: %s, warnings: %s" %
                                   (self.hostname,
                                    result['jobid'],
                                    result['messages'],
                                    result['warnings']))
                raise err.PanCommitFailed(pan_device=self, result=result)
            else:
                if result['success']:
                    self._logger.debug("Commit succeeded - device: %s, job: %s, messages: %s, warnings: %s" %
                                       (self.hostname,
                                        result['jobid'],
                                        result['messages'],
                                        result['warnings']))
                else:
                    self._logger.debug("Commit failed - device: %s, job: %s, messages: %s, warnings: %s" %
                                       (self.hostname,
                                        result['jobid'],
                                        result['messages'],
                                        result['warnings']))
                return result

    def syncjob(self, job_id, sync_all=False, interval=0.5):
        """Block until job completes and return result

        Args:
            job_id: int job ID, or response XML from job creation

        Returns:
            Job result dict
        """
        import httplib
        if interval is not None:
            try:
                interval = float(interval)
                if interval < 0:
                    raise ValueError
            except ValueError:
                raise err.PanDeviceError('Invalid interval: %s' % interval)

        try:
            job = job_id.find('./result/job')
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
                if not str(e).startswith("URLError:") and not str(e).startswith("Invalid credentials."):
                    # Error not related to connection issue.  Raise it.
                    raise e
                else:
                    #self._logger.debug2("Sleep %.2f seconds" % interval)
                    time.sleep(interval)
                    continue
            except httplib.BadStatusLine as e:
                # Connection issue.  The firewall is currently restarting the API service or rebooting
                #self._logger.debug2("Sleep %.2f seconds" % interval)
                time.sleep(interval)
                continue

            status = job_xml.find("./result/job/status")
            if status is None:
                raise pan.xapi.PanXapiError('No status element in ' +
                                            "'%s' response" % cmd)
            if status.text == 'FIN' and sync_all:
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

            if (self.timeout is not None and self.timeout != 0 and
                        time.time() > start_time + self.timeout):
                raise pan.xapi.PanXapiError("Timeout waiting for " +
                                            "job %s completion" % job)

            #self._logger.debug2("Sleep %.2f seconds" % interval)
            time.sleep(interval)

    def syncreboot(self, interval=5.0, timeout=600):
        """Block until reboot completes and return version of device"""

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
                if not e.msg.startswith("URLError:") and not e.msg.startswith("Invalid credentials."):
                    # Error not related to connection issue.  Raise it.
                    raise e
                else:
                    # Connection issue.  The firewall is currently rebooting.
                    is_rebooting = True
                    self._logger.debug("Connection attempted: %s" % str(e))
                    self._logger.debug("Device is not available yet. Connection attempts: %s" % str(attempts))
            except httplib.BadStatusLine as e:
                # Connection issue.  The firewall is currently rebooting.
                is_rebooting = True
                self._logger.debug("Connection attempted: %s" % str(e))
                self._logger.debug("Device is not available yet. Connection attempts: %s" % str(attempts))
            else:
                # No exception... connection succeeded and device is up!
                # This could mean reboot hasn't started yet, so check that we had
                # a connection error prior to this success.
                if is_rebooting:
                    self._logger.debug("Device is up! Running version %s" % version)
                    return version
                else:
                    self._logger.debug("Device is up, but it probably hasn't started rebooting yet.")

            # Check to see if we hit timeout
            if (self.timeout is not None and self.timeout != 0 and
                        time.time() > start_time + self.timeout):
                raise err.PanDeviceError("Timeout waiting for device to reboot")

            # Sleep and try again
            self._logger.debug("Sleep %.2f seconds" % interval)
            time.sleep(interval)

    def _parse_job_results(self, show_job_xml, get_devices=True):
        # Parse the final results
        pconf = PanConfig(show_job_xml)
        job_response = pconf.python()
        try:
            job = job_response['response']['result']['job']
        except KeyError:
            raise err.PanDeviceError("Can't get job results, error parsing results xml")
        devices_results = {}
        devices_success = True
        # Determine if this was a commit all job
        devices = show_job_xml.findall("./result/job/devices/entry")
        if devices and get_devices:
            devices = job['devices']['entry']
            for device in devices:
                dev_success = True if device['result'] == "OK" else False
                if not dev_success:
                    devices_success = False
                devices_results[device['serial-no']] = {
                    'success': dev_success,
                    'serial': device['serial-no'],
                    'name': device['devicename'],
                    'result': device['result'],
                    'starttime': device['tstart'],
                    'endtime': device['tfin'],
                }
                # Errors and warnings might not have a full structure.  If it is just a string, then
                # a TypeError will be produced, so in that case, just grab the string.
                try:
                    devices_results[device['serial-no']]['warnings'] = device['details']['msg']['warnings']
                except TypeError as e:
                    devices_results[device['serial-no']]['warnings'] = ""
                try:
                    devices_results[device['serial-no']]['messages'] = device['details']['msg']['errors'][
                        'line']
                except TypeError as e:
                    devices_results[device['serial-no']]['messages'] = device['details']

        success = True if job['result'] == "OK" and devices_success else False

        if get_devices:
            messages = []
        else:
            messages = job['details']['line']
        if issubclass(messages.__class__, basestring):
            messages = [messages]
        # Create the results dict
        result = {
            'success': success,
            'result': job['result'],
            'jobid': job['id'],
            'user': job['user'],
            'warnings': job['warnings'],
            'starttime': job['tenq'],
            'endtime': job['tfin'],
            'messages': messages,
            'devices': devices_results,
            'xml': show_job_xml,
        }
        return result

    def watch_op(self, cmd, path, value, vsys=None, cmd_xml=True, interval=1.0):
        """Watch an operational command for an expected value"""
        if interval is not None:
            try:
                interval = float(interval)
                if interval < 0:
                    raise ValueError
            except ValueError:
                raise err.PanDeviceError('Invalid interval: %s' % interval)

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

            if (self.timeout is not None and self.timeout != 0 and
                        time.time() > start_time + self.timeout):
                raise err.PanJobTimeout("Timeout waiting for value: %s" % value)

            logger.debug("Sleep %.2f seconds" % interval)
            time.sleep(interval)
