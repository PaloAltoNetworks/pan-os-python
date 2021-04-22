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


"""Retrieving and parsing predefined objects from the firewall"""

from pan.xapi import PanXapiError

import panos.errors as err
from panos import getlogger, objects
from panos.updater import PanOSVersion

logger = getlogger(__name__)


class Predefined(object):
    """Predefined Objects Subsystem of Firewall

    A member of a base.PanDevice object that has special methods for
    interacting with the predefined objects of the firewall

    This class is typically not instantiated by anything but the
    base.PanDevice class itself. There is an instance of this Predefined class
    inside every instantiated base.PanDevice class.

    Args:
        device (base.PanDevice): The firewall or Panorama this Predefined subsystem leverages

    """

    # xpath
    XPATH = "/config/predefined"
    SINGLE_ENTRY_XPATH = "/entry[@name='{0}']"
    ALL_ENTRIES_XPATH = "/entry"

    def __init__(self, device=None, *args, **kwargs):
        # Create a class logger
        self._logger = getlogger(__name__ + "." + self.__class__.__name__)

        self.parent = device
        self._initialize_params()

    def _initialize_params(self):
        self.application_container_objects = {}
        self.application_objects = {}
        self.service_objects = {}
        self.tag_objects = {}

    def _get_xml(self, xpath):
        """use the parent to get the xml given the xpath"""

        root = self.parent.xapi.get(xpath, retry_on_peer=False)
        return root.find("result")

    def _refresh(self, decisions, name=None):
        x = decisions[0][0]()
        x.parent = self
        xpath = x.xpath_nosuffix()
        if name is not None:
            xpath += self.SINGLE_ENTRY_XPATH.format(name)
        else:
            xpath += self.ALL_ENTRIES_XPATH

        xml = self._get_xml(xpath)

        for elm in xml:
            for cls, param, mandatory_xml_field in decisions:
                if (
                    mandatory_xml_field is None
                    or elm.find(mandatory_xml_field) is not None
                ):
                    inst = cls()
                    inst.refresh(xml=elm)
                    getattr(self, param)[inst.uid] = inst
                    break

    @property
    def vsys(self):
        return self.parent.vsys

    def _refresh_application(self, name=None):
        return self._refresh(
            [
                (
                    objects.ApplicationContainer,
                    "application_container_objects",
                    "functions",
                ),
                (objects.ApplicationObject, "application_objects", None),
            ],
            name,
        )

    def _refresh_service(self, name=None):
        return self._refresh([(objects.ServiceObject, "service_objects", None),], name,)

    def _refresh_tag(self, name=None):
        return self._refresh([(objects.Tag, "tag_objects", None),], name,)

    def refresh_application(self, name):
        """Refresh a Single Predefined Application

        This method refreshes single predefined application or application container
        (predefined only object).

        Args:
            name (str): Name of the application to refresh

        """
        return self._refresh_application(name)

    def refresh_service(self, name):
        """Refresh a Single Predefined Service

        This method refreshes single predefined service (predefined only object).

        Args:
            name (str): Name of the service to refresh

        """
        return self._refresh_service(name)

    def refresh_tag(self, name):
        """Refresh a Single Predefined Tag

        This method refreshes single predefined tag (predefined only object).

        Args:
            name (str): Name of the tag to refresh

        """
        return self._refresh_tag(name)

    def refreshall_applications(self):
        """Refresh all Predefined Applications

        This method refreshes all predefined applications and application containers.

        CAUTION: This method requires a lot of overhead on the device api to respond.
        Response time will vary by platform, but know that it will generally take
        longer than a normal api request.

        """
        return self._refresh_application()

    def refreshall_services(self):
        """Refresh all Predefined Services

        This method refreshes all predefined services.

        """
        return self._refresh_service()

    def refreshall_tags(self):
        """Refresh all Predefined Tags

        This method refreshes all predefined tag objects

        """
        return self._refresh_tag()

    def refreshall(self):
        """Refresh all Predefined Objects

        This method refreshes all predefined objects. This includes applications,
        application containers, services, and tags.

        CAUTION: This method requires a lot of overhead on the device api to respond.
        Response time will vary by platform, but know that it will generally take
        longer than a normal api request.

        """
        # first we clear all existing objects
        self._initialize_params()

        # now we call the refresh methods
        for x in [x for x in dir(self) if x.startswith("refreshall_")]:
            getattr(self, x)()

    def application(self, name, refresh_if_none=True, include_containers=True):
        """Get a Predefined Application

        Return the instance of the application from the given name.

        Args:
            name (str): Name of the application
            refresh_if_none (bool): Refresh the application if it is not found
            include_containers (bool): also search application containers if no match found

        Returns:
            Either an ApplicationObject, ApplicationContainerObject, or None

        """
        obj = self.application_objects.get(name, None)
        if obj is None and include_containers:
            obj = self.application_container_objects.get(name, None)

        if obj is None and refresh_if_none:
            self.refresh_application(name)
            # recursive call but with no refresh
            obj = self.application(
                name, refresh_if_none=False, include_containers=include_containers
            )

        return obj

    def _retrieve_predefined_object_from(
        self, name, param, refresh_if_none, refresh_func
    ):
        if name in getattr(self, param):
            return getattr(self, param)[name]

        if refresh_if_none:
            getattr(self, refresh_func)(name)
            return getattr(self, param).get(name, None)

    def service(self, name, refresh_if_none=True):
        """Get a Predefined Service

        Return the instance of the service from the given name.

        Args:
            name (str): Name of the service
            refresh_if_none (bool): Refresh the service if it is not found

        Returns:
            Either a ServiceObject or None

        """
        return self._retrieve_predefined_object_from(
            name, "service_objects", refresh_if_none, "refresh_service"
        )

    def tag(self, name, refresh_if_none=True):
        """Get a Predefined Tag

        Return the instance of the tag from the given name.

        Args:
            name (str): Name of the tag
            refresh_if_none (bool): Refresh the tag if it is not found

        Returns:
            Either a Tag or None

        """
        return self._retrieve_predefined_object_from(
            name, "tag_objects", refresh_if_none, "refresh_tag"
        )

    def applications(self, names, refresh_if_none=True, include_containers=True):
        """Get a list of Predefined Applications

        Return a list of the instances of the applications from the given names.

        Args:
            names (list): Names of the applications
            refresh_if_none (bool): Refresh the application(s) if it is not found
            include_containers (bool): also search application containers if no match found

        Returns:
            A list of all found ApplicationObjects or ApplicationContainerObjects

        """
        objs = []

        for name in set(names):
            obj = self.application(
                name,
                refresh_if_none=refresh_if_none,
                include_containers=include_containers,
            )
            if obj:
                objs.append(obj)

        return objs

    def services(self, names, refresh_if_none=True):
        """Get a list of Predefined Services

        Return a list of the instances of the services from the given names.

        Args:
            names (list): Names of the services
            refresh_if_none (bool): Refresh the service(s) if it is not found

        Returns:
            A list of all found ServiceObjects

        """
        objs = []

        for name in set(names):
            obj = self.service(name, refresh_if_none=refresh_if_none)
            if obj:
                objs.append(obj)

        return objs

    def tags(self, names, refresh_if_none=True):
        """Get a list of Predefined Tags

        Return a list of the instances of the tags from the given names.

        Args:
            names (list): Names of the tags
            refresh_if_none (bool): Refresh the tag(s) if it is not found

        Returns:
            A list of all found Tags

        """
        objs = []

        for name in set(names):
            obj = self.tag(name, refresh_if_none=refresh_if_none)
            if obj:
                objs.append(obj)

        return objs

    def object(self, name, classtype, refresh_if_none=True):
        """Get object by classtype

        For example, if you pass in panos.objects.ApplicationObject as the
        classtype, an application will be returned

        Args:
            name (str): Name of the object
            classtype: The class of the object (eg. panos.objects.ApplicationObject
            refresh_if_none (bool): Refresh the object if it is not found

        """
        if classtype == objects.ApplicationObject:
            return self.application(name, refresh_if_none, include_containers=False)
        elif classtype == objects.ApplicationContainer:
            return self.application(name, refresh_if_none, include_containers=True)
        elif classtype == objects.ServiceObject:
            return self.service(name, refresh_if_none)
        elif classtype == objects.Tag:
            return self.tag(name, refresh_if_none)

    def objects(self, names, classtype, refresh_if_none=True):
        """Get a list of objects by classtype

        For example, if you pass in panos.objects.ApplicationObject as the
        classtype, a list of application will be returned

        Args:
            names (list): List of names of the objects
            classtype: The class of the object (eg. panos.objects.ApplicationObject
            refresh_if_none (bool): Refresh the object if it is not found

        """
        if classtype == objects.ApplicationObject:
            return self.applications(names, refresh_if_none, include_containers=False)
        elif classtype == objects.ApplicationContainer:
            return self.applications(names, refresh_if_none, include_containers=True)
        elif classtype == objects.ServiceObject:
            return self.services(names, refresh_if_none)
        elif classtype == objects.Tag:
            return self.tags(names, refresh_if_none)
