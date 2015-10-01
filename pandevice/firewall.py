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


"""Palo Alto Networks device and firewall objects.

For performing common tasks on Palo Alto Networks devices.
"""


# import modules
import re
import logging
import inspect
import xml.etree.ElementTree as ET
import time
from copy import deepcopy
from decimal import Decimal

# import Palo Alto Networks api modules
# available at https://live.paloaltonetworks.com/docs/DOC-4762
import pan.xapi
import pan.commit
from pan.config import PanConfig

import pandevice

# import other parts of this pandevice package
import errors as err
from network import Interface
from base import PanObject, PanDevice
from updater import Updater
import userid

# set logging to nullhandler to prevent exceptions if logging not enabled
logging.getLogger(__name__).addHandler(logging.NullHandler())


class Firewall(PanDevice):

    def __init__(self,
                 hostname=None,
                 api_username=None,
                 api_password=None,
                 api_key=None,
                 serial=None,
                 port=443,
                 vsys='vsys1',  # vsys id or 'shared'
                 is_virtual=None,
                 panorama=None,
                 classify_exceptions=False):
        """Initialize PanDevice"""
        super(Firewall, self).__init__(hostname, api_username, api_password, api_key,
                                       port=port,
                                       is_virtual=is_virtual,
                                       serial=serial,
                                       classify_exceptions=classify_exceptions,
                                       )
        # create a class logger
        self._logger = logging.getLogger(__name__ + "." + self.__class__.__name__)

        self.vsys = vsys
        self.panorama = panorama

        # Create a User-ID subsystem
        self.userid = userid.UserId(self)

    def xpath_mgtconfig(self):
        return self.XPATH + "/mgt-config"

    def xpath_device(self):
        return self.XPATH + "/devices/entry[@name='localhost.localdomain']"

    def xpath_vsys(self):
        if self.vsys == "shared":
            return self.XPATH + "/shared"
        else:
            return self.XPATH + "/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='%s']" % self.vsys

    def op(self, cmd=None, cmd_xml=True, extra_qs=None):
        if self.vsys == "shared":
            vsys = "vsys1"
        else:
            vsys = self.vsys
        return self.xapi.op(cmd, vsys, cmd_xml, extra_qs)

    def generate_xapi(self):
        """Override super class to connect to Panorama

        Connect to this firewall via Panorama with 'target' argument set
        to this firewall's serial number.  This happens when panorama and serial
        variables are set in this firewall prior to the first connection.
        """
        if self.panorama is not None and self.serial is not None:
            if self._classify_exceptions:
                xapi_constructor = PanDevice.XapiWrapper
                kwargs = {'pan_device': self,
                          'api_key': self.panorama.api_key,
                          'hostname': self.panorama.hostname,
                          'port': self.panorama.port,
                          'timeout': self.timeout,
                          'serial': self.serial,
                          }
            else:
                xapi_constructor = pan.xapi.PanXapi
                kwargs = {'api_key': self.panorama.api_key,
                          'hostname': self.panorama.hostname,
                          'port': self.panorama.port,
                          'timeout': self.timeout,
                          'serial': self.serial,
                          }
            return xapi_constructor(**kwargs)
        else:
            return super(Firewall, self).generate_xapi()

    def add_address_object(self, name, address, description=''):
        """Add/update an ip-netmask type address object to the configuration

        Add or update an address object to the configuration. If the objects
        does not already exist, it is added. If it already exists, it
        is updated.
        NOTE: Only ip-netmask type objects are supported.

        Args:
            name: String name of the address object to add or update
            address: String IP Address optionally with subnet prefix
                (eg. "10.1.1.5" or "10.0.0.0/24")
            description: String to add to address object description field

        Raises:
            PanXapiError:  Raised by pan.xapi module for API errors
        """
        self.set_config_changed()
        address_xpath = self.xpath + "/address/entry[@name='%s']" % name
        element = "<ip-netmask>%s</ip-netmask><description>%s</description>" \
                  % (address, description)
        self.xapi.set(xpath=address_xpath, element=element)

    def delete_address_object(self, name):
        """Delete an address object from the configuration

        Delete an address object from the configuration. If the objects
        does not exist, an exception is raised.

        Args:
            name: String name of the address object to delete

        Raises:
            PanXapiError:  Raised by pan.xapi module for API errors
        """
        # TODO: verify what happens if the object doesn't exist
        self.set_config_changed()
        address_xpath = self.xpath + "/address/entry[@name='%s']" % name
        self.xapi.delete(xpath=address_xpath)

    def get_all_address_objects(self):
        """Return a list containing all address objects

        Return a list containing all address objects in the device
        configuration.

        Returns:
            Right now it just returns the python representation of the API
            call. Eventually it should return a santized list of objects

        Raises:
            PanXapiError:  Raised by pan.xapi module for API errors
        """
        # TODO: Currently returns raw results, but should return a list
        # and raise an exception on error
        address_xpath = self.xpath + "/address"
        self.xapi.get(xpath=address_xpath)
        pconf = PanConfig(self.xapi.element_result)
        response = pconf.python()
        return response['result']

    def add_interface(self, pan_interface, apply=True):
        """Apply a Interface object
        """
        self.set_config_changed()
        if not issubclass(type(pan_interface), Interface):
            raise TypeError(
                "set_interface argument must be of type Interface"
            )

        if pan_interface.parent:
            parent = pan_interface.parent
            if parent.name not in self.interfaces:
                self.interfaces[parent.name] = parent

        self.interfaces[pan_interface.name] = pan_interface
        pan_interface.pan_device = self

        if apply:
            pan_interface.apply()

    def delete_interface(self, pan_interface, apply=True,
                         delete_empty_parent=False):
        self.set_config_changed()
        self.interfaces.pop(pan_interface.name, None)
        if pan_interface.pan_device is None:
            pan_interface.pan_device = self

        if (delete_empty_parent and
                pan_interface.parent and
                not pan_interface.parent.subinterfaces):
            self.interfaces.pop(pan_interface.name, None)
            if apply:
                pan_interface.parent.delete()
        else:
            if apply:
                pan_interface.delete()

        pan_interface.pan_device = None

    def refresh_interfaces(self):
        self.xapi.op('show interface "all"', cmd_xml=True)
        pconf = PanConfig(self.xapi.element_root)
        response = pconf.python()
        hw = {}
        interfaces = {}
        # Check if there is a response and result
        try:
            response = response['response']['result']
        except KeyError as e:
            raise err.PanDeviceError("Error reading response while refreshing interfaces", pan_device=self)
        if response:
            self._logger.debug("Refresh interfaces result: %s" % response)
            # Create a hw dict with all the 'hw' info
            hw_result = response.get('hw', {})
            if hw_result is None:
                return
            hw_result = hw_result.get('entry', [])
            for hw_entry in hw_result:
                hw[hw_entry['name']] = hw_entry

            if_result = response.get('ifnet', {})
            if if_result is None:
                return
            if_result = if_result.get('entry', [])
            for entry in if_result:
                try:
                    router = entry['fwd'].split(":", 1)[1]
                except IndexError:
                    router = entry['fwd']
                interface = Interface(name=entry['name'],
                                      zone=entry['zone'],
                                      router=router,
                                      subnets=[entry['ip']],
                                      state=hw.get(entry['name'], {}).get('state')
                                      )
                interfaces[entry['name']] = interface
        else:
            raise err.PanDeviceError("Could not refresh interfaces",
                                     pan_device=self)
        self.interfaces = interfaces

    def show_system_resources(self):
        self.xapi.op(cmd="show system resources", cmd_xml=True)
        result = self.xapi.xml_root()
        regex = re.compile(r"load average: ([\d.]+).* ([\d.]+)%id.*Mem:.*?([\d.]+)k total.*?([\d]+)k free", re.DOTALL)
        match = regex.search(result)
        if match:
            """
            return cpu, mem_free, load
            """
            return {
                'load': Decimal(match.group(1)),
                'cpu': 100 - Decimal(match.group(2)),
                'mem_total': int(match.group(3)),
                'mem_free': int(match.group(4)),
            }
        else:
            raise err.PanDeviceError("Problem parsing show system resources",
                                     pan_device=self)

    @staticmethod
    def _convert_if_int(string):
        """Convert a string to an int, only if it is an int"""
        try:
            integer = int(string)
            return integer
        except ValueError:
            return string

    def get_interface_counters(self, interface):
        """Pull the counters for an interface

        :param interface: interface object or str with name of interface
        :return: Dictionary of counters, or None if no counters for interface
        """
        interface_name = self._interface_name(interface)

        self.xapi.op("<show><counter><interface>%s</interface></counter></show>" % (interface_name,))
        pconf = PanConfig(self.xapi.element_result)
        response = pconf.python()
        counters = response['result']
        if counters:
            entry = {}
            # Check for entry in ifnet
            if 'entry' in counters.get('ifnet', {}):
                entry = counters['ifnet']['entry'][0]
            elif 'ifnet' in counters.get('ifnet', {}):
                if 'entry' in counters['ifnet'].get('ifnet', {}):
                    entry = counters['ifnet']['ifnet']['entry'][0]

            # Convert strings to integers, if they are integers
            entry.update((k, PanDevice._convert_if_int(v)) for k, v in entry.iteritems())
            # If empty dictionary (no results) it usually means the interface is not
            # configured, so return None
            return entry if entry else None

    def _interface_name(self, interface):
        if issubclass(interface.__class__, basestring):
            return interface
        elif issubclass(interface.__class__, Interface):
            return interface.name
        else:
            raise err.PanDeviceError(
                "interface argument must be of type str or Interface",
                pan_device=self
            )


    def commit_device_and_network(self, sync=False, exception=False):
        return self._commit(sync=sync, exclude="device-and-network",
                            exception=exception)

    def commit_policy_and_objects(self, sync=False, exception=False):
        return self._commit(sync=sync, exclude="policy-and-objects",
                            exception=exception)

