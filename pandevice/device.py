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
A library for performing common tasks on a
Palo Alto Networks firewall or Panorama.
"""


# import modules
import re
import logging
import inspect
import xml.etree.ElementTree as ET
from decimal import Decimal

# import Palo Alto Networks api modules
# available at https://live.paloaltonetworks.com/docs/DOC-4762
import pan.xapi
import pan.commit

import pandevice

# import other parts of this pandevice package
import errors as err
from interface import PanInterface

# set logging to nullhandler to prevent exceptions if logging not enabled
logging.getLogger(__name__).addHandler(logging.NullHandler())


class PanDevice(object):
    """A Palo Alto Networks device

    The device can be of any type (currently supported devices are firewall
    firewall vsys, panorama, or device-group). The class handles common
    firewall functions such as adding address objects.

    Attributes:
        hostname: Hostname or IP of device for API connections
        port: Port of device for API connections
        vsys: This device class represents a specific VSYS
        panorama: This device class represents a Panorama device
        devicegroup: This device class represents a specific Device-Group
            in Panorama
        xpath: The XPath for the root of this device, taking into account any
            VSYS, Device-Group, or Panorama state
        timeout: The timeout for API connections
        api_key: The API Key for connecting to the device's API
    """


    def __init__(self,
                 hostname,
                 port=443,
                 api_username=None,
                 api_password=None,
                 api_key=None,
                 detect_device=False,
                 vsys='vsys1',
                 is_panorama=None,
                 is_virtual=None,
                 serial=None,
                 devicegroup=None,
                 timeout=120,
                 interval=.5):
        """Initialize PanDevice"""
        # create a class logger
        self._logger = logging.getLogger(__name__ + "." + self.__class__.__name__)

        # set the instance variables
        if devicegroup and not is_panorama:
            raise err.PanDeviceError('Device-group set on non-Panorama device',
                                     pan_device=self)
        self.hostname = hostname
        self.port = port
        self._api_username = api_username
        self._api_password = api_password
        self._api_key = api_key
        self.vsys = vsys
        self.is_panorama = is_panorama
        self.is_virtual = is_virtual
        self.serial = serial
        self.devicegroup = devicegroup
        self.timeout = timeout
        self.interval = interval
        self.interfaces = {}
        self._xapi_private = None
        self.classify_exceptions = False
        self.config_locked = False
        self.commit_locked = False
        self.lock_before_change = False
        self.config_changed = False

        self.xpath = self.__get_xpath_scope()

        if detect_device:
            self.set_device_by_detection()


    class XapiWrapper(pan.xapi.PanXapi):
        """This is a confusing class used for catching exceptions and
        faults.
        """
        # TODO: comment the hell out of it!

        def __init__(self, *args, **kwargs):
            self.pan_device = kwargs.pop('pan_device', None)
            pan.xapi.PanXapi.__init__(self, *args, **kwargs)

            for name, method in inspect.getmembers(
                    pan.xapi.PanXapi,
                    inspect.ismethod):
                # Ignore hidden methods
                if name[0] == "_":
                    continue

                # Wrapper method.  This is used to create
                # methods in this class that match the methods in the
                # super class, and call the super class methods inside
                # a try/except block, which allows us to check and
                # analyze the exceptions and convert them to more
                # useful exceptions than generic PanXapiErrors.
                wrapper_method = self.make_method(method)

                # Create method matching each public method of the base class
                setattr(PanDevice.XapiWrapper, name, wrapper_method)

        def make_method(self, super_method):
            def method(*args, **kwargs):
                try:
                    return super_method(*args, **kwargs)
                except pan.xapi.PanXapiError as e:
                    if e.msg == "Invalid credentials.":
                        raise err.PanInvalidCredentials(
                            e.msg,
                            pan_device=self.pan_device,
                        )
                    elif e.msg.startswith("URLError:"):
                        if e.msg.endswith("timed out"):
                            raise err.PanConnectionTimeout(
                                e.msg,
                                pan_device=self.pan_device,
                            )
                        else:
                            raise err.PanURLError(e.msg,
                                                  pan_device=self.pan_device)

                    elif e.msg.startswith("timeout waiting for job"):
                        raise err.PanJobTimeout(e.msg,
                                                pan_device=self.pan_device)

                    elif e.msg.startswith("Another commit/validate is in"
                                          " progress. Please try again later"):
                        raise err.PanCommitInProgress(e.msg,
                                                      pan_device=self.pan_device)

                    elif e.msg.startswith("A commit is in progress."):
                        raise err.PanCommitInProgress(e.msg,
                                                      pan_device=self.pan_device)

                    elif e.msg.startswith("You cannot commit while an install is in progress. Please try again later."):
                        raise err.PanInstallInProgress(e.msg,
                                                       pan_device=self.pan_device)

                    elif e.msg.startswith("Session timed out"):
                        raise err.PanSessionTimedOut(e.msg,
                                                     pan_device=self.pan_device)

                    else:
                        raise err.PanDeviceXapiError(e.msg,
                                                     pan_device=self.pan_device)

            return method

    # Properties

    @property
    def api_key(self):
        if self._api_key is None:
            self._logger.debug("API Key not provided for device: %s, "
                               "retrieving API key using credentials" %
                               (self.hostname,))
            self._api_key = self._retrieve_api_key()
        return self._api_key

    @property
    def _xapi(self):
        if self._xapi_private is None:
            if self.classify_exceptions:
                self._xapi_private = PanDevice.XapiWrapper(
                    pan_device=self,
                    api_key=self.api_key,
                    hostname=self.hostname,
                    port=self.port,
                    timeout=self.timeout,
                )
            else:
                self._xapi_private = pan.xapi.PanXapi(
                    api_key=self.api_key,
                    hostname=self.hostname,
                    port=self.port,
                    timeout=self.timeout,
                )
        return self._xapi_private

    def set_config_changed(self):
        if self.lock_before_change:
            if not self.config_locked:
                self.add_config_lock(exception=True)
                """
                if self.pending_changes():
                    self.revert_to_running_configuration()
                    raise err.PanPendingChanges("There are pending changes, "
                                            "cannot apply configuration "
                                            "because cannot get config-lock",
                                            pan_device=self)
                """
        self.config_changed = True


    def set_device_by_detection(self):
        """Set instance variables to detected values

        Log into the device and detect if it is a Panorama device or Firewall.
        Set the instance variables accordingly

        Raises:
            PanDeviceError: If unable to perform detection or
                unexpected values.
            PanXapiError:  Raised by pan.xapi module for API errors
        """
        version, model = self.system_info()
        if model == 'Panorama':
            self.is_panorama = True
        else:
            self.is_panorama = False
        self.xpath = self.__get_xpath_scope()

    def __get_xpath_scope(self):
        """Return the XPath root for the current device

        A private helper method to return an XPath that is appropriate given
        the current state of the instance variables. This XPath represents
        the root of the VSYS, Device-Group, or Shared object area.

        Returns:
            A string containing an XPath to be used as the root for
            other API calls
        """
        xpath_vsys = "/config/devices/entry/vsys/entry[@name='%s']"
        xpath_devicegroup = "/config/devices/entry/" \
                            "device-group/entry[@name='%s']"
        xpath_shared = "/config/shared"

        if self.devicegroup:
            return xpath_devicegroup % self.devicegroup
        elif self.is_panorama:
            return xpath_shared
        elif self.vsys:
            return xpath_vsys % self.vsys
        else:
            return xpath_shared

    def _retrieve_api_key(self):
        """Return an API key for a username and password

        Given a username and password, return the API key of that user for
        this PAN Device. The username and password are not stored, and the
        API key is returned.  It is up to the caller to store it in an
        instance variable if desired.

        Args:
            api_username: The username for which to get an API key
            api_password: The password for the username specified

        Returns:
            A string containing the API key

        Raises:
            PanDeviceError: If unable to retrieve the API key for reasons
                other than an API connectivity problem
            PanXapiError:  Raised by pan.xapi module for API errors
        """
        self._logger.debug("Getting API Key from %s for user %s" %
                           (self.hostname, self._api_username))
        if self.classify_exceptions:
            xapi = PanDevice.XapiWrapper(
                pan_device=self,
                api_username=self._api_username,
                api_password=self._api_password,
                hostname=self.hostname,
                port=self.port,
                timeout=self.timeout
            )
        else:
            xapi = pan.xapi.PanXapi(
                api_username=self._api_username,
                api_password=self._api_password,
                hostname=self.hostname,
                port=self.port,
                timeout=self.timeout
            )
        xapi.keygen()
        # TODO: verify this is a good way to error check
        if xapi.status == 'success':
            return xapi.api_key
        else:
            error_msg = 'Unable to retrieve apikey: %s' % xapi.status
            raise err.PanDeviceError(error_msg, pan_device=self)

    def system_info(self, all_info=False):
        """Get system information

        Returns:
            system information like version, platform, etc.
        """

        self._xapi.op(cmd="<show><system><info></info></system></show>")
        system_info = self._xapi.xml_python(True)
        if not system_info:
            error_msg = 'Cannot detect device type, unable to get system info'
            self._logger.error(error_msg)
            raise err.PanDeviceError(error_msg, pan_device=self)

        if not all_info:
            version = system_info['system']['sw-version']
            model = system_info['system']['model']
            serial = system_info['system']['serial']
            return version, model, serial
        else:
            return system_info

    def version(self):
        """Get version of PAN-OS

        returns:
            version of PAN-OS
        """
        system_info = self.system_info()
        return system_info[0]

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
        self._xapi.set(xpath=address_xpath, element=element)

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
        self._xapi.delete(xpath=address_xpath)

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
        self._xapi.get(xpath=address_xpath)
        return self._xapi.xml_python(True)

    def update_dynamic_addresses(self, register, unregister):
        """Add/update the registered addresses

        Register or unregister addresses and their tags.
        Registered addresses are a feature of PAN-OS 6.0 that allows tagging
        of IP addresses for use in dynamic object groups.

        Support:
            PAN-OS 6.0 and higher

        Args:
            register: List of tuples of the format (ip_address, tag). The
                tag will be registered to the IP address.
            unregister: List of tuples of the format (ip_address, tag). The
                tag will be unregistered from the IP address.

        Raises:
            PanXapiError:  Raised by pan.xapi module for API errors
        """
        reg_entries = ''
        unreg_entries = ''

        element_dag_update = """<uid-message>
                             <version>1.0</version>
                             <type>update</type>
                             <payload>
                             <register>
                             %s
                             </register>
                             <unregister>
                             %s
                             </unregister>
                             </payload>
                             </uid-message>"""

        for address in register:
            entry = '<entry ip="%s" identifier="%s" />' % address
            reg_entries += entry
        for address in unregister:
            entry = '<entry ip="%s" identifier="%s" />' % address
            unreg_entries += entry
        element = element_dag_update % (reg_entries, unreg_entries)
        self._xapi.user_id(cmd=element)

    def get_all_registered_addresses(self, return_xml=False):
        """Return all registered/tagged addresses

        Return all registered addresses as XML or as a list of tuples.
        Registered addresses are a feature of PAN-OS 6.0 that allows tagging
        of IP addresses for use in dynamic object groups.

        Support:
            PAN-OS 6.0 and higher

        Args:
            return_xml: True cuases the method to return a string containing
                <entry> elements for each registered address that can be used
                in a register/unregister XML update call to the API.
                False causes the method to return a list of tuples, where
                each tuple is of the format (ip_address, tag).

        Returns:
            A string of XML, or a list of tuples, containing all the
            registered addresses paired with their tags. If an address has
            more than one tag, it is listed once for each tag.

        Raises:
            PanXapiError:  Raised by pan.xapi module for API errors
        """
        self._xapi.op(cmd='show object registered-ip all', vsys=self.vsys, cmd_xml=True)
        result = self._xapi.xml_root()
        matches = re.finditer(r"<entry[^>]*\"((?:[0-9]{1,3}\.){3}[0-9]{1,3})\".*?<tag>(.*?)</tag>", result, re.DOTALL)
        addresses = []
        address_str = ''
        for match in matches:
            ip_address = match.group(1)
            tags = re.findall(r'<member>(.*?)</member>', match.group(2))
            for tag in tags:
                addresses.append((ip_address, tag))
                address_str += '<entry ip="%s" identifier="%s" />\n' % (ip_address, tag)
        if return_xml:
            return address_str
        else:
            return addresses

    def unregister_all_addresses(self):
        """Unregister all registered/tagged addresses

        Removes all registered addresses used by dynamic address groups.

        Support:
            PAN-OS 6.0 and higher

        Raises:
            PanXapiError:  Raised by pan.xapi module for API errors
        """
        self._xapi.op(cmd='show object registered-address all', vsys=self.vsys, cmd_xml=True)
        result = self._xapi.xml_root()
        matches = re.finditer(r"<entry[^>]*\"((?:[0-9]{1,3}\.){3}[0-9]{1,3})\".*?<tag>(.*?)</tag>", result, re.DOTALL)
        addresses = []
        for match in matches:
            ip_address = match.group(1)
            tags = re.findall(r'<member>(.*?)</member>', match.group(2))
            for tag in tags:
                addresses.append((ip_address, tag))
        self.update_dynamic_addresses([], addresses)

    def add_interface(self, pan_interface, apply=True):
        """Apply a PanInterface object
        """
        self.set_config_changed()
        if not issubclass(type(pan_interface), PanInterface):
            raise TypeError(
                "set_interface argument must be of type PanInterface"
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
        self._xapi.op('show interface "all"', cmd_xml=True)
        result = self._xapi.xml_python()
        hw = {}
        interfaces = {}
        # Check if there is a response and result
        try:
            result = result['response']['result']
        except KeyError as e:
            raise err.PanDeviceError("Error reading response while refreshing interfaces", pan_device=self)
        if result:
            self._logger.debug("Refresh interfaces result: %s" % result)
            # Create a hw dict with all the 'hw' info
            hw_result = result.get('hw', {})
            if hw_result is None:
                return
            hw_result = hw_result.get('entry', [])
            for hw_entry in hw_result:
                hw[hw_entry['name']] = hw_entry

            if_result = result.get('ifnet', {})
            if if_result is None:
                return
            if_result = if_result.get('entry', [])
            for entry in if_result:
                interface = PanInterface(name=entry['name'],
                                         zone=entry['zone'],
                                         router=entry['fwd'].split(":", 1)[1],
                                         subnets=[entry['ip']],
                                         state=hw.get(entry['name'], {}).get('state')
                                         )
                interfaces[entry['name']] = interface
        else:
            raise err.PanDeviceError("Could not refresh interfaces",
                                     pan_device=self)
        self.interfaces = interfaces

    def show_system_resources(self):
        self._xapi.op(cmd="show system resources", cmd_xml=True)
        result = self._xapi.xml_root()
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

    def set_hostname(self, hostname):
        self._logger.debug("Set hostname: %s" % (hostname,))
        self.set_config_changed()
        xpath = pandevice.XPATH_DEVICECONFIG_SYSTEM
        self._xapi.set(xpath, "<hostname>%s</hostname>" % (hostname,))

    def set_dns_servers(self, primary, secondary=None):
        self._logger.debug("Set dns-servers: primary:%s secondary:%s" % (primary, secondary))
        xpath = pandevice.XPATH_DEVICECONFIG_SYSTEM + "/dns-setting/servers"
        element = ET.Element("servers")
        if primary:
            element_primary = ET.SubElement(element, "primary")
            element_primary.text = primary
        if secondary:
            element_secondary = ET.SubElement(element, "secondary")
            element_secondary.text = secondary
        self._xapi.edit(xpath, ET.tostring(element))

    def set_ntp_servers(self, primary, secondary=None):
        self._logger.debug("Set ntp-servers: primary:%s secondary:%s" % (primary, secondary))
        self.set_config_changed()
        xpath = pandevice.XPATH_DEVICECONFIG_SYSTEM
        element = ''
        if primary:
            element += "<ntp-server-1>%s</ntp-server-1>" % (primary,)
        else:
            self._xapi.delete(xpath + "/ntp-server-1")
        if secondary:
            element += "<ntp-server-2>%s</ntp-server-2>" % (secondary,)
        else:
            self._xapi.delete(xpath + "/ntp-server-2")
        self._xapi.set(xpath, element)

    def show_interface(self, interface):
        self.set_config_changed()
        interface_name = self._interface_name(interface)

        self._xapi.op("<show><interface>%s</interface></show>" % (interface_name,))
        return self._xapi.xml_python(True)

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

        self._xapi.op("<show><counter><interface>%s</interface></counter></show>" % (interface_name,))
        counters = self._xapi.xml_python(True)
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
        elif issubclass(interface.__class__, PanInterface):
            return interface.name
        else:
            raise err.PanDeviceError(
                "interface argument must be of type str or PanInterface",
                pan_device=self
            )

    def pending_changes(self):
        self._xapi.op(cmd="check pending-changes", cmd_xml=True)
        return self._xapi.xml_python(True)

    def commit(self, sync=False, exception=False, cmd=None):
        self._logger.debug("Commit initiated on device: %s" % (self.hostname,))
        return self._commit(sync=sync, exception=exception, cmd=cmd)

    def commit_device_and_network(self, sync=False, exception=False):
        return self._commit(sync=sync, exclude="device-and-network",
                            exception=exception)

    def commit_policy_and_objects(self, sync=False, exception=False):
        return self._commit(sync=sync, exclude="policy-and-objects",
                            exception=exception)

    def commit_all(self, sync=False, sync_all=True, exception=False, cmd=None):
        self._logger.debug("Commit-all initiated on device: %s" % (self.hostname,))
        return self._commit(sync=sync,
                            sync_all=sync_all,
                            commit_all=True,
                            exception=exception,
                            cmd=cmd)

    def _commit(self, cmd=None, exclude=None, commit_all=False,
                sync=False, sync_all=True, exception=False):
        """Internal use commit helper method.

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

        if issubclass(cmd.__class__, pan.commit.PanCommit):
            cmd = cmd.cmd()
        elif issubclass(cmd.__class__, ET.Element):
            cmd = ET.tostring(cmd)
        elif issubclass(cmd.__class__, basestring):
            pass
        else:
            cmd = ET.Element("commit")
            if exclude is not None:
                excluded = ET.SubElement(cmd, "partial")
                excluded = ET.SubElement(excluded, exclude)
            cmd = ET.tostring(cmd)
        if commit_all:
            action = "all"
        else:
            action = None
        if sync:
            self._logger.debug("Waiting for commit job to finish...")
        self._xapi.commit(cmd=cmd,
                          action=action,
                          sync=sync,
                          sync_all=sync_all,
                          interval=self.interval,
                          timeout=self.timeout)
        self.config_changed = False
        self.config_locked = False
        self.commit_locked = False
        if sync:
            job = self._xapi.xml_python(True)
            if job is None:
                if exception:
                    raise err.PanCommitNotNeeded("Commit not needed",
                                                 pan_device=self)
                else:
                    return
            job = job['job']
            # Create a boolean called success to make
            # testing for success easier
            devices_results = {}
            devices_success = True
            if commit_all and sync_all:
                devices = job['devices']
                if devices is not None:
                    devices = devices['entry']
                    for device in devices:
                        success = True if device['result'] == "OK" else False
                        if not success:
                            devices_success = False
                        devices_results[device['serial-no']] = {
                            'success': success,
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

            if commit_all:
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
                'devices': devices_results
            }

            if exception and not success:
                self._logger.debug("Commit failed - device: %s, job: %s, messages: %s, warnings: %s" %
                                   (self.hostname,
                                    result['jobid'],
                                    result['messages'],
                                    result['warnings']))
                raise err.PanCommitFailed(pan_device=self, result=result)
            else:
                if success:
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
        else:
            jobid = self._xapi.element_root.find('./result/job')
            if jobid is None:
                if exception:
                    raise err.PanCommitNotNeeded("Commit not needed",
                                                 pan_device=self)
                else:
                    return
            self._logger.debug("Commit initiated (async), job id: %s" % (jobid,))
            return jobid

    def add_commit_lock(self, comment=None, exception=False):
        self._logger.debug("Add commit lock requested")
        cmd = ET.Element("request")
        subel = ET.SubElement(cmd, "commit-lock")
        subel = ET.SubElement(subel, "add")
        if comment is not None:
            subel = ET.SubElement(subel, "comment")
            subel.text = comment
        try:
            self._xapi.op(ET.tostring(cmd))
        except (pan.xapi.PanXapiError, err.PanDeviceXapiError) as e:
            if not re.match(r"Commit lock is already held", str(e)):
                raise
            else:
                if exception:
                    raise err.PanLockError(str(e), pan_device=self)
                else:
                    self._logger.debug(str(e))
                    return False
        self.commit_locked = True
        return True

    def remove_commit_lock(self, admin=None, exception=False):
        self._logger.debug("Remove commit lock requested")
        cmd = ET.Element("request")
        subel = ET.SubElement(cmd, "commit-lock")
        subel = ET.SubElement(subel, "remove")
        if admin is not None:
            subel = ET.SubElement(subel, "admin")
            subel.text = admin
        try:
            self._xapi.op(ET.tostring(cmd))
        except (pan.xapi.PanXapiError, err.PanDeviceXapiError) as e:
            if not re.match(r"Commit lock is not currently held", str(e)):
                raise
            else:
                if exception:
                    raise err.PanLockError(str(e), pan_device=self)
                else:
                    self._logger.debug(str(e))
                    return False
        self.commit_locked = False
        return True

    def add_config_lock(self, comment=None, exception=False):
        self._logger.debug("Add config lock requested")
        cmd = ET.Element("request")
        subel = ET.SubElement(cmd, "config-lock")
        subel = ET.SubElement(subel, "add")
        if comment is not None:
            subel = ET.SubElement(subel, "comment")
            subel.text = comment
        try:
            self._xapi.op(ET.tostring(cmd))
        except (pan.xapi.PanXapiError, err.PanDeviceXapiError) as e:
            if not re.match(r"Config for scope shared is currently locked",
                            str(e)):
                raise
            else:
                if exception:
                    raise err.PanLockError(str(e), pan_device=self)
                else:
                    self._logger.debug(str(e))
                    return False
        self.config_locked = True
        return True

    def remove_config_lock(self, exception=False):
        self._logger.debug("Remove config lock requested")
        cmd = ET.Element("request")
        subel = ET.SubElement(cmd, "config-lock")
        subel = ET.SubElement(subel, "remove")
        try:
            self._xapi.op(ET.tostring(cmd))
        except (pan.xapi.PanXapiError, err.PanDeviceXapiError) as e:
            if not re.match(r"Config is not currently locked for scope shared",
                            str(e)):
                raise
            else:
                if exception:
                    raise err.PanLockError(str(e), pan_device=self)
                else:
                    self._logger.debug(str(e))
                    return False
        self.config_locked = False
        return True

    def check_commit_locks(self):
        self._xapi.op("show commit-locks", cmd_xml=True)
        response = self._xapi.element_result.find(".//entry")
        return True if response is not None else False

    def revert_to_running_configuration(self):
        # self.set_config_changed()
        self._logger.debug("Revert to running configuration on device: %s" % (self.hostname,))
        self._xapi.op("<load><config><from>"
                      "running-config.xml"
                      "</from></config></load>")

    def refresh_devices_from_panorama(self, devices, overwrite=False):
        if issubclass(devices.__class__, PanDevice):
            devices = [devices]
        serials_by_host = {}
        devicegroups_by_serial = {}
        # Get the list of managed devices
        self._xapi.op("show devices all", cmd_xml=True)
        dev_element = self._xapi.element_result
        for device in dev_element.findall("./devices/entry"):
            hostname = device.find('hostname').text
            ip = device.find('ip-address').text
            serial = device.find('serial').text
            serials_by_host[ip] = serial
            serials_by_host[hostname] = serial
        for device in devices:
            if device.serial is None or overwrite:
                device.serial = serials_by_host.get(device.hostname)
            if device.serial is None:
                raise err.PanDeviceError("Can't determine serial for "
                                         "device", pan_device=device)
        # Get the list of device groups
        from pprint import pformat

        self._xapi.op("show devicegroups", cmd_xml=True)
        dg_element = self._xapi.element_result
        for dg in dg_element.findall("./devicegroups/entry"):
            for device in dg.findall("./devices/entry"):
                serial = device.find('serial').text
                name = dg.get('name')
                devicegroups_by_serial[serial] = name
        for device in devices:
            if device.devicegroup is None or overwrite:
                device.devicegroup = devicegroups_by_serial.get(device.serial)

    # XXX: I don't think this method is even needed
    def create_device_group(self, devicegroup, devices=None):
        """ Create a device-group and optionally add devices to it

        :param devicegroup: String, The device-group name
        :param devices: PanDevice or List of PanDevices to add to the device-group
        :return: None
        """
        self._logger.debug("Create device-group: %s" % (devicegroup,))
        if devices is not None:
            self.set_device_group(devicegroup, devices, exclusive=True)
        else:
            self._xapi.set(pandevice.XPATH_DEVICE_GROUPS + "/entry[@name='%s']" % (devicegroup,))

    def set_device_group(self, devicegroup, devices, exclusive=False):
        """ For Panorama, set the device group for a device

        :param devicegroup: String, Device-group to set devices to
        :param devices: PanDevice or List of PanDevices
        :param exclusive: Device-group should contain ONLY these devices
        :return: None
        """
        # TODO: Implement 'exclusive'
        self._logger.debug("Set device-group to '%s'" % (devicegroup))
        if issubclass(devices.__class__, PanDevice):
            devices = [devices]
        device_refresh_needed = False
        for device in devices:
            if device.serial is None or device.devicegroup is None:
                device_refresh_needed = True
                break
        if device_refresh_needed:
            self.refresh_devices_from_panorama(devices, overwrite=True)
        # All devices have serial numbers now, so start setting devicegroup
        for device in devices:
            # If the device was in a group, and that group changed, pull it out of the current group
            if device.devicegroup != devicegroup and \
                            device.devicegroup is not None:
                self._logger.debug("Moving device %s out of device-group %s" % (device.hostname, device.devicegroup))
                self.set_config_changed()
                self._xapi.delete(
                    pandevice.XPATH_DEVICE_GROUPS +
                    "/entry[@name='%s']/devices"
                    "/entry[@name='%s']"
                    % (device.devicegroup, device.serial)
                )
                device.devicegroup = None
            # If assigning device to a new group
            if devicegroup is not None:
                self.set_config_changed()
                self._logger.debug("Moving device %s into device-group %s" % (device.hostname, devicegroup))
                self._xapi.set(
                    pandevice.XPATH_DEVICE_GROUPS +
                    "/entry[@name='%s']/devices" % (devicegroup,),
                    "<entry name='%s'/>" % (device.serial,)
                )
                device.devicegroup = devicegroup
