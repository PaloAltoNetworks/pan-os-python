#!/usr/bin/env python

# Author: Brian Torres-Gil <btorres-gil@paloaltonetworks.com>
#
# This work is licensed under the Creative Commons
# Attribution 3.0 Unported License. To view a copy of this license,
# visit http://creativecommons.org/licenses/by/3.0/.


"""
A library for performing common tasks on a
Palo Alto Networks firewall or Panorama.
"""


# import modules
import re
import logging

# import Palo Alto Networks api modules
# available at https://live.paloaltonetworks.com/docs/DOC-4762
import pan.xapi

# set logging to nullhandler to prevent exceptions if logging not enabled
logging.getLogger(__name__).addHandler(logging.NullHandler())


# Exceptions used by PanDevice Class

class PanDeviceError(Exception):
    """Exception for errors in the PanDevice class

    The PanDevie class may raise errors when problems occur.  This exception
    class is raised on those errors.  This class is not for errors connecting
    to the API, as pan.xapi.PanXapiError is responsible for those.

    Attributes:
        message: The error message for the exception
    """
    def __init__(self, message):
        super(PanDeviceError, self).__init__()
        self.message = message

    def __str__(self):
        if self.message is None:
            return ''
        return self.message


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
                 panorama=None,
                 devicegroup=None,
                 timeout=None,
                 debug=0):
        """Initialize PanDevice"""
        # create a class logger
        self._logger = logging.getLogger(__name__ +  "." + self.__class__.__name__)
        # set the instance variables
        if devicegroup and not panorama:
            raise PanDeviceError('Device-group set on non-Panorama device')
        self.hostname = hostname
        self.port = port
        self.vsys = vsys
        self.panorama = panorama
        self.devicegroup = devicegroup

        self.xpath = self.__get_xpath_scope()

        self.timeout = timeout

        if api_key is None:
            self._logger.debug("API Key not provided")
            self.api_key = self.retrieve_api_key(api_username, api_password)
        else:
            self.api_key = api_key

        self.__xapi = pan.xapi.PanXapi(api_key=self.api_key,
                                     hostname=self.hostname,
                                     port=self.port,
                                     timeout=self.timeout,
                                     debug=debug)

        if detect_device:
            self.set_device_by_detection()


    def set_device_by_detection(self):
        """Set instance variables to detected values

        Log into the device and detect if it is a Panorama device or Firewall.
        Set the instance variables accordingly

        Raises:
            PanDeviceError: If unable to perform detection or
                unexpected values.
            PanXapiError:  Raised by pan.xapi module for API errors
        """
        # check if connecting to a firewall or panorama
        self.__xapi.op(cmd="<show><system><info></info></system></show>")
        system_info = self.__xapi.xml_python(True)
        if not system_info:
            error_msg = 'Cannot detect device type, unable to get system info'
            self._logger.error(error_msg)
            raise PanDeviceError(error_msg)

        model = system_info['system']['model']
        if model == 'Panorama':
            self.panorama = True
        else:
            self.panorama = False
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
        XPATH_VSYS = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='%s']"
        XPATH_DEVICEGROUP = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']"
        XPATH_SHARED = "/config/shared"

        if self.devicegroup:
            return XPATH_DEVICEGROUP % self.devicegroup
        elif self.panorama:
            return XPATH_SHARED
        elif self.vsys:
            return XPATH_VSYS % self.vsys
        else:
            return XPATH_SHARED


    def retrieve_api_key(self, api_username, api_password):
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
        self._logger.info("Getting API Key from %s for user %s", self.hostname, api_username)
        xapi = pan.xapi.PanXapi(api_username=api_username,
                                api_password=api_password,
                                hostname=self.hostname,
                                port=self.port)

        xapi.keygen()
        #TODO: verify this is a good way to error check
        if xapi.status == 'success':
            return xapi.api_key
        else:
            error_msg = 'Unable to retrieve apikey: %s' % xapi.status
            raise PanDeviceError(error_msg)


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
        address_xpath = self.xpath + "/address/entry[@name='%s']" % name
        element = "<ip-netmask>%s</ip-netmask><description>%s</description>" % (address, description)
        self.__xapi.set(xpath=address_xpath, element=element)


    def delete_address_object(self, name):
        """Delete an address object from the configuration

        Delete an address object from the configuration. If the objects
        does not exist, an exception is raised.

        Args:
            name: String name of the address object to delete

        Raises:
            PanXapiError:  Raised by pan.xapi module for API errors
        """
        #TODO: verify what happens if the object doesn't exist
        address_xpath = self.xpath + "/address/entry[@name='%s']" % name
        self.__xapi.delete(xpath=address_xpath)


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
        #TODO: Currently returns raw results, but should return a list
        # and raise an exception on error
        address_xpath = self.xpath + "/address"
        self.__xapi.get(xpath=address_xpath)
        return self.__xapi.xml_python(True)


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

        ELEMENT_DAG_UPDATE = """<uid-message>
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
        element = ELEMENT_DAG_UPDATE % (reg_entries, unreg_entries)
        self.__xapi.user_id(cmd=element)


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
        self.__xapi.op(cmd='show object registered-address all', vsys=self.vsys, cmd_xml=True)
        result = self.__xapi.xml_root()
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
        self.__xapi.op(cmd='show object registered-address all', vsys=self.vsys, cmd_xml=True)
        result = self.__xapi.xml_root()
        matches = re.finditer(r"<entry[^>]*\"((?:[0-9]{1,3}\.){3}[0-9]{1,3})\".*?<tag>(.*?)</tag>", result, re.DOTALL)
        addresses = []
        for match in matches:
            ip_address = match.group(1)
            tags = re.findall(r'<member>(.*?)</member>', match.group(2))
            for tag in tags:
                addresses.append((ip_address, tag))
        self.update_dynamic_addresses([], addresses)

