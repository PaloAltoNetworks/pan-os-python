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


"""User-ID and Dynamic Address Group updates using the User-ID API"""

import xml.etree.ElementTree as ET
from copy import deepcopy

from pandevice import getlogger
import pandevice.errors as err
from pandevice import string_or_list
from pandevice import string_or_list_or_none
from pan.xapi import PanXapiError
from pandevice.updater import PanOSVersion

logger = getlogger(__name__)


class UserId(object):
    """User-ID Subsystem of Firewall

    A member of a firewall.Firewall object that has special methods for
    interacting with the User-ID API. This includes login/logout of a user,
    user/group mappings, and dynamic address group tags.

    This class is typically not instantiated by anything but the
    base.PanDevice class itself. There is an instance of this UserId class
    inside every instantiated base.PanDevice class.

    **Support:** UserId API is supported on Panorama starting with Panorama 8.0
        UserId API is supported on all firewall PAN-OS versions but with varying
        features as noted in the documentation for each method.

    Args:
        device (base.PanDevice): The firewall or Panorama this user-id subsystem leverages
        prefix (str): Prefix to use in all IP tag operations for Dynamic Address Groups
        ignore_dup_errors (bool): Devices produce errors when a tag is registered that already
            exists. Set to true to ignore these errors. (Default: True)

    """

    def __init__(self, device, prefix="", ignore_dup_errors=True):
        # Create a class logger
        self._logger = getlogger(__name__ + "." + self.__class__.__name__)
        self.device = device
        self.prefix = prefix
        self.ignore_dup_errors = ignore_dup_errors

        # Build the initial uid-message
        self._uidmessage = ET.fromstring("<uid-message>" +
                                         "<version>1.0</version>" +
                                         "<type>update</type>" +
                                         "<payload/>" +
                                         "</uid-message>")
        # Batch state
        self._batch = False
        self._batch_uidmessage = deepcopy(self._uidmessage)

    def _create_uidmessage(self):
        if self._batch:
            payload = self._batch_uidmessage.find("payload")
            return self._batch_uidmessage, payload
        else:
            root = deepcopy(self._uidmessage)
            payload = root.find("payload")
            return root, payload

    def batch_start(self):
        """Start creating an API call

        The API call will not be sent to the firewall until batch_end() is
        called. This allows multiple operations to be added to a single API
        call.

        """
        self._batch = True
        self._batch_uidmessage = deepcopy(self._uidmessage)

    def batch_end(self):
        """End a batched API call and send it to the firewall

        This method usually follows a batch_start() and several other
        operations.

        The API call will not be sent to the firewall until batch_end() is
        called. This allows multiple operations to be added to a single API
        call.

        """
        uid_message, payload = self._create_uidmessage()
        self._batch = False
        # Only send the API call if there was actually a command added to the payload
        if len(payload) > 0:
            self.send(uid_message)
        self._batch_uidmessage = deepcopy(self._uidmessage)

    def send(self, uidmessage):
        """Send a uidmessage to the User-ID API of a firewall

        Used for adhoc User-ID API calls that are not supported by other
        methods in this class. This method cannot be batched.

        Args:
            uidmessage (str): The UID Message in XML to send to the firewall

        """
        if self._batch:
            return
        else:
            cmd = ET.tostring(uidmessage)
            try:
                self.device.xapi.user_id(cmd=cmd, vsys=self.device.vsys)
            except (err.PanDeviceXapiError, PanXapiError) as e:
                # Check if this is just an error about duplicates or nonexistant tags
                # If so, ignore the error. Most operations don't care about this.
                message = str(e)
                if self.ignore_dup_errors and (message.endswith("already exists, ignore") or message.endswith("does not exist, ignore unreg")):
                    return
                else:
                    raise e

    def login(self, user, ip, timeout=None):
        """Login a single user

        Maps a user to an IP address

        This method can be batched with batch_start() and batch_end().

        Args:
            user (str): a username
            ip (str): an ip address
            timeout (int): timeout in minutes to remove this mapping

        """
        root, payload = self._create_uidmessage()
        login = payload.find("login")
        if login is None:
            login = ET.SubElement(payload, "login")
        entry = ET.SubElement(login, "entry", {"name": user, "ip": ip})
        if timeout:
            entry.set('timeout', str(timeout))
        self.send(root)

    def logins(self, users):
        """Login multiple users in the same API call

        This method can be batched with batch_start() and batch_end().

        Args:
            users: a list of sets of user/ip mappings with optional timeout in minutes
                   eg. [('user1', '10.0.1.1'), ('user2', '10.0.1.2', 60)]

        """
        if not users:
            return
        root, payload = self._create_uidmessage()
        login = payload.find("login")
        if login is None:
            login = ET.SubElement(payload, "login")
        for user in users:
            entry = ET.SubElement(login, "entry", {"name": user[0], "ip": user[1]})
            try:
                entry.set('timeout', str(user[2]))
            except IndexError:
                # No timeout specified
                pass
        self.send(root)

    def logout(self, user, ip):
        """Logout a single user

        Removes a mapping of a user to an IP address

        This method can be batched with batch_start() and batch_end().

        Args:
            user (str): a username
            ip (str): an ip address

        """
        root, payload = self._create_uidmessage()
        logout = payload.find("logout")
        if logout is None:
            logout = ET.SubElement(payload, "logout")
        ET.SubElement(logout, "entry", {"name": user, "ip": ip})
        self.send(root)

    def logouts(self, users):
        """Logout multiple users in the same API call

        This method can be batched with batch_start() and batch_end().

        Arguments:
            users: a list of sets of user/ip mappings
                   eg. [(user1, 10.0.1.1), (user2, 10.0.1.2)]

        """
        if not users:
            return
        root, payload = self._create_uidmessage()
        logout = payload.find("logout")
        if logout is None:
            logout = ET.SubElement(payload, "logout")
        for user in users:
            ET.SubElement(logout, "entry", {"name": user[0], "ip": user[1]})
        self.send(root)

    def register(self, ip, tags):
        """Register an ip tag for a Dynamic Address Group

        This method can be batched with batch_start() and batch_end().

        Args:
            ip (:obj:`list` or :obj:`str`): IP address(es) to tag
            tags (:obj:`list` or :obj:`str`): The tag(s) for the IP address

        """
        root, payload = self._create_uidmessage()
        register = payload.find("register")
        if register is None:
            register = ET.SubElement(payload, "register")
        ip = list(set(string_or_list(ip)))
        tags = list(set(string_or_list(tags)))
        if not tags:
            return
        tags = [self.prefix+t for t in tags]
        for c_ip in ip:
            tagelement = register.find("./entry[@ip='%s']/tag" % c_ip)
            if tagelement is None:
                entry = ET.SubElement(register, "entry", {"ip": c_ip})
                tagelement = ET.SubElement(entry, "tag")
            for tag in tags:
                member = ET.SubElement(tagelement, "member")
                member.text = tag
        self.send(root)

    def unregister(self, ip, tags):
        """Unregister an ip tag for a Dynamic Address Group

        This method can be batched with batch_start() and batch_end().

        Args:
            ip (:obj:`list` or :obj:`str`): IP address(es) with the tag to remove
            tags (:obj:`list` or :obj:`str`): The tag(s) to remove from the IP address

        """
        root, payload = self._create_uidmessage()
        unregister = payload.find("unregister")
        if unregister is None:
            unregister = ET.SubElement(payload, "unregister")
        ip = list(set(string_or_list(ip)))
        tags = list(set(string_or_list(tags)))
        if not tags:
            return
        tags = [self.prefix+t for t in tags]
        for c_ip in ip:
            tagelement = unregister.find("./entry[@ip='%s']/tag" % c_ip)
            if tagelement is None:
                entry = ET.SubElement(unregister, "entry", {"ip": c_ip})
                tagelement = ET.SubElement(entry, "tag")
            for tag in tags:
                member = ET.SubElement(tagelement, "member")
                member.text = tag
        self.send(root)

    def get_registered_ip(self, ip=None, tags=None, prefix=None):
        """Return registered/tagged addresses

        When called without arguments, retrieves all registered addresses.

        Note: Passing a single ip and/or single tag to this method results in a response
        from the firewall that contains only the relevant entries. ie. the filtering is done on
        the firewall before it responds.  Passing a list of multiple ip addresses or tags will
        result in retreival of the entire tag database from the firewall which is then filtered and
        returned with only the relevant entries. Therefor, using a single ip or tag is more efficient.

        **Support:** PAN-OS 6.0 and higher

        Args:
            ip (:obj:`list` or :obj:`str`): IP address(es) to get tags for
            tags (:obj:`list` or :obj:`str`): Tag(s) to get
            prefix (str): Override class tag prefix

        Returns:
            dict: ip addresses as keys with tags as values

        """
        if prefix is None:
            prefix = self.prefix
        root = ET.Element("show")
        cmd = ET.SubElement(root, "object")
        # Simple check to determine which command to use
        if self.device and self.device.version and PanOSVersion('6.1.0') > self.device.version:
            cmd = ET.SubElement(cmd, "registered-address")
        else:
            cmd = ET.SubElement(cmd, "registered-ip")
        # Add arguments to command
        ip = list(set(string_or_list_or_none(ip)))
        tags = list(set(string_or_list_or_none(tags)))
        tags = [prefix+t for t in tags]
        if len(tags) == 1:
            tag_element = ET.SubElement(cmd, "tag")
            ET.SubElement(tag_element, "entry", {"name": tags[0]})
        if len(ip) == 1:
            ip_element = ET.SubElement(cmd, "ip")
            ip_element.text = ip[0]
        root = self.device.op(cmd=ET.tostring(root), vsys=self.device.vsys, cmd_xml=False)
        entries = root.findall("./result/entry")
        addresses = {}
        for entry in entries:
            c_ip = entry.get("ip")
            if ip and c_ip not in ip:
                continue
            members = entry.findall("./tag/member")
            c_tags = []
            for member in members:
                tag = member.text
                if not prefix or tag.startswith(prefix):
                    if not tags or tag in tags:
                        c_tags.append(tag)
            if c_tags:
                addresses[c_ip] = c_tags
        return addresses

    def clear_registered_ip(self, ip=None, tags=None, prefix=None):
        """Unregister registered/tagged addresses

        Removes registered addresses used by dynamic address groups.
        When called without arguments, removes all registered addresses

        Note: Passing a single ip and/or single tag to this method results in a response
        from the firewall that contains only the relevant entries. ie. the filtering is done on
        the firewall before it responds.  Passing a list of multiple ip addresses or tags will
        result in retreival of the entire tag database from the firewall which is then filtered and
        returned with only the relevant entries. Therefor, using a single ip or tag is more efficient.

        **Support:** PAN-OS 6.0 and higher

        Warning:
            This will clear any batch without it being sent, and can't be used as part of a batch.

        Args:
            ip (:obj:`list` or :obj:`str`): IP address(es) to remove tags for
            tags (:obj:`list` or :obj:`str`): Tag(s) to remove
            prefix (str): Override class tag prefix

        """
        addresses = self.get_registered_ip(ip, tags, prefix)
        self.batch_start()
        for ip, tags in addresses.items():
            self.unregister(ip, tags)
        self.batch_end()

    def audit_registered_ip(self, ip_tags_pairs):
        """Synchronize the current registered-ip tag list to this exact set of ip-tags

        Sets the registered-ip tag list on the device.
        Regardless of the current state of the registered-ip tag list when this method is
        called, at the end of the method the list will contain only the ip-tags passed in the
        argument. The current state of the list is retrieved to reduce the number of operations
        needed. If the list is currently in the requested state, no API call is made after
        retrieving the list.

        **Support:** PAN-OS 6.0 and higher

        Warning:
            This will clear any batch without it being sent, and can't be used as part of a batch.

        Args:
            ip_tags_pairs (dict): dictionary where keys are ip addresses and values or tuples of tags

        """
        device_list = self.get_registered_ip()
        requested_list = deepcopy(ip_tags_pairs)
        self.batch_start()
        # Handle unregistrations
        for ip, tags in device_list.items():
            if ip not in requested_list:
                # The IP is not requested, unregister it and all its tags
                self.unregister(ip, tags)
            else:
                # Convert requested tags from tuple to list
                requested_list[ip] = list(requested_list[ip])
                # The IP is requested, audit its tags
                for tag in tags:
                    if tag not in requested_list[ip]:
                        # Tag is not requested, unregister it
                        self.unregister(ip, tag)
                    else:
                        # Tag already exists on device, so don't re-register it
                        requested_list[ip].remove(tag)
        # Remove ip's with no tags left to register
        requested_list = {ip: tags for ip, tags in requested_list.items() if tags}
        # Handle registrations
        for ip, tags in requested_list.items():
            self.register(ip, tags)
        self.batch_end()
