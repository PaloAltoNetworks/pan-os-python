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

# Author: Brian Torres-Gil <btorres-gil@paloaltonetworks.com>

"""User-ID and Dynamic Address Group updates using the User-ID API"""

import logging
import xml.etree.ElementTree as et
from copy import deepcopy

import pandevice.errors as err
from pandevice import string_or_list
from pan.xapi import PanXapiError


logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class UserId(object):
    """User-ID Subsystem of Firewall

    A member of a firewall.Firewall object that has special methods for
    interacting with the User-ID API. This includes login/logout of a user,
    user/group mappings, and dynamic address group tags.

    This class is typically not instantiated by anything but the
    firewall.Firewall class itself. There is an instance of this UserId class
    inside every instantiated firewall.Firewall class.

    Args:
        panfirewall (firewall.Firewall): The firewall this user-id subsystem leverages

    """

    def __init__(self, panfirewall):
        # Create a class logger
        self._logger = logging.getLogger(__name__ + "." + self.__class__.__name__)
        self.panfirewall = panfirewall

        # Build the initial uid-message
        self._uidmessage = et.fromstring("<uid-message>"
                                         "<version>1.0</version>"
                                         "<type>update</type>"
                                         "<payload/>"
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
            cmd = et.tostring(uidmessage)
            try:
                self.panfirewall.xapi.user_id(cmd=cmd, vsys=self.panfirewall.vsys)
            except (err.PanDeviceXapiError, PanXapiError) as e:
                # Check if this is just an error about duplicates or nonexistant tags
                # If so, ignore the error. Most operations don't care about this.
                message = str(e)
                if message.endswith("already exists, ignore") or message.endswith("does not exist, ignore unreg"):
                    return
                else:
                    raise e

    def login(self, user, ip):
        """Login a single user

        Maps a user to an IP address

        This method can be batched with batch_start() and batch_end().

        Args:
            user (str): a username
            ip (str): an ip address

        """
        root, payload = self._create_uidmessage()
        login = payload.find("login")
        if login is None:
            login = et.SubElement(payload, "login")
        et.SubElement(login, "entry", {"name": user, "ip": ip})
        self.send(root)

    def logins(self, users):
        """Login multiple users in the same API call

        This method can be batched with batch_start() and batch_end().

        Args:
            users: a list of sets of user/ip mappings
                   eg. [(user1, 10.0.1.1), (user2, 10.0.1.2)]

        """
        root, payload = self._create_uidmessage()
        login = payload.find("login")
        if login is None:
            login = et.SubElement(payload, "login")
        for user in users:
            et.SubElement(login, "entry", {"name": user[0], "ip": user[1]})
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
            logout = et.SubElement(payload, "logout")
        et.SubElement(logout, "entry", {"name": user, "ip": ip})
        self.send(root)

    def logouts(self, users):
        """Logout multiple users in the same API call

        This method can be batched with batch_start() and batch_end().

        Arguments:
            users: a list of sets of user/ip mappings
                   eg. [(user1, 10.0.1.1), (user2, 10.0.1.2)]

        """
        root, payload = self._create_uidmessage()
        logout = payload.find("logout")
        if logout is None:
            logout = et.SubElement(payload, "logout")
        for user in users:
            et.SubElement(logout, "entry", {"name": user[0], "ip": user[1]})
        self.send(root)

    def register(self, ip, tags):
        """Register an ip tag for a Dynamic Address Group

        This method can be batched with batch_start() and batch_end().

        Args:
            ip (str): IP address to tag
            tags (str): The tag for the IP address

        """
        root, payload = self._create_uidmessage()
        register = payload.find("register")
        if register is None:
            register = et.SubElement(payload, "register")
        tagelement = register.find("./entry[@ip='%s']/tag" % ip)
        if tagelement is None:
            entry = et.SubElement(register, "entry", {"ip": ip})
            tagelement = et.SubElement(entry, "tag")
        tags = string_or_list(tags)
        tags = list(set(tags))
        for tag in tags:
            member = et.SubElement(tagelement, "member")
            member.text = tag
        self.send(root)

    def unregister(self, ip, tags):
        """Unregister an ip tag for a Dynamic Address Group

        This method can be batched with batch_start() and batch_end().

        Args:
            ip (str): IP address with the tag to remove
            tags (str): The tag to remove from the IP address

        """
        root, payload = self._create_uidmessage()
        unregister = payload.find("unregister")
        if unregister is None:
            unregister = et.SubElement(payload, "unregister")
        tagelement = unregister.find("./entry[@ip='%s']/tag" % ip)
        if tagelement is None:
            entry = et.SubElement(unregister, "entry", {"ip": ip})
            tagelement = et.SubElement(entry, "tag")
        tags = string_or_list(tags)
        tags = list(set(tags))
        for tag in tags:
            member = et.SubElement(tagelement, "member")
            member.text = tag
        self.send(root)

    def get_all_registered_ip(self):
        """Return all registered/tagged addresses

        **Support:** PAN-OS 6.0 and higher

        Returns:
            dict: ip addresses as keys with tags as values

        """
        root = self.panfirewall.op(cmd='show object registered-ip all', vsys=self.panfirewall.vsys, cmd_xml=True)
        entries = root.findall("./result/entry")
        if not entries:
            return None
        addresses = {}
        for entry in entries:
            ip = entry.get("ip")
            members = entry.findall("./tag/member")
            tags = []
            for member in members:
                tags.append(member.text)
            addresses[ip] = tags
        return addresses

    def clear_all_registered_ip(self):
        """Unregister all registered/tagged addresses

        Removes all registered addresses used by dynamic address groups.

        **Support:** PAN-OS 6.0 and higher

        Warning:
            This will clear any batch without it being sent, and can't be used as part of a batch.

        """
        addresses = self.get_all_registered_ip()
        self.batch_start()
        for ip, tags in addresses.iteritems():
            self.unregister(ip, tags)
        self.batch_end()
