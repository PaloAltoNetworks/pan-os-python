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
from pan.xapi import PanXapiError


class UserId(object):

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
        self._batch = True
        self._batch_uidmessage = deepcopy(self._uidmessage)

    def batch_end(self):
        uid_message, payload = self._create_uidmessage()
        self._batch = False
        if len(payload) > 0:
            self.send(uid_message)
        self._batch_uidmessage = deepcopy(self._uidmessage)

    def send(self, uidmessage):
        if self._batch:
            return
        else:
            cmd = et.tostring(uidmessage)
            try:
                self.panfirewall.xapi.user_id(cmd=cmd, vsys=self.panfirewall.vsys)
            except (err.PanDeviceXapiError, PanXapiError) as e:
                # Check if this is just an error about duplicates or nonexistant tags
                # If so, ignore the error. Most operations don't care about this.
                if hasattr(e, 'msg'):
                    message = e.msg
                else:
                    message = e.message
                if message.endswith("already exists, ignore") or e.msg.endswith("does not exist, ignore unreg"):
                    return
                else:
                    raise e

    def login(self, user, ip):
        root, payload = self._create_uidmessage()
        login = payload.find("login")
        if login is None:
            login = et.SubElement(payload, "login")
        et.SubElement(login, "entry", {"name": user, "ip": ip})
        self.send(root)

    def logins(self, users):
        """Login multiple users in the same API call
        
        Arguments:
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
        root, payload = self._create_uidmessage()
        logout = payload.find("logout")
        if logout is None:
            logout = et.SubElement(payload, "logout")
        et.SubElement(logout, "entry", {"name": user, "ip": ip})
        self.send(root)
    
    def logouts(self, users):
        """Logout multiple users in the same API call
        
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

    def groups(self):
        raise NotImplementedError

    def register(self, ip, tags):
        root, payload = self._create_uidmessage()
        register = payload.find("register")
        if register is None:
            register = et.SubElement(payload, "register")
        tagelement = register.find("./entry[@ip='%s']/tag" % ip)
        if tagelement is None:
            entry = et.SubElement(register, "entry", {"ip": ip})
            tagelement = et.SubElement(entry, "tag")
        tags = set(tags)
        for tag in tags:
            member = et.SubElement(tagelement, "member")
            member.text = tag
        self.send(root)

    def unregister(self, ip, tags):
        root, payload = self._create_uidmessage()
        unregister = payload.find("unregister")
        if unregister is None:
            unregister = et.SubElement(payload, "unregister")
        tagelement = unregister.find("./entry[@ip='%s']/tag" % ip)
        if tagelement is None:
            entry = et.SubElement(unregister, "entry", {"ip": ip})
            tagelement = et.SubElement(entry, "tag")
        tags = set(tags)
        for tag in tags:
            member = et.SubElement(tagelement, "member")
            member.text = tag
        self.send(root)

    def get_all_registered_ip(self):
        """Return all registered/tagged addresses

        Support:
            PAN-OS 6.0 and higher
        """
        self.panfirewall.xapi.op(cmd='show object registered-address all', vsys=self.panfirewall.vsys, cmd_xml=True)
        root = self.panfirewall.xapi.element_root
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
        WARNING: this will clear any batch without it being sent, and can't
        be used as part of a batch.

        Support:
            PAN-OS 6.0 and higher
        """
        addresses = self.get_all_registered_ip()
        self.batch_start()
        for ip, tags in addresses.iteritems():
            self.unregister(ip, tags)
        self.batch_end()
