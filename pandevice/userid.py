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

from pan.xapi import PanXapiError

import pandevice.errors as err
from pandevice import getlogger, string_or_list, string_or_list_or_none
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
        self._uidmessage = ET.fromstring(
            "<uid-message>"
            + "<version>1.0</version>"
            + "<type>update</type>"
            + "<payload/>"
            + "</uid-message>"
        )
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
                if self.ignore_dup_errors and (
                    message.endswith("already exists, ignore")
                    or message.endswith("does not exist, ignore unreg")
                ):
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
            entry.set("timeout", str(timeout))
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
                entry.set("timeout", str(user[2]))
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
        tags = [self.prefix + t for t in tags]
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
        tags = [self.prefix + t for t in tags]
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

        Raises:
            PanDeviceError if running PAN-OS < 8.0 and a logfile is returned
                instead of IP/tag mapings.

        """
        if self.device is None:
            raise err.PanDeviceNotSet("No device set for this userid instance")
        version = self.device.retrieve_panos_version()

        if prefix is None:
            prefix = self.prefix

        # Build up the command.
        limit = 0
        start_elm = None
        start_offset = 1
        root = ET.Element("show")
        cmd = ET.SubElement(root, "object")
        if version >= (6, 1, 0):
            cmd = ET.SubElement(cmd, "registered-ip")
            if version >= (8, 0, 0):
                # PAN-OS 8.0+ supports paging.
                limit = 500
                ET.SubElement(cmd, "limit").text = "{0}".format(limit)
                start_elm = ET.SubElement(cmd, "start-point")
                start_elm.text = "{0}".format(start_offset)
        else:
            cmd = ET.SubElement(cmd, "registered-address")

        # Add ip/tag filter arguments to command.
        ip = list(set(string_or_list_or_none(ip)))
        tags = list(set(string_or_list_or_none(tags)))
        tags = [prefix + t for t in tags]
        if len(tags) == 1:
            tag_element = ET.SubElement(cmd, "tag")
            ET.SubElement(tag_element, "entry", {"name": tags[0]})
        if len(ip) == 1:
            ip_element = ET.SubElement(cmd, "ip")
            ip_element.text = ip[0]

        addresses = {}
        while True:
            resp = self.device.op(
                cmd=ET.tostring(root, encoding="utf-8"),
                vsys=self.device.vsys,
                cmd_xml=False,
            )

            # PAN-OS 7.1 and lower can return "outfile" instead of actual results.
            outfile = resp.find("./result/msg/line/outfile")
            if outfile is not None:
                msg = [
                    'PAN-OS returned "{0}" instead of IP/tag mappings'.format(
                        outfile.text
                    ),
                    "please upgrade to PAN-OS 8.0+",
                ]
                raise err.PanDeviceError(", ".join(msg))

            entries = resp.findall("./result/entry")
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

            if start_elm is None or limit == 0 or len(entries) < limit:
                break

            start_offset += len(entries)
            start_elm.text = "{0}".format(start_offset)

        # Done.
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

    def set_group(self, group, users):
        """
        Set a group's membership to the specified users.

        This method can be batched with batch_start() and batch_end().

        Args:
            group: The group name.
            users (list): The users to be in this group.

        """
        root, payload = self._create_uidmessage()

        # Find the groups section.
        groups = payload.find("./groups")
        if groups is None:
            groups = ET.SubElement(payload, "groups")

        # Find the group.
        entries = groups.findall("./entry")
        for entry in entries:
            if entry.attrib["name"] == group:
                ge = entry.find("./members")
                break
        else:
            entry = ET.SubElement(groups, "entry", {"name": group})
            ge = ET.SubElement(entry, "members")

        # Now add in the users to this group.
        for user in users:
            ET.SubElement(ge, "entry", {"name": user})

        # Done.
        self.send(root)

    def get_groups(self, style=None):
        """
        Get a list of groups.

        Args:
            style: The type of groups to retrieve.  If unspecified, returns a list of
                all groups.  Can be "custom-group", "dynamic", or "xmlapi".

        Returns:
            list

        """
        msg = [
            "<show><user><group><list>",
        ]
        if style is not None:
            msg.append("<entry name='{0}'/>".format(style))
        msg.append("</list></group></user></show>")
        cmd = "".join(msg)
        vsys = self.device.vsys or "vsys1"

        resp = self.device.op(cmd, vsys=self.device.vsys, cmd_xml=False)
        if resp is None:
            return

        """
        Example returned XML:

        9.1:
        <response status="success"><result><![CDATA[\nmalicious_users \ncn=contractors,cn=users,dc=nam,dc=local \ntemp_contractors_dynamic_group \nspecial_project \nrisky_users \ncn=employees,cn=users,dc=nam,dc=local \nhigh_risk_users \n\nTotal: 7\n* : Custom Group\n\n]]></result></response>
        <response status="success"><result><![CDATA[\n\nTotal: 0\n* : Custom Group\n\n]]></result></response>
        <response status="success"><result><![CDATA[\nmalicious_users \ntemp_contractors_dynamic_group \nspecial_project \nrisky_users \nhigh_risk_users \n\nTotal: 5\n* : Custom Group\n\n]]></result></response>
        """

        data = resp.find("./result")
        if data is None:
            return

        lines = data.text.split("\n")
        ans = []
        for line in lines:
            if line.startswith("Total: "):
                break
            val = line.strip()
            if val:
                ans.append(val)

        return ans

    def get_group_members(self, group):
        """
        Returns a list of users in the given group.

        Args:
            group: The name of the group.

        Returns:
            list

        """
        cmd = "<show><user><group><name>" + group + "</name></group></user></show>"
        vsys = self.device.vsys or "vsys1"

        resp = self.device.op(cmd, vsys=vsys, cmd_xml=False)
        if resp is None:
            return

        """
        Example returned XML:

        9.1:
        <response status="success"><result><![CDATA[\nUser group \'blah\' does not exist or does not have members\n]]></result></response>
        <response status="success"><result><![CDATA[\n\nsource type: xmlapi\nGroup type: Dynamic\n\n[1     ] nam\\jsmith\n[2     ] panw\\garfield\n\n]]></result></response>
        """

        data = resp.find("./result")
        if data is None:
            return

        lines = data.text.split("\n")
        ans = [x.split("]")[1].strip() for x in lines if len(x.split("]")) == 2]

        return ans

    def get_user_tags(self, user=None, prefix=None):
        """
        Get the dynamic user tags.

        Note: PAN-OS 9.1+

        Args:
            user: Get only this user's tags, not all users and all tags.
            prefix: Override class tag prefix.

        Returns:
            dict: Dict where the user is the key and the value is a list of tags.

        """
        if prefix is None:
            prefix = self.prefix

        limit = 500
        start = 1
        start_elm = None
        msg = [
            "<show><object><registered-user>",
        ]
        if user is None:
            msg.append(
                "<all>"
                + "<limit>{0}</limit>".format(limit)
                + "<start-point>{0}</start-point>".format(start)
                + "</all>"
            )
        else:
            msg.append("<user>{0}</user>".format(user))
        msg.append("</registered-user></object></show>")

        cmd = ET.fromstring("".join(msg))
        if user is None:
            start_elm = cmd.find("./object/registered-user/all/start-point")

        ans = {}
        while True:
            resp = self.device.op(
                cmd=ET.tostring(cmd, encoding="utf-8"),
                vsys=self.device.vsys,
                cmd_xml=False,
            )
            entries = resp.findall("./result/entry")
            for entry in entries:
                key = entry.attrib["user"]
                val = []
                members = entry.findall("./tag/member")
                for member in members:
                    tag = member.text
                    if not prefix or tag.startswith(prefix):
                        val.append(tag)
                ans[key] = val

            if start_elm is None or limit <= 0 or len(entries) < limit:
                break

            start += len(entries)
            start_elm.text = "{0}".format(start)

        # Done.
        return ans

    def tag_user(self, user, tags, timeout=None, prefix=None):
        """
        Tags the user with the specified tags.

        This method can be batched with batch_start() and batch_end().

        Note: PAN-OS 9.1+

        Args:
            user: The user.
            tags (list): The list of tags to apply.
            timeout (int): (Optional) The timeout for the given tags.
            prefix: Override class tag prefix.

        """
        if timeout is not None:
            timeout = int(timeout)

        if prefix is None:
            prefix = self.prefix or ""

        root, payload = self._create_uidmessage()

        # Find the register user tags section.
        ru = payload.find("./register-user")
        if ru is None:
            ru = ET.SubElement(payload, "register-user")

        # Find the tags section for this specific user.
        entries = ru.findall("./entry")
        for entry in entries:
            if entry.attrib["name"] == user:
                te = entry.find("./tag")
                break
        else:
            entry = ET.SubElement(ru, "entry", {"user": user,})
            te = ET.SubElement(entry, "tag")

        # Now add in the tags with the specified timeout.
        props = {}
        if timeout is not None:
            props["timeout"] = "{0}".format(timeout)
        for tag in tags:
            ET.SubElement(te, "member", props).text = prefix + tag

        # Done.
        self.send(root)

    def untag_user(self, user, tags=None, prefix=None):
        """
        Removes tags associated with a user.

        This method can be batched with batch_start() and batch_end().

        Note: PAN-OS 9.1+

        Args:
            user: The user.
            tags (list): (Optional) Remove only these tags instead of all tags.
            prefix: Override class tag prefix.

        """
        root, payload = self._create_uidmessage()

        if prefix is None:
            prefix = self.prefix or ""

        # Find the unregister user tags section.
        uu = payload.find("./unregister-user")
        if uu is None:
            uu = ET.SubElement(payload, "unregister-user")

        # Find the tags section for this specific user.
        entries = uu.findall("./entry")
        for entry in entries:
            if entry.attrib["name"] == user:
                break
        else:
            entry = ET.SubElement(uu, "entry", {"user": user,})

        # Do tag removal.
        te = entry.find("./tag")
        if tags is not None:
            if te is None:
                te = ET.SubElement(entry, "tag")
            for tag in tags:
                ET.SubElement(te, "member").text = prefix + tag
        elif te is not None:
            entry.remove(te)

        # Done.
        self.send(root)
