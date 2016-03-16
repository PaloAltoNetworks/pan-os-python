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


"""Panorama object

For functions specific to Panorama
"""


# import modules
import logging
import xml.etree.ElementTree as ET
from copy import deepcopy

# import other parts of this pandevice package
import pandevice
import base
import firewall
import errors as err
from base import VarPath as Var
from base import PanObject, Root, MEMBER, ENTRY
from pandevice import yesno

import pan.commit


logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class DeviceGroup(PanObject):

    XPATH = "/device-group"
    ROOT = Root.DEVICE
    SUFFIX = ENTRY
    CHILDTYPES = (
        "objects.AddressObject",
    )

    @classmethod
    def variables(cls):
        return (
            Var("tag", vartype="entry"),
        )

    def devicegroup(self):
        return self


class Panorama(base.PanDevice):

    CHILDTYPES = (
        "panorama.DeviceGroup",
        "firewall.Firewall",
    )

    def __init__(self,
                 hostname,
                 api_username=None,
                 api_password=None,
                 api_key=None,
                 port=443,
                 *args,
                 **kwargs
                 ):
        super(Panorama, self).__init__(hostname, api_username, api_password, api_key, port, *args, **kwargs)
        # create a class logger
        self._logger = logging.getLogger(__name__ + "." + self.__class__.__name__)

    def op(self, cmd=None, vsys=None, xml=False, cmd_xml=True, extra_qs=None, retry_on_peer=False):
        # TODO: Support device-group and template scope
        return super(Panorama, self).op(cmd, vsys=None, xml=xml, cmd_xml=cmd_xml, extra_qs=extra_qs, retry_on_peer=retry_on_peer)

    def xpath_vsys(self):
        raise err.PanDeviceError("Attempt to modify vsys configuration on non-firewall device")

    def xpath_panorama(self):
        return "/config/panorama"

    def panorama(self):
        return self

    def commit_all(self, sync=False, sync_all=True, exception=False, devicegroup=None, serials=(), cmd=None):
        self._logger.debug("Commit-all initiated on device: %s" % (self.hostname,))

        if cmd is None:
            # XXX: This only works on PAN-OS 7.0+
            e = ET.Element("commit-all")
            if devicegroup is not None and cmd is None:
                sp = ET.SubElement(e, "shared-policy")
                dg = ET.SubElement(sp, "device-group")
                dg_e = ET.SubElement(dg, "entry", {"name": devicegroup})
                if serials:
                    d = ET.SubElement(dg_e, "devices")
                    for serial in serials:
                        ET.SubElement(d, "entry", {"name": serial})
            cmd = ET.tostring(e)
        elif isinstance(cmd, pan.commit.PanCommit):
            cmd = cmd.cmd()
        elif isinstance(cmd, ET.Element):
            cmd = ET.tostring(cmd)

        result = self._commit(sync=sync,
                              sync_all=sync_all,
                              commit_all=True,
                              exception=exception,
                              cmd=cmd)
        return result

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
            self.xapi.set(pandevice.XPATH_DEVICE_GROUPS + "/entry[@name='%s']" % (devicegroup,))

    def set_device_group(self, devicegroup, devices, exclusive=False):
        """ For Panorama, set the device group for a device

        :param devicegroup: String, Device-group to set devices to
        :param devices: PanDevice or List of PanDevices
        :param exclusive: Device-group should contain ONLY these devices
        :return: None
        """
        # TODO: Implement 'exclusive'
        self._logger.debug("Set device-group to '%s'" % devicegroup)
        if issubclass(devices.__class__, base.PanDevice):
            devices = [devices]
        device_refresh_needed = False
        for device in devices:
            if device.serial is None or device.devicegroup is None:
                device_refresh_needed = True
                break
        if device_refresh_needed:
            self.refresh_devices_from_panorama(devices)
        # All devices have serial numbers now, so start setting devicegroup
        for device in devices:
            # If the device was in a group, and that group changed, pull it out of the current group
            if device.devicegroup != devicegroup and \
                            device.devicegroup is not None:
                self._logger.debug("Moving device %s out of device-group %s" % (device.hostname, device.devicegroup))
                self.set_config_changed()
                self.xapi.delete(
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
                self.xapi.set(
                    pandevice.XPATH_DEVICE_GROUPS +
                    "/entry[@name='%s']/devices" % (devicegroup,),
                    "<entry name='%s'/>" % (device.serial,)
                )
                device.devicegroup = devicegroup

    def refresh_devices(self, devices=(), only_connected=False, expand_vsys=True, include_device_groups=True, add=False, running_config=False):
        """Refresh device groups and devices using config and operational commands"""
        logger.debug(self.hostname + ": refresh_devices called")
        try:
            # Test if devices is iterable
            test_iterable = iter(devices)
        except TypeError:
            # This probably means a single device was passed in, not an iterable.
            # Convert to an iterable with a single item.
            devices = (devices,)
        # Remove None from list of devices
        devices = [x for x in devices if x is not None]
        # Get the list of managed devices
        if only_connected:
            cmd = "show devices connected"
        else:
            cmd = "show devices all"
        devices_xml = self.op(cmd)
        devices_xml = devices_xml.find("result/devices")

        # Filter to only requested devices
        if devices:
            filtered_devices_xml = ET.Element("devices")
            for serial, vsys in [(d.serial, d.vsys) for d in devices]:
                if serial is None:
                    continue
                entry = devices_xml.find("entry[@name='%s']" % serial)
                if entry is None:
                    raise err.PanDeviceError("Can't find device with serial %s attached to Panorama at %s" %
                                             (serial, self.hostname))
                multi_vsys = yesno(entry.findtext("multi-vsys"))
                # Create entry if needed
                if filtered_devices_xml.find("entry[@name='%s']" % serial) is None:
                    entry_copy = deepcopy(entry)
                    # If multivsys firewall with vsys defined, erase all vsys in filtered
                    if multi_vsys and vsys != "shared" and vsys is not None:
                        entry_copy.remove(entry_copy.find("vsys"))
                        ET.SubElement(entry_copy, "vsys")
                    filtered_devices_xml.append(entry_copy)
                # Get specific vsys
                if vsys != "shared" and vsys is not None:
                    vsys_entry = entry.find("vsys/entry[@name='%s']" % vsys)
                    if vsys_entry is None:
                        raise err.PanDeviceError("Can't find device with serial %s and"
                                                 " vsys %s attached to Panorama at %s" %
                                                 (serial, vsys, self.hostname)
                                                 )
                    vsys_section = filtered_devices_xml.find("entry[@name='%s']/vsys" % serial)
                    vsys_section.append(vsys_entry)
            devices_xml = filtered_devices_xml

        # Manipulate devices_xml so each vsys is a separate device
        if expand_vsys:
            original_devices_xml = deepcopy(devices_xml)
            devices_xml = ET.Element("devices")
            for entry in original_devices_xml:
                serial = entry.findtext("serial")
                for vsys_entry in entry.findall("vsys/entry"):
                    new_vsys_device = deepcopy(entry)
                    new_vsys_device.set("name", serial)
                    ET.SubElement(new_vsys_device, "vsysid").text = vsys_entry.get("name")
                    ET.SubElement(new_vsys_device, "vsysname").text = vsys_entry.findtext("display-name")
                    devices_xml.append(new_vsys_device)

        # Create firewall instances
        firewall_instances = firewall.Firewall.refresh_all_from_xml(devices_xml, refresh_children=not expand_vsys)

        if not include_device_groups:
            if add:
                self.removeall(firewall.Firewall)
                self.extend(firewall_instances)
            return firewall_instances

        # Create device-groups

        # Get the list of device groups from configuration XML
        api_action = self.xapi.show if running_config else self.xapi.get
        devicegroup_configxml = api_action("/config/devices/entry[@name='localhost.localdomain']/device-group")
        devicegroup_configxml = devicegroup_configxml.find("result/device-group")

        # Get the list of device groups from operational commands
        devicegroup_opxml = self.op("show devicegroups")
        devicegroup_opxml = devicegroup_opxml.find("result/devicegroups")

        # Combine the config XML and operational command XML to get a complete picture
        # of the device groups
        pandevice.xml_combine(devicegroup_opxml, devicegroup_configxml)

        devicegroup_instances = DeviceGroup.refresh_all_from_xml(devicegroup_opxml, refresh_children=False)

        for dg in devicegroup_instances:
            dg_serials = [entry.get("name") for entry in devicegroup_opxml.findall("entry[@name='%s']/devices/entry" % dg.name)]
            # Find firewall with each serial
            for dg_serial in dg_serials:
                all_dg_vsys = [entry.get("name") for entry in devicegroup_opxml.findall(
                    "entry[@name='%s']/devices/entry[@name='%s']/vsys/entry" % (dg.name, dg_serial))]
                # Collect the firewall serial entry to get current status information
                fw_entry = devicegroup_opxml.find("entry[@name='%s']/devices/entry[@name='%s']" % (dg.name, dg_serial))
                if not all_dg_vsys:
                    # This is a single-context firewall, assume vsys1
                    all_dg_vsys = ["vsys1"]
                for dg_vsys in all_dg_vsys:
                    fw = next((x for x in firewall_instances if x.serial == dg_serial and x.vsys == dg_vsys), None)
                    if fw is None:
                        # It's possible for device-groups to reference a serial/vsys that doesn't exist
                        # In this case, create the FW instance
                        if not only_connected:
                            fw = firewall.Firewall(serial=dg_serial, vsys=dg_vsys)
                            dg.add(fw)
                    else:
                        # Move the firewall to the device-group
                        dg.add(fw)
                        firewall_instances.remove(fw)
                        fw.state.connected = yesno(fw_entry.findtext("connected"))
                        fw.state.unsupported_version = yesno(fw_entry.findtext("unsupported-version"))
                        fw.state.set_shared_policy_synced(fw_entry.findtext("shared-policy-status"))

        if add:
            for dg in devicegroup_instances:
                found_dg = self.find(dg.name, DeviceGroup)
                if found_dg is not None:
                    # Move the firewalls to the existing devicegroup
                    found_dg.removeall(firewall.Firewall)
                    found_dg.extend(dg.children)
                else:
                    # Devicegroup doesn't exist, add it
                    self.add(dg)
            # Add firewalls that are not in devicegroups
            self.removeall(firewall.Firewall)
            self.extend(firewall_instances)

        return firewall_instances + devicegroup_instances
