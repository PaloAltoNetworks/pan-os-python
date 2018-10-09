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


"""Palo Alto Networks Firewall object"""

# import modules
import itertools
import re
import logging
import xml.etree.ElementTree as ET
from decimal import Decimal

from pandevice import getlogger
from pandevice import device
from pandevice import yesno

# import other parts of this pandevice package
import pandevice.errors as err
from pandevice.base import PanDevice, Root, ENTRY
from pandevice.base import VarPath as Var


logger = getlogger(__name__)


class Firewall(PanDevice):
    """A Palo Alto Networks Firewall

    This object can represent a firewall physical chassis, virtual firewall, or
    individual vsys.

    Args:
        hostname: Hostname or IP of device for API connections
        api_username: Username of administrator to access API
        api_password: Password of administrator to access API
        api_key: The API Key for connecting to the device's API
        serial: The serial number of this firewall
        port: Port of device for API connections
        vsys: The vsys of this firewall (eg. "vsys1", "vsys2", etc.)
        is_virtual (bool): Physical or Virtual firewall
        timeout: The timeout for asynchronous jobs
        interval: The interval to check asynchronous jobs

    """
    XPATH = "/devices"
    ROOT = Root.MGTCONFIG
    SUFFIX = ENTRY
    NAME = "serial"
    DEFAULT_VSYS = 'vsys1'
    CHILDTYPES = (
        "device.Vsys",
        "device.VsysResources",
        "device.SystemSettings",
        "device.PasswordProfile",
        "device.Administrator",
        "ha.HighAvailability",
        "objects.AddressObject",
        "objects.AddressGroup",
        "objects.ServiceObject",
        "objects.ServiceGroup",
        "objects.ApplicationObject",
        "objects.ApplicationGroup",
        "objects.ApplicationFilter",
        "objects.SecurityProfileGroup",
        "objects.CustomUrlCategory",
        "policies.Rulebase",
        "network.EthernetInterface",
        "network.AggregateInterface",
        "network.LoopbackInterface",
        "network.TunnelInterface",
        "network.VlanInterface",
        "network.Vlan",
        "network.VirtualRouter",
        "network.ManagementProfile",
        "network.VirtualWire",
        "network.IkeGateway",
        "network.IpsecTunnel",
        "network.IpsecCryptoProfile",
        "network.IkeCryptoProfile",
    )

    def __init__(self,
                 hostname=None,
                 api_username=None,
                 api_password=None,
                 api_key=None,
                 serial=None,
                 port=443,
                 vsys=None,  # 'vsys#', 'shared', or None
                 is_virtual=None,
                 multi_vsys=None,
                 *args,
                 **kwargs
                 ):
        """Initialize PanDevice"""
        vsys_name = kwargs.pop('vsys_name', None)
        serial_ha_peer = kwargs.pop('serial_ha_peer', None)
        management_ip = kwargs.pop('management_ip', None)
        super(Firewall, self).__init__(hostname, api_username, api_password, api_key,
                                       port=port,
                                       is_virtual=is_virtual,
                                       *args,
                                       **kwargs
                                       )
        # create a class logger
        self._logger = logging.getLogger(__name__ + "." + self.__class__.__name__)

        self.serial = serial
        self._vsys = vsys
        self.vsys_name = vsys_name
        self.multi_vsys = multi_vsys
        self.serial_ha_peer = serial_ha_peer
        self.management_ip = management_ip

        self.shared = False
        """Set to True to act on the shared part of this firewall"""

        self.state = FirewallState()
        """Panorama state variables refreshed by Panorama"""

    def __repr__(self):
        return "<%s %s %s at 0x%x>" % (type(self).__name__, repr(self.id), repr(self.vsys), id(self))

    @property
    def id(self):
        return self.serial or self.hostname or '<no-id>'

    @property
    def vsys(self):
        # Check if attribute exists because this could be called during
        # init of the object before 'shared' exists.
        if hasattr(self, "shared") and self.shared:
            return None
        else:
            return self._vsys

    @vsys.setter
    def vsys(self, value):
        self._vsys = value
        # Check if attribute exists because this could be called during
        # init of the object before _ha_peer exists.
        if hasattr(self, "_ha_peer") and self.ha_peer is not None:
            self.ha_peer._vsys = value

    def xpath_vsys(self):
        return self._root_xpath_vsys(self.vsys)

    def xpath_panorama(self):
        raise err.PanDeviceError("Attempt to modify Panorama configuration on non-Panorama device")

    def op(self, cmd=None, vsys=None, xml=False, cmd_xml=True, extra_qs=None, retry_on_peer=False):
        """Perform operational command on this Firewall

        Args:
            cmd (str): The operational command to execute
            vsys (str): Vsys id. Defaults to the vsys of the firewall or the Vsys object in the parent tree.
            xml (bool): Return value should be a string (Default: False)
            cmd_xml (bool): True: cmd is not XML, False: cmd is XML (Default: True)
            extra_qs: Extra parameters for API call
            retry_on_peer (bool): Try on active Firewall first, then try on passive Firewall

        Returns:
            xml.etree.ElementTree: The result of the operational command. May also return a string of XML if xml=True

        """
        if vsys is None:
            vsys = self.vsys
        return super(Firewall, self).op(cmd, vsys, xml, cmd_xml, extra_qs, retry_on_peer)

    def generate_xapi(self):
        # Override super class to connect to Panorama
        #
        # Connect to this firewall via Panorama with 'target' argument set
        # to this firewall's serial number.  This happens when panorama and serial
        # variables are set in this firewall prior to the first connection.
        try:
            self.panorama()
        except err.PanDeviceNotSet:
            return super(Firewall, self).generate_xapi()
        if self.serial is not None and self.hostname is None:
            xapi_constructor = PanDevice.XapiWrapper
            kwargs = {'pan_device': self,
                      'api_key': self.panorama().api_key,
                      'hostname': self.panorama().hostname,
                      'port': self.panorama().port,
                      'timeout': self.timeout,
                      'serial': self.serial,
                      }
            return xapi_constructor(**kwargs)
        else:
            return super(Firewall, self).generate_xapi()

    def _save_system_info(self, system_info):
        """Save all the shared system info, plus firewall specific info.

        Invoked during "refresh_system_info()"

        """
        super(Firewall, self)._save_system_info(system_info)
        self.multi_vsys = system_info['system']['multi-vsys'] == 'on'

    def element(self):
        if self.serial is None:
            raise ValueError("Serial number must be set to generate element")
        entry = ET.Element("entry", {"name": self.serial})
        if self.parent == self.panorama() and self.serial is not None:
            # This is a firewall under a panorama
            if not self.multi_vsys:
                vsys = ET.SubElement(entry, "vsys")
                ET.SubElement(vsys, "entry", {"name": "vsys1"})
        elif self.parent == self.devicegroup() and self.multi_vsys:
            # This is a firewall under a device group
            if self.vsys.startswith("vsys"):
                vsys = ET.SubElement(entry, "vsys")
                ET.SubElement(vsys, "entry", {"name": self.vsys})
            else:
                vsys = ET.SubElement(entry, "vsys")
                all_vsys = self.findall(device.Vsys)
                for a_vsys in all_vsys:
                    ET.SubElement(vsys, "entry", {"name": a_vsys})
        return entry

    def apply(self):
        return

    def create(self):
        if self.parent is None:
            self.create_vsys()
            return
        # This is a firewall under a panorama or devicegroup
        panorama = self.panorama()
        logger.debug(panorama.hostname + ": create called on %s object \"%s\"" % (type(self), self.uid))
        panorama.set_config_changed()
        element = self.element_str()
        panorama.xapi.set(self.xpath_short(), element)

    def delete(self):
        if self.parent is None:
            self.delete_vsys()
            return
        panorama = self.panorama()
        logger.debug(panorama.hostname + ": delete called on %s object \"%s\"" % (type(self), self.serial))
        if self.parent == self.devicegroup() and self.multi_vsys:
            # This is a firewall under a devicegroup
            # Refresh device-group first to see if this is the only vsys
            devices_xpath = self.devicegroup().xpath() + self.XPATH
            devices_xml = panorama.xapi.get(devices_xpath)
            dg_vsys = devices_xml.findall("result/devices/entry[@name='%s']/vsys/entry" % self.serial)
            if dg_vsys:
                if len(dg_vsys) == 1:
                    # Only vsys, so delete whole entry
                    panorama.set_config_changed()
                    panorama.xapi.delete(self.xpath())
                else:
                    # It's not the only vsys, just delete the vsys
                    panorama.set_config_changed()
                    panorama.xapi.delete(self.xpath() + "/vsys/entry[@name='%s']" % self.vsys)
        else:
            # This is a firewall under a panorama
            panorama.set_config_changed()
            panorama.xapi.delete(self.xpath())
        if self.parent is not None:
            self.parent.remove_by_name(self.uid, type(self))

    def create_vsys(self):
        """Create the vsys on the live device that this Firewall object represents"""
        if self.vsys.startswith("vsys"):
            element = ET.Element("entry", {"name": self.vsys})
            if self.vsys_name is not None:
                ET.SubElement(element, "display-name").text = self.vsys_name
            self.set_config_changed()
            path = self._root_xpath_vsys(None).rsplit('/', 1)[0]
            self.xapi.set(path, ET.tostring(element, encoding='utf-8'), retry_on_peer=True)

    def delete_vsys(self):
        """Delete the vsys on the live device that this Firewall object represents"""
        if self.vsys.startswith("vsys"):
            self.set_config_changed()
            self.xapi.delete(self._root_xpath_vsys(self.vsys), retry_on_peer=True)

    def refreshall_from_xml(self, xml, refresh_children=False, variables=None):
        if len(xml) == 0:
            return []
        if variables is not None:
            return super(Firewall, self).refreshall_from_xml(
                xml, refresh_children, variables)
        op_vars = (
            Var("serial"),
            Var("ip-address", "management_ip"),
            Var("sw-version", "version"),
            Var("multi-vsys", vartype="bool"),
            Var("vsys_id", "vsys", default="vsys1"),
            Var("vsys_name"),
            Var("ha/state/peer/serial", "serial_ha_peer"),
            Var("connected", "state.connected"),
        )
        if len(xml[0]) > 1:
            # This is a 'show devices' op command
            firewall_instances = super(Firewall, self).refreshall_from_xml(
                xml, refresh_children=False, variables=op_vars)
            # Add system settings to firewall instances
            for fw in firewall_instances:
                entry = xml.find("entry[@name='%s']" % fw.serial)
                system = fw.find_or_create(None, device.SystemSettings)
                system.hostname = entry.findtext("hostname")
                system.ip_address = entry.findtext("ip-address")
                # Add state
                fw.state.connected = yesno(entry.findtext("connected"))
                fw.state.unsupported_version = yesno(entry.findtext("unsupported-version"))
        else:
            # This is a config command
            # For each vsys, instantiate a new firewall
            firewall_instances = []
            all_serial = xml.findall("entry")
            for entry in all_serial:
                all_vsys = entry.findall("vsys/entry")
                if all_vsys:
                    for vsys in all_vsys:
                        firewall_instances.append(Firewall(
                            serial=entry.get("name"), vsys=vsys.get("name")))
                else:
                    firewall_instances.append(Firewall(
                        serial=entry.get("name")))
        return firewall_instances

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

    def commit_device_and_network(self, sync=False, exception=False):
        return self._commit(sync=sync, exclude="device-and-network",
                            exception=exception)

    def commit_policy_and_objects(self, sync=False, exception=False):
        return self._commit(sync=sync, exclude="policy-and-objects",
                            exception=exception)

    def organize_into_vsys(self, create_vsys_objects=True, refresh_vsys=True):
        """Organizes all imported objects under the appropriate Vsys object.

        Args:
            create_vsys_objects (bool): Create the vsys objects (True) or use the ones already connected to this firewall (False).
            refresh_vsys (bool): Refresh all vsys objects' parameters before doing the reorganization or not.  This is assumed True if create_vsys_objects is True.

        """
        from pandevice import network

        # Mapping of device.Vsys params to pandevice classes.
        mapping = {
            'interface': network.Interface,
            'vlans': network.Vlan,
            'virtual_wires': network.VirtualWire,
            'virtual_routers': network.VirtualRouter,
        }

        # Optional: create the vsys objects.
        if create_vsys_objects:
            device.Vsys.refreshall(self, name_only=True)

        # Vsys to put objects into.
        available_vsys = [x for x in self.children
                          if isinstance(x, device.Vsys)]

        # Optional: refresh the vsys params.
        if create_vsys_objects or refresh_vsys:
            for x in available_vsys:
                x.refresh(refresh_children=False)

        # List of objects we need to iterate over.
        parents = self.children[:]

        # Reorganize into vsys.
        for x in itertools.chain(parents):
            # Skip device.Vsys children.
            if isinstance(x, device.Vsys):
                continue

            # Add children for later processing.
            parents.extend(x.children)

            # Check this class against the importable classes.
            for param, importable_class in mapping.items():
                if isinstance(x, importable_class):
                    # Importable class found, check if it should be moved.
                    for vsys in available_vsys:
                        if (getattr(vsys, param) is not None and
                                x.uid in getattr(vsys, param)):
                            # If its vsys isn't right, move it.
                            if x.vsys != vsys.uid:
                                x.parent.remove(x)
                                vsys.add(x)
                            break
                    else:
                        # Checked every vsys, this importable isn't in any of
                        # them (vsys is None), so move this node to be a child
                        # of the firewall.
                        if x.parent != self:
                            x.parent.remove(x)
                            self.add(x)
                    break


class FirewallState(object):

    def __init__(self):
        self.connected = None
        self.shared_policy_synced = None
        self.unsupported_version = None

    def set_shared_policy_synced(self, sync_status):
        if sync_status == "In Sync":
            self.shared_policy_synced = True
        elif sync_status == "Out of Sync":
            self.shared_policy_synced = False
        elif not sync_status:
            self.shared_policy_synced = None
        else:
            raise err.PanDeviceError("Unknown shared policy status: %s" % str(sync_status))
