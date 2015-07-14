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

# import other parts of this pandevice package
import pandevice.base


class Panorama(pandevice.base.PanDevice):

    def __init__(self,
                 hostname,
                 api_username=None,
                 api_password=None,
                 api_key=None,
                 port=443,
                 serial=None,
                 classify_exceptions=False):
        super(Panorama, self).__init__(hostname, api_username, api_password, api_key, classify_exceptions=classify_exceptions)
        # create a class logger
        self._logger = logging.getLogger(__name__ + "." + self.__class__.__name__)

    def commit_all(self, sync=False, sync_all=True, exception=False, cmd=None):
        self._logger.debug("Commit-all initiated on device: %s" % (self.hostname,))
        return self._commit(sync=sync,
                            sync_all=sync_all,
                            commit_all=True,
                            exception=exception,
                            cmd=cmd)

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
        self._logger.debug("Set device-group to '%s'" % (devicegroup))
        if issubclass(devices.__class__, pandevice.base.PanDevice):
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

