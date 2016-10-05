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

"""Device updater handles software versions and updates for devices"""

import logging
from distutils.version import LooseVersion

from pan.config import PanConfig
import pandevice.errors as err


logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class Updater(object):
    """This class is instantiated by the PanDevice class as a software update subsystem"""

    def __init__(self, pandevice):
        # create a class logger
        self._logger = logging.getLogger(__name__ + "." + self.__class__.__name__)
        self.pandevice = pandevice
        self.versions = {}

    def _op(self, cmd):
        return self.pandevice.xapi.op(cmd, cmd_xml=True)


class SoftwareUpdater(Updater):

    def info(self):
        self._logger.debug("Device %s software updater: info" % self.pandevice.id)
        response = self._op('request system software info')
        self.pandevice.version = self._parse_current_version(response)
        self.versions = self._parse_version_list(response)

    def check(self):
        self._logger.debug("Device %s software updater: check for new versions" % self.pandevice.id)
        response = self._op('request system software check')
        self.pandevice.version = self._parse_current_version(response)
        self.versions = self._parse_version_list(response)

    def download(self, version, sync_to_peer=True, sync=False):
        self._logger.info("Device %s downloading version: %s" % (self.pandevice.id, version))
        response = self._op('request system software download sync-to-peer "%s" version "%s"' %
                            ("yes" if sync_to_peer else "no",
                             version))
        if sync:
            result = self.pandevice.syncjob(response)
            if not result['success']:
                raise err.PanDeviceError("Device %s attempt to download version %s failed: %s" %
                                         (self.pandevice.id, version, result['messages']))
            return result
        else:
            return True

    def install(self, version, load_config=None, sync=False):
        self._logger.info("Device %s installing version: %s" % (self.pandevice.id, version))
        response = self._op('request system software install%s version "%s"' %
                            (" load-config " + load_config if load_config is not None else "",
                             version))
        if sync:
            result = self.pandevice.syncjob(response)
            if not result['success']:
                raise err.PanDeviceError("Device %s attempt to install version %s failed: %s" %
                                         (self.pandevice.id, version, result['messages']))
            return result
        else:
            return True

    def _parse_version_list(self, response_element):
        all_versions = {}
        for software_version in response_element.findall(".//versions/entry"):
            # This line doesn't work correctly in pan-python < 0.7.0.
            newversion = PanConfig(software_version).python("./")
            all_versions[newversion['version']] = newversion
        return all_versions

    def _parse_current_version(self, response_element):
        current_entry = response_element.find(".//versions/entry/[current='yes']")
        current_version = current_entry.find("./version").text
        self._logger.debug("Found current version: %s" % current_version)
        return current_version

    def download_install(self, version, load_config=None, sync=False):
        if issubclass(type(version), basestring):
            version = PanOSVersion(version)
        # Get list of software if needed
        if not self.versions:
            self.check()
        # Get versions as StrictVersion objects
        available_versions = map(PanOSVersion, self.versions.keys())
        target_version = PanOSVersion(str(version))
        current_version = PanOSVersion(self.pandevice.version)

        if str(target_version) not in available_versions:
            raise err.PanDeviceError("Error upgrading to unknown version: %s" % target_version)

        # Check if already on the target version
        if current_version == target_version:
            raise err.PanDeviceError("Requested upgrade to version %s which is already running on device %s" %
                                     (target_version, self.pandevice.id))

        # Download the software upgrade
        if not self.versions[str(target_version)]['downloaded']:
            self.download(target_version, sync=True)
        # Install the software upgrade
        result = self.install(target_version, load_config=load_config, sync=sync)
        return result

    def download_install_reboot(self, version, load_config=None, sync=False):
        if issubclass(type(version), basestring):
            version = PanOSVersion(version)
        self.download_install(version, load_config, sync=True)
        # Reboot the device
        self.pandevice.restart()
        if sync:
            new_version = self.pandevice.syncreboot()
            if version != new_version:
                raise err.PanDeviceError("Attempt to upgrade to version %s failed."
                                         "Device %s is on version %s after reboot." %
                                         (version, self.pandevice.id, new_version))
            self.pandevice.version = new_version
            return new_version
        else:
            return None

    def upgrade_to_version(self, target_version, dryrun=False):
        """Upgrade to the target version, completely all intermediate upgrades

        For example, if firewall is running version 6.0.5 and target version is 7.0.2,
        then this method will proceed through the following steps:

         - Upgrade to 6.1.0 and reboot
         - Upgrade to 7.0.0 and reboot
         - Upgrade to 7.0.1 and reboot

         This method does not support HA pairs.
         """
        # Get list of software if needed
        if not self.versions:
            self.check()

        # For a dry run, need to record the starting version
        starting_version = self.pandevice.version

        # Get versions as StrictVersion objects
        available_versions = map(PanOSVersion, self.versions.keys())
        current_version = PanOSVersion(self.pandevice.version)
        latest_version = max(available_versions)
        next_minor_version = self._next_minor_version(current_version)

        # Check that this is an upgrade, not a downgrade
        if current_version > target_version:
            raise err.PanDeviceError("Device %s upgrade failed: Can't upgrade from %s to %s." %
                                     (self.pandevice.id, self.pandevice.version, target_version))

        # Determine the next version to upgrade to
        if target_version == "latest":
            next_version = min(latest_version, next_minor_version)
        elif latest_version < target_version:
            next_version = next_minor_version
        elif not self._direct_upgrade_possible(current_version, target_version):
            next_version = next_minor_version
        else:
            next_version = PanOSVersion(str(target_version))

        if next_version not in available_versions and not dryrun:
            self._logger.info("Device %s upgrading to %s, currently on %s. Checking for newer versions." %
                               (self.pandevice.id, target_version, self.pandevice.version))
            self.check()
            available_versions = map(PanOSVersion, self.versions.keys())
            latest_version = max(available_versions)

        # Check if done upgrading
        if current_version == target_version:
            self._logger.info("Device %s is running target version: %s" % (self.pandevice.id, target_version))
            return True
        elif target_version == "latest" and current_version == latest_version:
            self._logger.info("Device %s is running latest version: %s" % (self.pandevice.id, latest_version))
            if dryrun:
                self._logger.info("NOTE: dryrun with 'latest' does not show all upgrades,")
                self._logger.info("as new versions are learned through the upgrade process,")
                self._logger.info("so results may be different than dryrun output when using 'latest'.")
            return True

        # Ensure the content pack is upgraded to the latest
        self.pandevice.content.download_and_install_latest(sync=True)

        # Upgrade to the next version
        self._logger.info("Device %s will be upgraded to version: %s" % (self.pandevice.id, next_version))
        if dryrun:
            self.pandevice.version = str(next_version)
        else:
            self.download_install_reboot(next_version, sync=True)
            self.check()
        result = self.upgrade_to_version(target_version, dryrun=dryrun)
        if result and dryrun:
            self.pandevice.version = starting_version
        return result


    def _next_major_version(self, version):
        if issubclass(type(version), basestring):
            version = PanOSVersion(version)
        next_version = PanOSVersion(str(version.major+1)+".0.0")
        # Account for lack of PAN-OS 7.0.0
        if next_version == "7.0.0":
            next_version = PanOSVersion("7.0.1")
        return next_version

    def _next_minor_version(self, version):
        from pandevice.firewall import Firewall
        if issubclass(type(version), basestring):
            next_version = PanOSVersion(version)
        if version.minor == 1:
            next_version = PanOSVersion(str(version.major+1)+".0.0")
        # There is no PAN-OS 5.1 for firewalls, so next minor release from 5.0.x is 6.0.0.
        elif version.major == 5 and version.minor == 0 and issubclass(type(self.pandevice), Firewall):
            next_version = PanOSVersion("6.0.0")
        else:
            next_version = PanOSVersion(str(version.major)+".1.0")
        # Account for lack of PAN-OS 7.0.0
        if next_version == "7.0.0":
            next_version = PanOSVersion("7.0.1")
        return next_version

    def _next_patch_version(self, version):
        if issubclass(type(version), basestring):
            version = PanOSVersion(version)
        next_version = PanOSVersion(str(version.major)+str(version.minor)+str(version.patch+1))
        return next_version

    def _direct_upgrade_possible(self, current_version, target_version):
        """Check if current version can directly upgrade to target version

        :returns True if a direct upgrade is possible, False if not
        """
        if issubclass(type(current_version), basestring):
            current_version = PanOSVersion(current_version)
        if issubclass(type(target_version), basestring):
            target_version = PanOSVersion(target_version)

        # Upgrade the patch version
        # eg. 6.0.2 -> 6.0.3
        if (current_version.major == target_version.major
            and current_version.minor == current_version.minor):
            return True

        # Upgrade the minor version
        # eg. 6.0.2 -> 6.1.0
        if (current_version.major == target_version.major
            and current_version.minor == 0 and target_version.minor == 1
            and target_version.patch == 0):
            return True

        # Upgrade the major version
        # eg. 6.1.2 -> 7.0.0
        if (current_version.major+1 == target_version.major
            and current_version.minor == 1 and target_version.minor == 0
            and target_version.patch == 0):
            return True

        # Upgrading a firewall from PAN-OS 5.0.x to 6.0.x
        # This is a special case because there is no PAN-OS 5.1.x
        from pandevice.firewall import Firewall
        if (current_version.major == 5 and current_version.minor == 0
            and target_version == "6.0.0"
            and issubclass(type(self.pandevice), Firewall)):
            return True

        return False


class ContentUpdater(Updater):

    def info(self):
        response = self._op('request content upgrade info')
        self.pandevice.content_version = self._parse_current_version(response)
        self.versions = self._parse_version_list(response)

    def check(self):
        response = self._op('request content upgrade check')
        self.pandevice.content_version = self._parse_current_version(response)
        self.versions = self._parse_version_list(response)

    def download(self, version="latest", sync_to_peer=True, sync=False):
        if not self.versions:
            self.check()
        available_versions = map(PanOSVersion, self.versions.keys())
        latest_version = max(available_versions)
        if self.versions[str(latest_version)]['downloaded']:
            return
        self._logger.info("Device %s downloading content version: %s" % (self.pandevice.id, version))
        response = self._op('request content upgrade download latest sync-to-peer "%s"' %
                            "yes" if sync_to_peer else "no")
        if sync:
            result = self.pandevice.syncjob(response)
            if not result['success']:
                raise err.PanDeviceError("Device %s attempt to download content version %s failed: %s" %
                                         (self.pandevice.id, version, result['messages']))
            return result
        else:
            return True

    def install(self, version="latest", sync_to_peer=True, skip_commit=False, sync=False):
        if not self.versions:
            self.check()
        available_versions = map(PanOSVersion, self.versions.keys())
        latest_version = max(available_versions)
        if self.versions[str(latest_version)]['current']:
            return
        self._logger.info("Device %s installing content version: %s" % (self.pandevice.id, version))
        op = ('request content upgrade install commit "%s" sync-to-peer "%s" version "%s"' %
              ("no" if skip_commit else "yes",
               "yes" if sync_to_peer else "no",
               version))
        response = self._op(op)
        if sync:
            result = self.pandevice.syncjob(response)
            if not result['success']:
                raise err.PanDeviceError("Device %s attempt to install content version %s failed: %s" %
                                         (self.pandevice.id, version, result['messages']))
            return result
        else:
            return True

    def download_and_install_latest(self, sync=False):
        self.download(sync=sync)
        self.install(sync=sync)

    def downgrade(self, sync=False):
        response = self._op('request content downgrade install "previous"')
        if sync:
            return self.pandevice.syncjob(response)
        else:
            return True

    def _parse_version_list(self, response_element):
        all_versions = {}
        for software_version in response_element.findall(".//content-updates/entry"):
            # This line doesn't work correctly in pan-python < 0.7.0.
            newversion = PanConfig(software_version).python("./")
            all_versions[newversion['version']] = newversion
        return all_versions

    def _parse_current_version(self, response_element):
        current_entry = response_element.find(".//content-updates/entry/[current='yes']")
        if current_entry is None:
            return
        current_version = current_entry.find("./version").text
        self._logger.debug("Found current version: %s" % current_version)
        return current_version

    def download_install(self, version="latest", sync_to_peer=False, skip_commit=False, sync=False):
        # Get list of software if needed
        if not self.versions:
            self.check()
        # Download the software upgrade
        self.download(version, sync_to_peer=sync_to_peer, sync=True)
        # Install the software upgrade
        self.install(version, sync_to_peer=sync_to_peer, skip_commit=skip_commit, sync=sync)


class PanOSVersion(LooseVersion):
    """LooseVersion with convenience properties to access version components"""
    @property
    def major(self):
        return self.version[0]

    @property
    def minor(self):
        return self.version[1]

    @property
    def patch(self):
        try:
            patch = self.version[2]
        except KeyError:
            patch = 0
        return patch

    @property
    def prerelease(self):
        try:
            prerelease = "".join(map(self.version[4:6]))
        except KeyError:
            prerelease = None
        return prerelease

    @property
    def prerelease_type(self):
        try:
            prerelease_type = self.version[4]
        except KeyError:
            prerelease_type = None
        return prerelease_type

    @property
    def prerelease_num(self):
        try:
            prerelease_num = self.version[5]
        except KeyError:
            prerelease_num = None
        return prerelease_num
