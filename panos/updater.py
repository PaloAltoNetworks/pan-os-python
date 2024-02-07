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


"""Device updater handles software versions and updates for devices"""

import time

from pan.config import PanConfig
from pan.xapi import PanXapiError

import panos.errors as err
from panos import PanOSVersion, getlogger, isstring
from panos.errors import PanDeviceXapiError, PanURLError

logger = getlogger(__name__)


class Updater(object):
    """This class is instantiated by the PanDevice class as a software update subsystem"""

    def __init__(self, pandevice):
        # create a class logger
        self._logger = getlogger(__name__ + "." + self.__class__.__name__)
        self.pandevice = pandevice
        self.versions = {}

    def _op(self, cmd):
        return self.pandevice.xapi.op(cmd, cmd_xml=True)


class SoftwareUpdater(Updater):
    def info(self):
        """Fetch version list from live device.

        Synchronizes this current updater state with the live device.

        """
        self._logger.debug("Device %s software updater: info" % self.pandevice.id)
        response = self._op("request system software info")
        self.pandevice.version = self._parse_current_version(response)
        self.versions = self._parse_version_list(response)

    def check(self):
        """Trigger PAN-OS to get versions, then synchronize this object instance.

        First, PAN-OS will reach out to the upgrade servers to get the list of
        all version that can be upgraded to. Then synchronizes this current
        updater state with the live device.

        """
        self._logger.debug(
            "Device %s software updater: check for new versions" % self.pandevice.id
        )
        response = self._op("request system software check")
        self.pandevice.version = self._parse_current_version(response)
        self.versions = self._parse_version_list(response)

    def download(self, version, sync_to_peer=True, sync=False):
        """PAN-OS downloads the requested version.

        Args:
            version (string): PAN-OS version (eg. "10.0.2")
            sync_to_peer (bool, optional): Send a copy to HA peer. Defaults to True.
            sync (bool, optional): Run job synchronously and return the result. Defaults to False.

        Raises:
            err.PanDeviceError: on unsuccessful download

        Returns:
            If sync, returns result of PAN-OS download job

        """
        self._logger.info(
            "Device %s downloading version: %s" % (self.pandevice.id, version)
        )
        response = self._op(
            'request system software download sync-to-peer "%s" version "%s"'
            % ("yes" if sync_to_peer else "no", version)
        )
        if sync:
            result = self.pandevice.syncjob(response)
            if not result["success"]:
                raise err.PanDeviceError(
                    "Device %s attempt to download version %s failed: %s"
                    % (self.pandevice.id, version, result["messages"])
                )
            return result
        else:
            return True

    def install(self, version, load_config=None, sync=False):
        """Install the requested PAN-OS version.

        Does not download the software or perform the reboot required after
        installation.

        Args:
            version (string): PAN-OS version (eg. "10.0.2")
            load_config (string, optional): Configuration to use for booting new software. Defaults to None.
            sync (bool, optional): Run job synchronously and return the result. Defaults to False.

        Raises:
            err.PanDeviceError: on unsuccessful install

        Returns:
            If sync, returns result of PAN-OS install job

        """
        self._logger.info(
            "Device %s installing version: %s" % (self.pandevice.id, version)
        )
        response = self._op(
            'request system software install %s version "%s"'
            % (
                'load-config "{0}"'.format(load_config) if load_config else "",
                version,
            )
        )
        if sync:
            result = self.pandevice.syncjob(response)
            if not result["success"]:
                raise err.PanDeviceError(
                    "Device %s attempt to install version %s failed: %s"
                    % (self.pandevice.id, version, result["messages"])
                )
            return result
        else:
            return True

    def _parse_version_list(self, response_element):
        all_versions = {}
        for software_version in response_element.findall(".//versions/entry"):
            # This line doesn't work correctly in pan-python < 0.7.0.
            newversion = PanConfig(software_version).python("./")
            all_versions[newversion["version"]] = newversion
        return all_versions

    def _parse_current_version(self, response_element):
        current_entry = response_element.find(".//versions/entry/[current='yes']")
        current_version = current_entry.find("./version").text
        self._logger.debug("Found current version: %s" % current_version)
        return current_version

    def download_install(self, version, load_config=None, sync=False):
        """Download and install the requested PAN-OS version.

        Like a combinations of the ``check()``, ``download()``, and
        ``install()`` methods, but with some additional checks. For example, it
        will not act if the requested version is already running, and it will
        skip to the install if it is already downloaded.

        Does not perform the required reboot after the install.

        Args:
            version (string): PAN-OS version (eg. "10.0.2")
            load_config (string, optional): Configuration to use for booting new software. Defaults to None.
            sync (bool, optional): Run jobs synchronously and return the result. Defaults to False.

        Raises:
            err.PanDeviceError: problem found in pre-download checks

        Returns:
            If sync, returns result of PAN-OS install job

        """
        if isstring(version):
            version = PanOSVersion(version)
        # Get list of software if needed
        if not self.versions:
            self.check()
        # Get versions as StrictVersion objects
        available_versions = map(PanOSVersion, self.versions.keys())
        target_version = PanOSVersion(str(version))
        current_version = PanOSVersion(self.pandevice.version)

        if str(target_version) not in available_versions:
            raise err.PanDeviceError(
                "Error upgrading to unknown version: %s" % target_version
            )

        # Check if already on the target version
        if current_version == target_version:
            raise err.PanDeviceError(
                "Requested upgrade to version %s which is already running on device %s"
                % (target_version, self.pandevice.id)
            )

        # Download the software upgrade
        if not self.versions[str(target_version)]["downloaded"]:
            self.download(target_version, sync=True)
        # Install the software upgrade
        result = self.install(target_version, load_config=load_config, sync=sync)
        return result

    def download_install_reboot(self, version, load_config=None, sync=False):
        """Download and install the requested PAN-OS version, then reboot.

        Like a combinations of the ``check()``, ``download()``, and
        ``install()`` methods with a reboot at the end. It has additional
        checks. For example, it will not act if the requested version is already
        running, and it will skip to the install if it is already downloaded.

        Args:
            version (string): PAN-OS version (eg. "10.0.2")
            load_config (string, optional): Configuration to use for booting new software. Defaults to None.
            sync (bool, optional): Run jobs synchronously and return the result. Defaults to False.

        Raises:
            err.PanDeviceError: problem found in pre-download checks or after reboot

        """
        if isstring(version):
            version = PanOSVersion(version)
        self.download_install(version, load_config, sync=True)
        # Reboot the device
        self._logger.info(
            "Device %s is rebooting after upgrading to version  %s. This will take a while."
            % (self.pandevice.id, version)
        )
        self.pandevice.restart()
        if sync:
            new_version = self.pandevice.syncreboot()
            if version != new_version:
                raise err.PanDeviceError(
                    "Attempt to upgrade to version %s failed."
                    "Device %s is on version %s after reboot."
                    % (version, self.pandevice.id, new_version)
                )
            self.pandevice.version = new_version
            return new_version
        else:
            return None

    def upgrade_to_version(self, target_version, dryrun=False):
        """Upgrade to the target version, completing all intermediate upgrades.

        For example, if firewall is running version 9.0.5 and target version is 10.0.2,
        then this method will proceed through the following steps:

         - Upgrade to 9.1.0 and reboot
         - Upgrade to 10.0.0 and reboot
         - Upgrade to 10.0.2 and reboot

        Does not account for HA pairs.

        Example:
            This shows how to upgrade a firewall to version 10.0.2. This will
            work regardless of which version the firewall is currently running::

                from panos.firewall import Firewall

                fw = Firewall("10.0.0.5", "admin", "password")
                fw.software.upgrade_to_version("10.0.2")

        Args:
            target_version (string): PAN-OS version (eg. "10.0.2") or "latest"
            dryrun (bool, optional): Log what steps would be taken, but don't
                make any changes to the live device. Defaults to False.

        Raises:
            err.PanDeviceError: any problem during the upgrade process

        """
        # Given this function is called repeatedly between upgrade and
        # reboot cycles, ensure the device is ready before attempting
        # to continue with further checking and upgrading
        self.pandevice.is_ready()

        # Get list of software if needed
        if not self.versions:
            self.check()

        # For a dry run, need to record the starting version
        starting_version = self.pandevice.version

        # Get versions as StrictVersion objects
        available_versions = map(PanOSVersion, self.versions.keys())
        current_version = PanOSVersion(self.pandevice.version)
        latest_version = max(available_versions)
        next_minor_version = self._next_minor_version(
            current_version, self.versions.keys()
        )
        print(
            "current ver:"
            + str(current_version.major)
            + "."
            + str(current_version.minor)
            + "."
            + str(current_version.patch)
        )
        print("target ver:" + target_version)
        print(
            "next_minor_version:"
            + str(next_minor_version.major)
            + "."
            + str(next_minor_version.minor)
            + "."
            + str(next_minor_version.patch)
        )

        # Check if done upgrading
        if current_version == target_version:
            self._logger.info(
                "Device %s is running target version: %s"
                % (self.pandevice.id, target_version)
            )
            return True

        # Check that this is an upgrade, not a downgrade
        if current_version > target_version:
            raise err.PanDeviceError(
                "Device %s upgrade failed: Can't upgrade from %s to %s."
                % (self.pandevice.id, self.pandevice.version, target_version)
            )

        # Determine the next version to upgrade to
        if target_version == "latest":
            print("latest")
            next_version = min(latest_version, next_minor_version)
        elif latest_version < target_version:
            print("go to next minor")
            next_version = next_minor_version
        elif not self._direct_upgrade_possible(
            current_version, target_version, self.versions.keys()
        ):
            print("direct not possible")
            next_version = next_minor_version
        else:
            print("lgtm")
            next_version = PanOSVersion(str(target_version))
        print(
            "next_version:"
            + str(next_version.major)
            + "."
            + str(next_version.minor)
            + "."
            + str(next_version.patch)
        )

        if str(next_version) not in self.versions.keys() and not dryrun:
            self._logger.info(
                "Device %s upgrading to %s, currently on %s. Checking for newer versions."
                % (self.pandevice.id, target_version, self.pandevice.version)
            )
            self.check()
            available_versions = map(PanOSVersion, self.versions.keys())
            latest_version = max(available_versions)

        # Check if done upgrading
        if current_version == target_version:
            self._logger.info(
                "Device %s is running target version: %s"
                % (self.pandevice.id, target_version)
            )
            return True
        elif target_version == "latest" and current_version == latest_version:
            self._logger.info(
                "Device %s is running latest version: %s"
                % (self.pandevice.id, latest_version)
            )
            if dryrun:
                self._logger.info(
                    "NOTE: dryrun with 'latest' does not show all upgrades,"
                )
                self._logger.info(
                    "as new versions are learned through the upgrade process,"
                )
                self._logger.info(
                    "so results may be different than dryrun output when using 'latest'."
                )
            return True

        # Ensure the content pack is upgraded to the latest
        self.pandevice.content.download_and_install_latest(sync=True)

        # Upgrade to the next version
        self._logger.info(
            "Device %s will be upgraded to version: %s"
            % (self.pandevice.id, next_version)
        )
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
        if isstring(version):
            version = PanOSVersion(version)
        next_version = PanOSVersion(str(version.major + 1) + ".0.0")
        # Account for lack of PAN-OS 7.0.0
        if next_version == "7.0.0":
            next_version = PanOSVersion("7.0.1")
        return next_version

    def _next_minor_version(self, version, available_version_list):
        # If version parameter is a string, convert to a PanOSVersion object
        if isstring(version):
            version = PanOSVersion(version)

        # Initial values before iterating over list of available versions
        next_minor_found = False
        next_minor_patch_number = 999

        # Create a map or PanOSVersion objects to represent all the
        # available versions the device has reported, and iterate
        available_versions = map(PanOSVersion, available_version_list)
        for available_version in available_versions:
            if (
                available_version.major == version.major
                and available_version.minor == (version.minor + 1)
            ):
                # We found a newer minor version on the current major version
                # Examples: 9.1 from 9.0, 10.2 from 10.1
                next_minor_found = True

                if available_version.patch < next_minor_patch_number:
                    # Looking for the lowest patch version of this newer
                    # minor version
                    next_minor_patch_number = available_version.patch
                    next_version = available_version

        if not next_minor_found:
            # We didn't find a newer minor version for the current major
            # version, so now check for a newer major version, set initial
            # values before iterating over available values
            next_major_found = False
            next_major_number = 999
            next_minor_number = 999
            next_patch_number = 999

            # Create a map or PanOSVersion objects to represent all the
            # available versions the device has reported, and iterate
            available_versions = map(PanOSVersion, available_version_list)
            for available_version in available_versions:
                if available_version.major == (version.major + 1):
                    # Found a newer minor version of the current major version
                    # Examples: 9.0 from 8.1, 10.0 from 9.1, 11.0 from 10.2
                    next_major_found = True
                    next_major_number = available_version.major

                    if available_version.minor < next_minor_number:
                        # Looking for the lowest minor version of this newer
                        # major version
                        next_minor_number = available_version.minor
                        next_patch_number = 999
                    if (
                        available_version.minor == next_minor_number
                        and available_version.patch < next_patch_number
                    ):
                        # Looking for the lowest patch version of the current
                        # lowest minor version of this newer major version
                        next_patch_number = available_version.patch

            # Create the return object
            next_version = PanOSVersion(
                str(next_major_number)
                + "."
                + str(next_minor_number)
                + "."
                + str(next_patch_number)
            )

            # If there were no newer minor or major version, return the
            # current version
            if not next_minor_found and not next_major_found:
                next_version = version

        return next_version

    def _next_patch_version(self, version):
        if isstring(version):
            version = PanOSVersion(version)
        next_version = PanOSVersion(
            str(version.major) + str(version.minor) + str(version.patch + 1)
        )
        return next_version

    def _direct_upgrade_possible(
        self, current_version, target_version, available_version_list
    ):
        """Check if current version can directly upgrade to target version

        :returns True if a direct upgrade is possible, False if not

        """
        if isstring(current_version):
            current_version = PanOSVersion(current_version)
        if isstring(target_version):
            target_version = PanOSVersion(target_version)

        # Upgrade the patch version
        # eg. 6.0.2 -> 6.0.3
        if (
            current_version.major == target_version.major
            and current_version.minor == target_version.minor
            and (
                current_version.patch < target_version.patch
                or (
                    current_version.patch == target_version.patch
                    and current_version.subrelease_num < target_version.subrelease_num
                )
            )
        ):
            print(
                "patch upgrade: "
                + str(current_version.major)
                + "."
                + str(current_version.minor)
                + "."
                + str(current_version.patch)
                + " to "
                + str(target_version.major)
                + "."
                + str(target_version.minor)
                + "."
                + str(target_version.patch)
            )
            return True

        # Upgrade the minor version
        # eg. 6.0.2 -> 6.1.0
        for available_version in available_version_list:
            # First check if there is a newer minor
            # Example: 10.0 to 10.1, 10.1 to 10.2, etc
            # If so, this becomes the direct upgrade
            # If not, the next major is the direct upgrade
            if (
                # Search all the available versions to see if there is a newer
                # minor of this major version, and if the target matches
                # the newer minor version
                # Example 10.1.something to 10.2.lowest
                PanOSVersion(available_version).major == current_version.major
                and PanOSVersion(available_version).minor == current_version.minor + 1
                and PanOSVersion(available_version).major == target_version.major
                and PanOSVersion(available_version).minor == target_version.minor
            ):
                # Check if there is a lower patch version of the proposed minor upgrade
                for checking_version in available_version_list:
                    if (
                        PanOSVersion(checking_version).major == target_version.major
                        and PanOSVersion(checking_version).minor == target_version.minor
                        and PanOSVersion(checking_version).patch < target_version.patch
                    ):
                        print("version that's lower:" + checking_version)
                        print(
                            "not direct, minor upgrade must go to lowest patch version first: "
                            + str(current_version.major)
                            + "."
                            + str(current_version.minor)
                            + "."
                            + str(current_version.patch)
                            + " to "
                            + str(target_version.major)
                            + "."
                            + str(target_version.minor)
                            + "."
                            + str(target_version.patch)
                        )
                        return False
                print(
                    "upgrade is minor: "
                    + str(current_version.major)
                    + "."
                    + str(current_version.minor)
                    + "."
                    + str(current_version.patch)
                    + " to "
                    + str(target_version.major)
                    + "."
                    + str(target_version.minor)
                    + "."
                    + str(target_version.patch)
                )
                return True
            elif (
                # Search all the available versions, to see if user is trying a
                # major upgrade when there is a newer minor of this major version,
                # because that would not be a direct upgrade
                # Example 10.1 to 11.0 is attempting to skip 10.2
                target_version.major > current_version.major
                and PanOSVersion(available_version).major == current_version.major
                and PanOSVersion(available_version).minor > current_version.minor
            ):
                print(
                    "not direct, intermediate minor being skipped: "
                    + str(current_version.major)
                    + "."
                    + str(current_version.minor)
                    + "."
                    + str(current_version.patch)
                    + " to "
                    + str(target_version.major)
                    + "."
                    + str(target_version.minor)
                    + "."
                    + str(target_version.patch)
                )
                return False

        # Upgrade the major version
        # eg. 6.1.2 -> 7.0.0
        if (
            # Having checked above that there is no newer minor for
            # the current major, just check that we're moving to the
            # next major version
            current_version.major + 1 == target_version.major
            and target_version.minor == 0
        ):
            # Collect all the available minor versions in the next
            # major version
            minors_in_next_major = []
            for available_version in available_version_list:
                if (
                    PanOSVersion(available_version).major == target_version.major
                    and PanOSVersion(available_version).minor >= target_version.minor
                ):
                    minors_in_next_major.append(available_version)
            if len(minors_in_next_major) == 0:
                print(
                    "no direct upgrade earlier: "
                    + str(current_version.major)
                    + "."
                    + str(current_version.minor)
                    + "."
                    + str(current_version.patch)
                    + " to "
                    + str(target_version.major)
                    + "."
                    + str(target_version.minor)
                    + "."
                    + str(target_version.patch)
                )
                return False

            # Create a map of PanOSVersion objects so we can use min()
            minor_vers_in_next_major = map(PanOSVersion, minors_in_next_major)

            if min(minor_vers_in_next_major) == target_version:
                # Ensures the attempted major upgrade is targeting the
                # lowest minor version available, to cover cases like
                # 7.0.0 being pulled
                print(
                    "major upgrade: "
                    + str(current_version.major)
                    + "."
                    + str(current_version.minor)
                    + "."
                    + str(current_version.patch)
                    + " to "
                    + str(target_version.major)
                    + "."
                    + str(target_version.minor)
                    + "."
                    + str(target_version.patch)
                )
                return True
            else:
                # Whilst the upgrade is valid in theory, target version
                # was not the lowest minor version of the next major version
                # as observed in the available versions
                print("New failure condition")
                return False

        # Upgrading a firewall from PAN-OS 5.0.x to 6.0.x
        # This is a special case because there is no PAN-OS 5.1.x
        from panos.firewall import Firewall

        if (
            current_version.major == 5
            and current_version.minor == 0
            and target_version == "6.0.0"
            and issubclass(type(self.pandevice), Firewall)
        ):
            print(
                "major upgrade 5x case: "
                + str(current_version.major)
                + "."
                + str(current_version.minor)
                + "."
                + str(current_version.patch)
                + " to "
                + str(target_version.major)
                + "."
                + str(target_version.minor)
                + "."
                + str(target_version.patch)
            )
            return True

        print(
            "no direct upgrade: "
            + str(current_version.major)
            + "."
            + str(current_version.minor)
            + "."
            + str(current_version.patch)
            + " to "
            + str(target_version.major)
            + "."
            + str(target_version.minor)
            + "."
            + str(target_version.patch)
        )
        return False


class ContentUpdater(Updater):
    def info(self):
        """Fetch version list from live device.

        Synchronizes this current updater state with the live device.

        """
        response = self._op("request content upgrade info")
        self.pandevice.content_version = self._parse_current_version(response)
        self.versions = self._parse_version_list(response)

    def check(self):
        """Trigger PAN-OS to get versions, then synchronize this object instance.

        First, PAN-OS will reach out to the upgrade servers to get the list of
        all version that can be upgraded to. Then synchronizes this current
        updater state with the live device.

        """
        response = self._op("request content upgrade check")
        self.pandevice.content_version = self._parse_current_version(response)
        self.versions = self._parse_version_list(response)

    def download(self, sync_to_peer=None, sync=False):
        """Download the latest content version.

        Args:
            sync_to_peer (bool, optional): Send a copy to HA peer. Defaults to None.
            sync (bool, optional): Run jobs synchronously and return the result. Defaults to False.

        Raises:
            err.PanDeviceError: on unsuccessful download

        Returns:
            If sync, returns result of download job

        """
        if not self.versions:
            self.check()
        available_versions = map(PanOSVersion, self.versions.keys())
        latest_version = max(available_versions)
        if self.versions[str(latest_version)]["downloaded"]:
            return
        self._logger.info(
            "Device %s downloading content version: %s"
            % (self.pandevice.id, latest_version)
        )
        if sync_to_peer is None:
            sync_to_peer_text = ""
        elif sync_to_peer:
            sync_to_peer_text = ' "" sync-to-peer "yes"'
        else:
            sync_to_peer_text = ' "" sync-to-peer "no"'
        command = "request content upgrade download latest{0}".format(sync_to_peer_text)
        response = self._op(command)
        if sync:
            result = self.pandevice.syncjob(response)
            if not result["success"]:
                raise err.PanDeviceError(
                    "Device %s attempt to download content version %s failed: %s"
                    % (self.pandevice.id, latest_version, result["messages"])
                )
            return result
        else:
            return True

    def install(
        self, version="latest", sync_to_peer=True, skip_commit=False, sync=False
    ):
        """Install the requested content version.

        Args:
            version (string): Content version (eg. "8357-6464"). Defaults to "latest".
            sync_to_peer (bool, optional): Send a copy to HA peer. Defaults to True.
            skip_commit (bool, optional): Do not perform a commit after install. Defaults to False.
            sync (bool, optional): Run jobs synchronously and return the result. Defaults to False.

        Raises:
            err.PanDeviceError: on unsuccessful install

        Returns:
            If sync, returns result of install job

        """
        if not self.versions:
            self.check()
        available_versions = map(PanOSVersion, self.versions.keys())
        latest_version = max(available_versions)
        if self.versions[str(latest_version)]["current"]:
            return
        self._logger.info(
            "Device %s installing content version: %s" % (self.pandevice.id, version)
        )
        op = (
            'request content upgrade install commit "%s" sync-to-peer "%s" version "%s"'
            % ("no" if skip_commit else "yes", "yes" if sync_to_peer else "no", version)
        )
        response = self._op(op)
        if sync:
            result = self.pandevice.syncjob(response)
            if not result["success"]:
                raise err.PanDeviceError(
                    "Device %s attempt to install content version %s failed: %s"
                    % (self.pandevice.id, version, result["messages"])
                )
            return result
        else:
            return True

    def download_and_install_latest(self, sync=False):
        self.download(sync=sync)
        self.install(sync=sync)

    def downgrade(self, sync=False):
        """Return to the previous content version.

        Args:
            sync (bool, optional): Run jobs synchronously and return the result. Defaults to False.

        Returns:
            If sync, returns result of install job

        """
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
            all_versions[newversion["version"]] = newversion
        return all_versions

    def _parse_current_version(self, response_element):
        current_entry = response_element.find(
            ".//content-updates/entry/[current='yes']"
        )
        if current_entry is None:
            return
        current_version = current_entry.find("./version").text
        self._logger.debug("Found current version: %s" % current_version)
        return current_version

    def download_install(
        self, version="latest", sync_to_peer=False, skip_commit=False, sync=False
    ):
        """Download and install the requested content version.

        Like a combinations of the ``check()``, ``download()``, and
        ``install()`` methods.

        Args:
            version (string): Content version (eg. "8357-6464"). Defaults to "latest".
            sync_to_peer (bool, optional): Send a copy to HA peer. Defaults to False.
            skip_commit (bool, optional): Do not perform a commit after install. Defaults to False.
            sync (bool, optional): Run jobs synchronously and return the result. Defaults to False.

        """
        # Get list of software if needed
        if not self.versions:
            self.check()
        # Download the software upgrade
        self.download(sync_to_peer=sync_to_peer, sync=True)
        # Install the software upgrade
        self.install(
            version, sync_to_peer=sync_to_peer, skip_commit=skip_commit, sync=sync
        )
