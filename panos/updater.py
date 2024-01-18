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

from typing import Any, List, Literal, Optional, Union, cast

from pan.config import PanConfig

import panos.errors as err
from panos import PanOSVersion, getlogger, isstring

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

    def download_install(
        self,
        version: Union[str, PanOSVersion],
        load_config: Optional[str] = None,
        sync: bool = False,
    ) -> Any:
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
        # Get list of software if needed
        if not self.versions:
            self.check()
        # Get versions as StrictVersion objects
        available_versions = list(map(PanOSVersion, self.versions.keys()))
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

    def download_install_reboot(
        self,
        version: Union[str, PanOSVersion],
        load_config: Optional[str] = None,
        sync: bool = False,
    ) -> Optional[str]:
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
        target_version = PanOSVersion(str(version))
        self.download_install(target_version, load_config, sync=True)
        # Reboot the device
        self._logger.info(
            "Device %s is rebooting after upgrading to version %s. This will take a while."
            % (self.pandevice.id, version)
        )
        self.pandevice.restart()
        if sync:
            new_version: str = self.pandevice.syncreboot()
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

    def _next_upgrade_version(
        self,
        target_version: Union[PanOSVersion, Literal["latest"]],
        install_base: bool,
    ) -> PanOSVersion:
        current_version = PanOSVersion(self.pandevice.version)
        if target_version != "latest" and current_version == target_version:
            return None
        available_versions = list(map(PanOSVersion, self.versions.keys()))
        latest_version = max(available_versions)
        next_minor_version = self._next_minor_version(current_version)
        if next_minor_version not in available_versions:
            next_minor_version = None
        if install_base:
            if target_version == "latest":
                return (
                    next_minor_version
                    if next_minor_version is not None
                    else latest_version
                )
            elif self._direct_upgrade_possible(
                current_version, target_version, install_base
            ):
                # No minor upgrade needed to target
                return target_version
            elif next_minor_version is None:
                return latest_version
            else:
                return next_minor_version
        else:
            if target_version == "latest":
                if next_minor_version is None:
                    return latest_version
                else:
                    return self._latest_patch_version(
                        next_minor_version, available_versions
                    )
            elif self._direct_upgrade_possible(
                current_version, target_version, install_base
            ):
                return target_version
            else:
                # More than one minor upgrade needed to target
                return self._latest_patch_version(
                    next_minor_version, available_versions
                )

    def _current_version_is_target(
        self, target_version: Union[PanOSVersion, Literal["latest"]]
    ) -> bool:
        current_version = PanOSVersion(self.pandevice.version)
        available_versions = list(map(PanOSVersion, self.versions.keys()))
        latest_version = max(available_versions)
        if target_version == "latest" and current_version == latest_version:
            return True
        elif current_version == target_version:
            return True
        else:
            return False

    def upgrade_to_version(
        self,
        target_version: Union[str, PanOSVersion],
        dryrun: bool = False,
        install_base: bool = True,
    ) -> List[str]:
        """Upgrade to the target version, completing all intermediate upgrades.

        For example, if firewall is running version 9.0.5 and target version is 10.0.2,
        then this method will proceed through the following steps:

         - Download 9.1.0
         - Upgrade to 9.1.0 and reboot
         - Download 10.0.0
         - Upgrade to 10.0.0 and reboot (to skip this step, set `install_base` to False)
         - Download 10.0.2
         - Upgrade to 10.0.2 and reboot

        Does not account for HA pairs.

        Example:
            This shows how to upgrade a firewall to version 10.0.2. This will
            work regardless of which version the firewall is currently running::

                from panos.firewall import Firewall

                fw = Firewall("192.168.1.1", "admin", "password")
                fw.software.upgrade_to_version("10.0.2")

        Args:
            target_version (string): PAN-OS version (eg. "10.0.2") or "latest"
            dryrun (bool, optional): Log what steps would be taken, but don't
                make any changes to the live device. Defaults to False.
            install_base (bool, optional): The upgrade path will include an
                upgrade to each base image (eg. 10.0.0) before upgrade to the
                patch version. If this is False, the base image will download
                but not install.

        Raises:
            err.PanDeviceError: any problem during the upgrade process

        """
        # Get list of software if needed
        if not self.versions:
            self.check()

        # For a dry run, need to record the starting version
        starting_version = self.pandevice.version

        # Get versions as StrictVersion objects
        target_is_latest = target_version == "latest"
        target_version = (
            PanOSVersion(str(target_version)) if not target_is_latest else "latest"
        )
        current_version = PanOSVersion(self.pandevice.version)

        # Check that this is an upgrade, not a downgrade
        if current_version > target_version:
            raise err.PanDeviceError(
                "Device %s upgrade failed: Can't upgrade from %s to %s."
                % (self.pandevice.id, self.pandevice.version, target_version)
            )

        # Check if done upgrading
        if self._current_version_is_target(target_version):
            self._logger.info(
                "Device %s is running target version: %s"
                % (self.pandevice.id, current_version)
            )
            if dryrun:
                self._logger.info(
                    "NOTE: dryrun with 'latest' does not show all upgrades, as new versions are learned through the upgrade process, so results may be different than dryrun output when using 'latest'."
                )
            return [str(current_version)]

        # Determine the next version to upgrade to
        next_version = self._next_upgrade_version(target_version, install_base)

        # Download base image if needed
        if (
            not install_base
            and not self.versions[str(next_version.baseimage)]["downloaded"]
        ):
            if dryrun:
                self._logger.info(
                    "Device %s will download base image: %s"
                    % (self.pandevice.id, next_version.baseimage)
                )
            else:
                self.download(next_version.baseimage, sync=True)

        # Ensure the content pack is upgraded to the latest
        if not dryrun:
            self.pandevice.content.download_and_install_latest(sync=True)

        # Upgrade to the next version
        self._logger.info(
            "Device %s will download and upgrade to version: %s"
            % (self.pandevice.id, next_version)
        )
        if dryrun:
            self.pandevice.version = str(next_version)
        else:
            self.download_install_reboot(next_version, sync=True)
            self.check()
        result = self.upgrade_to_version(
            target_version, dryrun=dryrun, install_base=install_base
        )
        if result and dryrun:
            self.pandevice.version = starting_version
        return [str(current_version)] + result

    def _next_major_version(self, version):
        if isstring(version):
            version = PanOSVersion(version)
        next_version = PanOSVersion(str(version.major + 1) + ".0.0")
        # Account for lack of PAN-OS 7.0.0
        if next_version == "7.0.0":
            next_version = PanOSVersion("7.0.1")
        return next_version

    def _next_minor_version(self, version: Union[PanOSVersion, str]) -> PanOSVersion:
        from panos.firewall import Firewall

        version = PanOSVersion(str(version))

        # Account for 10.2.x (only release with minor version of '2')
        if version.major == 10 and version.minor == 1:
            next_version = PanOSVersion("10.2.0")
        elif version.minor > 0:
            next_version = PanOSVersion(str(version.major + 1) + ".0.0")
        # There is no PAN-OS 5.1 for firewalls, so next minor release from 5.0.x is 6.0.0.
        elif (
            version.major == 5
            and version.minor == 0
            and issubclass(type(self.pandevice), Firewall)
        ):
            next_version = PanOSVersion("6.0.0")
        else:
            next_version = PanOSVersion(str(version.major) + ".1.0")
        # Account for lack of PAN-OS 7.0.0
        if next_version == "7.0.0":
            next_version = PanOSVersion("7.0.1")
        return next_version

    def _next_patch_version(self, version):
        if isstring(version):
            version = PanOSVersion(version)
        next_version = PanOSVersion(
            str(version.major) + str(version.minor) + str(version.patch + 1)
        )
        return next_version

    def _latest_patch_version(
        self, version: Union[str, PanOSVersion], available_versions: List[PanOSVersion]
    ):
        if isstring(version):
            version = PanOSVersion(version)
        found_patch = False
        latest_patch: PanOSVersion = PanOSVersion("0.0.0")
        for v in available_versions:
            if v.major == version.major and v.minor == version.minor:
                latest_patch = max(latest_patch, v)
                found_patch = True
        return latest_patch if found_patch else None

    def _direct_upgrade_possible(
        self, current_version, target_version, install_base=True
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
        ):
            return True

        # Upgrade the minor version
        # eg. 6.0.2 -> 6.1.0
        if (
            current_version.major == target_version.major
            and current_version.minor == 0
            and target_version.minor == 1
            and (not install_base or target_version.patch == 0)
        ):
            return True

        # Upgrade the major version
        # eg. 6.1.2 -> 7.0.0
        if (
            current_version.major + 1 == target_version.major
            and current_version.minor == 1
            and target_version.minor == 0
            and (not install_base or target_version.patch == 0)
        ):
            return True

        # SPECIAL CASES

        # Upgrading a firewall from PAN-OS 5.0.x to 6.0.x
        # This is a special case because there is no PAN-OS 5.1.x
        from panos.firewall import Firewall

        if (
            current_version.major == 5
            and current_version.minor == 0
            and target_version == "6.0.0"
            and issubclass(type(self.pandevice), Firewall)
        ):
            return True

        # Upgrade from PAN-OS 10.1.x to 10.2.x
        # This is a special case because only minor release with a 2
        if (
            current_version.major == 10
            and current_version.minor == 1
            and target_version.major == 10
            and target_version.minor == 2
            and (not install_base or target_version.patch == 0)
        ):
            return True

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
