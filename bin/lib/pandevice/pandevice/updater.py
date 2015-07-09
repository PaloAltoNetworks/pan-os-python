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

from pan.config import PanConfig


class Updater(object):
    """This class is instantiated by the PanDevice class as a software update subsystem"""

    def __init__(self, pandevice):
        # create a class logger
        self._logger = logging.getLogger(__name__ + "." + self.__class__.__name__)
        self.pandevice = pandevice
        self.software = {}

    def info(self):
        response = self._op('request system software info')
        self.pandevice.version = self._parse_current_version(response)
        self.software = self._parse_version_list(response)

    def check(self):
        response = self._op('request system software check')
        self.pandevice.version = self._parse_current_version(response)
        self.software = self._parse_version_list(response)

    def download(self, version, sync_to_peer=True, sync=False):
        response = self._op('request system software download sync-to-peer "%s" version "%s"' %
                            ("yes" if sync_to_peer else "no",
                             version))
        if sync:
            return self.pandevice.syncjob(response)
        else:
            return True

    def install(self, version, load_config=None, sync=False):
        response = self._op('request system software install%s version "%s"' %
                            (" load-config " + load_config if load_config is not None else "",
                             version))
        if sync:
            return self.pandevice.syncjob(response)
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
        self._logger.debug("found current entry: %s" % current_entry)
        current_version = current_entry.find("./version").text
        return current_version

    def _op(self, cmd):
        self.pandevice.xapi.op(cmd, cmd_xml=True)
        return self.pandevice.xapi.element_root
