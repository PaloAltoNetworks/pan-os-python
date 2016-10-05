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

"""Common functions used by all custom searchbar commands"""

import os
import sys
import traceback

from environment import run_by_splunk

def create_logger(in_splunk):
    if in_splunk:
        import splunk.mining.dcutils as logging
        # this logs to python.log
        logger = logging.getLogger()
    else:
        import logging
        logger = logging.getLogger()
        ch = logging.StreamHandler(sys.stdout)
        logger.addHandler(ch)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        ch.setFormatter(formatter)
    return logger
 
# Import library if script was run by Splunk
if run_by_splunk():
    import splunk.Intersplunk
    import splunk.entity as entity  # for splunk config info
    from splunk import ResourceNotFound

libpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(libpath)]
sys.path[:0] = [os.path.join(libpath, 'pan-python', 'lib')]
sys.path[:0] = [os.path.join(libpath, 'pandevice')]
try:
    import pandevice.base
except Exception as e:
    sys.exit(4)


class NoCredentialsFound(Exception):
    pass


class SplunkConnector(object):
    # This is the folder name for the app and not the app's common name (ie. "Splunk_TA_paloalto")
    APPNAME = 'Splunk_TA_paloalto'
    
    def __init__(self, session_key, logger):
        self.session_key = session_key
        self.logger = logger

    def get_firewall_credentials(self):
        """Given a splunk self.session_key returns a clear text user name and password from a splunk password container"""
        try:
            # Get all credentials
            self.logger.debug("Getting firewall credentials from Splunk")
            entities = entity.getEntities(['admin', 'passwords'], namespace=self.APPNAME, owner='nobody', sessionKey=self.session_key)
        except Exception as e:
            self.exit_with_error("Could not get %s credentials from splunk. Error: %s" % (self.APPNAME, str(e)))
        else:
            # return first set of credentials
            for i, c in entities.items():
                if c['username'] != 'wildfire_api_key':
                    return c['username'], c['clear_password']
            raise NoCredentialsFound("No credentials have been found")

    def get_wildfire_apikey(self):
        """Given a splunk self.session_key returns a clear text API Key from a splunk password container"""
        try:
            entities = entity.getEntities(['admin', 'passwords'], namespace=self.APPNAME, owner='nobody', sessionKey=self.session_key)
        except Exception as e:
            self.exit_with_error("Could not get %s credentials from splunk. Error: %s" % (self.APPNAME, str(e)))
        else:
            # return first set of credentials
            for i, c in entities.items():
                if c['username'] == 'wildfire_api_key':
                    return c['clear_password']
            self.logger.warn(
                "There are Palo Alto Networks WildFire malware events, but no WildFire API Key found, please set the API key in the Splunk_TA_paloalto Add-on set up page")
            self.exit_with_error("No Wildfire API key is set, set apikey in Add-on configuration.", log_traceback=False)

    def get_firewall_apikey(self):
        """Given a splunk self.session_key returns a clear text API Key from a splunk password container"""
        try:
            entities = entity.getEntities(['admin', 'passwords'], namespace=self.APPNAME, owner='nobody', sessionKey=self.session_key)
        except Exception as e:
            self.exit_with_error("Could not get %s credentials from splunk. Error: %s" % (self.APPNAME, str(e)))
        else:
            for i, c in entities.items():
                if c['username'] == 'firewall_api_key':
                    return c['clear_password']
            raise NoCredentialsFound

    def set_firewall_apikey(self, apikey):
        """Given a splunk self.session_key sets the firewall API key in the Splunk password store"""
        try:
            # The password cannot be modified, so it must be deleted before it can be added back.
            self.delete_firewall_apikey()
            apikey = {'name': 'firewall_api_key', 'password': apikey}
            apikey_entity = entity.Entity(['admin', 'passwords'], "firewall_api_key", namespace=self.APPNAME, owner='nobody', contents=apikey)
            entity.setEntity(apikey_entity, sessionKey=self.session_key, strictCreate=False)
        except Exception as e:
            stack = traceback.format_exc()
            self.logger.warn(stack)
            self.logger.warn("entity exception")
            self.exit_with_error("Could not set %s firewall apikey from splunk. Error: %s" % (self.APPNAME, str(e)))

    def delete_firewall_apikey(self):
        """Given a splunk self.session_key delete the firewall API key in the Splunk password store"""
        try:
            entity.deleteEntity(['admin', 'passwords'], ":firewall_api_key:", namespace=self.APPNAME, owner='nobody', sessionKey=self.session_key)
        except ResourceNotFound:
            pass
        except Exception as e:
            self.exit_with_error("Could not delete %s firewall apikey from splunk. Error: %s" % (self.APPNAME, str(e)))

    def apikey(self, hostname):
        """Login to a Palo Alto Networks device (firewall or Panorama)

        Returns:
            The API key for the firewall or Panorama
        """
        try:
            # Get the API Key for the device or Panorama if Splunk knows it
            apikey = self.get_firewall_apikey()
            self.logger.debug("API Key found in Splunk credential store")
            return apikey
        except NoCredentialsFound:
            try:
                self.logger.debug("API Key was not in Splunk credential store")
                # If Splunk doesn't know the API Key, get the username and password instead
                self.logger.debug("Getting credentials from Splunk credential store")
                fw_username, fw_password = self.get_firewall_credentials()
                # Use the username and password to determine the API key
                self.logger.debug("Getting API Key from firewall/Panorama")
                device = pandevice.base.PanDevice(hostname, fw_username, fw_password)
                apikey = device.api_key
                # Save the API key to the Splunk credential store inside the App
                self.logger.debug("Adding API Key to Splunk credential store")
                self.set_firewall_apikey(apikey)
                return apikey
            except NoCredentialsFound as e:
                self.exit_with_error("No Firewall/Panorama credentials for searchbar command. Please set the username and password in the Add-on set up page.", log_traceback=False)
            except Exception as e:
                self.exit_with_error("Unable to get apikey from firewall: %s" % str(e))

    def check_debug(self, arguments):
        # Enable debugging by passing 'debug=yes' as an argument of
        # the command on the Splunk searchbar.
        if 'debug' in arguments:
            if arguments['debug'] != "no" and arguments['debug'] != "false":
                #logger.setLevel(logging.DEBUG)
                return True
        return False

    def exit_with_error(self, e, errorcode=2, log_traceback=True):
        if log_traceback:
            self.logger.error(''.join(traceback.format_stack()))
        self.logger.error(str(e))
        if run_by_splunk():
            splunk.Intersplunk.generateErrorResults(str(e))
        sys.exit(errorcode)

    def add_firewall_cli_args(self, parser):
        # Palo Alto Networks related arguments
        fw_group = parser.add_argument_group('Palo Alto Networks')
        fw_group.add_argument('hostname', help="Hostname of firewall or Panorama")
        fw_group.add_argument('-s', '--fw-vsys', default="vsys1", help="vsys on Firewall or Panorama")
        fw_group.add_argument('-u', '--username', help="Username of firewall or Splunk")
        fw_group.add_argument('-p', '--password', help="Password of firewall or Splunk")
        fw_group.add_argument('-c', '--splunk-creds', action='store_true', help="Use firewall credentials stored in Splunk app")
        return parser
