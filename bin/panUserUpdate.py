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

"""Update users on the firewall from logs in Splunk

About this script
-----------------
User-ID is a mechanism in the firewall that maps users to IP addresses.
These User to IP mappings can be updated using many methods including from
Active Directory or by sending syslogs to a firewall from a Radius or other
authentication server.

Many organizations send authentication logs to Splunk, so it is natural for
Splunk to communicate these authentication events to the firewalls so their
User to IP mappings are always up-to-date.

There are two methods to synchronize authentication events from Splunk to the firewall:

  Method 1:  Forward logs from Splunk to the User-ID firewall.

  Method 2:  Use this script to update the firewall using its API.

Method 1 is preferred because it is more efficient.  However, Method 2 is
useful in cases where the user and the IP are not in the same logs. Splunk
can correlate the user to the IP before passing the mapping to the firewall
via API.

This script supports connection to a firewall or to Panorama.
"""


#########################################################
# Do NOT modify anything below this line unless you are
# certain of the ramifications of the changes
#########################################################

import sys  # for system params and sys.exit()
import os


libpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(libpath, 'lib')]
import common
import environment

logger = common.logging.getLogger().getChild('panUserUpdate')

try:
    if environment.run_by_splunk():
        import splunk.Intersplunk  # so you can interact with Splunk
        import splunk.entity as entity  # for splunk config info

    libpath = os.path.dirname(os.path.abspath(__file__))
    sys.path[:0] = [os.path.join(libpath, 'lib')]
    sys.path[:0] = [os.path.join(libpath, 'lib', 'pan-python', 'lib')]
    sys.path[:0] = [os.path.join(libpath, 'lib', 'pandevice')]
    import pandevice
    from pandevice.panorama import Panorama
    from pandevice.firewall import Firewall
    import pan.xapi

    from common import log

except Exception as e:
    # Handle exception to produce logs to python.log
    common.exit_with_error(e)


def main_splunk():
    # Get arguments
    args, kwargs = splunk.Intersplunk.getKeywordsAndOptions()

    # Enable debugging by passing 'debug=yes' as an argument of
    # the command on the Splunk searchbar.

    debug = common.check_debug(kwargs)

    # kwargs contains important parameters.
    # parameters from splunk searchbar include:
    #   action
    #   device
    #   panorama
    #   serial
    #   vsys
    #   user_field
    #   ip_field
    #   debug

    # Verify required args were passed to command
    log(debug, "Determining if required arguments are present")
    if 'device' not in kwargs and 'panorama' not in kwargs:
        common.exit_with_error("Missing required command argument: device or panorama", 3)
    if 'panorama' in kwargs and 'serial' not in kwargs:
        common.exit_with_error("Found 'panorama' arguments, but missing 'serial' argument", 3)

    # Assign defaults to fields that aren't specified
    action = kwargs['action'] if 'action' in kwargs else "login"
    vsys = kwargs['vsys'] if 'vsys' in kwargs else "vsys1"
    ip_field = kwargs['ip_field'] if 'ip_field' in kwargs else "src_ip"
    user_field = kwargs['user_field'] if 'user_field' in kwargs else "user"

    # Determine if device hostname or serial was provided as argument or should be pulled from entries
    log(debug, "Determining how firewalls should be contacted based on arguments")
    use_panorama = False
    hostname = None
    serial = None
    if "device" in kwargs:
        hostname = kwargs['device']
    elif "panorama" in kwargs:
        use_panorama = True
        hostname = kwargs['panorama']
        serial = kwargs['serial']
    else:
        common.exit_with_error("Missing required command argument: device or panorama", 3)
    log(debug, "Use Panorama: %s" % use_panorama)
    log(debug, "VSys: %s" % vsys)
    log(debug, "Hostname: %s" % hostname)
    if use_panorama and serial is not None:
        log(debug, "Device Serial: %s" % serial)

    # Results contains the data from the search results and settings
    # contains the sessionKey that we can use to talk to Splunk
    results, unused1, settings = splunk.Intersplunk.getOrganizedResults()
    # Get the sessionKey
    sessionKey = settings['sessionKey']

    log(debug, "Begin get API key")
    # Get the API key from the Splunk store or from the device at hostname if no apikey is stored
    apikey = common.apikey(sessionKey, hostname, debug)

    # Create the connection to the firewall or Panorama
    panorama = None
    if use_panorama:
        # For Panorama, create the Panorama object, and the firewall object
        panorama = Panorama(hostname, api_key=apikey)
        firewall = Firewall(panorama=panorama, serial=serial, vsys=vsys)
        firewall.userid.batch_start()
    else:
        # No Panorama, so just create the firewall object
        firewall = Firewall(hostname, api_key=apikey, vsys=vsys)
        firewall.userid.batch_start()

    # Collect all the ip addresses and users into firewall batch requests
    for result in results:

        ## Find the user (if a user_field was specified)

        try:
            this_user = result[user_field]
        except KeyError as e:
            result['status'] = "ERROR: Unable to determine user from field: %s" % user_field
            continue

        ## Find the IP

        try:
            this_ip = result[ip_field]
        except KeyError as e:
            result['status'] = "ERROR: Unable to determine ip from field: %s" % ip_field

        ## Create a request in the batch user-id update for the firewall
        ## No API call to the firewall happens until all batch requests are created.

        if action == "login":
            log(debug, "Login event on firewall %s: %s - %s" % (firewall, this_ip, this_user))
            firewall.userid.login(this_user, this_ip)
        else:
            log(debug, "Logout event on firewall %s: %s - %s" % (firewall, this_ip, this_user))
            firewall.userid.logout(this_user, this_ip)

        result['status'] = "Submitted successfully"

    ## Make the API calls to the User-ID API of each firewall

    try:
        firewall.userid.batch_end()

    except pan.xapi.PanXapiError as e:
        common.exit_with_error(str(e))

    except Exception as e:
        common.exit_with_error(str(e))

    # output results
    splunk.Intersplunk.outputResults(results)


def main_cli():
    raise NotImplementedError


if __name__ == "__main__":
    if environment.run_by_splunk():
        try:
            main_splunk()
        except Exception as e:
            common.exit_with_error(e)
    else:
        main_cli()
