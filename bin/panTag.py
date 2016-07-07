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

"""Device updater handles software versions and updates for devices

About this script
-----------------
Given an IP address, tags or identifies the ip address in PAN-OS.
Behavior in PAN-OS 6.0 and higher:
  IP address is tagged. IP's can have multiple tags. Tags are
  referenced in Dynamic Address Groups. Boolean logic (AND/OR)
  can be used in Dynamic Address Groups to filter ip's based on tags
Behavior in PAN-OS 5.1 and lower:
  IP address is mapped to an identifier. Only one identifier
  per IP address. The identifier associates the IP with a single
  Dynamic Address Object in PAN-OS.

The script assumes that you have firewall policy setup that blocks
traffic for a given dynamic address group

It is important to recognize that this script does NOT modify a firewall rule!
It is only tagging IP addresses with metadata so that the existing firewall
policy can act accordingly.

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

logger = common.logging.getLogger().getChild('panTag')
#logger.setLevel(pan_common.logging.INFO)

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

# Default fields that contain IP addresses and should be tagged if they exist
IP_FIELDS = ['src_ip', 'dest_ip', 'ip']


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
    #   tag
    #   tag_field
    #   ip_field
    #   debug

    # Verify required args were passed to command
    log(debug, "Determining if required arguments are present")
    if 'device' not in kwargs and 'panorama' not in kwargs:
        common.exit_with_error("Missing required command argument: device or panorama", 3)
    if 'tag' not in kwargs and 'tag_field' not in kwargs:
        common.exit_with_error("Missing required command argument: tag or tag_field", 3)

    # Assign defaults to fields that aren't specified
    action = kwargs['action'] if 'action' in kwargs else "add"
    vsys = kwargs['vsys'] if 'vsys' in kwargs else None
    ip_field = kwargs['ip_field'] if 'ip_field' in kwargs else "src_ip"
    # Support 'field' argument (legacy syntax)
    if 'field' in kwargs and not 'ip_field' in kwargs:
        ip_field = kwargs['field']
    tag = kwargs['tag'] if 'tag' in kwargs else None
    tag_field = kwargs['tag_field'] if 'tag_field' in kwargs else None

    # Determine if device hostname or serial was provided as argument or should be pulled from entries
    log(debug, "Determining how firewalls should be contacted based on arguments")
    use_panorama = False
    hostname = None
    serial = None
    if "device" in kwargs:
        hostname = kwargs['device']
        if vsys is None:
            vsys = "vsys1"
    elif "panorama" in kwargs:
        use_panorama = True
        hostname = kwargs['panorama']
        if "serial" in kwargs:
            serial = kwargs['serial']
            if vsys is None:
                vsys = "vsys1"
    else:
        common.exit_with_error("Missing required command argument: device or panorama", 3)
    log(debug, "Use Panorama: %s" % use_panorama)
    log(debug, "VSys: %s" % vsys)
    log(debug, "Hostname: %s" % hostname)
    if use_panorama and serial is not None:
        log(debug, "Device Serial: %s" % serial)
    else:
        log(debug, "Using serials from logs")


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
        # For Panorama, create the Panorama object, and the firewall if only one serial
        panorama = Panorama(hostname, api_key=apikey)
        if serial is not None:
            firewall = {'firewall': Firewall(panorama=panorama, serial=serial, vsys=vsys)}
            firewall['firewall'].userid.batch_start()
        else:
            firewall = {}
    else:
        firewall = {'firewall': Firewall(hostname, api_key=apikey, vsys=vsys)}
        firewall['firewall'].userid.batch_start()

    # Collect all the ip addresses and tags into firewall batch requests
    for result in results:

        ## Find the serial (if not a single firewall)

        if use_panorama and serial is None:
            try:
                this_serial = result['serial_number']
                this_vsys = result['vsys']
            except KeyError as e:
                result['status'] = "ERROR: Unable to determine serial number or vsys of device"
                continue
            else:
                ## Create the firewall object if using multiple serials
                if this_serial in firewall:
                    this_firewall = firewall[(this_serial, this_vsys)]
                else:
                    # Create the firewall object for this serial
                    firewall[(this_serial, this_vsys)] = Firewall(panorama=panorama, serial=this_serial, vsys=this_vsys)
                    this_firewall = firewall[(this_serial, this_vsys)]
                    this_firewall.userid.batch_start()
        else:
            this_firewall = firewall['firewall']

        ## Find the tag (if a tag_field was specified)

        this_tag = []
        if tag_field is not None:
            try:
                this_tag.append(result[tag_field])
            except KeyError as e:
                result['status'] = "ERROR: Unable to determine tag from field: %s" % tag_field
                continue
        if tag is not None:
            this_tag.append(tag)

        ## Find the IP

        try:
            this_ip = result[ip_field]
        except KeyError as e:
            result['status'] = "ERROR: Unable to determine ip from field: %s" % ip_field

        ## Create a request in the batch user-id update for the firewall
        ## No API call to the firewall happens until all batch requests are created.

        if action == "add":
            log(debug, "Registering tags on firewall %s: %s - %s" % (this_firewall, this_ip, this_tag))
            this_firewall.userid.register(this_ip, this_tag)
        else:
            log(debug, "Unregistering tags on firewall %s: %s - %s" % (this_firewall, this_ip, this_tag))
            this_firewall.userid.unregister(this_ip, this_tag)

        result['status'] = "Submitted successfully"

    ## Make the API calls to the User-ID API of each firewall

    try:
        for fw in firewall.values():
            fw.userid.batch_end()

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
