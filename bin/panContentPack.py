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

"""Update app and threat lookup files

About this script
-----------------
Pulls the latest app and threat information from a firewall
or Panorama and outputs it as search results. This can be leveraged
to update the app_list.csv and threat_list.csv files
in the Palo Alto Networks Add-On (TA).

Example usage in Splunk searchbar:

Update app list:
    | pancontentpack 10.5.5.5 apps

Update threat list:
    | pancontentpack 10.5.5.5 threats

Where 10.5.5.5 is the ip of a firewall or Panorama.

"""


#########################################################
# Do NOT modify anything below this line unless you are
# certain of the ramifications of the changes
#########################################################

import sys  # for system params and sys.exit()
import os
import traceback

libpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(libpath, 'lib')]
import common
import environment
import xmltodict
from collections import OrderedDict

logger = common.logging.getLogger().getChild('updateAppsThreats')

try:
    import splunk.Intersplunk  # so you can interact with Splunk
    import splunk.entity as entity  # for splunk config info
except ImportError as e:
    logger.error("Unable to import Splunk libraries. Run command with Splunk python:"
                 "  $SPLUNK_HOME/bin/splunk cmd python %s" % __file__)
    sys.exit(3)

libpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(libpath, 'lib')]
sys.path[:0] = [os.path.join(libpath, 'lib', 'pan-python', 'lib')]
sys.path[:0] = [os.path.join(libpath, 'lib', 'pandevice')]
try:
    import pandevice.base
    import pan.xapi
except ImportError:
    print "Unable to import libraries. Please run command from app's bin directory where the script is located."
    exit(3)

from common import log


def usage():
    common.exit_with_error("Usage: | pancontentpack <firewall/Panorama IP> <apps|threats>")

def parse_apps(apps_xml):
    obj = xmltodict.parse(apps_xml)
    try:
        apps = obj['response']['result']['application']['entry']
    except KeyError as e:
        logger.error("Unable to parse app xml from firewall")
        raise e
    csv_apps = []
    for app in apps:
        a = OrderedDict()
        try:
            a['app'] = app['@name']
            a['app:category'] = app.get('category', "")
            a['app:subcategory'] = app.get('subcategory', "")
            a['app:technology'] = app.get('technology', "")
            a['app:risk'] = app['risk']
            a['app:evasive'] = app['evasive-behavior']
            a['app:excessive_bandwidth'] = app['consume-big-bandwidth']
            a['app:used_by_malware'] = app['used-by-malware']
            a['app:able_to_transfer_file'] = app['able-to-transfer-file']
            a['app:has_known_vulnerability'] = app['has-known-vulnerability']
            a['app:tunnels_other_application'] = app['tunnel-other-application']
            if a['app:tunnels_other_application'] != u"yes" and a['app:tunnels_other_application'] != u"no":
                a['app:tunnels_other_application'] = a['app:tunnels_other_application']['#text']
            a['app:prone_to_misuse'] = app['prone-to-misuse']
            a['app:pervasive_use'] = app['pervasive-use']
            a['app:is_saas'] = app.get('is-saas', "no")
            a['app:default_ports'] = ""
            try:
                # Sometimes there are more than one default tag
                # so make it a list and iterate over the default tags.
                default = app['default']
                if isinstance(default, list):
                    for d in default:
                        a['app:default_ports'] = d['port']['member']
                        break
                else:
                    a['app:default_ports'] = default['port']['member']
            except KeyError:
                pass
            else:
                if not isinstance(a['app:default_ports'], basestring):
                    a['app:default_ports'] = "|".join(a['app:default_ports'])
        except Exception as e:
            logger.error("Error parsing app: %s" % app['@name'])
            logger.error(traceback.format_exc())
            common.exit_with_error(str(e))
        # convert all out of unicode
        for key in a:
            a[key] = str(a[key])
        csv_apps.append(a)
    logger.info("Found %s apps" % len(csv_apps))
    return csv_apps


def parse_threats(threats_xml):
    obj = xmltodict.parse(threats_xml)
    try:
        phone_home = obj['response']['result']['threats']['phone-home']['entry']
        vulnerability = obj['response']['result']['threats']['vulnerability']['entry']
        threats = phone_home + vulnerability
    except KeyError as e:
        logger.error("Unable to parse threat xml from firewall")
        raise e
    csv_threats = []
    for threat in threats:
        a = OrderedDict()
        try:
            a['threat_id'] = threat['@name']
            a['threat:name'] = threat['threatname']
            a['threat:category'] = threat['category']
            a['threat:severity'] = threat['severity']
            a['threat:cve'] = threat.get('cve', None)
            if a['threat:cve'] is not None:
                a['threat:cve'] = threat['cve']['member']
                if not isinstance(a['threat:cve'], basestring):
                    a['threat:cve'] = ", ".join(a['threat:cve'])
            else:
                a['threat:cve'] = ""
        except KeyError as e:
            logger.error("Error parsing app: %s" % threat['@name'])
            raise e
        # convert all out of unicode
        for key in a:
            a[key] = str(a[key])
        csv_threats.append(a)
    logger.info("Found %s threats" % len(csv_threats))
    return csv_threats

def main():
    # Get arguments
    args, kwargs = splunk.Intersplunk.getKeywordsAndOptions()

    # Enable debugging by passing 'debug=yes' as an argument of
    # the command on the Splunk searchbar.

    debug = common.check_debug(kwargs)

    if len(args) < 2:
        logger.error("pancontentpack: Wrong number of arguments: %s, expected 2.\n" % len(args))
        usage()

    if args[1] == "apps":
        logger.info("Getting apps from content pack on Palo Alto Networks device at %s..." % args[0])
    elif args[1] == "threats":
        logger.info("Getting threats from content pack on Palo Alto Networks device at %s..." % args[0])
    else:
        usage()

    # Results contains the data from the search results and settings
    # contains the sessionKey that we can use to talk to Splunk
    # Ignore the results
    results, unused1, settings = splunk.Intersplunk.getOrganizedResults()
    # Get the sessionKey
    sessionKey = settings['sessionKey']

    log(debug, "Begin get API key")
    # Get the API key from the Splunk store or from the device at hostname if no apikey is stored
    apikey = common.apikey(sessionKey, args[0], debug)

    device = pandevice.base.PanDevice(args[0], api_key=apikey)

    try:
        if args[1] == "apps":
            device.xapi.get("/config/predefined/application")
            app_xml = device.xapi.xml_document
            csv = parse_apps(app_xml)
        else:
            device.xapi.get("/config/predefined/threats")
            threat_xml = device.xapi.xml_document
            csv = parse_threats(threat_xml)

    except pan.xapi.PanXapiError as e:
        common.exit_with_error(str(e))


    # output results
    splunk.Intersplunk.outputResults(csv)


if __name__ == "__main__":
    main()
