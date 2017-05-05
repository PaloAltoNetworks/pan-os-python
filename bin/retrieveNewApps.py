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

"""Retrieve the latest additions to Applipedia

About this script
-----------------
This script retrieves an xml file with new apps so they
can be highlighted in a dashboard.

As with other scripts in this app, all script actions and warning
messages are logged in $SPLUNK_HOME/var/log/splunk/python.log
"""

# if you DO want to go through a proxy, e.g., HTTP_PROXY={squid:'2.2.2.2'}
HTTP_PROXY = {}

#########################################################
# Do NOT modify anything below this line unless you are
# certain of the ramifications of the changes
#########################################################

import sys  # for system params and sys.exit()
import os
import xml.etree.ElementTree as ET  # for xml parsing
import urllib2  # make http requests to PAN firewall

libpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(libpath, 'lib')]
import common

logger = common.logging.getLogger().getChild('panRetrieveNewApps')

try:
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


def createOpener():
    """Create a generic opener for http
    This is particularly helpful when there is a proxy server in line"""
    # Thanks to: http://www.decalage.info/en/python/urllib2noproxy
    proxy_handler = urllib2.ProxyHandler(HTTP_PROXY)
    opener = urllib2.build_opener(proxy_handler)
    urllib2.install_opener(opener)
    return opener


def retrieveNewApps():
    # Create a urllib2 opener
    opener = createOpener()
    # URL for WildFire cloud API
    newAppUrl = 'https://ww2.paloaltonetworks.com/iphone/NewApps.aspx'
    # Create a request object
    newAppReq = urllib2.Request(newAppUrl)
    # Make the request
    result = opener.open(newAppReq)
    return result



try:
    # Get arguments
    args, kwargs = splunk.Intersplunk.getKeywordsAndOptions()

    # Enable debugging by passing 'debug=yes' as an argument of
    # the command on the Splunk searchbar.

    debug = common.check_debug(kwargs)

    # Results contains the data from the search results
    results, unused1, settings = splunk.Intersplunk.getOrganizedResults()

    existing_apps = []
    for app in results:
        existing_apps.append(str(app['app{@name}']))

    results = []
    log(debug, "Existing apps already known and considered: %s" % (len(existing_apps),))
    log(debug, existing_apps)

    log(debug, "Getting new Apps from Palo Alto Networks")
    resp = retrieveNewApps()
    log(debug, "Apps retrieved")
    xml = resp.read()

    log(debug, "Apps read")
    xmlroot = ET.fromstring(xml)
    log(debug, "Apps parsed")

    newapps = xmlroot.findall("./entry")
    log(debug, "Found %s new apps at Palo Alto Networks" % (len(newapps),))

    for app in newapps:
        app.tag = 'app'
        if app.get('name') not in existing_apps:
            results.append({"_raw": ET.tostring(app)})

    log(debug, "Found %s new apps that weren't already known" % (len(results),))

    # output the complete results sent back to splunk
    splunk.Intersplunk.outputResults(results)

except Exception, e:
    common.exit_with_error("Exception while getting new apps. Error: %s" % str(e))

