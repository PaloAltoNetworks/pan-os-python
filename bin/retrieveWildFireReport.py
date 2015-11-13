# ##########################################
# Version 1.0
# Author: Brian Torres-Gil
#
# About this script:
#   Triggered when a WildFire syslog indicates a file has been analyzed by WildFire.
#   This script retrieves the WildFire data relating to that syslog from the WildFire
#   cloud service API.
#
# Script's actions and warning messages are logged in $SPLUNK_HOME/var/log/splunk/python.log
############################################
############################################
# How to Use this script
# The script must be provided 3 things to retrieve an WildFire log from the cloud:
# 1.  An API Key. This is found at https://wildfire.paloaltonetworks.com
#   under 'My Account'.
# 2.  The Serial Number of the device that produced the alert. This is in the syslog.
# 3.  The ID of the report. This is in the syslog.
###########################################
###########################################

# if you want to go through a proxy, e.g., HTTP_PROXY={squid:'2.2.2.2'}
HTTP_PROXY = {}

#########################################################
# Do NOT modify anything below this line unless you are
# certain of the ramifications of the changes
#########################################################

import sys
import os
import urllib  # for urllib.urlencode()
import urllib2  # make http requests to PAN firewall
import traceback
import argparse

libpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(libpath, 'lib')]
import common
import environment

logger = common.logging.getLogger().getChild('retrieveWildFireReport')
#logger.setLevel(common.logging.INFO)

if environment.run_by_splunk():
    try:
        import splunk.Intersplunk  # so you can interact with Splunk
        import splunk.entity as entity  # for splunk config info
    except Exception as e:
        # Handle exception to produce logs to python.log
        logger.error("Error during import")
        logger.error(traceback.format_exc())
        raise e


def get_cli_args():
    """Used if this script is run from the CLI

    This function is not used if script run from Splunk searchbar
    """
    # Setup the argument parser
    parser = argparse.ArgumentParser(description="Download a Wildfire Report using the Wildfire API")
    #parser.add_argument('-v', '--verbose', action='store_true', help="Verbose")
    parser.add_argument('apikey', help="API Key from https://wildfire.paloaltonetworks.com")
    parser.add_argument('serial', help="Serial number of the device which produced the WildFire syslog")
    parser.add_argument('reportid', help="ID of the report in the WildFire cloud")
    options = parser.parse_args()
    return options

def createOpener():
    """Create a generic opener for http

    This is particularly helpful when there is a proxy server in line
    """
    # Thanks to: http://www.decalage.info/en/python/urllib2noproxy
    proxy_handler = urllib2.ProxyHandler(HTTP_PROXY)
    opener = urllib2.build_opener(proxy_handler)
    urllib2.install_opener(opener)
    return opener


def retrieveWildFireData(apikey, serial, reportid):
    # Create a urllib2 opener
    opener = createOpener()
    # URL for WildFire cloud API
    wfUrl = 'https://wildfire.paloaltonetworks.com/publicapi/report'
    # Prepare the variables as POST data
    post_data = urllib.urlencode({
        'apikey': apikey,
        'device_id': serial,
        'report_id': reportid,
    })
    # Create a request object
    wfReq = urllib2.Request(wfUrl)
    # Make the request to the WildFire cloud
    result = opener.open(wfReq, post_data)
    return result


def main_cli():
    # Get command line arguments
    options = get_cli_args()
    #debug = options.verbose
    #logger = common.logging.getLogger()
    #common.logging.basicConfig(level=common.logging.INFO)
    #if debug:
    #    logger.setLevel(common.logging.DEBUG)
    #    logger.info("Verbose logging enabled")
    # Grab WildFire data
    data = retrieveWildFireData(options.apikey, options.serial, options.reportid)
    # Parse XML for fields
    print data.read()
    sys.exit(0)


def main_splunk():
    # Get arguments passed to command on Splunk searchbar
    args, kwargs = splunk.Intersplunk.getKeywordsAndOptions()

    debug = common.check_debug(kwargs)

    # Setup the logger. $SPLUNK_HOME/var/log/splunk/python.log
    logger = common.logging.getLogger()
    if debug:
        logger.setLevel(common.logging.DEBUG)

    # Results contains the data from the search results and settings contains
    # the sessionKey that we can use to talk to splunk
    logger.debug("Getting search results and settings from Splunk")
    results, unused1, settings = splunk.Intersplunk.getOrganizedResults()

    # Get the sessionKey
    sessionKey = settings['sessionKey']
    # If there are logs to act on, get the Panorama user and password from Splunk using the sessionKey
    if len(results) < 0:
        logger.debug("No search results.  Nothing to do.")
        splunk.Intersplunk.outputResults(results)
        sys.exit(0)

    logger.debug("Getting Wildfire APIKey from encrypted store")
    wf_apikey = common.get_wildfire_apikey(sessionKey)

    # Get a wildfire report for each row
    logger.debug("Getting Wildfire reports for %s search results" % len(results))
    for idx, result in enumerate(results):
        # Check to see if the result has the necessary fields
        if 'serial_number' in result and 'report_id' in result:
            logger.debug("Getting Wildfire report for result # %s with report_id: %s" % (idx, result['report_id']))
            try:
                # Get the report
                wfReportXml = retrieveWildFireData(wf_apikey, result['serial_number'],
                                                   result['report_id']).read().strip()
                # Add the report id to the XML for correlation to the original WildFire log from the firewall
                wfReportXml = wfReportXml.replace("</version>", "</version>\n<id>" + result['report_id'] + "</id>", 1)
                result['wildfire_report'] = wfReportXml
            except:
                logger.warn("Error retrieving WildFire report for report id: %s" % result['report_id'])
                # Log the result row in case of an exception
                logger.info("Log with error: %s" % result)
                stack = traceback.format_exc()
                # Log the stack information
                logger.warn(stack)
        else:
            logger.debug("Required fields missing from result # %s."
                         "Expected the following fields: serial_number, report_id" % idx)
    # output the complete results sent back to splunk
    splunk.Intersplunk.outputResults(results)

if __name__ == "__main__":
    if environment.run_by_splunk():
        main_splunk()
    else:
        main_cli()
