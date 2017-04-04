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
# 2.  The file digest (MD5, SHA-1, or SHA256) of the file that produced the alert. This is in the syslog.
# 3.  The ID of the report. This is in the syslog.
###########################################
###########################################
# if you DO want to go through a proxy, e.g., HTTP_PROXY={squid:'2.2.2.2'}
HTTP_PROXY = {}
#########################################################
# Do NOT modify anything below this line unless you are
# certain of the ramifications of the changes
#########################################################

import sys
import os
import traceback
import argparse

libpath = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(libpath, 'lib')]
import common
import environment
import pan.wfapi

logger = common.logging.getLogger().getChild('retrieveWildFireReport')
# logger.setLevel(common.logging.INFO)

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
    # parser.add_argument('-v', '--verbose', action='store_true', help="Verbose")
    parser.add_argument('apikey', help="API Key from https://wildfire.paloaltonetworks.com")
    parser.add_argument('file_digest', help="Hash of the file for the report")
    options = parser.parse_args()
    return options


def retrieveWildFireData(apikey, file_digest):
    wfapi = pan.wfapi.PanWFapi(api_key=apikey)
    wfapi.report(file_digest)
    return wfapi.response_body


def main_cli():
    # Get command line arguments
    options = get_cli_args()
    # debug = options.verbose
    # logger = common.logging.getLogger()
    # common.logging.basicConfig(level=common.logging.INFO)
    # if debug:
    #    logger.setLevel(common.logging.DEBUG)
    #    logger.info("Verbose logging enabled")
    # Grab WildFire data
    data = retrieveWildFireData(options.apikey, options.file_digest)
    # Parse XML for fields
    print data
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
        if 'file_digest' in result:
            logger.debug("Getting Wildfire report for result # %s with file_digest: %s" % (idx, result['file_digest']))
            try:
                # Get the report
                wfReportXml = retrieveWildFireData(wf_apikey, result['file_digest']).strip()
                result['wildfire_report'] = wfReportXml
            except:
                logger.warn("Error retrieving WildFire report for file_digest: %s" % result['file_digest'])
                # Log the result row in case of an exception
                logger.info("Log with error: %s" % result)
                stack = traceback.format_exc()
                # log the stack information
                logger.warn(stack)
        else:
            logger.debug("Required fields missing from result # %s."
                         "Expected the following fields: file_digest" % idx)
    # output the complete results sent back to splunk
    splunk.Intersplunk.outputResults(results)

if __name__ == "__main__":
    if environment.run_by_splunk():
        main_splunk()
    else:
        main_cli()
