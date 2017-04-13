# ##########################################
# Version 1.0
# Author: Palo Alto Networks
#
# About this script:
#
# Script's actions and warning messages are logged in $SPLUNK_HOME/var/log/splunk/python.log
############################################
############################################
# How to Use this script
# The script must be provided 3 things to retrieve an AutoFocus log from the cloud:
# 1.  An API Key. This is found at https://autofocus.paloaltonetworks.com
#   under 'Settings'.
# 3.  The Label of the export. Created on autoocus.paloaltonetworks.com.
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
import pan.afapi
import json

# logger = common.logging.getLogger().getChild('retrieveAutofocusReport')
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

def validate_input(helper, definition):
    """Implement your own validation logic to validate the input stanza configurations"""
    # This example accesses the modular input variable
    label = definition.parameters.get('label', None)
    # af_apikey = common.get_autofocus_apikey(sessionKey)
    pass


def get_cli_args():
    """Used if this script is run from the CLI

    This function is not used if script run from Splunk searchbar
    """
    # Setup the argument parser
    parser = argparse.ArgumentParser(description="Retrieve Autofocus export using the Autofocus API")
    # parser.add_argument('-v', '--verbose', action='store_true', help="Verbose")
    parser.add_argument('apikey', help="API Key from https://autofocus.paloaltonetworks.com")
    parser.add_argument('label', help="Label of export list.")
    options = parser.parse_args()
    return options


def retrieveAutoFocusData(apikey, label):
    values = {
        "apiKey":apikey,
        "panosFormatted":"false",
        "exportMetadata":"true",
        "label":label
    }
    afapi = pan.afapi.PanAFapi(api_key=apikey)
    return afapi.export(json.dumps(values)).json


def main_cli():
    # Get command line arguments
    options = get_cli_args()
    # debug = options.verbose
    # logger = common.logging.getLogger()
    # common.logging.basicConfig(level=common.logging.INFO)
    # if debug:
    #    logger.setLevel(common.logging.DEBUG)
    #    logger.info("Verbose logging enabled")
    # Grab AutoFocus data
    data = retrieveAutoFocusData(options.apikey, options.label)
    # Parse XML for fields
    print data
    sys.exit(0)


def collect_events(helper, inputs, ew):
    # Setup the logger. $SPLUNK_HOME/var/log/splunk/python.log
    logger = common.logging.getLogger()
    logger.setLevel(common.logging.DEBUG)

    # Get the sessionKey
    sessionKey = settings['sessionKey']

    # Get API KEY
    logger.debug("Getting Autofocus APIKey from encrypted store")
    af_apikey = common.get_autofocus_apikey(sessionKey)
    # label = definition.parameters.get('label', None)
    opt_label = helper.get_arg('label')

    #Retrieve AutoFocus Export List
    logger.debug("Getting AutoFocus Export for %s search results" % len(results))
    afJson = retrieveAutoFocusData(af_apikey, opt_label)



if __name__ == "__main__":
    if environment.run_by_splunk():
        collect_events()
    else:
        main_cli()
