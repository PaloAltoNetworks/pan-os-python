# ##########################################
# author: Brian Torres-Gil
#
#########################################################
# Do NOT modify anything below this line unless you are
# certain of the ramifications of the changes
#########################################################

import sys  # for system params and sys.exit()
import os
import re  # regular expressions checks in PAN messages
import traceback
from pprint import pformat


try:
    path = os.path.dirname(os.path.abspath(__file__))
    sys.path[:0] = [os.path.join(path, 'lib')]
    import common
    import environment

    logger = common.logging.getLogger().getChild('common_test')
    #logger.setLevel(common.logging.DEBUG)

    from common import log
except Exception as e:
    # Handle exception to produce logs to python.log
    logger.error("Error during import")
    logger.error(traceback.format_exc())
    raise e

try:
    if environment.run_by_splunk():
        import splunk.Intersplunk  # so you can interact with Splunk
        import splunk.entity as entity  # for splunk config info

    libpath = os.path.dirname(os.path.abspath(__file__))
    import pandevice
    import pan.xapi
except Exception as e:
    # Handle exception to produce logs to python.log
    logger.error("Error during import")
    logger.error(traceback.format_exc())
    raise e


def main_splunk():

    ###
    ### Test keywords and options
    ###
    logger.info("Testing getting keywords and options...")
    args, kwargs = splunk.Intersplunk.getKeywordsAndOptions()
    logger.info("args: %s" % pformat(args))
    logger.info("kwargs: %s" % pformat(kwargs))

    ###
    ### Test debug mode
    ###
    logger.info("Testing if debug is enabled...")
    debug = False
    if 'debug' in kwargs:
        if kwargs['debug'] != "no" and kwargs['debug'] != "false":
            debug = True
    if debug:
        logger.info("Debugging enabled")
    else:
        logger.info("Debugging disabled")

    ###
    ### Test field values
    ###
    logger.info("Testing for values in fields specified by device_field...")

    ###
    ### Test get session key and results
    ###
    logger.info("Testing session key retrieval")
    results, unused1, settings = splunk.Intersplunk.getOrganizedResults()
    sessionKey = settings['sessionKey']
    log(debug, "Session Key: %s" % sessionKey)

    ###
    ### Test credential store
    ###

    # Username and password
    logger.info("Testing access to firewall credential store...")
    try:
        fw_username, fw_password = common.get_firewall_credentials(sessionKey)
    except common.NoCredentialsFound as e:
        log(debug, "No firewall credentials were found")
    else:
        log(debug, "FW User: %s" % fw_username)
        log(debug, "FW Pass: %s" % fw_password)

    # Wildfire API Key
    logger.info("Testing access to wildfire apikey")
    try:
        wf_apikey = common.get_wildfire_apikey(sessionKey)
    except common.NoCredentialsFound as e:
        log(debug, "No Wildfire API Key was found")
    else:
        log(debug, "Wildfire API Key: %s" % wf_apikey)

    # Firewall API Key (get)
    logger.info("Testing get fw api key...")
    try:
        fw_apikey = common.get_firewall_apikey(sessionKey)
    except common.NoCredentialsFound as e:
        log(debug, "No Firewall API Key was found")
    else:
        log(debug, "FW APIKey: %s" % fw_apikey)

    # Firewall API Key (set)
    logger.info("Testing set fw api key...")
    try:
        common.set_firewall_apikey(sessionKey, "this_is_a_test_FW_API_KEY")
        fw_apikey = common.get_firewall_apikey(sessionKey)
    except common.NoCredentialsFound as e:
        log(debug, "No Firewall API Key was set")
    else:
        log(debug, "Set FW APIKey: %s" % fw_apikey)

    # Firewall API Key (edit)
    logger.info("Testing modify fw api key...")
    try:
        common.set_firewall_apikey(sessionKey, "this_is_a_modified_FW_API_KEY")
        fw_apikey = common.get_firewall_apikey(sessionKey)
    except common.NoCredentialsFound as e:
        log(debug, "No Firewall API Key was modified")
    else:
        log(debug, "Modified FW APIKey: %s" % fw_apikey)

    # Firewall API Key (delete)
    logger.info("Testing deleted fw api key...")
    try:
        common.delete_firewall_apikey(sessionKey)
        fw_apikey = common.get_firewall_apikey(sessionKey)
    except common.NoCredentialsFound as e:
        log(debug, "No Firewall API Key was found after deletion")
    else:
        log(debug, "ERROR, deleted FW APIKey found: %s" % fw_apikey)

    # Firewall API Key (delete again)
    logger.info("Testing deleted fw api key (again)...")
    try:
        common.delete_firewall_apikey(sessionKey)
        fw_apikey = common.get_firewall_apikey(sessionKey)
    except common.NoCredentialsFound as e:
        log(debug, "No Firewall API Key was found after deletion")
    else:
        log(debug, "ERROR, deleted FW APIKey found: %s" % fw_apikey)

    splunk.Intersplunk.generateErrorResults("this is a test")
    sys.exit(5)

    # output results
    #splunk.Intersplunk.outputResults(results)

    # kwargs contains important parameters.
    # parameters from splunk searchbar include:
    #   action
    #   device
    #   device_field
    #   panorama
    #   vsys
    #   group
    #   tag
    #   tag_field
    #   field
    #   debug

    """
    # Verify required args were passed to command
    if 'tag' not in kwargs:
        logger.error("pantag: Missing required command argument: tag")
        splunk.Intersplunk.generateErrorResults("pantag: Missing required command argument: tag")
        exit(1)

    # results contains the data from the search results and settings
    # contains the sessionKey that we can use to talk to splunk
    results, unused1, settings = splunk.Intersplunk.getOrganizedResults()
    # get the sessionKey
    sessionKey = settings['sessionKey']
    # get the user and password using the sessionKey
    fw_username, fw_password = common.get_firewall_credentials(sessionKey)

    # Determine if hostname was provided as argument or should be pulled from entries
    if "device" in kwargs:
        device_per_log = False
        use_panorama = False
        hostname = kwargs['device']
    elif "device_field" in kwargs:
        device_per_log = True
        use_panorama = False
        hostname = kwargs['device_field']
    elif "panorama" in kwargs:
        device_per_log = True
        use_panorama = True
        hostname = kwargs['panorama']
    else:
        device_per_log = True
        use_panorama = False
        hostname = "host"

    # If only tagging on one firewall, create it now
    if not device_per_log:
        firewall = pandevice.firewall.Firewall(hostname,
                                               fw_username,
                                               fw_password,
                                               )

    ADDRESSES = []

    try:
        for result in results:
            if field and field in result:
                ADDRESSES.append(result[field])
            else:
                for field in IP_FIELDS:
                    if field in result:
                        ADDRESSES.append(result[field])
            result["status"] = "action submitted"
        # dedup the ADDRESSES list
        ADDRESSES = set(ADDRESSES)
        ADDRESSES = list(ADDRESSES)

        tag(device, ACTION, ADDRESSES, TAG)

    except pan.xapi.PanXapiError as e:
        if re.search(r"tag [^ ]* already exists, ignore", str(e)):
            pass
        else:
            stack = traceback.format_exc()
            logger.warn(stack)
            splunk.Intersplunk.parseError(str(e))
            splunk.Intersplunk.generateErrorResults(str(e))

    except Exception as e:
        stack = traceback.format_exc()
        logger.warn(stack)
        splunk.Intersplunk.parseError(str(e))
        splunk.Intersplunk.generateErrorResults(str(e))

    # output results
    splunk.Intersplunk.outputResults(results)
    """

def main_cli():
    pass

if __name__ == "__main__":
    if environment.run_by_splunk():
        main_splunk()
    else:
        main_cli()
