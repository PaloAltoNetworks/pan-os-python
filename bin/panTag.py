# ##########################################
# Version 0.8
# Extremely Experimental
# author: Brian Torres-Gil
# 
# About this script:
# Given an IP address, tags or identifies the ip address in PAN-OS.
# Behavior in PAN-OS 6.0 and higher:
#   IP address is tagged. IP's can have multiple tags. Tags are
#   referenced in Dynamic Address Groups. Boolean logic (AND/OR)
#   can be used in Dynamic Address Groups to filter ip's based on tags
# Behavior in PAN-OS 5.1 and lower:
#   IP address is mapped to an identifier. Only one identifier
#   per IP address. The identifier associates the IP with a single
#   Dynamid Address Object in PAN-OS.
#
# The script assumes that you have firewall policy setup that blocks
# traffic for a given dynamic address group
#
# It is important to recognize that this script does NOT modify a firewall rule!
# It is only tagging IP addresses with metadata so that the existing firewall
# policy can act accordingly.
#
############################################

############################################
# How to Use this script
# in the example below, we are blocking all ip's returned by the search
# example1: index=pan_logs 1.1.1.1 | stats dc(dst_ip) by dst_ip | pantag action="add" tag="malware-infected" device="1.0.0.1"
# Adds a 'malware-infected' tag to the IP 1.1.1.1 on the firewall with ip 1.0.0.1
# example2: index=pan_logs wine | stats dc(dst_ip) by dst_ip | pantag action="rem" group="shairpoint" device="sales-fw"
# Removes the 'shairpoint' tag from all dst_ip returned by the search on the firewall with hostname sales-fw
###########################################

###########################################
# Known issues:
# Very limited error checking
# Errors may not reported in the Splunk UI
# Does not support panorama
###########################################

#############################
# Change the values below to suit your PAN configuration, or
# supply these values in the Splunk search bar.
#
# WARNING!!!! Password is stored in clear text.
# It is recommended to leave PANUSER and PANPASS commented out,
# and user the app configuration screen to provide these instead.
#############################

# firewall IP. you can provide this via the device parameter
PAN = '192.168.4.100'

# Admin account for the PAN device
#PANUSER = 'admin'

# Password for the admin user.
# Any special characters in the password must be URL/percent-encoded.
#PANPASS = 'admin'

# Defaults to vsys1. vsys substition is not supported at this time
VSYS = 'vsys1'

# Name of the address group for bad actors
TAG = 'bad-actor'

# Add or Remove the tag (add or rem)
ACTION = 'add'

# This is a default actor.
ACTOR = '1.1.1.1'

# if you DO want to go through a proxy, e.g., HTTP_PROXY={squid:'2.2.2.2'}
HTTP_PROXY = {}

# Default fields that contain IP addresses and should be tagged if they exist
IP_FIELDS = ['src_ip', 'dst_ip', 'ip']

# Enable debugging (script is otherwise silent unless there is an error)
DEBUG = False

#########################################################
# Do NOT modify anything below this line unless you are
# certain of the ramifications of the changes
#########################################################

import splunk.mining.dcutils as dcu

logger = dcu.getLogger().getChild('panTag')
logger.setLevel(20)

try:
    import splunk.Intersplunk  # so you can interact with Splunk
    import splunk.entity as entity  # for splunk config info
    import urllib2  # make http requests to PAN firewall
    import sys  # for system params and sys.exit()
    import os
    import re  # regular expressions checks in PAN messages
    import traceback

    libpath = os.path.dirname(os.path.abspath(__file__))
    sys.path[:0] = [os.path.join(libpath, 'lib')]
    sys.path[:0] = [os.path.join(libpath, 'lib', 'pan-python', 'lib')]
    sys.path[:0] = [os.path.join(libpath, 'lib', 'pandevice')]
    import pandevice
    import pan.xapi

except Exception, e:
    logger.error("Error during import")
    logger.error(traceback.format_exc())


## Major props to Ledion. copying his function, verbatim and then adding comments and traceback and logging
## http://blogs.splunk.com/2011/03/15/storing-encrypted-credentials/
## access the credentials in /servicesNS/nobody/<YourApp>/admin/passwords
def getCredentials(sessionKey):
    """Given a splunk sesionKey returns a clear text user name and password from a splunk password container"""
    # this is the folder name for the app and not the app's common name
    myapp = 'SplunkforPaloAltoNetworks'
    try:
        # list all credentials
        entities = entity.getEntities(['admin', 'passwords'], namespace=myapp, owner='nobody', sessionKey=sessionKey)
    except Exception, e:
        stack = traceback.format_exc()
        logger.warn(stack)
        logger.warn("entity exception")
        raise Exception("Could not get %s credentials from splunk. Error: %s" % (myapp, str(e)))
    # return first set of credentials
    for i, c in entities.items():
        if c['username'] != 'wildfire_api_key':
            return c['username'], c['clear_password']
    logger.warn(
        "Attempted to tag ip, however, no credentials for firewall found. Try setting credentials in the SplunkforPaloAltoNetworks app set up screen.")
    raise Exception("No credentials have been found")


def tag(device, add_remove, ip_addresses, tag):
    """Tag the ip address"""
    ip_tag_sets = []
    for ip in ip_addresses:
        ip_tag_sets.append((ip, tag))

    if add_remove == 'add':
        device.update_dynamic_addresses(ip_tag_sets, [])
    else:
        device.update_dynamic_addresses([], ip_tag_sets)


args, kwargs = splunk.Intersplunk.getKeywordsAndOptions()

if 'debug' in kwargs:
    logger.info("Debugging enabled")
    DEBUG = kwargs['debug']

if DEBUG:
    logger.setLevel(10)

#parse the kwargs for ACTION, VSYS, PAN
if kwargs.has_key('action'):
    ACTION = kwargs['action']
if kwargs.has_key('device'):
    PAN = kwargs['device']
if kwargs.has_key('vsys'):
    VSYS = kwargs['vsys']
if kwargs.has_key('group'):
    TAG = kwargs['group']
if kwargs.has_key('identifier'):
    TAG = kwargs['identifier']
if kwargs.has_key('tag'):
    TAG = kwargs['tag']
if kwargs.has_key('field'):
    field = kwargs['field']
else:
    field = None

# an empty dictionary. it will be used to hold system values
settings = dict()
# results contains the data from the search results and settings contains the sessionKey that we can use to talk to splunk
results, unused1, settings = splunk.Intersplunk.getOrganizedResults()
# get the sessionKey
sessionKey = settings['sessionKey']
# get the user and password using the sessionKey
PANUSER, PANPASS = getCredentials(sessionKey)

device = pandevice.PanDevice(PAN,
                             443,
                             PANUSER,
                             PANPASS,
                             detect_device=True,
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

except pan.xapi.PanXapiError, e:
    if re.search(r"tag [^ ]* already exists, ignore", str(e)):
        pass
    else:
        stack = traceback.format_exc()
        logger.warn(stack)
        splunk.Intersplunk.parseError(str(e))
        results = splunk.Intersplunk.generateErrorResults(str(e))

except Exception, e:
    stack = traceback.format_exc()
    logger.warn(stack)
    splunk.Intersplunk.parseError(str(e))
    results = splunk.Intersplunk.generateErrorResults(str(e))

# output results
splunk.Intersplunk.outputResults(results)
