# ##########################################
# Version 0.1
# Extremely Experimental
# author: monzy@splunk.com
# About this script:
# Given an IP address, adds or removes the IP from an address group
# The script assumes that you have firewall policy setup that blocks
# traffic for a given group, e.g. a badActors group.
# It is important to recognize that this script does NOT modify a firewall rule.
# It only adds/removes address objects.
# So if a rule operates on an Address Group, this scripts add/remove will impact
# that rule/policy.
############################################

############################################
# How to Use this script
# in the example below, we are blocking all ip's returned by the search
# example1: index=pan_logs 1.1.1.1 | stats dc(dst_ip) by dst_ip | panblock action="add" group="badboys"
# Adds the IP 1.1.1.1
# example2: index=pan_logs wine | stats dc(dst_hostname) by dst_hostname | panblock action="rem" group="badboys" device="sales-fw"
# Removes all dst_hostnames returned by the search from the sales firewall from the badboys group
###########################################

###########################################
# Known issues:
# Very limited error checking
# Errors may not reported in the Splunk UI
###########################################

#############################
# Change the values below to suit your PAN configuration
# WARNING!!!! Password is stored in clear text.
#############################
# firewall IP. you can provide this via the device parameter
PAN = '192.168.4.100'
# admin account for the PAN device
PANUSER = 'admin'
# password for the admin user.
# any special characters in the password must be URL/percent-encoded.
PANPASS = 'admin'
# Defaults to vsys1. vsys substition is not supported at this time
VSYS = 'vsys1'
# Name of the address group for bad actors
BADACTORS = 'badActors'
ACTION = 'add'
# This is a default actor.
ACTOR = '1.1.1.1'
# if you DO want to go through a proxy, e.g., HTTP_PROXY={squid:'2.2.2.2'}
HTTP_PROXY = {}

#########################################################
# Do NOT modify anything below this line unless you are
# certain of the ramifications of the changes
#########################################################

import urllib2  # make http requests to PAN firewall
import sys  # for system params and sys.exit()
import os  # os.path
import re  # regular expressions checks in PAN messages

# Set python path to include app libs
current_path = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(current_path, 'lib')]
sys.path[:0] = [os.path.join(current_path, 'lib', 'pan-python', 'lib')]

from environment import run_by_splunk, init_splunk_environment, init_logging
from environment import SPLUNK_HOME

# Initialize the Splunk environment for connectivity to Splunk, and
# restart this script.  If the environment is already initialized,
# then continue by importing the splunk libraries.
init_splunk_environment(SPLUNK_HOME)

# Import Splunk libraries
import splunk.Intersplunk  # so you can interact with Splunk
import splunk.entity as entity  # for splunk config info

import common


# Configure root logger
logger = init_logging()


def createOpener():
    """Create a generic opener for http. This is particularly helpful when there is a proxy server in line"""
    # Thanks to: http://www.decalage.info/en/python/urllib2noproxy
    proxy_handler = urllib2.ProxyHandler(HTTP_PROXY)
    opener = urllib2.build_opener(proxy_handler)
    urllib2.install_opener(opener)
    return opener


def getKey(PAN, PANUSER, PANPASS):
    """ Logs into the PAN firewall and obtains a PAN session key"""
    # create an opener object
    opener = createOpener()
    try:
        # the url for the PAN
        panReq = urllib2.Request('https://' + PAN + '/api/?type=keygen&user=' + PANUSER + '&password=' + PANPASS)
        # make the request
        req = opener.open(panReq)
    except:
        sys.exit(-1)
    # the result of the URL request
    result = req.read()
    # get the status of the result
    try:
        sm = re.search(r"success", result).group(0)
        if sm == 'success':
            status = 'success'
    except:
        sys.exit(-1)
    # parse the key from the result
    key = result.split("</key>")[0].split("<key>")[1]
    return key


def checkAddr(address):
    """Check if an address is a FQDN or IP with some netmask. Return the appropriate uri for PAN api"""
    # element is everything after the element= field in the PAN api
    # re pattern for IP address
    ippat = '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    # re pattern for fully qualified domain name (could be stricter)
    fqdnpat = '\w+[.-]'
    # is element an IP address
    if re.match(ippat, address) != None:
        ipuri = '<ip-netmask>' + address + '/32</ip-netmask>'
        return ipuri
    if re.match(fqdnpat, address) != None:
        fqdnuri = '<fqdn>' + address + '</fqdn>'
        return fqdnuri


def panorama():
    """ Interact with PANorama"""
    #Set dynamic address object (with LinkID) at Panorama level, commit
    #https://pm-panorama/api/?type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='splunktastic']/address/entry[@name='test-add']&element=<dynamic>test1</dynamic>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09
    #https://pm-panorama/api/?type=commit&action=all&cmd=<commit-all><shared-policy><device-group>splunktastic</device-group></shared-policy></commit-all>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09
    #Map IPs to correct UserID
    #https://pm-panorama/api/?type=user-id&action=set&cmd=<uid-message><version>1.0</version><type>update</type><payload><login><entry name="domain\uid1" ip="10.1.1.1" timeout="20"></entry></login></payload></uid-message>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09&target=0006C107916
    return 0


def addActor(PAN, key, VSYS, ACTOR, BADACTORS):
    """Creates an address object then add the object to an Address group"""
    # create an opener object
    opener = createOpener()
    # create the address object
    panReq = urllib2.Request(
        'https://' + PAN + '//api/?type=config&action=set&key=' + key + '&xpath=/config/devices/entry/vsys/entry[@name=' + "'" + VSYS + "'" + ']/address/entry[@name=' + "'" + ACTOR + "'" + ']&element=' + checkAddr(
            ACTOR))
    req = opener.open(panReq)
    # add the address object to the BADACTORS group
    panReq = urllib2.Request(
        'https://' + PAN + '//api/?type=config&action=set&key=' + key + '&xpath=/config/devices/entry/vsys/entry[@name=' + "'" + VSYS + "'" + ']/address-group/entry[@name=' + "'" + BADACTORS + "'" + ']&element=<member>' + ACTOR + '</member>')
    req = opener.open(panReq)
    return 0


def remActor(PAN, key, VSYS, ACTOR, BADACTORS):
    """Remove an address object from the address-group then remove the addres object"""
    # create an opener object
    opener = createOpener()
    # first we remove him from the badactors group
    #panReq = urllib2.Request('https://'+PAN+'/api/?type=config&action=delete&key='+key+'&xpath=/config/devices/entry/vsys/entry[@name='+"'"+VSYS+"'"+']/address-group/entry[@name='+"'"+BADACTORS+"'"+']&element=<member>'+ACTOR+'</member>')
    #req = opener.open(panReq)
    # then we remove him all together
    #panReq = urllib2.Request('https://'+PAN+'/api/?type=config&action=delete&key='+key+'&xpath=/config/devices/entry/vsys/entry[@name='+"'"+VSYS+"'"+']/address/entry[@name='+"'"+ACTOR+"'"+']')
    #req = opener.open(panReq)
    panReq = urllib2.Request(
        'https://' + PAN + '/api/?type=config&action=delete&key=' + key + '&xpath=/config/devices/entry/vsys/entry[@name=' + "'" + VSYS + "'" + ']/address-group/entry[@name=' + "'" + BADACTORS + "'" + ']/member[text()=' + "'" + ACTOR + "'" + ']')
    req = opener.open(panReq)
    panReq = urllib2.Request(
        'https://' + PAN + '/api/?type=config&action=delete&key=' + key + '&xpath=/config/devices/entry/vsys/entry[@name=' + "'" + VSYS + "'" + ']/address/entry[@name=' + "'" + ACTOR + "'" + ']')
    req = opener.open(panReq)
    return 0


def commitConfig(PAN, key):
    """Save the changes made to the address objects"""
    # create an opener object
    opener = createOpener()
    panReq = urllib2.Request('https://' + PAN + '//api/?type=commit&cmd=<commit></commit>&key=' + key)
    req = opener.open(panReq)
    return 0


def block(result):
    key = getKey(PAN, PANUSER, PANPASS)
    if ACTION == "add":
        addActor(PAN, key, VSYS, str(result[result.keys()[0]]), BADACTORS)
    elif ACTION == "rem":
        remActor(PAN, key, VSYS, str(result[result.keys()[0]]), BADACTORS)
    else:
        return ["bad action", key]
    return ["action submitted", key]

def update_address_group(device, group, action="add", vsys="vsys1"):
    pass




def main_from_splunk():
    logger.warn("Going to parse args")
    from pprint import pformat
    logger.warn("args: %s" % pformat(sys.argv))

    args, kwargs = splunk.Intersplunk.getKeywordsAndOptions()
    if 'action' in kwargs:
        ACTION = kwargs['action']
    if 'device' in kwargs:
        PAN = kwargs['device']
    if 'vsys' in kwargs:
        VSYS = kwargs['vsys']
    if 'group' in kwargs:
        BADACTORS = kwargs['group']

    logger.warn("parsed args")

    # results contains the data from the search results and settings contains the sessionKey that we can use to talk to splunk
    results, unused1, settings = splunk.Intersplunk.getOrganizedResults()
    logger.warn("Got organized results")
    # get the sessionKey
    sessionKey = settings['sessionKey']
    logger.warn("sessionKey: %s" % sessionKey)
    # get the user and password using the sessionKey
    logger.warn("going to get credentials")
    PANUSER, PANPASS = getCredentials(sessionKey)

    logger.warn("Got Credentials")
    try:
        for result in results:
            if ('src_ip' in result
               or 'dst_ip' in result
               or 'ip' in result
               or 'hostname' in result
               or 'dst_hostname' in result
               or 'dest_host' in result
               or 'domain' in result
               or 'clientip' in result):
                blockresult = block(result)
                result["status"] = blockresult[0]
                key = blockresult[1]
            # for test purposes
            elif (len(result) == 2) and 'test' in result:
                result["status"] = ["this is the sessionKey. not printing the password :p " + sessionKey]
            else:
                result["status"] = 'empty or invalid field vlue'

        #after all the addresses have been processed, commit the config
        commitConfig(PAN, key)
    except Exception, e:
        import traceback

        stack = traceback.format_exc()
        if isgetinfo:
            splunk.Intersplunk.parseError(str(e))

        results = splunk.Intersplunk.generateErrorResults(str(e))
        logger.warn(stack)

    # output results
    splunk.Intersplunk.outputResults(results)

# If run from CLI
def main_from_cli(argv=sys.argv):
    """Received parameters from the command line"""
    import argparse
    import logging
    from splunk.clilib import cli_common, cli

    global options

    # Setup the argument parser
    parser = argparse.ArgumentParser(description='Modify static address object on Palo Alto Networks firewall')

    # Firewall related args
    parser = common.add_firewall_cli_args(parser)

    # Arguments related to this script
    options_group = parser.add_argument_group('Options')
    action_group = options_group.add_mutually_exclusive_group(required=True)
    action_group.add_argument('-a', '--add', action='store_true', help="Add an address to an address object.")
    action_group.add_argument('-r', '--remove', action='store_true', help="Remove an address to an address object.")
    options_group.add_argument('-i', '--ip', dest="ip_address", default=ACTOR, help="IP Address to add/remove to group")
    options_group.add_argument('-g', '--group', dest="group", default=BADACTORS, help="Address group to add/remove address to")
    options_group.add_argument('-d', '--debug', action='store_true', default=False, help="Debug output")

    options = parser.parse_args()

    if options.debug:
        logger.setLevel(logging.DEBUG)
    logger.debug("Detected run from CLI, not Splunk")
    sessionKey = cli.user_friendly_login(options.username, options.password)

    username, password = common.get_firewall_credentials(sessionKey)

    # get an authentication key
    #key = getKey(options.PAN, options.PANUSER, options.PANPASS)
    # add an address object
    if options.action == 'add':
        status = addActor(options.PAN,
                          key,
                          options.VSYS,
                          options.ACTOR,
                          options.BADACTORS)
    #remove an address object
    elif options.action == 'rem':
        status = remActor(options.PAN,
                          key,
                          options.VSYS,
                          options.ACTOR,
                          options.BADACTORS)
    elif (options.test == '1'):
        logger.info("So you just want to see the test mode")
        from pprint import pformat
        logger.info("options: %s" % pformat(options))
        logger.info("Thats all i got. Have a nice day!")
        sys.exit(-1)
    else:
        print "Please specify an action of add or rem. e.g. to add an address"
        print "panChange.py -a add -b 1.1.1.1"
        print "Action must be either 'add' or 'rem' "
        sys.exit(-1)
    # save the config changes
    commitConfig(options.PAN, key)
    return 0


if __name__ == "__main__":
    if run_by_splunk():
        main_from_splunk()
    else:
        main_from_cli()
