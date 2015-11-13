
##########################################
#### This command is deprecated
#### Please use panuserupdate instead
##########################################





###########################################
# Version 0.1
# author: monzy
# About this script:
# Adds Dynamic Address objects and maps users to thoese objects as a result of a splunk search command
# The search command is called panupdate
# Script's actions and warning messages are logged in $SPLUNK_HOME/var/log/splunk/python.log
############################################
############################################
# How to Use this script
# index=main sourcetype=radius | panupdate device="192.168.4.211" devicegroup="homedev"
# Search radius logs for userid and associated ip's.
# Panupdate: the Panorama ip is 192.168.4.211, and we want to update devicegroup called homedev
# NOTE: The Panorama's admin user's credentials must be set using the app's setup
# NOTE: The devicegroup must exist in the Panorama prior to executing this command
###########################################
###########################################
# Known issues:
# Very limited error checking
# Errors may not be reported in the Splunk UI
# ONLY works with PANORAMA at this time
# Device group have to be pre-populated
# The panoramaMapIpToUser function contains a timeout setting (in minutes). It is currently set to 30. This is the duration for which the user-id to ip mapping will exist. Change this value to suit your business requirements.
# '<login><entry%20name='+'"'+result['addruser']+'"'+'%20ip='+'"'+result['addrip']+'"'+'%20timeout="30"></entry></login>'
###########################################
#############################
# Change the values below to suit your PAN configuration
# WARNING!!!! Password is here for legacy. You should set the password by running the app's Setup
#############################
# Device IP
PAN = ''
#Panorama name
PANO = "Panorama"
# admin account for the PAN device
PANUSER = ''
# password for the admin user.
# any special characters in the password must be URL/percent-encoded.
PANPASS = ''
# this is the device group where changes will take effect
DEVICEGROUP = 'homedev'
# Defaults to vsys1. vsys substition is not supported at this time
VSYS = 'vsys1'
# if you DO want to go through a proxy, e.g., HTTP_PROXY={squid:'2.2.2.2'}
HTTP_PROXY = {}
#########################################################
# Do NOT modify anything below this line unless you are
# certain of the ramifications of the changes
#########################################################
import splunk.Intersplunk # so you can interact with Splunk
import splunk.entity as entity # for splunk config info
import splunk.mining.dcutils as dcu
import urllib2 # make http requests to PAN firewall
import sys # for system params and sys.exit()
import re # regular expressions checks in PAN messages
import xml.etree.ElementTree as ET # for xml parsing
import traceback

def createOpener():
  '''Create a generic opener for http
  This is particularly helpful when there is a proxy server in line'''
  # Thanks to: http://www.decalage.info/en/python/urllib2noproxy
  proxy_handler = urllib2.ProxyHandler(HTTP_PROXY)
  opener = urllib2.build_opener(proxy_handler)
  urllib2.install_opener(opener)
  return opener

def getCredentials(sessionKey):
  '''Given a splunk sesionKey returns a clear text user name and password from a splunk password container'''
  # this is the folder name for the app and not the app's common name
  myapp = 'SplunkforPaloAltoNetworks'
  try:
     # list all credentials
    entities = entity.getEntities(['admin', 'passwords'], namespace=myapp, owner='nobody', sessionKey=sessionKey)
  except Exception, e:
    stack =  traceback.format_exc()
    logger.warn(stack)
    logger.warn("entity exception")
    raise Exception("Could not get %s credentials from splunk. Error: %s" % (myapp, str(e)))
  # return first set of credentials
  for i, c in entities.items():
    if c['username'] != 'wildfire_api_key':
      return c['username'], c['clear_password']
  logger.warn("No credentials")
  raise Exception("No credentials have been found")

def getPanSerial(key, PAN):
  '''Get the Serial Numbers from the Panorama'''
  #List device groups: List devices by named Device Group, obtain Serial Numbers (for &target=)
  panurl = 'https://'+PAN+'/api/?type=config&action=show&xpath=/config/devices/entry[@name='+"'"+"localhost.localdomain"+"'"+']/device-group/entry[@name='+"'"+DEVICEGROUP+"'"+']/devices&key='+key
  # create a request object
  panReq = urllib2.Request(panurl)
  # make the request to the PAN
  try:
    xmlresult = opener.open(panReq)
  except:
    sys.exit(-1)
  # create a root by reading the xml results
  # save the raw xml
  xmlresult = xmlresult.read()
  root = ET.fromstring(xmlresult)
  # a list of serial numbers
  devicegroup = []
  serial = []
  for node in root.getiterator():
    # for the devices node
    if node.tag == 'devices':
      for child in node.getiterator():
        # add the entry names to the serial list
        if child.tag == 'entry':
          serial.append(child.attrib['name'])
  return serial

def getKey(PAN, PANUSER, PANPASS):
  ''' Logs into the PAN firewall and obtains a PAN session key'''
  try:
    # the url for the PAN
    panurl = 'https://'+PAN+'/api/?type=keygen&user='+PANUSER+'&password='+PANPASS
    panReq =  urllib2.Request(panurl)
    # make the request
    req = opener.open(panReq)
  except:
    stack =  traceback.format_exc()
    logger.warn(stack)
    sys.exit(-1)
  # the result of the URL request
  result = req.read()
  # get the status of the result
  try:
    sm = re.search(r"success",result).group(0)
    if sm == 'success' :
      status = 'success'
  except:
    stack =  traceback.format_exc()
    logger.warn(stack)
    sys.exit(-1)
  # parse the key from the result
  key = result.split("</key>")[0].split("<key>")[1]
  return key

def commitConfig(PAN, key):

  '''Save the changes made to the address objects'''
  panReq =  urllib2.Request('https://'+PAN+'//api/?type=commit&cmd=<commit></commit>&key='+key)
  req = opener.open(panReq)
  return 0

def panoramaCommit(PAN,key):
  '''Commit the currently loaded updates'''
  panurl = 'https://'+PAN+'/api/?type=commit&action=all&cmd=<commit-all><shared-policy><device-group>'+DEVICEGROUP+'</device-group></shared-policy></commit-all>&key='+key
  try:
    # the url for the PAN
    panReq =  urllib2.Request(panurl)
    # make the request
    req = opener.open(panReq)
  except:
    stack =  traceback.format_exc()
    logger.warn(stack)
    sys.exit(-1)
  # the result of the URL
  return req.read()

def panoramaAddLinkId(key, device, devicegroup, addrip):
  '''Set dynamic address object (with LinkID) at Panorama level'''
  #we will use the same name for linkid as the addrIp
  #Set dynamic address object (with LinkID) at Panorama level
  panurl = 'https://'+device+'/api/?type=config&action=set&xpath=/config/devices/entry[@name='+"'"+'localhost.localdomain'+"'"+']/device-group/entry[@name='+"'"+devicegroup+"'"+']/address/entry[@name='+"'"+addrip+"'"+']&element=<dynamic>'+addrip+'</dynamic>&key='+key
  logger.info("Adding LinkID using:")
  logger.info(panurl)
  try:
    # the url for the PAN
    panReq =  urllib2.Request(panurl)
    # make the request
    req = opener.open(panReq)
  except:
    stack =  traceback.format_exc()
    logger.warn(stack)
  # the response from the url request
  logger.info(req.read())
  return 0

def panoramaMapIpToLinkId(key, device, results, serial):
  '''Map IPs to correct link ID (No commit required)'''
  register = ''
  for result in results:
    register = '<register><entry%20identifier='+'"'+result['addrip']+'"'+'%20ip='+'"'+result['addrip']+'"'+'/></register>'
    panurl = 'https://'+device+'/api/?type=user-id&action=set&cmd=<uid-message><version>1.0</version><type>update</type><payload>'+register+'</payload></uid-message>&key='+key+'&target='+serial
    logger.info("Mapping IP to LinkID using:")
    logger.info(panurl)
    try:
      # the url for the PAN
      panReq =  urllib2.Request(panurl)
      # make the request
      req = opener.open(panReq)
    except:
      stack =  traceback.format_exc()
      logger.info(stack)
      return -1
    # the response from the url request
    logger.info(req.read())
  return 0

def panoramaMapIpToUser(key, device, results, serial):
  '''Map IPs to UserID'''
  login = ''
  for result in results:
    login = '<login><entry%20name='+'"'+result['addruser']+'"'+'%20ip='+'"'+result['addrip']+'"'+'%20timeout="30"></entry></login>'
    panurl = 'https://'+device+'/api/?type=user-id&action=set&cmd=<uid-message><version>1.0</version><type>update</type><payload>'+login+'</payload></uid-message>&key='+key+'&target='+serial
    logger.info("Mapping IP to User using:")
    logger.info(panurl)
    try:
      # the url for the PAN
      panReq =  urllib2.Request(panurl)
      # make the request
      req = opener.open(panReq)
    except:
      stack = traceback.format_exc()
      logger.info(stack)
      sys.exit(-1)
      # the result of the URL
    # the response from the url request
    logger.info(req.read())
  return 0

def panoramaUpdate(results, PAN, DEVICEGROUP):
  '''Given search results, updates the PAN's device group with the addrip and addruser '''
  #PAN = '192.168.4.211'  Good catch Jeff Hillon PAN
  key = getKey(PAN, PANUSER, PANPASS)
  # create LinkIDs
  for result in results:
    linkid = panoramaAddLinkId(key, PAN, DEVICEGROUP, result["addrip"])
    logger.info(linkid)
  #commit
  commit = panoramaCommit(PAN, key)
  logger.info(commit)
  #get serial numbers for all PAN devices from the Panorama
  serialnum = getPanSerial(key,PAN)
  # update info for each of the devices
  for serial in serialnum:
    #Map IP to LinkID
    panoramaMapIpToLinkId(key, PAN, results, serial)
    #Map IP to User
    panoramaMapIpToUser(key, PAN, results, serial)
  return 0

# setup the logger. $SPLUNK_HOME/var/log/splunk/python.log
logger = dcu.getLogger()
# create a global http opener
opener = createOpener()
# get command line args
args, kwargs = splunk.Intersplunk.getKeywordsAndOptions()
#parse the kwargs
if kwargs.has_key('device'):
  PAN = kwargs['device']
if kwargs.has_key('devicegroup'):
  DEVICEGROUP = kwargs['devicegroup']
else:
  logger.warn("You did not specify a Panorama device name or IP in the splunk command")
  sys.exit(-1)

# an empty dictionary will be used to hold system values
settings = dict()
# results contains the data from the search results and settings contains the sessionKey that we can use to talk to splunk
results,unused1,settings = splunk.Intersplunk.getOrganizedResults()
logger.info(settings)
# get the sessionKey
sessionKey = settings['sessionKey']
# get the Panorama user and password from Splunk using the sessionKey
PANUSER, PANPASS = getCredentials(sessionKey)
# Copying the results in a new dict. We don't want to update and commit individual results against the Panorama.
ipandusers = []
for result in results:
  if result.has_key("addrip") and result.has_key("addruser"):
    pair = {"addrip":result["addrip"],"addruser":result["addruser"]}
    ipandusers.append(pair)
panoramaUpdate(ipandusers, PAN, DEVICEGROUP)

try:
  splunk.Intersplunk.outputResults([{"result":"Your request has been submitted. It might take up to a minute for changes to take effect"}])
except:
  stack = traceback.format_exc()
  logger.warn(stack)
