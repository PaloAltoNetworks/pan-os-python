###########################################
# Version 0.1
# author: Brian Torres-Gil
# 
# About this script:
# This script retrieves an xml file with new apps so they
# can be highlighted in a dashboard.
# 
# Script's actions and warning messages are logged in $SPLUNK_HOME/var/log/splunk/python.log
############################################
###########################################
# if you DO want to go through a proxy, e.g., HTTP_PROXY={squid:'2.2.2.2'}
HTTP_PROXY = {}
DEBUG = False
#########################################################
# Do NOT modify anything below this line unless you are
# certain of the ramifications of the changes
#########################################################
import splunk.Intersplunk # so you can interact with Splunk
import splunk.entity as entity # for splunk config info
import splunk.mining.dcutils as dcu
import urllib # for urllib.urlencode()
import urllib2 # make http requests to PAN firewall
import sys # for system params and sys.exit()
import traceback
import xml.etree.ElementTree as ET # for xml parsing

def createOpener():
  '''Create a generic opener for http
  This is particularly helpful when there is a proxy server in line'''
  # Thanks to: http://www.decalage.info/en/python/urllib2noproxy
  proxy_handler = urllib2.ProxyHandler(HTTP_PROXY)
  opener = urllib2.build_opener(proxy_handler)
  urllib2.install_opener(opener)
  return opener

def retrieveNewApps():
  # Create a urllib2 opener
  opener = createOpener()
  # URL for WildFire cloud API
  newAppUrl = 'http://ww2.paloaltonetworks.com/iphone/NewApps.aspx'
  # Create a request object
  newAppReq = urllib2.Request(newAppUrl)
  # Make the request
  result = opener.open(newAppReq)
  return result


# an empty dictionary will be used to hold system values
settings = dict()
# results contains the data from the search results and settings contains the sessionKey that we can use to talk to splunk
results,unused1,settings = splunk.Intersplunk.getOrganizedResults()
args, kwargs = splunk.Intersplunk.getKeywordsAndOptions()
#logger.debug(settings) #For debugging
# get the sessionKey
sessionKey = settings['sessionKey']

try:
  DEBUG = True if 'debug' in kwargs else False
  # setup the logger. $SPLUNK_HOME/var/log/splunk/python.log
  logger = dcu.getLogger().getChild('retrieveNewApps')

  if DEBUG:
    logger.setLevel(DEBUG)

  existing_apps = []
  for app in results:
    existing_apps.append(str(app['app{@name}']))

  results = []
  logger.debug("Existing apps already known and considered: %s" % (len(existing_apps),))
  logger.debug(existing_apps)

  logger.debug("Getting new Apps from Palo Alto Networks")
  resp = retrieveNewApps()
  logger.debug("Apps retrieved")
  xml = resp.read()

  logger.debug("Apps read")
  xmlroot = ET.fromstring(xml)
  logger.debug("Apps parsed")

  newapps = xmlroot.findall("./entry")
  logger.debug("Found %s new apps at Palo Alto Networks" % (len(newapps),))

  for app in newapps:
    app.tag = 'app'
    if app.get('name') not in existing_apps:
      results.append( { "_raw" : ET.tostring(app) } )

  logger.debug("Found %s new apps that weren't already known" % (len(results),))

  # output the complete results sent back to splunk
  splunk.Intersplunk.outputResults(results)

except Exception, e:
  stack = traceback.format_exc()
  logger.warn("Exception:")
  logger.warn(stack)
  raise Exception("Exception while getting new apps. Error: %s" % (str(e),))

