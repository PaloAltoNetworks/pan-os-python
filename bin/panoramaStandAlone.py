###########################################
# Version 0.1
# author: monzy@splunk.com
# About this script:
#
############################################
############################################
# How to Use this script
#
###########################################
###########################################
# Known issues:
# Very limited error checking
# Errors may not be reported in the Splunk UI
# ONLY works with PANORAMA at this time
# Device group have to be pre-populated
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
PANUSER = 'admin'
# password for the admin user.
# any special characters in the password must be URL/percent-encoded.
PANPASS = 'admin'
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
import urllib2 # make http requests to PAN firewall
import sys # for system params and sys.exit()
import re # regular expressions checks in PAN messages
import xml.etree.ElementTree as ET # for xml parsing

def createOpener():
  # Create a generic opener for http
  # This is particularly helpful when there is a proxy server in line
  # Thanks to: http://www.decalage.info/en/python/urllib2noproxy
  proxy_handler = urllib2.ProxyHandler(HTTP_PROXY)
  opener = urllib2.build_opener(proxy_handler)
  urllib2.install_opener(opener)
  return opener

def getPanSerial(key, PAN):
  '''Interact with PANorama'''
  #List device groups: List devices by named Device Group, obtain Serial Numbers (for &target=)
  panurl = 'https://'+PAN+'/api/?type=config&action=show&xpath=/config/devices/entry[@name='+"'"+"localhost.localdomain"+"'"+']/device-group/entry[@name='+"'"+DEVICEGROUP+"'"+']/devices&key='+key
  #http opener
  opener = createOpener()
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
  # create an opener object
  opener = createOpener()
  try:
    # the url for the PAN
    panurl = 'https://'+PAN+'/api/?type=keygen&user='+PANUSER+'&password='+PANPASS
    print panurl
    panReq =  urllib2.Request(panurl)
    # make the request
    req = opener.open(panReq)
  except:
    sys.exit(-1)
  # the result of the URL request
  result = req.read()
  # get the status of the result
  try:
    sm = re.search(r"success",result).group(0)
    if sm == 'success' :
      status = 'success'
  except:
    sys.exit(-1)
  # parse the key from the result
  key = result.split("</key>")[0].split("<key>")[1]
  return key

def commitConfig(PAN, key):

  '''Save the changes made to the address objects'''
  # create an opener object
  opener = createOpener()
  panReq =  urllib2.Request('https://'+PAN+'//api/?type=commit&cmd=<commit></commit>&key='+key)
  req = opener.open(panReq)
  return 0

def panoramaCommit(PAN,key):
  panurl = 'https://'+PAN+'/api/?type=commit&action=all&cmd=<commit-all><shared-policy><device-group>'+DEVICEGROUP+'</device-group></shared-policy></commit-all>&key='+key
  opener = createOpener()
  try:
    # the url for the PAN
    panReq =  urllib2.Request(panurl)
    # make the request
    req = opener.open(panReq)
  except:
    return "Failed: Commit to Panarama"
  # the result of the URL
  return req.read()

def panoramaAddLinkId(key, device, devicegroup, addrip, addr):
  '''Set dynamic address object (with LinkID) at Panorama level'''
  #we will use the same name for linkid as the addrIp
  #Set dynamic address object (with LinkID) at Panorama level
  panurl = 'https://'+device+'/api/?type=config&action=set&xpath=/config/devices/entry[@name='+"'"+'localhost.localdomain'+"'"+']/device-group/entry[@name='+"'"+devicegroup+"'"+']/address/entry[@name='+"'"+addr+"'"+']&element=<dynamic>'+addrip+'</dynamic>&key='+key
  print "Adding LinkID using:"
  print panurl
  opener = createOpener()
  try:
    # the url for the PAN
    panReq =  urllib2.Request(panurl)
    # make the request
    req = opener.open(panReq)
  except:
    return "Failed: Adding LinkId to Panarama"
  # the result of the URL
  return req.read()
  #Set dynamic address object (with LinkID) at Device level, commit
  #https://10.5.172.24/api/?type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='dynamo']&element=<dynamic>dyn1</dynamic>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09
  #https://10.5.172.24/api/?type=commit&cmd=<commit></commit>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09

  #Note, all additional calls listed below are identical whether or not they are applied to panorama or devices, the only differences are the target IP/FQDN and if performing the call directly against a device please remove the &target=serial# section from the end.

def panoramaMapIpToLinkId(key, device, results, serial):
  '''Map IPs to correct link ID (No commit required)'''
  register = ''
  for result in results:
    register = register + '<register><entry%20identifier='+'"'+result['addrip']+'"'+'%20ip='+'"'+result['addrip']+'"'+'/></register>'
  panurl = 'https://'+device+'/api/?type=user-id&action=set&cmd=<uid-message><version>1.0</version><type>update</type><payload>'+register+'</payload></uid-message>&key='+key+'&target='+serial
  print "Mapping IP to LinkID using:"
  print panurl
  opener = createOpener()
  try:
    # the url for the PAN
    panReq =  urllib2.Request(panurl)
    # make the request
    req = opener.open(panReq)
  except:
    import traceback
    stack =  traceback.format_exc()
    print 2 * '\n'
    print "Failed: Mapping IP to LinkId"
    print panurl
    print stack
    return -1
  # the result of the URL
  return req.read()

  #List All Mappings
  #https://pm-panorama/api/?type=op&cmd=<show><object><dynamic-address-object><all></all></dynamic-address-object></object></show>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09&target=0006C107916
  #<response cmd="status" status="success"><result><entry identifier="dyn-obj" ip="10.1.1.1" name="dyn-obj" vsys="vsys1"/><entry identifier="test1" ip="10.1.1.1" name="test-add" vsys="vsys1"/></result></response>

  #List Specific Mapping
  #https://pm-panorama/api/?type=op&cmd=<show><object><dynamic-address-object><name>test-add</name></dynamic-address-object></object></show>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09&target=0006C107916
  #<response cmd="status" status="success"><result><entry identifier="test1" ip="10.1.1.1" name="test-add" vsys="vsys1"/></result></response>

  #Remove Specific Mapping
  #https://pm-panorama/api/?type=user-id&action=set&cmd=<uid-message><version>1.0</version><type>update</type><payload><unregister><entry identifier="test1" ip="10.1.1.1"/></unregister></payload></uid-message>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09&target=0006C107916

def panoramaMapIpToUser(key, device, results, serial):
  '''Map IPs to UserID'''
  login = ''
  for result in results:
    login = login + '<login><entry%20name='+'"'+result['addruser']+'"'+'%20ip='+'"'+result['addrip']+'"'+'%20timeout="20"></entry></login>'
  panurl = 'https://'+device+'/api/?type=user-id&action=set&cmd=<uid-message><version>1.0</version><type>update</type><payload>'+login+'</payload></uid-message>&key='+key+'&target='+serial
  print "Mapping IP to User using:"
  print panurl
  opener = createOpener()
  try:
    # the url for the PAN
    panReq =  urllib2.Request(panurl)
    # make the request
    req = opener.open(panReq)
  except:
    print 2 * '\n'
    print "Failed: Map IP to user"
    print panurl
    import traceback
    stack =  traceback.format_exc()
    print stack
    return -1
  # the result of the URL
  return req.read()

def panorama():
  '''test function'''
  addrip = '1.1.1.1'
  addruser = 'monzy'
  action = 'list'
  devicetype = 'panorama'
  print PAN, PANUSER, PANPASS
  key = getKey(PAN, PANUSER, PANPASS)
  print key
  # if device is a firewall
  if devicetype == "pan":
    print panAction(key)
  # if device type is Panorama
  elif devicetype == 'panorama':
    #print panoramaAddLinkId(key,action,PAN,devicetype, DEVICEGROUP, addrip, addruser)
    #get serial numbers for all devices from Panorama
    serial = getPanSerial(key,PAN)
    print serial
  else:
    print "unknown device type"
    sys.exit(-1)

def panoramaUpdate(results, PAN, DEVICEGROUP):
  PAN = '192.168.4.211'
  key = getKey(PAN, PANUSER, PANPASS)
  for result in results:
    linkid = panoramaAddLinkId(key, PAN, DEVICEGROUP, result["addrip"], result["addrip"])
    print linkid
  #commit
  print panoramaCommit(PAN, key)
  #get serial numbers for all PAN devices from the Panorama
  serialnum = getPanSerial(key,PAN)
  # update info for each of the devices
  for serial in serialnum:
    print panoramaMapIpToLinkId(key, PAN, results, serial)
    print panoramaMapIpToUser(key, PAN, results, serial)

def main():
  #panorama()
  results = [{"addruser":"monte", "addrip":"2.2.2.2"},{"addruser":"lostha", "addrip":"9.9.9.9"}]
  panoramaUpdate(results, PAN,DEVICEGROUP)

if __name__ == "__main__":
  main()
