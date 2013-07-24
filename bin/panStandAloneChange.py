###########################################
# version 0.1
# author: monzy merza
# Given an IP address adds or removes the IP from an address group
# The script assumes that you have firewall policy setup that blocks
# traffic for the badActors group. or otherwise acts on the address group
# We dont' actually modify a firewall rule. We only add/remove address objects.
# So if a rule operates on an Address Group, this scripts add/remove will impact
# that policy.
###########################################

###########################################
# Issues/Bugs
# No Panorama support
# Limited error checking
###########################################

#############################
# Change the values below to suit your PAN configuration
#############################
# firewall IP
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
import urllib2 # make http requests to PAN firewall
import sys # for system params and sys.exit()
import re # regular expressions checks in PAN messages
import traceback # for stack tracing
import optparse # for option parsing

def createOpener():
  # Create a generic opener for http
  # This is particularly helpful when there is a proxy server in line
  # Thanks to: http://www.decalage.info/en/python/urllib2noproxy
  proxy_handler = urllib2.ProxyHandler(HTTP_PROXY)
  opener = urllib2.build_opener(proxy_handler)
  urllib2.install_opener(opener)
  return opener

def getKey(PAN, PANUSER, PANPASS):
  ''' Logs into the PAN firewall and obtains a session key'''
  # create an opener object
  opener = createOpener()
  try:
    # the url for the PAN
    panReq =  urllib2.Request('https://'+PAN+'/api/?type=keygen&user='+PANUSER+'&password='+PANPASS)
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

def addActor(PAN, key, VSYS, ACTOR, BADACTORS):
  '''Creates an address object then add the object to an Address group'''
  # create an opener object
  opener = createOpener()
  # create the address object
  panReq =  urllib2.Request('https://'+PAN+'//api/?type=config&action=set&key='+key+'&xpath=/config/devices/entry/vsys/entry[@name='+"'"+VSYS+"'"+']/address/entry[@name='+"'"+ACTOR+"'"+']&element=<ip-netmask>'+ACTOR+'/32</ip-netmask>')
  req = opener.open(panReq)
  # add the address object to the BADACTORS group
  panReq =  urllib2.Request('https://'+PAN+'//api/?type=config&action=set&key='+key+'&xpath=/config/devices/entry/vsys/entry[@name='+"'"+VSYS+"'"+']/address-group/entry[@name='+"'"+BADACTORS+"'"+']&element=<member>'+ACTOR+'</member>')
  req = opener.open(panReq)
  return 0

def remActor(PAN, key, VSYS, ACTOR, BADACTORS):
  '''Remove an address object from the address-group then remove the addres object '''
  # create an opener object
  opener = createOpener()
  # first we remove him from the badactors group
  panReq =  urllib2.Request('https://'+PAN+'//api/?type=config&action=delete&key='+key+'&xpath=/config/devices/entry/vsys/entry[@name='+"'"+VSYS+"'"+']/address-group/entry[@name='+"'"+BADACTORS+"'"+']&element=<member>'+ACTOR+'</member>')
  req = opener.open(panReq)
  # then we remove him all together
  panReq =  urllib2.Request('https://'+PAN+'//api/?type=config&action=delete&key='+key+'&xpath=/config/devices/entry/vsys/entry[@name='+"'"+VSYS+"'"+']/address/entry[@name='+"'"+ACTOR+"'"+']')
  req = opener.open(panReq)
  return 0

def commitConfig(PAN, key):
  '''Save the changes made to the address objects'''
  # create an opener object
  opener = createOpener()
  panReq =  urllib2.Request('https://'+PAN+'//api/?type=commit&cmd=<commit></commit>&key='+key)
  req = opener.open(panReq)
  return 0

def panChange(result):
  '''Handles the input from Splunk and starts the change process'''
  # Result may contain other info about configs. e.g. PAN device or Vsys etc.
  PAN = PANUSER = PANPASS = VSYS = 0
  if result.has_key('PAN') :
    PAN = result['PAN']
  if result.has_key('PANUSER') :
    PANUSER = result['PANUSER']
  if result.has_key('VSYS') :
    VSYS = result['VSYS']
  if result.has_key('PANPASS'):
    PANPASS = result['PANPASS']
  key = getKey(PAN, PANUSER, PANPASS)
  # check for the action
  if result['panAction'] == 'add' :
    addActor(PAN, key, VSYS, str(result[result.keys()[0]]), BADACTORS)
  elif result['panAction'] == 'rem':
    remActor(PAN, key, VSYS, str(result[result.keys()[0]]), BADACTORS)
  else:
    return 'bad action'
  #commit the changes
  commitConfig(PAN, key)
  return 'action completed'


def main(argv = sys.argv):
  '''Received parameters from the command line'''
  # setup the option parser
  parser = optparse.OptionParser()
  parser.add_option('-a', '--add', dest="ACTION", default="0", help="Adding or removing an address object. Acceptable options are add or rem")
  parser.add_option('-v', '--vsys', dest="VSYS", default=VSYS, help="vsys of the address address object")
  parser.add_option('-u', '--user', dest="PANUSER", default=PANUSER, help="Name of the admin user")
  parser.add_option('-p', '--pass', dest="PANPASS", default=PANPASS, help="Password for the admin user")
  parser.add_option('-d', '--device', dest="PAN", default=PAN, help="IP address of the PAN device")
  parser.add_option('-b', '--bad', dest="ACTOR", default=ACTOR, help="Address of the bad actor.")
  parser.add_option('-g', '--group', dest="BADACTORS", default=BADACTORS, help="Address group of Bad Actors")
  parser.add_option('-t', '--test', dest="test", default="0", help="This is just a dummy run command")


  options, remainder = parser.parse_args()

  # get an authentication key
  key = getKey(options.PAN, options.PANUSER, options.PANPASS)
  # add an address object
  if options.ACTION == 'add':
    status = addActor(options.PAN,
 key,
 options.VSYS,
 options.ACTOR,
 options.BADACTORS)
  #remove an address object
  elif options.ACTION == 'rem':
    status = remActor(options.PAN,
        key,
        options.VSYS,
    options.ACTOR,
    options.BADACTORS)
  elif (options.test == 1):
    print "So you just want to see the test mode"
    print "PAN Device: " + options.PAN
    print "PAN User: " + options.PANUSER
    print "PANPASS: " + options.PANPASS
    print "VSYS: " + options.VSYS
    print "Action: " + options.ACTION
    print "Actor: " + options.ACTOR
    print "Group: " + options.BADACTORS
    print "Thats all i got. Have a nice day!"
  else:
    print "Please specify an action of add or rem. e.g. to add an address"
    print "panChange.py -a add -b 1.1.1.1"
    print "Action must be either 'add' or 'rem' "
    sys.exit(-1)
  # save the config changes
  commitConfig(options.PAN, key)
  return 0


if __name__ == "__main__":
  main()
