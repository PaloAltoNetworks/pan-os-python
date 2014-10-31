import os
from environment import run_by_splunk
import splunk.entity as entity  # for splunk config info

if run_by_splunk():
    import splunk.mining.dcutils as logging
else:
    import logging


logger = logging.getLogger(__name__)


def get_firewall_credentials(session_key):
    """Given a splunk sesionKey returns a clear text user name and password from a splunk password container"""
    # This is the folder name for the app and not the app's common name (ie. "SplunkforPaloAltoNetworks")
    current_file = os.path.dirname(os.path.abspath(__file__))
    myapp = os.path.basename(os.path.normpath(os.path.join(current_file, os.pardir, os.pardir)))
    try:
        # Get all credentials
        logger.debug("Getting firewall credentials from Splunk")
        entities = entity.getEntities(['admin', 'passwords'], namespace=myapp, owner='nobody', sessionKey=session_key)
    except Exception as e:
        import traceback
        logger.warn(traceback.format_exc())
        raise Exception("Could not get %s credentials from splunk. Error: %s" % (myapp, str(e)))
    # return first set of credentials
    for i, c in entities.items():
        if c['username'] != 'wildfire_api_key':
            return c['username'], c['clear_password']
    raise Exception("No credentials have been found")


def add_firewall_cli_args(parser):
    # Palo Alto Networks related arguments
    fw_group = parser.add_argument_group('Palo Alto Networks')
    fw_group.add_argument('hostname', help="Hostname of firewall or Panorama")
    fw_group.add_argument('-s', '--fw-vsys', default=VSYS, help="vsys on Firewall or Panorama")
    fw_group.add_argument('-u', '--username', help="Username of firewall or Splunk")
    fw_group.add_argument('-p', '--password', help="Password of firewall or Splunk")
    fw_group.add_argument('-c', '--splunk-creds', action='store_true', help="Use firewall credentials stored in Splunk app")
    return parser
