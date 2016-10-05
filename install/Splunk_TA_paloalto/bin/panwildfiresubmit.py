import sys
import gzip
import csv
import json
import logging
import logging.handlers
import traceback

# CORE SPLUNK IMPORTS (not needed)
# import splunk
# import splunk.search as splunkSearch
# from splunk.rest import simpleRequest
# import splunk.version as ver
# import splunk.clilib.cli_common
# import splunk.auth, splunk.search
# import splunk.Intersplunk as si

try:
    from splunk.clilib.bundle_paths import make_splunkhome_path
except ImportError:
    from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path

sys.path.append(make_splunkhome_path(["etc", "apps", "Splunk_SA_CIM", "lib"]))
sys.path.append(make_splunkhome_path(["etc", "apps", "SA-Utils", "lib"]))
sys.path.append(make_splunkhome_path(["etc", "apps", "Splunk_TA_paloalto", "bin", "lib"]))
sys.path.append(make_splunkhome_path(["etc", "apps", "Splunk_TA_paloalto", "bin", "lib", "pan-python", "lib"]))
sys.path.append(make_splunkhome_path(["etc", "apps", "Splunk_TA_paloalto", "bin", "lib", "pandevice"]))

from cim_actions import ModularAction
import common
import pan.wfapi

# set the maximum allowable CSV field size
#
# The default of the csv module is 128KB; upping to 10MB. See SPL-12117 for
# the background on issues surrounding field sizes.
# (this method is new in python 2.5)
csv.field_size_limit(10485760)

# Default fields that contain a URL and should be tagged if they exist
URL_FIELDS = ['url', 'misc', 'dest_url']

##
## Debugging : index=_internal (source=*_modalert.log* OR source=*_modworkflow.log*)

## ModularAction wrapper
class PanWildFireSubmitModularAction(ModularAction):

    def __init__(self, settings, logger, action_name=None):
        super(PanWildFireSubmitModularAction, self).__init__(settings, logger, action_name)

        self.verbose = self.configuration.get('verbose', 'false') in ["True", "true", "yes", "on"]
        self.logger.debug("verbose = %s", self.verbose)
        self.resultcount = 0

        connector = common.SplunkConnector(self.session_key, self.logger)
        api_key = connector.get_wildfire_apikey()
        self.wfapi = pan.wfapi.PanWFapi(api_key=api_key)

    def apply(self, result):

        # Extract the url to be submitted
        url = None
        for field in URL_FIELDS:
            if field in result:
                url = result[field]
                break

        # Couldn't find a field with a URL
        if url is None:
            modaction.message('Unable to find field with URL to submit', status='failure', rids=self.rids, level=logging.ERROR)
            raise KeyError("Unable to find field with URL to submit, need field 'url'")

        self.logger.debug("Submitting URL to WildFire: %s" % url)
        try:
            self.wfapi.submit(url=url)
        except pan.wfapi.PanWFapiError as e:
            if str(e).startswith("HTTP Error 422: Unprocessable Entities") \
                    or str(e).startswith("HTTP Error 418: Unsupport File Type"):
                self.logger.debug("URL is not a file that can be processed by WildFire: %s" % url)
            else:
                raise e
        self.resultcount += 1


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] != "--execute":
        print >> sys.stderr, "FATAL Unsupported execution mode (expected --execute flag)"
        sys.exit(1)

    logger = ModularAction.setup_logger('panwildfiresubmit_modalert')
    try:
        modaction = PanWildFireSubmitModularAction(sys.stdin.read(), logger, 'panwildfiresubmit')
        session_key = modaction.session_key
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug('%s', json.dumps(modaction.settings, sort_keys=True,
                indent=4, separators=(',', ': ')))

        ## process results
        with gzip.open(modaction.results_file, 'rb') as fh:
            for num, result in enumerate(csv.DictReader(fh)):
                ## set rid to row # (0->n) if unset
                result.setdefault('rid', str(num))
                modaction.update(result)
                modaction.invoke()
                modaction.apply(result)

        modaction.message("Submitted urls to WildFire for analysis",
                          status='success',
                          rids=modaction.rids
                          )

    except Exception as e:
        ## adding additional logging since adhoc search invocations do not write to stderr
        try:
            logger.critical(traceback.format_exc())
            logger.critical(modaction.message(e, 'failure'))
        except:
            logger.critical(e)
            traceback.print_exc(file=sys.stderr)
        print >> sys.stderr, "ERROR Unexpected error: %s" % e
        sys.exit(3)
