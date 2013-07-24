import os
import splunk.appserver.mrsparkle.controllers as controllers
from splunk.appserver.mrsparkle.lib.decorators import expose_page

APP = 'SplunkforPaloAltoNetworks'
VERSION_CONF = os.path.join(os.environ['SPLUNK_HOME'], 'etc', 'apps', APP, 'default', 'nfi_version.conf')

class GetVersion(controllers.BaseController):
    @expose_page(must_login=True, methods=['GET'])
    def get_version(self, **kwargs):
        version = 'unknown';
        try:
            with open(VERSION_CONF, 'r') as cf:
                for line in cf:
                    if not line.startswith('#') and not line.startswith(';') and line.strip() != '':
                        parts = line.split('=', 1)
                        if len(parts) == 1:
                            continue
                        key = parts[0].strip()
                        if key == 'version':
                            version = parts[1].strip()
                            break
        except:
            version = 'unknown';
        return version

