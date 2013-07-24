import os
import shutil
import splunk.appserver.mrsparkle.controllers as controllers
from splunk.appserver.mrsparkle.lib.decorators import expose_page

APP = 'SplunkforPaloAltoNetworks'
ENABLED_NAV = os.path.join(os.environ['SPLUNK_HOME'], 'etc', 'apps', APP, 'default', 'data', 'ui', 'nav', 'default.xml.enabled')
DISABLED_NAV = os.path.join(os.environ['SPLUNK_HOME'], 'etc', 'apps', APP, 'default', 'data', 'ui', 'nav', 'default.xml.disabled')
NAV = os.path.join(os.environ['SPLUNK_HOME'], 'etc', 'apps', APP, 'default', 'data', 'ui', 'nav', 'default.xml')

class NAVHANDLER(controllers.BaseController):
    @expose_page(must_login=True, methods=['GET'])
    def enable(self, **kwargs):
        try:
            shutil.copy(ENABLED_NAV, NAV)
        except:
            pass
        return 'Enabled!'
    @expose_page(must_login=True, methods=['GET'])
    def disable(self, **kwargs):
        try:
            shutil.copy(DISABLED_NAV, NAV)
        except:
            pass
        return 'Disabled!'

