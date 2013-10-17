import os
import shutil
import splunk.appserver.mrsparkle.controllers as controllers
from splunk.appserver.mrsparkle.lib.decorators import expose_page

APP = 'SplunkforPaloAltoNetworks'
ENABLED_NAV = os.path.join(os.environ['SPLUNK_HOME'], 'etc', 'apps', APP, 'default', 'data', 'ui', 'nav', 'default.xml.nfi_enabled')
DISABLED_NAV = os.path.join(os.environ['SPLUNK_HOME'], 'etc', 'apps', APP, 'default', 'data', 'ui', 'nav', 'default.xml.nfi_disabled')
NAV_DIR = os.path.join(os.environ['SPLUNK_HOME'], 'etc', 'apps', APP, 'local', 'data', 'ui', 'nav')
NAV = os.path.join(os.environ['SPLUNK_HOME'], 'etc', 'apps', APP, 'local', 'data', 'ui', 'nav', 'default.xml')

class NAVHANDLER(controllers.BaseController):
    @expose_page(must_login=True, methods=['GET'])
    def enable(self, **kwargs):
        if not os.path.exists(NAV_DIR):
            os.makedirs(NAV_DIR)
        try:
            shutil.copy(ENABLED_NAV, NAV)
        except:
            pass
        return 'Enabled!'
    @expose_page(must_login=True, methods=['GET'])
    def disable(self, **kwargs):
        if not os.path.exists(NAV_DIR):
            os.makedirs(NAV_DIR)
        try:
            shutil.copy(DISABLED_NAV, NAV)
        except:
            pass
        return 'Disabled!'

