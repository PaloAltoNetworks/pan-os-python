from distutils.version import LooseVersion
import distutils.dir_util as dir_util
import logging
import logging.handlers
import os
import sys
import traceback

import splunk
import splunk.entity
import splunk.appserver.mrsparkle.lib.util as app_util

SPLUNK_HOME = os.environ.get('SPLUNK_HOME')
INSTALLER_LOG_FILENAME = os.path.join(SPLUNK_HOME,'var','log','splunk','paloalto_ta_installer.log')
logger = logging.getLogger('paloalto_ta_installer')
logger.setLevel(logging.DEBUG)
handler = logging.handlers.RotatingFileHandler(INSTALLER_LOG_FILENAME, maxBytes=1024000, backupCount=5)
handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
handler.setLevel(logging.DEBUG)
logger.addHandler(handler)

APP_NAME = 'SplunkforPaloAltoNetworks'
APPS_DIR = app_util.get_apps_dir()
(ETC_DIR, APPS_STEM) = os.path.split(APPS_DIR)
DEPLOYMENT_APPS_DIR = os.path.join(ETC_DIR, 'deployment-apps')
INSTALL_DIR = os.path.join(APPS_DIR, APP_NAME, 'install')
SPLUNK_PROTOCOL = 'http'
SPLUNK_HOST = 'localhost'
SPLUNK_PORT = '8000'
SPLUNK_ROOT_ENDPOINT = '/'
DEPENDENCY_TA = 'Splunk_TA_paloalto'
DEPENDENCY_VERSION = '3.5.0 build 8'
TA_RELOAD_URI = 'services/apps/local/splunk_ta_paloalto/_reload'


def install_dependency(dep):
    src = os.path.join(INSTALL_DIR, dep)
    dst = os.path.join(APPS_DIR, dep)
    try:
        dir_util.copy_tree(src, dst)
        logger.info("%s was successfully copied to %s" % (src, dst)) 
        if os.path.exists(DEPLOYMENT_APPS_DIR):
            dst = os.path.join(DEPLOYMENT_APPS_DIR, dep)
            dir_util.copy_tree(src, dst)
            logger.info("%s was successfully copied to %s" % (src, dst)) 

    except Exception, ex:
        logger.error("unable to copy %s to %s" % (src, dst)) 
        logger.exception(ex)

def get_loose_version(version, build):
    version = "%s build %s" % (version, build)
    return LooseVersion(version)


if __name__ == '__main__':

    token = sys.stdin.readlines()[0]
    token = token.strip()

    logger.info("Splunk App for Palo Alto Networks Dependency Manager: Starting...")
   
    en = splunk.entity.getEntity('server/settings', 'settings', sessionKey=token)
    if (en):
        SPLUNK_PROTOCOL = ("https" if int(en['enableSplunkWebSSL'])==1 else "http")
        SPLUNK_HOST = en['host']
        SPLUNK_PORT = en['httpport']
    else:
        logger.error("unable to retrieve server settings")

    en = splunk.entity.getEntity('configs/conf-web', 'settings', sessionKey=token)
    if (en and 'root_endpoint' in en):
        SPLUNK_ROOT_ENDPOINT = en['root_endpoint']
        if not SPLUNK_ROOT_ENDPOINT.startswith('/'):
            SPLUNK_ROOT_ENDPOINT = "/" + SPLUNK_ROOT_ENDPOINT
        if not SPLUNK_ROOT_ENDPOINT.endswith('/'):
            SPLUNK_ROOT_ENDPOINT += '/'
    else:
        logger.error("unable to retrieve root_endpoint setting")

    # search for Splunk_TA_paloalto dependency
    dependency_en = splunk.entity.getEntities('/apps/local', search=DEPENDENCY_TA, sessionKey=token)
    needed_version = LooseVersion(DEPENDENCY_VERSION)
    if not dependency_en:
        logger.info("dependency %s not found - installing..." % DEPENDENCY_TA)
        install_dependency(DEPENDENCY_TA)
    else:
        dep_version = get_loose_version(dependency_en[DEPENDENCY_TA]['version'], dependency_en[DEPENDENCY_TA]['build'])
        if needed_version > dep_version:
            logger.info("installed version of %s is %s, which is older than required version %s - updating..." % (DEPENDENCY_TA, dep_version, needed_version))
            install_dependency(DEPENDENCY_TA)
        else:
            logger.info("installed version of %s is %s, which is newer or equal to version %s - leaving alone..." % (DEPENDENCY_TA, dep_version, needed_version))

    logger.info("Splunk App for Palo Alto Networks Dependency Manager: Exiting...")
